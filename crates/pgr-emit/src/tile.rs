//! Pass 4 v2 — the M4 fused tile emit (architecture doc §10.3 row M4,
//! perf doc §4.4).
//!
//! The central structural change for raw speed. Instead of "copy everything,
//! then fix up, then encode chains, then hash everything" (five serial passes
//! over the output — the [`crate::emit::build_image`] reference), the emit
//! processes the output in **tiles of one 16 KiB page** while the bytes are
//! in L1/L2. Every tile, executed as an independent task on the shared
//! compute pool (D9):
//!
//! 1. **copy** — the [`CopyRun`]s intersecting the tile (`memcpy` from the
//!    input objects) plus the synthetic `__got`/`__stubs` pieces;
//! 2. **relocate** — the pre-resolved [`PatchOp`]s at their absolute
//!    positions (the Pass 3 patch stream carries absolute operands, so this
//!    step reads no symbol data at all);
//! 3. **chains** — the encoded rebase/bind words of the fixup slots in this
//!    page (chains never cross a 16 KiB page — TDD §7.4 — so this is
//!    tile-local by construction);
//! 4. **place** — the `__LINKEDIT` chunk bytes and the `__chain_starts`
//!    mirror intersecting the tile (disjoint ranges, sized in Pass 3);
//! 5. **hash** — every 4 KiB sub-page of the tile is final unless it is the
//!    header page (fused hashing, D14): the SHA-256 page table for the
//!    ad-hoc signature is built *inside* the tile loop instead of re-reading
//!    the whole image from DRAM afterwards.
//!
//! Only the header page (UUID) and the signature blob are finished late: the
//! UUID derives from the fused hash table (§9 two-pass derivation), the
//! header page re-hashes, and the SuperBlob lands last — byte-identical to
//! the reference by the M4 gate (gated in `tests/m4_fused.rs` and e2e).
//!
//! Output allocation (D10): `vec![0u8; n]` reaches the allocator's
//! zeroed-allocation path (lazy zero pages, no memset for large sizes); the
//! parallel pre-fault touches one byte per 4 KiB page so the first tile
//! write pays a soft fault, not a zero-fill fault. Padding and `__bss` are
//! zero by the same contract the reference relies on (§11).
//!
//! Work-item lists (`runs`, `synths`, `patches`, `words`, `blobs`) are
//! sorted by position and internally disjoint, so each tile binary-searches
//! its range and touches its slice only — no locks, no cross-tile data
//! (perf doc §5 rule 4), and the result is schedule-independent (§4.3).

use crate::EmitError;
use crate::emit::{indirect_bytes, symtab_bytes};
use crate::reloc;
use crate::signature;
use pgr_core::layout::{CopyRun, Layout, PatchOp};
use pgr_core::object::InputObject;
use pgr_format::consts::PAGE_SIZE_16K;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

/// Tile width: one 16 KiB output page (the TDD's VM-page invariant; the perf
/// doc allows tuning to a 64 KiB multiple — the bench keeps the knob).
const TILE: u64 = PAGE_SIZE_16K;

/// The signature's 4 KiB page size (`CS_PAGE_SIZE_LOG2 = 12`; independent of
/// the 16 KiB VM pages).
const HASH_PAGE: u64 = 4096;

/// One placed span: output range `[start, end)` and its bytes.
type Span<'a> = (u64, u64, &'a [u8]);

/// Read-only tile context shared by every tile task (no locks: every task
/// writes a disjoint buffer slice and returns its own hash slices).
struct TileCtx<'a> {
    /// Coalesced copy runs as spans into the input objects, sorted by `dst`.
    run_spans: Vec<Span<'a>>,
    /// Synthetic piece spans (`__got`/`__stubs` bytes), sorted by `dst`.
    synth_spans: Vec<Span<'a>>,
    /// Placed chunk spans (`__chain_starts` + `__LINKEDIT`), sorted by `dst`.
    blob_spans: Vec<Span<'a>>,
    /// The absolute-position patch stream, sorted by `at`.
    patches: Vec<(u64, PatchOp)>,
    /// Encoded fixup slot words as `(file offset, word)`, sorted by offset.
    words: Vec<(u64, u64)>,
}

/// Builds the complete output image with the fused tile pipeline.
///
/// # Errors
/// [`EmitError::Contract`] on operand/plan inconsistencies;
/// [`EmitError::Internal`] on buffer indexing bugs.
pub fn build_image_fused(layout: &Layout, objects: &[InputObject]) -> Result<Vec<u8>, EmitError> {
    // D10: the zeroed allocation reaches the allocator's lazy zero-page path
    // (no memset); padding and zero-fill sections are zero by contract.
    let mut buf = vec![0u8; layout.file_size as usize];
    if buf.len() < layout.header_bytes.len() {
        return Err(EmitError::Contract {
            message: "header page larger than the output file".into(),
        });
    }
    buf[..layout.header_bytes.len()].copy_from_slice(&layout.header_bytes);

    // Hashed range: everything before the signature (the CodeDirectory's
    // codeLimit). Without a signature nothing is hashed (the reference
    // behavior: `-no_adhoc` keeps the zero UUID and writes no blob).
    let content_end = if layout.linkedit.sig_size > 0 {
        layout.linkedit.sig_off
    } else {
        0
    };

    let symtab = symtab_bytes(layout);
    let indirect = indirect_bytes(layout);
    let ctx = TileCtx::build(layout, objects, &symtab, &indirect)?;

    // D10 (background pre-fault): touch one byte per 4 KiB page in parallel
    // so tile tasks pay soft faults instead of zero-fill faults.
    prefault(&mut buf);

    // ---- the tile loop (parallel over disjoint 16 KiB buffer slices) -------
    let hash_tables: Vec<Vec<[u8; 32]>> = buf
        .par_chunks_mut(TILE as usize)
        .enumerate()
        .map(|(idx, tile)| {
            let lo = idx as u64 * TILE;
            // Copy → relocate → chains → place, THEN hash the finalized
            // bytes while they are still in L1/L2 (the fusion is the point).
            emit_tile(tile, lo, &ctx)?;
            let hashes = if content_end > 0 {
                tile_hashes(tile, lo, content_end)
            } else {
                Vec::new()
            };
            Ok(hashes)
        })
        .collect::<Result<Vec<Vec<[u8; 32]>>, EmitError>>()?;

    if content_end > 0 {
        // Flatten in tile order — the exact chunk sequence of the reference
        // `page_hashes` (4 KiB cuts from 0, partial tail page).
        let mut hashes: Vec<u8> = Vec::with_capacity(hash_table_len(content_end));
        for table in &hash_tables {
            for h in table {
                hashes.extend_from_slice(h);
            }
        }
        // §9: the UUID derives from the page hashes of the UUID-zeroed image
        // (the header bytes carry a zero UUID until this write), then the
        // header page re-hashes. Only page 0 can change.
        let uuid = signature::derive_uuid(&hashes);
        let uuid_at = layout.linkedit.uuid_at as usize;
        let dst = buf
            .get_mut(uuid_at..uuid_at + 16)
            .ok_or(EmitError::Internal {
                message: "UUID field leaves the output buffer".into(),
            })?;
        dst.copy_from_slice(&uuid);
        let first = buf
            .get_mut(..HASH_PAGE as usize)
            .ok_or(EmitError::Internal {
                message: "output smaller than one hash page".into(),
            })?;
        let mut h = Sha256::new();
        h.update(first);
        hashes[..32].copy_from_slice(&h.finalize());

        // The SuperBlob lands last (beyond the hashed range).
        write_superblob(layout, &mut buf, &hashes)?;
    }
    Ok(buf)
}

/// The reference `page_hashes` table length for `code_limit` bytes.
fn hash_table_len(code_limit: u64) -> usize {
    code_limit.div_ceil(HASH_PAGE) as usize * 32
}

/// The ad-hoc SuperBlob (M3 flag rules: `CS_EXECSEG_MAIN_BINARY` only for
/// executables), written at `sig_off`.
fn write_superblob(layout: &Layout, buf: &mut [u8], hashes: &[u8]) -> Result<(), EmitError> {
    let le = &layout.linkedit;
    let is_exec = layout.filetype == pgr_format::consts::MH_EXECUTE;
    let blob = signature::build_superblob(
        &layout.ident,
        le.sig_off,
        hashes,
        layout.text_vmsize,
        is_exec,
    )?;
    if blob.len() != le.sig_size as usize {
        return Err(EmitError::Contract {
            message: format!(
                "signature blob is {} bytes but the layout reserved {}",
                blob.len(),
                le.sig_size
            ),
        });
    }
    let dst = buf
        .get_mut(le.sig_off as usize..(le.sig_off + le.sig_size) as usize)
        .ok_or(EmitError::Contract {
            message: "code signature leaves the output buffer".into(),
        })?;
    dst.copy_from_slice(&blob);
    Ok(())
}

/// Parallel pre-fault (D10): one **read** of the existing value per 4 KiB
/// page. An anonymous zero page maps on the first access of any kind — a
/// read faults it in without dirtying or altering a single byte (writing a
/// re-read 0 would clobber the header magic on page 0), and the read is
/// pinned with `black_box` so the optimizer cannot elide the fault.
fn prefault(buf: &mut [u8]) {
    buf.par_chunks_mut(HASH_PAGE as usize).for_each(|page| {
        if let Some(first) = page.first() {
            std::hint::black_box(*first);
        }
    });
}

/// Turns a `dst` + length + bytes triple into a placed span.
fn span(dst: u64, len: u64, bytes: &[u8]) -> Span<'_> {
    (dst, dst + len, bytes)
}

/// Collects the read-only tile context (flatten + sort, once per emit).
impl<'a> TileCtx<'a> {
    fn build(
        layout: &'a Layout,
        objects: &'a [InputObject],
        symtab: &'a [u8],
        indirect: &'a [u8],
    ) -> Result<Self, EmitError> {
        // 1. Coalesced copy runs → spans into the input objects.
        let run_spans: Vec<Span<'a>> = layout
            .runs
            .iter()
            .map(|run: &CopyRun| {
                let src = objects
                    .get(run.file.0 as usize)
                    .ok_or(EmitError::Internal {
                        message: format!("copy-run file {} missing", run.file.0),
                    })?;
                let bytes = src
                    .bytes
                    .get(run.src.start as usize..run.src.end as usize)
                    .ok_or(EmitError::Contract {
                        message: format!(
                            "copy-run range {}..{} leaves its input",
                            run.src.start, run.src.end
                        ),
                    })?;
                Ok(span(run.dst, run.src.end - run.src.start, bytes))
            })
            .collect::<Result<Vec<Span<'a>>, EmitError>>()?;

        // 2. Synthetic pieces (M2 `__got` slots / `__stubs` entries).
        let mut synth_spans: Vec<Span<'a>> = Vec::new();
        for sect in &layout.sections {
            if sect.zerofill {
                continue;
            }
            for piece in &sect.pieces {
                if let Some(synth) = &piece.synth {
                    synth_spans.push(span(
                        sect.file_off + piece.offset,
                        piece.size,
                        synth.bytes.as_slice(),
                    ));
                }
            }
        }
        synth_spans.sort_unstable_by_key(|s| s.0);

        // 3. The absolute-position patch stream (the D8-shaped handoff: Pass
        //    3 resolved the operands; emit only writes bits).
        let mut patches: Vec<(u64, PatchOp)> = Vec::new();
        for sect in &layout.sections {
            if sect.zerofill {
                continue;
            }
            for piece in &sect.pieces {
                let dest = sect.file_off + piece.offset;
                for op in &piece.patches {
                    let at = dest
                        + u64::from(match op {
                            PatchOp::Adrp { in_offset, .. }
                            | PatchOp::PageOff12 { in_offset, .. }
                            | PatchOp::Branch26 { in_offset, .. }
                            | PatchOp::Write64 { in_offset, .. } => *in_offset,
                        });
                    patches.push((at, *op));
                }
            }
        }
        patches.sort_unstable_by_key(|(at, _)| *at);

        // 4. Chain words at their file offsets (`vaddr − image_base`; M3:
        //    the base is 0 for dylibs/bundles).
        let mut words: Vec<(u64, u64)> = layout
            .fixups
            .slot_words
            .iter()
            .map(|(vaddr, word)| {
                let at = (*vaddr)
                    .checked_sub(layout.image_base)
                    .ok_or(EmitError::Contract {
                        message: format!("fixup slot vaddr {vaddr:#x} below the image base"),
                    })?;
                Ok((at, *word))
            })
            .collect::<Result<Vec<(u64, u64)>, EmitError>>()?;
        words.sort_unstable_by_key(|(at, _)| *at);

        // 5. Placed chunks: the `__chain_starts` mirror + the `__LINKEDIT`
        //    chunks (fixup payload → trie → function starts → symtab →
        //    strtab → indirect), each a disjoint byte range (§8.2 order).
        //    The symtab/indirect chunk bytes are built by the caller and
        //    borrowed here (one builder shared with the reference emit).
        let le = &layout.linkedit;
        let mut blob_spans: Vec<Span<'a>> = Vec::with_capacity(8);
        if le.fixup_payload_size > 0 {
            blob_spans.push(span(
                le.fixup_payload_off,
                layout.fixups.payload.len() as u64,
                &layout.fixups.payload,
            ));
        }
        blob_spans.push(span(le.trie_off, layout.trie.len() as u64, &layout.trie));
        if le.func_starts_size > 0 {
            blob_spans.push(span(
                le.func_starts_off,
                layout.func_starts.len() as u64,
                &layout.func_starts,
            ));
        }
        blob_spans.push(span(le.sym_off, symtab.len() as u64, symtab));
        blob_spans.push(span(le.str_off, layout.strtab.len() as u64, &layout.strtab));
        if le.indirect_size > 0 {
            blob_spans.push(span(le.indirect_off, indirect.len() as u64, indirect));
        }
        if let Some(cs) = layout
            .sections
            .iter()
            .find(|s| s.name == "__chain_starts" && s.size > 0)
        {
            if layout.fixups.chain_starts.len() as u64 > cs.size {
                return Err(EmitError::Contract {
                    message: "__chain_starts section smaller than its content".into(),
                });
            }
            blob_spans.push(span(
                cs.file_off,
                layout.fixups.chain_starts.len() as u64,
                &layout.fixups.chain_starts,
            ));
        }
        blob_spans.retain(|s| s.1 > s.0);
        blob_spans.sort_unstable_by_key(|s| s.0);

        Ok(Self {
            run_spans,
            synth_spans,
            blob_spans,
            patches,
            words,
        })
    }
}

/// Copies the spans intersecting the tile (spans are sorted by `dst` and
/// disjoint, so `end` is monotonic and the first intersector binary-searches).
fn copy_spans(tile: &mut [u8], lo: u64, spans: &[Span<'_>], what: &str) -> Result<(), EmitError> {
    let hi = lo + tile.len() as u64;
    let first = spans.partition_point(|&(_, end, _)| end <= lo);
    for &(dst, end, bytes) in &spans[first..] {
        if dst >= hi {
            break;
        }
        let skip = lo.saturating_sub(dst) as usize;
        let at = (dst + skip as u64 - lo) as usize;
        // Clip to the tile: a span may extend into the next tile (the next
        // tile's task copies its own half at the same file offset).
        let take = ((end - dst) as usize - skip).min(tile.len() - at);
        let src = bytes.get(skip..skip + take).ok_or(EmitError::Internal {
            message: format!("{what} span at {dst:#x} shrunk below its planned size"),
        })?;
        tile.get_mut(at..at + take)
            .ok_or(EmitError::Internal {
                message: format!("{what} span at {dst:#x} leaves its tile"),
            })?
            .copy_from_slice(src);
    }
    Ok(())
}

/// The per-tile body (perf doc §4.4 `emit_tile`): copy → relocate → chains →
/// place, all within one disjoint 16 KiB slice. (Step 5, hashing, runs on
/// the tile slice before this — see `tile_hashes` — so the bytes are hashed
/// while hot in cache.)
fn emit_tile(tile: &mut [u8], lo: u64, ctx: &TileCtx<'_>) -> Result<(), EmitError> {
    if tile.is_empty() {
        return Ok(());
    }
    let hi = lo + tile.len() as u64;

    // 1. copy: coalesced runs + synthetic pieces.
    copy_spans(tile, lo, &ctx.run_spans, "copy run")?;
    copy_spans(tile, lo, &ctx.synth_spans, "synthetic piece")?;

    // 2. relocate: the pre-resolved patch stream (4/8-byte writes never
    //    straddle a 16 KiB tile: positions are 4/8-aligned and tiles are
    //    16 KiB multiples — `apply` bounds-checks the slice regardless).
    let first_patch = ctx.patches.partition_point(|(at, _)| *at < lo);
    for &(at, op) in &ctx.patches[first_patch..] {
        if at >= hi {
            break;
        }
        reloc::apply(tile, &op, at - lo)?;
    }

    // 3. chains: page-local by construction (TDD §7.4).
    let first_word = ctx.words.partition_point(|(at, _)| *at < lo);
    for &(at, word) in &ctx.words[first_word..] {
        if at >= hi {
            break;
        }
        let dst = tile
            .get_mut((at - lo) as usize..(at - lo) as usize + 8)
            .ok_or(EmitError::Contract {
                message: format!("fixup slot at {at:#x} leaves the output buffer"),
            })?;
        dst.copy_from_slice(&word.to_le_bytes());
    }

    // 4. place: `__chain_starts` + `__LINKEDIT` chunks.
    copy_spans(tile, lo, &ctx.blob_spans, "__LINKEDIT chunk")?;

    Ok(())
}

/// Hashes this tile's 4 KiB sub-pages (clipped to `content_end`), returning
/// the hashes in the global page order (the reference chunk sequence).
fn tile_hashes(tile: &[u8], lo: u64, content_end: u64) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    let end = (lo + tile.len() as u64).min(content_end);
    let mut start = lo;
    while start < end {
        let stop = (start + HASH_PAGE).min(end);
        let from = (start - lo) as usize;
        let to = (stop - lo) as usize;
        let mut h = Sha256::new();
        h.update(&tile[from..to]);
        out.push(h.finalize().into());
        start = stop;
    }
    out
}

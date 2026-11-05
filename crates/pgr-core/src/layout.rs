//! Pass 3 — layout & address assignment (TDD §5 Pass 3, §8).
//!
//! Output sections are bucketed by `(segment, section_name)` in the fixed
//! canonical order (`__TEXT`: `__text, __const, __cstring, __chain_starts`;
//! `__DATA_CONST`: `__const, __got`; `__DATA`: `__data, __bss, __common`),
//! input sections become *pieces* (M1 keeps whole sections as pieces —
//! symbol-boundary atomization joins with `-dead_strip` at M5), segments
//! follow the 16 KiB packing contract and the constant-delta scheme
//! (`vmaddr = fileoff + 0x1_0000_0000`), and `__LINKEDIT` chunks take the
//! fixed ld64-compatible order (§8.2) with the signature last.
//!
//! The patch plan is *fully resolved* here: every patch carries absolute
//! operands, so Pass 4 (emit) only writes bits into the output buffer.
//!
//! Address/fixed-point structure (§5 Pass 3 step 3): `__chain_starts` lives
//! in `__TEXT` but its size depends on the fixup packing, which depends on
//! `__DATA` addresses. Head counts and page-relative slot offsets are
//! invariant under 16 KiB-aligned address shifts, so one re-run converges.

use crate::LinkError;
use crate::fixups::{FixupPlan, FixupSlot, plan_fixups};
use crate::ids::{FileId, StringId};
use crate::interner::Interner;
use crate::object::{InputObject, RelocKind, RelocTarget};
use crate::resolve::{Def, Rank, Resolution};
use pgr_format::consts::{
    N_ABS, N_EXT, N_SECT, N_WEAK_DEF, PAGE_SIZE_16K, PAGEZERO_SIZE_64, S_REGULAR, S_ZEROFILL,
    SECTION_TYPE_MASK, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};

/// Link configuration the layout pass consumes (driver-derived).
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// Identifier embedded in the code signature (output-path leaf).
    pub ident: String,
    /// Entry symbol name (`-e`, default `_main`).
    pub entry_symbol: String,
    /// `LC_BUILD_VERSION` platform (macOS at M1).
    pub platform: u32,
    /// Packed minimum OS version (`X.Y.Z` → `(X<<16)|(Y<<8)|Z`).
    pub minos: u32,
    /// Packed SDK version.
    pub sdk: u32,
    /// Emit `LC_LOAD_DYLINKER` (verifier-clean images; true-static binaries
    /// omit it — M1 keeps it, matching the M0 fixtures).
    pub dynamic_linker: bool,
    /// `-no_fixup_chains` disables the chained-fixups payload.
    pub fixup_chains: bool,
    /// `-no_adhoc` skips the ad-hoc signature.
    pub adhoc: bool,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            ident: String::new(),
            entry_symbol: "_main".into(),
            platform: pgr_format::consts::PLATFORM_MACOS,
            minos: 0x000c_0000, // 12.0.0
            sdk: 0x000e_0400,   // 14.4.0
            dynamic_linker: true,
            fixup_chains: true,
            adhoc: true,
        }
    }
}

/// A resolved patch operand: emit applies these mechanically (TDD §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOp {
    /// ADRP: encode `page_delta` (signed 21-bit page count) at `in_offset`.
    Adrp {
        /// Patch position, piece-relative.
        in_offset: u32,
        /// Signed page delta (target page − pc page, in 4 KiB pages).
        page_delta: i64,
    },
    /// ADD/LDR/STR imm12: encode `imm12` at `in_offset`.
    PageOff12 {
        /// Patch position, piece-relative.
        in_offset: u32,
        /// The 12-bit page-offset immediate.
        imm12: u32,
    },
    /// `B`/`BL` imm26: encode `delta = target - pc` (4-aligned, ±128 MiB).
    Branch26 {
        /// Patch position, piece-relative.
        in_offset: u32,
        /// PC of the branch (diagnostics / range check).
        pc: u64,
        /// Signed byte delta to the target.
        delta: i64,
    },
    /// 8-byte absolute write (subtractor results).
    Write64 {
        /// Patch position, piece-relative.
        in_offset: u32,
        /// The resolved 64-bit value.
        value: u64,
    },
}

/// One contribution to an output section: a whole input section (M1) or a
/// zero-fill chunk (commons).
#[derive(Debug, Clone)]
pub struct Piece {
    /// Owning input file.
    pub file: FileId,
    /// Input section index within its file (`usize::MAX` for commons).
    pub in_sect: usize,
    /// Byte range in the input object (empty for zero-fill pieces).
    pub in_range: core::ops::Range<u64>,
    /// Destination offset within the output section.
    pub offset: u64,
    /// Piece size in bytes.
    pub size: u64,
    /// Piece alignment exponent.
    pub align_log2: u32,
    /// True when the piece is zero-filled.
    pub zerofill: bool,
    /// The common symbol this piece allocates (`__common` pieces only).
    pub common_name: Option<StringId>,
    /// Fully-resolved patches (piece-relative offsets).
    pub patches: Vec<PatchOp>,
    /// Chained-fixup pointer slots: `(piece-relative offset, final value)`.
    pub fixup_slots: Vec<(u32, u64)>,
}

/// An output section with its placed pieces.
#[derive(Debug, Clone)]
pub struct PlacedSection {
    /// Output section name (`__text`...).
    pub name: String,
    /// Owning output segment name.
    pub seg_name: String,
    /// Merged `S_*` flags.
    pub flags: u32,
    /// Section alignment exponent (max over pieces).
    pub align_log2: u32,
    /// Absolute vaddr of the section start.
    pub vm_addr: u64,
    /// Section size in bytes.
    pub size: u64,
    /// File offset (0 for zero-fill sections).
    pub file_off: u64,
    /// True when zero-fill (`S_ZEROFILL` output).
    pub zerofill: bool,
    /// Placed pieces, in canonical (file, section) order.
    pub pieces: Vec<Piece>,
}

/// One `LC_SEGMENT_64` plan entry.
#[derive(Debug, Clone)]
pub struct SegmentPlan {
    /// Segment name.
    pub name: String,
    /// vaddr start.
    pub vmaddr: u64,
    /// Virtual size (covers zero-fill tails).
    pub vmsize: u64,
    /// File offset.
    pub fileoff: u64,
    /// File-backed size.
    pub filesize: u64,
    /// Maximum protection.
    pub maxprot: u32,
    /// Initial protection.
    pub initprot: u32,
    /// Indices (into `Layout::sections`) of this segment's sections.
    pub sections: Vec<usize>,
}

/// `__LINKEDIT` chunk plan (§8.2 fixed order: fixup payload → trie →
/// function starts → symtab → strtab → UUID → signature).
#[derive(Debug, Clone, Copy, Default)]
pub struct LinkeditPlan {
    /// File offset of the chained-fixups payload (0 when absent).
    pub fixup_payload_off: u64,
    /// Payload size in bytes.
    pub fixup_payload_size: usize,
    /// Export trie file offset.
    pub trie_off: u64,
    /// Export trie size.
    pub trie_size: usize,
    /// Function-starts file offset.
    pub func_starts_off: u64,
    /// Function-starts size.
    pub func_starts_size: usize,
    /// Symbol table file offset.
    pub sym_off: u64,
    /// Symbol table size.
    pub sym_size: usize,
    /// String table file offset.
    pub str_off: u64,
    /// String table size.
    pub str_size: usize,
    /// Byte offset of the `LC_UUID` uuid field inside the header bytes.
    pub uuid_at: u64,
    /// Code signature file offset (16-aligned).
    pub sig_off: u64,
    /// Code signature size.
    pub sig_size: u64,
}

/// One output symbol-table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputSymbol {
    /// Interned name.
    pub name: StringId,
    /// `n_type` byte (`N_EXT | N_SECT` for defs, locals keep `N_SECT`/abs).
    pub n_type: u8,
    /// 1-based output section index (0 for absolute).
    pub n_sect: u8,
    /// `n_desc` (`N_WEAK_DEF` passthrough).
    pub n_desc: u16,
    /// Output vaddr (or absolute value).
    pub value: u64,
    /// True when the entry belongs in the dysymtab extdef subrange.
    pub external: bool,
}

/// The final Pass 3 product: everything Pass 4 needs to write bytes.
#[derive(Debug, Clone)]
pub struct Layout {
    /// Echo of the config identifier (the signature's identity string).
    pub ident: String,
    /// Output segments in command order (PAGEZERO first, LINKEDIT last).
    pub segments: Vec<SegmentPlan>,
    /// Output sections in file order.
    pub sections: Vec<PlacedSection>,
    /// `__LINKEDIT` chunk plan.
    pub linkedit: LinkeditPlan,
    /// Header + load-command bytes (the UUID field is zeroed; emit patches
    /// it after hashing).
    pub header_bytes: Vec<u8>,
    /// Byte offset of the `LC_MAIN` entryoff field inside the header bytes.
    pub entryoff_at: u64,
    /// Total file size.
    pub file_size: u64,
    /// Entry point offset within `__TEXT`.
    pub entryoff: u64,
    /// `__TEXT` vmsize (the signature's execSegLimit).
    pub text_vmsize: u64,
    /// Output symbol table in emission order.
    pub symbols: Vec<OutputSymbol>,
    /// Export trie bytes (minimal executable trie).
    pub trie: Vec<u8>,
    /// Function-starts ULEB delta stream.
    pub func_starts: Vec<u8>,
    /// String table bytes.
    pub strtab: Vec<u8>,
    /// Per-symbol `n_strx` (parallel to `symbols`).
    pub str_offsets: Vec<u32>,
    /// Fixup plan (payload, slot words, `__chain_starts` mirror bytes).
    pub fixups: FixupPlan,
}

/// One output bucket: `(segment, name, merged flags, zerofill)`.
type BucketTable = Vec<(String, String, u32, bool)>;

/// Buckets input sections by `(segment, name)`; returns the bucket table,
/// the per-file section→bucket map (`usize::MAX` = skipped) and the count
/// of chained-fixup pointer slots.
fn bucket_inputs(
    objects: &[InputObject],
    res: &Resolution,
) -> Result<(BucketTable, Vec<Vec<usize>>, usize), LinkError> {
    let mut buckets: Vec<(String, String, u32, bool)> = Vec::new(); // (seg, name, flags, zerofill)
    let mut bucket_of: Vec<Vec<usize>> = Vec::with_capacity(objects.len());
    let mut fixup_slot_count = 0usize;
    for obj in objects {
        let mut per_sect = Vec::with_capacity(obj.sections.len());
        for in_sect in &obj.sections {
            let bucket = bucket_for(in_sect, obj, &mut buckets, &mut fixup_slot_count)?;
            per_sect.push(bucket);
        }
        bucket_of.push(per_sect);
    }
    if res.definitions().any(|(_, d)| d.rank == Rank::Common)
        && !buckets
            .iter()
            .any(|(seg, name, _, _)| seg == "__DATA" && name == "__common")
    {
        buckets.push(("__DATA".into(), "__common".into(), S_ZEROFILL, true));
    }
    Ok((buckets, bucket_of, fixup_slot_count))
}

/// Classifies one input section into its output bucket.
fn bucket_for(
    in_sect: &crate::object::InputSection,
    obj: &InputObject,
    buckets: &mut BucketTable,
    fixup_slot_count: &mut usize,
) -> Result<usize, LinkError> {
    if in_sect.size == 0 {
        return Ok(usize::MAX);
    }
    let debugish = in_sect.segment.starts_with("__LLVM")
        || matches!(in_sect.segment.as_str(), "__LD" | "__DWARF");
    if debugish {
        return Ok(usize::MAX); // no load-time bytes at M1
    }
    if !matches!(
        in_sect.segment.as_str(),
        "__TEXT" | "__DATA_CONST" | "__DATA"
    ) {
        return Err(LinkError::Unsupported {
            file: obj.name.clone(),
            message: format!(
                "input section {} in segment {} (M1 buckets __TEXT/__DATA_CONST/__DATA only)",
                in_sect.name, in_sect.segment
            ),
        });
    }
    let zerofill = in_sect.zerofill || in_sect.flags & SECTION_TYPE_MASK == S_ZEROFILL;
    let name = if zerofill {
        // Zero-fill inputs and commons share the __common bucket
        // (S_ZEROFILL output; the kernel zero-fills the tail).
        "__common".to_string()
    } else {
        in_sect.name.clone()
    };
    *fixup_slot_count += in_sect
        .relocs
        .iter()
        .filter(|r| r.kind == RelocKind::Unsigned)
        .count();
    Ok(
        match buckets
            .iter()
            .position(|(seg, n, _, _)| seg == &in_sect.segment && n == &name)
        {
            Some(i) => {
                buckets[i].2 |= in_sect.flags;
                i
            }
            None => {
                buckets.push((in_sect.segment.clone(), name, in_sect.flags, zerofill));
                buckets.len() - 1
            }
        },
    )
}

/// Appends the synthesized `__chain_starts` bucket (when chains are on) and
/// applies the canonical ordering.
fn prepare_buckets(buckets: &mut BucketTable, bucket_of: &mut [Vec<usize>], chains_enabled: bool) {
    if chains_enabled {
        buckets.push(("__TEXT".into(), "__chain_starts".into(), S_REGULAR, false));
    }
    // Canonical ordering: stable sort keeps first-seen order for unknowns.
    let mut order: Vec<usize> = (0..buckets.len()).collect();
    order.sort_by_key(|&i| (canonical_rank(&buckets[i].0, &buckets[i].1), i));
    let mut rank_of = vec![0usize; buckets.len()];
    for (pos, &i) in order.iter().enumerate() {
        rank_of[i] = pos;
    }
    *buckets = order.iter().map(|&i| buckets[i].clone()).collect();
    for per_file in bucket_of.iter_mut() {
        for b in per_file.iter_mut() {
            if *b != usize::MAX {
                *b = rank_of[*b];
            }
        }
    }
}

/// Canonical rank: segments ordered TEXT < DATA_CONST < DATA; known section
/// names in the fixed canonical order; unknown names follow in first-seen
/// order (deterministic; TDD §8.4).
fn canonical_rank(segment: &str, name: &str) -> u64 {
    let seg: u64 = match segment {
        "__TEXT" => 0,
        "__DATA_CONST" => 1,
        "__DATA" => 2,
        _ => 3,
    };
    let name: u64 = match (segment, name) {
        ("__TEXT", "__text") => 0,
        ("__TEXT", "__const") => 1,
        ("__TEXT", "__cstring") => 2,
        ("__TEXT", "__chain_starts") => 3,
        ("__DATA_CONST", "__const") => 0,
        ("__DATA_CONST", "__got") => 1,
        ("__DATA", "__data") => 0,
        ("__DATA", "__bss") => 1,
        ("__DATA", "__common") => 2,
        _ => 100,
    };
    seg * 1000 + name
}

/// Placement intermediate: sections, segments, flat pieces, address tables.
struct PlacedState {
    sections: Vec<PlacedSection>,
    segments: Vec<SegmentPlan>,
    /// Flat piece list (section order, piece order within a section).
    flat: Vec<FlatPiece>,
    /// (file, input section) → output vaddr base.
    addr_of: std::collections::HashMap<(u32, usize), u64>,
    /// Interned name id → output vaddr (all resolved definitions).
    def_addr: std::collections::BTreeMap<u32, u64>,
}

/// One flat piece: output section, position within its piece list, absolute
/// vaddr, and the piece (patches resolved in place).
#[derive(Debug, Clone)]
struct FlatPiece {
    section: usize,
    piece_idx: usize,
    addr: u64,
    piece: Piece,
}

/// Lays out the image (Pass 3). See the module docs for the fixed-point
/// structure.
///
/// # Errors
/// [`LinkError::Layout`] on contract violations (header page overflow,
/// branch range), [`LinkError::Symbol`] on unresolvable references,
/// [`LinkError::Unsupported`] on M1-rejected input shapes.
pub fn layout(
    objects: &[InputObject],
    res: &Resolution,
    interner: &Interner,
    cfg: &LinkConfig,
) -> Result<Layout, LinkError> {
    // ---- bucketing ---------------------------------------------------------
    let (mut buckets, mut bucket_of, fixup_slot_count) = bucket_inputs(objects, res)?;
    let chains_enabled = cfg.fixup_chains && fixup_slot_count > 0;
    prepare_buckets(&mut buckets, &mut bucket_of, chains_enabled);

    // ---- commons (name-sorted for deterministic allocation) ----------------
    let mut commons: Vec<(StringId, &Def)> = res
        .definitions()
        .filter(|(_, d)| d.rank == Rank::Common)
        .collect();
    commons.sort_by(|a, b| interner.bytes(a.0).cmp(interner.bytes(b.0)));

    // ---- placement fixed-point loop -----------------------------------------
    let mut chain_starts_size = 8usize;
    let mut converged: Option<PlacedState> = None;
    let mut final_plan: Option<FixupPlan> = None;
    for _ in 0..4 {
        let mut state = place(
            cfg,
            objects,
            &buckets,
            &bucket_of,
            &commons,
            chain_starts_size,
        )?;
        resolve_all(objects, &mut state, res, interner)?;
        let mut slots: Vec<FixupSlot> = Vec::new();
        for fp in &state.flat {
            for (off, value) in &fp.piece.fixup_slots {
                slots.push(FixupSlot {
                    vaddr: fp.addr + u64::from(*off),
                    target_vaddr: *value,
                });
            }
        }
        let segs: Vec<(u64, u64, u64)> = state
            .segments
            .iter()
            .map(|s| (s.vmaddr, s.vmsize, s.fileoff))
            .collect();
        let plan = plan_fixups(slots, &segs, PAGEZERO_SIZE_64, PAGE_SIZE_16K)?;
        let actual = if chains_enabled {
            plan.chain_starts.len()
        } else {
            0
        };
        if actual == chain_starts_size {
            // Converged: patch the section size (it equals the assumption).
            if let Some(cs) = state
                .sections
                .iter_mut()
                .find(|s| s.name == "__chain_starts")
            {
                cs.size = actual as u64;
            }
            final_plan = Some(plan);
            converged = Some(state);
            break;
        }
        chain_starts_size = actual;
    }
    let mut state = converged.ok_or(LinkError::Internal {
        message: "layout fixed point did not converge in 4 iterations".into(),
    })?;
    let fixups = final_plan.ok_or(LinkError::Internal {
        message: "fixup plan missing after convergence".into(),
    })?;

    // ---- symbol table ---------------------------------------------------------
    let symbols = build_symtab(
        objects,
        res,
        interner,
        &state.sections,
        &state.addr_of,
        &commons,
    );
    let n_locals = symbols.iter().filter(|s| !s.external).count();
    let n_defs = symbols.iter().filter(|s| s.external).count();

    // ---- string table (dedup by interned name, emission order) ----------------
    let mut strtab: Vec<u8> = vec![0];
    let mut str_by_id: std::collections::BTreeMap<u32, u32> = std::collections::BTreeMap::new();
    for sym in &symbols {
        str_by_id.entry(sym.name.0).or_insert_with(|| {
            let o = strtab.len() as u32;
            strtab.extend_from_slice(interner.bytes(sym.name));
            strtab.push(0);
            o
        });
    }

    // Per-symbol string-table offsets (emit writes n_strx from these).
    let str_offsets: Vec<u32> = symbols.iter().map(|sym| str_by_id[&sym.name.0]).collect();

    // ---- function starts ---------------------------------------------------------
    let func_starts = build_func_starts(&state.sections, &symbols);

    // ---- minimal export trie -----------------------------------------------------
    let trie = build_minimal_trie();

    // ---- entry --------------------------------------------------------------------
    let entry_id = interner
        .lookup(cfg.entry_symbol.as_bytes())
        .ok_or(LinkError::Symbol {
            name: cfg.entry_symbol.clone(),
            message: format!(
                "entry symbol \"{}\" is not defined by any input",
                cfg.entry_symbol
            ),
        })?;
    let entry_vaddr = state
        .def_addr
        .get(&entry_id.0)
        .copied()
        .ok_or(LinkError::Symbol {
            name: cfg.entry_symbol.clone(),
            message: format!(
                "entry symbol \"{}\" is not defined by any input",
                cfg.entry_symbol
            ),
        })?;
    let entryoff = entry_vaddr - PAGEZERO_SIZE_64;

    // ---- __LINKEDIT chunks + signature sizing --------------------------------------
    let fixup_payload_size = if fixups.slot_count > 0 && cfg.fixup_chains {
        fixups.payload.len()
    } else {
        0
    };
    let le_idx = state
        .segments
        .iter()
        .position(|s| s.name == "__LINKEDIT")
        .ok_or(LinkError::Internal {
            message: "no __LINKEDIT segment".into(),
        })?;
    let mut cur = state.segments[le_idx].fileoff;
    let take = |size: usize, align: u64, cur: &mut u64| {
        *cur = cur.div_ceil(align) * align;
        let at = *cur;
        *cur += size as u64;
        at
    };
    let fixup_payload_off = if fixup_payload_size > 0 {
        take(fixup_payload_size, 8, &mut cur)
    } else {
        0
    };
    let trie_off = take(trie.len(), 4, &mut cur);
    let func_off = if func_starts.is_empty() {
        0
    } else {
        take(func_starts.len(), 4, &mut cur)
    };
    let sym_off = take(symbols.len() * 16, 8, &mut cur);
    let str_off = take(strtab.len(), 8, &mut cur);
    let (sig_off, sig_size, file_size) = if cfg.adhoc {
        let aligned = cur.div_ceil(16) * 16;
        let nblocks = aligned.div_ceil(4096);
        let ident_padded = align_up_usize(cfg.ident.len() + 1, 4);
        let dir_len = 88 + ident_padded + (nblocks as usize) * 32;
        let blob = align_up_usize(12 + 8 + dir_len, 8) as u64;
        (aligned, blob, aligned + blob)
    } else {
        (0, 0, cur)
    };

    // __LINKEDIT covers through EOF (§8: verifier asserts this).
    let le_size = file_size - state.segments[le_idx].fileoff;
    state.segments[le_idx].filesize = le_size;
    state.segments[le_idx].vmsize =
        le_size.max(PAGE_SIZE_16K).div_ceil(PAGE_SIZE_16K) * PAGE_SIZE_16K;
    let text_vmsize = state
        .segments
        .iter()
        .find(|s| s.name == "__TEXT")
        .map(|s| s.vmsize)
        .unwrap_or(0);

    // ---- header + load commands -----------------------------------------------------
    let header_inputs = HeaderInputs {
        sym_off,
        nsyms: symbols.len(),
        str_off,
        strsize: strtab.len(),
        n_locals,
        n_defs,
        fixup_off: fixup_payload_off,
        fixup_size: fixup_payload_size,
        trie_off,
        trie_len: trie.len(),
        func_off,
        func_len: func_starts.len(),
        sig_off,
        sig_size,
        entryoff,
    };
    let (header_bytes, uuid_at, entryoff_at) =
        build_header(cfg, &state.segments, &state.sections, &header_inputs)?;

    Ok(Layout {
        ident: cfg.ident.clone(),
        segments: state.segments,
        sections: state.sections,
        linkedit: LinkeditPlan {
            fixup_payload_off,
            fixup_payload_size,
            trie_off,
            trie_size: trie.len(),
            func_starts_off: func_off,
            func_starts_size: func_starts.len(),
            sym_off,
            sym_size: symbols.len() * 16,
            str_off,
            str_size: strtab.len(),
            uuid_at,
            sig_off,
            sig_size,
        },
        header_bytes,
        entryoff_at,
        file_size,
        entryoff,
        text_vmsize,
        symbols,
        trie,
        func_starts,
        strtab,
        str_offsets,
        fixups,
    })
}

/// Builds the per-bucket piece lists (offsets assigned later by `place`).
fn build_bucket_pieces(
    objects: &[InputObject],
    buckets: &BucketTable,
    bucket_of: &[Vec<usize>],
    commons: &[(StringId, &Def)],
) -> Result<Vec<Vec<Piece>>, LinkError> {
    let mut pieces_of_bucket: Vec<Vec<Piece>> = vec![Vec::new(); buckets.len()];
    for obj in objects {
        for (si, in_sect) in obj.sections.iter().enumerate() {
            let bi = bucket_of
                .get(obj.file.0 as usize)
                .and_then(|v| v.get(si))
                .copied();
            let Some(bi) = bi else { continue };
            if bi == usize::MAX {
                continue;
            }
            pieces_of_bucket[bi].push(Piece {
                file: obj.file,
                in_sect: si,
                in_range: in_sect.data.clone(),
                offset: 0,
                size: in_sect.size,
                align_log2: in_sect.align_log2,
                zerofill: false,
                common_name: None,
                patches: Vec::new(),
                fixup_slots: Vec::new(),
            });
        }
    }
    // Commons as zero-fill pieces (caller passes name-sorted order).
    for (id, def) in commons {
        let Some(bi) = buckets
            .iter()
            .position(|(seg, name, _, _)| seg == "__DATA" && name == "__common")
        else {
            return Err(LinkError::Internal {
                message: "__common bucket missing although commons exist".into(),
            });
        };
        pieces_of_bucket[bi].push(Piece {
            file: def.file,
            in_sect: usize::MAX,
            in_range: 0..0,
            offset: 0,
            size: def.common_size,
            align_log2: def.common_align,
            zerofill: true,
            common_name: Some(*id),
            patches: Vec::new(),
            fixup_slots: Vec::new(),
        });
    }
    Ok(pieces_of_bucket)
}

/// Places every output section and packs segments (§8).
fn place(
    cfg: &LinkConfig,
    objects: &[InputObject],
    buckets: &BucketTable,
    bucket_of: &[Vec<usize>],
    commons: &[(StringId, &Def)],
    chain_starts_size: usize,
) -> Result<PlacedState, LinkError> {
    let mut pieces_of_bucket = build_bucket_pieces(objects, buckets, bucket_of, commons)?;

    // ---- piece offsets within each output section --------------------------
    let mut sections: Vec<PlacedSection> = Vec::with_capacity(buckets.len());
    for (bi, (seg_name, name, flags, zerofill)) in buckets.iter().enumerate() {
        let mut cursor = 0u64;
        let mut max_align = 0u32;
        let mut pieces = core::mem::take(&mut pieces_of_bucket[bi]);
        for p in &mut pieces {
            max_align = max_align.max(p.align_log2);
            cursor = align_up_u64(cursor, 1u64 << p.align_log2);
            p.offset = cursor;
            cursor += p.size;
        }
        let (align, size) = if name == "__chain_starts" {
            (2u32, chain_starts_size as u64)
        } else {
            (max_align, cursor)
        };
        sections.push(PlacedSection {
            name: name.clone(),
            seg_name: seg_name.clone(),
            flags: if name == "__chain_starts" {
                S_REGULAR
            } else {
                *flags
            },
            align_log2: align,
            vm_addr: 0,
            size,
            file_off: 0,
            zerofill: *zerofill && name != "__chain_starts",
            pieces,
        });
    }

    // ---- sizeofcmds (computed before placement so __TEXT starts right) -----
    // Shared with `build_header` (one formula, one source of truth).
    let nsections = sections.iter().filter(|s| s.size > 0).count();
    let chains_on = sections.iter().any(|s| s.name == "__chain_starts");
    let sizeofcmds = command_size(cfg, nsections, chains_on);
    let header_len = 32 + sizeofcmds;
    if header_len as u64 > PAGE_SIZE_16K {
        return Err(LinkError::Layout {
            message: format!(
                "header and load commands ({header_len} bytes) exceed the 16 KiB first page \
                 (TDD §8.1 rule 7)"
            ),
        });
    }

    // ---- segment packing (§8) ----------------------------------------------
    let mut segments: Vec<SegmentPlan> = Vec::new();
    segments.push(SegmentPlan {
        name: "__PAGEZERO".into(),
        vmaddr: 0,
        vmsize: PAGEZERO_SIZE_64,
        fileoff: 0,
        filesize: 0,
        maxprot: 0,
        initprot: 0,
        sections: Vec::new(),
    });

    for seg_name in ["__TEXT", "__DATA_CONST", "__DATA"] {
        let (maxprot, initprot) = match seg_name {
            "__TEXT" => (
                VM_PROT_READ | VM_PROT_EXECUTE,
                VM_PROT_READ | VM_PROT_EXECUTE,
            ),
            _ => (VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE),
        };
        let prev_end = segments
            .last()
            .map(|s| s.fileoff + s.vmsize)
            .unwrap_or(PAGE_SIZE_16K);
        let seg_fileoff = if seg_name == "__TEXT" {
            0
        } else {
            align_up_u64(prev_end, PAGE_SIZE_16K)
        };
        // VM and file cursors move in lockstep under the constant-delta
        // contract (`vmaddr = fileoff + PAGEZERO`); zero-fill sections
        // advance VM only (§8.1 rule 5).
        let mut cursor = if seg_name == "__TEXT" {
            align_up_u64(header_len as u64, 8)
        } else {
            seg_fileoff
        };
        let mut file_end = cursor;
        let mut sects: Vec<usize> = Vec::new();
        for (i, s) in sections.iter_mut().enumerate() {
            if s.seg_name != seg_name || s.size == 0 {
                continue;
            }
            cursor = align_up_u64(cursor, 1u64 << s.align_log2);
            s.vm_addr = cursor + PAGEZERO_SIZE_64;
            if s.zerofill {
                s.file_off = 0;
            } else {
                s.file_off = cursor;
            }
            cursor += s.size;
            if !s.zerofill {
                file_end = cursor;
            }
            sects.push(i);
        }
        let vmsize = align_up_u64(cursor - seg_fileoff, PAGE_SIZE_16K).max(PAGE_SIZE_16K);
        segments.push(SegmentPlan {
            name: seg_name.into(),
            vmaddr: seg_fileoff + PAGEZERO_SIZE_64,
            vmsize,
            fileoff: seg_fileoff,
            filesize: file_end - seg_fileoff,
            maxprot,
            initprot,
            sections: sects,
        });
    }
    let prev_end = segments.last().map(|s| s.fileoff + s.vmsize).unwrap_or(0);
    let le_fileoff = align_up_u64(prev_end.max(PAGE_SIZE_16K), PAGE_SIZE_16K);
    segments.push(SegmentPlan {
        name: "__LINKEDIT".into(),
        vmaddr: le_fileoff + PAGEZERO_SIZE_64,
        vmsize: 0,
        fileoff: le_fileoff,
        filesize: 0,
        maxprot: VM_PROT_READ,
        initprot: VM_PROT_READ,
        sections: Vec::new(),
    });

    // ---- flat pieces + address tables ---------------------------------------
    let mut flat: Vec<FlatPiece> = Vec::new();
    let mut addr_of: std::collections::HashMap<(u32, usize), u64> =
        std::collections::HashMap::new();
    let mut def_addr: std::collections::BTreeMap<u32, u64> = std::collections::BTreeMap::new();
    for (si, s) in sections.iter().enumerate() {
        for (pi, p) in s.pieces.iter().enumerate() {
            let addr = s.vm_addr + p.offset;
            flat.push(FlatPiece {
                section: si,
                piece_idx: pi,
                addr,
                piece: p.clone(),
            });
            if !p.zerofill {
                addr_of.insert((p.file.0, p.in_sect), addr);
            }
            if let Some(id) = p.common_name {
                def_addr.insert(id.0, addr);
            }
        }
    }
    Ok(PlacedState {
        sections,
        segments,
        flat,
        addr_of,
        def_addr,
    })
}

/// Resolves every piece's patches and fixup slots against placed addresses.
fn resolve_all(
    objects: &[InputObject],
    state: &mut PlacedState,
    res: &Resolution,
    interner: &Interner,
) -> Result<(), LinkError> {
    // Definition addresses: commons already resolved; add section defs.
    let mut def_addr: std::collections::BTreeMap<u32, u64> = state.def_addr.clone();
    for (id, def) in res.definitions() {
        if let Some(sect) = def.section {
            let base =
                state
                    .addr_of
                    .get(&(def.file.0, sect))
                    .copied()
                    .ok_or(LinkError::Internal {
                        message: "defining section was not placed".into(),
                    })?;
            def_addr.insert(id.0, base + def.value);
        }
    }

    for fp_idx in 0..state.flat.len() {
        let (file, in_sect_idx, addr, zerofill) = {
            let fp = &state.flat[fp_idx];
            (fp.piece.file, fp.piece.in_sect, fp.addr, fp.piece.zerofill)
        };
        if zerofill {
            continue;
        }
        let obj = objects.get(file.0 as usize).ok_or(LinkError::Internal {
            message: "piece file missing".into(),
        })?;
        let in_sect = &obj.sections[in_sect_idx];
        let mut patches: Vec<PatchOp> = Vec::new();
        let mut slots: Vec<(u32, u64)> = Vec::new();
        let space = AddrSpace {
            addr_of: &state.addr_of,
            def_addr: &def_addr,
            interner,
        };
        for r in &in_sect.relocs {
            resolve_reloc(obj, in_sect, r, addr, &space, &mut patches, &mut slots)?;
        }
        state.flat[fp_idx].piece.patches = patches;
        state.flat[fp_idx].piece.fixup_slots = slots;
    }
    // Sync the resolved state back into the section view (Pass 4 reads
    // `sections[*].pieces`).
    for fp in &state.flat {
        let s = &mut state.sections[fp.section];
        s.pieces[fp.piece_idx].patches = fp.piece.patches.clone();
        s.pieces[fp.piece_idx].fixup_slots = fp.piece.fixup_slots.clone();
    }
    state.def_addr = def_addr;
    Ok(())
}

/// Borrowed view of the address space resolution reads (Pass 3 scratch).
struct AddrSpace<'a> {
    /// (file, input section) → output vaddr base.
    addr_of: &'a std::collections::HashMap<(u32, usize), u64>,
    /// Interned name id → output vaddr.
    def_addr: &'a std::collections::BTreeMap<u32, u64>,
    /// Name bytes for diagnostics.
    interner: &'a Interner,
}

/// Resolves one relocation into a static patch or a fixup slot.
fn resolve_reloc(
    obj: &InputObject,
    in_sect: &crate::object::InputSection,
    r: &crate::object::DecodedReloc,
    piece_addr: u64,
    space: &AddrSpace<'_>,
    patches: &mut Vec<PatchOp>,
    slots: &mut Vec<(u32, u64)>,
) -> Result<(), LinkError> {
    let slot_v = piece_addr + u64::from(r.offset);
    match r.kind {
        RelocKind::Unsigned => {
            let target = lookup(obj, r.target, space)?;
            let at = in_sect.data.start as usize + r.offset as usize;
            let addend = read_slot_i64(&obj.bytes, at)?;
            let value = (target as i64)
                .checked_add(addend)
                .ok_or(LinkError::Layout {
                    message: "fixup target overflow".into(),
                })?;
            slots.push((r.offset, value as u64));
        }
        RelocKind::Page21 { addend } => {
            let target = lookup(obj, r.target, space)?
                .checked_add_signed(addend)
                .ok_or(LinkError::Internal {
                    message: "page21 target overflow".into(),
                })?;
            let page_delta = ((target as i64) >> 12) - ((slot_v as i64) >> 12);
            patches.push(PatchOp::Adrp {
                in_offset: r.offset,
                page_delta,
            });
        }
        RelocKind::PageOff12 { addend } => {
            let target = lookup(obj, r.target, space)?
                .checked_add_signed(addend)
                .ok_or(LinkError::Internal {
                    message: "pageoff12 target overflow".into(),
                })?;
            patches.push(PatchOp::PageOff12 {
                in_offset: r.offset,
                imm12: (target & 0xFFF) as u32,
            });
        }
        RelocKind::Branch26 => {
            let target = lookup(obj, r.target, space)?;
            let delta = (target as i64) - (slot_v as i64);
            if delta.abs() > 0x0800_0000 {
                return Err(LinkError::Layout {
                    message: format!(
                        "branch at {slot_v:#x} to {target:#x} exceeds the ±128 MiB arm64 \
                         range by {delta:#x} (veneers arrive at M5)"
                    ),
                });
            }
            if delta % 4 != 0 {
                return Err(LinkError::Internal {
                    message: "branch target not 4-aligned".into(),
                });
            }
            patches.push(PatchOp::Branch26 {
                in_offset: r.offset,
                pc: slot_v,
                delta,
            });
        }
        RelocKind::Subtractor { minuend } => {
            let minuend_v = lookup(obj, minuend, space)?;
            let subtrahend_v = lookup(obj, r.target, space)?;
            let at = in_sect.data.start as usize + r.offset as usize;
            let addend = read_slot_i64(&obj.bytes, at)?;
            patches.push(PatchOp::Write64 {
                in_offset: r.offset,
                value: (minuend_v as i64)
                    .wrapping_sub(subtrahend_v as i64)
                    .wrapping_add(addend) as u64,
            });
        }
    }
    Ok(())
}

/// Reads the 8-byte slot addend at `at` (the classic Mach-O in-data addend).
fn read_slot_i64(bytes: &[u8], at: usize) -> Result<i64, LinkError> {
    bytes
        .get(at..at + 8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(i64::from_le_bytes)
        .ok_or(LinkError::Internal {
            message: "pointer slot out of input bounds".into(),
        })
}

/// Looks up a relocation target (extern or local section).
fn lookup(obj: &InputObject, target: RelocTarget, space: &AddrSpace<'_>) -> Result<u64, LinkError> {
    match target {
        RelocTarget::Extern(id) => space.def_addr.get(&id.0).copied().ok_or(LinkError::Symbol {
            name: space.interner.name(id),
            message: format!(
                "undefined symbol \"{}\" (referenced from {})",
                space.interner.name(id),
                obj.name
            ),
        }),
        RelocTarget::Section(idx) => {
            space
                .addr_of
                .get(&(obj.file.0, idx))
                .copied()
                .ok_or(LinkError::Internal {
                    message: format!("local section {idx} of {} was not placed", obj.name),
                })
        }
    }
}

/// Builds the output symbol table: locals (file order), ext defs (file
/// order), commons (name order); `n_sect` remapped to output sections.
fn build_symtab(
    objects: &[InputObject],
    res: &Resolution,
    interner: &Interner,
    sections: &[PlacedSection],
    addr_of: &std::collections::HashMap<(u32, usize), u64>,
    commons: &[(StringId, &Def)],
) -> Vec<OutputSymbol> {
    // Output section lookup by (file, input section): (index, base).
    let mut sect_of: std::collections::HashMap<(u32, usize), usize> =
        std::collections::HashMap::new();
    for (si, s) in sections.iter().enumerate() {
        for p in &s.pieces {
            if !p.zerofill {
                sect_of.insert((p.file.0, p.in_sect), si);
            }
        }
    }
    let mut out: Vec<OutputSymbol> = Vec::new();

    // Locals: file order, symbol order; stabs skipped; non-section locals
    // pass through as absolute.
    for obj in objects {
        for sym in &obj.symbols {
            if sym.stab || sym.external {
                continue;
            }
            match sym
                .section
                .and_then(|sect| addr_of.get(&(obj.file.0, sect)).copied())
            {
                Some(base) => {
                    let osect = sym
                        .section
                        .and_then(|sect| sect_of.get(&(obj.file.0, sect)).copied());
                    out.push(OutputSymbol {
                        name: sym.name,
                        n_type: N_SECT,
                        n_sect: osect.map_or(0, |i| (i + 1) as u8),
                        n_desc: 0,
                        value: base + sym.value,
                        external: false,
                    });
                }
                None => out.push(OutputSymbol {
                    name: sym.name,
                    n_type: N_ABS,
                    n_sect: 0,
                    n_desc: 0,
                    value: sym.value,
                    external: false,
                }),
            }
        }
    }
    // Ext defs (section-defined) in (file, sym) order.
    let mut defs: Vec<(&Def, StringId)> = res
        .definitions()
        .filter(|(_, d)| d.section.is_some())
        .map(|(id, d)| (d, id))
        .collect();
    defs.sort_by_key(|(d, _)| (d.file, d.sym));
    for (def, id) in defs {
        let Some(sect) = def.section else { continue };
        let Some(&base) = addr_of.get(&(def.file.0, sect)) else {
            continue;
        };
        let osect = sect_of
            .get(&(def.file.0, sect))
            .copied()
            .unwrap_or(usize::MAX);
        out.push(OutputSymbol {
            name: id,
            n_type: N_EXT | N_SECT,
            n_sect: if osect == usize::MAX {
                0
            } else {
                (osect + 1) as u8
            },
            n_desc: if def.weak { N_WEAK_DEF } else { 0 },
            value: base + def.value,
            external: true,
        });
    }
    // Commons: name-sorted (the allocation order); address from the
    // __common section layout via the piece's `common_name`.
    let common_sect = sections
        .iter()
        .position(|s| s.seg_name == "__DATA" && s.name == "__common");
    for (id, _def) in commons {
        let Some(ci) = common_sect else { continue };
        let Some(piece) = sections[ci]
            .pieces
            .iter()
            .find(|p| p.common_name == Some(*id))
        else {
            continue;
        };
        out.push(OutputSymbol {
            name: *id,
            n_type: N_EXT | N_SECT,
            n_sect: (ci + 1) as u8,
            n_desc: 0,
            value: sections[ci].vm_addr + piece.offset,
            external: true,
        });
    }
    let _ = interner;
    out
}

/// Function-starts ULEB delta stream over `__TEXT,__text` symbols.
fn build_func_starts(sections: &[PlacedSection], symbols: &[OutputSymbol]) -> Vec<u8> {
    let Some(t) = sections
        .iter()
        .position(|s| s.seg_name == "__TEXT" && s.name == "__text")
    else {
        return Vec::new();
    };
    let base = sections[t].vm_addr;
    let mut starts: Vec<u64> = symbols
        .iter()
        .filter(|s| s.n_sect == (t + 1) as u8 && s.value >= base)
        .map(|s| s.value - base)
        .collect();
    starts.sort_unstable();
    starts.dedup();
    let mut out = Vec::with_capacity(starts.len() * 2);
    for v in starts {
        out.extend_from_slice(&uleb(v));
    }
    out
}

/// ULEB128 encoding.
#[must_use]
pub fn uleb(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
    out
}

/// Minimal export trie: executables export `__mh_execute_header` (image
/// offset 0).
fn build_minimal_trie() -> Vec<u8> {
    vec![2, 0, 0, 0]
}

/// Assembles header + load commands. Returns `(bytes, uuid_at, entryoff_at)`.
/// `__LINKEDIT` chunk positions the header references.
struct HeaderInputs {
    /// LC_SYMTAB: file offset, entry count.
    sym_off: u64,
    nsyms: usize,
    /// LC_SYMTAB string table: file offset, byte size.
    str_off: u64,
    strsize: usize,
    /// LC_DYLD_CHAINED_FIXUPS payload (0 size = absent).
    fixup_off: u64,
    fixup_size: usize,
    /// LC_DYLD_EXPORTS_TRIE.
    trie_off: u64,
    trie_len: usize,
    /// LC_FUNCTION_STARTS.
    func_off: u64,
    func_len: usize,
    /// LC_CODE_SIGNATURE (0 size = absent).
    sig_off: u64,
    sig_size: u64,
    /// LC_DYSYMTAB subranges.
    n_locals: usize,
    n_defs: usize,
    /// LC_MAIN entry offset within `__TEXT`.
    entryoff: u64,
}

fn build_header(
    cfg: &LinkConfig,
    segments: &[SegmentPlan],
    sections: &[PlacedSection],
    hi: &HeaderInputs,
) -> Result<(Vec<u8>, u64, u64), LinkError> {
    let dylinker_len = align8(12 + "/usr/lib/dyld\0".len());
    let fixup_lc = if hi.fixup_size > 0 { 16 } else { 0 };
    let ncmds: u32 = 5
        + 1
        + u32::from(cfg.dynamic_linker)
        + 1 // LC_MAIN
        + 1 // LC_SYMTAB
        + 1 // LC_DYSYMTAB
        + u32::from(fixup_lc > 0)
        + 1 // LC_DYLD_EXPORTS_TRIE
        + 1 // LC_FUNCTION_STARTS
        + 1 // LC_UUID
        + u32::from(cfg.adhoc);
    let nsections: usize = sections.iter().filter(|s| s.size > 0).count();
    let sizeofcmds = command_size(cfg, nsections, fixup_lc > 0);
    debug_assert_eq!(
        32 + sizeofcmds,
        32 + 72 * 5
            + 80 * nsections
            + 32
            + if cfg.dynamic_linker { dylinker_len } else { 0 }
            + 24
            + 24
            + 80
            + fixup_lc
            + 16 // LC_DYLD_EXPORTS_TRIE
            + 16 // LC_FUNCTION_STARTS
            + 24 // LC_UUID
            + if cfg.adhoc { 16 } else { 0 }, // LC_CODE_SIGNATURE
        "sizing formula drift"
    );
    let mut buf = vec![0u8; 32 + sizeofcmds];
    let w32 = |buf: &mut [u8], at: usize, v: u32| buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let w64 = |buf: &mut [u8], at: usize, v: u64| buf[at..at + 8].copy_from_slice(&v.to_le_bytes());

    w32(&mut buf, 0, pgr_format::consts::MH_MAGIC_64);
    w32(&mut buf, 4, pgr_format::consts::CPU_TYPE_ARM64);
    w32(&mut buf, 8, pgr_format::consts::CPU_SUBTYPE_ARM64_ALL);
    w32(&mut buf, 12, pgr_format::consts::MH_EXECUTE);
    w32(&mut buf, 16, ncmds);
    w32(&mut buf, 20, sizeofcmds as u32);
    w32(
        &mut buf,
        24,
        pgr_format::consts::MH_NOUNDEFS
            | pgr_format::consts::MH_DYLDLINK
            | pgr_format::consts::MH_TWOLEVEL
            | pgr_format::consts::MH_PIE,
    );

    let mut lc = 32usize;
    for seg in segments {
        let seg_sects: Vec<&PlacedSection> = seg
            .sections
            .iter()
            .filter_map(|&i| sections.get(i))
            .filter(|s| s.size > 0)
            .collect();
        w32(&mut buf, lc, pgr_format::consts::LC_SEGMENT_64);
        w32(&mut buf, lc + 4, (72 + 80 * seg_sects.len()) as u32);
        buf[lc + 8..lc + 24].copy_from_slice(&pad16(seg.name.as_bytes()));
        w64(&mut buf, lc + 24, seg.vmaddr);
        w64(&mut buf, lc + 32, seg.vmsize);
        w64(&mut buf, lc + 40, seg.fileoff);
        w64(&mut buf, lc + 48, seg.filesize);
        w32(&mut buf, lc + 56, seg.maxprot);
        w32(&mut buf, lc + 60, seg.initprot);
        w32(&mut buf, lc + 64, seg_sects.len() as u32);
        w32(&mut buf, lc + 68, 0);
        lc += 72;
        for s in seg_sects {
            let mut sect = [0u8; 80];
            sect[0..16].copy_from_slice(&pad16(s.name.as_bytes()));
            sect[16..32].copy_from_slice(&pad16(seg.name.as_bytes()));
            w64(&mut sect, 32, s.vm_addr);
            w64(&mut sect, 40, s.size);
            w32(&mut sect, 48, s.file_off as u32);
            w32(&mut sect, 52, s.align_log2);
            w32(&mut sect, 56, 0); // no output relocations
            w32(&mut sect, 60, 0);
            w32(&mut sect, 64, s.flags);
            buf[lc..lc + 80].copy_from_slice(&sect);
            lc += 80;
        }
    }
    // LC_BUILD_VERSION (one ld tool entry).
    w32(&mut buf, lc, pgr_format::consts::LC_BUILD_VERSION);
    w32(&mut buf, lc + 4, 32);
    w32(&mut buf, lc + 8, cfg.platform);
    w32(&mut buf, lc + 12, cfg.minos);
    w32(&mut buf, lc + 16, cfg.sdk);
    w32(&mut buf, lc + 20, 1);
    w32(&mut buf, lc + 24, pgr_format::consts::TOOL_LD);
    w32(&mut buf, lc + 28, 0x000f_0200);
    lc += 32;
    if cfg.dynamic_linker {
        w32(&mut buf, lc, pgr_format::consts::LC_LOAD_DYLINKER);
        w32(&mut buf, lc + 4, dylinker_len as u32);
        w32(&mut buf, lc + 8, 12);
        buf[lc + 12..lc + 12 + "/usr/lib/dyld\0".len()].copy_from_slice(b"/usr/lib/dyld\0");
        lc += dylinker_len;
    }
    w32(&mut buf, lc, pgr_format::consts::LC_MAIN);
    w32(&mut buf, lc + 4, 24);
    let entryoff_at = lc + 8;
    w64(&mut buf, entryoff_at, hi.entryoff);
    w64(&mut buf, lc + 16, 0); // stacksize
    lc += 24;
    w32(&mut buf, lc, pgr_format::consts::LC_SYMTAB);
    w32(&mut buf, lc + 4, 24);
    w32(&mut buf, lc + 8, hi.sym_off as u32);
    w32(&mut buf, lc + 12, hi.nsyms as u32);
    w32(&mut buf, lc + 16, hi.str_off as u32);
    w32(&mut buf, lc + 20, hi.strsize as u32);
    lc += 24;
    w32(&mut buf, lc, pgr_format::consts::LC_DYSYMTAB);
    w32(&mut buf, lc + 4, 80);
    w32(&mut buf, lc + 8, 0); // ilocalsym
    w32(&mut buf, lc + 12, hi.n_locals as u32);
    w32(&mut buf, lc + 16, hi.n_locals as u32); // iextdefsym
    w32(&mut buf, lc + 20, hi.n_defs as u32);
    w32(&mut buf, lc + 24, (hi.n_locals + hi.n_defs) as u32); // iundefsym
    w32(&mut buf, lc + 28, 0); // nundefsym (static: none remain)
    lc += 80;
    if fixup_lc > 0 {
        w32(&mut buf, lc, pgr_format::consts::LC_DYLD_CHAINED_FIXUPS);
        w32(&mut buf, lc + 4, 16);
        w32(&mut buf, lc + 8, hi.fixup_off as u32);
        w32(&mut buf, lc + 12, hi.fixup_size as u32);
        lc += 16;
    }
    w32(&mut buf, lc, pgr_format::consts::LC_DYLD_EXPORTS_TRIE);
    w32(&mut buf, lc + 4, 16);
    w32(&mut buf, lc + 8, hi.trie_off as u32);
    w32(&mut buf, lc + 12, hi.trie_len as u32);
    lc += 16;
    w32(&mut buf, lc, pgr_format::consts::LC_FUNCTION_STARTS);
    w32(&mut buf, lc + 4, 16);
    w32(&mut buf, lc + 8, hi.func_off as u32);
    w32(&mut buf, lc + 12, hi.func_len as u32);
    lc += 16;
    let uuid_at = lc + 8;
    w32(&mut buf, lc, pgr_format::consts::LC_UUID);
    w32(&mut buf, lc + 4, 24);
    lc += 24;
    if cfg.adhoc {
        w32(&mut buf, lc, pgr_format::consts::LC_CODE_SIGNATURE);
        w32(&mut buf, lc + 4, 16);
        w32(&mut buf, lc + 8, hi.sig_off as u32);
        w32(&mut buf, lc + 12, hi.sig_size as u32);
        lc += 16;
    }
    debug_assert_eq!(lc, buf.len(), "load command assembly must match sizing");
    Ok((buf, uuid_at as u64, entryoff_at as u64))
}

/// 16-byte NUL-padded name.
fn pad16(name: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = name.len().min(16);
    out[..n].copy_from_slice(&name[..n]);
    out
}

/// The exact `sizeofcmds` for the M1 command set — the single source of
/// truth shared by `place` (section start math) and `build_header`.
fn command_size(cfg: &LinkConfig, nsections: usize, fixup_lc: bool) -> usize {
    let dylinker_len = if cfg.dynamic_linker {
        align8(12 + "/usr/lib/dyld\0".len())
    } else {
        0
    };
    72 * 5
        + 80 * nsections
        + 32 // LC_BUILD_VERSION
        + dylinker_len
        + 24 // LC_MAIN
        + 24 // LC_SYMTAB
        + 80 // LC_DYSYMTAB
        + usize::from(fixup_lc) * 16 // LC_DYLD_CHAINED_FIXUPS
        + 16 // LC_DYLD_EXPORTS_TRIE
        + 16 // LC_FUNCTION_STARTS
        + 24 // LC_UUID
        + usize::from(cfg.adhoc) * 16 // LC_CODE_SIGNATURE
}

fn align8(v: usize) -> usize {
    v.div_ceil(8) * 8
}

fn align_up_usize(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

fn align_up_u64(v: u64, a: u64) -> u64 {
    v.div_ceil(a) * a
}

#[cfg(test)]
mod tests {
    use super::{canonical_rank, uleb};

    #[test]
    fn canonical_order_is_fixed() {
        assert!(canonical_rank("__TEXT", "__text") < canonical_rank("__TEXT", "__cstring"));
        assert!(canonical_rank("__TEXT", "__cstring") < canonical_rank("__DATA", "__data"));
        assert_eq!(
            canonical_rank("__DATA", "__some_unknown"),
            canonical_rank("__DATA", "__another_unknown")
        );
    }

    #[test]
    fn uleb_encoding_matches_llvm() {
        assert_eq!(uleb(0), vec![0x00]);
        assert_eq!(uleb(127), vec![0x7f]);
        assert_eq!(uleb(128), vec![0x80, 0x01]);
        assert_eq!(uleb(0x1234), vec![0xb4, 0x24]);
    }
}

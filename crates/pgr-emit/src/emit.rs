//! Pass 4 — emit (TDD §5): the output buffer is allocated once with the
//! final size; sections copy their input bytes into disjoint ranges, apply
//! relocations in place, then the chained-fixup words land in their slots
//! and the `__LINKEDIT` chunks are assembled. Deterministic by construction:
//! the whole image is a pure function of the plan and the inputs.
//!
//! Two bodies share this module's chunk builders:
//!
//! * [`build_image`] — the M1–M3 **reference**: five serial sub-passes over
//!   the buffer. Kept verbatim: the M4 correctness gate is byte-identity
//!   against this function (architecture doc §10.3 row M4).
//! * `pgr_emit::tile::build_image_fused` — the M4 **fused tile emit**: one
//!   parallel pass over 16 KiB tiles (copy runs → patches → chain words →
//!   blobs → page hashes), perf doc §4.4.

use crate::EmitError;
use crate::reloc;
use crate::signature;
use pgr_core::PatchOp;
use pgr_core::layout::Layout;
use pgr_core::object::InputObject;

/// Builds the complete output image bytes from the layout plan.
///
/// # Errors
/// [`EmitError::Contract`] on operand/plan inconsistencies;
/// [`EmitError::Internal`] on buffer indexing bugs.
pub fn build_image(layout: &Layout, objects: &[InputObject]) -> Result<Vec<u8>, EmitError> {
    let mut buf = vec![0u8; layout.file_size as usize]; // zero-filled: padding is never garbage (§11)
    buf[..layout.header_bytes.len()].copy_from_slice(&layout.header_bytes);
    copy_and_patch(&mut buf, layout, objects)?;
    write_chain_words(&mut buf, layout)?;
    write_chain_starts(&mut buf, layout)?;
    write_linkedit(&mut buf, layout)?;
    write_signature(&mut buf, layout)?;
    Ok(buf)
}

/// Section copy + in-place relocation application (disjoint ranges; TDD §5
/// Pass 4 "copy + apply").
fn copy_and_patch(
    buf: &mut [u8],
    layout: &Layout,
    objects: &[InputObject],
) -> Result<(), EmitError> {
    for sect in &layout.sections {
        if sect.zerofill || sect.size == 0 {
            continue;
        }
        for piece in &sect.pieces {
            if piece.zerofill {
                continue;
            }
            let dest = sect.file_off + piece.offset;
            // Synthetic pieces (__got slots, __stubs entries) carry their
            // own bytes; input pieces copy from the object file.
            let bytes: &[u8] = if let Some(synth) = &piece.synth {
                &synth.bytes
            } else {
                let src = &objects
                    .get(piece.file.0 as usize)
                    .ok_or(EmitError::Internal {
                        message: format!("piece file {} missing", piece.file.0),
                    })?
                    .bytes;
                src.get(piece.in_range.start as usize..piece.in_range.end as usize)
                    .ok_or(EmitError::Internal {
                        message: format!(
                            "piece range {}..{} leaves its input",
                            piece.in_range.start, piece.in_range.end
                        ),
                    })?
            };
            let tile = buf
                .get_mut(dest as usize..(dest + piece.size) as usize)
                .ok_or(EmitError::Contract {
                    message: format!(
                        "section {} piece at {dest:#x} (size {}) leaves the output buffer",
                        sect.name, piece.size
                    ),
                })?;
            tile.copy_from_slice(bytes);
            // Patches in place, piece-relative offsets.
            for op in &piece.patches {
                reloc::apply(buf, op, dest + u64::from(patch_offset(op)))?;
            }
        }
    }
    Ok(())
}

/// The piece-relative patch position of any operand.
fn patch_offset(op: &PatchOp) -> u32 {
    match op {
        PatchOp::Adrp { in_offset, .. }
        | PatchOp::PageOff12 { in_offset, .. }
        | PatchOp::Branch26 { in_offset, .. }
        | PatchOp::Write64 { in_offset, .. } => *in_offset,
    }
}

/// Writes the encoded chained-fixup words into their pointer slots (file
/// offset == vaddr − `image_base` under the constant-delta contract; M3:
/// the base is 0 for dylibs/bundles).
fn write_chain_words(buf: &mut [u8], layout: &Layout) -> Result<(), EmitError> {
    for (vaddr, word) in &layout.fixups.slot_words {
        let at = vaddr
            .checked_sub(layout.image_base)
            .ok_or(EmitError::Contract {
                message: format!("fixup slot vaddr {vaddr:#x} below the image base"),
            })?;
        let Some(dst) = buf.get_mut(at as usize..at as usize + 8) else {
            return Err(EmitError::Contract {
                message: format!("fixup slot at {at:#x} leaves the output buffer"),
            });
        };
        dst.copy_from_slice(&word.to_le_bytes());
    }
    Ok(())
}

/// Writes the `__chain_starts` static mirror (TDD §7.5) into its section.
fn write_chain_starts(buf: &mut [u8], layout: &Layout) -> Result<(), EmitError> {
    let Some(cs) = layout.sections.iter().find(|s| s.name == "__chain_starts") else {
        return Ok(());
    };
    let dst = buf
        .get_mut(cs.file_off as usize..(cs.file_off + cs.size) as usize)
        .ok_or(EmitError::Contract {
            message: "__chain_starts section leaves the output buffer".into(),
        })?;
    let content = &layout.fixups.chain_starts;
    if dst.len() < content.len() {
        return Err(EmitError::Contract {
            message: "__chain_starts section smaller than its content".into(),
        });
    }
    dst[..content.len()].copy_from_slice(content);
    Ok(())
}

/// Writes a `__LINKEDIT` chunk at `at`.
fn put_chunk(buf: &mut [u8], at: u64, data: &[u8], what: &str) -> Result<(), EmitError> {
    let dst = buf
        .get_mut(at as usize..(at + data.len() as u64) as usize)
        .ok_or(EmitError::Contract {
            message: format!("{what} chunk at {at:#x} leaves the output buffer"),
        })?;
    dst.copy_from_slice(data);
    Ok(())
}

/// The output symbol-table chunk bytes (`n_strx` from the per-symbol
/// offsets table). One builder shared by the reference emit and the fused
/// tile emit — the M4 byte-identity gate depends on the two never diverging.
pub(crate) fn symtab_bytes(layout: &Layout) -> Vec<u8> {
    let mut sym_bytes = Vec::with_capacity(layout.symbols.len() * 16);
    for (sym, strx) in layout.symbols.iter().zip(&layout.str_offsets) {
        sym_bytes.extend_from_slice(&strx.to_le_bytes());
        sym_bytes.push(sym.n_type);
        sym_bytes.push(sym.n_sect);
        sym_bytes.extend_from_slice(&sym.n_desc.to_le_bytes());
        sym_bytes.extend_from_slice(&sym.value.to_le_bytes());
    }
    sym_bytes
}

/// The indirect symbol table chunk bytes (shared builder, see
/// [`symtab_bytes`]).
pub(crate) fn indirect_bytes(layout: &Layout) -> Vec<u8> {
    let mut indirect = Vec::with_capacity(layout.indirect_syms.len() * 4);
    for entry in &layout.indirect_syms {
        indirect.extend_from_slice(&entry.to_le_bytes());
    }
    indirect
}

/// Assembles the `__LINKEDIT` chunks in the fixed §8.2 order.
fn write_linkedit(buf: &mut [u8], layout: &Layout) -> Result<(), EmitError> {
    let le = &layout.linkedit;
    if le.fixup_payload_size > 0 {
        put_chunk(
            buf,
            le.fixup_payload_off,
            &layout.fixups.payload,
            "fixup payload",
        )?;
    }
    if let Some(info) = &layout.dyld_info {
        // M6 classic streams occupy the fixup payload's LINKEDIT slot.
        if !info.rebase.is_empty() {
            put_chunk(buf, le.dyld_rebase_off, &info.rebase, "rebase stream")?;
        }
        if !info.bind.is_empty() {
            put_chunk(buf, le.dyld_bind_off, &info.bind, "bind stream")?;
        }
    }
    put_chunk(buf, le.trie_off, &layout.trie, "export trie")?;
    if le.func_starts_size > 0 {
        put_chunk(
            buf,
            le.func_starts_off,
            &layout.func_starts,
            "function starts",
        )?;
    }
    if le.data_in_code_size > 0 {
        // M30: the data-in-code chunk rides right after function
        // starts — the TDD §8.2 `__LINKEDIT` order.
        put_chunk(
            buf,
            le.data_in_code_off,
            &layout.data_in_code,
            "data-in-code",
        )?;
    }
    put_chunk(buf, le.sym_off, &symtab_bytes(layout), "symbol table")?;
    put_chunk(buf, le.str_off, &layout.strtab, "string table")?;
    if le.indirect_size > 0 {
        put_chunk(
            buf,
            le.indirect_off,
            &indirect_bytes(layout),
            "indirect symbol table",
        )?;
    }
    Ok(())
}

/// Two-pass content-derived UUID (§9) + the ad-hoc `SuperBlob`, last in file.
fn write_signature(buf: &mut [u8], layout: &Layout) -> Result<(), EmitError> {
    let le = &layout.linkedit;
    if le.sig_size == 0 {
        return Ok(());
    }
    let zeroed = signature::page_hashes(buf, le.uuid_at as usize, le.sig_off, true);
    let uuid = signature::derive_uuid(&zeroed);
    let dst = buf
        .get_mut(le.uuid_at as usize..le.uuid_at as usize + 16)
        .ok_or(EmitError::Internal {
            message: "UUID field leaves the output buffer".into(),
        })?;
    dst.copy_from_slice(&uuid);
    let hashes = signature::page_hashes(buf, le.uuid_at as usize, le.sig_off, false);
    // M3: only executables carry the CS_EXECSEG_MAIN_BINARY flag; dylibs
    // and bundles sign with execSegFlags = 0.
    let is_exec = layout.filetype == pgr_format::consts::MH_EXECUTE;
    let blob = signature::build_superblob(
        &layout.ident,
        le.sig_off,
        &hashes,
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
    put_chunk(buf, le.sig_off, &blob, "code signature")?;
    Ok(())
}

//! Pass 4 — emit (TDD §5): the output buffer is allocated once with the
//! final size; sections copy their input bytes into disjoint ranges, apply
//! relocations in place, then the chained-fixup words land in their slots
//! and the `__LINKEDIT` chunks are assembled. Deterministic by construction:
//! the whole image is a pure function of the plan and the inputs.

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
            let bytes: &[u8] = match &piece.synth {
                Some(synth) => &synth.bytes,
                None => {
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
                }
            };
            let dst = buf
                .get_mut(dest as usize..(dest + piece.size) as usize)
                .ok_or(EmitError::Contract {
                    message: format!(
                        "section {} piece at {dest:#x} (size {}) leaves the output buffer",
                        sect.name, piece.size
                    ),
                })?;
            dst.copy_from_slice(bytes);
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
/// offset == vaddr − base under the constant-delta contract).
fn write_chain_words(buf: &mut [u8], layout: &Layout) -> Result<(), EmitError> {
    for (vaddr, word) in &layout.fixups.slot_words {
        let at = vaddr
            .checked_sub(pgr_format::consts::PAGEZERO_SIZE_64)
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
    put_chunk(buf, le.trie_off, &layout.trie, "export trie")?;
    if le.func_starts_size > 0 {
        put_chunk(
            buf,
            le.func_starts_off,
            &layout.func_starts,
            "function starts",
        )?;
    }
    // Symbol table: n_strx comes from the per-symbol offsets table.
    let mut sym_bytes = Vec::with_capacity(layout.symbols.len() * 16);
    for (sym, strx) in layout.symbols.iter().zip(&layout.str_offsets) {
        sym_bytes.extend_from_slice(&strx.to_le_bytes());
        sym_bytes.push(sym.n_type);
        sym_bytes.push(sym.n_sect);
        sym_bytes.extend_from_slice(&sym.n_desc.to_le_bytes());
        sym_bytes.extend_from_slice(&sym.value.to_le_bytes());
    }
    put_chunk(buf, le.sym_off, &sym_bytes, "symbol table")?;
    put_chunk(buf, le.str_off, &layout.strtab, "string table")?;
    if le.indirect_size > 0 {
        let mut indirect = Vec::with_capacity(le.indirect_size);
        for entry in &layout.indirect_syms {
            indirect.extend_from_slice(&entry.to_le_bytes());
        }
        put_chunk(buf, le.indirect_off, &indirect, "indirect symbol table")?;
    }
    Ok(())
}

/// Two-pass content-derived UUID (§9) + the ad-hoc SuperBlob, last in file.
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
    let blob =
        signature::build_superblob(&layout.ident, le.sig_off, &hashes, layout.text_vmsize, true)?;
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

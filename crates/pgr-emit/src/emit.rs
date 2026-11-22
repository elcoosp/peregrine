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
    // M118: under `-dtrace`, every `__dtrace_dof` (`S_DTRACE_DOF`)
    // section's assembled `DOF` header is validated before the section
    // links into the output (the producer-side gate the verifier
    // backstops read-side; the fused tile path pays the same gate so the
    // driver and daemon serve it regardless of which path ran — the M4
    // byte-identity contract).
    validate_dtrace_dof_sections(buf, layout)?;
    Ok(())
}

/// M118: under `-dtrace`, validates every `__dtrace_dof` (`S_DTRACE_DOF`)
/// section's assembled `DOF` header in the output buffer — the
/// identification magic and the bounds the `DTrace` consumer's first walk
/// gates on (the producer-side gate the verifier backstops read-side,
/// the M115 shape one section type over). The off face carries the
/// bytes verbatim (the read-side backstop still gates either way).
/// Shared by [`copy_and_patch`] (the reference path) and the fused tile
/// emit (`pgr_emit::tile::emit_fused`) so the gate fires regardless of
/// which path the driver or daemon serves.
pub(crate) fn validate_dtrace_dof_sections(buf: &[u8], layout: &Layout) -> Result<(), EmitError> {
    if !layout.dtrace {
        return Ok(());
    }
    for sect in &layout.sections {
        if sect.zerofill || sect.size == 0 {
            continue;
        }
        if !pgr_format::is_dtrace_dof_section(sect.flags) {
            continue;
        }
        let start = sect.file_off as usize;
        let end = start
            .checked_add(sect.size as usize)
            .ok_or(EmitError::Internal {
                message: format!("section {} size overflows the output", sect.name),
            })?;
        let sect_bytes = buf.get(start..end).ok_or(EmitError::Contract {
            message: format!(
                "section {} at {start:#x} (size {}) leaves the output buffer",
                sect.name, sect.size
            ),
        })?;
        if let Err(what) = pgr_format::validate_dof_header(sect_bytes) {
            return Err(EmitError::Contract {
                message: format!(
                    "section {} carries a malformed DOF header — {what} (drop -dtrace \
                     or supply a __dtrace_dof section whose head carries the DOF \
                     identification magic and whose size covers the identification region)",
                    sect.name
                ),
            });
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
    // M119: under -single_module the dylib carries one LC_DYSYMTAB module
    // table entry (the 56-byte `DylibModule64` the layout planned). The
    // chunk rides the same __LINKEDIT tail the symtab and indirect table
    // ride — the reference path and the fused tile path both write it so
    // the M4 byte-identity contract holds.
    if !layout.module_table.is_empty() {
        put_chunk(buf, le.modtab_off, &layout.module_table, "module table")?;
    }
    Ok(())
}

/// Two-pass UUID (§9 — content-derived, the M114 random draw, or the
/// M99 named value) + the ad-hoc `SuperBlob`, last in file.
fn write_signature(buf: &mut [u8], layout: &Layout) -> Result<(), EmitError> {
    let le = &layout.linkedit;
    if le.sig_size == 0 {
        return Ok(());
    }
    // M32: the uuid patch consults the plan offset's absent sentinel —
    // a suppressed image has no uuid field to zero, derive or write,
    // so the hashes hash the bytes as they are. M99: the config's
    // named value replaces the derivation — the page hashes still hash
    // the zeroed field (the signature's content contract is unchanged),
    // only the identity bytes are the config's own choice. M114: the
    // `Random` face draws the identity from the system CSPRNG at emit
    // time (fresh per emit — the plan carries the source, never the
    // bytes), the `None` face never reaches here (the absent sentinel).
    let hashes = if le.uuid_at != 0 {
        let zeroed = signature::page_hashes(buf, le.uuid_at as usize, le.sig_off, true);
        let uuid = match layout.uuid_source {
            pgr_core::layout::UuidSource::Random => {
                signature::random_uuid().map_err(|e| EmitError::Internal {
                    message: format!("the system entropy source failed: {e}"),
                })?
            }
            // The `Content` face: the named value (M99) or the derivation.
            _ => layout
                .named_uuid
                .unwrap_or_else(|| signature::derive_uuid(&zeroed)),
        };
        let dst = buf
            .get_mut(le.uuid_at as usize..le.uuid_at as usize + 16)
            .ok_or(EmitError::Internal {
                message: "UUID field leaves the output buffer".into(),
            })?;
        dst.copy_from_slice(&uuid);
        signature::page_hashes(buf, le.uuid_at as usize, le.sig_off, false)
    } else {
        signature::page_hashes(buf, 0, le.sig_off, false)
    };
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

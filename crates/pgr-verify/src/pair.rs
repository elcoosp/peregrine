//! Dylib + executable pair checks (M3 correctness gate, TDD §12 M3 row:
//! "a dylib built by Peregrine + a main executable against it pass verifier
//! pair-wise checks").
//!
//! The pair check closes risk R4 ("two-level namespace ordinal bugs"): the
//! executable's chained-fixup binds are replayed the same way dyld walks
//! them, and every import whose two-level ordinal names the dylib must be
//! exported by the dylib's trie — as a regular export or a re-export.

use crate::{Code, Issue, Options, Report, Severity, verify};
use pgr_format::consts::{DYLD_CHAINED_PTR_64_OFFSET, MH_DYLIB, MH_EXECUTE};
use pgr_format::fixups::{
    ChainWord64, parse_header, parse_imports, parse_starts_in_image, parse_starts_in_segment,
};

/// The pair verification result: both images' own reports plus the
/// cross-image findings.
#[derive(Debug, Default)]
pub struct PairReport {
    /// The executable's own verification report.
    pub exec: Report,
    /// The dylib's own verification report.
    pub dylib: Report,
    /// Cross-image issues (ordinal/trie agreement, re-export wiring).
    pub pair_issues: Vec<Issue>,
}

impl PairReport {
    /// True when both images verify clean and no pair issue was found
    /// (warnings count under `strict_warnings`).
    #[must_use]
    pub fn is_ok(&self, opts: &Options) -> bool {
        self.exec.is_ok(opts) && self.dylib.is_ok(opts) && self.pair_issues.is_empty()
    }

    /// Error-severity findings across both images and the pair checks.
    #[must_use]
    pub fn error_count(&self) -> usize {
        let errs = |r: &Report| {
            r.issues
                .iter()
                .filter(|i| i.severity == Severity::Error)
                .count()
        };
        errs(&self.exec) + errs(&self.dylib) + self.pair_issues.len()
    }
}

/// Verifies an executable and the dylib it links against, then cross-checks
/// the two-level namespace contract between them:
///
/// 1. both images verify individually (full reports included),
/// 2. the executable must name the dylib among its `LC_LOAD_DYLIB`
///    commands (otherwise the pair does not link),
/// 3. every bind whose two-level ordinal selects that dylib must resolve
///    to a name the dylib's export trie exports (regular or re-export),
/// 4. trie re-export ordinals must stay within the dylib's own dylib list.
///
/// # Panics
/// Never — all parsing failures surface as report issues.
#[must_use]
pub fn verify_dylib_pair(exec_bytes: &[u8], dylib_bytes: &[u8], opts: &Options) -> PairReport {
    let mut out = PairReport {
        exec: verify(exec_bytes, opts),
        dylib: verify(dylib_bytes, opts),
        pair_issues: Vec::new(),
    };

    // Filetype sanity (parse-level failures already reported above).
    let exec_type = pgr_format::MachHeader64::parse(exec_bytes).map_or(0, |h| h.filetype);
    let dylib_type = pgr_format::MachHeader64::parse(dylib_bytes).map_or(0, |h| h.filetype);
    if exec_type != MH_EXECUTE {
        out.pair_issues.push(Issue::error(
            Code::HeaderInvalid,
            format!("pair check expects an MH_EXECUTE executable, got {exec_type:#x}"),
            None,
        ));
        return out;
    }
    if dylib_type != MH_DYLIB {
        out.pair_issues.push(Issue::error(
            Code::HeaderInvalid,
            format!("pair check expects an MH_DYLIB dylib, got {dylib_type:#x}"),
            None,
        ));
        return out;
    }

    // Re-parse both images structurally (the verify reports prove they
    // parse; failures here are already covered by the individual reports).
    let (Ok(exec_img), Ok(dylib_img)) = (
        crate::structural::parse_image(exec_bytes),
        crate::structural::parse_image(dylib_bytes),
    ) else {
        return out;
    };

    // The dylib's exported surface (trie walk; already validated).
    let mut exports: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for cmd in &dylib_img.commands {
        if let pgr_format::load_command::LoadCommandKind::LinkeditData(
            pgr_format::consts::LC_DYLD_EXPORTS_TRIE,
        ) = cmd.kind
        {
            if let Ok(lc) = pgr_format::LinkeditDataCommand::parse(cmd.bytes) {
                if let Ok(payload) = lc.data(dylib_bytes) {
                    if let Ok(entries) = pgr_format::trie::exports(payload) {
                        for e in entries {
                            exports.insert(String::from_utf8_lossy(&e.name).into_owned());
                        }
                    }
                }
            }
        }
    }

    // The dylib's own install name and its re-export ordinal space.
    let dylib_install_name = dylib_img
        .id_dylib
        .as_ref()
        .and_then(|id| {
            let cmd = dylib_img
                .commands
                .iter()
                .find(|c| c.kind == pgr_format::load_command::LoadCommandKind::IdDylib)?;
            id.name(cmd.bytes).ok().map(<[u8]>::to_vec)
        })
        .map(|n| String::from_utf8_lossy(&n).into_owned());
    let Some(install_name) = dylib_install_name else {
        out.pair_issues.push(Issue::error(
            Code::LoadCommandMalformed,
            "the dylib carries no LC_ID_DYLIB install name",
            None,
        ));
        return out;
    };

    // The dylib's trie re-export ordinals must stay inside its dylib list.
    let dylib_dylib_count = dylib_img.dylibs.len();
    for cmd in &dylib_img.commands {
        if let pgr_format::load_command::LoadCommandKind::LinkeditData(
            pgr_format::consts::LC_DYLD_EXPORTS_TRIE,
        ) = cmd.kind
        {
            if let Ok(lc) = pgr_format::LinkeditDataCommand::parse(cmd.bytes) {
                if let Ok(payload) = lc.data(dylib_bytes) {
                    if let Ok(entries) = pgr_format::trie::exports(payload) {
                        for e in entries {
                            if let Some(ord) = e.reexport_ordinal {
                                if ord as usize > dylib_dylib_count {
                                    out.pair_issues.push(Issue::error(
                                        Code::ExportTrie,
                                        format!(
                                            "re-export of \"{}\" names ordinal {ord} but the \\
                                             dylib lists only {dylib_dylib_count} dylibs",
                                            String::from_utf8_lossy(&e.name)
                                        ),
                                        None,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // The executable must load this dylib; the ordinal is 1-based over its
    // LC_LOAD_DYLIB-family list.
    let ordinal = exec_img
        .dylibs
        .iter()
        .position(|name| *name == install_name)
        .map(|i| i + 1);
    let Some(ordinal) = ordinal else {
        out.pair_issues.push(Issue::error(
            Code::LoadCommandMalformed,
            format!("the executable does not load the dylib (no LC_LOAD_DYLIB for {install_name})"),
            None,
        ));
        return out;
    };

    // Replay the executable's binds: every slot bound with this dylib's
    // two-level ordinal must name an export of the dylib (R4 mitigation).
    let Some(fixups_lc) = &exec_img.fixups else {
        // No fixups: nothing binds out of the executable (pure static or
        // -no_fixup_chains image); the pair still links name-wise.
        return out;
    };
    // Payload errors are already in the exec report.
    let (Ok(payload), Ok(hdr)) = (
        fixups_lc.data(exec_bytes),
        parse_header_payload(fixups_lc, exec_bytes),
    ) else {
        return out;
    };
    let Ok(starts) = parse_starts_in_image(payload, hdr.starts_offset as usize) else {
        return out;
    };
    let Ok(imports) = parse_imports(payload, &hdr) else {
        return out;
    };
    let import_name = |ordinal_idx: usize| -> Option<String> {
        let imp = imports.get(ordinal_idx)?;
        let start = hdr.symbols_offset as usize + imp.name_offset as usize;
        let rest = payload.get(start..)?;
        let end = rest.iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&rest[..end]).into_owned())
    };

    let segments: Vec<&pgr_format::SegmentCommand64> = exec_img.segments.iter().collect();
    for (seg_index, &off) in starts.seg_info_offset.iter().enumerate() {
        if off == 0 {
            continue;
        }
        let Some(&mach_seg) = segments.get(seg_index) else {
            continue;
        };
        let Ok(seg) = parse_starts_in_segment(payload, hdr.starts_offset as usize + off as usize)
        else {
            continue;
        };
        if seg.pointer_format != DYLD_CHAINED_PTR_64_OFFSET {
            continue;
        }
        for page in 0..seg.page_count {
            let Ok(heads) = pgr_format::fixups::page_chain_starts(
                payload,
                hdr.starts_offset as usize + off as usize,
                &seg,
                page,
            ) else {
                continue;
            };
            for head in heads {
                if head == pgr_format::consts::DYLD_CHAINED_PTR_START_NONE {
                    continue;
                }
                // Walk the chain, replaying dyld's bind resolution.
                let mut slot_off = u64::from(head);
                loop {
                    if slot_off + 8 > u64::from(seg.page_size) || slot_off + 8 > mach_seg.vmsize {
                        break;
                    }
                    let slot_file = mach_seg
                        .fileoff
                        .saturating_add(u64::from(page).saturating_mul(u64::from(seg.page_size)))
                        .saturating_add(slot_off);
                    let Some(word_bytes) =
                        exec_bytes.get(slot_file as usize..slot_file as usize + 8)
                    else {
                        break;
                    };
                    let word = ChainWord64::new(u64::from_le_bytes(
                        word_bytes.try_into().unwrap_or([0; 8]),
                    ));
                    if word.is_bind() {
                        let bind_ord = word.bind_ordinal() as usize;
                        if let Some(name) = import_name(bind_ord) {
                            if bind_ord == ordinal && !exports.contains(&name) {
                                out.pair_issues.push(Issue::error(
                                    Code::FixupsImport,
                                    format!(
                                        "two-level bind of \"{name}\" names ordinal {ordinal} \\
                                         ({install_name}) but the dylib does not export it"
                                    ),
                                    Some(slot_file),
                                ));
                            }
                        }
                    }
                    let strides = u64::from(word.next());
                    if strides == 0 {
                        break;
                    }
                    slot_off += strides * 4;
                }
            }
        }
    }
    out
}

/// Parses the chained-fixups payload header (error-mapped for brevity).
fn parse_header_payload(
    lc: &pgr_format::LinkeditDataCommand,
    bytes: &[u8],
) -> Result<pgr_format::fixups::ChainedFixupsHeader, ()> {
    let payload = lc.data(bytes).map_err(|_| ())?;
    parse_header(payload).map_err(|_| ())
}

//! Miscellaneous `__LINKEDIT` checks: entry point, dylinker, build version,
//! function starts (ULEB), data-in-code, export trie bounds and UUID
//! presence.

use crate::structural::ParsedImage;
use crate::{Code, Issue, Report};
use pgr_format::consts::{LC_DATA_IN_CODE, LC_FUNCTION_STARTS, LC_MAIN, PLATFORM_MACOS};
use pgr_format::load_command::LoadCommandKind;

/// Entry point, dylinker and build-version checks.
pub(crate) fn check_entry_and_version(bytes: &[u8], img: &ParsedImage<'_>, report: &mut Report) {
    let exec = img.header.filetype == pgr_format::consts::MH_EXECUTE;
    if exec {
        match img.main {
            Some(ep) => {
                let text_vmsize = img
                    .segments
                    .iter()
                    .find(|s| s.name() == Ok("__TEXT"))
                    .map(|s| s.vmsize)
                    .unwrap_or(0);
                if ep.entryoff >= text_vmsize {
                    report.issues.push(Issue::error(
                        Code::LinkeditPayload,
                        format!(
                            "LC_MAIN entryoff {:#x} is outside __TEXT (vmsize {text_vmsize:#x})",
                            ep.entryoff
                        ),
                        Some(ep.entryoff),
                    ));
                }
            }
            None => report.issues.push(Issue::error(
                Code::LinkeditPayload,
                "executables require LC_MAIN",
                None,
            )),
        }
        let has_dylinker = img
            .commands
            .iter()
            .any(|c| c.kind == LoadCommandKind::LoadDylinker);
        if !has_dylinker {
            report.issues.push(Issue::warning(
                Code::LinkeditPayload,
                "executable has no LC_LOAD_DYLINKER",
                None,
            ));
        }
    } else if img.main.is_some() {
        report.issues.push(Issue::error(
            Code::LinkeditPayload,
            "LC_MAIN is only valid in executables",
            None,
        ));
    }

    if let Some(bv) = img.build_version {
        if bv.platform != PLATFORM_MACOS {
            report.issues.push(Issue::warning(
                Code::LinkeditPayload,
                format!(
                    "build platform {} is not macOS ({PLATFORM_MACOS})",
                    bv.platform
                ),
                None,
            ));
        }
        if bv.minos == 0 {
            report.issues.push(Issue::warning(
                Code::LinkeditPayload,
                "minimum OS version is 0",
                None,
            ));
        }
        if 24 + bv.ntools as usize * 8 > bv.cmdsize as usize {
            report.issues.push(Issue::error(
                Code::LinkeditPayload,
                "LC_BUILD_VERSION tool entries exceed cmdsize",
                None,
            ));
        }
    }
    let _ = bytes;
}

/// Function-starts, data-in-code, export-trie and UUID checks.
pub(crate) fn check_linkedit_payloads(bytes: &[u8], img: &ParsedImage<'_>, report: &mut Report) {
    let text_vmsize = img
        .segments
        .iter()
        .find(|s| s.name() == Ok("__TEXT"))
        .map(|s| s.vmsize)
        .unwrap_or(0);
    let mut uuid_present = false;
    for cmd in &img.commands {
        match cmd.kind {
            LoadCommandKind::LinkeditData(LC_FUNCTION_STARTS) => {
                let Ok(lc) = pgr_format::LinkeditDataCommand::parse(cmd.bytes) else {
                    continue;
                };
                match lc.data(bytes) {
                    Ok(data) => check_function_starts(data, text_vmsize, report),
                    Err(e) => report
                        .issues
                        .push(crate::issue_from(&e, Code::LinkeditPayload)),
                }
            }
            LoadCommandKind::LinkeditData(LC_DATA_IN_CODE) => {
                let Ok(lc) = pgr_format::LinkeditDataCommand::parse(cmd.bytes) else {
                    continue;
                };
                if let Ok(data) = lc.data(bytes) {
                    if data.len() % 8 != 0 {
                        report.issues.push(Issue::error(
                            Code::LinkeditPayload,
                            "LC_DATA_IN_CODE payload is not a multiple of 8 bytes",
                            Some(lc.dataoff as u64),
                        ));
                    }
                    for i in 0..data.len() / 8 {
                        let entry: pgr_format::DataInCodeEntry =
                            pgr_format::cursor::pod_read_unaligned_at(
                                bytes,
                                lc.dataoff as usize + i * 8,
                            )
                            .unwrap_or(pgr_format::DataInCodeEntry {
                                offset: 0,
                                length: 0,
                                kind: 0,
                            });
                        if u64::from(entry.offset).saturating_add(u64::from(entry.length))
                            > text_vmsize
                        {
                            report.issues.push(Issue::warning(
                                Code::LinkeditPayload,
                                format!("data-in-code entry {i} beyond __TEXT"),
                                Some(lc.dataoff as u64),
                            ));
                        }
                    }
                }
            }
            LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_EXPORTS_TRIE) => {
                let Ok(lc) = pgr_format::LinkeditDataCommand::parse(cmd.bytes) else {
                    continue;
                };
                match lc.data(bytes) {
                    Ok(data) => {
                        crate::export_trie::check_export_trie(data, report);
                    }
                    Err(e) => {
                        report
                            .issues
                            .push(crate::issue_from(&e, Code::LinkeditPayload));
                    }
                }
            }
            LoadCommandKind::Uuid => {
                uuid_present = true;
            }
            _ => {}
        }
    }
    if !uuid_present
        && matches!(
            img.header.filetype,
            pgr_format::consts::MH_EXECUTE | pgr_format::consts::MH_DYLIB
        )
    {
        report.issues.push(Issue::warning(
            Code::LinkeditPayload,
            "no LC_UUID (Peregrine derives one from the page hashes)",
            None,
        ));
    }
    let _ = LC_MAIN;
}

/// ULEB128 delta stream must be monotonic and stay inside `__TEXT`.
fn check_function_starts(data: &[u8], text_vmsize: u64, report: &mut Report) {
    let mut pos = 0usize;
    let mut value = 0u64;
    while pos < data.len() {
        let mut shift = 0u32;
        let mut byte = 0x80u8;
        let mut acc = 0u64;
        while byte & 0x80 != 0 {
            if pos >= data.len() {
                report.issues.push(Issue::error(
                    Code::LinkeditPayload,
                    "function-starts ULEB128 stream is truncated",
                    None,
                ));
                return;
            }
            byte = data[pos];
            pos += 1;
            acc |= u64::from(byte & 0x7f) << shift;
            shift += 7;
            if shift > 63 {
                report.issues.push(Issue::error(
                    Code::LinkeditPayload,
                    "function-starts ULEB128 entry exceeds 64 bits",
                    None,
                ));
                return;
            }
        }
        value = value.saturating_add(acc);
        if value > text_vmsize {
            report.issues.push(Issue::error(
                Code::LinkeditPayload,
                format!("function start {value:#x} beyond __TEXT (vmsize {text_vmsize:#x})"),
                None,
            ));
            return;
        }
    }
}

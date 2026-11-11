//! Miscellaneous `__LINKEDIT` checks: entry point, dylinker, build version,
//! function starts (ULEB), data-in-code, export trie bounds and UUID
//! presence.

use crate::structural::ParsedImage;
use crate::{Code, Issue, Report};
use pgr_format::consts::{
    LC_DATA_IN_CODE, LC_FUNCTION_STARTS, LC_MAIN, PAGE_SIZE_16K, PLATFORM_IOS, PLATFORM_MACOS,
    PLATFORM_TVOS, PLATFORM_VISIONOS, PLATFORM_WATCHOS, chained_fixups_floor,
};
use pgr_format::load_command::LoadCommandKind;

/// Formats a packed `X.Y.Z` build-version word (`(X<<16)|(Y<<8)|Z`) the
/// way the verifier's issue messages name it.
fn fmt_packed_version(v: u32) -> String {
    format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)
}

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
                    .map_or(0, |s| s.vmsize);
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
                // The stack-reserve invariant (M18): the kernel maps the
                // stack in pages, so a named reserve is a multiple of the
                // 16 KiB arm64 page; the zero default means "dyld's own
                // default" (every pre-M18 image carries it).
                if ep.stacksize % PAGE_SIZE_16K != 0 {
                    report.issues.push(Issue::error(
                        Code::LinkeditPayload,
                        format!(
                            "LC_MAIN stacksize {:#x} must be a multiple of the 16 KiB arm64 \
                             page (the kernel maps the stack in pages; 0 keeps dyld's own \
                             default)",
                            ep.stacksize
                        ),
                        Some(ep.stacksize),
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
        // M10 rung 2: the platform gate checks the declared platform,
        // not macOS. The five linked platforms are contract-clean; an
        // unknown platform constant is an error (dyld would refuse the
        // image), and the SDK must be at least the deployment target —
        // the SDK ships the deployment target's interfaces.
        let known = bv.platform == PLATFORM_MACOS
            || bv.platform == PLATFORM_IOS
            || bv.platform == PLATFORM_TVOS
            || bv.platform == PLATFORM_WATCHOS
            || bv.platform == PLATFORM_VISIONOS;
        if !known {
            report.issues.push(Issue::error(
                Code::LinkeditPayload,
                format!(
                    "build platform {} is not a known Mach-O platform \
                     (linked platforms: macos {}, ios {}, tvos {}, watchos {}, visionos {})",
                    bv.platform,
                    PLATFORM_MACOS,
                    PLATFORM_IOS,
                    PLATFORM_TVOS,
                    PLATFORM_WATCHOS,
                    PLATFORM_VISIONOS
                ),
                None,
            ));
        }
        if bv.sdk < bv.minos {
            report.issues.push(Issue::error(
                Code::LinkeditPayload,
                format!(
                    "SDK version {} is older than the deployment target {}",
                    fmt_packed_version(bv.sdk),
                    fmt_packed_version(bv.minos),
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
        // M10 rung 3, slice 2: the verifier reads the encoding floor — the
        // same per-platform table the layout's fixup-encoding gate and
        // `pgr_core::platform::FixupEncoding` encode, canonical beside the
        // `PLATFORM_*` constants (`pgr_format::consts::chained_fixups_floor`).
        // Chained words below the floor cannot load on that target's dyld;
        // the message carries the fix (raise the target or relink with
        // `-no_fixup_chains`). Above the floor the classic streams are a
        // producer choice (`-no_fixup_chains`) and stay silent, and the
        // gate stays silent for unknown platforms (the unknown-platform
        // error above already refused them).
        let floor = chained_fixups_floor(bv.platform);
        if known && img.fixups.is_some() && bv.minos < floor {
            report.issues.push(Issue::error(
                Code::FixupsFloor,
                format!(
                    "deployment target {} is below the chained-fixups floor {} \
                     for platform {} while the image carries LC_DYLD_CHAINED_FIXUPS — \
                     raise the target to at least the floor or relink with \
                     -no_fixup_chains (the classic opcode streams encode the same fixups)",
                    fmt_packed_version(bv.minos),
                    fmt_packed_version(floor),
                    bv.platform,
                ),
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
        .map_or(0, |s| s.vmsize);
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
                            Some(u64::from(lc.dataoff)),
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
                                Some(u64::from(lc.dataoff)),
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

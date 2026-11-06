//! Classic `LC_DYLD_INFO(_ONLY)` opcode-stream verification (M6 legacy
//! fallback gate).
//!
//! The checker walks both streams the way dyld does (state machine over
//! opcode nibbles) and validates:
//!
//! * every slot lands inside the named segment, 8-byte aligned for pointer
//!   slots;
//! * bind ordinals stay inside the `LC_LOAD_DYLIB` list (special ordinals
//!   only when the image drops `MH_TWOLEVEL`);
//! * every bind names a non-empty symbol and carries no unknown flag bits.
//!
//! Malformed streams are findings, never panics — the same contract the
//! chained-fixup walker keeps.

use crate::structural::ParsedImage;
use crate::{Code, Issue, Report};
use pgr_format::dyld_info::{
    BindEntry, BindOrdinal, DyldInfoCommand, decode_bind_stream, decode_rebase_stream,
};

/// Checks the image's classic dyld-info command (when present).
pub(crate) fn check_dyld_info(bytes: &[u8], img: &ParsedImage<'_>, report: &mut Report) {
    let Some(cmd) = img.dyld_info else {
        return;
    };
    let segments: Vec<(u64, u64)> = img.segments.iter().map(|s| (s.vmaddr, s.vmsize)).collect();
    let two_level = img.header.flags & pgr_format::consts::MH_TWOLEVEL != 0;
    // Stream payloads: offset/size pairs must stay inside the file.
    let mut streams: [Option<&[u8]>; 4] = [None; 4];
    for (idx, (off, size, what)) in [
        (cmd.rebase_off, cmd.rebase_size, "rebase"),
        (cmd.bind_off, cmd.bind_size, "bind"),
        (cmd.weak_bind_off, cmd.weak_bind_size, "weak-bind"),
        (cmd.lazy_bind_off, cmd.lazy_bind_size, "lazy-bind"),
    ]
    .into_iter()
    .enumerate()
    {
        streams[idx] = if size == 0 {
            Some(&[])
        } else {
            let start = off as usize;
            let end = start.saturating_add(size as usize);
            if end > bytes.len() {
                report.issues.push(Issue::error(
                    Code::DyldInfoStreams,
                    format!("{what} stream [{off:#x}, {end:#x}) leaves the file"),
                    Some(u64::from(off)),
                ));
                None
            } else {
                Some(&bytes[start..end])
            }
        };
    }
    if let Some(rebase) = streams[0] {
        match decode_rebase_stream(rebase) {
            Ok(entries) => {
                check_rebase_entries(&entries, &segments, report);
            }
            Err(e) => report.issues.push(Issue::error(
                Code::DyldInfoStreams,
                format!("rebase stream: {e}"),
                Some(u64::from(cmd.rebase_off)),
            )),
        }
    }
    if let Some(bind) = streams[1] {
        match decode_bind_stream(bind) {
            Ok(entries) => {
                check_bind_entries(&entries, &segments, img.dylibs.len(), two_level, report);
            }
            Err(e) => report.issues.push(Issue::error(
                Code::DyldInfoStreams,
                format!("bind stream: {e}"),
                Some(u64::from(cmd.bind_off)),
            )),
        }
    }
    // Weak/lazy streams Peregrine never emits; a foreign image's spans were
    // bounds-checked above and their opcodes are ignored (dyld semantics).
}

/// Slot-bounds check shared by both streams.
fn check_slot(seg: u8, seg_off: u64, segments: &[(u64, u64)], report: &mut Report) {
    let Some(&(vmaddr, vmsize)) = segments.get(usize::from(seg)) else {
        report.issues.push(Issue::error(
            Code::DyldInfoStreams,
            format!("stream entry names segment {seg} of {}", segments.len()),
            None,
        ));
        return;
    };
    if seg_off.saturating_add(8) > vmsize {
        report.issues.push(Issue::error(
            Code::DyldInfoStreams,
            format!("stream slot {seg_off:#x} leaves segment {seg} (vmsize {vmsize:#x})"),
            Some(vmaddr + seg_off),
        ));
    } else if seg_off % 8 != 0 {
        report.issues.push(Issue::error(
            Code::DyldInfoStreams,
            format!("stream slot {seg_off:#x} in segment {seg} is not 8-byte aligned"),
            Some(vmaddr + seg_off),
        ));
    }
}

fn check_rebase_entries(
    entries: &[pgr_format::dyld_info::DecodedRebase],
    segments: &[(u64, u64)],
    report: &mut Report,
) {
    for e in entries {
        if e.r#type != pgr_format::dyld_info::REBASE_TYPE_POINTER {
            report.issues.push(Issue::warning(
                Code::DyldInfoStreams,
                format!("rebase type {} is not REBASE_TYPE_POINTER", e.r#type),
                None,
            ));
        }
        check_slot(e.seg, e.seg_off, segments, report);
    }
}

fn check_bind_entries(
    entries: &[BindEntry],
    segments: &[(u64, u64)],
    n_dylibs: usize,
    two_level: bool,
    report: &mut Report,
) {
    for b in entries {
        check_slot(b.seg, b.seg_off, segments, report);
        match b.ordinal {
            BindOrdinal::Dylib(ord) => {
                let ord = usize::from(ord);
                if ord == 0 || ord > n_dylibs {
                    report.issues.push(Issue::error(
                        Code::DyldInfoStreams,
                        format!(
                            "bind ordinal {ord} outside the {} LC_LOAD_DYLIB command(s)",
                            n_dylibs
                        ),
                        None,
                    ));
                }
            }
            BindOrdinal::Special(neg) => {
                if two_level {
                    report.issues.push(Issue::error(
                        Code::DyldInfoStreams,
                        format!(
                            "special bind ordinal {neg} in a two-level image \
                             (dyld only accepts it flat)"
                        ),
                        None,
                    ));
                }
            }
        }
        if b.name.is_empty() {
            report.issues.push(Issue::error(
                Code::DyldInfoStreams,
                "bind entry carries an empty symbol name",
                None,
            ));
        }
        if b.flags & !pgr_format::dyld_info::BIND_SYMBOL_FLAGS_WEAK_IMPORT != 0 {
            report.issues.push(Issue::warning(
                Code::DyldInfoStreams,
                format!("bind entry carries unknown symbol flags {:#x}", b.flags),
                None,
            ));
        }
    }
}

/// Exposes the parsed command to the verifier's structural pre-pass.
pub(crate) fn parse_command(bytes: &[u8], at: usize) -> Option<DyldInfoCommand> {
    let raw = bytes.get(at..at + pgr_format::dyld_info::DYLD_INFO_COMMAND_SIZE)?;
    DyldInfoCommand::parse(raw).ok()
}

/// True when the load command kind is one of the classic dyld-info
/// commands (used by the structural pre-pass).
pub(crate) fn is_dyld_info_cmd(cmd: u32) -> bool {
    cmd == pgr_format::consts::LC_DYLD_INFO || cmd == pgr_format::consts::LC_DYLD_INFO_ONLY
}

#[cfg(test)]
mod tests {
    use super::check_slot;
    use crate::{Code, Report};

    #[test]
    fn slots_must_be_inside_their_segment_and_aligned() {
        let segs = vec![(0x100u64, 0x1000u64)];
        let mut r = Report::default();
        check_slot(0, 0x800, &segs, &mut r);
        assert!(r.issues.is_empty());
        check_slot(0, 0xFF8, &segs, &mut r);
        assert!(r.issues.is_empty(), "last aligned slot fits");
        r.issues.clear();
        check_slot(0, 0xFFC, &segs, &mut r); // 8-aligned? 0xFFC % 8 == 4 → error path is overflow
        assert!(
            r.issues
                .iter()
                .any(|i| i.message.contains("leaves segment"))
        );
        r.issues.clear();
        check_slot(0, 0x804, &segs, &mut r);
        assert!(
            r.issues
                .iter()
                .any(|i| i.message.contains("not 8-byte aligned"))
        );
        r.issues.clear();
        check_slot(1, 0x800, &segs, &mut r);
        assert!(
            r.issues
                .iter()
                .any(|i| i.message.contains("names segment 1"))
        );
        assert!(r.issues.iter().all(|i| i.code == Code::DyldInfoStreams));
    }
}

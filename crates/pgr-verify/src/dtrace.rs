//! M118: the `DTrace` `DOF` header contract — the read-side backstop the
//! producer's emit-side gate mirrors. Every `__dtrace_dof`
//! (`S_DTRACE_DOF`) section in the output carries a `DOF` payload whose
//! header the `DTrace` consumer's first walk gates on: the identification
//! magic (`DOF_MAGIC`, the four bytes `DoFD`) and the bounds (the
//! identification region `DOF_ID_SIZE` fits). The producer validates the
//! same contract at emit under `-dtrace`; the verifier reports it
//! read-side on every `S_DTRACE_DOF` section regardless of how it was
//! produced (the M115 read-side-backstop shape, one section type over — a
//! malformed header the producer never saw still reports).

use crate::{Code, Issue, Report};

/// Walks every declared section (the raw load-command walk — the
/// verifier's parsed view's own source, the same walk
/// `check_objc_registration` rides); a `__dtrace_dof` section whose
/// header fails the magic or the bounds is the malformed shape dyld's
/// consumer would misread. The section's file bytes ride the
/// `SectionBounds` gate the structural pass already paid.
pub(crate) fn check_dtrace_dof(bytes: &[u8], report: &mut Report) {
    let Ok(hdr) = pgr_format::MachHeader64::parse(bytes) else {
        return; // the header gate reports its own issue
    };
    let Ok(mut it) = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    ) else {
        return;
    };
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind != pgr_format::LoadCommandKind::Segment64 {
            continue;
        }
        // segment_command_64: nsects at +64, section_64 entries at +72
        if cmd.bytes.len() < 72 {
            continue;
        }
        let nsects = u32::from_le_bytes(cmd.bytes[64..68].try_into().unwrap_or([0; 4]));
        for i in 0..nsects as usize {
            let base = 72 + i * 80;
            if base + 80 > cmd.bytes.len() {
                return; // the bounds gate reports the truncation
            }
            let entry = &cmd.bytes[base..base + 80];
            let flags = u32::from_le_bytes(entry[64..68].try_into().unwrap_or([0; 4]));
            if !pgr_format::is_dtrace_dof_section(flags) {
                continue;
            }
            let name = String::from_utf8_lossy(&entry[..16]);
            let name = name.trim_end_matches('\0');
            let size = u64::from_le_bytes(entry[40..48].try_into().unwrap_or([0; 8]));
            let off = u32::from_le_bytes(entry[48..52].try_into().unwrap_or([0; 4]));
            let sect_off = off as usize;
            let sect_size = size as usize;
            let Some(sect_bytes) = bytes.get(sect_off..sect_off.saturating_add(sect_size)) else {
                report.issues.push(Issue::error(
                    Code::DtraceDof,
                    format!(
                        "section `{name}` (the __dtrace_dof DOF payload) at file off \
                         {off:#x} (size {size}) leaves the file — dyld's consumer reads the \
                         DOF header at the head of the section"
                    ),
                    Some(u64::try_from(cmd.offset).unwrap_or(0)),
                ));
                continue;
            };
            if let Err(what) = pgr_format::validate_dof_header(sect_bytes) {
                report.issues.push(Issue::error(
                    Code::DtraceDof,
                    format!(
                        "section `{name}` (the __dtrace_dof DOF payload) carries a \
                         malformed DOF header — {what} (the DTrace consumer's first walk \
                         gates on the identification magic and the bounds; drop -dtrace or \
                         supply a section whose head carries the DOF magic and whose size \
                         covers the identification region)"
                    ),
                    Some(u64::try_from(cmd.offset).unwrap_or(0)),
                ));
            }
        }
    }
}

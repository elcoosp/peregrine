//! M115: the `ObjC` registration contract — the `__objc_catlist`/
//! `__objc_nlcatlist` pointer arrays dyld's registration walk consumes
//! ride whole pointer strides (8-byte entries), whether the categories
//! stay separate (the `-no_objc_category_merging` face) or their
//! registration folded into the base classes (the default merge drops
//! the folded sections entirely, so the walk sees either the verbatim
//! sections or none).

use crate::{Code, Issue, Report};

/// Walks every declared section (the raw load-command walk — the
/// verifier's parsed view's own source); a registration section whose
/// size is not a whole pointer stride is the malformed shape dyld's
/// walk would misread. The bounds ride `SectionBounds`.
pub(crate) fn check_objc_registration(bytes: &[u8], report: &mut Report) {
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
            let name = String::from_utf8_lossy(&entry[..16]);
            let name = name.trim_end_matches('\0');
            if matches!(name, "__objc_catlist" | "__objc_nlcatlist") {
                let size = u64::from_le_bytes(entry[40..48].try_into().unwrap_or([0; 8]));
                if size % 8 != 0 {
                    report.issues.push(Issue::error(
                        Code::ObjcRegistration,
                        format!(
                            "`__objc` registration rides a broken pointer stride (size {size} \
                             is not a multiple of 8) — dyld's registration walk consumes \
                             whole 8-byte entries"
                        ),
                        Some(u64::try_from(cmd.offset).unwrap_or(0)),
                    ));
                }
            }
        }
    }
}

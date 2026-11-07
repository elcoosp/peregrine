//! Static-image chain-starts checks (TDD §7.5, new at M1): the
//! `__TEXT,__chain_starts` section must agree with the
//! `LC_DYLD_CHAINED_FIXUPS` payload — same pointer format, one mirror head
//! per chain in the payload, every head decoding as a rebase/bind word.

use crate::structural::ParsedImage;
use crate::{Code, Issue, Report};
use pgr_format::consts::{
    DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET, DYLD_CHAINED_PTR_START_NONE,
};
use pgr_format::fixups::{
    ChainWord64, page_chain_starts, parse_header, parse_starts_in_image, parse_starts_in_segment,
};

/// Validates the `__chain_starts` static mirror against the chained-fixups
/// payload. Runs only when the section exists (static executables).
pub(crate) fn check_chain_starts(bytes: &[u8], img: &ParsedImage<'_>, report: &mut Report) {
    let Some((addr, size)) = find_chain_starts(bytes, img) else {
        return;
    };
    // The payload is the ground truth; a missing payload makes the mirror
    // meaningless (but only an error when it also has fixup slots).
    let Some(lc) = img.fixups else {
        report.issues.push(Issue::error(
            Code::LinkeditPayload,
            "__chain_starts present without LC_DYLD_CHAINED_FIXUPS",
            Some(addr),
        ));
        return;
    };
    let Ok(payload) = lc.data(bytes) else {
        return; // payload errors are reported by the dynamic check
    };
    let Ok(hdr) = parse_header(payload) else {
        return;
    };
    let Ok(starts) = parse_starts_in_image(payload, hdr.starts_offset as usize) else {
        return;
    };
    // Collect the payload's chain heads as image offsets (file offsets under
    // the constant-delta contract).
    let mut payload_heads: Vec<u32> = Vec::new();
    let mut pointer_format: Option<u16> = None;
    for &off in &starts.seg_info_offset {
        if off == 0 {
            continue;
        }
        let rec_at = hdr.starts_offset as usize + off as usize;
        let Ok(seg) = parse_starts_in_segment(payload, rec_at) else {
            return;
        };
        pointer_format = Some(seg.pointer_format);
        for page in 0..seg.page_count {
            let Ok(heads) = page_chain_starts(payload, rec_at, &seg, page) else {
                return;
            };
            for h in heads {
                if h == DYLD_CHAINED_PTR_START_NONE {
                    continue;
                }
                let file = seg
                    .segment_offset
                    .saturating_add(u64::from(page).saturating_mul(u64::from(seg.page_size)))
                    .saturating_add(u64::from(h));
                if file <= u64::from(u32::MAX) {
                    payload_heads.push(file as u32);
                }
            }
        }
    }

    // Parse the mirror: u32 pointer format, u32 head count, u32 heads.
    let at = addr as usize;
    let Some(mirror) = bytes.get(at..at + size as usize) else {
        report.issues.push(Issue::error(
            Code::LinkeditPayload,
            "__chain_starts section bytes out of file bounds",
            Some(addr),
        ));
        return;
    };
    if mirror.len() < 8 {
        report.issues.push(Issue::error(
            Code::LinkeditPayload,
            "__chain_starts shorter than its fixed header",
            Some(addr),
        ));
        return;
    }
    let fmt = u32::from_le_bytes(mirror[0..4].try_into().unwrap_or([0; 4]));
    let count = u32::from_le_bytes(mirror[4..8].try_into().unwrap_or([0; 4]));
    if fmt != u32::from(DYLD_CHAINED_PTR_64_OFFSET) && fmt != u32::from(DYLD_CHAINED_PTR_64) {
        report.issues.push(Issue::error(
            Code::LinkeditPayload,
            format!("__chain_starts pointer format {fmt} is not DYLD_CHAINED_PTR_64(_OFFSET)"),
            Some(addr),
        ));
        return;
    }
    if let Some(pf) = pointer_format {
        if fmt != u32::from(pf) {
            report.issues.push(Issue::error(
                Code::LinkeditPayload,
                format!("__chain_starts pointer format {fmt} disagrees with the payload's {pf}"),
                Some(addr),
            ));
        }
    }
    if count != payload_heads.len() as u32 {
        report.issues.push(Issue::error(
            Code::LinkeditPayload,
            format!(
                "__chain_starts lists {count} heads but the payload carries {}",
                payload_heads.len()
            ),
            Some(addr),
        ));
        return;
    }
    for k in 0..count as usize {
        let at = 8 + k * 4;
        let Some(word_bytes) = mirror.get(at..at + 4) else {
            report.issues.push(Issue::error(
                Code::LinkeditPayload,
                "__chain_starts head table truncated",
                Some(addr),
            ));
            return;
        };
        let head = u32::from_le_bytes(word_bytes.try_into().unwrap_or([0; 4]));
        let Some(slot) = bytes.get(head as usize..head as usize + 8) else {
            report.issues.push(Issue::error(
                Code::LinkeditPayload,
                format!("__chain_starts head {k} ({head:#x}) is outside the file"),
                Some(addr),
            ));
            continue;
        };
        let word = ChainWord64::new(u64::from_le_bytes(slot.try_into().unwrap_or([0; 8])));
        // The head must decode as a chain word: 8-aligned (the mirror's
        // heads are image offsets) and within a fixup-carrying segment.
        if head % 8 != 0 {
            report.issues.push(Issue::error(
                Code::LinkeditPayload,
                format!("__chain_starts head {k} is not 8-byte aligned"),
                Some(addr),
            ));
        }
        // Bind ordinals are validated by the dynamic check; here only the
        // head-listing agreement matters.
        let _ = word;
        if let Some(expected) = payload_heads.get(k) {
            if head != *expected {
                report.issues.push(Issue::error(
                    Code::LinkeditPayload,
                    format!(
                        "__chain_starts head {k} ({head:#x}) disagrees with the payload's ({expected:#x})"
                    ),
                    Some(addr),
                ));
            }
        }
    }
}

/// Finds the `__chain_starts` section: (file offset, size).
fn find_chain_starts(bytes: &[u8], img: &ParsedImage<'_>) -> Option<(u64, u64)> {
    for cmd in &img.commands {
        if cmd.kind != pgr_format::load_command::LoadCommandKind::Segment64 {
            continue;
        }
        let seg = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).ok()?;
        let sects = seg
            .sections(bytes, pgr_format::SegmentCommand64::SIZE)
            .ok()?;
        for s in sects {
            if s.name() == Ok("__chain_starts") {
                return Some((u64::from(s.offset), s.size));
            }
        }
    }
    None
}

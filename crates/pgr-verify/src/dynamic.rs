//! Chained-fixups verification: payload structure and the full dyld
//! chain-walk simulation (TDD §11: "chain-walk closure — every chain ends;
//! every fixup reachable exactly once").

use crate::structural::ParsedImage;
use crate::{Code, Issue, Report, issue_from};
use pgr_format::consts::{
    DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET, DYLD_CHAINED_PTR_START_NONE, PAGE_SIZE_16K,
};
use pgr_format::fixups::{
    ChainWord64, parse_header, parse_imports, parse_starts_in_image, parse_starts_in_segment,
};
use pgr_format::{LinkeditDataCommand, SegmentCommand64};

/// Validates the `LC_DYLD_CHAINED_FIXUPS` payload and simulates dyld's walk
/// over every chain of every fixup-carrying segment.
pub(crate) fn check_fixups(
    bytes: &[u8],
    img: &ParsedImage<'_>,
    lc: &LinkeditDataCommand,
    report: &mut Report,
) {
    let payload = match lc.data(bytes) {
        Ok(p) => p,
        Err(e) => {
            report.issues.push(issue_from(&e, Code::FixupsPayload));
            return;
        }
    };
    let hdr = match parse_header(payload) {
        Ok(h) => h,
        Err(e) => {
            report.issues.push(issue_from(&e, Code::FixupsPayload));
            return;
        }
    };
    // Payload region sanity.
    let payload_len = payload.len() as u32;
    for (name, off) in [
        ("starts_offset", hdr.starts_offset),
        ("imports_offset", hdr.imports_offset),
        ("symbols_offset", hdr.symbols_offset),
    ] {
        if off > payload_len {
            report.issues.push(Issue::error(
                Code::FixupsPayload,
                format!("payload {name} {off} beyond the payload size {payload_len}"),
                Some(lc.dataoff as u64),
            ));
            return;
        }
    }
    let starts = match parse_starts_in_image(payload, hdr.starts_offset as usize) {
        Ok(s) => s,
        Err(e) => {
            report.issues.push(issue_from(&e, Code::FixupsPayload));
            return;
        }
    };
    if starts.seg_count as usize > img.segments.len() {
        report.issues.push(Issue::error(
            Code::FixupsPayload,
            format!(
                "starts-in-image covers {} segments but the header declares {}",
                starts.seg_count,
                img.segments.len()
            ),
            Some(lc.dataoff as u64),
        ));
        return;
    }

    // Imports (needed by the walk for ordinal checks).
    let imports = match parse_imports(payload, &hdr) {
        Ok(i) => i,
        Err(e) => {
            report.issues.push(issue_from(&e, Code::FixupsImport));
            return;
        }
    };
    for (i, imp) in imports.iter().enumerate() {
        let special = matches!(imp.lib_ordinal, 0 | 0xfd | 0xfe | 0xff);
        if !special && imp.lib_ordinal as usize > img.dylibs.len() {
            report.issues.push(Issue::error(
                Code::FixupsImport,
                format!(
                    "import {i}: lib_ordinal {} exceeds the {} LC_LOAD_DYLIB commands",
                    imp.lib_ordinal,
                    img.dylibs.len()
                ),
                Some(lc.dataoff as u64 + u64::from(hdr.imports_offset)),
            ));
        }
        // Name blob: names live at payload[symbols_offset + name_offset]
        // with a NUL terminator inside the payload (symbols_format == 0).
        let name_start = hdr.symbols_offset as usize + imp.name_offset as usize;
        if name_start >= payload.len() {
            report.issues.push(Issue::error(
                Code::FixupsImport,
                format!("import {i}: name offset beyond the payload name blob"),
                Some(lc.dataoff as u64 + u64::from(hdr.symbols_offset)),
            ));
        } else if payload[name_start..].iter().all(|&b| b != 0) {
            report.issues.push(Issue::error(
                Code::FixupsImport,
                format!("import {i}: unterminated name in the payload name blob"),
                Some(
                    lc.dataoff as u64 + u64::from(hdr.symbols_offset) + u64::from(imp.name_offset),
                ),
            ));
        }
    }

    // Segment lookups for the walk.
    let segments: Vec<&SegmentCommand64> = img.segments.iter().collect();
    let file_len = bytes.len() as u64;

    for (seg_index, &off) in starts.seg_info_offset.iter().enumerate() {
        if off == 0 {
            continue;
        }
        let record_at = hdr.starts_offset as usize + off as usize;
        let seg = match parse_starts_in_segment(payload, record_at) {
            Ok(s) => s,
            Err(e) => {
                report.issues.push(issue_from(&e, Code::FixupsPayload));
                return;
            }
        };
        if seg.pointer_format != DYLD_CHAINED_PTR_64_OFFSET
            && seg.pointer_format != DYLD_CHAINED_PTR_64
        {
            report.issues.push(Issue::error(
                Code::FixupsPayload,
                format!(
                    "pointer format {} unsupported (need DYLD_CHAINED_PTR_64_OFFSET or _64)",
                    seg.pointer_format
                ),
                Some(lc.dataoff as u64 + u64::from(off)),
            ));
            return;
        }
        let page_size = u64::from(seg.page_size);
        if page_size != 0x1000 && page_size != PAGE_SIZE_16K {
            report.issues.push(Issue::error(
                Code::FixupsPayload,
                format!("chain page size {page_size:#x} is neither 0x1000 nor 0x4000"),
                Some(lc.dataoff as u64 + u64::from(off)),
            ));
            return;
        }
        let Some(&mach_seg) = segments.get(seg_index) else {
            report.issues.push(Issue::error(
                Code::FixupsPayload,
                format!("fixup segment index {seg_index} has no matching LC_SEGMENT_64"),
                Some(lc.dataoff as u64),
            ));
            return;
        };
        // Peregrine's contract: segment_offset is image-base-relative, which
        // under `vmaddr = fileoff + delta` equals the segment's file offset.
        if seg.segment_offset != mach_seg.fileoff {
            report.issues.push(Issue::error(
                Code::FixupsSegmentOffset,
                format!(
                    "payload segment_offset {:#x} != segment fileoff {:#x} (image-base-relative contract)",
                    seg.segment_offset, mach_seg.fileoff
                ),
                Some(lc.dataoff as u64 + u64::from(off)),
            ));
        }
        // Pages cannot exceed the segment's virtual span.
        if u64::from(seg.page_count).saturating_mul(page_size)
            > mach_seg.vmsize.saturating_add(page_size)
        {
            report.issues.push(Issue::error(
                Code::FixupsPayload,
                format!(
                    "page_count {} covers more than the segment vmsize {:#x}",
                    seg.page_count, mach_seg.vmsize
                ),
                Some(lc.dataoff as u64 + u64::from(off)),
            ));
        }

        // The walk: every chain must terminate within its page, slots must
        // be 8-aligned file-backed words, and each slot reachable exactly once.
        let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for page in 0..seg.page_count {
            let heads = match pgr_format::fixups::page_chain_starts(payload, record_at, &seg, page)
            {
                Ok(h) => h,
                Err(e) => {
                    report.issues.push(issue_from(&e, Code::FixupsPayload));
                    return;
                }
            };
            let page_base = mach_seg
                .fileoff
                .saturating_add(u64::from(page).saturating_mul(page_size));
            for head in heads {
                if head == DYLD_CHAINED_PTR_START_NONE {
                    continue;
                }
                if u64::from(head) % 8 != 0 {
                    report.issues.push(Issue::error(
                        Code::FixupsChain,
                        format!(
                            "segment {seg_index} page {page}: chain start {head:#x} not 8-byte aligned"
                        ),
                        Some(page_base + u64::from(head)),
                    ));
                    continue;
                }
                let mut slot_off = u64::from(head);
                loop {
                    if slot_off + 8 > page_size || slot_off + 8 > mach_seg.vmsize {
                        report.issues.push(Issue::error(
                            Code::FixupsChain,
                            format!(
                                "segment {seg_index} page {page}: chain slot {slot_off:#x} leaves the page or segment"
                            ),
                            Some(page_base + slot_off),
                        ));
                        break;
                    }
                    let slot_file = page_base + slot_off;
                    if slot_file.saturating_add(8) > file_len
                        || slot_file.saturating_add(8)
                            > mach_seg.fileoff.saturating_add(mach_seg.filesize)
                    {
                        report.issues.push(Issue::error(
                            Code::FixupsChain,
                            format!(
                                "segment {seg_index} page {page}: fixup slot {slot_file:#x} is not file-backed"
                            ),
                            Some(slot_file),
                        ));
                        break;
                    }
                    if !visited.insert(slot_file) {
                        report.issues.push(Issue::error(
                            Code::FixupsChain,
                            format!(
                                "segment {seg_index} page {page}: fixup slot {slot_file:#x} reached more than once"
                            ),
                            Some(slot_file),
                        ));
                        break;
                    }
                    let word = ChainWord64::new(u64::from_le_bytes(
                        bytes[slot_file as usize..slot_file as usize + 8]
                            .try_into()
                            .unwrap_or([0; 8]),
                    ));
                    if word.is_bind() {
                        if word.bind_ordinal() as usize >= imports.len() {
                            report.issues.push(Issue::error(
                                Code::FixupsImport,
                                format!(
                                    "segment {seg_index} page {page}: bind ordinal {} beyond {} imports",
                                    word.bind_ordinal(),
                                    imports.len()
                                ),
                                Some(slot_file),
                            ));
                            break;
                        }
                    } else {
                        // Rebase: final image offset = high8 << 56 | target.
                        let target_offset =
                            (u64::from(word.rebase_high8()) << 56) | word.rebase_target();
                        if target_offset >= img.total_vmsize {
                            report.issues.push(Issue::error(
                                Code::FixupsChain,
                                format!(
                                    "segment {seg_index} page {page}: rebase target {target_offset:#x} beyond the image vmsize {:#x}",
                                    img.total_vmsize
                                ),
                                Some(slot_file),
                            ));
                            break;
                        }
                    }
                    let strides = u64::from(word.next());
                    if strides == 0 {
                        break; // chain terminates
                    }
                    let advance = strides * 4;
                    slot_off += advance;
                }
            }
        }
    }
}

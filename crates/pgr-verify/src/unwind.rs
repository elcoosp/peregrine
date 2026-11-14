//! The `__unwind_info` contract (M34): the `__TEXT,__unwind_info`
//! section dyld's exception unwinder and every backtrace reader walks
//! must be internally consistent — header arrays in bounds and in
//! order, the index sorted with one terminator, every second-level
//! page decoding through a shape the verifier walks (the regular
//! family; the compressed family is the M35 rung, refused until it
//! walks), every entry naming a 4-aligned offset inside the `__TEXT`
//! the image carries, and every encoding naming an arm64 mode nibble
//! plus a personality index the array answers to.
//!
//! The section's absence is the default (the entry-free corpus plans
//! no section — never a finding), and an empty section (size 0) is the
//! same default: the header carries no bytes to lie about.

use crate::structural::ParsedImage;
use crate::{Code, Issue, Report};
use pgr_format::consts::{
    UNWIND_ARM64_MODE_DWARF, UNWIND_ARM64_MODE_FRAME, UNWIND_ARM64_MODE_FRAME_PAUTH_LR,
    UNWIND_ARM64_MODE_FRAMELESS, UNWIND_ARM64_MODE_MASK, UNWIND_PERSONALITY_MASK,
    UNWIND_SECOND_LEVEL_COMPRESSED, UNWIND_SECOND_LEVEL_REGULAR, UNWIND_SECTION_VERSION,
};

/// The `unwind_info_section_header`'s byte width (seven `u32` words).
const HEADER_SIZE: usize = 28;
/// The index entry's byte width (three `u32` words).
const INDEX_ENTRY_SIZE: usize = 12;
/// The regular page header's byte width (`kind` u32 + two `u16`s).
const REGULAR_PAGE_HEADER_SIZE: usize = 8;
/// The compressed page header's byte width (adds two more `u16`s).
const COMPRESSED_PAGE_HEADER_SIZE: usize = 12;
/// The regular second-level entry's byte width.
const REGULAR_ENTRY_SIZE: usize = 8;
/// The LSDA index entry's byte width (two `u32` words).
const LSDA_ENTRY_SIZE: usize = 8;
/// The arm64 mode nibbles the unwinder defines.
const ARM64_MODES: [u32; 4] = [
    UNWIND_ARM64_MODE_FRAMELESS,
    UNWIND_ARM64_MODE_DWARF,
    UNWIND_ARM64_MODE_FRAME,
    UNWIND_ARM64_MODE_FRAME_PAUTH_LR,
];

/// Validates the `__unwind_info` section. Runs only when the section
/// exists with bytes (the absence and the empty section are the
/// entry-free default, never a finding).
pub(crate) fn check_unwind_info(bytes: &[u8], img: &ParsedImage<'_>, report: &mut Report) {
    let Some((off, size64, _addr)) = find_unwind_info(bytes, img) else {
        return;
    };
    if size64 == 0 {
        return;
    }
    let size = size64 as usize;
    let text_vmsize = img
        .segments
        .iter()
        .find(|s| s.name() == Ok("__TEXT"))
        .map_or(0, |s| s.vmsize);
    let err = |what: String, at: u64| Issue::error(Code::UnwindInfo, what, Some(at));
    let at = off as usize;
    let Some(s) = bytes.get(at..at + size) else {
        report.issues.push(err(
            "__unwind_info section bytes leave the file".into(),
            off,
        ));
        return;
    };
    let rd32 = |o: usize| -> Option<u32> {
        s.get(o..o + 4)
            .and_then(|w| <[u8; 4]>::try_from(w).ok().map(u32::from_le_bytes))
    };
    let rd16 = |o: usize| -> Option<u16> {
        s.get(o..o + 2)
            .and_then(|w| <[u8; 2]>::try_from(w).ok().map(u16::from_le_bytes))
    };

    if size < HEADER_SIZE {
        report.issues.push(err(
            format!(
                "__unwind_info section is truncated ({size} bytes — the header alone is \
                 {HEADER_SIZE})"
            ),
            off,
        ));
        return;
    }
    let version = rd32(0).unwrap_or(0);
    if version != UNWIND_SECTION_VERSION {
        report.issues.push(err(
            format!(
                "__unwind_info header names version {version} — dyld's unwinder walks \
                 version {UNWIND_SECTION_VERSION}"
            ),
            off,
        ));
        return;
    }
    let common_off = rd32(4).unwrap_or(0) as usize;
    let common_count = rd32(8).unwrap_or(0) as usize;
    let pers_off = rd32(12).unwrap_or(0) as usize;
    let pers_count = rd32(16).unwrap_or(0) as usize;
    let index_off = rd32(20).unwrap_or(0) as usize;
    let index_count = rd32(24).unwrap_or(0) as usize;
    // The arrays sit in one fixed order behind the header, every bound
    // inside the section (a walk past the section reads the next
    // section's bytes as array rows — the lie the bounds gate names).
    if common_off != HEADER_SIZE
        || pers_off < common_off + common_count * 4
        || index_off < pers_off + pers_count * 4
        || index_off + index_count * INDEX_ENTRY_SIZE > size
    {
        report.issues.push(err(
            format!(
                "__unwind_info header arrays are out of bounds or out of order (common \
                 encodings at {common_off:#x} × {common_count}, personalities at \
                 {pers_off:#x} × {pers_count}, index at {index_off:#x} × {index_count}, \
                 section {size} bytes)"
            ),
            off,
        ));
        return;
    }
    // The personality array indexes through a two-bit field: the
    // encoding names indices 1–3, so a fourth row is unnexecutable
    // padding no encoding can reach.
    if pers_count > 3 {
        report.issues.push(err(
            format!(
                "__unwind_info carries {pers_count} personality rows — the encoding's \
                 personality field (UNWIND_PERSONALITY_MASK) names indices 1–3"
            ),
            off,
        ));
        return;
    }
    for i in 0..pers_count {
        let p = rd32(pers_off + i * 4).unwrap_or(u32::MAX);
        if u64::from(p) >= text_vmsize {
            report.issues.push(err(
                format!(
                    "__unwind_info personality {i} names {p:#x} — beyond the __TEXT the \
                     image maps ({text_vmsize:#x})"
                ),
                off,
            ));
        }
    }

    // ---- the index: sorted, one terminator, in-bounds pages ---------------
    let mut seen_terminator = false;
    let mut prev_function = 0u32;
    let mut prev_had_page = false;
    let mut lsda_array_off: Option<u32> = None;
    for i in 0..index_count {
        let base = index_off + i * INDEX_ENTRY_SIZE;
        let function = rd32(base).unwrap_or(u32::MAX);
        let page = rd32(base + 4).unwrap_or(0);
        let lsda_at = rd32(base + 8).unwrap_or(0);
        if seen_terminator {
            report.issues.push(err(
                format!(
                    "__unwind_info index entry {i} rides behind the terminator — the \
                     terminator (page pointer 0) must be the index's last entry"
                ),
                off,
            ));
            return;
        }
        // Page-carrying entries partition the functions (strictly
        // increasing); the terminator may share the last page's base
        // only when the page is empty — the consumers' binary search
        // needs the order, never a plateau.
        if i > 0 && (function < prev_function || (prev_had_page && function == prev_function)) {
            report.issues.push(err(
                format!(
                    "__unwind_info index entries must be sorted by function offset (entry \
                     {i} names {function:#x} behind entry {}'s {prev_function:#x})",
                    i - 1
                ),
                off,
            ));
            return;
        }
        if lsda_array_off.is_none() {
            lsda_array_off = Some(lsda_at);
        } else if lsda_array_off != Some(lsda_at) {
            report.issues.push(err(
                format!(
                    "__unwind_info index entries disagree on the LSDA array's offset \
                     ({} vs {lsda_at:#x}) — the section carries one array",
                    lsda_array_off.map_or("none".into(), |v| format!("{v:#x}"))
                ),
                off,
            ));
            return;
        }
        if page == 0 {
            seen_terminator = true;
            prev_function = function;
            prev_had_page = false;
            continue;
        }
        let page_base = page as usize;
        if page_base < index_off + index_count * INDEX_ENTRY_SIZE || page_base >= size {
            report.issues.push(err(
                format!(
                    "__unwind_info index entry {i} names page {page:#x} — outside the \
                     section's second-level region"
                ),
                off,
            ));
            return;
        }
        prev_function = function;
        prev_had_page = true;
    }
    if !seen_terminator {
        report.issues.push(err(
            "__unwind_info index carries no terminator (the last entry's page pointer \
             must be 0)"
                .into(),
            off,
        ));
        return;
    }
    let lsda_off = lsda_array_off.unwrap_or(0) as usize;
    if lsda_off > size {
        report.issues.push(err(
            format!(
                "__unwind_info names its LSDA array at {lsda_off:#x} — beyond the section \
                 ({size} bytes)"
            ),
            off,
        ));
        return;
    }

    // ---- the second-level pages --------------------------------------------
    for i in 0..index_count {
        let base = index_off + i * INDEX_ENTRY_SIZE;
        let function = rd32(base).unwrap_or(u32::MAX);
        let page = rd32(base + 4).unwrap_or(0);
        if page == 0 {
            continue; // the terminator
        }
        let page_base = page as usize;
        let kind = rd32(page_base).unwrap_or(0);
        match kind {
            UNWIND_SECOND_LEVEL_REGULAR => {
                let entry_at = rd16(page_base + 4).unwrap_or(0) as usize;
                let entry_count = rd16(page_base + 6).unwrap_or(0) as usize;
                if entry_at < REGULAR_PAGE_HEADER_SIZE
                    || page_base + entry_at + entry_count * REGULAR_ENTRY_SIZE > size
                {
                    report.issues.push(err(
                        format!(
                            "__unwind_info regular page {i} carries {entry_count} entries at \
                             {entry_at:#x} — out of bounds or behind the page header"
                        ),
                        off,
                    ));
                    return;
                }
                let mut prev = None;
                for e in 0..entry_count {
                    let at = page_base + entry_at + e * REGULAR_ENTRY_SIZE;
                    let f = rd32(at).unwrap_or(u32::MAX);
                    let encoding = rd32(at + 4).unwrap_or(0);
                    if let Some(p) = prev
                        && f < p
                    {
                        report.issues.push(err(
                            format!(
                                "__unwind_info page {i}'s entries must be sorted by function \
                                 offset (entry {e} names {f:#x} behind {p:#x})"
                            ),
                            off,
                        ));
                        return;
                    }
                    if f < function {
                        report.issues.push(err(
                            format!(
                                "__unwind_info page {i}'s entry {e} names {f:#x} — behind the \
                                 page's index base {function:#x}"
                            ),
                            off,
                        ));
                        return;
                    }
                    if u64::from(f) >= text_vmsize {
                        report.issues.push(err(
                            format!(
                                "__unwind_info page {i}'s entry {e} names {f:#x} — beyond the \
                                 __TEXT the image maps ({text_vmsize:#x})"
                            ),
                            off,
                        ));
                    }
                    if !ARM64_MODES.contains(&(encoding & UNWIND_ARM64_MODE_MASK)) {
                        report.issues.push(err(
                            format!(
                                "__unwind_info page {i}'s entry {e} carries encoding \
                                 {encoding:#010x} — the mode nibble names no arm64 unwind mode"
                            ),
                            off,
                        ));
                    }
                    let index = (encoding & UNWIND_PERSONALITY_MASK) >> 28;
                    if index as usize > pers_count {
                        report.issues.push(err(
                            format!(
                                "__unwind_info page {i}'s entry {e} names personality index \
                                 {index} — the array carries {pers_count} rows"
                            ),
                            off,
                        ));
                    }
                    prev = Some(f);
                }
            }
            UNWIND_SECOND_LEVEL_COMPRESSED => {
                // The M35 rung: the compressed page family is refused
                // typed until the verifier walks it (a compressed page
                // this reader cannot decode is a page it must not
                // pretend to have checked).
                let entry_at = rd16(page_base + 4).unwrap_or(0) as usize;
                let entry_count = rd16(page_base + 6).unwrap_or(0) as usize;
                let _ = (entry_at, entry_count, COMPRESSED_PAGE_HEADER_SIZE);
                report.issues.push(err(
                    format!(
                        "__unwind_info page {i} is a compressed second-level page — this \
                         verifier walks the regular family only (the M35 rung carries the \
                         compressed walk)"
                    ),
                    off,
                ));
            }
            other => {
                report.issues.push(err(
                    format!(
                        "__unwind_info page {i} carries kind {other} — dyld's unwinder walks \
                         kinds {UNWIND_SECOND_LEVEL_REGULAR} (regular) and \
                         {UNWIND_SECOND_LEVEL_COMPRESSED} (compressed) only"
                    ),
                    off,
                ));
            }
        }
    }

    // ---- the LSDA index array ------------------------------------------------
    if lsda_off + 8 <= size {
        let rows = (size - lsda_off) / LSDA_ENTRY_SIZE;
        let mut prev = None;
        for r in 0..rows {
            let at = lsda_off + r * LSDA_ENTRY_SIZE;
            let f = rd32(at).unwrap_or(u32::MAX);
            let l = rd32(at + 4).unwrap_or(u32::MAX);
            if let Some(p) = prev
                && f < p
            {
                report.issues.push(err(
                    format!(
                        "__unwind_info LSDA rows must be sorted by function offset (row {r} \
                         names {f:#x} behind {p:#x})"
                    ),
                    off,
                ));
                return;
            }
            if l != u32::MAX && u64::from(l) >= text_vmsize {
                report.issues.push(err(
                    format!(
                        "__unwind_info LSDA row {r} names {l:#x} — beyond the __TEXT the \
                         image maps ({text_vmsize:#x})"
                    ),
                    off,
                ));
            }
            prev = Some(f);
        }
    }
}

/// Finds the image's `__TEXT,__unwind_info` section: file offset, size
/// and vmaddr (the `__TEXT` segment's first section with that name).
fn find_unwind_info(bytes: &[u8], img: &ParsedImage<'_>) -> Option<(u64, u64, u64)> {
    for cmd in &img.commands {
        if cmd.kind != pgr_format::load_command::LoadCommandKind::Segment64 {
            continue;
        }
        let seg = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).ok()?;
        let sects = seg
            .sections(bytes, cmd.offset + pgr_format::SegmentCommand64::SIZE)
            .ok()?;
        for s in sects {
            if s.name() == Ok("__unwind_info") && s.segname.starts_with(b"__TEXT\0") {
                return Some((u64::from(s.offset), s.size, s.addr));
            }
        }
    }
    None
}

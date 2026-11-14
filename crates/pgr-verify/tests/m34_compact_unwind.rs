//! M34 — the verifier's `__unwind_info` contract: the section dyld's
//! unwinder walks must be internally consistent (a section the reader
//! cannot walk is a section that lies), and every offset it names must
//! sit inside the `__TEXT` it annotates. The shapes here are built by
//! hand — the verifier gates shapes built independently of the
//! producer (the §11 different-code-path rule; the synthesis seam is
//! gated in pgr-core's own tests).
//!
//! Gate matrix:
//! * the honest section (built by hand, mirroring the synthesis
//!   layout) verifies strict;
//! * the broken shapes gate — a truncated header, a wrong version, an
//!   out-of-bounds array, an unsorted index, a missing terminator, an
//!   unsupported page kind (the M35 compressed pages are refused until
//!   they walk), an unsorted or out-of-bounds entry stream, an
//!   encoding whose arm64 mode nibble no arm64 unwinder defines, a
//!   personality index naming no slot, an unsorted LSDA array;
//! * the absence — an image without the section stays clean (the
//!   entry-free corpus is the default, never a finding);
//! * the selection — `unwind` joins the `--checks` surface (the M12
//!   registry), `Check::ALL` carries it in canonical order.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_verify::{Check, CheckSet, Code, Options, Severity, verify, verify_with_checks};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// One regular second-level entry (`functionOffset`, `encoding`).
const REGULAR_ENTRY_SIZE: usize = 8;
/// `unwind_info_regular_second_level_page_header` (kind u32, entryPageOffset
/// u16, entryCount u16).
const PAGE_HEADER_SIZE: usize = 8;
/// `unwind_info_section_header` (seven u32 words).
const HEADER_SIZE: usize = 28;
/// `unwind_info_section_header_index_entry` (three u32 words).
const INDEX_ENTRY_SIZE: usize = 12;
/// `unwind_info_section_header_lsda_index_entry` (two u32 words).
const LSDA_ENTRY_SIZE: usize = 8;

/// An arm64 frame-mode encoding (mode nibble 0x04000000, `x19/x20`).
const FRAME_ENCODING: u32 = 0x0400_0000;
/// A personality index of 1 in the encoding's personality field (bits
/// 28–29, `UNWIND_PERSONALITY_MASK`).
fn with_personality(encoding: u32, index: u32) -> u32 {
    (encoding & !0x3000_0000) | (index << 28)
}

/// Builds an honest `__unwind_info` for `entries` of
/// `(function_offset, encoding)` rows (all in one regular page, 4-byte
/// ranges), with `personalities` naming the `__TEXT`-relative
/// personality offsets the encodings' indices point at, and `lsdas`
/// the `(function, lsda)` rows.
fn honest_unwind_info(
    entries: &[(u32, u32)],
    personalities: &[u32],
    lsdas: &[(u32, u32)],
) -> Vec<u8> {
    let n_common = 0usize; // regular pages carry full encodings; none common
    let common_off = HEADER_SIZE;
    let personality_off = common_off + n_common * 4;
    let index_off = personality_off + personalities.len() * 4;
    let index_count = 2usize; // one page + the terminator
    let page_off = index_off + index_count * INDEX_ENTRY_SIZE;
    let lsda_off = page_off + PAGE_HEADER_SIZE + entries.len() * REGULAR_ENTRY_SIZE;
    let total = lsda_off + lsdas.len() * LSDA_ENTRY_SIZE;

    let mut b = Vec::with_capacity(total);
    b.extend_from_slice(&1u32.to_le_bytes()); // version
    b.extend_from_slice(&(common_off as u32).to_le_bytes());
    b.extend_from_slice(&(n_common as u32).to_le_bytes());
    b.extend_from_slice(&(personality_off as u32).to_le_bytes());
    b.extend_from_slice(&(personalities.len() as u32).to_le_bytes());
    b.extend_from_slice(&(index_off as u32).to_le_bytes());
    b.extend_from_slice(&(index_count as u32).to_le_bytes());
    // personalities
    for p in personalities {
        b.extend_from_slice(&p.to_le_bytes());
    }
    // index: the one page, then the terminator (secondLevelPagesSectionOffset 0)
    let first = entries.first().map_or(0, |e| e.0);
    b.extend_from_slice(&first.to_le_bytes());
    b.extend_from_slice(&(page_off as u32).to_le_bytes());
    b.extend_from_slice(&(lsda_off as u32).to_le_bytes());
    let end = entries.last().map_or(first, |e| e.0 + 4);
    b.extend_from_slice(&end.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&(lsda_off as u32).to_le_bytes());
    // the regular page (kind 2)
    b.extend_from_slice(&2u32.to_le_bytes());
    b.extend_from_slice(&(PAGE_HEADER_SIZE as u16).to_le_bytes());
    b.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for (off, enc) in entries {
        b.extend_from_slice(&off.to_le_bytes());
        b.extend_from_slice(&enc.to_le_bytes());
    }
    // the lsda index array
    for (f, l) in lsdas {
        b.extend_from_slice(&f.to_le_bytes());
        b.extend_from_slice(&l.to_le_bytes());
    }
    b
}

/// An executable whose `__text` spans 64 bytes of filler, carrying the
/// named `__unwind_info` section bytes.
fn exec_with_unwind(section: Vec<u8>) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m34exec");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_EXECUTE,
        initprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_EXECUTE,
        sections: vec![
            SectionSpec {
                name: "__text".into(),
                align_log2: 2,
                flags: pgr_format::consts::S_REGULAR | pgr_format::consts::S_ATTR_PURE_INSTRUCTIONS,
                data: filler(0x5AA5, 64),
                relocs: Vec::new(),
            },
            SectionSpec {
                name: "__unwind_info".into(),
                align_log2: 2,
                flags: pgr_format::consts::S_REGULAR,
                data: section,
                relocs: Vec::new(),
            },
        ],
    });
    b.set_entry(0);
    b
}

// ---- the honest shape ----------------------------------------------------------

#[test]
fn an_honest_section_verifies_strict() {
    let section = honest_unwind_info(
        &[
            (0, FRAME_ENCODING),
            (8, FRAME_ENCODING),
            (16, FRAME_ENCODING),
        ],
        &[],
        &[(8, 0x3C)],
    );
    let img = exec_with_unwind(section)
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the honest section verifies strict: {:?}",
        report.issues
    );
    assert!(
        !report.issues.iter().any(|i| i.code == Code::UnwindInfo),
        "no unwind findings ride the honest shape: {:?}",
        report.issues
    );
}

#[test]
fn an_image_without_the_section_stays_clean() {
    let mut b = ImageBuilder::executable("m34plain");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_EXECUTE,
        initprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: pgr_format::consts::S_REGULAR | pgr_format::consts::S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0x5AA5, 64),
            relocs: Vec::new(),
        }],
    });
    b.set_entry(0);
    let img = b.build().expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the absence is the default, never a finding: {:?}",
        report.issues
    );
}

// ---- the broken shapes (the hand-built controls) ----------------------------------

#[test]
fn a_truncated_header_is_an_error() {
    let section = honest_unwind_info(&[(0, FRAME_ENCODING)], &[], &[])[..16].to_vec();
    let img = exec_with_unwind(section)
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.code == Code::UnwindInfo
            && i.severity == Severity::Error
            && i.message.contains("truncated")),
        "the truncated header names its shape: {:?}",
        report.issues
    );
}

#[test]
fn a_wrong_version_is_an_error() {
    let mut section = honest_unwind_info(&[(0, FRAME_ENCODING)], &[], &[]);
    section[0] = 2; // UNWIND_SECTION_VERSION is 1
    let img = exec_with_unwind(section)
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.code == Code::UnwindInfo
            && i.severity == Severity::Error
            && i.message.contains("version")),
        "the version refusal names the field: {:?}",
        report.issues
    );
}

#[test]
fn an_array_leaving_the_section_is_an_error() {
    let mut section = honest_unwind_info(&[(0, FRAME_ENCODING)], &[], &[]);
    // Push the index offset past the section's end.
    let patch = HEADER_SIZE + 4 * 4; // indexSectionOffset word
    let lie = (section.len() as u32) + 64;
    section[patch..patch + 4].copy_from_slice(&lie.to_le_bytes());
    let img = exec_with_unwind(section)
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.code == Code::UnwindInfo && i.severity == Severity::Error),
        "the out-of-bounds array gates: {:?}",
        report.issues
    );
}

#[test]
fn an_unsorted_index_is_an_error() {
    // Swap the index's page entry with the terminator: the terminator
    // (page pointer 0) must be the index's LAST entry — an index whose
    // page entries ride behind it is the shape no reader walks.
    let mut section = honest_unwind_info(&[(0, FRAME_ENCODING), (8, FRAME_ENCODING)], &[], &[]);
    let index_off = u32::from_le_bytes([
        section[HEADER_SIZE - 8],
        section[HEADER_SIZE - 7],
        section[HEADER_SIZE - 6],
        section[HEADER_SIZE - 5],
    ]) as usize;
    let (a, b) = (index_off, index_off + INDEX_ENTRY_SIZE);
    for k in 0..INDEX_ENTRY_SIZE {
        section.swap(a + k, b + k);
    }
    let img = exec_with_unwind(section)
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.code == Code::UnwindInfo
            && i.severity == Severity::Error
            && i.message.contains("terminator")),
        "the index order contract gates: {:?}",
        report.issues
    );
}

#[test]
fn a_compressed_page_kind_is_refused_until_it_walks() {
    // Hand-build a one-page section whose page kind is 3 (the M35
    // compressed shape the verifier does not walk yet).
    let entries = [(0u32, FRAME_ENCODING)];
    let personalities: [u32; 0] = [];
    let mut section = honest_unwind_info(&entries, &personalities, &[]);
    let index_off = u32::from_le_bytes([
        section[HEADER_SIZE - 8],
        section[HEADER_SIZE - 7],
        section[HEADER_SIZE - 6],
        section[HEADER_SIZE - 5],
    ]) as usize;
    let page_off = u32::from_le_bytes([
        section[index_off + 4],
        section[index_off + 5],
        section[index_off + 6],
        section[index_off + 7],
    ]) as usize;
    section[page_off..page_off + 4].copy_from_slice(&3u32.to_le_bytes());
    let img = exec_with_unwind(section)
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.code == Code::UnwindInfo
            && i.severity == Severity::Error
            && i.message.contains("compressed")),
        "the compressed page kind refuses typed: {:?}",
        report.issues
    );
}

#[test]
fn an_unsorted_page_entry_stream_is_an_error() {
    let mut section = honest_unwind_info(&[(0, FRAME_ENCODING), (8, FRAME_ENCODING)], &[], &[]);
    let index_off = u32::from_le_bytes([
        section[HEADER_SIZE - 8],
        section[HEADER_SIZE - 7],
        section[HEADER_SIZE - 6],
        section[HEADER_SIZE - 5],
    ]) as usize;
    let page_off = u32::from_le_bytes([
        section[index_off + 4],
        section[index_off + 5],
        section[index_off + 6],
        section[index_off + 7],
    ]) as usize;
    let first_entry = page_off + PAGE_HEADER_SIZE;
    // Swap the two entries' function offsets (descending stream).
    let (a, b) = (first_entry, first_entry + REGULAR_ENTRY_SIZE);
    for k in 0..4 {
        section.swap(a + k, b + k);
    }
    let img = exec_with_unwind(section)
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.code == Code::UnwindInfo
            && i.severity == Severity::Error
            && i.message.contains("sorted")),
        "the entry sort contract gates: {:?}",
        report.issues
    );
}

#[test]
fn an_entry_beyond_text_is_an_error() {
    // The `__text` spans 64 bytes; an entry at 0x4000 annotates bytes
    // past the segment's mapped end.
    let section = honest_unwind_info(&[(0x4000, FRAME_ENCODING)], &[], &[]);
    let img = exec_with_unwind(section)
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.code == Code::UnwindInfo
            && i.severity == Severity::Error
            && i.message.contains("__TEXT")),
        "the beyond-__TEXT entry gates: {:?}",
        report.issues
    );
}

#[test]
fn an_unknown_arm64_mode_is_an_error() {
    let section = honest_unwind_info(&[(0, 0x0100_0000)], &[], &[]);
    let img = exec_with_unwind(section)
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.code == Code::UnwindInfo
            && i.severity == Severity::Error
            && i.message.contains("arm64")),
        "the mode contract gates: {:?}",
        report.issues
    );
}

#[test]
fn a_dangling_personality_index_is_an_error() {
    let section = honest_unwind_info(
        &[(0, with_personality(FRAME_ENCODING, 2))],
        &[0x30], // one slot; the encoding names index 2
        &[],
    );
    let img = exec_with_unwind(section)
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.code == Code::UnwindInfo
            && i.severity == Severity::Error
            && i.message.contains("personality")),
        "the personality-index contract gates: {:?}",
        report.issues
    );
}

#[test]
fn an_unsorted_lsda_array_is_an_error() {
    let section = honest_unwind_info(
        &[(0, FRAME_ENCODING), (8, FRAME_ENCODING)],
        &[],
        &[(16, 0x30), (8, 0x3C)], // descending function offsets
    );
    let img = exec_with_unwind(section)
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.code == Code::UnwindInfo
            && i.severity == Severity::Error
            && i.message.contains("sorted")),
        "the LSDA sort contract gates: {:?}",
        report.issues
    );
}

// ---- the selection -----------------------------------------------------------------

#[test]
fn the_unwind_family_joins_the_registry() {
    assert_eq!(
        Check::ALL.iter().position(|c| *c == Check::Unwind),
        Some(6),
        "the unwind family rides beside the chain-starts mirror (the static-section families)"
    );
    assert_eq!(Check::Unwind.as_str(), "unwind");
    let set = CheckSet::parse("unwind").expect("the name parses");
    assert!(set.contains(Check::Unwind));
    let report = verify_with_checks(
        &exec_with_unwind(honest_unwind_info(&[(0, FRAME_ENCODING)], &[], &[]))
            .build()
            .expect("the fixture builds")
            .bytes,
        &opts(),
        &set,
    );
    assert!(
        report.is_ok(&opts()),
        "the selected family alone gates the honest shape: {:?}",
        report.issues
    );
}

#[test]
fn a_broken_section_fails_the_selected_family() {
    let mut section = honest_unwind_info(&[(0, FRAME_ENCODING)], &[], &[]);
    section[0] = 9;
    let set = CheckSet::parse("unwind").expect("the name parses");
    let report = verify_with_checks(
        &exec_with_unwind(section)
            .build()
            .expect("the fixture builds")
            .bytes,
        &opts(),
        &set,
    );
    assert!(
        report.issues.iter().any(|i| i.code == Code::UnwindInfo),
        "the selected family gates the broken shape: {:?}",
        report.issues
    );
}

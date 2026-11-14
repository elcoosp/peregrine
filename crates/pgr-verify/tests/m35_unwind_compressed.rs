//! M35 — the verifier's compressed-page walk: the `__unwind_info`
//! second-level pages ride two families (regular and compressed), and
//! the compressed family's contract gates the same lies the regular
//! family gates — entries sorted, inside the `__TEXT` the image
//! carries, every encoding index resolving through the two-tier
//! decode libunwind runs (the section-level common encodings array
//! first, then the page-local array the compressed page header
//! names), every resolved word naming an arm64 mode nibble and a
//! personality index the arrays answer to. The shapes here are built
//! by hand — the verifier gates shapes built independently of the
//! producer (the §11 different-code-path rule; the synthesis seam is
//! gated in pgr-core's own tests).
//!
//! Gate matrix:
//! * the honest compressed section (a common array, index entries
//!   resolving at tier one) verifies strict;
//! * the honest page-local tier — an index landing past the common
//!   array resolves through the page-local rows — verifies strict
//!   (the two-tier decode the third-party producers ride);
//! * the broken shapes gate — an index resolving through neither
//!   array, a common or page-local row whose arm64 mode nibble no
//!   unwinder defines, a dangling personality index inside a common
//!   word, an unsorted entry stream, an entry beyond the `__TEXT`,
//!   an entry array behind the 12-byte page header or past the
//!   section, an encodings array past the section;
//! * the common-array rows gate their own words on every image (the
//!   regular-family shape carries the array empty — the gate is
//!   vacuous there, real the moment a row exists).

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_verify::{Check, CheckSet, Code, Options, Severity, verify, verify_with_checks};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// `unwind_info_section_header` (seven u32 words).
const HEADER_SIZE: usize = 28;
/// The index entry's byte width (three u32 words).
const INDEX_ENTRY_SIZE: usize = 12;
/// The compressed page header's byte width (kind u32 + four u16s: the
/// entry array's offset/count, then the page-local encodings array's
/// offset/count).
const COMPRESSED_PAGE_HEADER_SIZE: usize = 12;
/// The compressed entry's byte width (`(encodingIndex << 24) |
/// functionOffset`).
const COMPRESSED_ENTRY_SIZE: usize = 4;
/// The LSDA index entry's byte width (two u32 words).
const LSDA_ENTRY_SIZE: usize = 8;

/// An arm64 frame-mode encoding (mode nibble 0x04000000, `x19/x20`).
const FRAME_ENCODING: u32 = 0x0400_0000;
/// An arm64 frameless encoding (mode nibble 0x02000000).
const FRAMELESS_ENCODING: u32 = 0x0200_0000;

/// A personality index of `index` in the encoding's personality
/// field (bits 28–29, `UNWIND_PERSONALITY_MASK`).
fn with_personality(encoding: u32, index: u32) -> u32 {
    (encoding & !0x3000_0000) | (index << 28)
}

/// The compressed entry word: the index in the top 8 bits, the
/// function offset in the low 24.
fn compressed_entry(function: u32, index: u32) -> u32 {
    (index << 24) | function
}

/// Builds an honest compressed second-level page section: the common
/// array's rows, `entries` as `(function_offset, encoding_index)`
/// pairs (one page), `page_local` the page-local encodings rows the
/// entries may index past the common count, `personalities` the
/// personality offsets, `lsdas` the `(function, lsda)` rows.
fn compressed_unwind_info(
    common: &[u32],
    entries: &[(u32, u32)],
    page_local: &[u32],
    personalities: &[u32],
    lsdas: &[(u32, u32)],
) -> Vec<u8> {
    let common_off = HEADER_SIZE;
    let personality_off = common_off + common.len() * 4;
    let index_off = personality_off + personalities.len() * 4;
    let index_count = 2usize; // one page + the terminator
    let page_off = index_off + index_count * INDEX_ENTRY_SIZE;
    let page_local_at = COMPRESSED_PAGE_HEADER_SIZE + entries.len() * COMPRESSED_ENTRY_SIZE;
    let lsda_off = page_off + page_local_at + page_local.len() * 4;
    let total = lsda_off + lsdas.len() * LSDA_ENTRY_SIZE;

    let mut b = Vec::with_capacity(total);
    b.extend_from_slice(&1u32.to_le_bytes()); // version
    b.extend_from_slice(&(common_off as u32).to_le_bytes());
    b.extend_from_slice(&(common.len() as u32).to_le_bytes());
    b.extend_from_slice(&(personality_off as u32).to_le_bytes());
    b.extend_from_slice(&(personalities.len() as u32).to_le_bytes());
    b.extend_from_slice(&(index_off as u32).to_le_bytes());
    b.extend_from_slice(&(index_count as u32).to_le_bytes());
    // the common encodings array
    for w in common {
        b.extend_from_slice(&w.to_le_bytes());
    }
    // the personality array
    for p in personalities {
        b.extend_from_slice(&p.to_le_bytes());
    }
    // the index: the one page, then the terminator (page pointer 0)
    let first = entries.first().map_or(0, |e| e.0);
    b.extend_from_slice(&first.to_le_bytes());
    b.extend_from_slice(&(page_off as u32).to_le_bytes());
    b.extend_from_slice(&(lsda_off as u32).to_le_bytes());
    let end = entries.last().map_or(first, |e| e.0 + 4);
    b.extend_from_slice(&end.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&(lsda_off as u32).to_le_bytes());
    // the compressed page header (kind 3) + the entries
    b.extend_from_slice(&3u32.to_le_bytes());
    b.extend_from_slice(&(COMPRESSED_PAGE_HEADER_SIZE as u16).to_le_bytes());
    b.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    b.extend_from_slice(&(page_local_at as u16).to_le_bytes());
    b.extend_from_slice(&(page_local.len() as u16).to_le_bytes());
    for (f, idx) in entries {
        b.extend_from_slice(&compressed_entry(*f, *idx).to_le_bytes());
    }
    // the page-local encodings array
    for w in page_local {
        b.extend_from_slice(&w.to_le_bytes());
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
    let mut b = ImageBuilder::executable("m35exec");
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

fn report_of(section: Vec<u8>) -> pgr_verify::Report {
    let img = exec_with_unwind(section)
        .build()
        .expect("the fixture builds");
    verify(&img.bytes, &opts())
}

fn has_error(report: &pgr_verify::Report, needle: &str) -> bool {
    report.issues.iter().any(|i| {
        i.code == Code::UnwindInfo && i.severity == Severity::Error && i.message.contains(needle)
    })
}

// ---- the honest shapes -------------------------------------------------------------

#[test]
fn an_honest_compressed_section_verifies_strict() {
    // Two common words; the index entries resolve at tier one.
    let section = compressed_unwind_info(
        &[FRAME_ENCODING, FRAMELESS_ENCODING],
        &[(0, 1), (4, 0), (8, 0)],
        &[],
        &[],
        &[],
    );
    let report = report_of(section);
    assert!(
        report.is_ok(&opts()),
        "the honest compressed section verifies strict: {:?}",
        report.issues
    );
    assert!(
        !report.issues.iter().any(|i| i.code == Code::UnwindInfo),
        "no unwind findings ride the honest shape: {:?}",
        report.issues
    );
}

#[test]
fn an_honest_page_local_tier_verifies_strict() {
    // One common word; the second entry's index lands past it and
    // resolves through the page-local array (the two-tier decode).
    let section = compressed_unwind_info(
        &[FRAME_ENCODING],
        &[(0, 0), (4, 1)],
        &[FRAMELESS_ENCODING],
        &[],
        &[],
    );
    let report = report_of(section);
    assert!(
        report.is_ok(&opts()),
        "the tier-two index resolves through the page-local array: {:?}",
        report.issues
    );
}

#[test]
fn the_common_rows_gate_their_words_on_any_image() {
    // A common row whose mode nibble no arm64 unwinder defines — the
    // array's own contract, independent of which page family indexes
    // it.
    let section = compressed_unwind_info(&[0x0100_0000], &[(0, 0)], &[], &[], &[]);
    let report = report_of(section);
    assert!(
        has_error(&report, "arm64"),
        "the common row's mode contract gates: {:?}",
        report.issues
    );
}

// ---- the broken shapes (the hand-built controls) -------------------------------------

#[test]
fn an_index_resolving_through_neither_array_is_an_error() {
    // Two common rows, no page-local rows: the index 2 resolves
    // through neither tier — the shape no reader can decode.
    let section = compressed_unwind_info(
        &[FRAME_ENCODING, FRAMELESS_ENCODING],
        &[(0, 2)],
        &[],
        &[],
        &[],
    );
    let report = report_of(section);
    assert!(
        has_error(&report, "index"),
        "the two-tier index contract gates: {:?}",
        report.issues
    );
}

#[test]
fn a_page_local_row_gates_its_mode() {
    let section = compressed_unwind_info(
        &[FRAME_ENCODING],
        &[(0, 1)],
        &[0x0100_0000], // x86-only mode nibble
        &[],
        &[],
    );
    let report = report_of(section);
    assert!(
        has_error(&report, "arm64"),
        "the page-local row's mode contract gates: {:?}",
        report.issues
    );
}

#[test]
fn a_dangling_personality_index_in_a_common_word_is_an_error() {
    let section = compressed_unwind_info(
        &[with_personality(FRAME_ENCODING, 2)],
        &[(0, 0)],
        &[],
        &[0x30], // one slot; the word names index 2
        &[],
    );
    let report = report_of(section);
    assert!(
        has_error(&report, "personality"),
        "the common word's personality contract gates: {:?}",
        report.issues
    );
}

#[test]
fn an_unsorted_compressed_entry_stream_is_an_error() {
    let section = compressed_unwind_info(
        &[FRAME_ENCODING],
        &[(4, 0), (0, 0)], // descending function offsets
        &[],
        &[],
        &[],
    );
    let report = report_of(section);
    assert!(
        has_error(&report, "sorted"),
        "the entry sort contract gates: {:?}",
        report.issues
    );
}

#[test]
fn a_compressed_entry_beyond_text_is_an_error() {
    // The `__text` spans 64 bytes; an entry at 0x4000 annotates bytes
    // past the segment's mapped end.
    let section = compressed_unwind_info(&[FRAME_ENCODING], &[(0x4000, 0)], &[], &[], &[]);
    let report = report_of(section);
    assert!(
        has_error(&report, "__TEXT"),
        "the beyond-__TEXT entry gates: {:?}",
        report.issues
    );
}

#[test]
fn an_entry_array_behind_the_page_header_is_an_error() {
    let mut section = compressed_unwind_info(&[FRAME_ENCODING], &[(0, 0)], &[], &[], &[]);
    // entryPageOffset rides the page header's second field: point it
    // behind the 12-byte header.
    let index_off =
        u32::from_le_bytes([section[20], section[21], section[22], section[23]]) as usize;
    let page_off = u32::from_le_bytes([
        section[index_off + 4],
        section[index_off + 5],
        section[index_off + 6],
        section[index_off + 7],
    ]) as usize;
    section[page_off + 4] = 4;
    let report = report_of(section);
    assert!(
        has_error(&report, "behind"),
        "the entry-array bounds contract gates: {:?}",
        report.issues
    );
}

#[test]
fn an_entry_array_leaving_the_section_is_an_error() {
    let mut section = compressed_unwind_info(&[FRAME_ENCODING], &[(0, 0)], &[], &[], &[]);
    let index_off =
        u32::from_le_bytes([section[20], section[21], section[22], section[23]]) as usize;
    let page_off = u32::from_le_bytes([
        section[index_off + 4],
        section[index_off + 5],
        section[index_off + 6],
        section[index_off + 7],
    ]) as usize;
    // entryCount: claim 4096 entries — the array leaves the section.
    section[page_off + 6] = 0x10;
    section[page_off + 7] = 0x10;
    let report = report_of(section);
    assert!(
        has_error(&report, "bounds"),
        "the entry-count bounds contract gates: {:?}",
        report.issues
    );
}

#[test]
fn an_encodings_array_leaving_the_section_is_an_error() {
    let mut section = compressed_unwind_info(&[FRAME_ENCODING], &[(0, 0)], &[], &[], &[]);
    let index_off =
        u32::from_le_bytes([section[20], section[21], section[22], section[23]]) as usize;
    let page_off = u32::from_le_bytes([
        section[index_off + 4],
        section[index_off + 5],
        section[index_off + 6],
        section[index_off + 7],
    ]) as usize;
    // encodingsCount: claim 400 rows — the page-local array leaves
    // the section.
    section[page_off + 10] = 0x90;
    section[page_off + 11] = 0x01;
    let report = report_of(section);
    assert!(
        has_error(&report, "encodings"),
        "the page-local array bounds contract gates: {:?}",
        report.issues
    );
}

// ---- the selection -----------------------------------------------------------------

#[test]
fn the_compressed_shape_fails_the_selected_family() {
    let section = compressed_unwind_info(
        &[FRAME_ENCODING, FRAMELESS_ENCODING],
        &[(0, 2)],
        &[],
        &[],
        &[],
    );
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
        "the selected family gates the broken compressed shape: {:?}",
        report.issues
    );
}

#[test]
fn the_unwind_family_registry_is_unchanged() {
    assert_eq!(Check::Unwind.as_str(), "unwind");
    let set = CheckSet::parse("unwind").expect("the name parses");
    assert!(set.contains(Check::Unwind));
}

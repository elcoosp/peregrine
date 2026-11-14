//! M35 — the compressed second-level page rung: the synthesis
//! gathers the table's distinct final encoding words into the
//! section-level common encodings array (first-use order over the
//! sorted stream, the 8-bit index space capping the array at 256
//! rows), and a second-level page rides the compressed family
//! (`UNWIND_SECOND_LEVEL_COMPRESSED`) exactly when every row it
//! carries qualifies — its `functionOffset` fits the 24-bit
//! compressed field and its encoding word sits in the common array.
//! An unqualifying row keeps its whole page regular (the M34 shape,
//! the byte-identical fallback), so a corpus past the 16 MiB
//! `__TEXT` mark or past the encoding cap plans the pre-M35 bytes.
//!
//! Gate matrix:
//! * the compressed page — a qualifying table synthesizes one
//!   compressed page whose entries decode `(encodingIndex << 24) |
//!   functionOffset` through the common array (the two-tier decode
//!   libunwind runs; the page-local tier rides empty, count 0);
//! * the common array — dedup in first-use order over the sorted
//!   stream, the personality index riding inside the word;
//! * the planner — `plan_shape`/`synthesized_size_shape` share the
//!   builder's exact formula (the reservation can never drift), and
//!   the all-regular `synthesized_size` stays the shape's upper
//!   bound;
//! * the fallback — a table past the 24-bit offsets (or past the
//!   encoding cap) plans the pre-M35 bytes: no common rows, no
//!   compressed pages, the M34 layout verbatim; one unqualifying row
//!   keeps only its own page regular (mixed page kinds);
//! * the cap — the 256-row index space; words beyond it have no
//!   index and poison their page;
//! * the refusals — unchanged from M34 (the rung changes the page
//!   family, never the table's validity contract).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::unwind::{
    MAX_COMMON_ENCODINGS, SynthesisError, UnwindEntry, plan_shape, synthesize, synthesized_size,
    synthesized_size_shape,
};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::{
    UNWIND_ARM64_MODE_DWARF, UNWIND_ARM64_MODE_FRAME, UNWIND_ARM64_MODE_FRAMELESS,
    UNWIND_ARM64_MODE_MASK, UNWIND_PERSONALITY_MASK, UNWIND_SECOND_LEVEL_COMPRESSED,
    UNWIND_SECOND_LEVEL_REGULAR,
};

/// A canonical arm64 frame encoding (`__frame` mode, the `x19/x20`
/// pair).
const FRAME_ENCODING: u32 = UNWIND_ARM64_MODE_FRAME;
/// A canonical arm64 frameless encoding (stack-size word 0x20 — the
/// 512-byte reserve shape, /16).
const FRAMELESS_ENCODING: u32 = UNWIND_ARM64_MODE_FRAMELESS | (0x20 << 12);
/// The first offset the compressed entry's 24-bit field cannot carry
/// (`UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET_MASK` is the low 24
/// bits — 16 MiB of `__TEXT`).
const BEYOND_24_BIT: u32 = 0x0100_0000;

/// One unwind row (`personality_offset`/`lsda_offset` default to 0).
fn entry(offset: u32, len: u32, encoding: u32) -> UnwindEntry {
    UnwindEntry {
        function_offset: offset,
        range_length: len,
        encoding,
        personality_offset: 0,
        lsda_offset: 0,
    }
}

/// The header word at byte offset `at` (little-endian `u32`).
fn head(section: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([
        section[at],
        section[at + 1],
        section[at + 2],
        section[at + 3],
    ])
}

/// The index entry `i`: `(functionOffset, secondLevelPagesSectionOffset,
/// lsdaIndexArraySectionOffset)`.
fn index_entry(section: &[u8], i: usize) -> (u32, u32, u32) {
    let index_off = head(section, 20) as usize;
    let base = index_off + i * 12;
    (
        head(section, base),
        head(section, base + 4),
        head(section, base + 8),
    )
}

/// The compressed entry `i` of the page at `page`: `(functionOffset,
/// encodingIndex)` — the low 24 bits and the top 8.
fn compressed_entry(section: &[u8], page: usize, i: usize) -> (u32, u32) {
    let entry_at = u16::from_le_bytes([section[page + 4], section[page + 5]]) as usize;
    let at = page + entry_at + i * 4;
    let w = head(section, at);
    (w & 0x00FF_FFFF, w >> 24)
}

// ---- the compressed page --------------------------------------------------------

#[test]
fn a_compressible_table_synthesizes_compressed_pages() {
    let entries = [
        entry(0, 4, FRAMELESS_ENCODING),
        entry(4, 4, FRAME_ENCODING),
        entry(8, 4, FRAME_ENCODING),
    ];
    let info = synthesize(&entries).expect("the qualifying table synthesizes");
    assert_eq!(info.page_count, 1);
    assert_eq!(
        info.compressed_page_count, 1,
        "every row qualifies — the page rides the compressed family"
    );
    assert_eq!(
        info.common_encoding_count, 2,
        "the two distinct words dedup into the common array"
    );

    let b = &info.bytes;
    // The header names the common array at 28, then the personality
    // array (empty) and the index behind it.
    assert_eq!(head(b, 4), 28, "commonEncodingsArraySectionOffset");
    assert_eq!(head(b, 8), 2, "commonEncodingsArrayCount");
    assert_eq!(
        head(b, 12),
        36,
        "the personality array rides the common rows"
    );
    assert_eq!(head(b, 16), 0, "no personalities");
    assert_eq!(
        head(b, 20),
        36,
        "the index rides the (empty) personality array"
    );
    assert_eq!(head(b, 24), 2, "one page + the terminator");
    // The common array carries the words in first-use order: the
    // frameless row sorts first (offset 0).
    assert_eq!(head(b, 28), FRAMELESS_ENCODING, "common[0]");
    assert_eq!(head(b, 32), FRAME_ENCODING, "common[1]");
    // The page: kind 3, entries at +12 (the compressed header's five
    // fields), the page-local encodings array riding empty.
    let (page_func, page, page_lsda) = index_entry(b, 0);
    assert_eq!(page_func, 0);
    let page = page as usize;
    assert_eq!(
        page_lsda as usize,
        b.len(),
        "the LSDA array rides the section's end"
    );
    assert_eq!(
        head(b, page),
        UNWIND_SECOND_LEVEL_COMPRESSED,
        "the page kind"
    );
    assert_eq!(
        u16::from_le_bytes([b[page + 4], b[page + 5]]),
        12,
        "entries sit behind the 12-byte compressed page header"
    );
    assert_eq!(u16::from_le_bytes([b[page + 6], b[page + 7]]), 3);
    assert_eq!(
        u16::from_le_bytes([b[page + 8], b[page + 9]]),
        24,
        "the page-local encodings array would ride behind the entries"
    );
    assert_eq!(
        u16::from_le_bytes([b[page + 10], b[page + 11]]),
        0,
        "the page-local tier rides empty — every index resolves at tier one"
    );
    // The entries decode `(encodingIndex << 24) | functionOffset` and
    // the index resolves through the common array.
    let (f0, i0) = compressed_entry(b, page, 0);
    let (f1, i1) = compressed_entry(b, page, 1);
    let (f2, i2) = compressed_entry(b, page, 2);
    assert_eq!(
        (f0, f1, f2),
        (0, 4, 8),
        "the function offsets ride the low 24 bits"
    );
    assert_eq!(
        (i0, i1, i2),
        (0, 1, 1),
        "the encoding indices name the common rows"
    );
    let common0 = head(b, 28);
    let common1 = head(b, 32);
    assert_eq!(
        common0, FRAMELESS_ENCODING,
        "index 0 resolves to the frameless word"
    );
    assert_eq!(
        common1, FRAME_ENCODING,
        "index 1 resolves to the frame word"
    );
}

#[test]
fn the_common_array_dedups_in_first_use_order() {
    let mk = |offset: u32, personality: u32| UnwindEntry {
        personality_offset: personality,
        ..entry(offset, 4, FRAME_ENCODING)
    };
    // Sorted stream: 0 (pers 0x1000), 4 (pers 0x2000), 8 (pers 0x1000).
    let entries = [mk(0, 0x1000), mk(4, 0x2000), mk(8, 0x1000)];
    let info = synthesize(&entries).expect("the table synthesizes");
    assert_eq!(
        info.personality_count, 2,
        "the personalities dedup as in M34"
    );
    assert_eq!(
        info.common_encoding_count, 2,
        "the personality index rides INSIDE the word — two distinct words"
    );
    let b = &info.bytes;
    let w1 = FRAME_ENCODING | (1 << 28);
    let w2 = FRAME_ENCODING | (2 << 28);
    assert_eq!(head(b, 28), w1, "common[0] is the first use's final word");
    assert_eq!(head(b, 32), w2, "common[1] is the second use's final word");
    // The personality array itself rides unchanged (the offsets, not
    // the indices).
    assert_eq!(head(b, 36), 0x1000, "personality[0]");
    assert_eq!(head(b, 40), 0x2000, "personality[1]");
    let (_, page, _) = index_entry(b, 0);
    let page = page as usize;
    let (_, i0) = compressed_entry(b, page, 0);
    let (_, i1) = compressed_entry(b, page, 1);
    let (_, i2) = compressed_entry(b, page, 2);
    assert_eq!(
        (i0, i1, i2),
        (0, 1, 0),
        "the third row reuses the first word's index"
    );
}

// ---- the planner -----------------------------------------------------------------

#[test]
fn the_exact_planner_and_the_builder_agree() {
    let small = vec![
        entry(0, 4, FRAME_ENCODING),
        UnwindEntry {
            personality_offset: 0x300,
            ..entry(4, 4, FRAME_ENCODING)
        },
        UnwindEntry {
            lsda_offset: 0x400,
            ..entry(8, 4, FRAMELESS_ENCODING)
        },
    ];
    let one_page_cap = vec![
        entry(0, 4, FRAME_ENCODING),
        entry(BEYOND_24_BIT, 4, FRAME_ENCODING),
        entry(BEYOND_24_BIT + 4, 4, FRAME_ENCODING),
    ];
    let two_pages: Vec<UnwindEntry> = (0..4097)
        .map(|f| entry((f * 4) as u32, 4, FRAME_ENCODING))
        .collect();
    for entries in [&small, &one_page_cap, &two_pages] {
        let shape = plan_shape(entries).expect("the honest table plans");
        let info = synthesize(entries).expect("the honest table synthesizes");
        assert_eq!(
            synthesized_size_shape(&shape),
            info.bytes.len(),
            "the exact planner and the builder share one formula"
        );
        assert_eq!(shape.entry_count, info.entry_count);
        assert_eq!(shape.page_count, info.page_count);
        assert_eq!(shape.compressed_page_count, info.compressed_page_count);
        assert_eq!(shape.common_encoding_count, info.common_encoding_count);
        assert_eq!(shape.personality_count, info.personality_count);
        assert_eq!(shape.lsda_count, info.lsda_count);
    }
}

// ---- the fallback ------------------------------------------------------------------

#[test]
fn the_beyond_24bit_corpus_plans_the_pre_m35_bytes() {
    // Every offset past the 16 MiB mark: no row qualifies, so every
    // page rides the regular family and the section is the M34 layout
    // verbatim (no common rows, the personality array at 28).
    let entries = vec![
        entry(BEYOND_24_BIT, 4, FRAME_ENCODING),
        entry(BEYOND_24_BIT + 4, 4, FRAME_ENCODING),
        entry(BEYOND_24_BIT + 8, 4, FRAME_ENCODING),
    ];
    let info = synthesize(&entries).expect("the table synthesizes");
    assert_eq!(
        info.compressed_page_count, 0,
        "no row fits the 24-bit field"
    );
    assert_eq!(
        info.common_encoding_count, 0,
        "no compressed row references the array — it stays empty"
    );
    assert_eq!(
        info.bytes.len(),
        synthesized_size(3, 0, 0),
        "the section is the pre-M35 bytes exactly"
    );
    let b = &info.bytes;
    assert_eq!(head(b, 8), 0, "no common rows");
    assert_eq!(
        head(b, 12),
        28,
        "the personality array rides the header (the M34 layout)"
    );
    let (_, page, _) = index_entry(b, 0);
    assert_eq!(
        head(b, page as usize),
        UNWIND_SECOND_LEVEL_REGULAR,
        "the page rides the regular family"
    );
}

#[test]
fn one_unqualifying_row_keeps_only_its_own_page_regular() {
    // 4097 rows: the first 4096 qualify (one compressed page); the
    // last row sits past the 24-bit mark and rides the regular
    // family alone (mixed page kinds).
    let mut entries: Vec<UnwindEntry> = (0..4096)
        .map(|f| entry((f * 4) as u32, 4, FRAME_ENCODING))
        .collect();
    entries.push(entry(BEYOND_24_BIT, 4, FRAME_ENCODING));
    let info = synthesize(&entries).expect("the table synthesizes");
    assert_eq!(info.page_count, 2);
    assert_eq!(
        info.compressed_page_count, 1,
        "only the qualifying rows compress"
    );
    let b = &info.bytes;
    let (_, page0, _) = index_entry(b, 0);
    let (_, page1, _) = index_entry(b, 1);
    assert_eq!(
        head(b, page0 as usize),
        UNWIND_SECOND_LEVEL_COMPRESSED,
        "page 0"
    );
    assert_eq!(
        head(b, page1 as usize),
        UNWIND_SECOND_LEVEL_REGULAR,
        "page 1"
    );

    // The word-cap mirror: the first sorted row's word sits beyond
    // the cap only when 256 distinct words precede it — here the
    // first row carries the frame word and the rest carry 4096
    // distinct DWARF words, so the first 256 rows (the frame word
    // plus words 1–255) compress onto page 0 and the capped rows
    // ride page 1 regular (a page never mixes families, so the
    // family runs follow the sorted stream).
    let mut words = vec![entry(0, 4, FRAME_ENCODING)];
    words.extend((0..4096).map(|f| {
        entry(
            4 + (f * 4) as u32,
            4,
            UNWIND_ARM64_MODE_DWARF | (f as u32 + 1),
        )
    }));
    let shape = plan_shape(&words).expect("the table plans");
    assert_eq!(shape.common_encoding_count, MAX_COMMON_ENCODINGS);
    assert_eq!(shape.compressed_entry_count, MAX_COMMON_ENCODINGS);
    assert_eq!(shape.page_count, 2);
    assert_eq!(shape.compressed_page_count, 1);
    let info = synthesize(&words).expect("the table synthesizes");
    let b = &info.bytes;
    let (_, page0, _) = index_entry(b, 0);
    let (_, page1, _) = index_entry(b, 1);
    assert_eq!(
        head(b, page0 as usize),
        UNWIND_SECOND_LEVEL_COMPRESSED,
        "page 0"
    );
    assert_eq!(
        head(b, page1 as usize),
        UNWIND_SECOND_LEVEL_REGULAR,
        "page 1"
    );
    assert_eq!(
        u16::from_le_bytes([b[page0 as usize + 6], b[page0 as usize + 7]]),
        256,
        "page 0 carries the 256 qualifying rows"
    );
    assert_eq!(
        u16::from_le_bytes([b[page1 as usize + 6], b[page1 as usize + 7]]),
        3841,
        "page 1 carries the capped rows"
    );
}

// ---- the cap -----------------------------------------------------------------------

#[test]
fn the_common_array_caps_at_the_8bit_index_space() {
    // 300 distinct DWARF-mode words (the low bits carry the eh-frame
    // offset): the first 256 join the common array and ride the
    // compressed family; the last 44 have no index and ride the
    // regular family on their own page.
    let entries: Vec<UnwindEntry> = (0..300)
        .map(|f| entry((f * 4) as u32, 4, UNWIND_ARM64_MODE_DWARF | (f as u32)))
        .collect();
    let shape = plan_shape(&entries).expect("the table plans");
    assert_eq!(
        shape.common_encoding_count, MAX_COMMON_ENCODINGS,
        "the array caps at the 8-bit index space"
    );
    assert_eq!(shape.compressed_entry_count, MAX_COMMON_ENCODINGS);
    assert_eq!(shape.page_count, 2, "one page per family");
    assert_eq!(shape.compressed_page_count, 1);
    let info = synthesize(&entries).expect("the table synthesizes");
    assert_eq!(info.common_encoding_count, MAX_COMMON_ENCODINGS);
    assert_eq!(info.compressed_page_count, 1);
    assert_eq!(
        info.bytes.len(),
        synthesized_size_shape(&shape),
        "the capped shape still plans exactly"
    );
    // The capped rows are the FIRST 256 distinct words in first-use
    // order.
    let b = &info.bytes;
    assert_eq!(
        head(b, 28),
        UNWIND_ARM64_MODE_DWARF,
        "common[0] is the first word"
    );
    assert_eq!(
        head(b, 28 + 255 * 4),
        UNWIND_ARM64_MODE_DWARF | 255,
        "common[255] is the 256th distinct word"
    );
}

#[test]
fn a_word_beyond_the_cap_cannot_ride_a_compressed_entry() {
    // The 257th distinct word's row rides the regular family beside
    // the 256 qualifying rows (which compress onto one page).
    let mut entries: Vec<UnwindEntry> = (0..256)
        .map(|f| entry((f * 4) as u32, 4, UNWIND_ARM64_MODE_DWARF | (f as u32)))
        .collect();
    entries.push(entry((256 * 4) as u32, 4, UNWIND_ARM64_MODE_DWARF | 0x1000));
    let shape = plan_shape(&entries).expect("the table plans");
    assert_eq!(shape.common_encoding_count, MAX_COMMON_ENCODINGS);
    assert_eq!(
        shape.compressed_entry_count, 256,
        "the capped word's row does not compress"
    );
    let info = synthesize(&entries).expect("the table synthesizes");
    assert_eq!(info.page_count, 2);
    assert_eq!(info.compressed_page_count, 1);
    // The last row's page rides regular.
    let b = &info.bytes;
    let (_, page1, _) = index_entry(b, 1);
    assert_eq!(head(b, page1 as usize), UNWIND_SECOND_LEVEL_REGULAR);
}

// ---- the section shape ---------------------------------------------------------------

#[test]
fn the_lsda_rows_ride_sorted_under_compression() {
    let mk = |offset: u32, lsda: u32| UnwindEntry {
        lsda_offset: lsda,
        ..entry(offset, 4, FRAME_ENCODING)
    };
    let info = synthesize(&[mk(0, 0x100), mk(4, 0x200)]).expect("the table synthesizes");
    assert_eq!(info.lsda_count, 2);
    let b = &info.bytes;
    let (_, _, lsda_off) = index_entry(b, 0);
    let lsda_off = lsda_off as usize;
    assert_eq!(head(b, lsda_off), 0, "lsda row 0's function offset");
    assert_eq!(head(b, lsda_off + 4), 0x100, "lsda row 0's lsda offset");
    assert_eq!(head(b, lsda_off + 8), 4, "lsda row 1's function offset");
    assert_eq!(head(b, lsda_off + 12), 0x200, "lsda row 1's lsda offset");
    assert_eq!(lsda_off + 16, b.len(), "the lsda array ends the section");
}

#[test]
fn the_section_is_order_normalized() {
    let sorted = [entry(0, 4, FRAME_ENCODING), entry(4, 4, FRAMELESS_ENCODING)];
    let mut shuffled = [entry(4, 4, FRAMELESS_ENCODING), entry(0, 4, FRAME_ENCODING)];
    shuffled.reverse();
    let a = synthesize(&sorted).expect("the sorted table synthesizes");
    let b = synthesize(&shuffled).expect("the shuffled table synthesizes");
    assert_eq!(a, b, "the section bytes are order-normalized");
}

#[test]
fn the_refusals_are_unchanged_by_the_rung() {
    assert!(matches!(plan_shape(&[]), Err(SynthesisError::NoEntries)));
    assert!(matches!(synthesize(&[]), Err(SynthesisError::NoEntries)));
    let zero = [entry(0, 0, FRAME_ENCODING)];
    assert!(matches!(
        plan_shape(&zero),
        Err(SynthesisError::ZeroLengthRange { index: 0 })
    ));
    let unaligned = [entry(2, 4, FRAME_ENCODING)];
    assert!(matches!(
        plan_shape(&unaligned),
        Err(SynthesisError::UnalignedFunctionOffset { offset: 2 })
    ));
    let dup = [entry(0, 4, FRAME_ENCODING), entry(0, 4, FRAME_ENCODING)];
    assert!(matches!(
        plan_shape(&dup),
        Err(SynthesisError::DuplicateFunctionOffset { offset: 0 })
    ));
    let x86_mode = [entry(0, 4, 0x0100_0000)];
    let err = plan_shape(&x86_mode).expect_err("the x86 mode refuses in the planner too");
    assert!(err.to_string().contains("arm64"), "{err}");
}

// ---- the wire-up -----------------------------------------------------------------------

/// One `__text` of `n` RET functions with symbols at every function
/// start (`_main` for the first — only one input may own it).
fn ret_corpus(name: &str, n_fns: usize) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_fns),
        vec![],
    ));
    let stem = name.trim_end_matches(".o");
    for f in 0..n_fns {
        b.add_symbol(ObjectSymbol::Defined {
            name: if f == 0 {
                "_main".into()
            } else {
                format!("_{stem}_fn_{f}")
            },
            section_index: text,
            value: (f * 4) as u64,
            weak: false,
        });
    }
    b
}

#[test]
fn the_linked_image_carries_the_compressed_section() {
    // The wire-up: the carriage rides the same synthesis, so an
    // entry-carrying corpus links into an image whose `__unwind_info`
    // page kind is the compressed family (the mode nibbles still
    // validate — the words only moved into the common array).
    let mut b = ret_corpus("main.o", 3);
    let table: Vec<pgr_format::CompactUnwindEntry> = (0..3)
        .map(|f| pgr_format::CompactUnwindEntry {
            range_start: (f * 4) as u64,
            range_length: 4,
            encoding: if f == 0 {
                FRAMELESS_ENCODING
            } else {
                FRAME_ENCODING
            },
            personality: 0,
            lsda: 0,
        })
        .collect();
    b.add_section(ObjectSection::compact_unwind(&table));
    let inputs = vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }];
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let layout = link(&inputs, &[], &cfg).expect("the corpus links").layout;
    let sect = layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__unwind_info")
        .expect("the entry-carrying corpus synthesizes the section");
    let piece = sect.pieces.first().expect("the section carries one piece");
    let bytes = &piece
        .synth
        .as_ref()
        .expect("the piece carries synthetic bytes")
        .bytes;
    let (_, page, _) = index_entry(bytes, 0);
    assert_eq!(
        head(bytes, page as usize),
        UNWIND_SECOND_LEVEL_COMPRESSED,
        "the linked image's page rides the compressed family"
    );
    assert!(
        head(bytes, 8) > 0,
        "the common array carries the table's words"
    );
    assert!(
        (head(bytes, 28) & UNWIND_ARM64_MODE_MASK) == FRAMELESS_ENCODING & UNWIND_ARM64_MODE_MASK,
        "common[0] names an arm64 mode"
    );
    assert_eq!(
        head(bytes, 28) & UNWIND_PERSONALITY_MASK,
        0,
        "no personality bits ride the corpus's words"
    );
}

//! M34 — the compact-unwind carriage: the `__LD,__compact_unwind`
//! table the Pass-1 sweep kept dropping (the `__LD` segment rides the
//! debug-ish skip that keeps `__DWARF` bytes out of the image), now
//! decoded at parse and synthesized onto the output
//! `__TEXT,__unwind_info` — the section dyld's exception unwinder and
//! every backtrace reader walks. ld64's contract, mirrored: an
//! entry-carrying corpus links into an image whose `__unwind_info`
//! decodes to the translated entries (dead-stripped functions drop
//! with their placements, ICF-folded duplicates land once on the
//! canonical copy), an entry-free corpus plans the pre-M34 bytes (no
//! section, byte-identical), and the refusals name the fix — a table
//! annotating bytes the object does not carry, or a malformed stream,
//! never rides silently.
//!
//! Gate matrix:
//! * the carriage — an entry-carrying corpus links into an image whose
//!   `__TEXT,__unwind_info` decodes to one second-level entry per live
//!   function (since M35 the qualifying rows ride the compressed
//!   family), offset = placed vaddr − `__TEXT` vmaddr;
//! * the drops — a dead-stripped function's entry is gone, an
//!   ICF-folded duplicate's entry lands once on the canonical copy;
//! * the default — an entry-free corpus plans the pre-M34 bytes (no
//!   `__unwind_info` section at all);
//! * the refusals — a table whose range leaves the object's `__text`
//!   refuses at parse with the fix named; a zero-length range refuses;
//!   a payload that is not a multiple of the 32-byte entry refuses
//!   through the format reader (its unit gate);
//! * the synthesis seam — `pgr_core::unwind::synthesize` builds the
//!   section bytes a build system can plan with before any link runs,
//!   and refuses the shapes the carriage never plans;
//! * the cache — the POI cache's parsed-object image carries the
//!   entries (the codec revision bumps, stale entries self-heal).

use pgr_core::cache::{decode_poi, encode_poi};
use pgr_core::ids::FileId;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::object::InputObject;
use pgr_core::unwind::{SynthesisError, UnwindEntry, synthesize};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::CompactUnwindEntry;
use pgr_format::consts::{UNWIND_ARM64_MODE_FRAME, UNWIND_ARM64_MODE_FRAMELESS};

/// One `__text` of `n` RET functions (4 bytes each), symbols at every
/// function start (`_main` for the first when `entry` — only one input
/// may own it).
fn ret_corpus(name: &str, n_fns: usize, entry: bool) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_fns),
        vec![],
    ));
    let stem = name.trim_end_matches(".o");
    for f in 0..n_fns {
        b.add_symbol(ObjectSymbol::Defined {
            name: if f == 0 && entry {
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

/// A canonical arm64 frame encoding (`__frame` mode, the `x19/x20`
/// pair) — the table's opaque `u32` the verifier validates by mode.
const FRAME_ENCODING: u32 = UNWIND_ARM64_MODE_FRAME;
/// A canonical arm64 frameless encoding (stack-size word 0x20 — the
/// 512-byte reserve shape the frameless mode encodes /16).
const FRAMELESS_ENCODING: u32 = UNWIND_ARM64_MODE_FRAMELESS | (0x20 << 12);

/// A table of one entry per function (range start = the function's
/// blob-relative address, the input convention the carriage
/// translates from).
fn unwind_table(n_fns: usize) -> Vec<CompactUnwindEntry> {
    (0..n_fns)
        .map(|f| CompactUnwindEntry {
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
        .collect()
}

/// An `n`-function object carrying a compact-unwind entry per function.
fn obj_with_unwind(name: &str, n_fns: usize, entry: bool) -> Vec<u8> {
    let mut b = ret_corpus(name, n_fns, entry);
    b.add_section(ObjectSection::compact_unwind(&unwind_table(n_fns)));
    b.build().expect("the fixture object builds")
}

/// A single-object corpus (`_main` exported) from raw bytes.
fn corpus(bytes: Vec<u8>) -> Vec<LinkInput> {
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes,
    }]
}

/// Links the corpus (single input) under `tweak`.
fn plan(bytes: Vec<u8>, tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::layout::Layout {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(&corpus(bytes), &[], &cfg)
        .expect("the corpus links")
        .layout
}

/// The linked plan's `__TEXT,__unwind_info` section bytes, when the
/// plan carries the section (the content rides the section's one
/// synthetic piece — the M16 `__init_offsets` shape).
fn unwind_bytes(layout: &pgr_core::layout::Layout) -> Option<&[u8]> {
    let sect = layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__unwind_info")?;
    let piece = sect.pieces.first()?;
    Some(&piece.synth.as_ref()?.bytes)
}

/// The `__text` section's `__TEXT`-relative base (the header region
/// the first section sits behind — the translation floor every entry
/// adds).
fn text_base(layout: &pgr_core::layout::Layout) -> u32 {
    let text_vmaddr = layout
        .segments
        .iter()
        .find(|s| s.name == "__TEXT")
        .expect("the text segment exists")
        .vmaddr;
    let text = layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__text")
        .expect("the text section exists");
    u32::try_from(text.vm_addr - text_vmaddr).expect("the base fits u32")
}

/// The byte offset of second-level entry `i` inside a synthesized
/// `__unwind_info` section (the layout the verifier walks: header,
/// the arrays, the index, the page header, its entries — since M35
/// the qualifying rows ride the compressed family, so the rows are
/// the 4-byte `(encodingIndex << 24) | functionOffset` words).
fn entry_offset(section: &[u8], i: usize) -> usize {
    let index_off =
        u32::from_le_bytes([section[20], section[21], section[22], section[23]]) as usize;
    let page_off = u32::from_le_bytes([
        section[index_off + 4],
        section[index_off + 5],
        section[index_off + 6],
        section[index_off + 7],
    ]) as usize;
    let entry_page = u16::from_le_bytes([section[page_off + 4], section[page_off + 5]]) as usize;
    page_off + entry_page + i * 4
}

/// The second-level entry count of a synthesized section.
fn entry_count(section: &[u8]) -> usize {
    let index_off =
        u32::from_le_bytes([section[20], section[21], section[22], section[23]]) as usize;
    let page_off = u32::from_le_bytes([
        section[index_off + 4],
        section[index_off + 5],
        section[index_off + 6],
        section[index_off + 7],
    ]) as usize;
    u16::from_le_bytes([section[page_off + 6], section[page_off + 7]]) as usize
}

/// The `functionOffset` of second-level entry `i` (the low 24 bits of
/// the compressed word).
fn entry_function_offset(section: &[u8], i: usize) -> u32 {
    let at = entry_offset(section, i);
    u32::from_le_bytes([
        section[at],
        section[at + 1],
        section[at + 2],
        section[at + 3],
    ]) & 0x00FF_FFFF
}

// ---- the carriage ------------------------------------------------------------

#[test]
fn an_entry_carrying_corpus_synthesizes_the_section() {
    let layout = plan(obj_with_unwind("main.o", 3, true), |_| ());
    let bytes = unwind_bytes(&layout).expect("the entry-carrying corpus synthesizes");
    assert_eq!(
        entry_count(bytes),
        3,
        "one entry per live function (the corpus is fully live)"
    );
    let base = text_base(&layout);
    for (i, expected) in [base, base + 4, base + 8].into_iter().enumerate() {
        assert_eq!(
            entry_function_offset(bytes, i),
            expected,
            "entry {i} tracks its function's placement"
        );
    }
}

#[test]
fn the_dead_strip_drops_the_unreferenced_entries() {
    let layout = plan(obj_with_unwind("main.o", 3, true), |c| {
        c.dead_strip = true;
    });
    let bytes = unwind_bytes(&layout).expect("the strip keeps the rooted entries");
    let base = text_base(&layout);
    assert_eq!(
        entry_count(bytes),
        1,
        "only the entry-rooted function survives"
    );
    assert_eq!(entry_function_offset(bytes, 0), base);
}

#[test]
fn the_fold_drops_the_folded_away_entries() {
    // Two identical single-function objects: `-icf=all` folds the
    // second object's `__text` bytes out of the image (the same
    // section-granular fold the M6 gates ride) — an entry annotating
    // bytes the output no longer carries drops, and the canonical copy
    // carries the one surviving row.
    let inputs = vec![
        LinkInput {
            name: "a.o".to_string(),
            bytes: obj_with_unwind("a.o", 1, true),
        },
        LinkInput {
            name: "b.o".to_string(),
            bytes: obj_with_unwind("b.o", 1, false),
        },
    ];
    let cfg = LinkConfig {
        icf: pgr_core::icf::IcfMode::All,
        ..LinkConfig::default()
    };
    let layout = link(&inputs, &[], &cfg).expect("the corpus links").layout;
    let bytes = unwind_bytes(&layout).expect("the folded corpus synthesizes");
    let base = text_base(&layout);
    assert_eq!(
        entry_count(bytes),
        1,
        "the folded twin's entry drops; the canonical copy carries one row"
    );
    assert_eq!(entry_function_offset(bytes, 0), base);
}

// ---- the default --------------------------------------------------------------

#[test]
fn an_entry_free_corpus_plans_the_pre_m34_bytes() {
    let layout = plan(
        ret_corpus("main.o", 3, true).build().expect("builds"),
        |_| (),
    );
    assert!(
        layout.sections.iter().all(|s| s.name != "__unwind_info"),
        "the entry-free corpus carries no __unwind_info section"
    );
}

// ---- the refusals ---------------------------------------------------------------

#[test]
fn a_range_beyond_the_object_text_refuses_at_parse() {
    let mut b = ret_corpus("main.o", 2, true);
    let entries = vec![CompactUnwindEntry {
        range_start: 16, // the two 4-byte functions end at 8
        range_length: 4,
        encoding: FRAME_ENCODING,
        personality: 0,
        lsda: 0,
    }];
    b.add_section(ObjectSection::compact_unwind(&entries));
    let err = link(
        &corpus(b.build().expect("builds")),
        &[],
        &LinkConfig::default(),
    )
    .expect_err("the beyond-__text range refuses");
    let text = err.to_string();
    assert!(
        text.contains("__text"),
        "the refusal names the section the table must annotate: {text}"
    );
    assert!(
        text.contains("__LD,__compact_unwind"),
        "the refusal names the table: {text}"
    );
}

#[test]
fn a_zero_length_range_refuses_at_parse() {
    let mut b = ret_corpus("main.o", 2, true);
    let entries = vec![CompactUnwindEntry {
        range_start: 0,
        range_length: 0,
        encoding: FRAME_ENCODING,
        personality: 0,
        lsda: 0,
    }];
    b.add_section(ObjectSection::compact_unwind(&entries));
    let err = link(
        &corpus(b.build().expect("builds")),
        &[],
        &LinkConfig::default(),
    )
    .expect_err("the zero-length range refuses");
    assert!(
        err.to_string().contains("zero-length"),
        "the refusal names the shape: {err}"
    );
}

#[test]
fn a_personality_beyond_the_object_text_refuses_at_parse() {
    let mut b = ret_corpus("main.o", 2, true);
    let entries = vec![CompactUnwindEntry {
        range_start: 0,
        range_length: 4,
        encoding: FRAME_ENCODING,
        personality: 64, // the object's __text ends at 8
        lsda: 0,
    }];
    b.add_section(ObjectSection::compact_unwind(&entries));
    let err = link(
        &corpus(b.build().expect("builds")),
        &[],
        &LinkConfig::default(),
    )
    .expect_err("the dangling personality refuses");
    assert!(
        err.to_string().contains("personality"),
        "the refusal names the field: {err}"
    );
}

#[test]
fn a_malformed_table_refuses_typed() {
    // 33 bytes: not a multiple of the 32-byte entry — the format
    // reader's refusal, surfaced through the parse.
    let err = pgr_format::read_compact_unwind(&[0u8; 33]).expect_err("the tail refuses");
    assert!(
        err.to_string().contains("multiple of the 32-byte entry"),
        "{err}"
    );
}

// ---- the synthesis seam ---------------------------------------------------------

#[test]
fn the_synthesis_seam_builds_plannable_bytes() {
    let entries: Vec<UnwindEntry> = (0..3)
        .map(|f| UnwindEntry {
            function_offset: f * 0x100,
            range_length: 4,
            encoding: FRAME_ENCODING,
            personality_offset: if f == 0 { 0x300 } else { 0 },
            lsda_offset: if f == 1 { 0x400 } else { 0 },
        })
        .collect();
    let info = synthesize(&entries).expect("the honest entries synthesize");
    assert_eq!(info.entry_count, 3);
    assert_eq!(info.page_count, 1);
    assert_eq!(info.personality_count, 1, "one referenced personality");
    assert_eq!(info.lsda_count, 1, "one referenced lsda");
    assert_eq!(
        info.bytes.len() % 4,
        0,
        "the section keeps the load-command alignment"
    );
    // Unsorted input sorts (the synthesizer canonicalizes, never
    // refuses order — the carriage dedups before it calls).
    let mut shuffled = entries.clone();
    shuffled.reverse();
    let reordered = synthesize(&shuffled).expect("the reordered entries synthesize");
    assert_eq!(
        info.bytes, reordered.bytes,
        "the section is order-normalized"
    );
}

#[test]
fn the_synthesis_refuses_the_shapes_the_carriage_never_plans() {
    let zero = vec![UnwindEntry {
        function_offset: 0,
        range_length: 0,
        encoding: FRAME_ENCODING,
        personality_offset: 0,
        lsda_offset: 0,
    }];
    let err = synthesize(&zero).expect_err("the zero-length range refuses");
    assert!(
        matches!(err, SynthesisError::ZeroLengthRange { index: 0 }),
        "the index is named: {err}"
    );
    let unaligned = vec![UnwindEntry {
        function_offset: 2,
        range_length: 4,
        encoding: FRAME_ENCODING,
        personality_offset: 0,
        lsda_offset: 0,
    }];
    let err = synthesize(&unaligned).expect_err("the unaligned start refuses");
    assert!(
        matches!(err, SynthesisError::UnalignedFunctionOffset { offset: 2 }),
        "the offset is named: {err}"
    );
    assert!(matches!(synthesize(&[]), Err(SynthesisError::NoEntries)));
}

#[test]
fn an_unknown_arm64_encoding_mode_refuses() {
    // Mode nibble 0x01 is an x86-only shape — never an arm64 encoding.
    let bad = vec![UnwindEntry {
        function_offset: 0,
        range_length: 4,
        encoding: 0x0100_0000,
        personality_offset: 0,
        lsda_offset: 0,
    }];
    let err = synthesize(&bad).expect_err("the x86-mode encoding refuses");
    assert!(
        err.to_string().contains("arm64"),
        "the refusal names the architecture: {err}"
    );
}

#[test]
fn a_page_splitting_corpus_plans_two_pages() {
    // 4097 entries: the per-page cap splits the section into two
    // second-level pages (the index grows to three entries).
    let entries: Vec<UnwindEntry> = (0..4097)
        .map(|f| UnwindEntry {
            function_offset: (f * 4) as u32,
            range_length: 4,
            encoding: FRAME_ENCODING,
            personality_offset: 0,
            lsda_offset: 0,
        })
        .collect();
    let info = synthesize(&entries).expect("the big table synthesizes");
    assert_eq!(info.page_count, 2, "the 4096-entry page cap splits");
    assert_eq!(info.entry_count, 4097);
}

// ---- the cache --------------------------------------------------------------------

#[test]
fn the_poi_cache_carries_the_entries() {
    let built = obj_with_unwind("main.o", 3, true);
    let obj = InputObject::parse(FileId(0), "main.o", built).expect("the object parses");
    assert_eq!(obj.compact_unwind.len(), 3, "the parse carries the table");
    let encoded = encode_poi(&obj, true);
    let decoded =
        decode_poi(&encoded, FileId(0), "main.o", true).expect("the cached parse decodes");
    assert_eq!(
        decoded.compact_unwind, obj.compact_unwind,
        "the cached parse carries the same table"
    );
}

// ---- the default output kind keeps its contract -------------------------------------

#[test]
fn the_relocatable_output_never_engages_the_carriage() {
    // `-r` runs the relocatable pipeline (`link_reloc`, the M10 rung-1
    // shape): Passes 1–2 only — the parse carries the table, nothing
    // synthesizes, and the object emit's output surface is the input's
    // verbatim (the __LD table rides or drops exactly as the M10
    // verbatim contract already handles it).
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        ..LinkConfig::default()
    };
    let reloc = pgr_core::link_reloc(
        &corpus(obj_with_unwind("main.o", 2, true)),
        &[],
        &cfg,
        pgr_core::link::Parallelism::Auto,
    )
    .expect("the object output links");
    assert_eq!(reloc.objects.len(), 1);
    assert_eq!(
        reloc.objects[0].compact_unwind.len(),
        2,
        "the parse carries the table (the emit's verbatim surface decides its ride)"
    );
}

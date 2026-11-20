//! M105 — the debug-section suppression (`-S`): ld64's debug-symbol
//! strip names the Pass-1 classification's debug shapes. The `__LLVM*`/
//! `__LD`/`__DWARF` segments the M1 sweep already kept out are debug
//! metadata always; the `__debug_*` section names and the
//! `S_ATTR_DEBUG` attribute widen the class to the shapes the
//! segment-name rule misses — under the named decision. The default
//! (`false`) keeps every pre-M105 link byte-identical: the
//! name/attribute sections bucket as normal load-time bytes, their
//! symtab entries ride. Under `-S` the debug pieces drop (no bucket, no
//! placed bytes), the symtab's entries into them drop with them (a row
//! whose section never ships must not dangle), and the
//! `LC_FUNCTION_STARTS` and `LC_DATA_IN_CODE` commands drop — the
//! M31/M30 suppression pattern composed under one decision. The
//! synthetic `__unwind_info` still synthesizes (the runtime's walk
//! table is not debug metadata), and the relocatable output — whose
//! sections are the input's, verbatim — refuses the decision.
//!
//! Gate matrix:
//! * the default — the `S_ATTR_DEBUG`/`__debug_*` sections in the M1
//!   buckets ride byte-for-byte (the pre-M105 shape), and the `__DWARF`
//!   segment shapes stay swept (the M1 sweep, unchanged);
//! * the strip — `-S` drops the debug-classified sections' bytes and
//!   the symtab's debug entries with them;
//! * the commands — `-S` drops `LC_FUNCTION_STARTS` and
//!   `LC_DATA_IN_CODE` (the M31/M30 suppression pattern; the composed
//!   arithmetic never double-counts — `-S` beside `-no_function_starts`
//!   plans the same bytes as `-S` alone);
//! * the runtime table — `__unwind_info` synthesizes under `-S` (the
//!   M34 carriage is load-time metadata, not debug);
//! * the refusals — the relocatable shape refuses the decision (the
//!   image path's re-check and [`pgr_core::link::link_reloc`] back the
//!   driver refusal, the M102/M39 pattern);
//! * the lock — double-link determinism holds across the decision.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::{S_ATTR_DEBUG, S_REGULAR};
use pgr_format::{DataInCodeEntry, LoadCommandIter, LoadCommandKind, MachHeader64};

/// A corpus: `_main` in `__text`, an `S_ATTR_DEBUG` `__debug_info`
/// section inside `__TEXT` (the shape the segment-name rule misses),
/// a `__DWARF,__debug_info` section (the always-swept shape), a local
/// defined in each, and a name-only local that points nowhere.
fn corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    let debug_sect = b.add_section(ObjectSection {
        name: "__debug_info".into(),
        segment: "__TEXT".into(),
        align_log2: 0,
        flags: S_ATTR_DEBUG,
        data: vec![0xAA; 16],
        relocs: vec![],
    });
    let dwarf = b.add_section(ObjectSection {
        name: "__debug_info".into(),
        segment: "__DWARF".into(),
        align_log2: 0,
        flags: S_REGULAR,
        data: vec![0xBB; 8],
        relocs: vec![],
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::LocalDefined {
        name: "_debug_local".into(),
        section_index: debug_sect,
        value: 0,
    });
    b.add_symbol(ObjectSymbol::LocalDefined {
        name: "_dwarf_local".into(),
        section_index: dwarf,
        value: 0,
    });
    b.add_symbol(ObjectSymbol::Local("debug_abs".into()));
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// A corpus whose inputs carry function-starts-able `__text` and one
/// data-in-code entry per function — the two commands the `-S` face
/// suppresses.
fn dice_corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("dice.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let b = b.set_data_in_code(
        (0..3)
            .map(|f| DataInCodeEntry {
                offset: (f * 4) as u32,
                length: 4,
                kind: 1,
            })
            .collect(),
    );
    vec![LinkInput {
        name: "dice.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

fn plan(inputs: &[LinkInput], tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::layout::Layout {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(inputs, &[], &cfg).expect("the corpus links").layout
}

/// The output symtab row for `name`.
fn row_of(
    layout: &pgr_core::layout::Layout,
    name: &[u8],
) -> Option<pgr_core::layout::OutputSymbol> {
    for (i, s) in layout.symbols.iter().enumerate() {
        let off = usize::try_from(layout.str_offsets[i]).expect("offset");
        let end = layout.strtab[off..]
            .iter()
            .position(|&b| b == 0)
            .expect("NUL");
        if &layout.strtab[off..off + end] == name {
            return Some(s.clone());
        }
    }
    None
}

/// True when the header carries `LC_FUNCTION_STARTS` / `LC_DATA_IN_CODE`.
fn carries_linkedit_data(image: &[u8], kind: u32) -> bool {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::LinkeditData(k) = cmd.kind
            && k == kind
        {
            return true;
        }
    }
    false
}

// ---- the default ----------------------------------------------------------------

#[test]
fn the_default_buckets_the_debug_shapes_as_load_time_bytes() {
    assert!(
        !LinkConfig::default().strip_debug,
        "the pre-M105 shape: the default strips nothing"
    );
    let layout = plan(&corpus(), |_| {});
    let debug_sect = layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__debug_info")
        .expect("the S_ATTR_DEBUG section rides the default link");
    assert_eq!(
        debug_sect.size, 16,
        "the section's bytes ride as load-time bytes"
    );
    let row = row_of(&layout, b"_debug_local").expect("its symtab entry rides");
    assert!(
        row.n_type == pgr_format::consts::N_SECT && !row.external,
        "the entry is a plain local: {:#x}",
        row.n_type
    );
    // The always-swept shape: the `__DWARF` segment never buckets (the
    // M1 sweep, unchanged by the decision) — and its local rides the
    // pre-M105 way: absolute, pointing nowhere.
    assert!(
        !layout.sections.iter().any(|s| s.seg_name == "__DWARF"),
        "the __DWARF segment stays swept by default"
    );
    let dwarf_row = row_of(&layout, b"_dwarf_local").expect("the swept-shape local rides");
    assert_eq!(
        dwarf_row.n_type,
        pgr_format::consts::N_ABS,
        "the pre-M105 shape: a local whose section never ships rides absolute"
    );
}

// ---- the strip ------------------------------------------------------------------

#[test]
fn the_s_face_drops_the_debug_shapes() {
    let kept = plan(&corpus(), |_| {});
    let stripped = plan(&corpus(), |c| c.strip_debug = true);
    assert!(
        !stripped
            .sections
            .iter()
            .any(|s| s.seg_name == "__TEXT" && s.name == "__debug_info"),
        "the S_ATTR_DEBUG section drops"
    );
    assert!(
        !stripped.sections.iter().any(|s| s.seg_name == "__DWARF"),
        "the __DWARF segment stays swept under -S"
    );
    assert!(
        row_of(&stripped, b"_debug_local").is_none(),
        "the symtab's debug entry drops with its section"
    );
    assert!(
        row_of(&stripped, b"_dwarf_local").is_none(),
        "the entry into the swept shape drops under -S"
    );
    assert!(
        row_of(&stripped, b"debug_abs").is_some(),
        "the name-only local points at no debug section: it rides"
    );
    assert!(
        row_of(&stripped, b"_main").is_some(),
        "the extdefs survive the strip"
    );
    assert!(
        stripped.file_size < kept.file_size,
        "the debug pieces leave the file ({} < {})",
        stripped.file_size,
        kept.file_size
    );
}

// ---- the commands ---------------------------------------------------------------

#[test]
fn the_s_face_suppresses_the_linkedit_data_commands() {
    let kept = plan(&dice_corpus(), |_| {});
    let stripped = plan(&dice_corpus(), |c| c.strip_debug = true);
    assert!(
        stripped.func_starts.is_empty(),
        "the stream drops with the command (the M31 suppression pattern: no slot, \
         no ULEB stream)"
    );
    assert!(
        carries_linkedit_data(&kept.header_bytes, pgr_format::consts::LC_FUNCTION_STARTS),
        "the corpus plans LC_FUNCTION_STARTS by default (the precondition)"
    );
    assert!(
        !carries_linkedit_data(
            &stripped.header_bytes,
            pgr_format::consts::LC_FUNCTION_STARTS
        ),
        "-S drops LC_FUNCTION_STARTS"
    );
    assert!(
        carries_linkedit_data(&kept.header_bytes, pgr_format::consts::LC_DATA_IN_CODE),
        "the corpus plans LC_DATA_IN_CODE by default (the precondition)"
    );
    assert!(
        !carries_linkedit_data(&stripped.header_bytes, pgr_format::consts::LC_DATA_IN_CODE),
        "-S drops LC_DATA_IN_CODE"
    );
    assert!(
        stripped.data_in_code.is_empty(),
        "the data-in-code stream drops with the command"
    );
    // The commands' slots: two 16-byte commands leave the header.
    assert_eq!(
        kept.header_bytes.len() - stripped.header_bytes.len(),
        32,
        "both commands leave the load-command area"
    );
}

#[test]
fn the_s_face_composes_with_the_explicit_suppressions() {
    // `-S` beside `-no_function_starts`: the composed arithmetic never
    // double-counts — the same suppression the M31 decision already
    // names plans the same bytes.
    let stripped = plan(&dice_corpus(), |c| c.strip_debug = true);
    let composed = plan(&dice_corpus(), |c| {
        c.strip_debug = true;
        c.function_starts = false;
    });
    assert_eq!(
        stripped.header_bytes, composed.header_bytes,
        "-S plans the -no_function_starts shape for the command it suppresses"
    );
    assert_eq!(
        stripped.file_size, composed.file_size,
        "the same file shape"
    );
}

// ---- the runtime table ----------------------------------------------------------

#[test]
fn the_unwind_info_still_synthesizes_under_s() {
    // M34's `__unwind_info` is the runtime's walk table — load-time
    // metadata, not debug: `-S` drops the debug pieces around it,
    // never the synthesis.
    let mut b = ObjectBuilder::new("unwind.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let rows = [pgr_format::CompactUnwindEntry {
        range_start: 0,
        range_length: 4,
        encoding: pgr_format::consts::UNWIND_ARM64_MODE_FRAMELESS | (0x20 << 12),
        personality: 0,
        lsda: 0,
    }];
    let cu = b.add_section(ObjectSection::compact_unwind(&rows));
    let _ = cu;
    let inputs = vec![LinkInput {
        name: "unwind.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }];
    let stripped = plan(&inputs, |c| c.strip_debug = true);
    assert!(
        stripped
            .sections
            .iter()
            .any(|s| s.seg_name == "__TEXT" && s.name == "__unwind_info"),
        "the runtime table synthesizes under -S: {:?}",
        stripped
            .sections
            .iter()
            .map(|s| (s.seg_name.as_str(), s.name.as_str()))
            .collect::<Vec<_>>()
    );
}

// ---- the refusals ---------------------------------------------------------------

#[test]
fn the_relocatable_shape_refuses_the_s_face() {
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        strip_debug: true,
        ..LinkConfig::default()
    };
    let err = link(&corpus(), &[], &cfg).expect_err("the relocatable shape refuses -S");
    let message = err.to_string();
    assert!(
        message.contains("-S"),
        "the refusal names the flag: {message}"
    );
    assert!(
        message.contains("verbatim"),
        "the refusal names the contract (the object's sections are the input's): \
         {message}"
    );
}

#[test]
fn the_relocatable_path_refuses_the_s_face() {
    let cfg = LinkConfig {
        strip_debug: true,
        ..LinkConfig::default()
    };
    let err =
        link_reloc(&corpus(), &[], &cfg, Parallelism::Auto).expect_err("the -r path refuses -S");
    assert!(
        err.to_string().contains("-S"),
        "the relocatable re-check names the flag: {err}",
    );
}

// ---- the lock -------------------------------------------------------------------

#[test]
fn double_link_is_byte_identical_across_the_decision() {
    let a = plan(&corpus(), |c| c.strip_debug = true);
    let b = plan(&corpus(), |c| c.strip_debug = true);
    assert_eq!(
        a.header_bytes, b.header_bytes,
        "the strip face is deterministic"
    );
    assert_eq!(a.file_size, b.file_size, "the strip face plans one shape");
}

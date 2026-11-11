//! M17 — the segment-protection seam (`pgr_core::segprot`): the
//! per-segment `maxprot`/`initprot` pair stops being the layout's
//! hard-coded table (`__TEXT` RX/RX, `__DATA_CONST`/`__DATA` RW/RW,
//! `__LINKEDIT` R/R) and becomes a validated
//! [`pgr_core::segprot::SegProts`] decision carried on
//! [`pgr_core::layout::LinkConfig`] — the seam the segment packing and
//! the `LC_SEGMENT_64` emit read.
//!
//! Gate matrix:
//! * the seam — the `rwx` grammar parses to `VM_PROT_*` bits, every
//!   value contract refuses with the fix (unknown bits, init beyond
//!   max, a writable+executable initial mapping), and the segment
//!   names are the layout's planned set (`__TEXT`, `__DATA_CONST`,
//!   `__DATA`, `__LINKEDIT` — `__PAGEZERO` carries no protections by
//!   contract);
//! * the decision — one decision per segment, read back by
//!   [`SegProts::prot_for`], the house table falling out of `None`;
//! * layout — a named decision lands in the planned segment's
//!   `maxprot`/`initprot` fields (the `LC_SEGMENT_64` emit copies them)
//!   and leaves every other byte of the plan untouched — the seam names
//!   eight bits the layout already wrote, it does not re-shape it;
//! * the lock — the default config plans byte-for-byte what the
//!   explicit-default config plans (the seam adds nothing on a clean
//!   link), and a non-executable kind takes the knob the same way
//!   (dylibs and bundles carry segments; only `-r` does not).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::segprot::{SegName, SegProt, SegProtError, SegProts};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};

/// One-object corpus with a bind-free surface: `_main` plus a `__data`
/// pointer pair into `__text` (the rebase slots give the link honest
/// fixup work, so the plan is the plan the protections land on).
fn corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let helper_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_helper".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.section_mut(data).relocs = vec![
        ObjectReloc::unsigned(main_sym as u32).at(0),
        ObjectReloc::unsigned(helper_sym as u32).at(8),
    ];
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// Links the corpus with a config tweak and returns the layout.
fn link_layout(tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::Layout {
    let mut cfg = LinkConfig {
        entry_symbol: "_main".into(),
        ..LinkConfig::default()
    };
    tweak(&mut cfg);
    link(&corpus(), &[], &cfg).expect("the corpus links").layout
}

/// The planned segment's `(maxprot, initprot)` pair.
fn prots(layout: &pgr_core::Layout, seg: &str) -> (u32, u32) {
    let s = layout
        .segments
        .iter()
        .find(|s| s.name == seg)
        .unwrap_or_else(|| panic!("{seg} is planned"));
    (s.maxprot, s.initprot)
}

/// Field-wise plan equality (`SegmentPlan` is a Debug/Clone record, not
/// a value type — the comparisons below name the field they compare).
fn same_shape(a: &pgr_core::Layout, b: &pgr_core::Layout) {
    assert_eq!(a.segments.len(), b.segments.len(), "same segments");
    for (x, y) in a.segments.iter().zip(&b.segments) {
        assert_eq!(x.name, y.name);
        assert_eq!(x.vmaddr, y.vmaddr, "{}: same vmaddr", x.name);
        assert_eq!(x.vmsize, y.vmsize, "{}: same vmsize", x.name);
        assert_eq!(x.fileoff, y.fileoff, "{}: same fileoff", x.name);
        assert_eq!(x.filesize, y.filesize, "{}: same filesize", x.name);
        assert_eq!(x.sections, y.sections, "{}: same sections", x.name);
    }
    assert_eq!(a.entryoff, b.entryoff, "same entry");
    assert_eq!(a.file_size, b.file_size, "same file size");
}

// ---- the seam ----------------------------------------------------------------

#[test]
fn the_grammar_parses_the_rwx_subsets() {
    for (max, init, want) in [
        ("r", "r", (VM_PROT_READ, VM_PROT_READ)),
        ("rw", "r", (VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ)),
        (
            "rx",
            "rx",
            (
                VM_PROT_READ | VM_PROT_EXECUTE,
                VM_PROT_READ | VM_PROT_EXECUTE,
            ),
        ),
        (
            "rwx",
            "rx",
            (
                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
                VM_PROT_READ | VM_PROT_EXECUTE,
            ),
        ),
    ] {
        let p = SegProt::parse(max, init).expect("the protections parse");
        assert_eq!((p.maxprot(), p.initprot()), want, "{max}/{init}");
    }
}

#[test]
fn grammar_refusals_name_the_fix() {
    for (max, init) in [("", ""), ("q", "r"), ("rr", "r"), ("rwz", "r")] {
        let err = SegProt::parse(max, init).expect_err("the grammar refuses");
        assert!(
            err.to_string().contains("rwx"),
            "the refusal names the grammar: {err}"
        );
    }
    // Bits outside the family refuse on the wire-shaped constructor too.
    let err = SegProt::from_bits(0x8, VM_PROT_READ).expect_err("unknown bits refuse");
    assert!(err.to_string().contains("VM_PROT"), "{err}");
}

#[test]
fn init_must_fit_the_max() {
    let err = SegProt::from_bits(VM_PROT_READ, VM_PROT_READ | VM_PROT_WRITE)
        .expect_err("init beyond max refuses");
    assert!(
        err.to_string().contains("maxprot"),
        "the refusal names the kernel rule: {err}"
    );
}

#[test]
fn a_writable_executable_mapping_refuses() {
    let err = SegProt::from_bits(
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
    )
    .expect_err("a W+X initial mapping refuses");
    assert!(
        err.to_string().to_lowercase().contains("writable"),
        "the refusal names the W^X contract: {err}"
    );
    // A W+X *ceiling* (maxprot) stays legal — maxprot is what mprotect
    // may raise to, not what the kernel maps.
    SegProt::from_bits(
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        VM_PROT_READ | VM_PROT_EXECUTE,
    )
    .expect("a W+X max with an RX init is the ceiling shape");
}

#[test]
fn the_segment_names_are_the_planned_set() {
    for name in ["__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT"] {
        SegName::parse(name).expect("the planned segment parses");
    }
    for name in ["__PAGEZERO", "__FOO", "", "__text"] {
        let err = SegName::parse(name).expect_err("an unplanned segment refuses");
        assert!(
            err.to_string().contains("__LINKEDIT"),
            "the refusal names the planned set: {err}"
        );
    }
}

#[test]
fn one_decision_per_segment_reads_back() {
    let mut prots = SegProts::default();
    assert!(prots.is_empty(), "the default names nothing");
    prots
        .insert(
            SegName::DataConst,
            SegProt::parse("rw", "r").expect("the decision validates"),
        )
        .expect("the first insert is free");
    assert_eq!(prots.len(), 1);
    assert_eq!(
        prots.prot_for("__DATA_CONST"),
        Some(SegProt::parse("rw", "r").expect("revalidates"))
    );
    assert_eq!(
        prots.prot_for("__DATA"),
        None,
        "unnamed segments stay house"
    );
    let err = prots
        .insert(
            SegName::DataConst,
            SegProt::parse("rw", "rw").expect("the duplicate value validates"),
        )
        .expect_err("a second decision for one segment refuses");
    assert!(
        err.to_string().contains("twice"),
        "the refusal names the shape: {err}"
    );
}

// ---- layout ------------------------------------------------------------------

#[test]
fn the_house_table_falls_out_of_none() {
    let layout = link_layout(|_| {});
    assert_eq!(
        prots(&layout, "__TEXT"),
        (
            VM_PROT_READ | VM_PROT_EXECUTE,
            VM_PROT_READ | VM_PROT_EXECUTE
        ),
        "the house __TEXT pair"
    );
    assert_eq!(
        prots(&layout, "__DATA_CONST"),
        (VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE),
        "the house __DATA_CONST pair"
    );
    assert_eq!(
        prots(&layout, "__DATA"),
        (VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE),
        "the house __DATA pair"
    );
    assert_eq!(
        prots(&layout, "__LINKEDIT"),
        (VM_PROT_READ, VM_PROT_READ),
        "the house __LINKEDIT pair"
    );
}

#[test]
fn a_named_decision_lands_in_the_plan() {
    let layout = link_layout(|cfg| {
        cfg.seg_prots
            .insert(
                SegName::DataConst,
                SegProt::parse("rw", "r").expect("the decision validates"),
            )
            .expect("one decision per segment");
    });
    assert_eq!(
        prots(&layout, "__DATA_CONST"),
        (VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ),
        "the named pair rides the planned segment"
    );
    // The seam names protections, not shape: every other byte of the
    // plan is the house plan.
    same_shape(&link_layout(|_| {}), &layout);
}

#[test]
fn the_explicit_house_value_is_byte_identical_to_the_default() {
    // Naming the house pair for a segment plans exactly what the
    // default plans — the seam adds nothing on the clean path (the
    // protections equal the house table's, the shape is untouched).
    let default = link_layout(|_| {});
    let explicit = link_layout(|cfg| {
        cfg.seg_prots
            .insert(
                SegName::Data,
                SegProt::parse("rw", "rw").expect("the house pair validates"),
            )
            .expect("one decision per segment");
    });
    same_shape(&default, &explicit);
    assert_eq!(
        prots(&explicit, "__DATA"),
        prots(&default, "__DATA"),
        "the explicit house decision is the default pair"
    );
}

#[test]
fn non_executable_kinds_take_the_knob() {
    // Dylibs and bundles carry segments; only `-r` does not (the driver
    // surface refuses that one).
    for kind in [OutputType::Dylib, OutputType::Bundle] {
        let mut cfg = LinkConfig {
            filetype: kind,
            install_name: Some("@rpath/libgreet.dylib".into()),
            ..LinkConfig::default()
        };
        cfg.seg_prots
            .insert(
                SegName::Data,
                SegProt::parse("rw", "r").expect("the decision validates"),
            )
            .expect("one decision per segment");
        let result = link(&corpus(), &[], &cfg).expect("the dylib links");
        let s = result
            .layout
            .segments
            .iter()
            .find(|s| s.name == "__DATA")
            .expect("__DATA is planned");
        assert_eq!(
            (s.maxprot, s.initprot),
            (VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ),
            "{kind:?} plans the named pair"
        );
    }
}

#[test]
fn determinism_a_double_link_is_byte_identical() {
    let tweak = |cfg: &mut LinkConfig| {
        cfg.seg_prots
            .insert(
                SegName::DataConst,
                SegProt::parse("rw", "r").expect("the decision validates"),
            )
            .expect("one decision per segment");
    };
    let a = link_layout(tweak);
    let b = link_layout(tweak);
    same_shape(&a, &b);
    assert_eq!(a.segments[1].maxprot, b.segments[1].maxprot);
}

// ---- the error is a typed surface --------------------------------------------

#[test]
fn the_error_names_are_a_typed_surface() {
    // The wire maps every variant to a malformed frame; the driver
    // renders them as miette help text. The surface is exhaustive.
    let errors: [SegProtError; 6] = [
        SegProtError::Grammar { raw: "q".into() },
        SegProtError::UnknownBits { raw: 0x8 },
        SegProtError::UnknownSegment {
            name: "__FOO".into(),
        },
        SegProtError::InitBeyondMax {
            initprot: 3,
            maxprot: 1,
        },
        SegProtError::WritableExecutable { initprot: 6 },
        SegProtError::Duplicate {
            seg: "__TEXT".into(),
        },
    ];
    for err in &errors {
        assert!(!err.to_string().is_empty(), "{err:?} renders");
    }
}

//! M9 core foundations (architecture doc §10.4 row M9, §7.3 "layout
//! stability"): the cross-link **slack anchors** the in-place patch tier
//! stands on. M8-c shipped the per-link padding policy; M9 anchors the
//! *previously reserved* sizes across links so a changed section keeps its
//! on-disk place while its content fits — nothing downstream moves, which
//! is exactly the precondition the incremental patch planner requires
//! before it may reuse recorded page hashes.
//!
//! Gates here:
//!
//! * anchored relink of *grown* content keeps every section's padded size
//!   (the unanchored M8-c relink of the same content would re-pad it);
//! * content beyond the anchor overflows: the natural pad applies and the
//!   size grows (the ladder's observed signal);
//! * anchors are pure layout inputs — same anchors, byte-shaped layout
//!   again (§4.3 determinism);
//! * no anchors reproduces the M8-c behavior exactly.

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism, link_cached};
use pgr_core::slack::{SlackAnchor, SlackPolicy};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// hello.o with a `__text` body of `text_bytes` (the canonical ADRP+ADD /
/// BL / mov / ret prologue, zero-padded to size): `_main` ADRP+ADD loads
/// `_msg`, BL `_greet`, ret. The symbol set is invariant under `text_bytes`
/// — that is the point: content may grow without moving the symtab.
fn hello_sized(text_bytes: usize) -> ObjectBuilder {
    let mut words: Vec<u32> = vec![
        0x9000_0000, // adrp x0, _msg@page
        0x9100_0000, // add x0, x0, #_msg@pageoff
        0x9400_0000, // bl _greet
        0x5280_0000, // mov w0, #0
        0xD65F_03C0, // ret
    ];
    // Pad with `nop`s so reloc offsets stay valid and the body grows.
    words.resize(text_bytes / 4, 0xD503_201F);
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut b = ObjectBuilder::new("hello.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        text,
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12(1).at(4),
            ObjectReloc::branch26(2).at(8),
        ],
    ));
    b.add_section(ObjectSection::cstring("hello, peregrine\n"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_msg".into(),
        section_index: 1,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b
}

/// greet.o (invariant across the edit): `_greet` body + a `__data` pointer.
fn greet() -> ObjectBuilder {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.section_mut(data).relocs = vec![ObjectReloc::unsigned(0).at(0)];
    b
}

fn inputs(text_bytes: usize) -> Vec<LinkInput> {
    vec![
        LinkInput {
            name: "hello.o".into(),
            bytes: hello_sized(text_bytes).build().unwrap(),
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet().build().unwrap(),
        },
    ]
}

fn slack_cfg(anchor: &[SlackAnchor]) -> LinkConfig {
    LinkConfig {
        ident: "m9-anchor".into(),
        layout_slack: Some(SlackPolicy::default()),
        slack_anchor: anchor.to_vec(),
        ..LinkConfig::default()
    }
}

/// Anchors from a layout: every padded user section's `(seg, name, size)`.
fn anchors_of(layout: &pgr_core::layout::Layout) -> Vec<SlackAnchor> {
    layout
        .sections
        .iter()
        .filter(|s| SlackPolicy::is_padded_section(&s.seg_name, &s.name) && s.size > 0)
        .map(|s| SlackAnchor {
            seg: s.seg_name.clone(),
            name: s.name.clone(),
            padded: s.size,
        })
        .collect()
}

#[test]
fn anchored_relink_of_grown_content_keeps_every_section_size() {
    let small = inputs(64);
    let grown = inputs(2048);

    // Link 1 (unanchored slack): the reservation the record would capture.
    let first = link_cached(&small, &[], &slack_cfg(&[]), Parallelism::Serial, None).unwrap();
    let anchors = anchors_of(&first.layout);
    assert!(!anchors.is_empty(), "the fixture carries padded sections");

    // Link 2 (M8-c, unanchored): grown content re-pads — sizes drift.
    let unanchored =
        link_cached(&grown, &[], &slack_cfg(&[]), Parallelism::Serial, None).unwrap();

    // Link 2 (M9, anchored): grown content still fits the reservation —
    // every section keeps the link-1 size.
    let anchored = link_cached(&grown, &[], &slack_cfg(&anchors), Parallelism::Serial, None)
        .unwrap();
    for a in &anchors {
        let sect = anchored
            .layout
            .sections
            .iter()
            .find(|s| s.seg_name == a.seg && s.name == a.name)
            .unwrap_or_else(|| panic!("section {}:{} vanished", a.seg, a.name));
        assert_eq!(
            sect.size, a.padded,
            "{}:{} moved despite the anchor",
            a.seg, a.name
        );
    }

    // And the drift the anchor prevented is real (otherwise this gate is
    // vacuous): the unanchored relink differs somewhere.
    let drifted = anchors.iter().any(|a| {
        unanchored
            .layout
            .sections
            .iter()
            .find(|s| s.seg_name == a.seg && s.name == a.name)
            .is_none_or(|s| s.size != a.padded)
    });
    assert!(drifted, "the unanchored relink should re-pad some section");
}

#[test]
fn content_beyond_the_anchor_overflows_to_the_natural_pad() {
    let small = inputs(64);
    let huge = inputs(64 * 1024); // 64 KiB text: far past the min-pad anchor

    let first = link_cached(&small, &[], &slack_cfg(&[]), Parallelism::Serial, None).unwrap();
    let anchors = anchors_of(&first.layout);
    let text_anchor = anchors
        .iter()
        .find(|a| a.seg == "__TEXT" && a.name == "__text")
        .expect("fixture has a padded __text");

    let overflow =
        link_cached(&huge, &[], &slack_cfg(&anchors), Parallelism::Serial, None).unwrap();
    let text = overflow
        .layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__text")
        .unwrap();
    assert!(
        text.size > text_anchor.padded,
        "content past the anchor must grow the section ({} > {})",
        text.size,
        text_anchor.padded
    );
    // The natural pad reproduces the unanchored size for the same content.
    let natural = link_cached(&huge, &[], &slack_cfg(&[]), Parallelism::Serial, None).unwrap();
    let natural_text = natural
        .layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__text")
        .unwrap();
    assert_eq!(text.size, natural_text.size);
}

#[test]
fn anchors_are_pure_deterministic_layout_inputs() {
    let grown = inputs(2048);
    let small = inputs(64);
    let first = link_cached(&small, &[], &slack_cfg(&[]), Parallelism::Serial, None).unwrap();
    let anchors = anchors_of(&first.layout);

    let a = link_cached(&grown, &[], &slack_cfg(&anchors), Parallelism::Serial, None).unwrap();
    let b = link_cached(&grown, &[], &slack_cfg(&anchors), Parallelism::Auto, None).unwrap();
    assert_eq!(
        format!("{:?}", a.layout),
        format!("{:?}", b.layout),
        "same anchors must produce the same layout regardless of schedule"
    );

    // Anchoring twice is a fixpoint: re-deriving anchors from the anchored
    // link and relinking changes nothing (the stability property the
    // incremental loop relies on).
    let anchors2 = anchors_of(&a.layout);
    let c = link_cached(&grown, &[], &slack_cfg(&anchors2), Parallelism::Serial, None).unwrap();
    assert_eq!(format!("{:?}", a.layout), format!("{:?}", c.layout));
}

#[test]
fn empty_anchors_reproduce_the_m8c_pad_exactly() {
    let grown = inputs(2048);
    let no_anchor_field = LinkConfig {
        ident: "m9-anchor".into(),
        layout_slack: Some(SlackPolicy::default()),
        ..LinkConfig::default()
    };
    let m8c = link_cached(&grown, &[], &no_anchor_field, Parallelism::Serial, None).unwrap();
    let m9 = link_cached(&grown, &[], &slack_cfg(&[]), Parallelism::Serial, None).unwrap();
    assert_eq!(
        format!("{:?}", m8c.layout),
        format!("{:?}", m9.layout),
        "an empty anchor list must be the M8-c behavior"
    );
}

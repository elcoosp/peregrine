//! M112 — the link-statistics report (`-print_statistics`): ld64's
//! link-statistics report, rendered to stderr at the end of the link. The
//! counts ride the M54 observation seam and the link's own product — the
//! objects Pass 1 parsed and the names the interner batched (the phase
//! events' own details), the fixups Pass 3 planned and the bytes the emit
//! produced (the layout and image), and the wall time the run took. The
//! report is a measurement, not a layout product: an observed run plans
//! the identical layout (the parity gate is the seam's own contract), and
//! the relocatable output refuses the knob (the object path has no
//! full-emit layout or fixup planning to report in the same way).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_observed, link_reloc};
use pgr_core::statistics::{LinkStatistics, StatsCollector};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::time::Duration;

/// Two objects: `_main` in the first references `_greet`, which the
/// second defines — the corpus the stats counts name (2 objects, the
/// interner batch, the fixups, the image bytes).
fn corpus() -> Vec<LinkInput> {
    let mut main = ObjectBuilder::new("main.o");
    let text = main.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    main.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = main.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let undef = main.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    let slot = main.sym_index(undef);
    main.section_mut(data)
        .relocs
        .push(pgr_fixtures::ObjectReloc::unsigned(slot).at(0));
    let mut greet = ObjectBuilder::new("greet.o");
    let gtext = greet.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    greet.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: gtext,
        value: 0,
        weak: false,
    });
    vec![
        LinkInput {
            name: "main.o".into(),
            bytes: main.build().expect("the fixture object builds"),
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet.build().expect("the fixture object builds"),
        },
    ]
}

fn cfg() -> LinkConfig {
    LinkConfig {
        ..LinkConfig::default()
    }
}

#[test]
fn the_collector_rides_the_seam_and_finishes_the_report() {
    let inputs = corpus();
    let mut stats = StatsCollector::default();
    let result = link_observed(&inputs, &[], &cfg(), Parallelism::Auto, None, &mut stats)
        .expect("the corpus links");
    let report = stats.finish(
        result.layout.fixups.slot_count,
        4096,
        Duration::from_millis(3),
    );
    assert_eq!(report.objects, 2, "the parse phase's own count");
    assert!(
        report.interned >= 3,
        "the interner batch's own count (the externals plus the header symbol): {}",
        report.interned
    );
    assert!(
        report.fixup_slots >= 1,
        "the bind slot the corpus plans: {}",
        report.fixup_slots
    );
    assert_eq!(report.bytes, 4096, "the emit's own product");
    assert_eq!(report.wall, Duration::from_millis(3));
}

#[test]
fn the_render_is_deterministic_and_names_the_counts() {
    let report = LinkStatistics {
        objects: 2,
        interned: 7,
        fixup_slots: 3,
        bytes: 4096,
        wall: Duration::from_millis(3),
    };
    let a = report.render();
    let b = report.render();
    assert_eq!(a, b, "the render is a pure function of the report");
    for needle in [
        "objects parsed 2",
        "symbols interned 7",
        "fixups planned 3",
        "bytes emitted 4096",
    ] {
        assert!(
            a.contains(needle),
            "the render names the count: {needle} in\n{a}"
        );
    }
    assert!(a.contains("wall"), "the wall row rides: {a}");
}

#[test]
fn the_observed_stats_link_plans_the_identical_layout() {
    // The parity gate (the seam's own contract): a link observed by the
    // stats collector plans the identical layout to the unobserved one —
    // the report never re-plans a byte.
    let inputs = corpus();
    let plain = link(&inputs, &[], &cfg()).expect("the plain link plans");
    let mut stats = StatsCollector::default();
    let observed = link_observed(&inputs, &[], &cfg(), Parallelism::Auto, None, &mut stats)
        .expect("the observed link plans");
    assert_eq!(
        format!("{:?}", plain.layout),
        format!("{:?}", observed.layout),
        "the observation never moves a byte of the plan"
    );
}

#[test]
fn the_relocatable_output_refuses_the_report() {
    let inputs = corpus();
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        print_statistics: true,
        ..LinkConfig::default()
    };
    let err = link_reloc(&inputs, &[], &cfg, Parallelism::Auto)
        .expect_err("the object shape refuses the report");
    let msg = err.to_string();
    assert!(
        msg.contains("-print_statistics"),
        "the refusal names the knob: {msg}"
    );
}

#[test]
fn the_default_reports_nothing_and_moves_nothing() {
    // The default keeps every pre-knob link byte-identical: the field is
    // false, the collector never subscribes, the layout is the
    // pre-M112 layout (the parity gate's default face).
    let inputs = corpus();
    let cfg = cfg();
    assert!(
        !cfg.print_statistics,
        "the default reports nothing (every pre-knob link byte-identical)"
    );
    let result = link(&inputs, &[], &cfg).expect("the default links");
    assert!(
        result.layout.segments.len() >= 2,
        "the segmented plan rides"
    );
}

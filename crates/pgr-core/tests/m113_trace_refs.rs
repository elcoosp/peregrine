//! M113 — the reference trace (`-t`): ld64's symbol-reference tracing.
//! Each symbol Pass 2's resolve visits rides the M54 observation seam as
//! a new `LinkObserver::on_reference` event — the name as the resolver
//! saw it and the input that carries the reference — and the driver
//! prints each to stderr. The seam stays read-only (an observed link
//! plans the identical layout, the parity gate is the seam's own
//! contract), the event fires on both resolve paths (the full install
//! and the resolve-reuse replay — the trace is the run's own Pass-2
//! record, the M107/M108 config pattern), and the relocatable output
//! refuses the knob (the object's symtab is the input's, verbatim).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_observed, link_reloc};
use pgr_core::observe::{LinkObserver, ReferenceEvent, RefsCollector};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// main.o: `_main` references `_greet`; greet.o defines `_greet` — the
/// corpus the trace names (one reference, the input that carries it).
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
        .push(ObjectReloc::unsigned(slot).at(0));
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

#[test]
fn the_reference_walk_reports_every_visit() {
    let mut refs = RefsCollector::default();
    let result = link_observed(
        &corpus(),
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut refs,
    )
    .expect("the corpus links");
    let events = refs.finish();
    assert_eq!(
        events.len(),
        1,
        "the corpus carries exactly one reference: {events:?}"
    );
    assert_eq!(
        events[0],
        ReferenceEvent {
            name: "_greet".into(),
            from: "main.o".into(),
        },
        "the event names the symbol and the input that carries it"
    );
    assert!(
        result.layout.segments.len() >= 2,
        "the observed link plans the segmented layout"
    );
    assert_eq!(
        events[0].render(),
        "_greet (from main.o)",
        "the render is the face both lanes print"
    );
}

#[test]
fn the_observed_refs_link_plans_the_identical_layout() {
    // The parity gate (the seam's own contract): a link observed by the
    // refs collector plans the identical layout to the unobserved one —
    // the trace never re-plans a byte.
    let inputs = corpus();
    let plain = link(&inputs, &[], &LinkConfig::default()).expect("the plain link plans");
    let mut refs = RefsCollector::default();
    let observed = link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut refs,
    )
    .expect("the observed link plans");
    assert_eq!(
        format!("{:?}", plain.layout),
        format!("{:?}", observed.layout),
        "the observation never moves a byte of the plan"
    );
}

#[test]
fn every_visit_of_a_multi_site_name_rides_the_walk_order() {
    // Two objects carry the same undefined external — each visit is one
    // event, in the walk's own order (file order, then symbol order):
    // the trace is the walk's record, not a deduped set.
    let mut a = ObjectBuilder::new("a.o");
    let ta = a.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    a.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: ta,
        value: 0,
        weak: false,
    });
    let da = a.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let ua = a.add_symbol(ObjectSymbol::Undefined {
        name: "_shared".into(),
        weak_ref: false,
    });
    let sa = a.sym_index(ua);
    a.section_mut(da)
        .relocs
        .push(ObjectReloc::unsigned(sa).at(0));
    let mut b = ObjectBuilder::new("b.o");
    let tb = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_other".into(),
        section_index: tb,
        value: 0,
        weak: false,
    });
    let db = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let ub = b.add_symbol(ObjectSymbol::Undefined {
        name: "_shared".into(),
        weak_ref: false,
    });
    let sb = b.sym_index(ub);
    b.section_mut(db)
        .relocs
        .push(ObjectReloc::unsigned(sb).at(0));
    let inputs = vec![
        LinkInput {
            name: "a.o".into(),
            bytes: a.build().expect("the fixture object builds"),
        },
        LinkInput {
            name: "b.o".into(),
            bytes: b.build().expect("the fixture object builds"),
        },
    ];
    let mut refs = RefsCollector::default();
    link_observed(
        &inputs,
        &[],
        &LinkConfig {
            undefined_policy: pgr_core::resolve::UndefinedPolicy::DynamicLookup,
            ..LinkConfig::default()
        },
        Parallelism::Auto,
        None,
        &mut refs,
    )
    .expect("the corpus links");
    let events = refs.finish();
    assert_eq!(
        events,
        vec![
            ReferenceEvent {
                name: "_shared".into(),
                from: "a.o".into(),
            },
            ReferenceEvent {
                name: "_shared".into(),
                from: "b.o".into(),
            },
        ],
        "each visit rides, in walk order"
    );
}

#[test]
fn the_replay_rereports_the_references_in_walk_order() {
    // The M9 resolve-reuse replay re-walks the parse's references in the
    // same file order the full path pushes sites in — the trace rides
    // the replay too (the trace is the run's own Pass-2 record, the
    // M107/M108 config pattern; the events must not vanish on a warm
    // relink's resolve).
    use pgr_core::resolve_reuse::{ResolveReuseSeed, install_reused, plan_reuse};
    use pgr_core::{Interner, ids::FileId, object::InputObject};
    let inputs = corpus();
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut objects: Vec<InputObject> = Vec::new();
    for (i, input) in inputs.iter().enumerate() {
        let mut obj = InputObject::parse(FileId(i as u32), &input.name, input.bytes.clone())
            .expect("the fixture parses");
        names.append(&mut obj.take_symbol_names());
        objects.push(obj);
    }
    let (interner, ids) = Interner::build(&names);
    let mut cursor = 0usize;
    for obj in &mut objects {
        let take = obj.symbols.len();
        obj.finish(&ids[cursor..cursor + take])
            .expect("the ids fit");
        cursor += take;
    }
    let mut full = pgr_core::resolve::Resolution::default();
    full.install(
        &objects,
        &interner,
        pgr_core::resolve::MultiplyDefinedPolicy::Error,
        &mut None,
    )
    .expect("the full install resolves");
    let snapshot =
        pgr_core::resolve::ResolutionSnapshot::capture(&objects, &interner, &full, &[], &[]);
    let seed = ResolveReuseSeed {
        snapshot,
        digests: pgr_core::propagate::section_digests(&objects),
    };
    let plan = plan_reuse(&seed.snapshot, &seed.digests, &interner, &objects, &[], &[])
        .expect("the shape guard admits the unchanged parse");
    let mut refs = RefsCollector::default();
    let mut slot: Option<&mut dyn LinkObserver> = Some(&mut refs);
    let replayed = install_reused(
        &plan,
        &seed.snapshot,
        &interner,
        &objects,
        &[],
        &[],
        &[],
        pgr_core::resolve::UndefinedPolicy::Error,
        false,
        pgr_core::resolve::ModulePolicy::default(),
        false,
        pgr_core::resolve::MultiplyDefinedPolicy::Error,
        &mut slot,
    )
    .expect("the replay resolves");
    let events = refs.finish();
    assert_eq!(
        events,
        vec![ReferenceEvent {
            name: "_greet".into(),
            from: "main.o".into(),
        }],
        "the replay's reference walk reports the same visits"
    );
    let _ = replayed;
}

#[test]
fn the_relocatable_output_refuses_the_trace() {
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        trace_refs: true,
        ..LinkConfig::default()
    };
    let err = link_reloc(&corpus(), &[], &cfg, Parallelism::Auto)
        .expect_err("the object shape refuses the trace");
    let msg = err.to_string();
    assert!(msg.contains("-t"), "the refusal names the knob: {msg}");
}

#[test]
fn the_default_traces_nothing_and_moves_nothing() {
    let cfg = LinkConfig::default();
    assert!(
        !cfg.trace_refs,
        "the default traces nothing (every pre-knob link byte-identical)"
    );
    let result = link(&corpus(), &[], &cfg).expect("the default links");
    assert!(
        result.layout.segments.len() >= 2,
        "the segmented plan rides"
    );
}

/// A compile-time seatbelt: the trait's default subscribes to nothing
/// (the observer that never asks pays nothing — the M54 convention).
#[test]
fn the_default_observer_subscribes_to_nothing() {
    #[derive(Default)]
    struct Silent;
    impl LinkObserver for Silent {}
    let mut silent = Silent;
    let result = link_observed(
        &corpus(),
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut silent,
    )
    .expect("the corpus links");
    assert!(
        result.layout.segments.len() >= 2,
        "the segmented plan rides"
    );
}

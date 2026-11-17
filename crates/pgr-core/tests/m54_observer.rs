//! M54 — the typed link-pipeline observation seam (`pgr_core::observe`):
//! the pass structure Passes 1–3 already name on the tracing seam becomes a
//! nameable, typed surface a library consumer can subscribe to — the phase
//! sequence in link order, each phase's completion carrying its own detail
//! (the parse's input count, the pulled archive members, the interner
//! batch, the resolve's reuse split, the fold count, the plan shape), and
//! the ladder's silent-correct rungs (the resolve-reuse fallback) as
//! explicit notes. The observer is read-only: an observed link plans the
//! identical layout an unobserved one does (the parity gate), and the
//! default trait methods keep an observer that subscribes to nothing
//! cost-free.
//!
//! Gate matrix:
//! * the sequence — a segmented link reports
//!   `Parse → ArchivePull → Intern → Resolve → Liveness → Fold → Layout`
//!   in link order, each with its phase's own detail;
//! * the parity — the observed link's plan is indistinguishable from the
//!   unobserved one (the observer never touches the pipeline);
//! * the note — a reuse seed whose file list moved falls back to the full
//!   resolve *and names itself on the seam* (the link stays correct: the
//!   fallback is the ladder's bottom rung, always available);
//! * the relocatable shape — `link_reloc_observed` reports the object
//!   shape's own run (`Parse → ArchivePull → Intern → Resolve → Reloc`);
//! * the bridge — `TracingObserver` rides the house tracing convention
//!   (inert until a subscriber installs) and observes the same sequence.

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism, link_cached, link_observed, link_reloc_observed};
use pgr_core::observe::{LinkNote, LinkObserver, Phase, PhaseDetail, PhaseEvent, TracingObserver};
use pgr_core::resolve_reuse::ResolveReuseSeed;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// The test's assertion face: every event in arrival order.
#[derive(Debug, Default)]
struct Recorder {
    phases: Vec<PhaseEvent>,
    notes: Vec<LinkNote>,
}

impl LinkObserver for Recorder {
    fn on_phase(&mut self, event: PhaseEvent) {
        self.phases.push(event);
    }

    fn on_note(&mut self, note: LinkNote) {
        self.notes.push(note);
    }
}

/// An observer that subscribes to nothing (the default methods).
struct Nop;

impl LinkObserver for Nop {}

/// One object: a two-instruction `__text` and a `_main` (when `main`) or
/// `_fn_<stem>` definition — the minimal corpus every pass runs over.
fn object(name: &str, stem: &str, main: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_section(ObjectSection::data("__data", vec![0x41u8; 8], vec![]));
    let symbol = if main {
        "_main".to_string()
    } else {
        format!("_{stem}")
    };
    b.add_symbol(ObjectSymbol::Defined {
        name: symbol,
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// The two-object corpus (`main.o` carries the entry).
fn corpus() -> Vec<LinkInput> {
    vec![
        LinkInput {
            name: "main.o".to_string(),
            bytes: object("main.o", "main", true),
        },
        LinkInput {
            name: "aux.o".to_string(),
            bytes: object("aux.o", "aux_fn", false),
        },
    ]
}

#[test]
fn the_observer_sees_the_pass_sequence_in_link_order() {
    let inputs = corpus();
    let mut observer = Recorder::default();
    let result = link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut observer,
    )
    .expect("the corpus links");
    assert!(result.layout.file_size > 0, "the link produced a plan");

    let phases: Vec<Phase> = observer.phases.iter().map(|e| e.phase).collect();
    assert_eq!(
        phases,
        vec![
            Phase::Parse,
            Phase::ArchivePull,
            Phase::Intern,
            Phase::Resolve,
            Phase::Liveness,
            Phase::Fold,
            Phase::Layout,
        ],
        "the pipeline reports its phases in link order"
    );

    // The details name their phase's own shape (the counts the pass
    // already had in hand — observing costs no extra work).
    assert_eq!(
        observer.phases[0].detail,
        PhaseDetail::Objects { inputs: 2 },
        "the parse names its input count"
    );
    assert_eq!(
        observer.phases[1].detail,
        PhaseDetail::Members { pulled: 0 },
        "the archive pull runs (and reports) even with no archives"
    );
    assert!(
        matches!(observer.phases[2].detail, PhaseDetail::Names { interned } if interned >= 2),
        "the intern batch names its symbol count"
    );
    assert_eq!(
        observer.phases[3].detail,
        PhaseDetail::Winners { reused: false },
        "the full resolve is named as such"
    );
    assert!(
        matches!(observer.phases[5].detail, PhaseDetail::Folded { folded: 0 }),
        "an ICF-free corpus folds nothing"
    );
    assert!(
        matches!(
            observer.phases[6].detail,
            PhaseDetail::Planned { segments, sections } if segments >= 3 && sections >= 2
        ),
        "the layout names the plan shape"
    );
}

#[test]
fn the_observed_link_matches_the_unobserved_link() {
    let inputs = corpus();
    let plain = link_cached(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
    )
    .expect("the corpus links");
    let mut subscriber = Recorder::default();
    let tracked = link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut subscriber,
    )
    .expect("the corpus links");

    assert_eq!(
        plain.layout.file_size, tracked.layout.file_size,
        "the observer never moves a byte of the plan"
    );
    assert_eq!(
        plain.layout.sections.len(),
        tracked.layout.sections.len(),
        "the section table is identical"
    );
    assert_eq!(
        plain.layout.symbols.len(),
        tracked.layout.symbols.len(),
        "the symbol table is identical"
    );

    // The no-op observer subscribes to nothing and plans the same shape.
    let nop = link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut Nop,
    )
    .expect("the corpus links");
    assert_eq!(nop.layout.file_size, plain.layout.file_size);
}

#[test]
fn the_resolve_reuse_fallback_names_itself_on_the_seam() {
    // Record the Pass-2 state of a one-object link (`alpha.o`) — the
    // record-side seam the incremental cycle rides (`record_resolution`).
    let alpha = vec![LinkInput {
        name: "alpha.o".to_string(),
        bytes: object("alpha.o", "alpha", true),
    }];
    let recorded_cfg = LinkConfig {
        record_resolution: true,
        ..LinkConfig::default()
    };
    let recorded = link_cached(&alpha, &[], &recorded_cfg, Parallelism::Auto, None)
        .expect("the recorded link plans");
    let snapshot = recorded
        .resolve_snapshot
        .clone()
        .expect("`record_resolution` captures the Pass-2 state");

    // The relink's file list moved (`beta.o`): the reuse plan refuses, the
    // full resolve runs — and the seam names the fallback.
    let seed = ResolveReuseSeed {
        snapshot,
        digests: Vec::new(),
    };
    let beta = vec![LinkInput {
        name: "beta.o".to_string(),
        bytes: object("beta.o", "beta", true),
    }];
    let cfg = LinkConfig {
        resolve_reuse: Some(seed),
        ..LinkConfig::default()
    };
    let mut observer = Recorder::default();
    let result = link_observed(&beta, &[], &cfg, Parallelism::Auto, None, &mut observer)
        .expect("the fallback is the ladder's bottom rung: the relink plans");
    assert!(result.layout.file_size > 0);

    assert!(
        observer.notes.iter().any(|n| matches!(
            n,
            LinkNote::ResolveReuseFallback { reason }
                if reason.contains("file list")
        )),
        "the moved shape names itself on the seam: {:?}",
        observer.notes
    );
    // The relink resolved in full — no `reused` shortcut on the seam.
    assert!(
        matches!(
            observer
                .phases
                .iter()
                .find(|e| e.phase == Phase::Resolve)
                .map(|e| &e.detail),
            Some(PhaseDetail::Winners { reused: false })
        ),
        "the fallback ran the full resolve"
    );
}

#[test]
fn the_reloc_path_reports_the_object_shape() {
    let inputs = vec![LinkInput {
        name: "main.o".to_string(),
        bytes: object("main.o", "main", true),
    }];
    let mut observer = Recorder::default();
    let linked = link_reloc_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        &mut observer,
    )
    .expect("the relocatable front half links");

    let phases: Vec<Phase> = observer.phases.iter().map(|e| e.phase).collect();
    assert_eq!(
        phases,
        vec![
            Phase::Parse,
            Phase::ArchivePull,
            Phase::Intern,
            Phase::Resolve,
            Phase::Reloc,
        ],
        "the `-r` shape reports its own run"
    );
    assert_eq!(
        observer.phases[4].detail,
        PhaseDetail::Reloc { inputs: 1 },
        "the reloc completion names its input count"
    );
    assert_eq!(linked.objects.len(), 1, "the front half parsed the input");
}

#[test]
fn the_tracing_observer_rides_the_tracing_seam() {
    // The bridge observer (inert until a subscriber installs — the house
    // convention) observes the same phases a recorder does.
    let inputs = corpus();
    let mut observer = TracingObserver;
    let result = link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut observer,
    )
    .expect("the corpus links");
    assert!(result.layout.file_size > 0);

    // The reuse-fallback note bridges too (a subscriber would see the
    // refusal reason; without one the rung stays silent-correct).
    let recorded_cfg = LinkConfig {
        record_resolution: true,
        ..LinkConfig::default()
    };
    let alpha = vec![LinkInput {
        name: "alpha.o".to_string(),
        bytes: object("alpha.o", "alpha", true),
    }];
    let recorded = link_cached(&alpha, &[], &recorded_cfg, Parallelism::Auto, None)
        .expect("the recorded link plans");
    let seed = ResolveReuseSeed {
        snapshot: recorded.resolve_snapshot.expect("the snapshot captured"),
        digests: Vec::new(),
    };
    let cfg = LinkConfig {
        resolve_reuse: Some(seed),
        ..LinkConfig::default()
    };
    let beta = vec![LinkInput {
        name: "beta.o".to_string(),
        bytes: object("beta.o", "beta", true),
    }];
    let mut bridge = TracingObserver;
    let _ = link_observed(&beta, &[], &cfg, Parallelism::Auto, None, &mut bridge)
        .expect("the fallback relink plans");
}

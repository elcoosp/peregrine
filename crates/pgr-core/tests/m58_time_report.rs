//! M58 — the per-pass time report (`pgr_core::time_report`): the M54
//! observation seam's phase events collected into a nameable, typed
//! report — the per-pass wall table the TDD's instrumentation spec
//! (§Instrumentation) and the roadmap's §9.3 budgets name, rendered as
//! a deterministic text table and a compact JSON interchange face.
//!
//! Gate matrix:
//! * the collection — a segmented link's report carries the same
//!   `Parse → ArchivePull → Intern → Resolve → Liveness → Fold →
//!   Layout` sequence the observer sees, each row with its phase's own
//!   detail and wall time;
//! * the parity — collecting changes no bytes (the observed link plans
//!   the identical layout — the M54 gate, re-gated through the
//!   collector);
//! * the relocatable shape — the `-r` run reports its own five phases;
//! * the notes — the ladder's silent-correct rungs (the resolve-reuse
//!   fallback) ride the report, never silently dropped;
//! * the faces — the text table and the JSON line render a fixed
//!   report exactly (deterministic columns, fixed key order, the
//!   report-JSON escape rules).

use std::time::Duration;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism, link_cached, link_observed, link_reloc_observed};
use pgr_core::observe::{Phase, PhaseDetail, PhaseEvent};
use pgr_core::resolve_reuse::ResolveReuseSeed;
use pgr_core::time_report::TimeCollector;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

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
fn the_collector_gathers_the_pass_sequence() {
    let inputs = corpus();
    let mut collector = TimeCollector::default();
    let result = link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut collector,
    )
    .expect("the corpus links");
    assert!(result.layout.file_size > 0, "the link produced a plan");

    let report = collector.report();
    let phases: Vec<Phase> = report.phases.iter().map(|e| e.phase).collect();
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
        "the report carries the phases in link order"
    );
    assert_eq!(
        report.phases[0].detail,
        PhaseDetail::Objects { inputs: 2 },
        "the parse row names its input count"
    );
    assert!(
        report.emit.is_none() && report.total.is_none(),
        "the library collector reports the phases it saw; the emit/total bands are the caller's"
    );
}

#[test]
fn the_collected_link_matches_the_unobserved_link() {
    let inputs = corpus();
    let plain = link_cached(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
    )
    .expect("the corpus links");
    let mut collector = TimeCollector::default();
    let tracked = link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut collector,
    )
    .expect("the corpus links");
    assert_eq!(
        plain.layout.file_size, tracked.layout.file_size,
        "collecting never moves a byte of the plan"
    );
    assert_eq!(plain.layout.sections.len(), tracked.layout.sections.len());
    assert_eq!(plain.layout.symbols.len(), tracked.layout.symbols.len());
}

#[test]
fn the_reloc_run_reports_the_object_shape() {
    let inputs = vec![LinkInput {
        name: "main.o".to_string(),
        bytes: object("main.o", "main", true),
    }];
    let mut collector = TimeCollector::default();
    let linked = link_reloc_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        &mut collector,
    )
    .expect("the relocatable front half links");
    let report = collector.report();
    let phases: Vec<Phase> = report.phases.iter().map(|e| e.phase).collect();
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
    assert_eq!(linked.objects.len(), 1, "the front half parsed the input");
}

#[test]
fn the_fallback_note_rides_the_report() {
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
    let mut collector = TimeCollector::default();
    let result = link_observed(&beta, &[], &cfg, Parallelism::Auto, None, &mut collector)
        .expect("the fallback is the ladder's bottom rung: the relink plans");
    assert!(result.layout.file_size > 0);
    let report = collector.report();
    assert!(
        report.notes.iter().any(|n| n.contains("file list")),
        "the moved shape rides the report as a note: {:?}",
        report.notes
    );
}

/// A hand-built report with fixed wall times — the exact-render gate
/// (the row set and the columns are deterministic; the values here are
/// the test's, not the clock's). `from_micros(us)` names the row's
/// wall in microseconds.
fn fixed_report() -> pgr_core::time_report::TimeReport {
    let row = |phase: Phase, detail: PhaseDetail, us: u64| PhaseEvent {
        phase,
        detail,
        elapsed: Duration::from_micros(us),
    };
    pgr_core::time_report::TimeReport {
        phases: vec![
            row(Phase::Parse, PhaseDetail::Objects { inputs: 2 }, 5_000),
            row(Phase::Intern, PhaseDetail::Names { interned: 2 }, 1_000),
            row(
                Phase::Layout,
                PhaseDetail::Planned {
                    segments: 4,
                    sections: 9,
                },
                2_500,
            ),
        ],
        emit: Some(Duration::from_micros(1_500)),
        total: Some(Duration::from_millis(12)),
        notes: vec![
            "the resolve-reuse replay fell back to the full resolve (the file list moved)"
                .to_string(),
        ],
    }
}

#[test]
fn the_text_table_renders_a_fixed_report_exactly() {
    let text = fixed_report().render();
    let expected = "\
the per-pass wall report
  parse        inputs=2                  5.000 ms   50.0%
  intern       interned=2                1.000 ms   10.0%
  layout       segments=4, sections=9    2.500 ms   25.0%
  emit         fused tile emit           1.500 ms   15.0%
  total        link wall                12.000 ms
  note: the resolve-reuse replay fell back to the full resolve (the file list moved)
";
    assert_eq!(text, expected, "the table renders exactly");
}

#[test]
fn the_text_table_names_micros_and_seconds() {
    let row = |phase: Phase, detail: PhaseDetail, us: u64| PhaseEvent {
        phase,
        detail,
        elapsed: Duration::from_micros(us),
    };
    let report = pgr_core::time_report::TimeReport {
        phases: vec![
            row(Phase::Parse, PhaseDetail::Objects { inputs: 0 }, 831),
            row(
                Phase::Layout,
                PhaseDetail::Planned {
                    segments: 0,
                    sections: 0,
                },
                2_500,
            ),
            row(Phase::Intern, PhaseDetail::Names { interned: 0 }, 1_000),
        ],
        emit: None,
        total: Some(Duration::from_millis(1_250)),
        notes: Vec::new(),
    };
    let text = report.render();
    let expected = "\
the per-pass wall report
  parse        inputs=0                    831 µs   19.1%
  layout       segments=0, sections=0    2.500 ms   57.7%
  intern       interned=0                1.000 ms   23.0%
  total        link wall                  1.250 s
";
    assert_eq!(text, expected, "the unit ladder renders exactly");
}

#[test]
fn the_json_renders_a_fixed_report_exactly() {
    let json = fixed_report().render_json();
    let expected = concat!(
        "{\"phases\":[",
        "{\"phase\":\"parse\",\"detail\":{\"kind\":\"objects\",\"inputs\":2},\"elapsed_us\":5000},",
        "{\"phase\":\"intern\",\"detail\":{\"kind\":\"names\",\"interned\":2},\"elapsed_us\":1000},",
        "{\"phase\":\"layout\",\"detail\":{\"kind\":\"planned\",\"segments\":4,\"sections\":9},\"elapsed_us\":2500}",
        "],\"emit_us\":1500,\"total_us\":12000,\"notes\":[",
        "\"the resolve-reuse replay fell back to the full resolve (the file list moved)\"",
        "]}"
    );
    assert_eq!(json, expected, "the interchange renders exactly");
}

#[test]
fn the_json_renders_null_bands_and_escapes_notes() {
    let row = |us: u64| PhaseEvent {
        phase: Phase::Parse,
        detail: PhaseDetail::Objects { inputs: 0 },
        elapsed: Duration::from_micros(us),
    };
    let report = pgr_core::time_report::TimeReport {
        phases: vec![row(1)],
        emit: None,
        total: None,
        notes: vec!["a \"quoted\" note\nover two lines".to_string()],
    };
    let json = report.render_json();
    let expected = concat!(
        "{\"phases\":[{\"phase\":\"parse\",\"detail\":{\"kind\":\"objects\",\"inputs\":0},\"elapsed_us\":1}]",
        ",\"emit_us\":null,\"total_us\":null,\"notes\":[\"a \\\"quoted\\\" note\\nover two lines\"]}"
    );
    assert_eq!(
        json, expected,
        "the interchange escapes the notes and names the absent bands"
    );
}

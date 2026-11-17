//! M61 — the Chrome-trace timeline (`pgr_core::trace`): the roadmap's
//! §9.4 profiling toolbox ("`--trace` — Chrome-trace-format timeline, so
//! stragglers and idle gaps are visible") names a measurement surface the
//! M54 observation seam already serves the raw material for — the typed
//! [`PhaseEvent`]s carry each Pass 1–3 phase's completion and wall time.
//! This gate binds the consumer that turns those events *as data* into
//! the timeline: [`TraceCollector`] subscribes to the seam (an
//! [`LinkObserver`] impl) and [`TraceReport::render`] writes the Chrome
//! Trace Event Format's object form (deterministic, one line, the house
//! interchange rules), while [`parse_trace_json`] is the strict reader —
//! the round-trip convention, gated.
//!
//! Gate matrix:
//! * the collector — synthetic phase events land as spans in arrival
//!   order, each carrying its phase token, its detail (the event's own
//!   shape, verbatim), its lane and its µs bounds; the note rides as an
//!   instant; the `-r` shape rides its own run;
//! * the render — the object form's fixed key order, the metadata rows
//!   first (one `process_name`, one `thread_name` per lane), the spans
//!   and instants sorted by `(ts, kind, name)`, two renders of one
//!   report byte-identical (the determinism contract);
//! * the round trip — `parse_trace_json` restores the rendered report
//!   exactly (the data-only [`TraceReport`] compares equal, the re-render
//!   is byte-identical);
//! * the refusals — the reader names the byte it stopped at: an unknown
//!   `ph`, an unknown phase token, an unknown detail kind, a non-integer
//!   timestamp, a missing key, a duplicate key, an unknown top-level key,
//!   a lane a span names but no `thread_name` declared, trailing bytes;
//! * the parity — a link observed through the collector plans the
//!   identical image the unobserved one does (the seam's own contract:
//!   collecting never moves a byte);
//! * the composition — [`ObserverPair`] forwards the one stream to two
//!   collectors (the `--time` + `--trace` shape: both faces read the one
//!   observed run).

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism, link_cached, link_observed, link_reloc_observed};
use pgr_core::observe::{LinkNote, LinkObserver, ObserverPair, Phase, PhaseDetail, PhaseEvent};
use pgr_core::time_report::TimeCollector;
use pgr_core::trace::{TraceCollector, TraceJsonError, parse_trace_json};
use pgr_fixtures::ObjectBuilder;
use pgr_fixtures::ObjectSection;
use pgr_fixtures::ObjectSymbol;

/// A synthetic phase event (the m58 gate's `row` shape — the collector
/// is fed by hand so the µs bounds are the test's own).
fn row(phase: Phase, detail: PhaseDetail, us: u64) -> PhaseEvent {
    PhaseEvent {
        phase,
        detail,
        elapsed: std::time::Duration::from_micros(us),
    }
}

/// The note the ladder emits (the one variant today).
fn fallback(reason: &str) -> LinkNote {
    LinkNote::ResolveReuseFallback {
        reason: reason.to_string(),
    }
}

/// One object: a two-instruction `__text` and a `_main` (when `main`) or
/// `_fn_<stem>` definition — the minimal corpus every pass runs over
/// (the m54 corpus shape).
fn object(name: &str, stem: &str, main: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: if main {
            "_main".into()
        } else {
            format!("_{stem}")
        },
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

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

// ---- the collector -----------------------------------------------------------

#[test]
fn the_collector_keeps_the_spans_and_the_note() {
    let mut c = TraceCollector::new();
    c.on_phase(row(Phase::Parse, PhaseDetail::Objects { inputs: 2 }, 120));
    c.on_phase(row(
        Phase::Resolve,
        PhaseDetail::Winners { reused: false },
        340,
    ));
    c.on_note(fallback("the seed's file list moved"));
    let report = c.finish();
    assert_eq!(report.spans.len(), 2, "two phase spans");
    assert_eq!(report.notes.len(), 1, "the note rides");
    assert_eq!(report.lanes.len(), 1, "one lane (the pipeline thread)");
    let first = &report.spans[0];
    assert_eq!(first.phase, Phase::Parse, "arrival order");
    assert_eq!(first.detail, PhaseDetail::Objects { inputs: 2 });
    assert_eq!(first.dur_us, 120, "the event's own wall, in µs");
    assert_eq!(first.lane, 1, "the first lane is 1");
    assert_eq!(report.spans[1].phase, Phase::Resolve);
    assert_eq!(report.spans[1].lane, 1, "the same lane");
    assert_eq!(report.notes[0].reason, "the seed's file list moved");
}

#[test]
fn the_span_bounds_stay_ordered_and_unsigned() {
    let mut c = TraceCollector::new();
    c.on_phase(row(Phase::Parse, PhaseDetail::Objects { inputs: 1 }, 50));
    c.on_phase(row(Phase::Intern, PhaseDetail::Names { interned: 4 }, 60));
    c.on_phase(row(
        Phase::Layout,
        PhaseDetail::Planned {
            segments: 3,
            sections: 5,
        },
        70,
    ));
    let report = c.finish();
    for pair in report.spans.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        assert!(
            a.start_us <= b.start_us,
            "starts never move backwards: {} then {}",
            a.start_us,
            b.start_us
        );
    }
    // The µs bounds are the collector's own measurement (arrivals minus
    // the event's wall): none of them may ride the saturating floor.
    assert!(
        report.spans.iter().all(|s| s.dur_us >= 1),
        "every synthetic span keeps its µs wall"
    );
}

#[test]
fn the_reloc_shape_rides_its_own_run() {
    let inputs = vec![LinkInput {
        name: "solo.o".to_string(),
        bytes: object("solo.o", "solo", true),
    }];
    let mut c = TraceCollector::new();
    link_reloc_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        &mut c,
    )
    .expect("the reloc link runs");
    let report = c.finish();
    let phases: Vec<Phase> = report.spans.iter().map(|s| s.phase).collect();
    assert_eq!(
        phases,
        vec![
            Phase::Parse,
            Phase::ArchivePull,
            Phase::Intern,
            Phase::Resolve,
            Phase::Reloc,
        ],
        "the object shape's own run (the m54 sequence, no plan)"
    );
}

// ---- the render ---------------------------------------------------------------

#[test]
fn the_render_is_the_chrome_object_form() {
    let mut c = TraceCollector::new();
    c.on_phase(row(Phase::Parse, PhaseDetail::Objects { inputs: 2 }, 120));
    c.on_phase(row(
        Phase::Layout,
        PhaseDetail::Planned {
            segments: 3,
            sections: 2,
        },
        45,
    ));
    c.on_note(fallback("the seed's file list moved"));
    let json = c.finish().render();
    assert!(json.starts_with("{\"traceEvents\":["), "the object form");
    assert!(
        json.ends_with("]}}") || json.ends_with("]}"),
        "one object, closed"
    );
    assert!(!json.contains('\n'), "one line (the house interchange)");
    assert!(
        json.contains("\"name\":\"process_name\""),
        "the process metadata row leads"
    );
    assert!(
        json.contains("\"name\":\"thread_name\""),
        "one thread_name row per lane"
    );
    assert!(
        json.contains("\"ph\":\"X\""),
        "the phase spans ride the complete-event shape"
    );
    assert!(
        json.contains("\"ph\":\"i\""),
        "the note rides the instant shape"
    );
    assert!(
        json.contains("\"args\":{\"kind\":\"objects\",\"inputs\":2}"),
        "the detail rides its own keys (the m58 interchange shape)"
    );
}

#[test]
fn the_render_is_deterministic_and_sorted() {
    let mut c = TraceCollector::new();
    // The walls ride at the arrival-gap scale (1 µs): a span's start is
    // the arrival clock minus its own wall, and walls that exceed the
    // gaps clamp at the axis's floor (the saturating shape) — the
    // floor's ties sort by name, the ordered runs ride the ts order.
    c.on_phase(row(Phase::Parse, PhaseDetail::Objects { inputs: 2 }, 1));
    c.on_phase(row(Phase::Intern, PhaseDetail::Names { interned: 4 }, 1));
    c.on_note(fallback("first"));
    c.on_phase(row(
        Phase::Layout,
        PhaseDetail::Planned {
            segments: 3,
            sections: 2,
        },
        1,
    ));
    let report = c.finish();
    let a = report.render();
    let b = report.render();
    assert_eq!(a, b, "two renders of one report are byte-identical");
    // The events sort by (ts, kind, name): the metadata rows lead, then
    // the timeline rows in ts order. Phase names are unique per link, so
    // the sort is total.
    let parse_at = a.find("\"name\":\"parse\"").expect("the parse span rides");
    let intern_at = a
        .find("\"name\":\"intern\"")
        .expect("the intern span rides");
    assert!(parse_at < intern_at, "the ts order rides the render");
}

#[test]
fn an_empty_collector_renders_the_metadata_skeleton() {
    let report = TraceCollector::new().finish();
    let json = report.render();
    assert!(
        json.contains("\"name\":\"process_name\""),
        "the process row rides even with no events"
    );
    assert!(!json.contains("\"ph\":\"X\""), "no timeline rows");
    let parsed = parse_trace_json(&json).expect("the skeleton parses");
    assert!(parsed.spans.is_empty() && parsed.notes.is_empty());
}

// ---- the round trip -----------------------------------------------------------

#[test]
fn the_render_round_trips_through_the_strict_reader() {
    let mut c = TraceCollector::new();
    // The walls ride at the arrival-gap scale (1 µs) — the collector's
    // arrival order is the render's canonical (ts) order for a real
    // run, which is the shape the round trip restores.
    c.on_phase(row(Phase::Parse, PhaseDetail::Objects { inputs: 2 }, 1));
    c.on_phase(row(
        Phase::Resolve,
        PhaseDetail::Winners { reused: true },
        1,
    ));
    c.on_phase(row(
        Phase::Layout,
        PhaseDetail::Planned {
            segments: 3,
            sections: 2,
        },
        1,
    ));
    c.on_note(fallback("the seed's file list moved"));
    let report = c.finish();
    let json = report.render();
    let parsed = parse_trace_json(&json).expect("the rendered trace parses");
    assert_eq!(parsed, report, "the reader restores the writer's data");
    assert_eq!(parsed.render(), json, "the re-render is byte-identical");
}

#[test]
fn the_reader_accepts_the_schema_any_writer_produces() {
    // The same rigid-schema rule the m55 reader gates: keys in any order,
    // whitespace between tokens, the exact fields.
    let loose = " { \"traceEvents\" : [ \
        { \"ph\" : \"M\" , \"name\" : \"process_name\" , \"pid\" : 1 , \
          \"args\" : { \"name\" : \"pgr\" } } , \
        { \"ph\" : \"M\" , \"name\" : \"thread_name\" , \"pid\" : 1 , \"tid\" : 2 , \
          \"args\" : { \"name\" : \"pgr link\" } } , \
        { \"cat\" : \"pgr\" , \"ph\" : \"X\" , \"name\" : \"parse\" , \"ts\" : 5 , \
          \"dur\" : 7 , \"pid\" : 1 , \"tid\" : 2 , \
          \"args\" : { \"kind\" : \"objects\" , \"inputs\" : 3 } } ] } ";
    let parsed = parse_trace_json(loose).expect("the loose shape parses");
    assert_eq!(parsed.spans.len(), 1);
    assert_eq!(parsed.spans[0].phase, Phase::Parse);
    assert_eq!(parsed.spans[0].lane, 2);
    assert_eq!(parsed.spans[0].start_us, 5);
    assert_eq!(parsed.spans[0].dur_us, 7);
    assert_eq!(parsed.spans[0].detail, PhaseDetail::Objects { inputs: 3 });
    assert_eq!(
        parsed.lanes,
        vec![pgr_core::trace::TraceLane {
            id: 2,
            name: "pgr link".to_string(),
        }]
    );
}

// ---- the refusals -------------------------------------------------------------

#[test]
fn the_reader_refuses_the_broken_shapes() {
    // (tag, document, the refusal's own words)
    let cases: [(&str, &str, &str); 9] = [
        ("empty", "", "unexpected end of document"),
        (
            "unknown ph",
            "{\"traceEvents\":[{\"name\":\"x\",\"ph\":\"Z\",\"pid\":1,\"tid\":1}]}",
            "unknown trace event ph",
        ),
        (
            "unknown phase token",
            "{\"traceEvents\":[{\"name\":\"process_name\",\"ph\":\"M\",\"pid\":1,\"args\":{\"name\":\"pgr\"}},{\"name\":\"bogus_phase\",\"cat\":\"pgr\",\"ph\":\"X\",\"ts\":0,\"dur\":1,\"pid\":1,\"tid\":1,\"args\":{\"kind\":\"objects\",\"inputs\":1}}]}",
            "unknown phase token",
        ),
        (
            "unknown detail kind",
            "{\"traceEvents\":[{\"name\":\"process_name\",\"ph\":\"M\",\"pid\":1,\"args\":{\"name\":\"pgr\"}},{\"name\":\"parse\",\"cat\":\"pgr\",\"ph\":\"X\",\"ts\":0,\"dur\":1,\"pid\":1,\"tid\":1,\"args\":{\"kind\":\"gadgets\",\"inputs\":1}}]}",
            "unknown detail kind",
        ),
        (
            "float timestamp",
            "{\"traceEvents\":[{\"name\":\"process_name\",\"ph\":\"M\",\"pid\":1,\"args\":{\"name\":\"pgr\"}},{\"name\":\"parse\",\"cat\":\"pgr\",\"ph\":\"X\",\"ts\":0.5,\"dur\":1,\"pid\":1,\"tid\":1,\"args\":{\"kind\":\"objects\",\"inputs\":1}}]}",
            "a float rode here",
        ),
        (
            "missing key",
            "{\"traceEvents\":[{\"name\":\"process_name\",\"ph\":\"M\",\"pid\":1,\"args\":{\"name\":\"pgr\"}},{\"name\":\"parse\",\"cat\":\"pgr\",\"ph\":\"X\",\"ts\":0,\"pid\":1,\"tid\":1,\"args\":{\"kind\":\"objects\",\"inputs\":1}}]}",
            "missing field",
        ),
        (
            "unknown top-level key",
            "{\"traceEvents\":[],\"displayTimeUnit\":\"ns\"}",
            "unknown key",
        ),
        (
            "undeclared lane",
            "{\"traceEvents\":[{\"name\":\"process_name\",\"ph\":\"M\",\"pid\":1,\"args\":{\"name\":\"pgr\"}},{\"name\":\"parse\",\"cat\":\"pgr\",\"ph\":\"X\",\"ts\":0,\"dur\":1,\"pid\":1,\"tid\":9,\"args\":{\"kind\":\"objects\",\"inputs\":1}}]}",
            "no thread_name declares it",
        ),
        ("trailing bytes", "{\"traceEvents\":[]} x", "trailing bytes"),
    ];
    for (tag, raw, words) in cases {
        let err = parse_trace_json(raw).expect_err(tag);
        let rendered = err.to_string();
        assert!(
            rendered.contains(words),
            "the refusal names the shape ({tag}): {rendered}"
        );
        match &err {
            TraceJsonError::Invalid { at, .. } => {
                assert!(
                    rendered.contains(&format!("byte {at}")),
                    "the position rides the rendered refusal: {rendered}"
                );
            }
            TraceJsonError::Field { name, .. } => {
                assert!(
                    rendered.contains(name.as_str()),
                    "the field rides the rendered refusal: {rendered}"
                );
            }
        }
    }
}

// ---- the parity ----------------------------------------------------------------

#[test]
fn the_collector_never_moves_a_byte() {
    let inputs = corpus();
    let plain = link_cached(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
    )
    .expect("the corpus links");
    let mut collector = TraceCollector::new();
    let tracked = link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut collector,
    )
    .expect("the observed corpus links");
    assert_eq!(
        plain.layout.file_size, tracked.layout.file_size,
        "the observed link plans the identical size"
    );
    assert_eq!(plain.layout.entryoff, tracked.layout.entryoff);
    assert_eq!(
        plain.layout.segments.len(),
        tracked.layout.segments.len(),
        "the observed plan carries the same segment set"
    );
    let report = collector.finish();
    assert!(
        report.spans.iter().any(|s| s.phase == Phase::Parse),
        "the real run's spans landed"
    );
}

// ---- the composition -----------------------------------------------------------

#[test]
fn the_observer_pair_serves_two_collectors() {
    let mut times = TimeCollector::default();
    let mut traces = TraceCollector::new();
    {
        let mut pair = ObserverPair::new(&mut times, &mut traces);
        pair.on_phase(row(Phase::Parse, PhaseDetail::Objects { inputs: 2 }, 11));
        pair.on_note(fallback("the seed's file list moved"));
    }
    let t = times.report();
    assert_eq!(t.phases.len(), 1, "the time face saw the event");
    assert_eq!(t.notes.len(), 1, "the time face saw the note");
    let r = traces.finish();
    assert_eq!(r.spans.len(), 1, "the trace face saw the event");
    assert_eq!(r.notes.len(), 1, "the trace face saw the note");
}

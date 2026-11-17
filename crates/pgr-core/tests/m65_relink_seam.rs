//! M65 — the relink ladder rides the observation seam: the §7.3 ladder's
//! engine rungs (the integrity gate, the patch plan, the clone-and-patch,
//! the `-incremental-verify` audit) join the M54 seam's phase vocabulary
//! beside the pipeline's passes, and the ladder's fallback rungs join the
//! note vocabulary — the "silent-correct, not silent-blind" contract, made
//! nameable on the faces that already read the seam (`--time`'s table, the
//! Chrome-trace timeline). The vocabulary is additive: every collector,
//! bridge, reader and wire token the M54/M58/M61/M62 surfaces built keeps
//! its shape, and a rung row rides them exactly like a pass row.
//!
//! Gate matrix:
//! * the tokens — the rungs name their stable tokens (the `snake_case`
//!   convention the pipeline phases carry);
//! * the faces — a report carrying the rungs renders both faces (the text
//!   table, the JSON interchange) and the timeline round-trips through the
//!   strict reader (the vocabulary crossed the document, the reader
//!   restores it exactly);
//! * the reader's refusals — a foreign phase token still refuses (the
//!   schema's gate is the writer's own name set, grown, not opened);
//! * the note — the ladder's fallback names itself on both collectors
//!   (a table that hid the fallback would misread the run it timed);
//! * the bridge — `TracingObserver` carries both notes (the new variant
//!   names its own event, an arm, not a skip).

use std::time::Duration;

use pgr_core::observe::{LinkNote, LinkObserver, Phase, PhaseDetail, PhaseEvent, TracingObserver};
use pgr_core::time_report::TimeCollector;
use pgr_core::trace::{TraceCollector, TraceLane, TraceNote, TraceSpan, parse_trace_json};

/// The rungs' stable tokens (the M54 `snake_case` convention).
#[test]
fn the_relink_rungs_name_their_tokens() {
    assert_eq!(Phase::RelinkGate.as_str(), "relink_gate");
    assert_eq!(Phase::RelinkPlan.as_str(), "relink_plan");
    assert_eq!(Phase::RelinkPatch.as_str(), "relink_patch");
    assert_eq!(Phase::RelinkAudit.as_str(), "relink_audit");
}

/// One rung event per phase, sized like the ladder's own reports.
fn rung_events() -> Vec<PhaseEvent> {
    vec![
        PhaseEvent {
            phase: Phase::RelinkGate,
            detail: PhaseDetail::Gate { pages: 16 },
            elapsed: Duration::from_micros(120),
        },
        PhaseEvent {
            phase: Phase::RelinkPlan,
            detail: PhaseDetail::Plan { tiles: 8, dirty: 2 },
            elapsed: Duration::from_micros(340),
        },
        PhaseEvent {
            phase: Phase::RelinkPatch,
            detail: PhaseDetail::Patch {
                bytes: 32_768,
                tiles: 2,
            },
            elapsed: Duration::from_micros(900),
        },
        PhaseEvent {
            phase: Phase::RelinkAudit,
            detail: PhaseDetail::Audit {
                healed: false,
                issues: 0,
            },
            elapsed: Duration::from_micros(2_500),
        },
    ]
}

/// Both faces render the rungs: the table's shape column carries the
/// rung's own counts, the JSON line the same data (fixed key order).
#[test]
fn the_faces_render_the_relink_rungs() {
    let mut times = TimeCollector::default();
    for event in rung_events() {
        times.on_phase(event);
    }
    let report = times.report();

    let table = report.render();
    assert!(table.contains("relink_gate"), "the gate row rides: {table}");
    assert!(table.contains("relink_plan"), "the plan row rides: {table}");
    assert!(
        table.contains("relink_patch"),
        "the patch row rides: {table}"
    );
    assert!(
        table.contains("relink_audit"),
        "the audit row rides: {table}"
    );
    assert!(table.contains("pages=16"), "the gate names its page count");
    assert!(
        table.contains("tiles=8, dirty=2"),
        "the plan names its tiles"
    );
    assert!(table.contains("bytes=32768"), "the patch names its bytes");

    let json = report.render_json();
    assert!(
        json.contains(r#""phase":"relink_plan""#),
        "the JSON names the rung: {json}"
    );
    assert!(
        json.contains(r#""kind":"plan","tiles":8,"dirty":2"#),
        "the plan detail rides its own keys: {json}"
    );
    assert!(
        json.contains(r#""kind":"audit","healed":false,"issues":0"#),
        "the audit detail rides its own keys: {json}"
    );
}

/// The timeline round-trips the rungs: the collector keeps them, the
/// render writes them, the strict reader restores them exactly (the
/// round-trip convention, gated on the new vocabulary).
#[test]
fn the_timeline_round_trips_the_relink_rungs() {
    let mut traces = TraceCollector::new();
    for event in rung_events() {
        traces.on_phase(event);
    }
    traces.on_note(LinkNote::RelinkFallback {
        reason: "the record did not decode; the in-process relink re-records".into(),
    });
    let report = traces.finish();
    assert_eq!(report.spans.len(), 4, "the collector keeps every rung span");
    assert_eq!(report.notes.len(), 1, "the note rides the collector");

    let json = report.render();
    let restored = parse_trace_json(&json).expect("the timeline with the rung rows parses back");
    assert_eq!(restored, report, "the round trip restores the data exactly");
    assert!(
        restored.spans.iter().any(|s| s.phase == Phase::RelinkPatch),
        "the patch span rides the restored report"
    );
    assert_eq!(
        restored.notes[0].kind, "relink_fallback",
        "the note's token restores"
    );
}

/// A hand-built report (no collector between) renders and parses back —
/// the reader accepts exactly the writer's name set, grown to the rungs.
#[test]
fn the_reader_accepts_the_grown_name_set() {
    let report = pgr_core::trace::TraceReport {
        spans: vec![TraceSpan {
            phase: Phase::RelinkGate,
            detail: PhaseDetail::Gate { pages: 16 },
            lane: 1,
            start_us: 5,
            dur_us: 120,
        }],
        notes: vec![TraceNote {
            kind: "relink_fallback",
            reason: "no record for this output yet".into(),
            lane: 1,
            at_us: 3,
        }],
        lanes: vec![TraceLane {
            id: 1,
            name: "pgr link".into(),
        }],
        tasks: Vec::new(),
    };
    let json = report.render();
    assert!(
        json.contains(r#""name":"relink_gate""#),
        "the render writes the rung token: {json}"
    );
    assert!(
        json.contains(r#""name":"relink_fallback""#),
        "the render writes the note token: {json}"
    );
    let restored = parse_trace_json(&json).expect("the hand-built report parses back");
    assert_eq!(restored, report, "the strict reader restores it exactly");
}

/// A foreign phase token still refuses (the gate is the writer's name
/// set, grown — never opened).
#[test]
fn the_reader_still_refuses_a_foreign_token() {
    let json = r#"{"traceEvents":[{"name":"process_name","ph":"M","pid":1,"args":{"name":"pgr"}},{"name":"thread_name","ph":"M","pid":1,"tid":1,"args":{"name":"pgr link"}},{"name":"not_a_phase","cat":"pgr","ph":"X","ts":0,"dur":1,"pid":1,"tid":1,"args":{"kind":"gate","pages":16}}]}"#;
    let err = parse_trace_json(json).expect_err("a foreign token refuses");
    assert!(
        err.to_string().contains("unknown phase token"),
        "the refusal names the schema: {err}"
    );
}

/// The bridge carries both notes (the new variant names its own event).
#[test]
fn the_bridge_carries_both_notes() {
    let mut bridge = TracingObserver;
    bridge.on_note(LinkNote::ResolveReuseFallback {
        reason: "the file list moved".into(),
    });
    bridge.on_note(LinkNote::RelinkFallback {
        reason: "output changed: resized".into(),
    });
}

/// The time collector keeps both notes (the report's note lines name
/// the ladder's fallback beside the resolve's).
#[test]
fn the_time_collector_keeps_both_notes() {
    let mut times = TimeCollector::default();
    times.on_note(LinkNote::ResolveReuseFallback {
        reason: "the shape guard refused".into(),
    });
    times.on_note(LinkNote::RelinkFallback {
        reason: "no record for this output yet".into(),
    });
    let report = times.report();
    assert_eq!(report.notes.len(), 2, "both notes ride");
    assert!(
        report.render().contains("no record for this output yet"),
        "the ladder's fallback renders"
    );
}

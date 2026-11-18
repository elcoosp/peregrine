//! M68 — the emit half joins the observation seam: Passes 4–5 stop being
//! the caller's opaque band and ride the seam as typed phases (`emit` —
//! the fused tile emit's completion; `flush` — the pooled atomic write's
//! completion), the TDD §9.3 instrumentation spec's named rows beside the
//! pipeline's passes. The band face stays the library caller's (`TimeReport`
//! keeps `emit`/`total` as `Option`s); the driver's rows ride the seam.
//!
//! Gate matrix:
//! * the vocabulary — the two phase tokens and their detail kinds ride
//!   `Phase`/`PhaseDetail` with the house `snake_case` tokens;
//! * the faces — a collector fed the emit rows renders them in link order
//!   (text table and JSON interchange), the share span carrying the rows;
//! * the timeline — a trace collector fed the full nine-phase segmented
//!   run round-trips through the strict reader (the M61 round-trip
//!   convention, gated on the extension).

use std::time::Duration;

use pgr_core::TimeCollector;
use pgr_core::observe::{LinkObserver as _, Phase, PhaseDetail, PhaseEvent};
use pgr_core::trace::{TraceCollector, parse_trace_json};

fn event(phase: Phase, detail: PhaseDetail, us: u64) -> PhaseEvent {
    PhaseEvent {
        phase,
        detail,
        elapsed: Duration::from_micros(us),
    }
}

fn emit_row() -> PhaseEvent {
    event(
        Phase::Emit,
        PhaseDetail::Emitted {
            tiles: 256,
            bytes: 4_194_304,
        },
        1_100,
    )
}

fn flush_row() -> PhaseEvent {
    event(
        Phase::Flush,
        PhaseDetail::Flushed {
            blocks: 1,
            writers: 1,
        },
        400,
    )
}

// ---- the vocabulary -----------------------------------------------------------

#[test]
fn the_emit_rows_join_the_phase_vocabulary() {
    assert_eq!(Phase::Emit.as_str(), "emit", "the fused tile emit's token");
    assert_eq!(Phase::Flush.as_str(), "flush", "the pooled write's token");
    let report = TimeCollector::default().report();
    let _ = &report; // the collector face compiles beside the new rows
    let text = {
        let mut collector = TimeCollector::default();
        collector.on_phase(event(
            Phase::Emit,
            PhaseDetail::Emitted {
                tiles: 4,
                bytes: 65_536,
            },
            90,
        ));
        collector.report().render()
    };
    assert!(
        text.contains("emit") && text.contains("tiles=4, bytes=65536"),
        "the emitted row's detail renders: {text}"
    );
    let flushed = {
        let mut collector = TimeCollector::default();
        collector.on_phase(event(
            Phase::Flush,
            PhaseDetail::Flushed {
                blocks: 3,
                writers: 4,
            },
            120,
        ));
        collector.report().render()
    };
    assert!(
        flushed.contains("flush") && flushed.contains("blocks=3, writers=4"),
        "the flushed row's detail renders: {flushed}"
    );
}

#[test]
fn the_emit_rows_render_in_link_order() {
    let mut collector = TimeCollector::default();
    collector.on_phase(event(
        Phase::Layout,
        PhaseDetail::Planned {
            segments: 4,
            sections: 9,
        },
        210,
    ));
    collector.on_phase(emit_row());
    collector.on_phase(flush_row());
    let report = collector.report();
    let text = report.render();
    let layout_at = text.find("layout").expect("the layout row renders");
    let emit_at = text.find("  emit ").expect("the emit row renders");
    let flush_at = text.find("  flush ").expect("the flush row renders");
    assert!(
        layout_at < emit_at && emit_at < flush_at,
        "the rows render in link order (layout, emit, flush):\n{text}"
    );
    let line = report.render_json();
    let layout_at = line
        .find("\"phase\":\"layout\"")
        .expect("the layout row rides");
    let emit_at = line.find("\"phase\":\"emit\"").expect("the emit row rides");
    let flush_at = line
        .find("\"phase\":\"flush\"")
        .expect("the flush row rides");
    assert!(
        layout_at < emit_at && emit_at < flush_at,
        "the interchange keeps link order: {line}"
    );
    assert!(
        line.contains("\"kind\":\"emitted\",\"tiles\":256,\"bytes\":4194304"),
        "the emitted detail rides its keys: {line}"
    );
    assert!(
        line.contains("\"kind\":\"flushed\",\"blocks\":1,\"writers\":1"),
        "the flushed detail rides its keys: {line}"
    );
}

#[test]
fn the_share_span_covers_the_emit_rows() {
    let mut collector = TimeCollector::default();
    collector.on_phase(event(
        Phase::Layout,
        PhaseDetail::Planned {
            segments: 4,
            sections: 9,
        },
        1_000,
    ));
    collector.on_phase(emit_row());
    collector.on_phase(flush_row());
    let text = collector.report().render();
    // The span is the measured rows themselves (the band rides None):
    // 1000 + 1100 + 400 µs → 40.0% / 44.0% / 16.0%.
    assert!(text.contains("40.0%"), "the layout row's share: {text}");
    assert!(text.contains("44.0%"), "the emit row's share: {text}");
    assert!(text.contains("16.0%"), "the flush row's share: {text}");
}

#[test]
fn the_bands_stay_the_callers() {
    // The band face survives the extension: a library caller fills
    // `emit`/`total` and the bands render beside the phase rows (the
    // M58 contract, unchanged for the library shape).
    let mut collector = TimeCollector::default();
    collector.on_phase(emit_row());
    let mut report = collector.report();
    report.emit = Some(Duration::from_micros(1_500));
    report.total = Some(Duration::from_millis(12));
    let text = report.render();
    assert!(
        text.contains("fused tile emit"),
        "the band row still renders for the library caller: {text}"
    );
    assert!(text.contains("link wall"), "the total band rides: {text}");
    let line = report.render_json();
    assert!(
        line.contains("\"emit_us\":1500") && line.contains("\"total_us\":12000"),
        "the bands ride the interchange for the library caller: {line}"
    );
}

// ---- the timeline -------------------------------------------------------------

#[test]
fn the_timeline_round_trips_the_emit_rows() {
    let mut collector = TraceCollector::new();
    let pipeline = [
        event(Phase::Parse, PhaseDetail::Objects { inputs: 12 }, 900),
        event(Phase::ArchivePull, PhaseDetail::Members { pulled: 0 }, 4),
        event(Phase::Intern, PhaseDetail::Names { interned: 128 }, 90),
        event(Phase::Resolve, PhaseDetail::Winners { reused: false }, 120),
        event(Phase::Liveness, PhaseDetail::Live { active: false }, 30),
        event(Phase::Fold, PhaseDetail::Folded { folded: 0 }, 10),
        event(
            Phase::Layout,
            PhaseDetail::Planned {
                segments: 4,
                sections: 9,
            },
            210,
        ),
    ];
    for e in pipeline {
        collector.on_phase(e);
    }
    collector.on_phase(emit_row());
    collector.on_phase(flush_row());
    let timeline = collector.finish().render();
    assert!(
        timeline.contains("\"name\":\"emit\"") && timeline.contains("\"name\":\"flush\""),
        "the emit spans ride the timeline: {timeline}"
    );
    let parsed = parse_trace_json(&timeline).expect("the timeline parses");
    assert_eq!(parsed.spans.len(), 9, "one span per phase, nine per run");
    let emit_span = parsed
        .spans
        .iter()
        .find(|s| s.phase == Phase::Emit)
        .expect("the emit span restores");
    assert_eq!(
        emit_span.detail,
        PhaseDetail::Emitted {
            tiles: 256,
            bytes: 4_194_304,
        },
        "the emitted detail restores exactly"
    );
    let flush_span = parsed
        .spans
        .iter()
        .find(|s| s.phase == Phase::Flush)
        .expect("the flush span restores");
    assert_eq!(
        flush_span.detail,
        PhaseDetail::Flushed {
            blocks: 1,
            writers: 1,
        },
        "the flushed detail restores exactly"
    );
}

//! M78 — the timeline's write-pool lanes: the M64 registry named every
//! worker lane `pgr parse pool N` because the parse pool (M63) was the
//! only pool the task seam carried — and the M78 rung extends the seam to
//! Pass 5's writer pool (the flush workers the §5 pipeline runs), so the
//! registry's single label stopped being the truth: a viewer reading the
//! §9.4 timeline could not tell the parse workers from the write workers.
//! The naming rule follows the pool the task came from now: a parse task's
//! lane rides `pgr parse pool N`, a flush task's lane rides `pgr write
//! pool N` — each family numbered 1-based in registration order among its
//! own workers, the pipeline's thread `pgr link` beside them.
//!
//! Gate matrix:
//! * the naming rule — parse tasks name their lanes the parse pool's,
//!   flush tasks the write pool's, each family's numbering independent
//!   (registration order among the family's lanes), the pipeline lane
//!   `pgr link` beside them;
//! * the render + round trip — a mixed report (both pools beside the
//!   pipeline's spans) renders the per-lane labels and the strict reader
//!   restores them exactly (the M64 convention, gated on the mixed shape);
//! * the pure-task feeds — a feed with no phase events names every lane
//!   by its own task's family (the M64 rule, family-aware now): all-parse
//!   feeds keep the M64 shape, all-flush feeds name every lane a write
//!   worker;
//! * the serial flush task — a small write's task on the calling thread
//!   rides the pipeline lane, never a worker lane.

use std::thread::ThreadId;
use std::time::Duration;

use pgr_core::observe::{LinkObserver, Phase, PhaseDetail, PhaseEvent, TaskEvent};
use pgr_core::trace::{TraceCollector, parse_trace_json};

/// A synthetic phase event (the m58 gate's `row` shape).
fn row(phase: Phase, us: u64) -> PhaseEvent {
    PhaseEvent {
        phase,
        detail: PhaseDetail::Flushed {
            blocks: 5,
            writers: 4,
        },
        elapsed: Duration::from_micros(us),
    }
}

/// A synthetic task event: the caller names the phase, the thread and the
/// arrival clock so the lane registry and the µs bounds are the test's own.
fn task(phase: Phase, label: &str, us: u64, thread: ThreadId) -> TaskEvent {
    TaskEvent {
        phase,
        label: label.to_string(),
        elapsed: Duration::from_micros(us),
        at: std::time::Instant::now(),
        thread,
    }
}

/// `count` distinct thread ids from real threads (the registry's keys are
/// `ThreadId`s — the workers' own, synthesized here).
fn worker_ids(count: usize) -> Vec<ThreadId> {
    (0..count)
        .map(|_| {
            std::thread::spawn(|| std::thread::current().id())
                .join()
                .expect("the worker joins")
        })
        .collect()
}

fn lane_named(lanes: &[pgr_core::trace::TraceLane], name: &str) -> bool {
    lanes.iter().any(|l| l.name == name)
}

#[test]
fn the_naming_rule_names_each_pool_its_own_lanes() {
    let workers = worker_ids(4);
    let (p1, p2, w1, w2) = (workers[0], workers[1], workers[2], workers[3]);
    let main = std::thread::current().id();

    let mut c = TraceCollector::new();
    c.on_phase(row(Phase::Parse, 10));
    c.on_phase(row(Phase::Layout, 10));
    c.on_phase(row(Phase::Flush, 10));
    // The parse pool's workers (registration order p1, then p2).
    c.on_task(task(Phase::Parse, "a.o", 3, p1));
    c.on_task(task(Phase::Parse, "b.o", 3, p2));
    // The write pool's workers (registration order w1, then w2).
    c.on_task(task(Phase::Flush, "blocks 1,5 of 5", 2, w1));
    c.on_task(task(Phase::Flush, "blocks 2,3,4 of 5", 2, w2));

    let report = c.finish();
    assert_eq!(report.lanes.len(), 5, "one lane per distinct thread");
    assert!(lane_named(&report.lanes, "pgr link"), "the pipeline lane");
    assert!(lane_named(&report.lanes, "pgr parse pool 1"));
    assert!(lane_named(&report.lanes, "pgr parse pool 2"));
    assert!(lane_named(&report.lanes, "pgr write pool 1"));
    assert!(lane_named(&report.lanes, "pgr write pool 2"));
    // The lane each task landed on: the worker's own (the registry keys
    // on the event's thread — the M63 shape, family-aware now).
    let parse_lanes: Vec<u64> = report
        .tasks
        .iter()
        .filter(|t| t.phase == Phase::Parse)
        .map(|t| t.lane)
        .collect();
    let write_lanes: Vec<u64> = report
        .tasks
        .iter()
        .filter(|t| t.phase == Phase::Flush)
        .map(|t| t.lane)
        .collect();
    assert_eq!(parse_lanes.len(), 2);
    assert_eq!(write_lanes.len(), 2);
    assert!(
        parse_lanes
            .iter()
            .all(|l| write_lanes.iter().all(|w| l != w)),
        "the families ride disjoint lanes"
    );
    let _ = main;
}

#[test]
fn the_mixed_report_round_trips_through_the_reader() {
    let workers = worker_ids(2);
    let (p1, w1) = (workers[0], workers[1]);

    let mut c = TraceCollector::new();
    c.on_phase(row(Phase::Parse, 10));
    c.on_phase(row(Phase::Flush, 10));
    c.on_task(task(Phase::Parse, "obj_00.o", 3, p1));
    c.on_task(task(Phase::Flush, "blocks 1 of 2", 2, w1));
    c.on_task(task(Phase::Flush, "blocks 2 of 2", 2, w1));

    let rendered = c.finish().render();
    let restored = parse_trace_json(&rendered).expect("the mixed report restores");
    assert!(
        lane_named(&restored.lanes, "pgr write pool 1"),
        "the reader restores the write pool's label"
    );
    assert!(
        lane_named(&restored.lanes, "pgr parse pool 1"),
        "the reader restores the parse pool's label"
    );
    let flush_tasks = restored
        .tasks
        .iter()
        .filter(|t| t.phase == Phase::Flush)
        .count();
    assert_eq!(flush_tasks, 2, "the flush tasks ride the round trip");
    // Two lanes, one worker each, beside the pipeline lane.
    assert_eq!(restored.lanes.len(), 3);
}

#[test]
fn the_pure_flush_feed_names_every_lane_a_write_worker() {
    let workers = worker_ids(2);
    let mut c = TraceCollector::new();
    // No phase events: the M64 rule names every lane a worker lane — by
    // its own task's family now.
    c.on_task(task(Phase::Flush, "blocks 1 of 2", 2, workers[0]));
    c.on_task(task(Phase::Flush, "blocks 2 of 2", 2, workers[1]));
    let report = c.finish();
    assert_eq!(report.lanes.len(), 2);
    assert!(
        report
            .lanes
            .iter()
            .all(|l| l.name.starts_with("pgr write pool ")),
        "every lane is a write worker's: {:?}",
        report.lanes
    );
    assert!(lane_named(&report.lanes, "pgr write pool 1"));
    assert!(lane_named(&report.lanes, "pgr write pool 2"));
}

#[test]
fn the_pure_parse_feed_keeps_the_m64_shape() {
    let workers = worker_ids(2);
    let mut c = TraceCollector::new();
    c.on_task(task(Phase::Parse, "a.o", 3, workers[0]));
    c.on_task(task(Phase::Parse, "b.o", 3, workers[1]));
    let report = c.finish();
    assert!(
        lane_named(&report.lanes, "pgr parse pool 1")
            && lane_named(&report.lanes, "pgr parse pool 2"),
        "the M64 parse naming holds"
    );
}

#[test]
fn the_serial_flush_task_rides_the_pipeline_lane() {
    let mut c = TraceCollector::new();
    // The pipeline's phases arrive on the calling thread (the M54 shape).
    c.on_phase(row(Phase::Layout, 10));
    // The small write's task: the calling thread (the M64 serial rule).
    c.on_task(task(
        Phase::Flush,
        "blocks 1 of 1",
        2,
        std::thread::current().id(),
    ));
    let report = c.finish();
    assert_eq!(report.lanes.len(), 1, "one lane: the pipeline's");
    assert_eq!(report.lanes[0].name, "pgr link");
    assert_eq!(report.tasks[0].lane, report.lanes[0].id);
}

//! M63 — the parse pool's worker-lane task spans: the roadmap §9.4
//! toolbox's "per thread, so stragglers and idle gaps are visible" names
//! the lanes the M61 timeline renders — and the M61 module doc names the
//! future seam: "a future seam that reports worker-lane spans rides the
//! same shape with more lanes". This gate binds that seam: the parse
//! pool's per-input parses ride the M54 observation seam as
//! [`TaskEvent`]s (a new default-no-op `LinkObserver` method, the same
//! inert-until-subscriber convention), each carrying the thread that ran
//! it and its own arrival clock, and the [`TraceCollector`] keeps them
//! as timeline spans on the arrival threads' own lanes — the worker
//! lanes the §9.4 face is for. The seam stays read-only: an observed
//! link plans the identical image the unobserved one does (the parity
//! gate, the M54 contract).
//!
//! Gate matrix:
//! * the collector — synthetic task events from distinct threads land as
//!   spans on the threads' own lanes (the registry keys on the event's
//!   thread, never the collector's caller), each carrying the task's
//!   phase, its label and its µs bounds (the start is the event's own
//!   arrival clock minus its wall — the same reconstruction the phase
//!   spans ride);
//! * the serial parse — `Parallelism::Serial` reports one task per
//!   input, command-line order, phase `Parse`, on the calling lane;
//! * the pool parse — `Parallelism::Auto` reports one task per input
//!   (labels cover every input, order-free — the pool interleaves);
//! * the parity — an observed-with-tasks link plans the identical image
//!   the unobserved one does;
//! * the relocatable shape — the `-r` parse reports its own tasks;
//! * the render — the task rows ride the complete-event shape with the
//!   task args (`{"kind":"task","name":…}`), and the strict reader
//!   restores the writer's data exactly (the round-trip convention,
//!   gated) — a task row naming a lane no `thread_name` declared, a
//!   task row without its label, a task row with a stray count key and
//!   a task row naming an unknown phase all refuse with the position or
//!   field named;
//! * the composition — [`ObserverPair`] forwards the one task stream to
//!   two collectors (the `--time` + `--trace` shape) and the tracing
//!   bridge rides the house convention (inert until a subscriber
//!   installs).

use std::thread::ThreadId;
use std::time::Duration;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism, link_cached, link_observed, link_reloc_observed};
use pgr_core::observe::{LinkObserver, ObserverPair, Phase, PhaseDetail, PhaseEvent, TaskEvent};
use pgr_core::trace::{TraceCollector, TraceJsonError, parse_trace_json};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// A synthetic phase event (the m58 gate's `row` shape).
fn row(phase: Phase, detail: PhaseDetail, us: u64) -> PhaseEvent {
    PhaseEvent {
        phase,
        detail,
        elapsed: Duration::from_micros(us),
    }
}

/// A synthetic task event: the caller names the thread and the arrival
/// clock so the lane registry and the µs bounds are the test's own.
fn task(label: &str, us: u64, at_delta_us: u64, thread: ThreadId) -> TaskEvent {
    TaskEvent {
        phase: Phase::Parse,
        label: label.to_string(),
        elapsed: Duration::from_micros(us),
        at: std::time::Instant::now() + Duration::from_micros(at_delta_us),
        thread,
    }
}

/// One object: a two-instruction `__text` and one definition (the m54
/// corpus shape; `_main` on the first, `_fn_<i>` elsewhere).
fn object(i: usize) -> Vec<u8> {
    let mut b = ObjectBuilder::new(&format!("obj_{i:02}.o")).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: if i == 0 {
            "_main".to_string()
        } else {
            format!("_fn_{i:02}")
        },
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// `count` small objects (the first carries `_main`).
fn corpus(count: usize) -> Vec<LinkInput> {
    (0..count)
        .map(|i| LinkInput {
            name: format!("obj_{i:02}.o"),
            bytes: object(i),
        })
        .collect()
}

/// The test's assertion face: every event in arrival order (the m54
/// recorder shape, the tasks joined).
#[derive(Debug, Default)]
struct Recorder {
    phases: Vec<PhaseEvent>,
    tasks: Vec<TaskEvent>,
}

impl LinkObserver for Recorder {
    fn on_phase(&mut self, event: PhaseEvent) {
        self.phases.push(event);
    }

    fn on_task(&mut self, task: TaskEvent) {
        self.tasks.push(task);
    }
}

// ---- the collector -----------------------------------------------------------

#[test]
fn the_collector_keeps_the_tasks_on_the_threads_own_lanes() {
    let worker = std::thread::spawn(|| std::thread::current().id())
        .join()
        .expect("joins");
    let mut c = TraceCollector::new();
    c.on_phase(row(Phase::Parse, PhaseDetail::Objects { inputs: 2 }, 120));
    c.on_task(task("obj_00.o", 40, 1_000, worker));
    c.on_task(task("obj_01.o", 60, 2_000, std::thread::current().id()));
    let report = c.finish();
    assert_eq!(report.spans.len(), 1, "the phase span rides");
    assert_eq!(report.tasks.len(), 2, "the task spans ride");
    assert_eq!(
        report.lanes.len(),
        2,
        "two lanes: the pipeline thread and the worker the registry keyed"
    );
    // The tasks stay in arrival order, each carrying its label and its
    // phase; the bounds ride the event's own clock minus its wall.
    let first = &report.tasks[0];
    assert_eq!(first.label, "obj_00.o");
    assert_eq!(first.phase, Phase::Parse);
    assert_eq!(first.dur_us, 40);
    assert!(first.start_us > 0, "the event's own clock starts the span");
    let second = &report.tasks[1];
    assert_eq!(second.label, "obj_01.o");
    assert_eq!(second.dur_us, 60);
    assert!(
        second.start_us > first.start_us,
        "the later arrival starts later (µs granularity)"
    );
    // The lanes key on the event's thread, not the collector's caller:
    // the pipeline lane hosts the phase span, the worker lane hosts the
    // task that named it.
    let phase_lane = report.spans[0].lane;
    assert_ne!(first.lane, phase_lane, "the worker task rides its own lane");
    assert_eq!(
        second.lane, phase_lane,
        "the same-thread task rides the pipeline lane"
    );
}

#[test]
fn the_task_start_saturates_at_the_axis_floor() {
    // A wall longer than the time between the collector's epoch and the
    // event's arrival clamps at the axis's zero (the phase spans'
    // saturating shape — never a negative timestamp): a ten-second wall
    // predates the collector's construction from any arrival.
    let mut c = TraceCollector::new();
    c.on_task(task("obj_00.o", 10_000_000, 0, std::thread::current().id()));
    let report = c.finish();
    let t = &report.tasks[0];
    assert_eq!(t.start_us, 0, "the saturating floor");
    assert_eq!(t.dur_us, 10_000_000);
}

// ---- the pipeline ------------------------------------------------------------

#[test]
fn the_serial_parse_reports_one_task_per_input() {
    let inputs = corpus(3);
    let mut rec = Recorder::default();
    link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Serial,
        None,
        &mut rec,
    )
    .expect("the corpus links");
    assert_eq!(
        rec.tasks.len(),
        3,
        "one task per input (a cached parse is still a parse the consumer waited on)"
    );
    let labels: Vec<&str> = rec.tasks.iter().map(|t| t.label.as_str()).collect();
    assert_eq!(
        labels,
        vec!["obj_00.o", "obj_01.o", "obj_02.o"],
        "the serial path reports in command-line order"
    );
    assert!(
        rec.tasks.iter().all(|t| t.phase == Phase::Parse),
        "the tasks ride the parse phase"
    );
    // The tasks land inside the parse phase: they report before the
    // phase's own completion event.
    assert_eq!(rec.phases[0].phase, Phase::Parse);
    assert_eq!(
        rec.phases.len(),
        7,
        "the segmented run's phases ride untouched (the m54 sequence)"
    );
}

#[test]
fn the_pool_parse_reports_one_task_per_input() {
    let inputs = corpus(8);
    let mut rec = Recorder::default();
    link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut rec,
    )
    .expect("the corpus links");
    assert_eq!(
        rec.tasks.len(),
        8,
        "one task per input, order-free (the pool interleaves)"
    );
    let mut labels: Vec<&str> = rec.tasks.iter().map(|t| t.label.as_str()).collect();
    labels.sort_unstable();
    let mut expected: Vec<String> = (0..8).map(|i| format!("obj_{i:02}.o")).collect();
    expected.sort();
    assert_eq!(labels, expected, "the labels name every input exactly once");
    assert!(
        rec.tasks.iter().all(|t| t.phase == Phase::Parse),
        "the tasks ride the parse phase"
    );
}

#[test]
fn the_observed_with_tasks_link_plans_the_identical_image() {
    let inputs = corpus(8);
    let unobserved = link_cached(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
    )
    .expect("the corpus links");
    let mut rec = Recorder::default();
    let observed = link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut rec,
    )
    .expect("the corpus links");
    assert_eq!(
        unobserved.layout.file_size, observed.layout.file_size,
        "the parity gate: the task seam never moves a byte (the size)"
    );
    assert_eq!(
        unobserved.layout.segments.len(),
        observed.layout.segments.len(),
        "the observed plan carries the same segment set"
    );
    assert!(!rec.tasks.is_empty(), "the tasks rode the observed link");
}

#[test]
fn the_reloc_parse_reports_its_own_tasks() {
    let inputs = corpus(3);
    let mut rec = Recorder::default();
    link_reloc_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Serial,
        &mut rec,
    )
    .expect("the reloc link runs");
    assert_eq!(rec.tasks.len(), 3, "one task per input");
    assert!(
        rec.tasks.iter().all(|t| t.phase == Phase::Parse),
        "the tasks ride the parse phase"
    );
}

#[test]
fn the_tasks_ride_the_timeline_order_when_the_drain_reorders() {
    // The pool's drain interleaves the workers' records: a worker whose
    // span starts later can drain after a worker whose span starts
    // earlier (the first arrival below carries the later ts). The
    // report's tasks ride the timeline's canonical ts order (stable on
    // the ties) so the render's document and the reader's restore agree
    // — the round-trip convention the example's own gate caught.
    let mut c = TraceCollector::new();
    c.on_task(task("obj_01.o", 60, 2_000, std::thread::current().id()));
    c.on_task(task("obj_00.o", 40, 1_000, std::thread::current().id()));
    let report = c.finish();
    let labels: Vec<&str> = report.tasks.iter().map(|t| t.label.as_str()).collect();
    assert_eq!(
        labels,
        vec!["obj_00.o", "obj_01.o"],
        "the tasks ride the ts order, not the drain order"
    );
    let json = report.render();
    let parsed = parse_trace_json(&json).expect("the rendered trace parses");
    assert_eq!(
        parsed, report,
        "the round trip holds on the reordered drain"
    );
}

// ---- the render and the reader -------------------------------------------------

#[test]
fn the_render_names_the_task_rows_and_round_trips() {
    let worker = std::thread::spawn(|| std::thread::current().id())
        .join()
        .expect("joins");
    let mut c = TraceCollector::new();
    c.on_task(task("obj_00.o", 40, 1_000, worker));
    c.on_task(task("obj_01.o", 60, 2_000, std::thread::current().id()));
    c.on_phase(row(Phase::Parse, PhaseDetail::Objects { inputs: 2 }, 120));
    c.on_phase(row(
        Phase::Layout,
        PhaseDetail::Planned {
            segments: 3,
            sections: 2,
        },
        45,
    ));
    let report = c.finish();
    let json = report.render();
    assert!(!json.contains('\n'), "one line (the house interchange)");
    assert!(
        json.contains("\"args\":{\"kind\":\"task\",\"name\":\"obj_00.o\"}"),
        "the task args ride the kind/name pair: {json}"
    );
    assert!(json.contains("\"ph\":\"X\""), "the complete-event shape");
    let parsed = parse_trace_json(&json).expect("the rendered trace parses");
    assert_eq!(parsed, report, "the reader restores the writer's data");
    assert_eq!(parsed.tasks.len(), 2, "the task spans restore");
    assert_eq!(parsed.tasks[0].label, "obj_00.o");
    assert_eq!(parsed.render(), json, "the re-render is byte-identical");
}

#[test]
fn the_reader_refuses_the_broken_task_shapes() {
    let metadata = "{ \"ph\" : \"M\" , \"name\" : \"process_name\" , \"pid\" : 1 , \
        \"args\" : { \"name\" : \"pgr\" } } , \
        { \"ph\" : \"M\" , \"name\" : \"thread_name\" , \"pid\" : 1 , \"tid\" : 2 , \
        \"args\" : { \"name\" : \"pgr link\" } }";
    let task_row = |args: &str| {
        format!(
            "{{\"traceEvents\":[{metadata},{{\"cat\":\"pgr\",\"ph\":\"X\",\"name\":\"parse\",\
             \"ts\":5,\"dur\":7,\"pid\":1,\"tid\":2,\"args\":{args}}}]}}"
        )
    };
    // A task row without its label.
    let missing = parse_trace_json(&task_row("{\"kind\":\"task\"}"));
    assert!(
        matches!(&missing, Err(TraceJsonError::Field { name, .. }) if name == "name"),
        "the label is required: {missing:?}"
    );
    // A task row with a stray count key (the detail keys ride the phase
    // detail alone).
    let stray = parse_trace_json(&task_row(
        "{\"kind\":\"task\",\"name\":\"obj_00.o\",\"inputs\":3}",
    ));
    assert!(
        stray.is_err(),
        "the count keys refuse beside a task: {stray:?}"
    );
    // A task row naming an unknown phase.
    let unknown = parse_trace_json(
        &task_row("{\"kind\":\"task\",\"name\":\"x\"}")
            .replace("\"name\":\"parse\"", "\"name\":\"nope\""),
    );
    assert!(
        matches!(&unknown, Err(TraceJsonError::Field { name, .. }) if name == "name"),
        "the task's phase token is the seam's name set: {unknown:?}"
    );
    // A task row naming a lane no thread_name declared.
    let laneless = format!(
        "{{\"traceEvents\":[{metadata},{{\"cat\":\"pgr\",\"ph\":\"X\",\"name\":\"parse\",\
         \"ts\":5,\"dur\":7,\"pid\":1,\"tid\":9,\"args\":{{\"kind\":\"task\",\"name\":\"obj_00.o\"}}}}]}}"
    );
    let refused = parse_trace_json(&laneless);
    assert!(
        matches!(&refused, Err(TraceJsonError::Field { name, .. }) if name == "tid"),
        "the lane registry gates the task rows too: {refused:?}"
    );
}

// ---- the composition -----------------------------------------------------------

#[test]
fn the_observer_pair_forwards_the_tasks() {
    let mut a = TraceCollector::new();
    let mut b = TraceCollector::new();
    {
        let mut pair = ObserverPair::new(&mut a, &mut b);
        pair.on_task(task("obj_00.o", 40, 1_000, std::thread::current().id()));
    }
    assert_eq!(a.finish().tasks.len(), 1, "the first face rides");
    assert_eq!(b.finish().tasks.len(), 1, "the second face rides");
}

#[test]
fn the_tracing_bridge_rides_the_tasks_inert() {
    // No subscriber installed: the bridge's debug event is inert (the
    // house convention) — the call neither panics nor formats.
    let mut bridge = pgr_core::observe::TracingObserver;
    bridge.on_task(task("obj_00.o", 40, 1_000, std::thread::current().id()));
}

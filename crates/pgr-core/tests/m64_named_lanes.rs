//! M64 — the lane registry's names: the M63 worker lanes made the
//! timeline multi-lane, and every `thread_name` metadata row still
//! carried the one hard-coded `pgr link` label — a viewer could not tell
//! the pipeline's lane from the pool's workers, and the §9.4 toolbox
//! reads the timeline by its lane names. This gate binds the naming: the
//! collector's registry carries each lane's own label — `pgr link` for
//! the pipeline's thread (the first phase/note arrival; a serial-path
//! task on the calling thread is the same lane, not a worker), `pgr
//! parse pool N` (1-based, registration order among the worker lanes)
//! for the pool workers — and the data model is honest about it:
//! [`TraceReport`]'s `lanes` are [`TraceLane`]s (`id`, `name`), the
//! render writes each lane's own label, and the strict reader restores
//! the labels exactly (the round-trip convention, gated).
//!
//! Gate matrix:
//! * the names — a phase event on the calling thread plus task events
//!   from two workers name the registry `pgr link`, `pgr parse pool 1`,
//!   `pgr parse pool 2` (worker ordinals by registration order; the ids
//!   stay the first-arrival registry's);
//! * the serial task — a task on the pipeline's own thread rides the
//!   `pgr link` lane (no worker name for same-thread work);
//! * the pure task feed — no phase event ever arrives, every lane is a
//!   worker lane;
//! * the pool pipeline — one `pgr link` lane and the rest `pgr parse
//!   pool N` (the shape the `trace_tasks` example prints);
//! * the render — the `thread_name` rows carry each lane's own label and
//!   the reader restores them (a multi-lane report round-trips exactly,
//!   re-render byte-identical);
//! * the refusals — an empty lane name and a duplicate `thread_name`
//!   row refuse with the field named (the registry's own gates).

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism, link_observed};
use pgr_core::observe::{LinkObserver, Phase, PhaseDetail, PhaseEvent, TaskEvent};
use pgr_core::trace::{TraceCollector, TraceJsonError, TraceLane, parse_trace_json};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// A synthetic phase event (the m63 gate's `row` shape).
fn row(phase: Phase, detail: PhaseDetail, us: u64) -> PhaseEvent {
    PhaseEvent {
        phase,
        detail,
        elapsed: std::time::Duration::from_micros(us),
    }
}

/// A synthetic task event on the given thread (the m63 gate's `task`
/// shape).
fn task(label: &str, us: u64, at_delta_us: u64, thread: std::thread::ThreadId) -> TaskEvent {
    TaskEvent {
        phase: Phase::Parse,
        label: label.to_string(),
        elapsed: std::time::Duration::from_micros(us),
        at: std::time::Instant::now() + std::time::Duration::from_micros(at_delta_us),
        thread,
    }
}

/// One object: a two-instruction `__text` and one definition (the m63
/// corpus shape).
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

// ---- the names -----------------------------------------------------------------

#[test]
fn the_registry_names_the_pipeline_lane_and_the_workers() {
    let worker_a = std::thread::spawn(|| std::thread::current().id())
        .join()
        .expect("joins");
    let worker_b = std::thread::spawn(|| std::thread::current().id())
        .join()
        .expect("joins");
    let mut c = TraceCollector::new();
    c.on_phase(row(Phase::Parse, PhaseDetail::Objects { inputs: 2 }, 120));
    c.on_task(task("obj_00.o", 40, 1_000, worker_a));
    c.on_task(task("obj_01.o", 40, 2_000, worker_b));
    let report = c.finish();
    assert_eq!(
        report.lanes,
        vec![
            TraceLane {
                id: 1,
                name: "pgr link".to_string(),
            },
            TraceLane {
                id: 2,
                name: "pgr parse pool 1".to_string(),
            },
            TraceLane {
                id: 3,
                name: "pgr parse pool 2".to_string(),
            },
        ],
        "the pipeline lane keeps its name, the workers number by registration"
    );
}

#[test]
fn the_serial_task_rides_the_pipeline_lane() {
    // A task on the pipeline's own thread is the same lane — no worker
    // name for same-thread work (the serial path's shape).
    let mut c = TraceCollector::new();
    c.on_task(task("obj_00.o", 40, 1_000, std::thread::current().id()));
    c.on_phase(row(Phase::Parse, PhaseDetail::Objects { inputs: 1 }, 120));
    let report = c.finish();
    assert_eq!(
        report.lanes,
        vec![TraceLane {
            id: 1,
            name: "pgr link".to_string(),
        }],
        "one lane, the pipeline's own"
    );
}

#[test]
fn the_pure_task_feed_names_every_lane_a_worker() {
    // No phase event ever arrives (a task-only consumer): the collector
    // has no pipeline thread to name, so every lane is a worker lane.
    let worker = std::thread::spawn(|| std::thread::current().id())
        .join()
        .expect("joins");
    let mut c = TraceCollector::new();
    c.on_task(task("obj_00.o", 40, 1_000, std::thread::current().id()));
    c.on_task(task("obj_01.o", 40, 2_000, worker));
    let report = c.finish();
    let names: Vec<&str> = report.lanes.iter().map(|l| l.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["pgr parse pool 1", "pgr parse pool 2"],
        "no pipeline thread, no `pgr link` lane"
    );
}

#[test]
fn the_pool_pipeline_names_one_pipeline_lane_and_the_workers() {
    let inputs = corpus(8);
    let mut c = TraceCollector::new();
    link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut c,
    )
    .expect("the corpus links");
    let report = c.finish();
    let pipeline = report.lanes.iter().filter(|l| l.name == "pgr link").count();
    assert_eq!(pipeline, 1, "exactly one pipeline lane");
    assert!(
        report
            .lanes
            .iter()
            .all(|l| l.name == "pgr link" || l.name.starts_with("pgr parse pool ")),
        "every lane carries the naming scheme: {:?}",
        report.lanes
    );
}

// ---- the render and the reader ---------------------------------------------------

#[test]
fn the_render_writes_each_lanes_own_name_and_round_trips() {
    let worker = std::thread::spawn(|| std::thread::current().id())
        .join()
        .expect("joins");
    let mut c = TraceCollector::new();
    c.on_phase(row(Phase::Parse, PhaseDetail::Objects { inputs: 2 }, 120));
    c.on_task(task("obj_00.o", 40, 1_000, worker));
    let report = c.finish();
    let json = report.render();
    assert!(
        json.contains("\"name\":\"thread_name\",\"ph\":\"M\",\"pid\":1,\"tid\":1,\"args\":{\"name\":\"pgr link\"}"),
        "the pipeline lane's own label: {json}"
    );
    assert!(
        json.contains("\"tid\":2,\"args\":{\"name\":\"pgr parse pool 1\"}"),
        "the worker lane's own label: {json}"
    );
    let parsed = parse_trace_json(&json).expect("the rendered trace parses");
    assert_eq!(parsed, report, "the reader restores the writer's data");
    assert_eq!(parsed.render(), json, "the re-render is byte-identical");
}

#[test]
fn the_reader_accepts_any_conforming_lane_labels() {
    // The reader restores the document's labels (a foreign writer may
    // name its lanes its own way); the registry's gates stay.
    let loose = " { \"traceEvents\" : [ \
        { \"ph\" : \"M\" , \"name\" : \"process_name\" , \"pid\" : 1 , \
          \"args\" : { \"name\" : \"pgr\" } } , \
        { \"ph\" : \"M\" , \"name\" : \"thread_name\" , \"pid\" : 1 , \"tid\" : 7 , \
          \"args\" : { \"name\" : \"worker seven\" } } ] } ";
    let parsed = parse_trace_json(loose).expect("the loose shape parses");
    assert_eq!(
        parsed.lanes,
        vec![TraceLane {
            id: 7,
            name: "worker seven".to_string(),
        }],
        "the label restores verbatim"
    );
}

#[test]
fn the_reader_refuses_the_broken_lane_names() {
    let base = |tid_args: &str| {
        format!(
            "{{\"traceEvents\":[{{\"ph\":\"M\",\"name\":\"process_name\",\"pid\":1,\
             \"args\":{{\"name\":\"pgr\"}}}},{{\"ph\":\"M\",\"name\":\"thread_name\",\
             \"pid\":1,{tid_args}}}]}}"
        )
    };
    // An empty lane name.
    let empty = parse_trace_json(&base("\"tid\":2,\"args\":{\"name\":\"\"}"));
    assert!(
        matches!(&empty, Err(TraceJsonError::Field { name, .. }) if name == "args"),
        "the lane name is required: {empty:?}"
    );
    // A duplicate thread_name row.
    let dup = parse_trace_json(
        "{\"traceEvents\":[{\"ph\":\"M\",\"name\":\"process_name\",\"pid\":1,\
         \"args\":{\"name\":\"pgr\"}},\
         {\"ph\":\"M\",\"name\":\"thread_name\",\"pid\":1,\"tid\":2,\"args\":{\"name\":\"pgr link\"}},\
         {\"ph\":\"M\",\"name\":\"thread_name\",\"pid\":1,\"tid\":2,\"args\":{\"name\":\"pgr link\"}}]}",
    );
    assert!(
        matches!(&dup, Err(TraceJsonError::Field { name, .. }) if name == "tid"),
        "one thread_name row per lane: {dup:?}"
    );
}

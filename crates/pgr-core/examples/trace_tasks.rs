//! The M63 worker-lane task spans, runnable: a twelve-object link whose
//! parse pool reports each input's parse through the observation seam as
//! a [`TaskEvent`] — the event carries the thread that ran it and its own
//! arrival clock, so the [`TraceCollector`] keeps one timeline lane per
//! worker and the rendered file shows which worker parsed which object,
//! and where the idle gaps fell (the §9.4 toolbox's per-thread face). The
//! phase spans still name the phases; the task spans ride the workers'
//! lanes beside them.
//!
//! Set `PGR_TRACING=1` to also install a subscriber and watch the house
//! spans (the convention — the subscriber makes the spans visible, it
//! never changes the plan). The written `trace-tasks.json` opens in
//! `chrome://tracing` or the Perfetto UI, and the strict reader
//! (`pgr_core::trace::parse_trace_json`) restores the writer's data
//! exactly — the round-trip gate runs right here.
//!
//! ```sh
//! cargo run -p pgr-core --example trace_tasks
//! ```

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism, link_observed};
use pgr_core::trace::{TraceCollector, parse_trace_json};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// Twelve objects with varied `__text` sizes (the LPT schedule spreads
/// the parse across the pool's workers — the lane registry keys one lane
/// per worker).
fn corpus(count: usize) -> Vec<LinkInput> {
    (0..count)
        .map(|i| {
            let mut b =
                ObjectBuilder::new(&format!("obj_{i:02}.o")).set_subsections_via_symbols(true);
            let instrs = 4 + i * 8;
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(instrs),
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
            LinkInput {
                name: format!("obj_{i:02}.o"),
                bytes: b.build().expect("the fixture object builds"),
            }
        })
        .collect()
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let inputs = corpus(12);
    let mut collector = TraceCollector::new();
    let result = link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut collector,
    )
    .expect("the corpus links");

    let timeline = collector.finish();
    let json = timeline.render();
    let parsed = parse_trace_json(&json).expect("the timeline round-trips");
    assert_eq!(parsed, timeline, "the reader restored the writer's data");

    let path = std::env::temp_dir().join(format!("pgr_trace_tasks_{}.json", std::process::id()));
    std::fs::write(&path, &json).expect("the timeline writes");

    println!(
        "== the parse pool's worker lanes ({} bytes planned, {} lanes) ==",
        result.layout.file_size,
        parsed.lanes.len(),
    );
    // The lanes with their own names (M64): the pipeline's `pgr link`
    // lane and the pool's workers, each lane's task spans in arrival
    // order — the stragglers and idle gaps the timeline shows.
    for lane in &parsed.lanes {
        let tasks: Vec<&pgr_core::trace::TraceTask> =
            parsed.tasks.iter().filter(|t| t.lane == lane.id).collect();
        println!(
            "-- lane {} ({}): {} task span(s)",
            lane.id,
            lane.name,
            tasks.len()
        );
        for task in &tasks {
            println!(
                "    {:<12} ts={:>6} µs dur={:>6} µs",
                task.phase.as_str(),
                task.start_us,
                task.dur_us,
            );
        }
    }
    println!(
        "-- {} -- ({} bytes, opens in chrome://tracing or the Perfetto UI)",
        path.display(),
        json.len(),
    );
}

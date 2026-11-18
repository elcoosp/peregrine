//! The M78 write-pool lanes' consumer cycle, runnable: the flush pool's
//! writers report their own spans through the M63 task seam (one
//! [`pgr_core::observe::TaskEvent`] per writer — the blocks it carried,
//! its wall time, its thread and its own arrival clock), and the
//! [`pgr_core::trace::TraceCollector`] keeps them on the workers' own
//! lanes — `pgr write pool N` beside the pipeline's `pgr link` lane, the
//! §9.4 toolbox's per-thread face the write side never had. The demo
//! writes a multi-block image (33 MiB — five 8 MiB blocks, all four
//! writers busy), renders the timeline and round-trips it through the
//! strict reader (the interchange's own gate), then prints the lanes and
//! the write workers' spans.
//!
//! ```sh
//! cargo run -p pgr-emit --example write_lanes
//! ```

use std::path::PathBuf;
use std::time::Instant;

use pgr_core::trace::{TraceCollector, parse_trace_json};
use pgr_emit::write_image_observed;

fn main() {
    let dir = std::env::temp_dir().join("pgr_write_lanes_demo");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let path: PathBuf = dir.join("image.bin");
    // 33 MiB + 3 bytes: four full blocks plus a partial tail — five
    // blocks, so all four writers carry work and the pool's interleaving
    // is honest.
    let len = 33 * 1024 * 1024 + 3;
    let image: Vec<u8> = (0..len as u64).map(|i| (i % 251) as u8).collect();

    let mut collector = TraceCollector::new();
    let started = Instant::now();
    pgr_emit::write_image(&image, &path).expect("the unobserved write ships (the parity twin)");
    let plain = std::fs::read(&path).expect("the plain bytes read");
    write_image_observed(&image, &path, &mut collector).expect("the observed write ships");
    let observed = std::fs::read(&path).expect("the observed bytes read");
    assert_eq!(
        plain, observed,
        "the parity gate: observing never moves a byte"
    );
    println!(
        "write  {:>9} µs  5 blocks, 4 writers (parity gate passed)",
        started.elapsed().as_micros()
    );

    let report = collector.finish();
    let rendered = report.render();
    // The interchange's own gate: the strict reader restores the writer's
    // data exactly — the lanes and the task rows included.
    let restored = parse_trace_json(&rendered).expect("the timeline restores");
    assert_eq!(
        restored.lanes, report.lanes,
        "the lanes ride the round trip"
    );
    assert_eq!(restored.tasks.len(), report.tasks.len());

    println!("\nlanes:");
    for lane in &restored.lanes {
        let tasks = restored.tasks.iter().filter(|t| t.lane == lane.id).count();
        println!("  tid {:<2} {:<18} {tasks} task row(s)", lane.id, lane.name);
    }
    println!("\nthe write workers' spans:");
    for task in &restored.tasks {
        if task.phase.as_str() == "flush" {
            println!(
                "  {:<18} {:>6} µs  {}",
                format!("tid {}", task.lane),
                task.dur_us,
                task.label
            );
        }
    }
    println!(
        "\ntimeline: {} bytes, {} task rows — the write workers ride their own lanes",
        rendered.len(),
        restored.tasks.len()
    );
    std::fs::remove_dir_all(&dir).ok();
}

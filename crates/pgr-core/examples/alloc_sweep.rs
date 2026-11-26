//! The allocation lane, runnable: the §9.3 per-PR allocation-count job's
//! storage and comparison faces over one generated corpus — the counted
//! sweep recorded into the strict alloc ledger (`alloc_ledger_json`,
//! `write_alloc_ledger`, `parse_alloc_ledger`), the round-trip walk the
//! reader's own gate pins, and the nightly's "vs baselines" half (`AllocSweepDelta`)
//! rendered between two recorded lanes.
//!
//! A build system drives this seam when it wants the §9.3 allocation
//! counts *stored and compared* — the nightly's alloc lane writes one
//! ledger per shape (the wall lane's binary keeps the plain allocator:
//! the seat is process-global, the walls stay honest), and the next
//! nightly's delta reads the pairing.
//!
//! ```sh
//! cargo run -p pgr-core --example alloc_sweep
//! ```

/// The example's global allocator: the DHAT seat. The profiler below is
/// the recording window.
#[global_allocator]
static DHAT: dhat::Alloc = dhat::Alloc;

use pgr_core::alloc_count::{AllocSnapshot, AllocSource};
use pgr_core::layout::LinkConfig;
use pgr_core::link::Parallelism;
use pgr_core::sweep::{
    AllocSweepDelta, SweepPlan, alloc_ledger_json, parse_alloc_ledger, run_alloc_sweep,
};
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus};

/// The DHAT seat's bridge — the seat consumer's own glue (the library
/// never links DHAT; this file's bridge is the copy the walk owns).
struct DhatSource;

impl AllocSource for DhatSource {
    fn sample(&self) -> AllocSnapshot {
        let stats = dhat::HeapStats::get();
        AllocSnapshot {
            blocks: stats.total_blocks,
            bytes: stats.total_bytes,
        }
    }
}

fn main() {
    // The many-tiny preset, quartered for a runnable walk — the
    // parameters are the sweep's knobs.
    let spec = CorpusSpec {
        objects: Some(8),
        ..CorpusSpec::new(CorpusPreset::ManyTiny)
    };
    let contents = build_corpus(&spec).expect("the corpus builds");
    let inputs: Vec<pgr_core::link::LinkInput> = contents
        .files
        .iter()
        .map(|(name, bytes)| pgr_core::link::LinkInput {
            name: name.clone(),
            bytes: bytes.clone(),
        })
        .collect();
    let cfg = LinkConfig::default();
    let source = DhatSource;

    // The recording window: both lanes' runs ride the seat (the counts
    // are the process's own — the honesty the seat contract rides), the
    // `testing` mode keeping the filesystem and stderr silent (the
    // ledger lines are the walk's stored face).
    let profiler = dhat::Profiler::builder().testing().build();

    // The previous nightly's lane (fewer runs — the baseline the delta
    // compares against) and the current one's: two records of one
    // shape, the labels identical.
    let plan = SweepPlan {
        label: "alloc-sweep-walk".to_string(),
        runs: 3,
    };
    let previous = run_alloc_sweep(
        &inputs,
        &[],
        &cfg,
        Parallelism::Serial,
        &plan,
        &mut (),
        &source,
    )
    .expect("the previous lane sweeps");
    let current_plan = SweepPlan {
        label: "alloc-sweep-walk".to_string(),
        runs: 5,
    };
    let current = run_alloc_sweep(
        &inputs,
        &[],
        &cfg,
        Parallelism::Serial,
        &current_plan,
        &mut (),
        &source,
    )
    .expect("the current lane sweeps");

    // The stored faces: the deterministic JSON lines, the reader
    // restoring them exactly (the round-trip convention, gated).
    let previous_ledger = previous.ledger();
    let current_ledger = current.ledger();
    let previous_line = alloc_ledger_json(
        &previous_ledger.label,
        previous_ledger.runs,
        &previous_ledger.summary,
    );
    let current_line = alloc_ledger_json(
        &current_ledger.label,
        current_ledger.runs,
        &current_ledger.summary,
    );
    let restored_previous = parse_alloc_ledger(&previous_line).expect("the line restores");
    let restored_current = parse_alloc_ledger(&current_line).expect("the line restores");
    assert_eq!(restored_previous, previous_ledger, "the round-trip holds");
    assert_eq!(restored_current, current_ledger, "the round-trip holds");

    print!("{}", current.render());
    println!("{current_line}");

    // The comparison face: the current order leads, the counts' moves
    // in signed permille — the chart's input.
    let delta = AllocSweepDelta::between(&restored_previous, &restored_current)
        .expect("one shape's own history");
    print!("{}", delta.render());
    println!("{}", delta.render_json());

    drop(profiler);
}

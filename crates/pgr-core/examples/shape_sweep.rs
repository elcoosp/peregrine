//! The shape-sweep harness, runnable: a generated corpus swept through
//! the observed pipeline — the nightly shape sweep's core, driven here
//! at gate scale. The corpus the `pgr_fixtures::corpus` seam generates
//! (the §9.2 rows the presets name) sweeps through
//! [`pgr_core::sweep::run_sweep`], the runs reduce to the §9.3 face
//! (median and p95 over the recorded walls, one reduced row per phase),
//! the ledger renders as its deterministic text and interchange faces,
//! and the strict reader restores the written line (the round-trip
//! convention).
//!
//! A build system drives this seam when it wants the shape sweep *as
//! data* — the stored ledger line is the file the nightly job keeps and
//! the next nightly's baseline compares against.
//!
//! ```sh
//! cargo run -p pgr-core --example shape_sweep
//! ```

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism};
use pgr_core::sweep::{SweepDelta, SweepPlan, parse_ledger, run_sweep};
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus};

fn main() {
    // The many-tiny preset (the §9.2 "50-link many tiny links" row),
    // halved for a runnable walk — the parameters are the sweep's knobs.
    let spec = CorpusSpec {
        objects: Some(16),
        ..CorpusSpec::new(CorpusPreset::ManyTiny)
    };
    let contents = build_corpus(&spec).expect("the corpus builds");
    let inputs: Vec<LinkInput> = contents
        .files
        .iter()
        .map(|(name, bytes)| LinkInput {
            name: name.clone(),
            bytes: bytes.clone(),
        })
        .collect();
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };

    // The sweep: three recorded runs over the same corpus (the §9.3
    // nightly contract names ten; the example walks three for pace).
    let outcome = run_sweep(
        &inputs,
        &[],
        &cfg,
        Parallelism::Auto,
        &SweepPlan {
            label: "many-tiny-16".to_string(),
            runs: 3,
        },
    )
    .expect("the sweep sweeps");

    print!("{}", outcome.render());
    let json = outcome.render_json();
    println!("{json}");

    // The stored face restores exactly (the round-trip convention).
    let ledger = parse_ledger(&json).expect("the sweep's own ledger parses");
    assert_eq!(
        ledger.summary, outcome.summary,
        "the reader restores the writer"
    );
    println!(
        "ledger restored: {} runs, median {} µs, p95 {} µs",
        ledger.runs, ledger.summary.median_wall_us, ledger.summary.p95_wall_us
    );

    // The comparison face (§9.3 "vs baselines"): the same shape's
    // previous nightly beside this one's — here a second sweep standing
    // in for the next nightly.
    let next = run_sweep(
        &inputs,
        &[],
        &cfg,
        Parallelism::Auto,
        &SweepPlan {
            label: "many-tiny-16".to_string(),
            runs: 3,
        },
    )
    .expect("the second sweep sweeps");
    let delta = SweepDelta::between(&outcome.ledger(), &next.ledger())
        .expect("one shape's own history compares");
    print!("{}", delta.render());
}

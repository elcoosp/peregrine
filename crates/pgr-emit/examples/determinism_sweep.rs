//! The sweep's determinism gate, runnable: a generated corpus swept
//! through the observed pipeline with every run's image compared
//! byte-for-byte against the run-0 image — §9.3's determinism half
//! ("**Determinism:** double-link byte-equality on every PR (TDD
//! §4.3)") driven at gate scale, with TDD §11's separate-process face
//! walked beside it (the gate's recorded baseline written out — the
//! artifact two processes byte-compare). Each run's plan emits through
//! the fused tile path, the gate's stats name what it compared per run,
//! and a hand-diverged twin of the honest image walks the refusal face
//! (the gate bites, the first differing byte named).
//!
//! A build system drives this seam when it wants the nightly's
//! determinism contract *as data* — the `xtask sweep` command rides
//! this gate (and writes the baseline artifact under `--determinism`),
//! so a ledger line the nightly writes was earned by images that
//! double-linked byte-identically.
//!
//! ```sh
//! cargo run -p pgr-emit --example determinism_sweep
//! ```

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism};
use pgr_core::sweep::SweepPlan;
use pgr_emit::build_image_fused;
use pgr_emit::sweep::run_deterministic_sweep;
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus};

fn main() {
    // The many-tiny preset (the §9.2 "50-link many tiny links" row),
    // halved for a runnable walk — the parameters are the sweep's knobs.
    let spec = CorpusSpec {
        objects: Some(12),
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
    let plan = SweepPlan {
        label: "many-tiny-12".to_string(),
        runs: 3,
    };

    // The deterministic sweep: three runs, every image compared against
    // the run-0 image (the gate runs outside the measured wall — the
    // walls price the pipeline, the gate owns the bytes).
    let swept = run_deterministic_sweep(&inputs, &[], &cfg, Parallelism::Auto, &plan)
        .expect("the deterministic sweep sweeps");
    print!("{}", swept.outcome.render());
    let baseline_len = swept.gate.stats()[0].bytes;
    for stat in swept.gate.stats() {
        println!(
            "  run {}: byte-identical ({} bytes, gate {} µs)",
            stat.run,
            stat.bytes,
            stat.gate_wall.as_micros()
        );
    }
    // The separate-process artifact: the run-0 image is the gate's
    // baseline — the face a second process byte-compares (TDD §11:
    // "twice in separate processes → byte-identical"). A build system
    // writes it per process and diffs the files.
    let baseline = swept.gate.baseline_image().expect("the baseline rode");
    println!(
        "the run-0 baseline: {} bytes — write it per process and byte-compare the files",
        baseline.len()
    );

    // The refusal face: a hand-diverged twin of the honest image (the
    // §11 different-code-path rule — one flipped byte in the middle, a
    // shape the deterministic pipeline would never plan). The gate
    // names the run and the first differing byte.
    let result = pgr_core::link::link(&inputs, &[], &cfg).expect("the corpus links");
    let image = build_image_fused(&result.layout, &result.objects).expect("the honest image emits");
    let mut diverged = image.clone();
    let flip = image.len() / 2;
    diverged[flip] = diverged[flip].wrapping_add(1);
    let mut gate = pgr_emit::sweep::DeterminismGate::new();
    gate.compare_image(0, &image)
        .expect("the honest image records the baseline");
    let refusal = gate
        .compare_image(1, &diverged)
        .expect_err("the diverged image refuses");
    println!("the gate bites on the diverged twin:");
    println!("{refusal}");
    assert_eq!(
        baseline_len,
        swept.gate.stats()[0].bytes,
        "the baseline's size is the run-0 stat's"
    );
    assert_eq!(gate.stats().len(), 1, "the refused run recorded nothing");
}

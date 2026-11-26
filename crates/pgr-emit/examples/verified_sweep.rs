//! The sweep's verify gate, runnable: a generated corpus swept through
//! the observed pipeline with the strict verifier on every run's image
//! — the §9.3 correctness half ("every benchmark link is also run
//! through `pgr-verify`") driven at gate scale. Each run's plan emits
//! through the fused tile path, the bytes ride the strict pass, the
//! gate's stats name what the verifier read per run, and a hand-broken
//! twin of the honest image walks the refusal face (the gate bites).
//!
//! A build system drives this seam when it wants the nightly's
//! correctness contract *as data* — the `xtask sweep` command rides
//! this gate, so a ledger line the nightly writes was earned by images
//! the strict pass shipped.
//!
//! ```sh
//! cargo run -p pgr-emit --example verified_sweep
//! ```

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism};
use pgr_core::sweep::SweepPlan;
use pgr_emit::sweep::run_verified_sweep;
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus};
use pgr_verify::Options;

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
    let opts = Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let plan = SweepPlan {
        label: "many-tiny-12".to_string(),
        runs: 3,
    };

    // The verified sweep: three runs, every image gated (the strict
    // pass runs outside the measured wall — the walls price the
    // pipeline, the gate owns the product).
    let verified = run_verified_sweep(&inputs, &[], &cfg, Parallelism::Auto, &plan, &opts)
        .expect("the verified sweep sweeps");
    print!("{}", verified.outcome.render());
    println!(
        "verify gate: {} run(s) shipped",
        verified.gate.stats().len()
    );
    for stat in verified.gate.stats() {
        println!(
            "  run {}: strict-clean ({} symbols, {} fixup slots, {} hash pages, verify {} µs)",
            stat.run,
            stat.symbols,
            stat.fixup_slots,
            stat.hash_pages,
            stat.verify_wall.as_micros()
        );
    }

    // The refusal face: a hand-broken twin of the honest image (the §11
    // different-code-path rule — the gate's per-image face over a shape
    // the pipeline would never plan). The truncation breaks the
    // segment/`__LINKEDIT` contract, and the gate names the findings.
    let result = pgr_core::link::link(&inputs, &[], &cfg).expect("the corpus links");
    let image = pgr_emit::build_image_fused(&result.layout, &result.objects)
        .expect("the honest image emits");
    let mut broken = image.clone();
    broken.truncate(broken.len() / 2);
    let mut gate = pgr_emit::sweep::VerifyGate::new(opts);
    gate.verify_image(0, &image)
        .expect("the honest image ships");
    let refusal = gate
        .verify_image(1, &broken)
        .expect_err("the broken image refuses");
    println!("the gate bites on the broken twin:");
    println!("{refusal}");
    assert_eq!(gate.stats().len(), 1, "the refused run recorded nothing");
}

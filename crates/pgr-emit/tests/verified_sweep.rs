//! The sweep's verify gate (the `pgr_emit::sweep` seam over the
//! `pgr_core::sweep` run-gate seam).
//!
//! Plan fidelity: the performance architecture doc §9.3 — "**Correctness
//! stays first:** performance jobs never gate on unverified output —
//! every benchmark link is also run through `pgr-verify`." The sweep
//! seam (the §9.3 nightly contract's measurement core) recorded the
//! nightly's walls; this seam is the correctness half the same section
//! names: every swept run's image rides the strict verifier, and a
//! failing verdict aborts the sweep — the measurement never rides an
//! ungated image.
//!
//! Gate matrix:
//! * the gate rides every run — one strict pass per recorded run, the
//!   stats naming the run, the findings and the price (the verify wall
//!   is its own measurement, never a link-wall row);
//! * the gate bites — a hand-broken image (the §11 different-code-path
//!   rule) refuses with the report's own lines, the honest twin passes;
//! * the gate is outside the wall — a verified sweep's rows are the
//!   plain sweep's rows (the M54 parity contract: measuring and gating
//!   are read-only);
//! * the pass-through gate — the ungated sweep is the `()` gate's sweep
//!   (one shape, no decision copy);
//! * a gate refusal aborts the sweep with the run and the gate's own
//!   wording ([`pgr_core::sweep::SweepError::Gate`]);
//! * the archive-heavy shape rides (the pull's members verified beside
//!   the direct objects).

use std::time::Duration;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism};
use pgr_core::observe::{PhaseDetail, PhaseEvent};
use pgr_core::sweep::{SweepPlan, SweepRunGate, run_sweep, run_sweep_gated};
use pgr_emit::sweep::{VerifyGate, run_verified_sweep};
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus};

/// The strict pass's options — the M73 `-verify` gate's shape (warnings
/// fail, the signature hash recomputed).
fn strict() -> pgr_verify::Options {
    pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// The many-tiny corpus, halved for a runnable walk, projected onto the
/// sweep's inputs (no archive — the archive-heavy shape rides its own
/// gate).
fn many_tiny_inputs(objects: usize) -> Vec<LinkInput> {
    let spec = CorpusSpec {
        objects: Some(objects),
        ..CorpusSpec::new(CorpusPreset::ManyTiny)
    };
    let contents = build_corpus(&spec).expect("the corpus builds");
    contents
        .files
        .iter()
        .map(|(name, bytes)| LinkInput {
            name: name.clone(),
            bytes: bytes.clone(),
        })
        .collect()
}

/// The execute-link config the sweep rides.
fn exec_cfg() -> LinkConfig {
    LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    }
}

/// The row identity a parity comparison reads (the phase token and the
/// detail's counts — walls aside).
fn row_key(event: &PhaseEvent) -> String {
    let detail = match &event.detail {
        PhaseDetail::Objects { inputs } => format!("objects/{inputs}"),
        PhaseDetail::Members { pulled } => format!("members/{pulled}"),
        PhaseDetail::Names { interned } => format!("names/{interned}"),
        PhaseDetail::Winners { reused } => format!("winners/{reused}"),
        PhaseDetail::Live { active } => format!("live/{active}"),
        PhaseDetail::Folded { folded } => format!("folded/{folded}"),
        PhaseDetail::Planned { segments, sections } => format!("planned/{segments}/{sections}"),
        PhaseDetail::Reloc { inputs } => format!("reloc/{inputs}"),
        PhaseDetail::Gate { pages } => format!("gate/{pages}"),
        PhaseDetail::Plan { tiles, dirty } => format!("plan/{tiles}/{dirty}"),
        PhaseDetail::Patch { bytes, tiles } => format!("patch/{bytes}/{tiles}"),
        PhaseDetail::Audit { healed, issues } => format!("audit/{healed}/{issues}"),
        PhaseDetail::Emitted { tiles, bytes } => format!("emitted/{tiles}/{bytes}"),
        PhaseDetail::Flushed { blocks, writers } => format!("flushed/{blocks}/{writers}"),
    };
    format!("{}/{detail}", event.phase.as_str())
}

// ---- the gate rides every run (the §9.3 correctness contract) --------

#[test]
fn every_run_rides_the_strict_verifier() {
    let inputs = many_tiny_inputs(8);
    let plan = SweepPlan {
        label: "verified-shape".to_string(),
        runs: 3,
    };
    let verified = run_verified_sweep(
        &inputs,
        &[],
        &exec_cfg(),
        Parallelism::Serial,
        &plan,
        &strict(),
    )
    .expect("the verified sweep sweeps");
    assert_eq!(verified.outcome.runs, 3, "every planned run ran");
    assert_eq!(verified.gate.stats().len(), 3, "one gate per run");
    for (run, stat) in verified.gate.stats().iter().enumerate() {
        assert_eq!(stat.run, run, "the stats ride the run order");
        assert_eq!(stat.issues, 0, "run {run}: the strict pass found nothing");
        assert_eq!(stat.warnings, 0, "run {run}: strict — no warnings either");
        assert!(
            stat.verify_wall > Duration::ZERO,
            "the verify pass is its own measurement"
        );
    }
    // The produced images are real: the verifier's parse-derived
    // counters name what the strict pass read.
    assert!(
        verified.gate.stats().iter().all(|s| s.symbols > 0),
        "the strict pass read the image's symtab"
    );
}

// ---- the gate bites (the §11 different-code-path rule) ---------------

#[test]
fn the_gate_bites_on_a_broken_image() {
    let inputs = many_tiny_inputs(4);
    let plan = SweepPlan {
        label: "gate-bites".to_string(),
        runs: 1,
    };
    let verified = run_verified_sweep(
        &inputs,
        &[],
        &exec_cfg(),
        Parallelism::Serial,
        &plan,
        &strict(),
    )
    .expect("the honest sweep sweeps");
    let stat = &verified.gate.stats()[0];
    assert_eq!(stat.issues, 0, "the honest image is clean");

    // The gate's per-image face, over the honest image and a hand-broken
    // twin: one truncated (the structural parse refuses) — the refusal
    // carries the verifier's own lines, the run index rides the gate.
    let honest = build_one_image(&inputs);
    let mut broken = honest.clone();
    broken.truncate(broken.len() / 2);
    let mut gate = VerifyGate::new(strict());
    gate.verify_image(0, &honest)
        .expect("the honest image ships");
    let err = gate
        .verify_image(7, &broken)
        .expect_err("the broken image refuses");
    assert!(err.contains("run-7"), "the refusal names the run: {err}");
    assert!(
        err.to_lowercase().contains("verifier"),
        "the refusal names the pass: {err}"
    );
    // The gate's stats stay the honest run's (the refused image never
    // rode a measurement).
    assert_eq!(gate.stats().len(), 1, "the broken image recorded nothing");
    assert_eq!(gate.stats()[0].run, 0);
}

/// One linked corpus's fused image (the gate's per-image face's input).
fn build_one_image(inputs: &[LinkInput]) -> Vec<u8> {
    let result = pgr_core::link::link(inputs, &[], &exec_cfg()).expect("the corpus links");
    pgr_emit::build_image_fused(&result.layout, &result.objects).expect("the image emits")
}

// ---- the gate is outside the wall (the M54 parity contract) ----------

#[test]
fn a_verified_run_is_the_plain_observed_run() {
    // The gate reads the run's product; it never rides the measured
    // wall or the rows — the verified sweep's samples are the plain
    // sweep's samples, shapes and details identical, walls aside.
    let inputs = many_tiny_inputs(8);
    let plan = SweepPlan {
        label: "parity-shape".to_string(),
        runs: 2,
    };
    let ungated = run_sweep(&inputs, &[], &exec_cfg(), Parallelism::Serial, &plan)
        .expect("the ungated sweep sweeps");
    let verified = run_verified_sweep(
        &inputs,
        &[],
        &exec_cfg(),
        Parallelism::Serial,
        &plan,
        &strict(),
    )
    .expect("the verified sweep sweeps");
    assert_eq!(ungated.samples.len(), verified.outcome.samples.len());
    for (ungated_run, verified_run) in ungated.samples.iter().zip(&verified.outcome.samples) {
        let ungated_rows: Vec<String> = ungated_run.report.phases.iter().map(row_key).collect();
        let verified_rows: Vec<String> = verified_run.report.phases.iter().map(row_key).collect();
        assert_eq!(
            ungated_rows, verified_rows,
            "the verified run is the plain run"
        );
        assert!(
            verified_run.wall.as_nanos() > 0,
            "each run's wall is a measurement"
        );
    }
    assert_eq!(
        ungated.summary.phases.len(),
        verified.outcome.summary.phases.len()
    );
}

// ---- the pass-through gate (one shape, no decision copy) -------------

#[test]
fn the_ungated_sweep_is_the_pass_through_gate() {
    let inputs = many_tiny_inputs(6);
    let plan = SweepPlan {
        label: "pass-through".to_string(),
        runs: 2,
    };
    let ungated = run_sweep(&inputs, &[], &exec_cfg(), Parallelism::Serial, &plan)
        .expect("the ungated sweep sweeps");
    let mut no_gate = ();
    let gated = run_sweep_gated(
        &inputs,
        &[],
        &exec_cfg(),
        Parallelism::Serial,
        &plan,
        &mut no_gate,
    )
    .expect("the pass-through sweep sweeps");
    assert_eq!(ungated.runs, gated.runs);
    let ungated_tokens: Vec<String> = ungated
        .summary
        .phases
        .iter()
        .map(|r| r.phase.as_str().to_string())
        .collect();
    let gated_tokens: Vec<String> = gated
        .summary
        .phases
        .iter()
        .map(|r| r.phase.as_str().to_string())
        .collect();
    assert_eq!(ungated_tokens, gated_tokens, "one sweep shape");
}

// ---- a gate refusal aborts the sweep ---------------------------------

#[test]
fn a_gate_refusal_aborts_the_sweep_with_the_run_named() {
    /// The test's own gate: it refuses every run with its own wording
    /// (the consumer-side gate the seam carries — the M67 shape).
    struct Refusing;
    impl SweepRunGate for Refusing {
        fn on_run(
            &mut self,
            run: usize,
            _result: &pgr_core::link::LinkResult,
        ) -> Result<(), String> {
            Err(format!("the test gate refuses run {run} on principle"))
        }
    }
    let inputs = many_tiny_inputs(4);
    let plan = SweepPlan {
        label: "refusing".to_string(),
        runs: 3,
    };
    let mut gate = Refusing;
    let err = run_sweep_gated(
        &inputs,
        &[],
        &exec_cfg(),
        Parallelism::Serial,
        &plan,
        &mut gate,
    )
    .expect_err("the refusing gate aborts the sweep");
    assert!(
        err.to_string().contains("run 0"),
        "the refusal names the run: {err}"
    );
    assert!(
        err.to_string().contains("on principle"),
        "the refusal carries the gate's own wording: {err}"
    );
}

// ---- the archive-heavy shape rides -----------------------------------

#[test]
fn the_archive_heavy_shape_sweeps_verified() {
    // §9.2: "Archive-heavy (hundreds of static libs, most members
    // unused)" — the preset's one `libcorpus.a` rides the archives
    // parameter (the S7 pull's own input); every run's image still
    // ships the strict pass.
    let spec = CorpusSpec::new(CorpusPreset::ArchiveHeavy);
    let contents = build_corpus(&spec).expect("the corpus builds");
    let mut inputs = Vec::new();
    let mut archives = Vec::new();
    for (name, bytes) in &contents.files {
        if name
            .rsplit_once('.')
            .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("a"))
        {
            archives.push(
                pgr_core::sweep::archive_input(name, bytes.clone())
                    .expect("the corpus archive projects"),
            );
        } else {
            inputs.push(LinkInput {
                name: name.clone(),
                bytes: bytes.clone(),
            });
        }
    }
    let plan = SweepPlan {
        label: "archive-heavy".to_string(),
        runs: 2,
    };
    let verified = run_verified_sweep(
        &inputs,
        &archives,
        &exec_cfg(),
        Parallelism::Serial,
        &plan,
        &strict(),
    )
    .expect("the archive-heavy corpus sweeps verified");
    assert_eq!(verified.gate.stats().len(), 2);
    assert!(
        verified
            .gate
            .stats()
            .iter()
            .all(|s| s.issues == 0 && s.warnings == 0),
        "every shipped image is strict-clean"
    );
    // The pull's decision rode the sweep's rows (the S7 fixpoint pulled
    // nothing — the §9.2 row's shape).
    let pull = verified
        .outcome
        .samples
        .iter()
        .flat_map(|s| s.report.phases.iter())
        .find(|e| e.phase.as_str() == "archive_pull")
        .expect("the pull reports");
    assert!(
        matches!(pull.detail, PhaseDetail::Members { pulled: 0 }),
        "an unreferenced archive pulls nothing: {:?}",
        pull.detail
    );
}

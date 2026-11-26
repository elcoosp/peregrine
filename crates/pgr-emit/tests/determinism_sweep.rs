//! The sweep's determinism gate (the `pgr_emit::sweep` seam over the
//! `pgr_core::sweep` run-gate seam).
//!
//! Plan fidelity: the performance architecture doc §9.3 — "**Determinism:**
//! double-link byte-equality on every PR (TDD §4.3)." — and TDD §11's
//! normative verifier assertion: "**Determinism:** link the same corpus
//! twice in separate processes → byte-identical (CI-level, every PR)",
//! restated by §4.3's own close ("The end-to-end test `pgr link twice →
//! byte-identical` runs in CI at every milestone"). The sweep seam
//! (`pgr_core::sweep`) already runs the observed pipeline N times and
//! hands each run's plan to a consumer gate outside the measured wall
//! (the run-gate seam); this seam is the determinism half the same
//! section names: every run's fused image is compared byte-for-byte
//! against the run-0 image, and any divergence aborts the sweep — the
//! nightly never stores a wall from a link whose bytes moved.
//!
//! Gate matrix:
//! * the gate rides every run — one fused emit + byte-compare per
//!   recorded run, the stats naming the run, the bytes and the gate's
//!   own wall (its own measurement, never a link-wall row);
//! * the gate bites — a hand-diverged image (the §11
//!   different-code-path rule) refuses with the first differing byte
//!   named, the honest twin passes;
//! * a length mismatch refuses with both images' sizes named;
//! * the gate is outside the wall — a gated sweep's rows are the plain
//!   sweep's rows (the M54 parity contract: measuring and gating are
//!   read-only);
//! * the gate composes — [`pgr_core::sweep::GatePair`] carries the
//!   verify gate and the determinism gate behind one
//!   [`pgr_core::sweep::SweepRunGate`], either refusal aborting the
//!   sweep;
//! * the archive-heavy shape rides (the pull's members gated beside the
//!   direct objects).

use std::time::Duration;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism};
use pgr_core::sweep::{GatePair, SweepPlan, SweepRunGate, run_sweep, run_sweep_gated};
use pgr_emit::sweep::{DeterminismGate, VerifyGate, run_deterministic_sweep};
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
/// sweep's inputs.
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
fn row_key(event: &pgr_core::observe::PhaseEvent) -> String {
    let detail = match &event.detail {
        pgr_core::observe::PhaseDetail::Objects { inputs } => format!("objects/{inputs}"),
        pgr_core::observe::PhaseDetail::Members { pulled } => format!("members/{pulled}"),
        pgr_core::observe::PhaseDetail::Names { interned } => format!("names/{interned}"),
        pgr_core::observe::PhaseDetail::Winners { reused } => format!("winners/{reused}"),
        pgr_core::observe::PhaseDetail::Live { active } => format!("live/{active}"),
        pgr_core::observe::PhaseDetail::Folded { folded } => format!("folded/{folded}"),
        pgr_core::observe::PhaseDetail::Planned { segments, sections } => {
            format!("planned/{segments}/{sections}")
        }
        pgr_core::observe::PhaseDetail::Reloc { inputs } => format!("reloc/{inputs}"),
        pgr_core::observe::PhaseDetail::Gate { pages } => format!("gate/{pages}"),
        pgr_core::observe::PhaseDetail::Plan { tiles, dirty } => format!("plan/{tiles}/{dirty}"),
        pgr_core::observe::PhaseDetail::Patch { bytes, tiles } => format!("patch/{bytes}/{tiles}"),
        pgr_core::observe::PhaseDetail::Audit { healed, issues } => {
            format!("audit/{healed}/{issues}")
        }
        pgr_core::observe::PhaseDetail::Emitted { tiles, bytes } => {
            format!("emitted/{tiles}/{bytes}")
        }
        pgr_core::observe::PhaseDetail::Flushed { blocks, writers } => {
            format!("flushed/{blocks}/{writers}")
        }
    };
    format!("{}/{detail}", event.phase.as_str())
}

// ---- the gate rides every run (§9.3: "double-link byte-equality") -----

/// §9.3's determinism bullet, as a gate: "**Determinism:** double-link
/// byte-equality on every PR (TDD §4.3)." The same corpus linked N times
/// inside one sweep — every run's image must be byte-identical to the
/// run-0 image, and the gate's stats name what it compared.
#[test]
fn double_link_byte_equality_gates_every_run() {
    let inputs = many_tiny_inputs(8);
    let plan = SweepPlan {
        label: "determinism-shape".to_string(),
        runs: 3,
    };
    let swept = run_deterministic_sweep(&inputs, &[], &exec_cfg(), Parallelism::Serial, &plan)
        .expect("the deterministic sweep sweeps");
    assert_eq!(swept.outcome.runs, 3, "every planned run ran");
    assert_eq!(swept.gate.stats().len(), 3, "one gate per run");
    for (run, stat) in swept.gate.stats().iter().enumerate() {
        assert_eq!(stat.run, run, "the stats ride the run order");
        assert!(stat.bytes > 0, "run {run}: the image was really built");
        assert!(
            stat.gate_wall > Duration::ZERO,
            "the gate's emit+compare is its own measurement"
        );
    }
    // The recorded run-0 image is the separate-process artifact the
    // CI determinism job byte-compares (TDD §11: "twice in separate
    // processes → byte-identical").
    let baseline = swept
        .gate
        .baseline_image()
        .expect("the run-0 image is the gate's baseline");
    assert_eq!(baseline.len(), swept.gate.stats()[0].bytes);
    // The honest re-link is byte-identical: re-emitting the recorded
    // plan through the same fused path reproduces the baseline bytes.
    let again = pgr_core::link::link(&inputs, &[], &exec_cfg()).expect("the corpus links again");
    let image =
        pgr_emit::build_image_fused(&again.layout, &again.objects).expect("the image emits again");
    assert_eq!(image, baseline, "the double link is byte-identical");
}

// ---- the gate bites (the §11 different-code-path rule) ----------------

#[test]
fn the_gate_bites_on_a_divergent_image() {
    let inputs = many_tiny_inputs(4);
    let honest = build_one_image(&inputs);
    let mut diverged = honest.clone();
    let flip = honest.len() / 2;
    diverged[flip] = diverged[flip].wrapping_add(1);

    let mut gate = DeterminismGate::new();
    gate.compare_image(0, &honest)
        .expect("the honest image records the baseline");
    let err = gate
        .compare_image(1, &diverged)
        .expect_err("the diverged image refuses");
    assert!(err.contains("run-1"), "the refusal names the run: {err}");
    assert!(
        err.contains("byte-identical"),
        "the refusal names the contract: {err}"
    );
    assert!(
        err.contains(&format!("byte {flip}")),
        "the refusal names the first differing byte: {err}"
    );
    // The gate's stats stay the honest run's (the diverged image never
    // rode a measurement).
    assert_eq!(gate.stats().len(), 1, "the diverged image recorded nothing");
    assert_eq!(gate.stats()[0].run, 0);
}

#[test]
fn a_length_mismatch_names_both_images() {
    let inputs = many_tiny_inputs(4);
    let honest = build_one_image(&inputs);
    let mut truncated = honest.clone();
    truncated.truncate(truncated.len() / 2);

    let mut gate = DeterminismGate::new();
    gate.compare_image(0, &honest)
        .expect("the honest image records the baseline");
    let err = gate
        .compare_image(2, &truncated)
        .expect_err("the truncated image refuses");
    assert!(err.contains("run-2"), "the refusal names the run: {err}");
    assert!(
        err.contains(&format!("{0} bytes", truncated.len()))
            && err.contains(&format!("{0} baseline bytes", honest.len())),
        "the refusal names both images' sizes: {err}"
    );
}

/// One linked corpus's fused image (the gate's per-image face's input).
fn build_one_image(inputs: &[LinkInput]) -> Vec<u8> {
    let result = pgr_core::link::link(inputs, &[], &exec_cfg()).expect("the corpus links");
    pgr_emit::build_image_fused(&result.layout, &result.objects).expect("the image emits")
}

/// Two links of *different* corpora (the shapes differ), each projected
/// onto the gate's run face — the divergence the gate exists to refuse,
/// driven without a magic hook.
#[test]
fn a_gate_refusal_aborts_through_the_run_face() {
    let a = build_one_image(&many_tiny_inputs(4));
    let b = build_one_image(&many_tiny_inputs(8));
    let result_a =
        pgr_core::link::link(&many_tiny_inputs(4), &[], &exec_cfg()).expect("corpus A links");
    let result_b =
        pgr_core::link::link(&many_tiny_inputs(8), &[], &exec_cfg()).expect("corpus B links");
    let mut gate = DeterminismGate::new();
    gate.on_run(0, &result_a)
        .expect("the run-0 image records the baseline");
    let err = gate
        .on_run(1, &result_b)
        .expect_err("the different shape's image refuses");
    assert!(err.contains("run-1"), "the refusal names the run: {err}");
    // The byte-level face and the run-level face refuse identically.
    let mut twin = DeterminismGate::new();
    twin.compare_image(0, &a).expect("the baseline rides");
    assert!(
        twin.compare_image(1, &b).is_err(),
        "the same divergence refuses at the image face"
    );
}

// ---- the gate is outside the wall (the M54 parity contract) ----------

#[test]
fn a_deterministic_run_is_the_plain_observed_run() {
    let inputs = many_tiny_inputs(8);
    let plan = SweepPlan {
        label: "parity-shape".to_string(),
        runs: 2,
    };
    let ungated = run_sweep(&inputs, &[], &exec_cfg(), Parallelism::Serial, &plan)
        .expect("the ungated sweep sweeps");
    let swept = run_deterministic_sweep(&inputs, &[], &exec_cfg(), Parallelism::Serial, &plan)
        .expect("the deterministic sweep sweeps");
    assert_eq!(ungated.samples.len(), swept.outcome.samples.len());
    for (plain, gated) in ungated.samples.iter().zip(&swept.outcome.samples) {
        let plain_rows: Vec<String> = plain.report.phases.iter().map(row_key).collect();
        let gated_rows: Vec<String> = gated.report.phases.iter().map(row_key).collect();
        assert_eq!(plain_rows, gated_rows, "the gated run is the plain run");
        assert!(
            gated.wall.as_nanos() > 0,
            "each run's wall is a measurement"
        );
    }
}

// ---- the gate composes (the nightly rides both gates) -----------------

#[test]
fn the_gate_pair_composes_verify_and_determinism() {
    let inputs = many_tiny_inputs(6);
    let plan = SweepPlan {
        label: "paired".to_string(),
        runs: 2,
    };
    let mut verify = VerifyGate::new(strict());
    let mut determinism = DeterminismGate::new();
    let mut pair = GatePair::new(&mut verify, &mut determinism);
    let outcome = run_sweep_gated(
        &inputs,
        &[],
        &exec_cfg(),
        Parallelism::Serial,
        &plan,
        &mut pair,
    )
    .expect("the paired sweep sweeps");
    assert_eq!(outcome.runs, 2);
    assert_eq!(verify.stats().len(), 2, "the verify gate rode every run");
    assert_eq!(
        determinism.stats().len(),
        2,
        "the determinism gate rode every run"
    );
    assert!(
        verify
            .stats()
            .iter()
            .all(|s| s.issues == 0 && s.warnings == 0),
        "every image is strict-clean"
    );
    assert!(
        determinism.stats()[1].bytes == determinism.stats()[0].bytes,
        "the double link is byte-equal"
    );
}

// ---- the archive-heavy shape rides ------------------------------------

#[test]
fn the_archive_heavy_shape_sweeps_deterministic() {
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
    let swept =
        run_deterministic_sweep(&inputs, &archives, &exec_cfg(), Parallelism::Serial, &plan)
            .expect("the archive-heavy corpus sweeps deterministic");
    assert_eq!(swept.gate.stats().len(), 2);
    assert!(
        swept.gate.stats()[1].bytes == swept.gate.stats()[0].bytes,
        "the pull's shape double-links byte-identically"
    );
}

//! The shape-sweep delta's gate matrix (the `SweepDelta` face — the
//! §9.3 nightly's "vs baselines" half).
//!
//! Plan fidelity: the performance architecture doc §9.3's nightly
//! contract — "Nightly (wall-clock, dedicated hardware): full corpus,
//! 10 runs, median and p95, vs baselines. Results stored and charted."
//! The stored ledger (the `shape_sweep` gate matrix's round-trip) is the
//! "stored" half; the delta is the comparison face a chart reads: the
//! previous nightly's ledger beside the current one's, the bands and the
//! per-phase rows paired, the move rendered in signed permille (integer
//! math — no float rounding rides the delta, the time-report share
//! column's own rule).
//!
//! The gates pin: the signed permille arithmetic (exact), the
//! positional phase pairing (the current ledger's order leads, a phase
//! the previous nightly lacks renders new, a phase it lost renders
//! gone), the cross-shape refusal (two different shapes' histories do
//! not compare), and the deterministic render faces.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism};
use pgr_core::observe::Phase;
use pgr_core::sweep::{SweepDelta, SweepLedger, SweepPhaseRow, SweepPlan, SweepSummary, run_sweep};
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus};

/// A summary with fixed walls — the delta's input, no clock in sight.
fn summary(median: u64, p95: u64, min: u64, max: u64, phases: &[(&str, u64)]) -> SweepSummary {
    SweepSummary {
        runs: 10,
        median_wall_us: median,
        p95_wall_us: p95,
        min_wall_us: min,
        max_wall_us: max,
        phases: phases
            .iter()
            .map(|(token, us)| SweepPhaseRow {
                phase: phase_token(token),
                median_us: *us,
            })
            .collect(),
    }
}

/// The phase token by name (the M54 vocabulary).
fn phase_token(name: &str) -> Phase {
    match name {
        "parse" => Phase::Parse,
        "intern" => Phase::Intern,
        "fold" => Phase::Fold,
        "layout" => Phase::Layout,
        other => panic!("unknown phase token {other}"),
    }
}

/// A ledger carrying the given summary (the parsed-file face's shape).
fn ledger(label: &str, s: SweepSummary) -> SweepLedger {
    SweepLedger {
        label: label.to_string(),
        runs: 10,
        summary: s,
    }
}

// ---- the signed permille arithmetic ---------------------------------

#[test]
fn the_bands_reduce_to_signed_permille() {
    // §9.3: "median and p95, vs baselines" — the move is
    // (current−previous) as permille of the previous; positive is
    // slower, negative is faster. Integer math end to end.
    let previous = ledger(
        "shape",
        summary(1_000, 2_000, 900, 2_500, &[("parse", 800)]),
    );
    let current = ledger(
        "shape",
        summary(1_100, 1_800, 950, 2_000, &[("parse", 880)]),
    );
    let delta = SweepDelta::between(&previous, &current).expect("one shape's own history compares");
    assert_eq!(delta.median.previous_us, 1_000);
    assert_eq!(delta.median.current_us, 1_100);
    assert_eq!(delta.median.permille, 100, "+10 % reads +100 permille");
    assert_eq!(
        delta.p95.permille, -100,
        "the p95 got faster: −100 permille"
    );
    assert_eq!(
        delta.min.permille, 55,
        "950 over 900: +55 permille (integer math)"
    );
    assert_eq!(delta.max.permille, -200, "2_000 over 2_500: −200 permille");
    assert_eq!(delta.phases[0].permille, Some(100), "880 over 800");
}

#[test]
fn the_zero_previous_renders_zero_permille() {
    // A zero wall (the share column's own convention): the move reads
    // zero permille rather than dividing by zero.
    let previous = ledger("shape", summary(0, 0, 0, 0, &[("parse", 0)]));
    let current = ledger("shape", summary(500, 500, 500, 500, &[("parse", 500)]));
    let delta = SweepDelta::between(&previous, &current).expect("the shapes match");
    assert_eq!(delta.median.permille, 0, "no divide by zero");
    assert_eq!(delta.phases[0].permille, Some(0));
}

// ---- the positional phase pairing -----------------------------------

#[test]
fn the_phases_pair_positionally_and_name_the_changes() {
    // The current ledger's order leads; a phase the previous nightly
    // lacked renders new (previous_us `None`), a phase it lost renders
    // gone (current_us `None`) and trails the paired rows.
    let previous = ledger(
        "shape",
        summary(1_000, 2_000, 900, 2_500, &[("parse", 800), ("layout", 200)]),
    );
    let current = ledger(
        "shape",
        summary(
            1_100,
            1_800,
            950,
            2_000,
            &[("parse", 880), ("fold", 60), ("layout", 190)],
        ),
    );
    let delta = SweepDelta::between(&previous, &current).expect("the shapes match");
    let tokens: Vec<&str> = delta.phases.iter().map(|p| p.phase.as_str()).collect();
    assert_eq!(
        tokens,
        vec!["parse", "fold", "layout"],
        "the current order leads"
    );
    assert_eq!(delta.phases[1].phase, Phase::Fold);
    assert_eq!(delta.phases[1].previous_us, None, "the fold is new");
    assert_eq!(delta.phases[1].current_us, Some(60));
    assert_eq!(
        delta.phases[1].permille, None,
        "a new phase carries no move"
    );
    assert_eq!(delta.phases[2].current_us, Some(190), "layout pairs");
    assert_eq!(delta.phases[2].permille, Some(-50), "190 over 200");
}

#[test]
fn a_lost_phase_trails_the_paired_rows() {
    let previous = ledger(
        "shape",
        summary(
            1_000,
            2_000,
            900,
            2_500,
            &[("parse", 800), ("fold", 60), ("layout", 200)],
        ),
    );
    let current = ledger(
        "shape",
        summary(1_100, 1_800, 950, 2_000, &[("parse", 880), ("layout", 190)]),
    );
    let delta = SweepDelta::between(&previous, &current).expect("the shapes match");
    let tokens: Vec<&str> = delta.phases.iter().map(|p| p.phase.as_str()).collect();
    assert_eq!(
        tokens,
        vec!["parse", "layout", "fold"],
        "the paired lead, the lost trail"
    );
    assert_eq!(delta.phases[2].previous_us, Some(60));
    assert_eq!(delta.phases[2].current_us, None, "the fold is gone");
}

// ---- the refusal faces ----------------------------------------------

#[test]
fn a_cross_shape_comparison_refuses() {
    // Two different shapes' histories do not compare — the label is the
    // shape's name, and a mismatched pair is a caller mistake the delta
    // refuses with both names.
    let previous = ledger(
        "many-tiny",
        summary(1_000, 2_000, 900, 2_500, &[("parse", 800)]),
    );
    let current = ledger(
        "large-debug",
        summary(1_100, 1_800, 950, 2_000, &[("parse", 880)]),
    );
    let err = SweepDelta::between(&previous, &current).expect_err("the shapes refuse");
    let worded = err.to_string();
    assert!(
        worded.contains("many-tiny") && worded.contains("large-debug"),
        "the refusal names both shapes: {worded}"
    );
}

// ---- the deterministic render faces ---------------------------------

#[test]
fn the_delta_renders_deterministically() {
    // The render faces are the chart's input: fixed key order, one line
    // for the JSON (the M55/M58 interchange convention), the signed
    // permille riding the text face's last column.
    let previous = ledger(
        "shape",
        summary(1_000, 2_000, 900, 2_500, &[("parse", 800), ("layout", 200)]),
    );
    let current = ledger(
        "shape",
        summary(
            1_100,
            1_800,
            950,
            2_000,
            &[("parse", 880), ("fold", 60), ("layout", 190)],
        ),
    );
    let delta = SweepDelta::between(&previous, &current).expect("the shapes match");
    let text = delta.render();
    assert!(
        text.contains("the shape-sweep delta: shape"),
        "the shape leads"
    );
    assert!(text.contains("+100"), "the median's move reads signed");
    assert!(text.contains("-100"), "the p95's move reads the minus sign");
    assert!(text.contains("fold"), "the new phase renders");
    let json = delta.render_json();
    assert!(
        json.starts_with("{\"label\":\"shape\",\"runs\":{"),
        "fixed key order"
    );
    assert!(
        json.contains("\"median\":{\"previous_us\":1000,\"current_us\":1100,\"permille\":100}")
    );
    assert!(
        json.contains("\"permille\":null"),
        "the new phase carries no move"
    );
    // Deterministic: the same input answers the same faces.
    let again = SweepDelta::between(&previous, &current).expect("the shapes match");
    assert_eq!(again.render(), text);
    assert_eq!(again.render_json(), json);
}

// ---- end to end (the sweep's own ledgers) ---------------------------

#[test]
fn the_delta_compares_the_sweeps_own_ledgers() {
    // Two sweeps of the same corpus (the nightly's shape) delta through
    // the stored face: the labels match, the runs pair, the per-phase
    // rows pair positionally — the chart reads the same shapes either
    // lane rides.
    let spec = CorpusSpec {
        objects: Some(6),
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
        label: "nightly-shape".to_string(),
        runs: 2,
    };
    let previous = sweep_ledger(&inputs, &cfg, &plan);
    let current = sweep_ledger(&inputs, &cfg, &plan);
    let delta = SweepDelta::between(&previous, &current).expect("one shape's own history compares");
    assert_eq!(delta.label, "nightly-shape");
    assert_eq!(delta.runs, (2, 2));
    assert_eq!(
        delta.phases.len(),
        previous.summary.phases.len(),
        "one row per phase either sweep reported"
    );
}

/// Sweeps once and projects the stored ledger (the nightly's own
/// sequence, in-process).
fn sweep_ledger(inputs: &[LinkInput], cfg: &LinkConfig, plan: &SweepPlan) -> SweepLedger {
    let outcome = run_sweep(inputs, &[], cfg, Parallelism::Serial, plan).expect("the sweep sweeps");
    assert_eq!(
        outcome.samples.len(),
        plan.runs,
        "every planned run recorded"
    );
    outcome.ledger()
}

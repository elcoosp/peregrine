//! The §9.3 budget gate's matrix (the `pgr_core::budget` seam).
//!
//! Plan fidelity: the performance architecture doc §9.3 — "**Budgets
//! enforced from `--time` JSON output:** per-pass wall, thread-seconds,
//! parallel efficiency; fail the build if the single-threaded fraction
//! exceeds 15% (except flush) or parallel efficiency drops below 70% on
//! Passes 1/3/4." — restated by §2.2 ("Pass-level budgets (enforced in
//! CI, Section 9.3): no single-threaded section above 15% of wall except
//! flush; parallel efficiency ≥ 70% for Passes 1, 3, 4 at 8 P-cores")
//! and docs/BENCHMARKS.md's "Budgets land in CI as they ship" row. The
//! sweep seam (`pgr_core::sweep`) reduced and stored the nightly's rows;
//! this seam is the enforcement half the same section names.
//!
//! The gates pin: the serial-fraction arithmetic (integer permille of
//! the run's wall, `flush` exempt — the plan's own exception), the
//! parallel-efficiency arithmetic (the §2.1 metric — the 1-thread wall
//! over N × the N-thread wall, per gated pass, integer permille), the
//! gated pass set (Passes 1/3/4's rows in the M54 vocabulary), the
//! not-measurable rows (a phase one lane never reported, a zero wall —
//! recorded as unmeasured, never guessed), and the two rendered faces
//! (the deterministic text table and the one-line interchange — the
//! M55/M58 conventions). Every gate runs on recorded rows — no clock in
//! the matrix.

use std::time::Duration;

use pgr_core::budget::{
    BreachKind, BudgetReport, PARALLEL_EFFICIENCY_PERMILLE_MIN, SERIAL_SHARE_PERMILLE_MAX,
    check_report, check_sweep,
};
use pgr_core::observe::{Phase, PhaseDetail, PhaseEvent};
use pgr_core::sweep::{SweepPhaseRow, SweepSummary};
use pgr_core::time_report::TimeReport;

/// A summary with the given run wall and phase rows (µs) — the checker's
/// recorded input, no clock in sight.
fn summary(wall_us: u64, phases: &[(&str, u64)]) -> SweepSummary {
    SweepSummary {
        runs: 10,
        median_wall_us: wall_us,
        p95_wall_us: wall_us,
        min_wall_us: wall_us,
        max_wall_us: wall_us,
        phases: phases
            .iter()
            .map(|(token, us)| SweepPhaseRow {
                phase: phase_token(token),
                median_us: *us,
            })
            .collect(),
    }
}

/// The phase token by name (the matrix reads the M54 vocabulary).
fn phase_token(name: &str) -> Phase {
    match name {
        "parse" => Phase::Parse,
        "archive_pull" => Phase::ArchivePull,
        "intern" => Phase::Intern,
        "resolve" => Phase::Resolve,
        "liveness" => Phase::Liveness,
        "fold" => Phase::Fold,
        "layout" => Phase::Layout,
        "reloc" => Phase::Reloc,
        "emit" => Phase::Emit,
        "flush" => Phase::Flush,
        other => panic!("unknown phase token {other}"),
    }
}

/// One synthetic run's report (the `--time` face's input): every row at
/// `µs`, the emit and total bands as given.
fn report(phases: &[(&str, u64)], emit_us: Option<u64>, total_us: Option<u64>) -> TimeReport {
    TimeReport {
        phases: phases
            .iter()
            .map(|(token, us)| PhaseEvent {
                phase: phase_token(token),
                detail: PhaseDetail::Objects { inputs: 1 },
                elapsed: Duration::from_micros(*us),
            })
            .collect(),
        emit: emit_us.map(Duration::from_micros),
        total: total_us.map(Duration::from_micros),
        notes: Vec::new(),
    }
}

/// The share row's (token, permille, breach) triple.
fn share_row(verdict: &BudgetReport, token: &str) -> (String, u32, bool) {
    let row = verdict
        .serial_rows
        .iter()
        .find(|r| r.phase.as_str() == token)
        .unwrap_or_else(|| panic!("the {token} share row is recorded"));
    (
        row.phase.as_str().to_string(),
        row.share_permille,
        row.breach,
    )
}

/// The efficiency row's recorded ratio for one token (absent row →
/// `None` at the caller's discretion — this helper asserts presence).
fn efficiency(verdict: &BudgetReport, token: &str) -> Option<u32> {
    verdict
        .efficiency_rows
        .iter()
        .find(|r| r.phase.as_str() == token)
        .unwrap_or_else(|| panic!("the {token} efficiency row is recorded"))
        .efficiency_permille
}

// ---- the serial-fraction half (§9.3: "the single-threaded fraction
// ---- exceeds 15% (except flush)") -----------------------------------

#[test]
fn a_share_over_the_budget_breaches_and_flush_is_exempt() {
    // The plan's own exception, verbatim: flush never breaches the
    // serial-fraction gate — the pooled write is the wall's tail by
    // design. Every other row does, and the exempt row still counts in
    // the wall denominator.
    let parallel = summary(
        10_000,
        &[
            ("parse", 9_000), // 900‰ — the skew the budget exists to name
            ("resolve", 900), // 90‰ — clean
            ("layout", 100),  // 10‰ — clean
            ("flush", 9_000), // 900‰ — exempt
        ],
    );
    let verdict = check_sweep("many-tiny", &parallel, None, 8);
    assert!(
        !verdict.is_clean(),
        "a 900‰ parse breaches the {SERIAL_SHARE_PERMILLE_MAX}‰ budget"
    );
    let parse_breach = verdict
        .breaches
        .iter()
        .find(|b| b.phase.as_str() == "parse")
        .expect("the parse breach is named");
    assert!(matches!(
        parse_breach.kind,
        BreachKind::SerialShare {
            share_permille: 900,
            limit_permille: 150,
        }
    ));
    assert!(
        !verdict.breaches.iter().any(|b| b.phase.as_str() == "flush"),
        "flush is the plan's own exception"
    );
    assert_eq!(
        share_row(&verdict, "flush"),
        ("flush".to_string(), 900, false),
        "the exempt row rides, its own flag saying so"
    );
}

#[test]
fn the_share_boundary_is_integer_exact() {
    // §9.3: "exceeds 15%" — at exactly 150‰ the budget holds, the first
    // whole permille over it breaches (integer math, no float rounding —
    // the time-report share column's rule).
    let at_limit = summary(10_000, &[("parse", 1_500)]);
    assert!(
        check_sweep("limit", &at_limit, None, 8).is_clean(),
        "150‰ is the budget, not a breach"
    );
    let over = summary(10_000, &[("parse", 1_510)]);
    assert!(
        !check_sweep("over", &over, None, 8).is_clean(),
        "151‰ exceeds the budget"
    );
}

#[test]
fn every_measured_row_is_checked_against_its_own_share() {
    // One row per measured phase (link order), each with its own share;
    // a wall-less summary (an empty run set's shape) never divides by
    // zero and has no share to price.
    let parallel = summary(
        4_000,
        &[
            ("parse", 2_000),  // 500‰
            ("intern", 1_000), // 250‰
            ("layout", 1_000), // 250‰
        ],
    );
    let verdict = check_sweep("three-phases", &parallel, None, 8);
    let rows: Vec<(String, u32, bool)> = verdict
        .serial_rows
        .iter()
        .map(|r| (r.phase.as_str().to_string(), r.share_permille, r.breach))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("parse".to_string(), 500, true),
            ("intern".to_string(), 250, true),
            ("layout".to_string(), 250, true),
        ],
        "one row per measured phase, link order, each priced"
    );
    let empty = summary(0, &[]);
    assert!(
        check_sweep("empty", &empty, None, 8).is_clean(),
        "a wall-less summary has no share to price"
    );
}

// ---- the parallel-efficiency half (§9.3: "parallel efficiency drops
// ---- below 70% on Passes 1/3/4"; §2.1 defines the metric) -----------

#[test]
fn the_efficiency_gate_pins_passes_1_3_4_only() {
    // §2.1: "Parallel efficiency = (thread-seconds at 1 thread) / (N ×
    // wall at N threads) per pass". The 1-thread run's wall is its own
    // thread-seconds (one thread); the gate prices exactly the passes
    // §9.3 names — Passes 1/3/4's rows in the M54 vocabulary (the parse,
    // archive-pull and intern rows are Pass 1's; layout is Pass 3's;
    // emit is Pass 4's) — and never Pass 2's resolve, the ladder's rows
    // or the flush. The gated rows ride the summary's own order.
    let serial = summary(
        10_000,
        &[
            ("parse", 6_000),
            ("archive_pull", 100),
            ("intern", 400),
            ("resolve", 3_000),
            ("layout", 400),
            ("flush", 100),
        ],
    );
    // The N-thread lane: parse scaled 2× on 2 threads (1000‰), intern
    // scaled 2× (1000‰), archive_pull scaled 4× (250‰ — a breach),
    // layout scaled 2.5× (400‰ — a breach), resolve scaled 10× — a
    // Pass-2 collapse the efficiency gate does not price.
    let parallel = summary(
        10_000,
        &[
            ("parse", 3_000),
            ("archive_pull", 200),
            ("intern", 200),
            ("resolve", 30_000),
            ("layout", 500),
            ("flush", 100),
        ],
    );
    let verdict = check_sweep("two-lane", &parallel, Some(&serial), 2);
    let tokens: Vec<&str> = verdict
        .efficiency_rows
        .iter()
        .map(|r| r.phase.as_str())
        .collect();
    assert_eq!(
        tokens,
        vec!["parse", "archive_pull", "intern", "layout"],
        "the gated set, the summary's own order — resolve and flush stay out"
    );
    assert_eq!(
        efficiency(&verdict, "parse"),
        Some(1_000),
        "6000 / (2 × 3000)"
    );
    assert_eq!(
        efficiency(&verdict, "archive_pull"),
        Some(250),
        "100 / (2 × 200) — Pass 1's row, priced and breaching"
    );
    assert_eq!(
        efficiency(&verdict, "intern"),
        Some(1_000),
        "400 / (2 × 200)"
    );
    assert_eq!(
        efficiency(&verdict, "layout"),
        Some(400),
        "400 / (2 × 500) — Pass 3's row, priced and breaching"
    );
    assert!(
        !verdict.is_clean(),
        "the archive-pull and layout collapses breach the floor"
    );
}

#[test]
fn the_efficiency_floor_is_integer_exact() {
    // §9.3: "drops below 70% on Passes 1/3/4" — exactly 700‰ holds, the
    // first permille under it breaches, and the breach carries the floor
    // it broke.
    let serial = summary(10_000, &[("layout", 1_400)]);
    let at_floor = summary(10_000, &[("layout", 1_000)]); // 1400 / (2 × 1000) = 700‰
    assert!(
        check_sweep("floor", &at_floor, Some(&serial), 2).is_clean(),
        "700‰ is the floor, not a breach"
    );
    let under = summary(10_000, &[("layout", 1_001)]); // 1400 / (2 × 1001) = 699‰
    let verdict = check_sweep("under", &under, Some(&serial), 2);
    let breach = verdict
        .breaches
        .iter()
        .find(|b| b.phase.as_str() == "layout")
        .expect("the under-floor layout breaches");
    assert!(matches!(
        breach.kind,
        BreachKind::ParallelEfficiency {
            efficiency_permille: 699,
            floor_permille: PARALLEL_EFFICIENCY_PERMILLE_MIN,
        }
    ));
}

#[test]
fn an_unmeasurable_efficiency_row_says_so() {
    // The gate never guesses: a phase the parallel lane never reported
    // is absent (nothing was measured); a zero wall on either side or a
    // missing 1-thread reference records `None` — and none of them is a
    // breach (the rig job measures what this runner cannot).
    let serial = summary(10_000, &[("parse", 6_000), ("emit", 1_000)]);
    let parallel = summary(10_000, &[("parse", 3_000)]);
    let verdict = check_sweep("solo", &parallel, Some(&serial), 2);
    let parse = verdict
        .efficiency_rows
        .iter()
        .find(|r| r.phase.as_str() == "parse")
        .expect("the measured pass rides");
    assert_eq!(parse.efficiency_permille, Some(1_000));
    assert!(!parse.breach);
    assert!(
        !verdict
            .efficiency_rows
            .iter()
            .any(|r| r.phase.as_str() == "emit"),
        "the parallel lane never reported emit — nothing was measured"
    );

    let zero = summary(10_000, &[("parse", 0)]);
    let verdict = check_sweep("zero", &zero, Some(&serial), 2);
    let parse = verdict
        .efficiency_rows
        .iter()
        .find(|r| r.phase.as_str() == "parse")
        .expect("the zero row rides");
    assert_eq!(
        parse.efficiency_permille, None,
        "a zero parallel wall measures nothing"
    );

    let no_reference = summary(10_000, &[("parse", 1_000)]);
    let verdict = check_sweep("no-ref", &no_reference, None, 2);
    let parse = verdict
        .efficiency_rows
        .iter()
        .find(|r| r.phase.as_str() == "parse")
        .expect("the row rides");
    assert_eq!(
        parse.efficiency_permille, None,
        "no 1-thread run rode — the efficiency half is not measurable"
    );
    assert!(verdict.is_clean(), "an unmeasurable gate is not a breach");
}

// ---- the --time face (§9.3: "Budgets enforced from `--time` JSON
// ---- output") --------------------------------------------------------

#[test]
fn the_report_face_prices_one_runs_rows() {
    // The driver's `--time` report is the plan's named source: one run's
    // rows priced against the run's own wall (the total band when the
    // caller measured it, the measured rows plus the emit band otherwise
    // — the share column's own rule). Flush rides the denominator and
    // stays exempt; the efficiency half needs the 1-thread run beside
    // this one, so the report face carries none.
    let one = report(
        &[
            ("parse", 8_000),
            ("resolve", 1_000),
            ("layout", 500),
            ("flush", 9_500),
        ],
        None,
        Some(19_000),
    );
    let verdict = check_report("cold-link", &one);
    assert_eq!(
        share_row(&verdict, "parse"),
        ("parse".to_string(), 421, true),
        "8000 of 19000, integer permille"
    );
    assert_eq!(
        share_row(&verdict, "flush"),
        ("flush".to_string(), 500, false),
        "flush is exempt on the report face too"
    );
    assert!(
        !verdict.is_clean(),
        "an 8000/19000 parse (421‰) breaches the serial budget"
    );
    assert!(
        verdict.efficiency_rows.is_empty(),
        "one report — no pairing, no efficiency rows"
    );
    // Without the total band the denominator is the measured rows plus
    // the emit band (the share column's own rule).
    let bands = report(
        &[("parse", 1_000), ("layout", 500), ("flush", 500)],
        Some(2_000),
        None,
    );
    let verdict = check_report("bands", &bands);
    assert_eq!(
        share_row(&verdict, "parse"),
        ("parse".to_string(), 250, true),
        "1000 of rows(2000) + emit(2000) = 4000 — 250 permille breaches"
    );
}

// ---- the rendered faces (the M55/M58 conventions) --------------------

#[test]
fn the_verdict_renders_the_text_and_interchange_faces() {
    let serial = summary(10_000, &[("parse", 6_000), ("layout", 400)]);
    let parallel = summary(10_000, &[("parse", 5_000), ("layout", 800)]);
    let verdict = check_sweep("two-lane", &parallel, Some(&serial), 2);
    // parse: share 500‰ (breach), efficiency 6000 / (2 × 5000) = 600‰
    // (breach); layout: share 80‰ (clean), efficiency 400 / (2 × 800) =
    // 250‰ (breach).

    let text = verdict.render();
    assert!(text.contains("two-lane"), "the label leads — {text}");
    assert!(text.contains("parse"), "every gated row renders — {text}");
    assert!(
        text.contains("500"),
        "the 500‰ parse share renders — {text}"
    );
    assert!(
        text.contains("600"),
        "the 600‰ parse efficiency renders — {text}"
    );

    let json = verdict.render_json();
    assert!(json.starts_with("{\"label\":"));
    assert!(
        json.contains("\"clean\":false"),
        "the breaches ride — {json}"
    );
    // Fixed key order (the interchange convention): label, threads,
    // clean, then the rows and the breaches.
    let label = json.find("\"label\"").expect("label");
    let threads = json.find("\"threads\"").expect("threads");
    let clean = json.find("\"clean\"").expect("clean");
    assert!(
        label < threads && threads < clean,
        "fixed key order: {json}"
    );
    assert!(!json.contains(".0"), "no floats ride the interchange");
    assert!(json.ends_with('}'), "one line, one object");

    // A clean verdict says so in both faces.
    let clean_verdict = check_sweep(
        "clean-shape",
        &summary(10_000, &[("parse", 1_000)]),
        None,
        8,
    );
    assert!(clean_verdict.is_clean());
    let clean_json = clean_verdict.render_json();
    assert!(
        clean_json.contains("\"clean\":true"),
        "the clean rides — {clean_json}"
    );
    assert!(clean_json.contains("\"breaches\":[]"));
}

#[test]
fn the_report_face_renders_its_own_shape() {
    let one = report(&[("parse", 12_000), ("flush", 3_000)], None, Some(15_000));
    let verdict = check_report("cold-link", &one);
    let text = verdict.render();
    assert!(text.contains("cold-link"), "the label leads — {text}");
    assert!(
        text.contains("800"),
        "the 800‰ parse share renders — {text}"
    );
    let json = verdict.render_json();
    assert!(json.contains("\"clean\":false"));
    assert!(
        json.contains("\"threads\":null"),
        "one report — no lane size rode"
    );
}

// ---- the end-to-end face (the nightly's own shape) -------------------

#[test]
fn the_gate_prices_a_real_swept_corpus() {
    // The nightly's shape: one corpus, two lanes (the measured one and
    // the 1-thread reference), the gate pricing the recorded rows. The
    // walls are the clock's — the gates pin the *shape*: every gated
    // pass the pipeline reported measured on both lanes, every share a
    // fraction of the wall, every breach flag matching its arithmetic.
    let spec = pgr_fixtures::corpus::CorpusSpec {
        objects: Some(8),
        ..pgr_fixtures::corpus::CorpusSpec::new(pgr_fixtures::corpus::CorpusPreset::ManyTiny)
    };
    let contents = pgr_fixtures::corpus::build_corpus(&spec).expect("the corpus builds");
    let inputs: Vec<pgr_core::link::LinkInput> = contents
        .files
        .iter()
        .map(|(name, bytes)| pgr_core::link::LinkInput {
            name: name.clone(),
            bytes: bytes.clone(),
        })
        .collect();
    let cfg = pgr_core::layout::LinkConfig {
        filetype: pgr_core::layout::OutputType::Execute,
        ..pgr_core::layout::LinkConfig::default()
    };
    let plan = pgr_core::sweep::SweepPlan {
        label: "budget-shape".to_string(),
        runs: 2,
    };
    let measured =
        pgr_core::sweep::run_sweep(&inputs, &[], &cfg, pgr_core::link::Parallelism::Auto, &plan)
            .expect("the measured lane sweeps");
    let reference = pgr_core::sweep::run_sweep(
        &inputs,
        &[],
        &cfg,
        pgr_core::link::Parallelism::Serial,
        &plan,
    )
    .expect("the reference lane sweeps");
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let verdict = check_sweep(
        "budget-shape",
        &measured.summary,
        Some(&reference.summary),
        threads,
    );
    // Passes 1/3/4's rows the pipeline reported ride the gate. Pass 4's
    // emit row rides the driver's face — the sweep prices Passes 1–3,
    // so emit is absent here (nothing was measured), never guessed.
    let tokens: Vec<&str> = verdict
        .efficiency_rows
        .iter()
        .map(|r| r.phase.as_str())
        .collect();
    assert!(tokens.contains(&"parse"), "Pass 1 rides — {tokens:?}");
    assert!(tokens.contains(&"layout"), "Pass 3 rides — {tokens:?}");
    assert!(!tokens.contains(&"flush"), "flush is not the gated set");
    for row in &verdict.serial_rows {
        assert!(
            row.share_permille <= 1_000,
            "a share is a fraction of the wall: {}‰",
            row.share_permille
        );
        assert_eq!(
            row.breach,
            row.share_permille > SERIAL_SHARE_PERMILLE_MAX,
            "the flag matches the arithmetic"
        );
    }
    let text = verdict.render();
    assert!(text.contains("budget-shape"), "the label leads — {text}");
}

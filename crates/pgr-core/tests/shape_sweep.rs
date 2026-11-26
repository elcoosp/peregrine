//! The shape-sweep harness's gate matrix (the `pgr_core::sweep` seam).
//!
//! Plan fidelity: docs/BENCHMARKS.md, "How to read these numbers" —
//! "**Known follow-ups**: a byte-touching parse bench … · parameterized
//! corpus generator behind an `xtask` for nightly shape sweeps" — the
//! generator and the `corpus` command landed; this seam is the sweep
//! they drive. The acceptance criterion the gates pin is the performance
//! architecture doc §9.3's nightly contract: "Nightly (wall-clock,
//! dedicated hardware): full corpus, 10 runs, median and p95, vs
//! baselines. Results stored and charted." — and §9.2's "Baselines to run
//! on every rig … commit the harness".
//!
//! The gates pin: the reduction (median and p95 over recorded runs —
//! exact integer math, nearest-rank p95), the per-phase reduction (the
//! §9.3 budgets' per-pass rows), the sweep's honesty (a measured run is
//! the observed pipeline's run — row shapes identical to a plain
//! observed link, the M54 parity contract), the refusal faces (zero
//! runs, a broken ledger, an existing ledger file), and the stored
//! ledger's round-trip (the M55/M60 writer-plus-strict-reader
//! convention — the reader restores the writer's data exactly).

use std::path::PathBuf;
use std::time::Duration;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link_observed};
use pgr_core::observe::PhaseDetail;
use pgr_core::sweep::{SweepPlan, SweepSample, parse_ledger, reduce, run_sweep};
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus};

/// A temp directory the write-face tests emit into (removed on return).
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr-sweep-gate-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// One sample with a fixed wall and a fixed phase row set — the
/// reduction's input, no clock in sight (the reduction is pure).
fn sample(wall_us: u64, phases: &[(&str, u64)]) -> SweepSample {
    let report = pgr_core::time_report::TimeReport {
        phases: phases
            .iter()
            .map(|(token, us)| pgr_core::observe::PhaseEvent {
                phase: phase_token(token),
                detail: PhaseDetail::Objects { inputs: 1 },
                elapsed: Duration::from_micros(*us),
            })
            .collect(),
        emit: None,
        total: None,
        notes: Vec::new(),
    };
    SweepSample {
        wall: Duration::from_micros(wall_us),
        report,
    }
}

/// The phase token by name (the matrix reads the tokens the pipeline
/// emits — the M54 seam's own vocabulary).
fn phase_token(name: &str) -> pgr_core::observe::Phase {
    match name {
        "parse" => pgr_core::observe::Phase::Parse,
        "intern" => pgr_core::observe::Phase::Intern,
        "resolve" => pgr_core::observe::Phase::Resolve,
        "liveness" => pgr_core::observe::Phase::Liveness,
        "fold" => pgr_core::observe::Phase::Fold,
        "layout" => pgr_core::observe::Phase::Layout,
        other => panic!("unknown phase token {other}"),
    }
}

// ---- the reduction (the §9.3 nightly contract: median and p95) ------

#[test]
fn ten_runs_reduce_to_median_and_p95() {
    // §9.3: "full corpus, 10 runs, median and p95". Ten recorded walls,
    // every value distinct so the rank arithmetic is unambiguous.
    let samples: Vec<SweepSample> = (1u64..=10)
        .map(|us| sample(us * 1_000, &[("parse", us * 100)]))
        .collect();
    let summary = reduce("many-tiny", &samples);
    assert_eq!(summary.runs, 10, "every recorded run rides");
    assert_eq!(summary.min_wall_us, 1_000, "the fastest run");
    assert_eq!(summary.max_wall_us, 10_000, "the slowest run");
    // The median of an even count is the lower middle (sorted index
    // (n-1)/2 = 4 → the 5th of ten): 5 ms.
    assert_eq!(summary.median_wall_us, 5_000, "lower-median convention");
    // Nearest-rank p95: ceil(95·10/100) = 10 → the 10th of ten: 10 ms.
    assert_eq!(summary.p95_wall_us, 10_000, "nearest-rank p95");
}

#[test]
fn nearest_rank_p95_and_lower_median_conventions() {
    // n=1: median and p95 are the only run.
    let one = reduce("one", &[sample(7_000, &[("parse", 700)])]);
    assert_eq!(one.median_wall_us, 7_000);
    assert_eq!(one.p95_wall_us, 7_000);
    // n=2: median is the lower; p95 is ceil(1.9)=2 → the upper.
    let two = reduce(
        "two",
        &[
            sample(3_000, &[("parse", 300)]),
            sample(4_000, &[("parse", 400)]),
        ],
    );
    assert_eq!(two.median_wall_us, 3_000);
    assert_eq!(two.p95_wall_us, 4_000);
    // n=3: median is the middle; p95 is ceil(2.85)=3 → the max.
    let three = reduce(
        "three",
        &[
            sample(1_000, &[("parse", 100)]),
            sample(2_000, &[("parse", 200)]),
            sample(3_000, &[("parse", 300)]),
        ],
    );
    assert_eq!(three.median_wall_us, 2_000);
    assert_eq!(three.p95_wall_us, 3_000);
    // n=20: p95 is ceil(19)=19 → the 19th of twenty.
    let twenty: Vec<SweepSample> = (1u64..=20).map(|us| sample(us, &[("parse", us)])).collect();
    let s = reduce("twenty", &twenty);
    assert_eq!(s.median_wall_us, 10, "sorted index (20-1)/2 = 9 → 10");
    assert_eq!(s.p95_wall_us, 19, "nearest rank ceil(95·20/100)=19");
    // n=21: p95 is ceil(19.95)=20 → the 20th of twenty-one.
    let twenty_one: Vec<SweepSample> = (1u64..=21).map(|us| sample(us, &[("parse", us)])).collect();
    let s = reduce("twenty-one", &twenty_one);
    assert_eq!(s.median_wall_us, 11, "sorted index (21-1)/2 = 10 → 11");
    assert_eq!(s.p95_wall_us, 20, "nearest rank ceil(95·21/100)=20");
}

#[test]
fn per_phase_reduction_rides_first_seen_order() {
    // The §9.3 budgets read per-pass rows: the reduction groups each
    // phase's per-run walls and reduces them with the same conventions,
    // in the phases' first-seen (link) order.
    let samples = vec![
        sample(
            5_000,
            &[("parse", 1_000), ("intern", 2_000), ("layout", 2_000)],
        ),
        sample(
            7_000,
            &[("parse", 3_000), ("intern", 1_000), ("layout", 3_000)],
        ),
        sample(
            6_000,
            &[("parse", 2_000), ("intern", 3_000), ("layout", 1_000)],
        ),
    ];
    let summary = reduce("three-phases", &samples);
    let tokens: Vec<&str> = summary.phases.iter().map(|p| p.phase.as_str()).collect();
    assert_eq!(tokens, vec!["parse", "intern", "layout"], "link order");
    assert_eq!(summary.phases[0].median_us, 2_000, "Parse medians 1/3/2 ms");
    assert_eq!(
        summary.phases[1].median_us, 2_000,
        "Intern medians 2/1/3 ms"
    );
    assert_eq!(
        summary.phases[2].median_us, 2_000,
        "Layout medians 2/3/1 ms"
    );
}

// ---- the sweep's honesty (the M54 parity contract) ------------------

#[test]
fn a_measured_run_is_the_plain_observed_run() {
    // The sweep measures the pipeline; it never changes it (the M54
    // parity contract — the collector is read-only). The rows a swept
    // run reports are the rows a plain observed link of the same corpus
    // reports, shapes and details identical, walls aside.
    let spec = CorpusSpec {
        objects: Some(8),
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

    let mut reference = pgr_core::time_report::TimeCollector::default();
    let _ = link_observed(
        &inputs,
        &[],
        &cfg,
        Parallelism::Serial,
        None,
        &mut reference,
    )
    .expect("the plain link links");
    let plain_rows: Vec<(String, String)> = reference
        .report()
        .phases
        .iter()
        .map(|e| (e.phase.as_str().to_string(), detail_key(&e.detail)))
        .collect();

    let plan = SweepPlan {
        label: "many-tiny".to_string(),
        runs: 3,
    };
    let outcome =
        run_sweep(&inputs, &[], &cfg, Parallelism::Serial, &plan).expect("the sweep sweeps");
    assert_eq!(outcome.runs, 3, "every planned run ran");
    assert_eq!(outcome.samples.len(), 3);
    for s in &outcome.samples {
        assert!(s.wall.as_nanos() > 0, "each run's wall is a measurement");
        let rows: Vec<(String, String)> = s
            .report
            .phases
            .iter()
            .map(|e| (e.phase.as_str().to_string(), detail_key(&e.detail)))
            .collect();
        assert_eq!(rows, plain_rows, "the swept run is the plain run");
    }
    assert_eq!(outcome.summary.runs, 3);
    assert!(outcome.summary.median_wall_us > 0);
    assert_eq!(
        outcome.summary.phases.len(),
        plain_rows.len(),
        "one reduced row per pipeline phase"
    );
    // The corpus is deterministic; the run set's walls may vary, but the
    // summary's phase rows carry the same phase tokens in the same order.
    let tokens: Vec<&str> = outcome
        .summary
        .phases
        .iter()
        .map(|p| p.phase.as_str())
        .collect();
    let plain_tokens: Vec<&str> = plain_rows.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(tokens, plain_tokens, "link order, either lane");
}

/// The detail's identity for row comparison (the counts the corpus makes
/// deterministic — the sweep and the plain link parse the same inputs).
fn detail_key(detail: &PhaseDetail) -> String {
    match detail {
        PhaseDetail::Objects { inputs } => format!("objects/{inputs}"),
        PhaseDetail::Members { pulled } => format!("members/{pulled}"),
        PhaseDetail::Names { interned } => format!("names/{interned}"),
        PhaseDetail::Winners { reused } => format!("winners/{reused}"),
        PhaseDetail::Live { active } => format!("live/{active}"),
        PhaseDetail::Folded { folded } => format!("folded/{folded}"),
        PhaseDetail::Planned { segments, sections } => {
            format!("planned/{segments}/{sections}")
        }
        PhaseDetail::Reloc { inputs } => format!("reloc/{inputs}"),
        PhaseDetail::Gate { pages } => format!("gate/{pages}"),
        PhaseDetail::Plan { tiles, dirty } => format!("plan/{tiles}/{dirty}"),
        PhaseDetail::Patch { bytes, tiles } => format!("patch/{bytes}/{tiles}"),
        PhaseDetail::Audit { healed, issues } => format!("audit/{healed}/{issues}"),
        PhaseDetail::Emitted { tiles, bytes } => format!("emitted/{tiles}/{bytes}"),
        PhaseDetail::Flushed { blocks, writers } => format!("flushed/{blocks}/{writers}"),
    }
}

// ---- the refusal faces ---------------------------------------------

#[test]
fn zero_runs_refuse() {
    let spec = CorpusSpec {
        objects: Some(2),
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
        label: "empty".to_string(),
        runs: 0,
    };
    let err =
        run_sweep(&inputs, &[], &cfg, Parallelism::Serial, &plan).expect_err("zero runs refuse");
    assert!(
        err.to_string().contains("runs"),
        "the refusal names the fix: {err}"
    );
}

#[test]
fn the_ledger_round_trips_and_refuses_broken_shapes() {
    // The M55/M60 convention: the strict reader restores the writer's
    // data exactly, and the broken shapes refuse with the byte position
    // named.
    let samples = vec![
        sample(5_000, &[("parse", 1_000), ("layout", 4_000)]),
        sample(7_000, &[("parse", 3_000), ("layout", 4_000)]),
    ];
    let summary = reduce("round-trip", &samples);
    let json = pgr_core::sweep::ledger_json("round-trip", 2, &summary);
    let ledger = parse_ledger(&json).expect("the ledger parses");
    assert_eq!(ledger.label, "round-trip");
    assert_eq!(ledger.runs, 2);
    assert_eq!(ledger.summary, summary, "the reader restores the writer");

    // An unknown key refuses with the byte position.
    let broken = json.replace("\"runs\":2", "\"runs\":2,\"extra\":1");
    let err = parse_ledger(&broken).expect_err("unknown keys refuse");
    assert!(err.to_string().contains("byte"), "positioned: {err}");

    // A duplicate key refuses.
    let duplicated = json.replace("\"runs\":2", "\"runs\":2,\"runs\":2");
    assert!(parse_ledger(&duplicated).is_err(), "duplicates refuse");

    // A float number refuses (the interchange is integer-only).
    let floated = json.replace("\"runs\":2", "\"runs\":2.0");
    assert!(parse_ledger(&floated).is_err(), "floats refuse");

    // A trailing comma refuses.
    let trailed = json.replace("\"runs\":2", "\"runs\":2,");
    assert!(parse_ledger(&trailed).is_err(), "trailing commas refuse");

    // A label with the JSON-escaped characters round-trips (the
    // report-JSON escape rules — the M55 convention).
    let tricky = "quote\"backslash\\label";
    let escaped = reduce(tricky, &samples);
    let json = pgr_core::sweep::ledger_json(tricky, 2, &escaped);
    let ledger = parse_ledger(&json).expect("the escaped ledger parses");
    assert_eq!(
        ledger.label, tricky,
        "the reader restores the writer's label"
    );
}

#[test]
fn write_ledger_stores_and_refuses_an_existing_file() {
    let samples = vec![sample(9_000, &[("parse", 9_000)])];
    let summary = reduce("stored", &samples);
    let outcome_json = pgr_core::sweep::ledger_json("stored", 1, &summary);

    let dir = temp_dir("store");
    let path = dir.join("many-tiny.json");
    let written =
        pgr_core::sweep::write_ledger("stored", 1, &summary, &path).expect("the ledger writes");
    assert_eq!(written, outcome_json.len() as u64 + 1, "the newline rides");
    let on_disk = std::fs::read(&path).expect("the file exists");
    assert_eq!(
        String::from_utf8(on_disk).expect("utf8"),
        format!("{outcome_json}\n"),
        "the stored bytes are the interchange line"
    );
    let err = pgr_core::sweep::write_ledger("stored", 1, &summary, &path)
        .expect_err("an existing ledger refuses");
    assert!(
        err.to_string().contains("exists"),
        "the refusal names the fix: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- the ledger parses what the sweep wrote (end to end) ------------

#[test]
fn the_stored_ledger_is_the_swept_outcomes_ledger() {
    // §9.3: "Results stored" — the file the nightly job writes parses
    // back to the outcome's own summary.
    let spec = CorpusSpec {
        objects: Some(4),
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
        label: "stored-shape".to_string(),
        runs: 2,
    };
    let outcome =
        run_sweep(&inputs, &[], &cfg, Parallelism::Serial, &plan).expect("the sweep sweeps");
    let json = outcome.render_json();
    let ledger = parse_ledger(&json).expect("the outcome's ledger parses");
    assert_eq!(ledger.label, "stored-shape");
    assert_eq!(ledger.runs, 2);
    assert_eq!(ledger.summary, outcome.summary);
}

// ---- the archive-heavy shape (the §9.2 archive row) -----------------

#[test]
fn the_archive_heavy_corpus_sweeps_through_the_pull() {
    // §9.2: "Archive-heavy (hundreds of static libs, most members
    // unused)" — the preset's one `libcorpus.a` rides the `archives`
    // parameter (the S7 pull's own input), never the direct inputs: the
    // sweep's archive projection parses the ranlib table, the pull
    // reports its decision on the sample's `archive_pull` row, and the
    // direct objects ride beside it.
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
    assert_eq!(inputs.len(), contents.manifest.objects, "the direct inputs");
    assert_eq!(archives.len(), 1, "the one `libcorpus.a`");
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let plan = SweepPlan {
        label: "archive-heavy".to_string(),
        runs: 2,
    };
    let outcome = run_sweep(&inputs, &archives, &cfg, Parallelism::Serial, &plan)
        .expect("the archive-heavy corpus sweeps");
    assert_eq!(outcome.runs, 2);
    // The pull's decision rides the sweep's own rows (the S7 fixpoint
    // pulled nothing — the direct inputs reference nothing in the
    // archive, the §9.2 row's shape).
    let pull = outcome
        .samples
        .iter()
        .flat_map(|s| s.report.phases.iter())
        .find(|e| e.phase.as_str() == "archive_pull")
        .expect("the pull reports");
    assert!(
        matches!(
            pull.detail,
            pgr_core::observe::PhaseDetail::Members { pulled: 0 }
        ),
        "an unreferenced archive pulls nothing: {:?}",
        pull.detail
    );
}

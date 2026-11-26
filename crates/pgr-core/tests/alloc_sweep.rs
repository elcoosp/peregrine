//! The allocation lane's gate matrix (`pgr_core::sweep`'s alloc half) —
//! the §9.3 per-PR allocation-count job's storage and comparison face.
//!
//! Plan fidelity: the performance architecture doc §9.3's first bullet —
//! "**Per-PR (noise-resistant):** … plus **allocation counts per
//! pass**." — restated by §10.3's M1 performance gate ("no allocation
//! in Pass 1–4 hot loops (**counted in CI**)"), and by §9.3's stored
//! face ("Nightly … Results stored and charted"; the delta is the "vs
//! baselines" half). The acceptance this matrix pins: an alloc-swept
//! lane's per-phase medians ride the same lower-median rule the wall
//! lane's do, store into a strict ledger the reader restores exactly,
//! and compare night-over-night in signed permille — a lane the
//! dev-class runner carries end to end.
//!
//! Gate matrix:
//! * the reduction — per-phase median blocks/bytes over the recorded
//!   runs (one, three and five runs — the same lower-median rule the
//!   walls ride), pure over the samples;
//! * the lane — a real gated alloc sweep over the corpus (the silent
//!   seat's rows are measured zeros: the shape is the wire-up's, the
//!   counts are the seat's), the DHAT-seat run beside it (the testing
//!   profiler, serialized — the counts are the process's own);
//! * the ledger — the writer's JSON line restored exactly (the
//!   round-trip convention), the file face refusing an existing path,
//!   the reader refusing unknown/duplicate/missing keys, unknown phase
//!   tokens and trailing bytes with the byte position named;
//! * the delta — the paired phases' signed permille (integer math), the
//!   new/lost phases' honest absences, the cross-shape refusal, the two
//!   render faces.

#[global_allocator]
static DHAT: dhat::Alloc = dhat::Alloc;

use std::sync::{Mutex, OnceLock};

use pgr_core::alloc_count::SharedCounters;
use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism};
use pgr_core::observe::Phase;
use pgr_core::sweep::{
    AllocLedger, AllocSweepDelta, AllocSweepPhaseRow, AllocSweepSample, AllocSweepSummary,
    SweepError, SweepPlan, alloc_ledger_json, parse_alloc_ledger, reduce_allocs, run_alloc_sweep,
    write_alloc_ledger,
};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// One profiler per process (the DHAT contract) — the counted lane's
/// end-to-end run holds this lock; a panicking test unpoisons on take.
static DHAT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn dhat_lock() -> &'static Mutex<()> {
    DHAT_LOCK.get_or_init(|| Mutex::new(()))
}

/// One object: a two-instruction `__text` and a `_main` (when `main`) or
/// `_fn_<stem>` definition — the minimal corpus every pass runs over.
fn object(name: &str, stem: &str, main: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_section(ObjectSection::data("__data", vec![0x41u8; 8], vec![]));
    let symbol = if main {
        "_main".to_string()
    } else {
        format!("_{stem}")
    };
    b.add_symbol(ObjectSymbol::Defined {
        name: symbol,
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// The two-object corpus (`main.o` carries the entry).
fn corpus() -> Vec<LinkInput> {
    vec![
        LinkInput {
            name: "main.o".to_string(),
            bytes: object("main.o", "main", true),
        },
        LinkInput {
            name: "greet.o".to_string(),
            bytes: object("greet.o", "greet", false),
        },
    ]
}

/// A synthetic sample: one run's report with the given per-phase counts
/// (the phase order the segmented pipeline reports) and a fixed wall.
fn sample(runs_counts: &[(Phase, u64, u64)]) -> AllocSweepSample {
    AllocSweepSample {
        wall: std::time::Duration::from_micros(1_000),
        report: pgr_core::alloc_count::AllocReport {
            rows: runs_counts
                .iter()
                .map(|(phase, blocks, bytes)| pgr_core::alloc_count::AllocRow {
                    phase: *phase,
                    blocks: *blocks,
                    bytes: *bytes,
                })
                .collect(),
            total_blocks: runs_counts.iter().map(|(_, b, _)| b).sum(),
            total_bytes: runs_counts.iter().map(|(_, _, by)| by).sum(),
        },
    }
}

/// §9.3's reduction, allocation face: one phase's per-run counts ride
/// the lower median (`(n-1)/2` of the ascending counts — integer-exact,
/// no float rounding), the phases grouping in first-seen order.
#[test]
fn the_reduction_reduces_per_phase_with_the_lower_median() {
    let parse = Phase::Parse;
    let layout = Phase::Layout;
    // Three runs: parse blocks 10, 20, 30 → median 20; layout blocks 2,
    // 4, 6 → median 4 and bytes 5, 7, 9 → median 7 (the odd count's
    // middle).
    let samples = vec![
        sample(&[(parse, 10, 100), (layout, 2, 5)]),
        sample(&[(parse, 20, 200), (layout, 4, 7)]),
        sample(&[(parse, 30, 300), (layout, 6, 9)]),
    ];
    let summary = reduce_allocs("three-runs", &samples);
    assert_eq!(
        summary,
        AllocSweepSummary {
            runs: 3,
            median_wall_us: 1_000,
            phases: vec![
                AllocSweepPhaseRow {
                    phase: parse,
                    median_blocks: 20,
                    median_bytes: 200,
                },
                AllocSweepPhaseRow {
                    phase: layout,
                    median_blocks: 4,
                    median_bytes: 7,
                },
            ],
        },
        "the medians ride the lower-middle rule at three runs (layout bytes 5,7,9 → 7 \
         at odd counts, 4 the blocks' middle)"
    );
}

/// The lower median at an even count: the lower of the two middles.
#[test]
fn the_reduction_takes_the_lower_median_at_even_counts() {
    let parse = Phase::Parse;
    let samples = vec![
        sample(&[(parse, 10, 100)]),
        sample(&[(parse, 30, 300)]),
        sample(&[(parse, 20, 200)]),
        sample(&[(parse, 40, 400)]),
    ];
    let summary = reduce_allocs("four-runs", &samples);
    let row = &summary.phases[0];
    assert_eq!(
        row.median_blocks, 20,
        "10,20,30,40 → the lower middle is 20"
    );
    assert_eq!(row.median_bytes, 200);
}

/// The lane's wire-up: a real gated alloc sweep over the corpus — the
/// silent seat's rows are measured zeros (the shape is the wire-up's,
/// one row per phase in link order; the counts are the seat's own, and
/// nobody recorded), the ledger stores and restores them exactly.
#[test]
fn the_alloc_lane_sweeps_the_corpus_and_stores_its_ledger() {
    let inputs = corpus();
    let cfg = LinkConfig::default();
    let seat = SharedCounters::new();
    let plan = SweepPlan {
        label: "two-objects".to_string(),
        runs: 2,
    };
    let outcome = run_alloc_sweep(&inputs, &[], &cfg, Parallelism::Auto, &plan, &mut (), &seat)
        .expect("the silent-seat lane sweeps");
    assert_eq!(outcome.runs, 2);
    let phases: Vec<Phase> = outcome.summary.phases.iter().map(|r| r.phase).collect();
    assert_eq!(
        phases,
        vec![
            Phase::Parse,
            Phase::ArchivePull,
            Phase::Intern,
            Phase::Resolve,
            Phase::Liveness,
            Phase::Fold,
            Phase::Layout,
        ],
        "one reduced row per phase, link order (the M54 sequence)"
    );
    assert!(
        outcome
            .summary
            .phases
            .iter()
            .all(|r| r.median_blocks == 0 && r.median_bytes == 0),
        "the silent seat records measured zeros — the shape is honest"
    );

    // The stored face round-trips (the writer's line is the reader's).
    let ledger = outcome.ledger();
    let line = alloc_ledger_json(&ledger.label, ledger.runs, &ledger.summary);
    let restored = parse_alloc_ledger(&line).expect("the writer's line restores");
    assert_eq!(restored, ledger, "the round-trip convention (gated)");
}

/// The counted lane end to end: the DHAT seat records the process's own
/// allocations, the lanes' medians carry non-zero counts, and the
/// ledger stores them for the nightly's face. The profiler runs in the
/// `testing` mode (no `dhat-heap.json`, no stderr summary), serialized
/// — DHAT permits one running profiler per process.
#[test]
fn the_counted_lane_carries_the_process_counts() {
    let guard = dhat_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let profiler = dhat::Profiler::builder().testing().build();
    let source = DhatSource;

    let inputs = corpus();
    let cfg = LinkConfig::default();
    let plan = SweepPlan {
        label: "counted-two-objects".to_string(),
        runs: 3,
    };
    let outcome = run_alloc_sweep(
        &inputs,
        &[],
        &cfg,
        Parallelism::Serial,
        &plan,
        &mut (),
        &source,
    )
    .expect("the counted lane sweeps");
    let parse = outcome
        .summary
        .phases
        .iter()
        .find(|r| r.phase == Phase::Parse)
        .expect("the segmented link reports its parse");
    assert!(
        parse.median_blocks > 0 && parse.median_bytes > 0,
        "the parse window's median carries the corpus's allocations — {outcome:?}"
    );

    // The stored face rides the real counts too (the writer's line, the
    // reader's restore).
    let ledger = outcome.ledger();
    let line = alloc_ledger_json(&ledger.label, ledger.runs, &ledger.summary);
    let restored = parse_alloc_ledger(&line).expect("the counted line restores");
    assert_eq!(restored, ledger);

    // The file face: written to a fresh temp path, refusing a second
    // write to the same path (the nightly's one-write-per-shape rule).
    let path = std::env::temp_dir().join("pgr-alloc-sweep-gate.json");
    let _ = std::fs::remove_file(&path);
    let bytes = write_alloc_ledger(&ledger.label, ledger.runs, &ledger.summary, &path)
        .expect("the ledger writes");
    assert!(bytes > 0, "the written line is non-empty");
    let again = write_alloc_ledger(&ledger.label, ledger.runs, &ledger.summary, &path);
    assert!(again.is_err(), "the second write to the path refuses");
    let _ = std::fs::remove_file(&path);

    drop(profiler);
    drop(guard);
}

/// The reader's refusals: unknown keys, duplicate keys, missing fields,
/// unknown phase tokens and trailing bytes refuse with the byte
/// position named (the strict schema the writer's shape defines).
#[test]
fn the_ledger_reader_refuses_the_broken_shapes() {
    let good = "{\"label\":\"s\",\"runs\":1,\"median_wall_us\":10,\"phases\":[{\"phase\":\"parse\",\"median_blocks\":1,\"median_bytes\":2}]}";

    let unknown = good.replace("\"phases\"", "\"phases_x\"");
    let err = parse_alloc_ledger(&unknown).expect_err("an unknown key refuses");
    let SweepError::Ledger { at, detail } = err else {
        panic!("expected the ledger refusal, got {err:?}")
    };
    assert!(
        detail.contains("unknown key"),
        "the refusal names the key — {detail}"
    );
    assert!(at > 0, "the refusal is byte-positioned");

    let duplicate =
        "{\"label\":\"s\",\"label\":\"s\",\"runs\":1,\"median_wall_us\":10,\"phases\":[]}";
    let err = parse_alloc_ledger(duplicate).expect_err("a duplicate key refuses");
    assert!(
        matches!(err, SweepError::Ledger { ref detail, .. } if detail.contains("duplicate")),
        "the refusal names the duplicate — {err:?}"
    );

    let missing = "{\"label\":\"s\",\"runs\":1,\"phases\":[]}";
    let err = parse_alloc_ledger(missing).expect_err("a missing field refuses");
    assert!(
        matches!(err, SweepError::Ledger { ref detail, .. } if detail.contains("missing field")),
        "the refusal names the missing field — {err:?}"
    );

    let bad_token = "{\"label\":\"s\",\"runs\":1,\"median_wall_us\":10,\"phases\":[{\"phase\":\"nope\",\"median_blocks\":1,\"median_bytes\":2}]}";
    let err = parse_alloc_ledger(bad_token).expect_err("an unknown phase token refuses");
    assert!(
        matches!(err, SweepError::Ledger { ref detail, .. } if detail.contains("M54 vocabulary")),
        "the refusal names the vocabulary — {err:?}"
    );

    let err = parse_alloc_ledger(&format!("{good} junk")).expect_err("trailing bytes refuse");
    assert!(
        matches!(err, SweepError::Ledger { ref detail, .. } if detail.contains("trailing")),
        "the refusal names the trailing bytes — {err:?}"
    );
}

/// The delta: one shape's own history — the paired phases ride signed
/// permille (integer math), a phase the previous nightly lacked rides
/// honest absences, a phase it lost trails the paired rows, and a
/// cross-shape comparison refuses with both names.
#[test]
fn the_delta_pairs_the_histories_in_signed_permille() {
    let row = |phase: Phase, blocks: u64, bytes: u64| AllocSweepPhaseRow {
        phase,
        median_blocks: blocks,
        median_bytes: bytes,
    };
    let summary = |phases: Vec<AllocSweepPhaseRow>, wall: u64| AllocSweepSummary {
        runs: 3,
        median_wall_us: wall,
        phases,
    };
    let parse = Phase::Parse;
    let layout = Phase::Layout;
    let flush = Phase::Flush;
    let previous = AllocLedger {
        label: "shape".to_string(),
        runs: 3,
        summary: summary(vec![row(parse, 100, 1_000), row(layout, 40, 400)], 900),
    };
    let current = AllocLedger {
        label: "shape".to_string(),
        runs: 5,
        summary: summary(vec![row(parse, 130, 900), row(flush, 4, 40)], 1_100),
    };
    let delta = AllocSweepDelta::between(&previous, &current).expect("one shape's own history");
    assert_eq!(delta.runs, (3, 5));
    assert_eq!(
        delta.median_wall.permille, 222,
        "900 → 1100 is +222‰ (integer math)"
    );
    // The current order leads: parse pairs (+30‰), flush is new; layout
    // (lost) trails.
    assert_eq!(
        delta.phases.len(),
        3,
        "two paired-or-new rows plus the lost one"
    );
    let parse_row = &delta.phases[0];
    assert_eq!(parse_row.phase, parse);
    assert_eq!(parse_row.blocks_permille, Some(300), "100 → 130 is +300‰");
    assert_eq!(parse_row.bytes_permille, Some(-100), "1000 → 900 is −100‰");
    let flush_row = &delta.phases[1];
    assert_eq!(
        flush_row.previous_blocks, None,
        "a new phase rides honest absences"
    );
    assert_eq!(flush_row.blocks_permille, None);
    let layout_row = &delta.phases[2];
    assert_eq!(layout_row.phase, layout);
    assert_eq!(
        layout_row.current_blocks, None,
        "a lost phase rides honest absences"
    );

    // The faces render the pairing.
    let text = delta.render();
    assert!(text.contains("the allocation-sweep delta: shape"), "{text}");
    assert!(text.contains("+300‰"), "the blocks' move renders — {text}");
    assert!(text.contains("(gone)"), "the lost phase renders — {text}");
    assert!(text.contains("(new)"), "the new phase renders — {text}");
    let json = delta.render_json();
    assert!(
        json.starts_with("{\"label\":\"shape\",\"runs\":{\"previous\":3,\"current\":5}"),
        "the JSON's fixed key order — {json}"
    );
    assert!(
        json.contains("\"blocks_permille\":300"),
        "the paired move rides the JSON — {json}"
    );
    assert!(
        json.contains("\"blocks_permille\":null"),
        "the absent move rides null — {json}"
    );
}

/// The cross-shape refusal: a delta between different labels refuses
/// with both names (a comparison is one shape's own history).
#[test]
fn the_delta_refuses_cross_shape_comparisons() {
    let ledger = |label: &str| AllocLedger {
        label: label.to_string(),
        runs: 1,
        summary: AllocSweepSummary::default(),
    };
    let err = AllocSweepDelta::between(&ledger("a"), &ledger("b")).expect_err("labels differ");
    assert!(
        matches!(err, pgr_core::sweep::SweepError::LabelsDiffer { .. }),
        "the cross-shape comparison refuses — {err:?}"
    );
}

/// The DHAT seat's bridge — the seat consumer's own glue (the library
/// never links DHAT; this file's bridge is the copy the counted lane's
/// gate owns).
struct DhatSource;

impl pgr_core::alloc_count::AllocSource for DhatSource {
    fn sample(&self) -> pgr_core::alloc_count::AllocSnapshot {
        let stats = dhat::HeapStats::get();
        pgr_core::alloc_count::AllocSnapshot {
            blocks: stats.total_blocks,
            bytes: stats.total_bytes,
        }
    }
}

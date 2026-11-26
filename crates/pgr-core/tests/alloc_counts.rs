//! The §9.3 per-PR allocation-count seam (`pgr_core::alloc_count`) — the
//! gate matrix for the measurement infrastructure's allocation half.
//!
//! Plan fidelity: the performance architecture doc §9.3's first bullet —
//! "**Per-PR (noise-resistant):** instruction counts and cache-miss
//! counts on a fixed corpus (`perf stat` or valgrind-class tooling on
//! Linux), **plus allocation counts per pass**." — restated by §10.3's
//! M1 performance gate ("no allocation in Pass 1–4 hot loops (counted in
//! CI)") and the hot-path rules' first rule (§5: "No allocation in a
//! `par_iter` body except into pre-sized per-task arenas"). The
//! acceptance this matrix pins: a link's per-pass allocation counts ride
//! the M54 observation seam as data — one row per phase, the pass's
//! window, deterministic faces a build system can diff — without moving
//! a byte of the plan (the parity gate).
//!
//! Gate matrix:
//! * the windows — the counts a seat records between two phase
//!   completions price the pass that ran between them (the §9.3 "per
//!   pass" face), one row per phase event, link order;
//! * the honesty — a seat that never moves records measured zeros, and
//!   a seat that moves backwards (a reset) saturates at zero: a window
//!   is never negative, a count never fabricated;
//! * the wire-up — a real observed link rides the collector (the same
//!   seven phases the M54 matrix pins), and the parity holds: the
//!   observed-and-counted link plans the identical layout;
//! * the faces — the text table and the one-line JSON interchange are
//!   deterministic, the report-JSON escape rules;
//! * the DHAT seat — the process's `dhat::Alloc` counters (the
//!   valgrind-class tooling the plan names) sampled through the seat
//!   contract: real allocations ride the windows, the collector never
//!   re-derives a count.
//!
//! The test binary installs `dhat::Alloc` as its global allocator (the
//! seat the DHAT walks share). Without a running `Profiler` the
//! allocator is a pass-through — the synthetic-seat tests pay nothing —
//! and the DHAT-seat test runs its own `Profiler` under the `testing`
//! mode (no `dhat-heap.json`, no stderr summary), serialized: DHAT
//! permits one running profiler per process.

use std::sync::Mutex;

/// The test binary's global allocator: the DHAT seat (the §9.3 seat the
/// measurement binaries install). Without a running [`dhat::Profiler`]
/// it is a pass-through — the synthetic-seat tests pay nothing — and the
/// DHAT-seat test's profiler is the recording window.
#[global_allocator]
static DHAT: dhat::Alloc = dhat::Alloc;

use pgr_core::alloc_count::{
    AllocCollector, AllocReport, AllocRow, AllocSnapshot, AllocSource, SharedCounters,
};
use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism, link_cached, link_observed};
use pgr_core::observe::{LinkObserver, Phase, PhaseDetail, PhaseEvent};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// The DHAT seat's bridge — the seat consumer's own glue (the library
/// never links DHAT: the driver's dependency surface stays lean, perf
/// doc §8; the counting unsafe lives inside the seat crate, the tree's
/// `unsafe_code = "forbid"` gate stays intact). This file's bridge is
/// the copy the gate matrix owns.
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

/// One profiler per process, the DHAT contract — the DHAT-seat tests
/// hold this lock (a guard unpoisons the mutex a panicking test left).
static DHAT_LOCK: Mutex<()> = Mutex::new(());

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

/// The phase event one pass's completion rides (the detail's own shape
/// is the M54 vocabulary's; the collector reads only the phase).
fn event(phase: Phase) -> PhaseEvent {
    PhaseEvent {
        phase,
        detail: PhaseDetail::Objects { inputs: 2 },
        elapsed: std::time::Duration::from_micros(1),
    }
}

/// §9.3 bullet 1: "plus allocation counts per pass" — the counts a seat
/// records between two phase completions price the pass that ran
/// between them. The seat is bumped between hand-fired phase events (a
/// pipeline's phase completions in link order), and the report's rows
/// must name the pass windows: Parse's window opens at collection and
/// closes at the Parse event, Intern's at the Parse event, and so on —
/// one row per phase, link order, the totals the whole run's window.
#[test]
fn per_pass_windows_carry_the_allocation_counts() {
    let seat = SharedCounters::new();
    let mut collector = AllocCollector::new(&seat);

    // Pass 1's body: the parse's allocations land before its completion.
    seat.record(10, 4_096);
    collector.on_phase(event(Phase::Parse));
    // Pass 2's body: the resolve's allocations land before its event.
    seat.record(6, 1_024);
    collector.on_phase(event(Phase::Resolve));
    // Pass 3's body: the layout's allocations land before its event.
    seat.record(3, 512);
    collector.on_phase(event(Phase::Layout));

    let report = collector.finish();
    assert_eq!(
        report.rows,
        vec![
            AllocRow {
                phase: Phase::Parse,
                blocks: 10,
                bytes: 4_096,
            },
            AllocRow {
                phase: Phase::Resolve,
                blocks: 6,
                bytes: 1_024,
            },
            AllocRow {
                phase: Phase::Layout,
                blocks: 3,
                bytes: 512,
            },
        ],
        "each row names the window its pass ran in (§9.3: allocation counts per pass)"
    );
    assert_eq!(report.total_blocks, 19);
    assert_eq!(report.total_bytes, 4_096 + 1_024 + 512);
}

/// The honesty rule: a seat that never moves records measured zeros —
/// an unmeasured window is zero, never fabricated; and a seat that
/// moves backwards (a reset mid-run) saturates at zero, never negative.
#[test]
fn windows_record_measured_zeros_and_never_go_negative() {
    // A silent seat: the rows ride measured zeros.
    let seat = SharedCounters::new();
    let mut collector = AllocCollector::new(&seat);
    collector.on_phase(event(Phase::Parse));
    collector.on_phase(event(Phase::Intern));
    let report = collector.finish();
    assert!(report.rows.iter().all(|r| r.blocks == 0 && r.bytes == 0));

    // A reset mid-run: the window saturates at zero.
    let seat = SharedCounters::new();
    seat.record(5, 256);
    let mut collector = AllocCollector::new(&seat);
    collector.on_phase(event(Phase::Parse));
    seat.reset();
    collector.on_phase(event(Phase::Intern));
    let report = collector.finish();
    assert_eq!(report.rows[1].blocks, 0, "a reset window saturates at zero");
    assert_eq!(report.rows[1].bytes, 0);
    assert_eq!(
        report.total_blocks, 0,
        "the totals saturate too — the seat went backwards, nothing is fabricated"
    );
}

/// The wire-up: a real observed link rides the collector — the same
/// seven phases the M54 matrix pins, one row each, in link order (the
/// seat rides silently here: the rows are the wire-up's shape, not the
/// counts' — the DHAT-seat test pins those).
#[test]
fn a_real_observed_link_rides_the_collector() {
    let inputs = corpus();
    let cfg = LinkConfig::default();
    let seat = SharedCounters::new();
    let mut collector = AllocCollector::new(&seat);
    link_observed(&inputs, &[], &cfg, Parallelism::Auto, None, &mut collector)
        .expect("the two-object corpus links");
    let report = collector.finish();
    let phases: Vec<Phase> = report.rows.iter().map(|r| r.phase).collect();
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
        "one row per phase event, link order (the M54 sequence)"
    );
}

/// The parity gate: the observed-and-counted link plans the identical
/// layout an unobserved one does — measuring never moves a byte (the
/// M54 seam's own contract, re-gated through the collector).
#[test]
fn the_counted_link_plans_the_identical_layout() {
    let inputs = corpus();
    let cfg = LinkConfig::default();
    let plain = link_cached(&inputs, &[], &cfg, Parallelism::Auto, None)
        .expect("the unobserved link plans");
    let seat = SharedCounters::new();
    let mut collector = AllocCollector::new(&seat);
    let counted = link_observed(&inputs, &[], &cfg, Parallelism::Auto, None, &mut collector)
        .expect("the counted link plans");
    assert_eq!(
        plain.layout.file_size, counted.layout.file_size,
        "the observation is read-only (the parity gate — the M54 shape)"
    );
    assert_eq!(
        plain.layout.segments.len(),
        counted.layout.segments.len(),
        "the plan's segment table is identical (the parity gate)"
    );
}

/// The faces: the text table is the deterministic M58 shape a build
/// system diffs line by line, and the JSON interchange is the one-line
/// compact form with the fixed key order (the M55/M58 convention).
#[test]
fn the_report_faces_render_deterministically() {
    let report = AllocReport {
        rows: vec![
            AllocRow {
                phase: Phase::Parse,
                blocks: 10,
                bytes: 4_096,
            },
            AllocRow {
                phase: Phase::Layout,
                blocks: 3,
                bytes: 512,
            },
        ],
        total_blocks: 13,
        total_bytes: 4_608,
    };
    let text = report.render();
    assert!(
        text.contains("allocation report"),
        "the header leads — {text}"
    );
    for (phase, blocks, bytes) in [
        ("parse", "10", "4096"),
        ("layout", "3", "512"),
        ("total", "13", "4608"),
    ] {
        assert!(text.contains(phase), "every row's phase renders — {text}");
        assert!(
            text.contains(blocks),
            "the row's block count renders — {text}"
        );
        assert!(
            text.contains(bytes),
            "the row's byte count renders — {text}"
        );
    }
    assert_eq!(
        text.lines().count(),
        4,
        "header + one row per phase + total"
    );
    assert_eq!(
        report.render_json(),
        "{\"rows\":[{\"phase\":\"parse\",\"blocks\":10,\"bytes\":4096},{\"phase\":\"layout\",\"blocks\":3,\"bytes\":512}],\"total_blocks\":13,\"total_bytes\":4608}",
        "the JSON interchange's key order is fixed (the M55/M58 convention)"
    );
}

/// The DHAT seat: the process's own counters (the valgrind-class
/// tooling §9.3 names) ride the same seat contract — real allocations
/// land in the windows, the collector samples the seat, nothing is
/// re-derived. The profiler runs in the `testing` mode (no
/// `dhat-heap.json`, no stderr summary) and holds the process's one
/// profiler slot; the assertions are window-based (the counts are the
/// whole process's, the windows are the link's own — the same honesty
/// the per-pass face rides in production).
#[test]
fn the_dhat_seat_counts_the_process_allocations() {
    let guard = DHAT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _guard = guard;
    let profiler = dhat::Profiler::builder().testing().build();
    let source = DhatSource;

    let before = source.sample();
    let seat_bump = Vec::<u8>::with_capacity(8_192);
    let after = source.sample();
    assert!(
        after.blocks > before.blocks,
        "the seat records the process's allocations (the bump's block included)"
    );
    assert!(
        after.bytes >= before.bytes.saturating_add(8_192),
        "the seat records the process's bytes (the bump's bytes included)"
    );

    // The real face: a link's per-pass windows carry non-zero counts.
    let inputs = corpus();
    let cfg = LinkConfig::default();
    let mut collector = AllocCollector::new(&source);
    link_observed(
        &inputs,
        &[],
        &cfg,
        Parallelism::Serial,
        None,
        &mut collector,
    )
    .expect("the corpus links under the counted seat");
    let report = collector.finish();
    assert!(
        report.total_blocks > 0 && report.total_bytes > 0,
        "the link's windows carry the process's own counts (the seat is the run's)"
    );
    let parse = report
        .rows
        .iter()
        .find(|r| r.phase == Phase::Parse)
        .expect("the segmented link reports its parse");
    assert!(
        parse.blocks > 0 && parse.bytes > 0,
        "the parse window carries the corpus's allocations — {report:?}"
    );
    assert!(
        report
            .rows
            .iter()
            .all(|r| r.blocks <= report.total_blocks && r.bytes <= report.total_bytes),
        "no window exceeds the run's whole window (a monotonic seat's partial sums sit inside it)",
    );
    drop(seat_bump);
    drop(profiler);
}

//! The allocation lane's binary — the §9.3 per-PR allocation-count job's
//! CI face ("plus allocation counts per pass", "counted in CI" the §10.3
//! M1 gate's own wording). One process, one seat: the process's global
//! allocator is the DHAT seat (`dhat::Alloc` — the valgrind-class
//! tooling §9.3 names), the recording window the run's profiler opens.
//!
//! The lane is a separate *binary* (not a flag on the wall lane's
//! `xtask`) because the seat is process-global: a counting allocator's
//! per-allocation bookkeeping would ride the wall lane's stored walls,
//! and the nightly's baseline walls stay the plain allocator's. The two
//! binaries speak the same flag surface ([`xtask`], the shared
//! machinery) and project the same corpus the same way — the two
//! ledgers' labels name one shape.
//!
//! Every run rides the same gate pair the wall lane rides (the strict
//! verifier beside the determinism comparison — §9.3's correctness
//! half: the lane never records an ungated measurement, and the
//! counts are the gated links' own), and the ledger line writes to
//! `--out` beside the wall lane's.
//!
//! ```sh
//! cargo run -p xtask --bin xtask-alloc -- \
//!     --out /tmp/sweep/many-tiny.allocs.json --preset many-tiny --runs 10
//! ```

/// The process's global allocator: the DHAT seat. The lane's profiler
/// (below) is the recording window; the corpus generation before it
/// rides the pass-through.
#[global_allocator]
static DHAT: dhat::Alloc = dhat::Alloc;

use pgr_core::alloc_count::{AllocSnapshot, AllocSource};
use pgr_core::sweep::{
    GatePair, SweepPlan, alloc_ledger_json, run_alloc_sweep, write_alloc_ledger,
};
use pgr_emit::sweep::{DeterminismGate, VerifyGate};
use pgr_fixtures::corpus::build_corpus;
use pgr_verify::Options;
use xtask::{SweepArgs, parse_sweep_args, split_corpus, sweep_config};

/// The DHAT seat's bridge — the seat consumer's own glue (the library
/// never links DHAT; this binary's bridge is the copy the lane owns).
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

/// The exit code a runtime failure exits with (the wall lane's
/// convention).
const FAILURE_EXIT: i32 = 1;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_sweep_args(&args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("pgr-xtask-alloc: {message}");
            std::process::exit(2);
        }
    };
    if let Err(message) = run_alloc_lane(&parsed, &args) {
        eprintln!("pgr-xtask-alloc: {message}");
        std::process::exit(FAILURE_EXIT);
    }
}

/// Runs the allocation lane: the recording profiler opens, the corpus
/// builds (inside it — the generation's counts ride the seat, never a
/// link's window), the gated alloc sweep records the per-pass windows,
/// the ledger writes to `--out`.
///
/// # Errors
/// The generator's, the pipeline's, the gates' or the filesystem's
/// refusal, already worded.
fn run_alloc_lane(parsed: &SweepArgs, raw: &[String]) -> Result<(), String> {
    // The wall lane's gates are faces the wall command carries — the
    // alloc lane prices counts, not walls, and the ledger stores counts
    // (the flags refuse: the surface names each lane's own).
    for flag in ["--budgets", "--determinism"] {
        if raw.iter().any(|a| a == flag) {
            return Err(format!(
                "{flag} is the wall lane's flag — the allocation lane prices counts (the \
                 wall command's binary carries the gates' faces)"
            ));
        }
    }
    let out = parsed.out.as_ref().expect("parse_sweep_args checked --out");

    // The recording window opens here: the profiler rides the corpus
    // build and every run (the counts are the process's own — the
    // honesty the seat contract rides), the `testing` mode keeping the
    // filesystem and stderr silent (the ledger is the lane's stored
    // face; the DHAT document the wall lane's nightly does not carry).
    let profiler = dhat::Profiler::builder().testing().build();
    let source = DhatSource;

    let spec = parsed.spec();
    let contents = build_corpus(&spec).map_err(|e| e.to_string())?;
    let (inputs, archives) = split_corpus(&contents.files)?;
    let cfg = sweep_config();
    let plan = SweepPlan {
        label: parsed.label(),
        runs: parsed.runs(),
    };

    // The same gate pair the wall lane rides (§9.3's correctness half —
    // every benchmark link ships through the strict verifier before the
    // ledger records, and the double-link comparison rides beside it).
    let strict = Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let mut verify_gate = VerifyGate::new(strict);
    let mut determinism_gate = DeterminismGate::new();
    let mut pair = GatePair::new(&mut verify_gate, &mut determinism_gate);
    let outcome = run_alloc_sweep(
        &inputs,
        &archives,
        &cfg,
        parsed.parallel(),
        &plan,
        &mut pair,
        &source,
    )
    .map_err(|e| e.to_string())?;

    print!("{}", contents.manifest.render());
    print!("{}", outcome.render());
    let ledger = outcome.ledger();
    let line = alloc_ledger_json(&ledger.label, ledger.runs, &ledger.summary);
    println!("{line}");
    let written = write_alloc_ledger(&ledger.label, ledger.runs, &ledger.summary, out)
        .map_err(|e| e.to_string())?;
    println!("alloc ledger: {} ({written} bytes)", out.display());

    drop(profiler);
    Ok(())
}

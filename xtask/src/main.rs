//! The workspace's developer commands — the `xtask` pattern's crate, run
//! as `cargo run -p xtask -- <command>`.
//!
//! The commands are the two faces of the benchmarks ledger's named
//! follow-up — the nightly shape sweep (docs/BENCHMARKS.md, "How to read
//! these numbers" — "Known follow-ups: … parameterized corpus generator
//! behind an `xtask` for nightly shape sweeps"):
//!
//! - **corpus** writes the generated corpus (the `pgr_fixtures::corpus`
//!   seam's deterministic bytes) and prints the manifest the sweep
//!   records beside its measurements:
//!
//! ```sh
//! cargo run -p xtask -- corpus --out /tmp/sweep/many-tiny \
//!     --preset many-tiny --objects 50
//! ```
//!
//! - **sweep** measures the §9.3 nightly face over a generated corpus —
//!   the observed pipeline run `--runs` times (the contract names ten),
//!   the runs reduced to the median/p95 walls and the per-phase rows
//!   ([`pgr_core::sweep`], the harness seam), the ledger line written to
//!   `--out` (the file the nightly keeps and the next nightly's baseline
//!   compares against):
//!
//! ```sh
//! cargo run -p xtask -- sweep --out /tmp/sweep/many-tiny.json \
//!     --preset many-tiny --runs 10
//! ```
//!
//! The sweep prices the §9.3 budgets beside the walls when `--budgets`
//! rides (`report` the default — the verdict renders with the ledger;
//! `enforce` fails the build on a breach, the calibrated rig job's face;
//! `off` skips the gate): the serial share per pass (`flush` exempt, the
//! plan's own exception) and, when the measured lane is `auto`, the
//! parallel efficiency of Passes 1/3/4 against the 1-thread reference
//! lane the command sweeps beside it ([`pgr_core::budget`], the gate
//! seam).

use std::path::PathBuf;

use pgr_core::budget::{RssSample, check_rss, check_sweep, peak_rss_bytes};
use pgr_core::link::Parallelism;
use pgr_core::sweep::{GatePair, SweepPlan, run_sweep_gated, write_ledger};
use pgr_emit::sweep::{DeterminismGate, VerifyGate};
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus, write_corpus};
use pgr_verify::Options;
use xtask::{
    BudgetsMode, SweepArgs, parse_count, parse_flags, parse_sweep_args, split_corpus, sweep_config,
};

/// The exit code a malformed command line exits with (the driver's usage
/// convention).
const USAGE_EXIT: i32 = 2;
/// The exit code a runtime failure exits with.
const FAILURE_EXIT: i32 = 1;

/// The corpus command's parsed arguments: the preset shape plus one
/// optional override per axis (`None` keeps the preset's default).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct CorpusArgs {
    /// The output directory (required — never a repo-tree default).
    out: Option<PathBuf>,
    /// The preset shape (kebab-case; the default is `many-tiny`).
    preset: Option<CorpusPreset>,
    /// Direct objects (overrides the preset's count).
    objects: Option<usize>,
    /// `__text` payload per object, in KiB.
    text_kib: Option<usize>,
    /// Extra defined symbols per object.
    symbols_per_object: Option<usize>,
    /// Archive members (0 = no archive).
    archive_members: Option<usize>,
    /// `__text` payload per archive member, in KiB.
    member_text_kib: Option<usize>,
}

impl CorpusArgs {
    /// The spec the arguments name: the preset's shape with the parsed
    /// overrides applied.
    fn spec(&self) -> CorpusSpec {
        let base = CorpusSpec::new(self.preset.unwrap_or(CorpusPreset::ManyTiny));
        CorpusSpec {
            preset: base.preset,
            objects: self.objects,
            text_kib: self.text_kib,
            symbols_per_object: self.symbols_per_object,
            archive_members: self.archive_members,
            member_text_kib: self.member_text_kib,
        }
    }
}

/// Applies one flag to the args, refusing unknown names (the surface's
/// own vocabulary is the fix).
fn apply_flag(args: &mut CorpusArgs, flag: &str, value: &str) -> Result<(), String> {
    match flag {
        "out" => {
            args.out = Some(PathBuf::from(value));
            Ok(())
        }
        "preset" => {
            let preset = CorpusPreset::from_name(value).ok_or_else(|| {
                format!(
                    "--preset {value:?} is not a preset name (the presets are {})",
                    [
                        "many-tiny",
                        "large-debug",
                        "archive-heavy",
                        "single-giant",
                        "byte-touching"
                    ]
                    .join(", ")
                )
            })?;
            args.preset = Some(preset);
            Ok(())
        }
        "objects" => {
            args.objects = Some(parse_count(flag, value)?);
            Ok(())
        }
        "text-kib" => {
            args.text_kib = Some(parse_count(flag, value)?);
            Ok(())
        }
        "symbols-per-object" => {
            args.symbols_per_object = Some(parse_count(flag, value)?);
            Ok(())
        }
        "archive-members" => {
            args.archive_members = Some(parse_count(flag, value)?);
            Ok(())
        }
        "member-text-kib" => {
            args.member_text_kib = Some(parse_count(flag, value)?);
            Ok(())
        }
        other => Err(format!(
            "--{other} is not a corpus flag (the flags are --out --preset --objects \
             --text-kib --symbols-per-object --archive-members --member-text-kib)"
        )),
    }
}

/// Parses the corpus command's argument list.
///
/// # Errors
/// A descriptive message for a malformed command line — an unexpected
/// positional, a flag missing its value, an unknown flag, a bad count or
/// a missing `--out`.
fn parse_corpus_args(args: &[String]) -> Result<CorpusArgs, String> {
    let mut parsed = CorpusArgs::default();
    for flag in parse_flags(args)? {
        apply_flag(&mut parsed, flag.name, flag.value)?;
    }
    if parsed.out.is_none() {
        return Err("the corpus command needs --out <dir> (never a repo-tree default)".to_string());
    }
    Ok(parsed)
}

/// Runs the corpus command: writes the generated corpus into `--out` and
/// prints the manifest the sweep records.
///
/// # Errors
/// The generator's or the filesystem's refusal, already worded.
fn run_corpus(args: &CorpusArgs) -> Result<(), String> {
    let out = args.out.as_ref().expect("parse_corpus_args checked --out");
    let spec = args.spec();
    let manifest = write_corpus(&spec, out).map_err(|e| e.to_string())?;
    print!("{}", manifest.render());
    Ok(())
}

/// Runs the sweep command: generates the corpus in memory, sweeps it
/// through the observed pipeline, prints the manifest and the reduced
/// faces, and writes the ledger line to `--out`.
///
/// # Errors
/// The generator's, the pipeline's or the filesystem's refusal, already
/// worded.
fn run_sweep_command(args: &SweepArgs) -> Result<(), String> {
    let out = args.out.as_ref().expect("parse_sweep_args checked --out");
    let spec = args.spec();
    let contents = build_corpus(&spec).map_err(|e| e.to_string())?;
    // The corpus's files split on their kind: the direct objects ride the
    // inputs, the one `libcorpus.a` (when the shape carries one) projects
    // onto the archives — the S7 pull's own input, never a direct parse
    // (the lanes' shared projection, the lib's own face).
    let (inputs, archives) = split_corpus(&contents.files)?;
    let cfg = sweep_config();
    let plan = SweepPlan {
        label: args.label(),
        runs: args.runs(),
    };
    // The strict options (the M73 `-verify` gate's shape): warnings
    // fail, the signature hash recomputed — §9.3's "performance jobs
    // never gate on unverified output" is the nightly's own contract,
    // not a flag.
    let strict = Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    // The nightly's gate pair: every run's image rides the strict
    // verifier (§9.3's correctness half) *and* the byte-equality
    // comparison against the run-0 image (§9.3's determinism half —
    // "double-link byte-equality on every PR (TDD §4.3)"), both outside
    // the measured wall, either refusal aborting the sweep.
    let mut verify_gate = VerifyGate::new(strict);
    let mut determinism_gate = DeterminismGate::new();
    let mut pair = GatePair::new(&mut verify_gate, &mut determinism_gate);
    let outcome = run_sweep_gated(&inputs, &archives, &cfg, args.parallel(), &plan, &mut pair)
        .map_err(|e| e.to_string())?;
    print!("{}", contents.manifest.render());
    print!("{}", outcome.render());
    for stat in verify_gate.stats() {
        println!(
            "verify: run {} strict-clean ({} symbols, {} fixup slots, verify {} µs)",
            stat.run,
            stat.symbols,
            stat.fixup_slots,
            stat.verify_wall.as_micros()
        );
    }
    for stat in determinism_gate.stats() {
        println!(
            "determinism: run {} byte-identical ({} bytes, gate {} µs)",
            stat.run,
            stat.bytes,
            stat.gate_wall.as_micros()
        );
    }
    // The §11 separate-process artifact: the run-0 image written where
    // the CI determinism job's second process writes its own — the two
    // files byte-compare (TDD §11: "twice in separate processes →
    // byte-identical").
    if let Some(path) = &args.determinism {
        let baseline = determinism_gate.baseline_image().ok_or_else(|| {
            "the sweep recorded no run-0 image (the plan's runs are zero)".to_string()
        })?;
        std::fs::write(path, baseline).map_err(|e| e.to_string())?;
        println!(
            "determinism: the run-0 image written to {} ({} bytes) — byte-compare it against \
             the second process's",
            path.display(),
            baseline.len()
        );
    }
    let written = write_ledger(&outcome.label, outcome.runs, &outcome.summary, out)
        .map_err(|e| e.to_string())?;
    println!("ledger: {} ({written} bytes)", out.display());

    // The §9.3 budget gate: the recorded rows priced against the
    // budgets — the serial share per pass (`flush` exempt), and, when
    // the measured lane is the parallel pool, the Passes 1/3/4
    // efficiency against the 1-thread reference lane swept beside it.
    // The walls are stored regardless (the §9.3 "results stored" half —
    // the ledger is data); under `enforce` a breach fails the build.
    let mode = args.budgets_mode();
    if mode != BudgetsMode::Off {
        let measured_lane = args.parallel();
        let reference = if measured_lane == Parallelism::Auto {
            // The 1-thread reference lane sweeps gated too — §9.3's
            // "every benchmark link is also run through `pgr-verify`"
            // names every benchmark link, the reference lane's
            // included, and its bytes ride the same double-link
            // comparison.
            let mut verify_ref = VerifyGate::new(strict);
            let mut determinism_ref = DeterminismGate::new();
            let mut pair_ref = GatePair::new(&mut verify_ref, &mut determinism_ref);
            Some(
                run_sweep_gated(
                    &inputs,
                    &archives,
                    &cfg,
                    Parallelism::Serial,
                    &plan,
                    &mut pair_ref,
                )
                .map_err(|e| e.to_string())?,
            )
        } else {
            None
        };
        let threads = if measured_lane == Parallelism::Auto {
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
        } else {
            1
        };
        let verdict = check_sweep(
            &args.label(),
            &outcome.summary,
            reference.as_ref().map(|r| &r.summary),
            threads,
        );
        print!("{}", verdict.render());
        println!("{}", verdict.render_json());
        // The peak-RSS row (§2.2's note — "peak RSS ≤ 2.5× output (TDD
        // §10.5)"): the process's high-water mark over the sweep priced
        // against the gated image's byte size — the determinism gate's
        // recorded run-0 image is the §2.1 metric's denominator. A
        // platform that does not expose the mark records the honest
        // `None` (the rig's numbers own it), and the calibrated
        // `enforce` face is the rig job's, the tree's own convention.
        let rss = check_rss(peak_rss_bytes().and_then(|peak_bytes| {
            let output_bytes =
                u64::try_from(determinism_gate.baseline_image().map_or(0, <[u8]>::len)).ok()?;
            Some(RssSample {
                peak_bytes,
                output_bytes,
            })
        }));
        print!("{}", rss.render());
        println!("{}", rss.render_json());
        if mode == BudgetsMode::Enforce && (!verdict.is_clean() || rss.breach) {
            return Err(format!(
                "budget gate: {} breach(es) against the §9.3 budgets (the verdict above names \
                 each gate, the measured value and the budget it broke) — the peak-RSS row \
                 breached: {}",
                verdict.breaches.len(),
                rss.render().trim()
            ));
        }
    }
    Ok(())
}

/// Parses the command line into the one command the crate carries.
///
/// # Errors
/// A descriptive message for a missing or unknown command.
fn parse_command(args: &[String]) -> Result<Command, String> {
    match args.first().map(String::as_str) {
        Some("corpus") => Ok(Command::Corpus(parse_corpus_args(&args[1..])?)),
        Some("sweep") => Ok(Command::Sweep(parse_sweep_args(&args[1..])?)),
        Some(other) => Err(format!(
            "unknown command {other:?} (the commands are: corpus, sweep)"
        )),
        None => Err("a command is required: corpus | sweep".to_string()),
    }
}

/// One dispatched command: the parsed arguments and the runner they ride.
#[derive(Debug)]
enum Command {
    /// The corpus generator's face.
    Corpus(CorpusArgs),
    /// The shape-sweep harness's face.
    Sweep(SweepArgs),
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dispatch = parse_command(&args).and_then(|command| match command {
        Command::Corpus(ref parsed) => run_corpus(parsed),
        Command::Sweep(ref parsed) => run_sweep_command(parsed),
    });
    match dispatch {
        Ok(()) => {}
        Err(message) => {
            eprintln!("pgr-xtask: {message}");
            let usage = args.first().is_none_or(|c| c != "corpus" && c != "sweep");
            std::process::exit(if usage { USAGE_EXIT } else { FAILURE_EXIT });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().copied().map(String::from).collect()
    }

    #[test]
    fn corpus_args_parse_the_preset_and_the_out_dir() {
        let parsed = parse_corpus_args(&args(&["--out", "/tmp/sweep", "--preset", "large-debug"]))
            .expect("the command line parses");
        assert_eq!(parsed.out, Some(PathBuf::from("/tmp/sweep")));
        assert_eq!(parsed.preset, Some(CorpusPreset::LargeDebug));
    }

    #[test]
    fn corpus_args_default_to_the_many_tiny_preset() {
        let parsed =
            parse_corpus_args(&args(&["--out", "/tmp/sweep"])).expect("the command line parses");
        assert_eq!(parsed.preset, None, "the default rides the spec's");
        assert_eq!(parsed.spec().preset, CorpusPreset::ManyTiny);
    }

    #[test]
    fn corpus_args_override_the_shape_axes() {
        let parsed = parse_corpus_args(&args(&[
            "--out",
            "/tmp/sweep",
            "--objects",
            "8",
            "--text-kib",
            "2",
            "--symbols-per-object",
            "16",
            "--archive-members",
            "0",
            "--member-text-kib",
            "1",
        ]))
        .expect("the command line parses");
        let shape = parsed.spec().resolved();
        assert_eq!(shape.objects, 8);
        assert_eq!(shape.text_kib, 2);
        assert_eq!(shape.symbols_per_object, 16);
        assert_eq!(shape.archive_members, 0);
        assert_eq!(shape.member_text_kib, 1);
    }

    #[test]
    fn a_missing_out_refuses_with_the_fix() {
        let err = parse_corpus_args(&args(&["--preset", "many-tiny"]))
            .expect_err("the missing --out refuses");
        assert!(
            err.contains("--out"),
            "the refusal names the missing flag: {err}"
        );
    }

    #[test]
    fn unknown_flags_and_bad_counts_refuse_with_the_vocabulary() {
        let err = parse_corpus_args(&args(&["--out", "/tmp", "--bogus", "1"]))
            .expect_err("the unknown flag refuses");
        assert!(err.contains("--bogus"), "the refusal names the flag: {err}");
        let err = parse_corpus_args(&args(&["--out", "/tmp", "--objects", "eight"]))
            .expect_err("the bad count refuses");
        assert!(
            err.contains("--objects"),
            "the refusal names the flag: {err}"
        );
        let err = parse_corpus_args(&args(&["--out"])).expect_err("the valueless flag refuses");
        assert!(err.contains("value"), "the refusal names the shape: {err}");
    }

    #[test]
    fn sweep_args_default_to_the_nightly_contract() {
        let parsed = parse_sweep_args(&args(&["--out", "/tmp/ledger.json"]))
            .expect("the command line parses");
        assert_eq!(
            parsed.runs(),
            10,
            "the §9.3 contract's ten runs is the default"
        );
        assert_eq!(
            parsed.parallel(),
            Parallelism::Auto,
            "the M4 lane is the default"
        );
        assert_eq!(parsed.spec().preset, CorpusPreset::ManyTiny);
        let label = parsed.label();
        assert!(
            label.contains("many-tiny") && label.contains("objects=50"),
            "the label names the preset and the axes: {label}"
        );
    }

    #[test]
    fn sweep_args_parse_the_runs_and_the_lane() {
        let parsed = parse_sweep_args(&args(&[
            "--out",
            "/tmp/ledger.json",
            "--runs",
            "3",
            "--parallel",
            "serial",
            "--preset",
            "large-debug",
        ]))
        .expect("the command line parses");
        assert_eq!(parsed.runs(), 3);
        assert_eq!(parsed.parallel(), Parallelism::Serial);
        assert_eq!(parsed.spec().preset, CorpusPreset::LargeDebug);
        let err = parse_sweep_args(&args(&["--out", "/tmp/l.json", "--parallel", "turbo"]))
            .expect_err("the unknown lane refuses");
        assert!(err.contains("auto"), "the refusal names the lanes: {err}");
        let err = parse_sweep_args(&args(&["--runs", "0"])).expect_err("zero runs refuse");
        assert!(
            err.contains("at least one run"),
            "the refusal names the fix: {err}"
        );
        let err =
            parse_sweep_args(&args(&["--runs", "3"])).expect_err("the missing ledger refuses");
        assert!(err.contains("--out"), "the refusal names the flag: {err}");
    }

    #[test]
    fn sweep_args_parse_the_budget_gate_modes() {
        let parsed =
            parse_sweep_args(&args(&["--out", "/tmp/l.json"])).expect("the command line parses");
        assert_eq!(
            parsed.budgets_mode(),
            BudgetsMode::Report,
            "report is the default — the verdict rides, the build holds"
        );
        let parsed = parse_sweep_args(&args(&["--out", "/tmp/l.json", "--budgets", "off"]))
            .expect("the command line parses");
        assert_eq!(parsed.budgets_mode(), BudgetsMode::Off);
        let parsed = parse_sweep_args(&args(&["--out", "/tmp/l.json", "--budgets", "enforce"]))
            .expect("the command line parses");
        assert_eq!(parsed.budgets_mode(), BudgetsMode::Enforce);
        let err = parse_sweep_args(&args(&["--out", "/tmp/l.json", "--budgets", "strict"]))
            .expect_err("the unknown mode refuses");
        assert!(
            err.contains("off, report and enforce"),
            "the refusal names the modes: {err}"
        );
    }

    #[test]
    fn the_command_name_gates_the_parse() {
        let err = parse_command(&args(&["link"])).expect_err("the unknown command refuses");
        assert!(
            err.contains("corpus") && err.contains("sweep"),
            "the refusal names the commands: {err}"
        );
        let err = parse_command(&args(&[])).expect_err("the missing command refuses");
        assert!(
            err.contains("corpus"),
            "the refusal names the command: {err}"
        );
        let parsed = parse_command(&args(&["sweep", "--out", "/tmp/l.json"]))
            .expect("the sweep command dispatches");
        assert!(matches!(parsed, Command::Sweep(_)));
    }
}

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

use pgr_core::budget::check_sweep;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism};
use pgr_core::sweep::{SweepPlan, write_ledger};
use pgr_emit::sweep::run_verified_sweep;
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus, write_corpus};
use pgr_verify::Options;

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

/// One parsed flag: its name and the value token that followed it.
struct Flag<'a> {
    name: &'a str,
    value: &'a str,
}

/// Parses `--flag value` pairs out of the argument list — the value rides
/// the next token (the driver's two-token flag shape). An odd trailing
/// flag or an unknown name refuses with the fix named.
fn parse_flags(args: &[String]) -> Result<Vec<Flag<'_>>, String> {
    let mut flags = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if !arg.starts_with("--") {
            return Err(format!(
                "unexpected argument {arg:?} (the corpus command reads --flags only)"
            ));
        }
        let Some(value) = args.get(i + 1) else {
            return Err(format!(
                "{arg} needs a value (the flags are two-token: --flag value)"
            ));
        };
        flags.push(Flag {
            name: &arg[2..],
            value,
        });
        i += 2;
    }
    Ok(flags)
}

/// Parses an unsigned count for the flags that take one.
fn parse_count(flag: &str, value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("--{flag} {value:?} is not a non-negative integer"))
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

/// The sweep command's parsed arguments: the corpus shape (the corpus
/// command's axes), the run count and the ledger file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct SweepArgs {
    /// The ledger file to write (required — never a repo-tree default).
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
    /// Recorded runs (the §9.3 contract names 10; the default rides it).
    runs: Option<usize>,
    /// `auto` (the M4 parallel pipeline, the default) or `serial` (the
    /// determinism lane).
    parallel: Option<String>,
    /// The §9.3 budget gate's mode (`off`, `report` — the default — or
    /// `enforce`; the calibrated rig job's face).
    budgets: Option<String>,
}

/// The `--budgets` flag's parsed mode (the §9.3 gate's three faces).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum BudgetsMode {
    /// Skip the gate entirely (the walls-only ledger face).
    Off,
    /// Price the budgets and render the verdict; never fail the build
    /// (the dev-class runner's honest face — the thresholds are the
    /// §9.1 rig job's calibration).
    #[default]
    Report,
    /// Price the budgets and fail the build on a breach (the rig job's
    /// face — §9.3's "fail the build if").
    Enforce,
}

impl SweepArgs {
    /// The spec the arguments name: the preset's shape with the parsed
    /// overrides applied (the corpus command's own projection).
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

    /// The recorded-run count (the §9.3 nightly contract's ten).
    fn runs(&self) -> usize {
        self.runs.unwrap_or(10)
    }

    /// The lane the sweep rides: the M4 parallel pipeline by default, the
    /// serial determinism lane under `--parallel serial`.
    fn parallel(&self) -> Parallelism {
        match self.parallel.as_deref() {
            Some("serial") => Parallelism::Serial,
            _ => Parallelism::Auto,
        }
    }

    /// The budget gate's mode (`report` the default).
    fn budgets_mode(&self) -> BudgetsMode {
        match self.budgets.as_deref() {
            Some("off") => BudgetsMode::Off,
            Some("enforce") => BudgetsMode::Enforce,
            _ => BudgetsMode::Report,
        }
    }

    /// The ledger's shape label: the preset and the effective axes, in a
    /// stable order — the string the next nightly's baseline names.
    fn label(&self) -> String {
        let shape = self.spec().resolved();
        format!(
            "{} objects={} text_kib={} syms_per_obj={} archive_members={}",
            self.spec().preset.name(),
            shape.objects,
            shape.text_kib,
            shape.symbols_per_object,
            shape.archive_members,
        )
    }
}

/// Applies one sweep flag to the args, refusing unknown names (the
/// surface's own vocabulary is the fix). The shape axes ride the corpus
/// command's projection; `--runs` and `--parallel` are the sweep's own.
fn apply_sweep_flag(args: &mut SweepArgs, flag: &str, value: &str) -> Result<(), String> {
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
        "runs" => {
            args.runs = Some(parse_count(flag, value)?);
            Ok(())
        }
        "parallel" => {
            if value != "auto" && value != "serial" {
                return Err(format!(
                    "--parallel {value:?} is not a lane (the lanes are auto and serial)"
                ));
            }
            args.parallel = Some(value.to_string());
            Ok(())
        }
        "budgets" => {
            if value != "off" && value != "report" && value != "enforce" {
                return Err(format!(
                    "--budgets {value:?} is not a mode (the modes are off, report and enforce)"
                ));
            }
            args.budgets = Some(value.to_string());
            Ok(())
        }
        other => Err(format!(
            "--{other} is not a sweep flag (the flags are --out --preset --objects --text-kib \
             --symbols-per-object --archive-members --member-text-kib --runs --parallel --budgets)"
        )),
    }
}

/// Parses the sweep command's argument list.
///
/// # Errors
/// A descriptive message for a malformed command line — an unexpected
/// positional, a flag missing its value, an unknown flag, a bad count or
/// a missing `--out`.
fn parse_sweep_args(args: &[String]) -> Result<SweepArgs, String> {
    let mut parsed = SweepArgs::default();
    for flag in parse_flags(args)? {
        apply_sweep_flag(&mut parsed, flag.name, flag.value)?;
    }
    if parsed.runs() == 0 {
        return Err("--runs 0 records nothing — plan at least one run".to_string());
    }
    if parsed.out.is_none() {
        return Err(
            "the sweep command needs --out <ledger.json> (the file the nightly keeps)".to_string(),
        );
    }
    Ok(parsed)
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
    // onto the archives — the S7 pull's own input, never a direct parse.
    let mut inputs = Vec::new();
    let mut archives = Vec::new();
    for (name, bytes) in &contents.files {
        if name
            .rsplit_once('.')
            .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("a"))
        {
            archives.push(
                pgr_core::sweep::archive_input(name, bytes.clone()).map_err(|e| e.to_string())?,
            );
        } else {
            inputs.push(LinkInput {
                name: name.clone(),
                bytes: bytes.clone(),
            });
        }
    }
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let plan = SweepPlan {
        label: args.label(),
        runs: args.runs(),
    };
    let outcome = run_verified_sweep(
        &inputs,
        &archives,
        &cfg,
        args.parallel(),
        &plan,
        // The strict pass (the M73 `-verify` gate's shape): warnings
        // fail, the signature hash recomputed — §9.3's "performance
        // jobs never gate on unverified output" is the nightly's own
        // contract, not a flag.
        &Options {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    )
    .map_err(|e| e.to_string())?;
    print!("{}", contents.manifest.render());
    print!("{}", outcome.outcome.render());
    for stat in outcome.gate.stats() {
        println!(
            "verify: run {} strict-clean ({} symbols, {} fixup slots, verify {} µs)",
            stat.run,
            stat.symbols,
            stat.fixup_slots,
            stat.verify_wall.as_micros()
        );
    }
    let written = write_ledger(
        &outcome.outcome.label,
        outcome.outcome.runs,
        &outcome.outcome.summary,
        out,
    )
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
            Some(
                run_verified_sweep(
                    &inputs,
                    &archives,
                    &cfg,
                    Parallelism::Serial,
                    &plan,
                    &Options {
                        strict_warnings: true,
                        skip_hash_recompute: false,
                    },
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
            &outcome.outcome.summary,
            reference.as_ref().map(|r| &r.outcome.summary),
            threads,
        );
        print!("{}", verdict.render());
        println!("{}", verdict.render_json());
        if mode == BudgetsMode::Enforce && !verdict.is_clean() {
            return Err(format!(
                "budget gate: {} breach(es) against the §9.3 budgets (the verdict above names \
                 each gate, the measured value and the budget it broke)",
                verdict.breaches.len()
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

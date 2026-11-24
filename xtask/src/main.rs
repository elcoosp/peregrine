//! The workspace's developer commands — the `xtask` pattern's crate, run
//! as `cargo run -p xtask -- <command>`.
//!
//! The first command is the one the benchmarks ledger names as a
//! follow-up: the **parameterized corpus generator** for nightly shape
//! sweeps (docs/BENCHMARKS.md, "How to read these numbers" — "Known
//! follow-ups: … parameterized corpus generator behind an `xtask` for
//! nightly shape sweeps"). The generator itself is the
//! `pgr_fixtures::corpus` seam; this crate is the CLI face the ledger
//! names — the command a nightly shape-sweep job drives:
//!
//! ```sh
//! cargo run -p xtask -- corpus --out /tmp/sweep/many-tiny \
//!     --preset many-tiny --objects 50
//! ```
//!
//! The command writes the generated corpus (deterministic bytes — the
//! BENCHMARKS corpora contract) under zero-padded command-line-ordered
//! names and prints the manifest the sweep records beside its
//! measurements.

use std::path::PathBuf;

use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, write_corpus};

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
                    ["many-tiny", "large-debug", "archive-heavy", "single-giant"].join(", ")
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

/// Parses the command line into the one command the crate carries.
///
/// # Errors
/// A descriptive message for a missing or unknown command.
fn parse_command(args: &[String]) -> Result<CorpusArgs, String> {
    match args.first().map(String::as_str) {
        Some("corpus") => parse_corpus_args(&args[1..]),
        Some(other) => Err(format!(
            "unknown command {other:?} (the commands are: corpus)"
        )),
        None => Err("a command is required: corpus".to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_command(&args).and_then(|parsed| run_corpus(&parsed)) {
        Ok(()) => {}
        Err(message) => {
            eprintln!("pgr-xtask: {message}");
            let usage = args.first().is_none_or(|c| c != "corpus");
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
    fn the_command_name_gates_the_parse() {
        let err = parse_command(&args(&["link"])).expect_err("the unknown command refuses");
        assert!(
            err.contains("corpus"),
            "the refusal names the commands: {err}"
        );
        let err = parse_command(&args(&[])).expect_err("the missing command refuses");
        assert!(
            err.contains("corpus"),
            "the refusal names the command: {err}"
        );
    }
}

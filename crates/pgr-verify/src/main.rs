//! `pgr-verify` CLI: verify Mach-O files against the Peregrine contract.
//!
//! Exit codes: 0 = clean (or warnings without `--strict`), 1 = issues, 2 =
//! usage / IO error. `--json` emits a machine-readable report (the
//! library's `report_json` shape — one writer for the binary and the
//! library). `--baseline <file>` gates the run on the previous report:
//! only *new* findings fail (`--fail-on any` restores the whole verdict).

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use pgr_verify::{
    BaselineDelta, CheckSet, IssueIdentity as _, OffsetIdentity, Options, Severity,
    verify_with_checks,
};

/// Program name.
const PROGRAM: &str = "pgr-verify";

/// What the exit code answers: the whole verdict, or only the findings
/// the baseline does not vouch for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailOn {
    /// Any issue fails (the historical gate; `is_ok`).
    Any,
    /// Only introduced findings fail (the baseline gate).
    New,
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut files: Vec<PathBuf> = Vec::new();
    let mut json = false;
    let mut strict = false;
    let mut quiet = false;
    let mut skip_hashes = false;
    let mut checks: Option<CheckSet> = None;
    let mut baseline: Option<PathBuf> = None;
    let mut fail_on: Option<FailOn> = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--json" => json = true,
            "--strict" => strict = true,
            "--quiet" | "-q" => quiet = true,
            "--skip-hash-recompute" => skip_hashes = true,
            "--list-checks" => {
                print_checks();
                return ExitCode::SUCCESS;
            }
            "--checks" => {
                i += 1;
                let Some(value) = argv.get(i) else {
                    eprintln!("{PROGRAM}: --checks needs a comma-separated list (try --help)");
                    return ExitCode::from(2);
                };
                match CheckSet::parse(value) {
                    Ok(set) => checks = Some(set),
                    Err(e) => {
                        eprintln!("{PROGRAM}: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            "--baseline" => {
                i += 1;
                let Some(value) = argv.get(i) else {
                    eprintln!(
                        "{PROGRAM}: --baseline needs the previous report's JSON path (try --help)"
                    );
                    return ExitCode::from(2);
                };
                baseline = Some(PathBuf::from(value));
            }
            "--fail-on" => {
                i += 1;
                let Some(value) = argv.get(i) else {
                    eprintln!("{PROGRAM}: --fail-on needs `new` or `any` (try --help)");
                    return ExitCode::from(2);
                };
                match value.as_str() {
                    "new" => fail_on = Some(FailOn::New),
                    "any" => fail_on = Some(FailOn::Any),
                    other => {
                        eprintln!("{PROGRAM}: unknown --fail-on value `{other}` (valid: new, any)");
                        return ExitCode::from(2);
                    }
                }
            }
            "--help" | "-h" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            "--version" | "-V" => {
                println!("{PROGRAM} {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            other => files.push(PathBuf::from(other)),
        }
        i += 1;
    }
    if files.is_empty() {
        eprintln!("{PROGRAM}: no input files (try --help)");
        return ExitCode::from(2);
    }
    if let Some(b) = &baseline {
        if files.len() > 1 {
            eprintln!(
                "{PROGRAM}: --baseline gates one file ({} named); run one invocation per image",
                files.len()
            );
            return ExitCode::from(2);
        }
        if !b.exists() {
            eprintln!(
                "{PROGRAM}: {}: baseline report not found (a first link has no baseline; verify without --baseline and save its --json output)",
                b.display()
            );
            return ExitCode::from(2);
        }
    }
    if fail_on.is_some() && baseline.is_none() {
        eprintln!(
            "{PROGRAM}: --fail-on gates against a baseline; pass --baseline <path> (without one the whole verdict already runs)"
        );
        return ExitCode::from(2);
    }
    // The gate the exit code answers: explicit --fail-on wins; a
    // baseline defaults to new-findings-only, no baseline keeps the
    // historical whole-verdict gate.
    let fail_on = fail_on.unwrap_or(if baseline.is_some() {
        FailOn::New
    } else {
        FailOn::Any
    });
    let opts = Options {
        strict_warnings: strict,
        skip_hash_recompute: skip_hashes,
    };
    let checks = checks.unwrap_or_else(CheckSet::all);
    let baseline_prev: Option<Vec<pgr_verify::Issue>> = match baseline.as_deref() {
        Some(path) => match load_baseline(path) {
            Ok(issues) => Some(issues),
            Err(e) => {
                eprintln!("{PROGRAM}: {e}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut any_bad = false;
    let mut any_io = false;

    for file in &files {
        let bytes = match std::fs::read(file) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{PROGRAM}: {}: {e}", file.display());
                any_io = true;
                continue;
            }
        };
        let report = verify_with_checks(&bytes, &opts, &checks);
        let delta = baseline_prev
            .as_deref()
            .map(|prev| BaselineDelta::between(prev, &report.issues, &OffsetIdentity));
        if json {
            let body = match &delta {
                Some(delta) => pgr_verify::to_json_with_baseline(
                    &file.display().to_string(),
                    &report,
                    delta,
                    OffsetIdentity.name(),
                ),
                None => pgr_verify::to_json_with_file(&file.display().to_string(), &report),
            };
            if let Err(e) = writeln!(out, "{body}") {
                eprintln!("{PROGRAM}: {e}");
                any_io = true;
            }
        } else if !quiet {
            let _ = writeln!(
                out,
                "{}: {}",
                file.display(),
                report_label(&report, opts, delta.as_ref(), fail_on)
            );
            for issue in &report.issues {
                let sev = match issue.severity {
                    Severity::Error => "error",
                    Severity::Warning => "warning",
                };
                let at = issue
                    .offset
                    .map(|o| format!(" at {o:#x}"))
                    .unwrap_or_default();
                let _ = writeln!(
                    out,
                    "  {sev} [{}] {}{at}",
                    issue.code.as_str(),
                    issue.message
                );
            }
            if let Some(delta) = &delta {
                for issue in &delta.introduced {
                    let _ = writeln!(
                        out,
                        "  + [{}] {} (new since the baseline)",
                        issue.code.as_str(),
                        issue.message
                    );
                }
                for issue in &delta.resolved {
                    let _ = writeln!(
                        out,
                        "  - [{}] {} (resolved since the baseline)",
                        issue.code.as_str(),
                        issue.message
                    );
                }
                let _ = writeln!(
                    out,
                    "  baseline: {} new, {} resolved, {} surviving ({})",
                    delta.introduced.len(),
                    delta.resolved.len(),
                    delta.surviving,
                    OffsetIdentity.name(),
                );
            }
        }
        let bad = match &delta {
            // The baseline gate: only what the baseline does not vouch
            // for fails (fail-on=new); `any` keeps the whole verdict.
            Some(delta) => match fail_on {
                FailOn::New => !delta.is_clean(),
                FailOn::Any => !report.is_ok(&opts),
            },
            None => !report.is_ok(&opts),
        };
        if bad {
            any_bad = true;
        }
    }
    if any_io {
        ExitCode::from(2)
    } else if any_bad {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn report_label(
    report: &pgr_verify::Report,
    opts: Options,
    delta: Option<&BaselineDelta>,
    fail_on: FailOn,
) -> &'static str {
    let bad = match delta {
        Some(delta) => match fail_on {
            FailOn::New => !delta.is_clean(),
            FailOn::Any => !report.is_ok(&opts),
        },
        None => !report.is_ok(&opts),
    };
    if bad { "FAILED" } else { "OK" }
}

/// Reads and parses the baseline report (the CLI's own `--json` output
/// from the last accepted image — the library reader accepts both the
/// wrapped and the body shape).
fn load_baseline(path: &std::path::Path) -> Result<Vec<pgr_verify::Issue>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let report = pgr_verify::parse_report_json(&text).map_err(|e| {
        format!(
            "{}: {e} (a baseline is a previous run's --json report)",
            path.display()
        )
    })?;
    Ok(report.issues)
}

/// The selector surface, one line per family (the `--list-checks` view).
fn print_checks() {
    for unit in pgr_verify::image_checks() {
        println!("{:<14} {}", unit.name(), unit.summary());
    }
}

fn print_help() {
    println!(
        "{PROGRAM} {} — Peregrine read-side Mach-O verifier (M0)\n\n\
         USAGE:\n    pgr-verify [OPTIONS] <mach-o-file>...\n\n\
         OPTIONS:\n    --json                  Machine-readable report\n    --strict                Treat warnings as failures\n    --quiet, -q             Only set the exit code\n    --skip-hash-recompute   Skip SHA-256 page-hash verification\n    --checks <a,b,...>      Run only the named families (e.g. segments,fixups)\n    --list-checks           Print the families and exit\n    --baseline <path>       Gate on a previous --json report: only NEW\n                            findings fail (one file per invocation)\n    --fail-on new|any       What fails: introduced findings only (default\n                            with --baseline) or the whole verdict\n    --help, -h              This help\n    --version, -V           Version\n\n\
         EXIT:\n    0 clean · 1 issues · 2 usage/IO error",
        env!("CARGO_PKG_VERSION")
    );
}

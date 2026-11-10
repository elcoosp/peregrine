//! `pgr-verify` CLI: verify Mach-O files against the Peregrine contract.
//!
//! Exit codes: 0 = clean (or warnings without `--strict`), 1 = issues, 2 =
//! usage / IO error. `--json` emits a machine-readable report.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use pgr_verify::{CheckSet, Options, Severity, verify_with_checks};

/// Program name.
const PROGRAM: &str = "pgr-verify";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut files: Vec<PathBuf> = Vec::new();
    let mut json = false;
    let mut strict = false;
    let mut quiet = false;
    let mut skip_hashes = false;
    let mut checks: Option<CheckSet> = None;
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

    let opts = Options {
        strict_warnings: strict,
        skip_hash_recompute: skip_hashes,
    };
    let checks = checks.unwrap_or_else(CheckSet::all);
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
        if json {
            if let Err(e) = write_json(&mut out, file, &report) {
                eprintln!("{PROGRAM}: {e}");
                any_io = true;
            }
        } else if !quiet {
            let _ = writeln!(out, "{}: {}", file.display(), report_label(&report, opts));
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
        }
        if !report.is_ok(&opts) {
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

fn report_label(report: &pgr_verify::Report, opts: Options) -> &'static str {
    if report.is_ok(&opts) { "OK" } else { "FAILED" }
}

/// The selector surface, one line per family (the `--list-checks` view).
fn print_checks() {
    for unit in pgr_verify::image_checks() {
        println!("{:<14} {}", unit.name(), unit.summary());
    }
}

/// Minimal dependency-free JSON writer with proper string escaping.
fn write_json<W: std::io::Write>(
    out: &mut W,
    file: &std::path::Path,
    report: &pgr_verify::Report,
) -> std::io::Result<()> {
    let json_string = |s: &str| -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(format!("\\u{:04x}", c as u32).as_str()),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    };
    write!(
        out,
        "{{\"file\":{},",
        json_string(&file.display().to_string())
    )?;
    write!(
        out,
        "\"stats\":{{\"segments\":{},\"sections\":{},\"symbols\":{},\"fixup_slots\":{},\"hash_pages\":{}}},",
        report.stats.segments,
        report.stats.sections,
        report.stats.symbols,
        report.stats.fixup_slots,
        report.stats.hash_pages
    )?;
    write!(out, "\"issues\":[")?;
    for (i, issue) in report.issues.iter().enumerate() {
        if i > 0 {
            write!(out, ",")?;
        }
        let sev = match issue.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        let offset = match issue.offset {
            Some(o) => o.to_string(),
            None => "null".into(),
        };
        write!(
            out,
            "{{\"severity\":{},\"code\":{},\"message\":{},\"offset\":{}}}",
            json_string(sev),
            json_string(issue.code.as_str()),
            json_string(&issue.message),
            offset
        )?;
    }
    writeln!(out, "]}}")
}

fn print_help() {
    println!(
        "{PROGRAM} {} — Peregrine read-side Mach-O verifier (M0)\n\n\
         USAGE:\n    pgr-verify [OPTIONS] <mach-o-file>...\n\n\
         OPTIONS:\n    --json                  Machine-readable report\n    --strict                Treat warnings as failures\n    --quiet, -q             Only set the exit code\n    --skip-hash-recompute   Skip SHA-256 page-hash verification\n    --checks <a,b,...>      Run only the named families (e.g. segments,fixups)\n    --list-checks           Print the families and exit\n    --help, -h              This help\n    --version, -V           Version\n\n\
         EXIT:\n    0 clean · 1 issues · 2 usage/IO error",
        env!("CARGO_PKG_VERSION")
    );
}

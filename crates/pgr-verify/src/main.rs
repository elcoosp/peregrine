//! `pgr-verify` CLI: verify Mach-O files against the Peregrine contract.
//!
//! Exit codes: 0 = clean (or warnings without `--strict`), 1 = issues, 2 =
//! usage / IO error. `--json` emits a machine-readable report (the
//! library's `report_json` shape — one writer for the binary and the
//! library). `--sarif` emits the M69 SARIF 2.1.0 document the
//! ecosystem's triage reads natively (one machine face per run).
//! `--baseline <file>` gates the run on the previous report:
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
    let mut sarif = false;
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
            "--sarif" => sarif = true,
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
    // The machine faces are one writer per run (M75): the SARIF document
    // and the M13 report are two shapes for one verdict, not two halves
    // of one output.
    if sarif && json {
        eprintln!("{PROGRAM}: --sarif and --json are two machine faces; run one per invocation");
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
    // The baseline loads at the face that reads it (M96): a universal
    // container's document is the container's own --json output — one
    // report line per declared slice — which the single-image reader
    // cannot parse, so the container face loads it through the
    // container reader and the single-image face keeps its own. (The
    // gate is one file per invocation — the load runs once either way.)

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
        // The M74 container face: a universal ("fat") container is not
        // one image — the single-image pass would refuse the fat magic
        // and never name the slice. The table's declared slices each get
        // their own verdict (the check selection composes), and the exit
        // gate is every slice's.
        if pgr_format::universal::is_universal(&bytes) {
            // The M95 container face: the M71 container verdict composed
            // with the M69 render — one deterministic SARIF document, one
            // run per declared slice, the anchors container-absolute (the
            // slices ride inside the audited file, so the anchor names
            // its own bytes). The M75 refusal retires with its premise.
            if sarif {
                let report = match pgr_verify::verify_universal_with_checks(&bytes, &opts, &checks)
                {
                    Ok(report) => report,
                    Err(e) => {
                        if !quiet
                            && !text_writeln(
                                &mut out,
                                format_args!("{}: REFUSED: {e}", file.display()),
                            )
                        {
                            any_io = true;
                        }
                        any_bad = true;
                        continue;
                    }
                };
                // The M97 face: the M95 whole-verdict document, or the
                // M96 baseline gate stated per slice (SARIF 2.1.0's own
                // `baselineState` — the M75 refusal's premise retired).
                let body = match &baseline {
                    Some(baseline_path) => {
                        match load_container_baseline(baseline_path).and_then(|document| {
                            pgr_verify::sarif::render_universal_with_baseline(
                                &report,
                                &document,
                                &OffsetIdentity,
                                &file.display().to_string(),
                            )
                            .map_err(|e| e.to_string())
                        }) {
                            Ok(body) => body,
                            Err(e) => {
                                eprintln!("{PROGRAM}: {}: {e}", file.display());
                                return ExitCode::from(2);
                            }
                        }
                    }
                    None => {
                        pgr_verify::sarif::render_universal(&report, &file.display().to_string())
                    }
                };
                if let Err(e) = writeln!(out, "{body}") {
                    eprintln!("{PROGRAM}: {e}");
                    any_io = true;
                }
                if !report.is_ok(&opts) {
                    any_bad = true;
                }
                continue;
            }
            // The M96 container baseline face: the M74 refusal ("the
            // baseline identity gates one image's offsets, never a slice
            // table") retires with its premise — the slices ride *inside*
            // the audited file and every slice's verdict is its own M13
            // report, so the container's own --json output is the
            // baseline document, paired slice by slice
            // (`UniversalDelta::between_slices`: positional, window-checked).
            if let Some(baseline_path) = &baseline {
                let baseline_prev = match load_container_baseline(baseline_path) {
                    Ok(document) => document,
                    Err(e) => {
                        eprintln!("{PROGRAM}: {e}");
                        return ExitCode::from(2);
                    }
                };
                let report = match pgr_verify::verify_universal_with_checks(&bytes, &opts, &checks)
                {
                    Ok(report) => report,
                    Err(e) => {
                        if !quiet
                            && !text_writeln(
                                &mut out,
                                format_args!("{}: REFUSED: {e}", file.display()),
                            )
                        {
                            any_io = true;
                        }
                        any_bad = true;
                        continue;
                    }
                };
                let universal_delta = match pgr_verify::UniversalDelta::between_slices(
                    &report,
                    &baseline_prev,
                    &OffsetIdentity,
                ) {
                    Ok(delta) => delta,
                    Err(e) => {
                        eprintln!("{PROGRAM}: {}: {e}", file.display());
                        return ExitCode::from(2);
                    }
                };
                let stdout_file = file.display().to_string();
                for (i, verdict) in report.slices.iter().enumerate() {
                    let slice_delta = &universal_delta.slices[i].delta;
                    let label = pgr_verify::universal::slice_label(&stdout_file, i, &verdict.arch);
                    let bad = match fail_on {
                        FailOn::New => !slice_delta.is_clean(),
                        FailOn::Any => !verdict.report.is_ok(&opts),
                    };
                    if json {
                        let body = pgr_verify::to_json_with_baseline(
                            &label,
                            &verdict.report,
                            slice_delta,
                            OffsetIdentity.name(),
                        );
                        if let Err(e) = writeln!(out, "{body}") {
                            eprintln!("{PROGRAM}: {e}");
                            any_io = true;
                        }
                    } else if !quiet {
                        if !text_writeln(
                            &mut out,
                            format_args!("{label}: {}", if bad { "FAILED" } else { "OK" }),
                        ) {
                            any_io = true;
                        }
                        for issue in &verdict.report.issues {
                            let sev = match issue.severity {
                                Severity::Error => "error",
                                Severity::Warning => "warning",
                            };
                            let at = issue
                                .offset
                                .map(|o| format!(" at {o:#x}"))
                                .unwrap_or_default();
                            if !text_writeln(
                                &mut out,
                                format_args!(
                                    "  {sev} [{}] {}{at}",
                                    issue.code.as_str(),
                                    issue.message
                                ),
                            ) {
                                any_io = true;
                            }
                        }
                        for issue in &slice_delta.introduced {
                            if !text_writeln(
                                &mut out,
                                format_args!(
                                    "  + [{}] {} (new since the baseline)",
                                    issue.code.as_str(),
                                    issue.message
                                ),
                            ) {
                                any_io = true;
                            }
                        }
                        for issue in &slice_delta.resolved {
                            if !text_writeln(
                                &mut out,
                                format_args!(
                                    "  - [{}] {} (resolved since the baseline)",
                                    issue.code.as_str(),
                                    issue.message
                                ),
                            ) {
                                any_io = true;
                            }
                        }
                        if !text_writeln(
                            &mut out,
                            format_args!(
                                "  baseline: {} new, {} resolved, {} surviving ({})",
                                slice_delta.introduced.len(),
                                slice_delta.resolved.len(),
                                slice_delta.surviving,
                                OffsetIdentity.name(),
                            ),
                        ) {
                            any_io = true;
                        }
                    }
                    if bad {
                        any_bad = true;
                    }
                }
                continue;
            }
            let (bad, io_failed) =
                universal_face(file, &bytes, opts, checks, json, quiet, &mut out);
            if bad {
                any_bad = true;
            }
            if io_failed {
                any_io = true;
            }
            continue;
        }
        let report = verify_with_checks(&bytes, &opts, &checks);
        // The M13 baseline gate, loaded at its own face: the previous
        // report's issues classify the fresh ones (the delta is `Some`
        // exactly when a baseline rides — the exit gate's contract).
        let delta = match baseline.as_deref() {
            Some(path) => match load_baseline(std::path::Path::new(path)) {
                Ok(prev) => Some(BaselineDelta::between(
                    &prev,
                    &report.issues,
                    &OffsetIdentity,
                )),
                Err(e) => {
                    eprintln!("{PROGRAM}: {e}");
                    return ExitCode::from(2);
                }
            },
            None => None,
        };
        if sarif {
            // The M75 face, stated since M97: the M69 render, or the M13
            // delta carried on SARIF 2.1.0's own `baselineState` when a
            // baseline rides — the refusal's premise retired.
            let body = match &delta {
                Some(delta) => pgr_verify::sarif::render_with_baseline(
                    &report,
                    delta,
                    &OffsetIdentity,
                    &file.display().to_string(),
                ),
                None => pgr_verify::sarif::render(&report, &file.display().to_string()),
            };
            if let Err(e) = writeln!(out, "{body}") {
                eprintln!("{PROGRAM}: {e}");
                any_io = true;
            }
        } else if json {
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
            if !text_writeln(
                &mut out,
                format_args!(
                    "{}: {}",
                    file.display(),
                    report_label(&report, opts, delta.as_ref(), fail_on)
                ),
            ) {
                any_io = true;
            }
            for issue in &report.issues {
                let sev = match issue.severity {
                    Severity::Error => "error",
                    Severity::Warning => "warning",
                };
                let at = issue
                    .offset
                    .map(|o| format!(" at {o:#x}"))
                    .unwrap_or_default();
                if !text_writeln(
                    &mut out,
                    format_args!("  {sev} [{}] {}{at}", issue.code.as_str(), issue.message),
                ) {
                    any_io = true;
                }
            }
            if let Some(delta) = &delta {
                for issue in &delta.introduced {
                    if !text_writeln(
                        &mut out,
                        format_args!(
                            "  + [{}] {} (new since the baseline)",
                            issue.code.as_str(),
                            issue.message
                        ),
                    ) {
                        any_io = true;
                    }
                }
                for issue in &delta.resolved {
                    if !text_writeln(
                        &mut out,
                        format_args!(
                            "  - [{}] {} (resolved since the baseline)",
                            issue.code.as_str(),
                            issue.message
                        ),
                    ) {
                        any_io = true;
                    }
                }
                if !text_writeln(
                    &mut out,
                    format_args!(
                        "  baseline: {} new, {} resolved, {} surviving ({})",
                        delta.introduced.len(),
                        delta.resolved.len(),
                        delta.surviving,
                        OffsetIdentity.name(),
                    ),
                ) {
                    any_io = true;
                }
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

/// The text faces' write helper (the json/sarif faces' own convention):
/// a failed write prints the error beside the run instead of a silently
/// dropped line — a broken pipe is an exit-code matter, never noise.
fn text_writeln(out: &mut dyn std::io::Write, line: std::fmt::Arguments<'_>) -> bool {
    if let Err(e) = writeln!(out, "{line}") {
        eprintln!("{PROGRAM}: {e}");
        return false;
    }
    true
}

/// The M74 container face: one verdict per declared slice. The text face
/// prints a `slice N` line per table row (the OK/FAILED words the
/// single-image face rides) with the issues in the verifier's own words;
/// the `--json` face serves one M13 document per slice, the `file` field
/// naming the slice it rode — each line the strict reader's own shape.
/// The malformed table refuses (`REFUSED`, the format reader's
/// offset-tagged error verbatim — there is nothing to slice). Returns
/// (gate fails, a write failed) — the caller's exit code honors both, the
/// text face's write errors the json face's own convention (printed, the
/// run marked, never a silently dropped line).
fn universal_face(
    file: &std::path::Path,
    bytes: &[u8],
    opts: Options,
    checks: CheckSet,
    json: bool,
    quiet: bool,
    out: &mut dyn std::io::Write,
) -> (bool, bool) {
    let mut io_failed = false;
    let report = match pgr_verify::verify_universal_with_checks(bytes, &opts, &checks) {
        Ok(report) => report,
        Err(e) => {
            if !quiet && !text_writeln(out, format_args!("{}: REFUSED: {e}", file.display())) {
                io_failed = true;
            }
            return (true, io_failed);
        }
    };
    let mut any_bad = false;
    for (i, slice) in report.slices.iter().enumerate() {
        let label = format!(
            "{}[slice {i} cputype {:#x} at {:#x}, {} bytes]",
            file.display(),
            slice.arch.cputype,
            slice.arch.offset,
            slice.arch.size,
        );
        let bad = !slice.report.is_ok(&opts);
        if json {
            let body = pgr_verify::to_json_with_file(&label, &slice.report);
            if let Err(e) = writeln!(out, "{body}") {
                eprintln!("{PROGRAM}: {e}");
                return (true, true);
            }
        } else if !quiet {
            if !text_writeln(
                out,
                format_args!("{label}: {}", if bad { "FAILED" } else { "OK" }),
            ) {
                io_failed = true;
            }
            for issue in &slice.report.issues {
                let sev = match issue.severity {
                    Severity::Error => "error",
                    Severity::Warning => "warning",
                };
                let at = issue
                    .offset
                    .map(|o| format!(" at {o:#x}"))
                    .unwrap_or_default();
                if !text_writeln(
                    out,
                    format_args!("  {sev} [{}] {}{at}", issue.code.as_str(), issue.message),
                ) {
                    io_failed = true;
                }
            }
        }
        any_bad |= bad;
    }
    (any_bad, io_failed)
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

/// The container baseline's loader (M96): the document is the
/// container's own `--json` face output — one whole-output report line
/// per declared slice — and the reader names the line it died at.
fn load_container_baseline(
    path: &std::path::Path,
) -> Result<pgr_verify::ContainerBaseline, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    pgr_verify::parse_container_baseline(&text).map_err(|e| format!("{}: {e}", path.display()))
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
         OPTIONS:\n    --json                  Machine-readable report\n    --sarif                 SARIF 2.1.0 document (the triage tools'\n                            native shape; one machine face per run)\n    --strict                Treat warnings as failures\n    --quiet, -q             Only set the exit code\n    --skip-hash-recompute   Skip SHA-256 page-hash verification\n    --checks <a,b,...>      Run only the named families (e.g. segments,fixups)\n    --list-checks           Print the families and exit\n    --baseline <path>       Gate on a previous --json report: only NEW\n                            findings fail (one file per invocation; a\n                            universal container's baseline is its own\n                            --json output, paired slice by slice)\n    --fail-on new|any       What fails: introduced findings only (default\n                            with --baseline) or the whole verdict\n    --help, -h              This help\n    --version, -V           Version\n\n\
         EXIT:\n    0 clean · 1 issues · 2 usage/IO error",
        env!("CARGO_PKG_VERSION")
    );
}

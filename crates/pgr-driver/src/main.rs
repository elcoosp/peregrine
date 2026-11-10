//! `pgr` — the Peregrine linker driver.
//!
//! M1: the ld64-compatible option surface for static links plus the Pass 0–5
//! loop. `pgr --help` documents the surface; `pgr-verify <image>` validates
//! any output.

use std::process::ExitCode;

/// Program name as invoked on the command line.
const PROGRAM: &str = "pgr";

fn main() -> ExitCode {
    // The relink/audit spans stay inert until a subscriber installs;
    // PGR_INCREMENTAL_DEBUG=1 (or PGR_RESIDENT_DEBUG=1) turns them into
    // stderr lines.
    if std::env::var_os("PGR_INCREMENTAL_DEBUG").is_some()
        || std::env::var_os("PGR_RESIDENT_DEBUG").is_some()
    {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .init();
    }
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    match args.first().and_then(|a| a.to_str()) {
        Some("--version" | "-version" | "-V") => {
            println!("{}", pgr_driver::version_line());
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-help" | "-h") => {
            print!("{}", pgr_driver::usage());
            return ExitCode::SUCCESS;
        }
        Some("--print-fixup-encoding") => {
            return print_fixup_encoding(&args[1..]);
        }
        Some("--print-record") => {
            return print_record(&args[1..]);
        }
        _ => {}
    }

    match run(&args) {
        Ok(outcome) => {
            println!(
                "{PROGRAM}: wrote {} ({} bytes, entryoff {:#x}, {} fixup slot(s))",
                outcome.output, outcome.file_size, outcome.entryoff, outcome.fixup_slots
            );
            if let Some(patch) = &outcome.patch {
                if patch.untouched {
                    println!(
                        "{PROGRAM}: incremental: untouched (0 of {} tiles, 0 bytes patched)",
                        patch.total_tiles
                    );
                } else {
                    println!(
                        "{PROGRAM}: incremental: {} of {} tiles patched ({} bytes)",
                        patch.dirty_tiles, patch.total_tiles, patch.bytes_patched
                    );
                }
            }
            if let Some(audit) = &outcome.audit {
                let served_by = if audit.healed {
                    "healed from the reference emit"
                } else if audit.identity_ok {
                    "byte-identity held"
                } else {
                    "diverged"
                };
                println!(
                    "{PROGRAM}: incremental-verify: {} (strict pass {})",
                    served_by,
                    if audit.verify_ok { "clean" } else { "FAILED" }
                );
            }
            if let Some(transport) = &outcome.transport {
                match transport {
                    pgr_daemon::Transport::Full => {
                        println!("{PROGRAM}: resident: the image crossed the wire in full");
                    }
                    pgr_daemon::Transport::Tiles { tiles, bytes } => {
                        println!(
                            "{PROGRAM}: resident: {tiles} tile(s), {bytes} bytes crossed the wire"
                        );
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(pgr_driver::DriverError::Opts(_)) => {
            // The refusal renders with its miette help text (the fix, not
            // just the verdict) — the same convention as the audit refusal.
            eprintln!("{PROGRAM}: error: {}", first_error(&args));
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("{PROGRAM}: error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the driver over `args`, mapping results to a summary line.
fn run(args: &[std::ffi::OsString]) -> Result<pgr_driver::LinkOutcome, pgr_driver::DriverError> {
    let opts = pgr_driver::opts::parse(args)?;
    pgr_driver::run(&opts)
}

/// The `--print-fixup-encoding` intercept (M10 rung 3, slice 2): names
/// the fixup encoding a `-platform_version` triple plans with before
/// any link runs — the build-system seam. The verdict prints on
/// stdout; a below-floor answer renders its miette advisory (help text
/// included) on stderr and still exits 0 (an advisory is a plan, not a
/// failure); option refusals render like the parse path and exit 2.
fn print_fixup_encoding(rest: &[std::ffi::OsString]) -> ExitCode {
    if rest.len() != 3 {
        eprintln!("{PROGRAM}: error: --print-fixup-encoding <platform> <minos> <sdk>");
        return ExitCode::from(2);
    }
    let (Some(platform), Some(minos), Some(sdk)) =
        (rest[0].to_str(), rest[1].to_str(), rest[2].to_str())
    else {
        eprintln!(
            "{PROGRAM}: error: --print-fixup-encoding <platform> <minos> <sdk> \
             (arguments must be UTF-8)"
        );
        return ExitCode::from(2);
    };
    match pgr_driver::fixup_encoding_report(platform, minos, sdk) {
        Ok(report) => {
            let encoding = match report.encoding {
                pgr_core::platform::FixupEncoding::ChainedFixups => "chained-fixups",
                pgr_core::platform::FixupEncoding::ClassicOpcodes => "classic-opcodes",
            };
            println!(
                "{PROGRAM}: {platform} {minos} links {encoding} (chained-fixups floor {})",
                report.floor_text()
            );
            if let Some(advisory) = report.advisory {
                eprintln!("{:?}", miette::Report::new(advisory));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{PROGRAM}: error: {:?}", miette::Report::new(e));
            ExitCode::from(2)
        }
    }
}

/// The `--print-record` intercept (M13 rung 2): reads a `.pgr-inc`
/// sidecar and prints its summary — the identity, skeleton and table
/// counts the last `-incremental` link recorded. The text renders on
/// stdout (deterministic, the map's contract); a frame refusal names
/// its layer on stderr and exits 1 (a diagnosis, not a usage error);
/// usage problems exit 2.
fn print_record(rest: &[std::ffi::OsString]) -> ExitCode {
    if rest.len() != 1 {
        eprintln!("{PROGRAM}: error: --print-record <output.pgr-inc>");
        return ExitCode::from(2);
    }
    let Some(path) = rest[0].to_str() else {
        eprintln!("{PROGRAM}: error: --print-record <output.pgr-inc> (the path must be UTF-8)");
        return ExitCode::from(2);
    };
    match pgr_driver::record_report(path) {
        Ok(summary) => {
            print!("{}", summary.render());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{PROGRAM}: error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The rendered error for the failing option (parse errors carry the
/// flag and their miette help text — the fix, not just the verdict).
fn first_error(args: &[std::ffi::OsString]) -> String {
    match pgr_driver::opts::parse(args) {
        Err(e) => format!("{:?}", miette::Report::new(e)),
        Ok(_) => "option handling failed".into(),
    }
}

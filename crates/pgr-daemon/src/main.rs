//! `pgrd` — the Peregrine resident link server (M8).
//!
//! Holds the cross-link state (parsed objects, input bytes, the fused-emit
//! output buffer) for `pgr -resident` clients over a unix-domain socket.
//! Optional and transparent by contract: any client that cannot reach it
//! links one-shot, and the daemon's own idles-out policy keeps stray
//! processes from living forever.

use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    // The session's relink/audit spans stay inert until a subscriber
    // installs; PGR_RESIDENT_DEBUG=1 turns them into stderr lines.
    if std::env::var_os("PGR_RESIDENT_DEBUG").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .init();
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut socket = pgr_daemon::client_default_socket();
    let mut idle_secs: u64 = 900;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--version" | "-V" => {
                println!("pgrd (Peregrine) {}", pgr_daemon::VERSION);
                return ExitCode::SUCCESS;
            }
            "-h" | "--help" => {
                print!("{HELP}");
                return ExitCode::SUCCESS;
            }
            "--socket" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("pgrd: missing value for --socket");
                    return ExitCode::from(2);
                };
                socket.clone_from(v);
                i += 1;
            }
            "--idle-secs" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("pgrd: missing value for --idle-secs");
                    return ExitCode::from(2);
                };
                if let Ok(n) = v.trim().parse::<u64>() {
                    idle_secs = n;
                } else {
                    eprintln!("pgrd: invalid --idle-secs value {v:?}");
                    return ExitCode::from(2);
                }
                i += 1;
            }
            "--shutdown" => {
                return match pgr_daemon::shutdown_daemon(std::path::Path::new(&socket)) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("pgrd: {e}");
                        ExitCode::FAILURE
                    }
                };
            }
            other => {
                eprintln!("pgrd: unknown argument {other:?} (try --help)");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    match pgr_daemon::serve(
        std::path::Path::new(&socket),
        Duration::from_secs(idle_secs),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pgrd: {e}");
            ExitCode::FAILURE
        }
    }
}

const HELP: &str = "pgrd — the Peregrine resident link server.

Keeps parsed object state (POIs), input bytes and the fused-emit output
buffer across links for `pgr -resident` clients. Optional by contract:
clients fall back to the one-shot link whenever the daemon is unreachable,
and the daemon never writes output files (clients do, atomically).

Usage: pgrd [options]

Options:
  --socket <path>    listen path (default: $PGR_DAEMON_SOCK, else
                     {tmpdir}/pgr-<uid|pid>.sock — SUDO_UID when
                     present, else the process id)
  --idle-secs <n>    exit after this many seconds with no client work
                     (default 900)
  --shutdown         ask the daemon at the socket path to exit
  -h, --help         this text
  -V, --version      version banner
";

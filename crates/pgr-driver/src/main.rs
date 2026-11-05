//! `pgr` — the Peregrine linker driver.
//!
//! M0 placeholder: the ld64-compatible option surface (TDD §5 Pass 0) lands
//! with the M1 pipeline. This binary only reports version/build metadata so
//! the workspace shape is exercisable from day one. Deliberately
//! dependency-free: TDD §8 keeps heavy dependencies out of `pgr-driver`.

use std::process::ExitCode;

/// Program name as invoked on the command line.
const PROGRAM: &str = "pgr";

/// Returns the one-line version banner printed by `pgr --version`.
pub fn version_line() -> String {
    format!("{PROGRAM} (Peregrine) {}", env!("CARGO_PKG_VERSION"))
}

/// Returns the short usage text printed by `pgr --help`.
pub fn usage() -> String {
    let mut s = String::with_capacity(512);
    s.push_str(&version_line());
    s.push_str("\n\n");
    s.push_str("Peregrine: ultra-fast Mach-O linker for arm64-apple-darwin.\n\n");
    s.push_str("M0 ships the verifier-first toolchain only; linking passes arrive at M1.\n");
    s.push_str("Use `pgr-verify <image>` to validate a Mach-O file in the meantime.\n");
    s
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref().and_then(|a| a.to_str()) {
        Some("--version") | Some("-V") => {
            println!("{}", version_line());
            ExitCode::SUCCESS
        }
        Some("--help") | Some("-h") => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "{PROGRAM}: no linkable work is implemented at M0; see --help.\nLinking passes start at M1 (TDD roadmap)."
            );
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_line_contains_pkg_version() {
        let line = super::version_line();
        assert!(line.contains(env!("CARGO_PKG_VERSION")));
        assert!(line.starts_with("pgr"));
    }

    #[test]
    fn usage_mentions_verify() {
        assert!(super::usage().contains("pgr-verify"));
    }
}

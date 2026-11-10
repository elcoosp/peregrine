//! M13 rung 2 — the `--print-record` driver surface: the sidecar a
//! real `-incremental` link writes reads back as a summary (exit 0,
//! deterministic text), and every way a query can be wrong refuses
//! with the right exit code and the fix on stderr — usage errors exit
//! 2, record refusals exit 1 with the layer named (a diagnosis, not a
//! crash), and the object itself is not a record.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir()
        .join("pgr_m13_record_query")
        .join(format!(
            "{tag}_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// hello.o: `_main` returns (ret), no imports — the smallest linkable
/// static executable.
fn hello_o(dir: &std::path::Path) -> PathBuf {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let path = dir.join("hello.o");
    std::fs::write(&path, b.build().unwrap()).unwrap();
    path
}

/// Runs the `pgr` binary and captures status, stdout and stderr.
fn run_pgr(args: &[&str]) -> (i32, String, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_pgr"))
        .args(args)
        .output()
        .expect("the pgr binary runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_incremental_sidecar_reads_back_as_a_summary() {
    let dir = scratch("read");
    let hello = hello_o(&dir);
    let app = dir.join("app");

    // The first incremental link is a full link that records (M9's
    // contract): the sidecar exists after a successful exit.
    let (code, stdout, stderr) = run_pgr(&[
        "-o",
        app.to_str().expect("utf-8 path"),
        hello.to_str().expect("utf-8 path"),
        "-incremental",
    ]);
    assert_eq!(code, 0, "the link links clean: {stdout} {stderr}");
    let sidecar = dir.join("app.pgr-inc");
    assert!(sidecar.exists(), "the record rides next to the output");

    // The query: exit 0, deterministic text naming the shape.
    let (code, stdout, stderr) =
        run_pgr(&["--print-record", sidecar.to_str().expect("utf-8 path")]);
    assert_eq!(code, 0, "{stdout} {stderr}");
    assert!(stderr.is_empty(), "clean reads are quiet: {stderr}");
    assert!(stdout.starts_with("# Peregrine link record"), "{stdout}");
    assert!(stdout.contains("record version:"), "{stdout}");
    assert!(stdout.contains("segment __TEXT"), "{stdout}");
    assert!(stdout.contains("section __text"), "{stdout}");

    // Determinism: the same sidecar renders byte-identical text.
    let (_, again, _) = run_pgr(&["--print-record", sidecar.to_str().expect("utf-8 path")]);
    assert_eq!(stdout, again);
}

#[test]
fn the_query_refusals_carry_their_exit_codes() {
    let dir = scratch("refusals");
    let hello = hello_o(&dir);

    // Usage: no argument, and a nonexistent path is a record refusal
    // (exit 1 — a diagnosis), not a usage error.
    let (code, _, stderr) = run_pgr(&["--print-record"]);
    assert_eq!(code, 2, "no path is a usage problem");
    assert!(stderr.contains("--print-record"), "{stderr}");

    let (code, _, stderr) = run_pgr(&["--print-record", "/nonexistent/app.pgr-inc"]);
    assert_eq!(code, 1, "a missing record is a diagnosis");
    assert!(
        stderr.contains("a record is written by"),
        "the fix rides the refusal: {stderr}"
    );

    // A Mach-O object is not a record: the magic layer names it.
    let (code, _, stderr) = run_pgr(&["--print-record", hello.to_str().expect("utf-8 path")]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("not a Peregrine link record"), "{stderr}");
}

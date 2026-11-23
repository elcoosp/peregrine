//! M136 — the `-warn_unused_dylibs` driver surface: ld64's unused-dylib
//! advisory. The pair parses onto the config decision (last-wins, the
//! M109 pair shape), the relocatable output refuses it (the object
//! carries no dylib load commands), and the end-to-end gates: the
//! unbound dylib prints as a `pgr: warning: unused dylib` face and the
//! link still exits 0, `-fatal_warnings` elevates the tally to a hard
//! exit with no image written, and `-w` silences the print while the
//! tally still elevates (the M133 composition). The spawn gates run the
//! real binary.

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m136_driver").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn args(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

/// `main.o`: `_main` in a `__text` body — the entry symbol.
fn main_corpus(dir: &Path, name: &str) -> PathBuf {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(4),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let path = dir.join(name);
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// A stub `.tbd` exporting nothing the corpus binds — the dylib rides
/// the load commands with zero binding references (the advisory's row).
fn stub_library(dir: &Path) -> PathBuf {
    let tbd = "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: \
        @rpath/libunused.dylib\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\n\
        exports:\n  - targets: [ arm64-macos ]\n    symbols: [_noone_uses_this]\n...\n";
    let path = dir.join("libunused.tbd");
    std::fs::write(&path, tbd).unwrap();
    path
}

/// Runs the real `pgr` binary: `(exit code, stderr)`.
fn spawn_pgr(argv: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_pgr"))
        .args(argv)
        .output()
        .expect("the pgr binary spawns");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_pair_names_the_decision() {
    let dir = scratch("parse");
    let obj = main_corpus(&dir, "main.o");
    let obj = obj.display().to_string();
    let o = opts::parse(&args(&["-o", "out", &obj])).expect("the plain argv parses");
    assert!(
        !o.config.warn_unused_dylibs,
        "the default carries no advisory (every pre-knob link byte-identical)"
    );
    let o = opts::parse(&args(&["-warn_unused_dylibs", "-o", "out", &obj]));
    assert!(o.is_ok(), "the flag parses: {:?}", o.err());
    let o = opts::parse(&args(&["-no_warn_unused_dylibs", "-o", "out", &obj]));
    assert!(o.is_ok(), "the off face parses: {:?}", o.err());
    // Last-wins: the pair composes, the later flag is the decision (the
    // off face's parse carries no error surface to inspect — the config
    // is private to `finish`, so the face's acceptance is the gate).
    let o = opts::parse(&args(&[
        "-warn_unused_dylibs",
        "-no_warn_unused_dylibs",
        "-o",
        "out",
        &obj,
    ]));
    assert!(o.is_ok(), "the pair composes: {:?}", o.err());
}

#[test]
fn the_relocatable_output_refuses_the_knob() {
    let dir = scratch("reloc");
    let obj = main_corpus(&dir, "main.o");
    let argv = args(&[
        "-o",
        "out.o",
        obj.to_str().unwrap(),
        "-r",
        "-warn_unused_dylibs",
    ]);
    let err = opts::parse(&argv).expect_err("-r carries no dylib load commands");
    assert!(
        err.to_string().contains("load commands"),
        "the refusal names the shape conflict: {err}"
    );
}

#[test]
fn the_advisory_prints_and_the_link_exits_zero() {
    let dir = scratch("print");
    let obj = main_corpus(&dir, "main.o");
    let lib = stub_library(&dir);
    let out = dir.join("app");
    let (code, stderr) = spawn_pgr(&[
        "-o",
        out.to_str().unwrap(),
        obj.to_str().unwrap(),
        lib.to_str().unwrap(),
        "-warn_unused_dylibs",
    ]);
    assert_eq!(code, Some(0), "the advisory exits 0: {stderr}");
    assert!(
        stderr.contains("pgr: warning: unused dylib @rpath/libunused.dylib"),
        "the unbound rider names: {stderr}"
    );
    assert!(out.exists(), "the image ships");

    // The default stays silent (the bytes never move — the advisory is
    // a measurement).
    let out2 = dir.join("app_silent");
    let (code, stderr) = spawn_pgr(&[
        "-o",
        out2.to_str().unwrap(),
        obj.to_str().unwrap(),
        lib.to_str().unwrap(),
    ]);
    assert_eq!(code, Some(0));
    assert!(
        !stderr.contains("unused dylib"),
        "the unnamed decision prints nothing: {stderr}"
    );
    assert_eq!(
        std::fs::read(&out).unwrap(),
        std::fs::read(&out2).unwrap(),
        "the face never moves the bytes"
    );
}

#[test]
fn fatal_warnings_elevates_and_w_suppresses_the_print() {
    let dir = scratch("elevate");
    let obj = main_corpus(&dir, "main.o");
    let lib = stub_library(&dir);
    let out = dir.join("app_fatal");
    let (code, stderr) = spawn_pgr(&[
        "-o",
        out.to_str().unwrap(),
        obj.to_str().unwrap(),
        lib.to_str().unwrap(),
        "-warn_unused_dylibs",
        "-fatal_warnings",
    ]);
    assert_eq!(code, Some(1), "the elevation is a hard exit: {stderr}");
    assert!(
        stderr.contains("unused dylib"),
        "the elevated face still names the row: {stderr}"
    );
    assert!(!out.exists(), "no image ships under the elevation");

    // `-w` composes: the print silences, the tally still elevates.
    let (code, stderr) = spawn_pgr(&[
        "-o",
        out.to_str().unwrap(),
        obj.to_str().unwrap(),
        lib.to_str().unwrap(),
        "-warn_unused_dylibs",
        "-fatal_warnings",
        "-w",
    ]);
    assert_eq!(
        code,
        Some(1),
        "the suppressed tally still elevates: {stderr}"
    );
    assert!(
        !stderr.contains("unused dylib"),
        "the print is silenced: {stderr}"
    );
}

//! M121 — the `-warn_duplicate` driver surface: ld64's duplicate-symbol
//! advisory. The flag parses onto the config decision, the relocatable
//! output refuses it (the object's symtab is the input's, verbatim), and
//! the end-to-end gates: under `-multiply_defined suppress -warn_duplicate`
//! the duplicate strong-strong collision prints as a `pgr: warning:
//! duplicate symbol` face and the link still exits 0 (the resolution
//! policy itself is unchanged — the default `error` still applies unless
//! overridden, so under `-warn_duplicate` alone a duplicate strong
//! definition still refuses the link); and the relocatable refusal. The
//! spawn gates run the real binary.

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir()
        .join("pgr_m121_warn_duplicate")
        .join(format!(
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

/// One object defining the named strong external — two of these under the
/// same name collide at the `install_sect_def` `Equal`/`Strong` tie.
fn dup_corpus(dir: &Path, name: &str, sym: &str) -> PathBuf {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: sym.into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let path = dir.join(name);
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
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
fn the_flag_names_the_decision() {
    let dir = scratch("parse");
    let obj = main_corpus(&dir, "main.o");
    let obj = obj.display().to_string();
    let o = opts::parse(&args(&["-o", "out", &obj])).expect("the plain argv parses");
    assert!(
        !o.config.warn_duplicate,
        "the default carries no advisory (every pre-knob link byte-identical)"
    );
    let o = opts::parse(&args(&["-warn_duplicate", "-o", "out", &obj])).expect("the flag parses");
    assert!(
        o.config.warn_duplicate,
        "the flag names the advisory decision"
    );
}

#[test]
fn warn_duplicate_prints_the_duplicate_warning_under_suppress() {
    // Under `-multiply_defined suppress` the collision's first definition
    // wins silently (the suppress face prints nothing); `-warn_duplicate`
    // adds the advisory — the duplicate strong-strong collision prints as
    // a `pgr: warning: duplicate symbol` face and the link still exits 0
    // (the resolution policy itself is unchanged).
    let dir = scratch("e2e_suppress");
    let main = main_corpus(&dir, "main.o");
    let a = dup_corpus(&dir, "a.o", "_dup");
    let b = dup_corpus(&dir, "b.o", "_dup");
    let out = dir.join("app").display().to_string();
    let (code, stderr) = spawn_pgr(&[
        "-multiply_defined",
        "suppress",
        "-warn_duplicate",
        "-o",
        &out,
        &main.display().to_string(),
        &a.display().to_string(),
        &b.display().to_string(),
    ]);
    assert_eq!(
        code,
        Some(0),
        "the suppress+warn_duplicate link exits 0: {stderr}"
    );
    assert!(
        stderr.contains("pgr: warning: duplicate symbol") && stderr.contains("_dup"),
        "the advisory prints the duplicate collision: {stderr}"
    );
    // Under suppress alone the same collision prints nothing (the advisory
    // is the distinct face — the M108 suppress face is silent).
    let out2 = dir.join("app2").display().to_string();
    let (code, stderr) = spawn_pgr(&[
        "-multiply_defined",
        "suppress",
        "-o",
        &out2,
        &main.display().to_string(),
        &a.display().to_string(),
        &b.display().to_string(),
    ]);
    assert_eq!(code, Some(0), "the suppress-alone link exits 0: {stderr}");
    assert!(
        !stderr.contains("duplicate symbol"),
        "the suppress face alone prints no duplicate advisory: {stderr}"
    );
}

#[test]
fn warn_duplicate_never_changes_the_resolution_policy() {
    // Under the default `error` policy a duplicate strong definition still
    // refuses the link — `-warn_duplicate` is advisory, the policy is
    // unchanged (the default `error` still applies unless overridden).
    let dir = scratch("e2e_error");
    let main = main_corpus(&dir, "main.o");
    let a = dup_corpus(&dir, "a.o", "_dup");
    let b = dup_corpus(&dir, "b.o", "_dup");
    let out = dir.join("app").display().to_string();
    let (code, stderr) = spawn_pgr(&[
        "-warn_duplicate",
        "-o",
        &out,
        &main.display().to_string(),
        &a.display().to_string(),
        &b.display().to_string(),
    ]);
    assert_ne!(
        code,
        Some(0),
        "the default error policy still refuses the duplicate: {stderr}"
    );
    assert!(
        stderr.contains("duplicate strong definition") && stderr.contains("_dup"),
        "the refusal names the duplicate and the unchanged policy: {stderr}"
    );
}

#[test]
fn warn_duplicate_refuses_on_the_relocatable_output() {
    let dir = scratch("reloc");
    let obj = main_corpus(&dir, "main.o");
    let out = dir.join("out.o").display().to_string();
    let obj = obj.display().to_string();
    let err = opts::parse(&args(&["-r", "-o", &out, &obj, "-warn_duplicate"]))
        .expect_err("the relocatable output refuses the knob");
    let rendered = err.to_string();
    assert!(
        rendered.contains("-warn_duplicate") && rendered.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {rendered}"
    );
}

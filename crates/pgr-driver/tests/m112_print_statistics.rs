//! M112 — the `-print_statistics` driver surface: the flag parses onto
//! the config (the stats report rides the run), the relocatable output
//! refuses the knob (the object path has no full-emit layout or fixup
//! planning to report in the same way — the surface's knob refusal
//! mirrored exactly), and the spawn gate pins the report's stderr face on
//! the real binary (the exit face is stderr + exit code — the driver
//! library cannot assert its own stderr).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m112_stats").join(format!(
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

/// hello.o: `_main` references `_greet` — one bind slot, the counts the
/// stats report names.
fn hello_object(dir: &Path) -> PathBuf {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let undef = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    let slot = b.sym_index(undef);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    let path = dir.join("hello.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

#[test]
fn the_flag_parses_onto_the_config() {
    let dir = scratch("parse");
    let obj = hello_object(&dir).display().to_string();
    let o = opts::parse(&args(&["-o", "out", "-print_statistics", &obj])).expect("the knob parses");
    assert!(
        o.config.print_statistics,
        "the report decision rides the config"
    );
}

#[test]
fn the_report_prints_to_stderr_at_the_end_of_the_link() {
    let dir = scratch("face");
    let obj = hello_object(&dir);
    let out = dir.join("app").display().to_string();
    let obj_str = obj.display().to_string();
    // The unresolved `_greet` rides the warning policy (the M109 gate's
    // own fixture shape); the report rides the run regardless.
    let (code, stderr) = spawn_pgr(&[
        "-o",
        &out,
        "-undefined",
        "warning",
        "-print_statistics",
        &obj_str,
    ]);
    assert_eq!(code, Some(0), "the link exits 0 with the report riding");
    assert!(
        stderr.contains("the link statistics"),
        "the report's header prints to stderr: {stderr}"
    );
    assert!(
        stderr.contains("objects parsed 1"),
        "the parse count rides: {stderr}"
    );
    assert!(
        stderr.contains("bytes emitted"),
        "the emit count rides: {stderr}"
    );
    assert!(Path::new(&out).exists(), "the image ships");
}

#[test]
fn the_default_prints_nothing() {
    let dir = scratch("default");
    let obj = hello_object(&dir);
    let out = dir.join("app").display().to_string();
    let obj_str = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, "-undefined", "warning", &obj_str]);
    assert_eq!(code, Some(0), "the default links clean");
    assert!(
        !stderr.contains("the link statistics"),
        "an unasked report never prints: {stderr}"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob() {
    let dir = scratch("reloc");
    let obj = hello_object(&dir).display().to_string();
    let err = opts::parse(&args(&["-r", "-o", "out.o", "-print_statistics", &obj]))
        .expect_err("the object shape refuses the report");
    let rendered = format!("{:?}", miette::Report::new(err));
    assert!(
        rendered.contains("-print_statistics"),
        "the refusal names the knob: {rendered}"
    );
    assert!(
        rendered.to_lowercase().contains("drop -print_statistics"),
        "the refusal names the fix (the house convention): {rendered}"
    );
}

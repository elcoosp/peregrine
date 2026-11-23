//! M133 — the warning-suppression face (`-w`): ld64's flag ("Suppress
//! warnings") — the advisory faces' print decision, the M109
//! `-fatal_warnings` escalation's complementary face. The default prints
//! every advisory face's product to stderr and exits 0; under `-w` the
//! same faces print nothing (the link is unchanged — the bytes never
//! move) and still exit 0. The tally is independent of the print: the
//! count rides even when suppressed, so `-w` composes with
//! `-fatal_warnings` (the suppressed warnings still elevate — ld64's own
//! composition: the exit is the exit, the print face is the print face).
//! The relocatable output refuses the knob (the object's shape is the
//! input's, verbatim; every advisory face that would warn is already
//! refused beside `-r`, so there is nothing left to suppress). The spawn
//! gates run the real binary (the print face is stderr — the driver
//! library cannot assert its own stderr).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir()
        .join("pgr_m133_warn_suppress")
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

/// hello.o: `_main` references `_hole` — the unresolved name the warning
/// face prints.
fn hole_object(dir: &Path) -> PathBuf {
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
    let undef = b.add_symbol(ObjectSymbol::Undefined {
        name: "_hole".into(),
        weak_ref: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let slot = b.sym_index(undef);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    let path = dir.join("hello.o");
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
fn the_flag_parses() {
    let dir = scratch("parse");
    let obj = hole_object(&dir);
    let obj = obj.display().to_string();
    let o = opts::parse(&args(&["-o", "out", "-w", &obj])).expect("the suppression parses");
    assert!(
        o.config.suppress_warnings,
        "the suppression rides the config"
    );
    // The flag is idempotent (ld64's `-w` carries no mirror): a second
    // occurrence is the same decision, never a toggle.
    let o = opts::parse(&args(&["-o", "out", "-w", "-w", &obj])).expect("the repeated flag parses");
    assert!(
        o.config.suppress_warnings,
        "the repeated flag is idempotent"
    );
}

#[test]
fn the_default_still_prints_the_warnings() {
    let dir = scratch("default");
    let obj = hole_object(&dir);
    let out = dir.join("app").display().to_string();
    let obj_str = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, "-undefined", "warning", &obj_str]);
    assert_eq!(code, Some(0), "the advisory exit holds");
    assert!(
        stderr.contains("pgr: warning: undefined symbol") && stderr.contains("_hole"),
        "the warning prints by default: {stderr}"
    );
    assert!(Path::new(&out).exists(), "the image ships");
}

#[test]
fn w_suppresses_the_warning_lines_and_still_exits_zero() {
    let dir = scratch("suppress");
    let obj = hole_object(&dir);
    let out = dir.join("app").display().to_string();
    let obj_str = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, "-undefined", "warning", "-w", &obj_str]);
    assert_eq!(
        code,
        Some(0),
        "the suppression is the exit's, not the link's"
    );
    assert!(
        !stderr.contains("pgr: warning:"),
        "the advisory faces print nothing under -w: {stderr}"
    );
    assert!(Path::new(&out).exists(), "the image ships unchanged");
}

#[test]
fn w_suppresses_the_order_file_advisory_face() {
    // The M11 order-file advisory is one of the driver's inline faces
    // (not a print_* helper) — the suppression covers every face, the
    // helpers and the inline walks alike.
    let dir = scratch("order");
    let obj = hole_object(&dir);
    let order = dir.join("order.txt");
    std::fs::write(&order, "_main\n_missing_symbol\n").unwrap();
    let out = dir.join("app").display().to_string();
    let (obj_str, order_str) = (obj.display().to_string(), order.display().to_string());
    let (code, stderr) = spawn_pgr(&[
        "-o",
        &out,
        "-undefined",
        "warning",
        "-order_file",
        &order_str,
        "-w",
        &obj_str,
    ]);
    assert_eq!(code, Some(0), "the unmatched order entry warns, not fails");
    assert!(
        !stderr.contains("pgr: warning:"),
        "the inline order-file face suppresses too: {stderr}"
    );
    let (code, stderr) = spawn_pgr(&[
        "-o",
        &out,
        "-undefined",
        "warning",
        "-order_file",
        &order_str,
        &obj_str,
    ]);
    assert_eq!(code, Some(0), "the unsuppressed link still exits 0");
    assert!(
        stderr.contains("order file symbol _missing_symbol"),
        "the same link without -w prints the advisory: {stderr}"
    );
}

#[test]
fn w_composes_with_fatal_warnings_the_tally_survives_the_suppression() {
    // The tally counts what the faces recorded, not what they printed:
    // under `-w -fatal_warnings` the escalation still fires (ld64's own
    // composition), the stderr carries the elevation's error render and
    // none of the suppressed warning lines.
    let dir = scratch("compose");
    let obj = hole_object(&dir);
    let out = dir.join("app").display().to_string();
    let obj_str = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&[
        "-o",
        &out,
        "-undefined",
        "warning",
        "-w",
        "-fatal_warnings",
        &obj_str,
    ]);
    assert_eq!(code, Some(1), "the suppressed warnings still elevate");
    assert!(
        !stderr.contains("pgr: warning:"),
        "the warning lines stay suppressed: {stderr}"
    );
    assert!(
        stderr.contains("-fatal_warnings"),
        "the elevation names itself: {stderr}"
    );
    assert!(
        !Path::new(&out).exists(),
        "the elevated link writes no image"
    );
}

#[test]
fn a_clean_link_is_unchanged_under_w() {
    // No advisory product, no print face: `-w` prices nothing.
    let dir = scratch("clean");
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let obj = dir.join("hello.o");
    std::fs::write(&obj, b.build().expect("the fixture object builds")).unwrap();
    let out = dir.join("app").display().to_string();
    let obj_str = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, "-w", &obj_str]);
    assert_eq!(code, Some(0), "a clean link exits 0");
    assert!(
        !stderr.contains("pgr: warning:"),
        "nothing to suppress: {stderr}"
    );
}

#[test]
fn r_refuses_the_knob() {
    // The relocatable output's shape is the input's, verbatim — the
    // surface's knob refusal mirrored exactly (the M109 shape); every
    // advisory face that would warn is already refused beside -r, so
    // there is nothing left to suppress.
    let dir = scratch("reloc");
    let obj = hole_object(&dir);
    let obj = obj.display().to_string();
    let argv = args(&["-o", "out.o", "-r", "-w", &obj]);
    let err = opts::parse(&argv).expect_err("the relocatable output refuses");
    assert!(
        err.to_string().contains("-w"),
        "the refusal names the knob: {err}"
    );
    let argv = args(&["-o", "out.o", "-r", &obj]);
    let o = opts::parse(&argv).expect("the default rides");
    pgr_driver::run(&o).expect("the default rides the relocatable output");
}

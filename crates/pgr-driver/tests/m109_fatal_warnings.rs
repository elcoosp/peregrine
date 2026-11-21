//! M109 — the `-fatal_warnings` / `-no_fatal_warnings` exit policy: the
//! advisory face's escalation. Any warning the driver's faces printed
//! (the unresolved-open render, the multiply-defined collision, the
//! unmatched order-file rows) elevates to a hard exit 1; the default (and
//! its explicit `-no_fatal_warnings` mirror) still exits 0 with the
//! warnings printed. The image bytes never move — the policy is the
//! exit's — and the relocatable output refuses the knob (the object's
//! shape is the input's, verbatim; every advisory face that would warn is
//! already refused beside `-r`, so there is nothing left to elevate).
//! The spawn gates run the real binary (the exit face is stderr + exit
//! code — the driver library cannot assert its own stderr).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m109_fatal").join(format!(
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

/// Two objects colliding on one strong `_dup` — the M108 warning face's
/// product.
fn collision_objects(dir: &Path) -> (PathBuf, PathBuf) {
    let build = |name: &str, with_main: bool, fill: u8| {
        let mut b = ObjectBuilder::new(name);
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            vec![],
        ));
        if with_main {
            b.add_symbol(ObjectSymbol::Defined {
                name: "_main".into(),
                section_index: text,
                value: 0,
                weak: false,
            });
        }
        let data = b.add_section(ObjectSection::data("__data", vec![fill; 8], vec![]));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_dup".into(),
            section_index: data,
            value: 0,
            weak: false,
        });
        let path = dir.join(name);
        std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
        path
    };
    (build("a.o", true, 0xAA), build("b.o", false, 0xBB))
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
fn the_pair_parses_last_wins() {
    let dir = scratch("parse");
    let obj = hole_object(&dir);
    let obj = obj.display().to_string();
    let o =
        opts::parse(&args(&["-o", "out", "-fatal_warnings", &obj])).expect("the escalation parses");
    assert!(o.config.fatal_warnings, "the escalation rides the config");
    let o = opts::parse(&args(&[
        "-o",
        "out",
        "-fatal_warnings",
        "-no_fatal_warnings",
        &obj,
    ]))
    .expect("the mirror parses");
    assert!(
        !o.config.fatal_warnings,
        "the explicit mirror wins (last flag)"
    );
    let o = opts::parse(&args(&[
        "-o",
        "out",
        "-no_fatal_warnings",
        "-fatal_warnings",
        &obj,
    ]))
    .expect("the escalation parses");
    assert!(o.config.fatal_warnings, "the last flag wins");
}

#[test]
fn the_default_still_exits_zero_with_warnings_printed() {
    let dir = scratch("default");
    let obj = hole_object(&dir);
    let out = dir.join("app").display().to_string();
    let obj_str = obj.display().to_string();
    // The explicit mirror is the default's shape.
    let (code, stderr) = spawn_pgr(&[
        "-o",
        &out,
        "-undefined",
        "warning",
        "-no_fatal_warnings",
        &obj_str,
    ]);
    assert_eq!(code, Some(0), "the mirror keeps the advisory exit");
    assert!(
        stderr.contains("pgr: warning: undefined symbol") && stderr.contains("_hole"),
        "the warning still prints: {stderr}"
    );
    assert!(Path::new(&out).exists(), "the image ships");
}

#[test]
fn fatal_warnings_elevates_the_exit() {
    let dir = scratch("fatal");
    let obj = hole_object(&dir);
    let out = dir.join("app").display().to_string();
    let obj_str = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&[
        "-o",
        &out,
        "-undefined",
        "warning",
        "-fatal_warnings",
        &obj_str,
    ]);
    assert_eq!(code, Some(1), "the warning elevates to a hard failure");
    assert!(
        stderr.contains("pgr: warning: undefined symbol") && stderr.contains("_hole"),
        "the advisory face's product still prints: {stderr}"
    );
    assert!(
        stderr.contains("-fatal_warnings") || stderr.contains("fatal"),
        "the elevation names itself: {stderr}"
    );
    assert!(
        !Path::new(&out).exists(),
        "the elevated link writes no image"
    );
}

#[test]
fn fatal_warnings_elevates_the_multiply_defined_warning() {
    // The M108 face composes: the collision's warning elevates too.
    let dir = scratch("multiply");
    let (a, b) = collision_objects(&dir);
    let out = dir.join("app").display().to_string();
    let (a, b) = (a.display().to_string(), b.display().to_string());
    let (code, stderr) = spawn_pgr(&[
        "-o",
        &out,
        "-multiply_defined",
        "warning",
        "-fatal_warnings",
        &a,
        &b,
    ]);
    assert_eq!(code, Some(1), "the collision warning elevates");
    assert!(
        stderr.contains("multiply defined symbol") && stderr.contains("_dup"),
        "the collision prints: {stderr}"
    );
}

#[test]
fn a_clean_link_still_exits_zero_under_fatal_warnings() {
    // No warnings, no elevation: the escalation prices warnings, never
    // the link.
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
    let (code, stderr) = spawn_pgr(&["-o", &out, "-fatal_warnings", &obj_str]);
    assert_eq!(code, Some(0), "a clean link exits 0");
    assert!(
        !stderr.contains("pgr: warning:"),
        "nothing to elevate: {stderr}"
    );
}

#[test]
fn r_refuses_the_knob() {
    // The relocatable output's shape is the input's, verbatim — the
    // surface's knob refusal mirrored exactly (the M104/M105/M107/M108
    // shape); every advisory face that would warn is already refused
    // beside -r, so there is nothing left to elevate.
    let dir = scratch("reloc");
    let obj = hole_object(&dir);
    let obj = obj.display().to_string();
    let argv = args(&["-o", "out.o", "-r", "-fatal_warnings", &obj]);
    let err = opts::parse(&argv).expect_err("the relocatable output refuses");
    assert!(
        err.to_string().contains("-fatal_warnings"),
        "the refusal names the knob: {err}"
    );
    let argv = args(&["-o", "out.o", "-r", "-no_fatal_warnings", &obj]);
    let o = opts::parse(&argv).expect("the mirror rides");
    pgr_driver::run(&o).expect("the mirror rides the relocatable output");
}

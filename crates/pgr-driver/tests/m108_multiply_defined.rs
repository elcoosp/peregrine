//! M108 — the `-multiply_defined <policy>` driver surface: the alphabet
//! parses onto the typed decision, the relocatable output refuses the
//! non-default faces, and the exit policy is the e2e contract — the default
//! `error` still refuses with the symbol named, `warning` prints the
//! collision and exits 0 with the first definition riding, `suppress`
//! prints nothing and exits 0 (the same image bytes), `dynamic_lookup`
//! plans the flat-lookup ride. The spawn gates run the real binary (the
//! exit face is stderr + exit code — the driver library cannot assert its
//! own stderr).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m108_multiply").join(format!(
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

/// One defining object: `_main` (the first object's only) plus a strong
/// `_dup` over a distinct `__data` fill byte — the byte the winner's
/// definition places, so the first-wins face is readable in the image.
fn definer(dir: &Path, name: &str, with_main: bool, fill: u8) -> PathBuf {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
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
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
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
fn the_alphabet_parses_and_the_unknown_value_refuses() {
    let dir = scratch("parse");
    let obj = definer(&dir, "a.o", true, 0xAA);
    let obj = obj.display().to_string();
    for (word, expected) in [
        ("error", pgr_core::resolve::MultiplyDefinedPolicy::Error),
        ("warning", pgr_core::resolve::MultiplyDefinedPolicy::Warning),
        (
            "suppress",
            pgr_core::resolve::MultiplyDefinedPolicy::Suppress,
        ),
        (
            "dynamic_lookup",
            pgr_core::resolve::MultiplyDefinedPolicy::DynamicLookup,
        ),
    ] {
        let argv = args(&["-multiply_defined", word, "-o", "out", &obj]);
        let o = opts::parse(&argv).expect("the alphabet parses");
        assert_eq!(
            o.config.multiply_defined, expected,
            "{word} carries its face"
        );
    }
    let argv = args(&["-multiply_defined", "ignore", "-o", "out", &obj]);
    let err = opts::parse(&argv).expect_err("the unknown value refuses");
    assert!(
        err.to_string().contains("error"),
        "the hint names the alphabet: {err}"
    );
}

#[test]
fn the_error_face_refuses_with_the_symbol_named() {
    let dir = scratch("error");
    let a = definer(&dir, "a.o", true, 0xAA);
    let b = definer(&dir, "b.o", false, 0xBB);
    let out = dir.join("app").display().to_string();
    let (a, b) = (a.display().to_string(), b.display().to_string());
    let (code, stderr) = spawn_pgr(&["-o", &out, &a, &b]);
    assert_ne!(code, Some(0), "the default refuses the collision");
    assert!(
        stderr.contains("duplicate strong") && stderr.contains("_dup"),
        "the refusal names the symbol: {stderr}"
    );
    assert!(
        !Path::new(&out).exists(),
        "the refused link writes no image"
    );
}

#[test]
fn the_warning_face_prints_and_exits_zero() {
    let dir = scratch("warning");
    let a = definer(&dir, "a.o", true, 0xAA);
    let b = definer(&dir, "b.o", false, 0xBB);
    let out = dir.join("app").display().to_string();
    let (a, b) = (a.display().to_string(), b.display().to_string());
    let (code, stderr) = spawn_pgr(&["-o", &out, "-multiply_defined", "warning", &a, &b]);
    assert_eq!(code, Some(0), "the warning face exits 0");
    assert!(
        stderr.contains("pgr: warning: multiply defined symbol") && stderr.contains("_dup"),
        "the warning face names the collision: {stderr}"
    );
    let image = std::fs::read(&out).expect("the image ships despite the warning");
    // The first definition wins: the placed `__data` carries a.o's fill.
    assert!(
        image.windows(8).any(|w| w == [0xAA; 8]),
        "the first object's definition rides the image"
    );
}

#[test]
fn warning_and_suppress_plan_identical_images() {
    // The policy is the exit's, never the image's: the first definition
    // wins under both faces, so the bytes agree (the M103 parity shape).
    let dir = scratch("parity");
    let a = definer(&dir, "a.o", true, 0xAA);
    let b = definer(&dir, "b.o", false, 0xBB);
    let (a, b) = (a.display().to_string(), b.display().to_string());
    let mut images = Vec::new();
    for (name, value) in [("warn", "warning"), ("suppress", "suppress")] {
        let out = dir.join(name).display().to_string();
        let (code, _) = spawn_pgr(&["-o", &out, "-multiply_defined", value, &a, &b]);
        assert_eq!(code, Some(0), "the {value} face links");
        images.push(std::fs::read(&out).expect("the image reads"));
    }
    assert_eq!(
        images[0], images[1],
        "suppress plans the warning bytes (the same first-wins product)"
    );
    assert!(
        verify(&images[0], &strict()).is_ok(&strict()),
        "the image verifies strict"
    );
}

#[test]
fn dynamic_lookup_plans_the_flat_ride() {
    let dir = scratch("lookup");
    let a = definer(&dir, "a.o", true, 0xAA);
    let b = definer(&dir, "b.o", false, 0xBB);
    let out = dir.join("app").display().to_string();
    let (a, b) = (a.display().to_string(), b.display().to_string());
    let (code, stderr) = spawn_pgr(&["-o", &out, "-multiply_defined", "dynamic_lookup", &a, &b]);
    assert_eq!(code, Some(0), "the lookup face links");
    assert!(
        !stderr.contains("pgr: warning:"),
        "the lookup face intends the ride — nothing printed: {stderr}"
    );
    let image = std::fs::read(&out).expect("the image reads");
    assert!(
        verify(&image, &strict()).is_ok(&strict()),
        "the flat-riding image verifies strict"
    );
}

#[test]
fn r_refuses_the_non_default_policies() {
    // The object's symtab is the input's, verbatim — the surface's knob
    // refusal mirrored exactly (the M104/M105/M107 shape).
    let dir = scratch("reloc");
    let obj = definer(&dir, "a.o", true, 0xAA);
    let obj = obj.display().to_string();
    for word in ["warning", "suppress", "dynamic_lookup"] {
        let argv = args(&["-o", "out.o", "-r", "-multiply_defined", word, &obj]);
        let err = opts::parse(&argv).expect_err("the relocatable output refuses");
        assert!(
            err.to_string().contains("-multiply_defined"),
            "the refusal names the knob: {err}"
        );
    }
    let argv = args(&["-o", "out.o", "-r", "-multiply_defined", "error", &obj]);
    let o = opts::parse(&argv).expect("the default rides the relocatable output");
    pgr_driver::run(&o).expect("the default rides");
}

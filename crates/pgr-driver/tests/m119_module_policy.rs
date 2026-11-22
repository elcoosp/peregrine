//! M119 — the `-single_module`/`-multi_module` driver surface: the flags
//! parse onto the config decision, the relocatable output refuses them
//! (the object's symtab is the input's, verbatim), and the end-to-end
//! gates: the `-single_module` dylib carries one `LC_DYSYMTAB` module-table
//! entry (`nmodtab = 1`) and verifies strict (the producer wrote a
//! well-formed entry; the read-side backstop passes); the default dylib
//! carries no module table (`nmodtab = 0`); `-single_module` refuses an
//! unresolved strong reference even under `-undefined dynamic_lookup`
//! (the M103 escalation forced); and the relocatable refusal. The spawn
//! gates run the real binary.

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::{DysymtabCommand, LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir()
        .join("pgr_m119_module_policy")
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

/// `main.o`: `_main` plus a defined `_fn` — the minimal dylib corpus
/// (two external definitions the module-table entry's extdef subrange
/// mirrors).
fn dylib_corpus(dir: &Path, name: &str) -> PathBuf {
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
    b.add_symbol(ObjectSymbol::Defined {
        name: "_fn".into(),
        section_index: text,
        value: 16,
        weak: false,
    });
    let path = dir.join(name);
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// `hole.o`: `_main` plus an unresolved strong external (`_hole`) the
/// escalation refuses under `-single_module`.
fn hole_corpus(dir: &Path, name: &str) -> PathBuf {
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
    let hole = b.add_symbol(ObjectSymbol::Undefined {
        name: "_hole".into(),
        weak_ref: false,
    });
    b.section_mut(text)
        .relocs
        .push(ObjectReloc::got_page21(hole as u32).at(4));
    b.section_mut(text)
        .relocs
        .push(ObjectReloc::got_pageoff12(hole as u32).at(8));
    let path = dir.join(name);
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// The `LC_DYSYMTAB` the linked image carries (the raw load-command walk).
fn image_dysymtab(image: &[u8]) -> DysymtabCommand {
    let hdr = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, hdr.ncmds, hdr.sizeofcmds)
        .expect("the load-command iter builds");
    while let Ok(Some(cmd)) = it.next_command() {
        if let LoadCommandKind::Dysymtab = cmd.kind {
            return DysymtabCommand::parse(cmd.bytes, 0).expect("the dysymtab parses");
        }
    }
    panic!("no LC_DYSYMTAB in the linked image");
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
fn the_flag_names_the_decision() {
    let dir = scratch("parse");
    let obj = dylib_corpus(&dir, "main.o");
    let obj = obj.display().to_string();
    let o = opts::parse(&args(&["-dylib", "-o", "out", &obj])).expect("the plain argv parses");
    assert!(
        !o.config.module_policy.is_single(),
        "the default is multi_module (every pre-knob link byte-identical)"
    );
    let o = opts::parse(&args(&["-single_module", "-dylib", "-o", "out", &obj]))
        .expect("the flag parses");
    assert!(
        o.config.module_policy.is_single(),
        "the flag names the single_module decision"
    );
    let o = opts::parse(&args(&["-multi_module", "-dylib", "-o", "out", &obj]))
        .expect("the flag parses");
    assert!(
        !o.config.module_policy.is_single(),
        "the multi_module flag names the default face"
    );
}

#[test]
fn the_single_module_dylib_carries_the_module_table_and_verifies_strict() {
    // The producer wrote one well-formed `DylibModule64` entry whose
    // subranges mirror the `LC_DYSYMTAB`; the read-side backstop passes
    // on the well-formed table (the image verifies strict).
    let dir = scratch("e2e_single");
    let obj = dylib_corpus(&dir, "main.o");
    let out = dir.join("libpgr.dylib").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-single_module", "-dylib", "-o", &out, &obj]);
    assert_eq!(code, Some(0), "the single_module dylib links: {stderr}");
    let image = std::fs::read(&out).expect("the image writes");
    let dys = image_dysymtab(&image);
    assert_eq!(dys.nmodtab, 1, "the single_module dylib carries one module");
    assert!(dys.modtaboff > 0, "the module table rides a real offset");
    assert!(
        verify(&image, &strict()).is_ok(&strict()),
        "the single_module dylib (a well-formed module table) verifies strict"
    );
}

#[test]
fn the_default_dylib_carries_no_module_table() {
    // The pre-M119 shape: the default `-multi_module` dylib carries no
    // module table (`nmodtab = 0`, the legacy table peregrine never
    // carried — every pre-knob link byte-identical).
    let dir = scratch("e2e_default");
    let obj = dylib_corpus(&dir, "main.o");
    let out = dir.join("libpgr.dylib").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-dylib", "-o", &out, &obj]);
    assert_eq!(code, Some(0), "the default dylib links: {stderr}");
    let image = std::fs::read(&out).expect("the image writes");
    let dys = image_dysymtab(&image);
    assert_eq!(dys.nmodtab, 0, "the default dylib carries no module table");
    assert_eq!(dys.modtaboff, 0, "the default dylib carries no modtaboff");
    assert!(
        verify(&image, &strict()).is_ok(&strict()),
        "the default dylib verifies strict"
    );
}

#[test]
fn single_module_refuses_an_unresolved_strong_reference() {
    // The escalation: under `-single_module` an unresolved strong,
    // two-level reference refuses even under `-undefined dynamic_lookup`
    // (the M103 `Error` shape forced — the producer never ships a hole
    // the single-module contract names).
    let dir = scratch("e2e_escalate");
    let obj = hole_corpus(&dir, "hole.o");
    let out = dir.join("app").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&[
        "-single_module",
        "-undefined",
        "dynamic_lookup",
        "-o",
        &out,
        &obj,
    ]);
    assert_ne!(
        code,
        Some(0),
        "the single_module escalation refuses the unresolved strong hole: {stderr}"
    );
    assert!(
        stderr.contains("_hole")
            && (stderr.contains("undefined") || stderr.contains("single_module")),
        "the refusal names the hole and the contract: {stderr}"
    );
    // The default `-multi_module` lets the same hole ride (the M103
    // dynamic-lookup shape).
    let out2 = dir.join("app2").display().to_string();
    let (code, stderr) = spawn_pgr(&["-undefined", "dynamic_lookup", "-o", &out2, &obj]);
    assert_eq!(
        code,
        Some(0),
        "the multi_module face lets the hole ride: {stderr}"
    );
}

#[test]
fn single_module_refuses_on_the_relocatable_output() {
    let dir = scratch("reloc");
    let obj = dylib_corpus(&dir, "main.o");
    let out = dir.join("out.o").display().to_string();
    let obj = obj.display().to_string();
    let err = opts::parse(&args(&["-r", "-o", &out, &obj, "-single_module"]))
        .expect_err("the relocatable output refuses the knob");
    let rendered = err.to_string();
    assert!(
        rendered.contains("-single_module") && rendered.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {rendered}"
    );
}

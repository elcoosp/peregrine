//! M120 — the `-executable` driver surface: ld64's explicit filetype
//! override. The flag parses onto the config decision (forcing
//! `OutputType::Execute`), overrides `-dylib`/`-bundle` regardless of
//! order, the relocatable output refuses it (the object's filetype is the
//! input's, verbatim), and the end-to-end gates: the `-executable` image
//! carries `MH_EXECUTE`, `__PAGEZERO` first, `LC_MAIN` and no `LC_ID_DYLIB`
//! (the contract the verifier's read-side executable gate mirrors) and
//! verifies strict; `-executable` beside `-install_name` refuses (an
//! executable's identity is `LC_MAIN`, never an install name); and the
//! relocatable refusal. The spawn gates run the real binary.

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::MH_EXECUTE;
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir()
        .join("pgr_m120_executable")
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

/// `main.o`: `_main` in a `__text` body — the minimal executable corpus
/// (the entry symbol the `LC_MAIN` command names).
fn exec_corpus(dir: &Path, name: &str) -> PathBuf {
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

/// The executable contract the linked image carries: `MH_EXECUTE`,
/// `__PAGEZERO` first, `LC_MAIN` present, no `LC_ID_DYLIB`.
struct ExecShape {
    filetype: u32,
    pagezero_first: bool,
    has_main: bool,
    has_id_dylib: bool,
}

fn image_exec_shape(image: &[u8]) -> ExecShape {
    let hdr = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, hdr.ncmds, hdr.sizeofcmds)
        .expect("the load-command iter builds");
    let mut pagezero_first = false;
    let mut has_main = false;
    let mut has_id_dylib = false;
    let mut first_segment = true;
    while let Ok(Some(cmd)) = it.next_command() {
        match cmd.kind {
            LoadCommandKind::Segment64 => {
                if first_segment {
                    let name = cmd
                        .bytes
                        .get(8..24)
                        .map(|b| {
                            String::from_utf8_lossy(b)
                                .trim_end_matches('\0')
                                .to_string()
                        })
                        .unwrap_or_default();
                    pagezero_first = name == "__PAGEZERO";
                    first_segment = false;
                }
            }
            LoadCommandKind::Main => has_main = true,
            LoadCommandKind::IdDylib => has_id_dylib = true,
            _ => {}
        }
    }
    ExecShape {
        filetype: hdr.filetype,
        pagezero_first,
        has_main,
        has_id_dylib,
    }
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
    let obj = exec_corpus(&dir, "main.o");
    let obj = obj.display().to_string();
    // The default is Execute with no explicit override bit.
    let o = opts::parse(&args(&["-o", "out", &obj])).expect("the plain argv parses");
    assert!(
        !o.config.executable,
        "the default carries no explicit override (every pre-knob link byte-identical)"
    );
    assert_eq!(
        o.config.filetype,
        pgr_core::layout::OutputType::Execute,
        "the default filetype is Execute"
    );
    // `-executable` names the explicit override and forces Execute.
    let o = opts::parse(&args(&["-executable", "-o", "out", &obj])).expect("the flag parses");
    assert!(
        o.config.executable,
        "the flag names the explicit override decision"
    );
    assert_eq!(
        o.config.filetype,
        pgr_core::layout::OutputType::Execute,
        "the flag forces the Execute filetype"
    );
}

#[test]
fn the_executable_override_wins_over_dylib_and_bundle() {
    let dir = scratch("parse_override");
    let obj = exec_corpus(&dir, "main.o");
    let obj = obj.display().to_string();
    // `-dylib -executable`: the override wins (filetype Execute, not Dylib).
    let o = opts::parse(&args(&["-dylib", "-executable", "-o", "out", &obj]))
        .expect("the override-after-dylib parses");
    assert!(o.config.executable, "the override bit rides after -dylib");
    assert_eq!(
        o.config.filetype,
        pgr_core::layout::OutputType::Execute,
        "-executable overrides -dylib (the later flag forces Execute)"
    );
    // `-executable -dylib`: the override wins regardless of order (the
    // `-dylib` arm no-ops when the override bit is set).
    let o = opts::parse(&args(&["-executable", "-dylib", "-o", "out", &obj]))
        .expect("the dylib-after-override parses");
    assert!(o.config.executable, "the override bit rides before -dylib");
    assert_eq!(
        o.config.filetype,
        pgr_core::layout::OutputType::Execute,
        "-executable overrides -dylib regardless of order"
    );
    // `-bundle -executable`: the override wins over -bundle too.
    let o = opts::parse(&args(&["-bundle", "-executable", "-o", "out", &obj]))
        .expect("the override-after-bundle parses");
    assert_eq!(
        o.config.filetype,
        pgr_core::layout::OutputType::Execute,
        "-executable overrides -bundle"
    );
}

#[test]
fn the_executable_image_carries_the_execute_shape_and_verifies_strict() {
    // The `-executable` image carries the executable contract — `MH_EXECUTE`,
    // `__PAGEZERO` first, `LC_MAIN` present, no `LC_ID_DYLIB` — and verifies
    // strict (the read-side executable gate passes on the well-formed shape).
    let dir = scratch("e2e_exec");
    let obj = exec_corpus(&dir, "main.o");
    let out = dir.join("app").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-executable", "-o", &out, &obj]);
    assert_eq!(code, Some(0), "the -executable image links: {stderr}");
    let image = std::fs::read(&out).expect("the image writes");
    let shape = image_exec_shape(&image);
    assert_eq!(shape.filetype, MH_EXECUTE, "the image is MH_EXECUTE");
    assert!(shape.pagezero_first, "the image carries __PAGEZERO first");
    assert!(shape.has_main, "the image carries LC_MAIN");
    assert!(
        !shape.has_id_dylib,
        "the image carries no LC_ID_DYLIB (an executable's identity is LC_MAIN)"
    );
    assert!(
        verify(&image, &strict()).is_ok(&strict()),
        "the -executable image verifies strict"
    );
}

#[test]
fn the_executable_override_links_a_dylib_corpus_as_an_execute() {
    // `-dylib -executable`: the override forces `MH_EXECUTE` — a corpus
    // that would default to a dylib under `-dylib` alone links as an
    // executable (the override wins, the image verifies strict).
    let dir = scratch("e2e_override");
    let obj = exec_corpus(&dir, "main.o");
    let out = dir.join("app").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-dylib", "-executable", "-o", &out, &obj]);
    assert_eq!(
        code,
        Some(0),
        "the -dylib -executable corpus links as an executable: {stderr}"
    );
    let image = std::fs::read(&out).expect("the image writes");
    let shape = image_exec_shape(&image);
    assert_eq!(
        shape.filetype, MH_EXECUTE,
        "the override forces MH_EXECUTE (not a dylib)"
    );
    assert!(
        !shape.has_id_dylib,
        "the overridden image carries no LC_ID_DYLIB"
    );
    assert!(
        verify(&image, &strict()).is_ok(&strict()),
        "the overridden image verifies strict"
    );
}

#[test]
fn executable_refuses_an_install_name() {
    // An executable's identity is `LC_MAIN`, never `LC_ID_DYLIB` — the
    // override forces `MH_EXECUTE`, so an `-install_name` (a dylib
    // contract) refuses on the driver surface (the layout's own re-check
    // backs the same contract for any library caller that sets the
    // override beside an install name).
    let dir = scratch("e2e_install_name");
    let obj = exec_corpus(&dir, "main.o");
    let out = dir.join("app").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&[
        "-executable",
        "-install_name",
        "@rpath/libpgr.dylib",
        "-o",
        &out,
        &obj,
    ]);
    assert_ne!(
        code,
        Some(0),
        "the install name refuses beside the override: {stderr}"
    );
    assert!(
        stderr.contains("install_name") && stderr.contains("dylib"),
        "the refusal names the install name and the dylib contract: {stderr}"
    );
}

#[test]
fn executable_refuses_on_the_relocatable_output() {
    let dir = scratch("reloc");
    let obj = exec_corpus(&dir, "main.o");
    let out = dir.join("out.o").display().to_string();
    let obj = obj.display().to_string();
    let err = opts::parse(&args(&["-r", "-o", &out, &obj, "-executable"]))
        .expect_err("the relocatable output refuses the override");
    let rendered = err.to_string();
    assert!(
        rendered.contains("-executable") && rendered.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {rendered}"
    );
}

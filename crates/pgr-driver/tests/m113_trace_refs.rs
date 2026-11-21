//! M113 — the `-t` driver surface: ld64's reference tracing. The flag
//! parses onto the config, each symbol Pass 2's resolve visits prints to
//! stderr (the real binary's face — the driver library cannot assert its
//! own stderr), and the relocatable output refuses the knob (the object's
//! symtab is the input's, verbatim — the surface's knob refusal mirrored
//! exactly).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m113_refs").join(format!(
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

/// main.o: `_main` references `_greet`; greet.o defines `_greet` — the
/// resolved reference the trace names.
fn hello_corpus(dir: &Path) -> Vec<PathBuf> {
    let mut main = ObjectBuilder::new("main.o");
    let text = main.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    main.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = main.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let undef = main.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    let slot = main.sym_index(undef);
    main.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    let mut greet = ObjectBuilder::new("greet.o");
    let gtext = greet.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    greet.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: gtext,
        value: 0,
        weak: false,
    });
    let main_path = dir.join("main.o");
    std::fs::write(&main_path, main.build().expect("the fixture builds")).unwrap();
    let greet_path = dir.join("greet.o");
    std::fs::write(&greet_path, greet.build().expect("the fixture builds")).unwrap();
    vec![main_path, greet_path]
}

#[test]
fn the_flag_parses_onto_the_config() {
    let dir = scratch("parse");
    let objs = hello_corpus(&dir);
    let argv: Vec<String> = ["-o", "out", "-t"]
        .iter()
        .map(|s| (*s).to_string())
        .chain(objs.iter().map(|p| p.display().to_string()))
        .collect();
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the knob parses");
    assert!(o.config.trace_refs, "the trace decision rides the config");
}

#[test]
fn the_trace_prints_every_reference_to_stderr() {
    let dir = scratch("face");
    let objs = hello_corpus(&dir);
    let out = dir.join("app").display().to_string();
    let argv: Vec<String> = ["-o".to_string(), out.clone(), "-t".to_string()]
        .into_iter()
        .chain(objs.iter().map(|p| p.display().to_string()))
        .collect();
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let (code, stderr) = spawn_pgr(&argv);
    assert_eq!(code, Some(0), "the link exits 0 with the trace riding");
    assert!(
        stderr.contains("pgr: reference: _greet") && stderr.contains("main.o"),
        "the reference prints to stderr with its input: {stderr}"
    );
    assert!(Path::new(&out).exists(), "the image ships");
}

#[test]
fn the_default_traces_nothing() {
    let dir = scratch("default");
    let objs = hello_corpus(&dir);
    let out = dir.join("app").display().to_string();
    let argv: Vec<String> = ["-o".to_string(), out]
        .into_iter()
        .chain(objs.iter().map(|p| p.display().to_string()))
        .collect();
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let (code, stderr) = spawn_pgr(&argv);
    assert_eq!(code, Some(0), "the default links clean");
    assert!(
        !stderr.contains("pgr: reference:"),
        "an unasked trace never prints: {stderr}"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob() {
    let dir = scratch("reloc");
    let objs = hello_corpus(&dir);
    let obj = objs[0].display().to_string();
    let err = opts::parse(&args(&["-r", "-o", "out.o", "-t", &obj]))
        .expect_err("the object shape refuses the trace");
    let rendered = format!("{:?}", miette::Report::new(err));
    assert!(
        rendered.contains("-t"),
        "the refusal names the knob: {rendered}"
    );
    assert!(
        rendered.to_lowercase().contains("drop -t"),
        "the refusal names the fix (the house convention): {rendered}"
    );
}

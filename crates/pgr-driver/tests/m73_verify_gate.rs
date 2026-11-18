//! M73 — the `-verify` driver surface: the link's own gate. The flag
//! runs the strict verifier on the produced bytes *before* the write (a
//! failing gate ships nothing — the audit's rule, on the cold path),
//! refuses where it cannot apply (`-r` produces an object, not an image;
//! the relink ladder carries its own gate, `-incremental-verify`), and
//! the verdict rides `LinkOutcome` — the embedding caller reads the
//! gate's summary without re-reading the file.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m73_verify_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A single-object corpus (`_main`) written to `dir`.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (i, sym) in ["_main", "_helper"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    let path = dir.join("main.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    vec![path]
}

fn parse(extra: &[&str]) -> Result<pgr_driver::opts::Options, pgr_driver::opts::OptsError> {
    let argv: Vec<std::ffi::OsString> = extra.iter().map(std::ffi::OsString::from).collect();
    pgr_driver::opts::parse(&argv)
}

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flag_parses_onto_the_surface() {
    let o = parse(&["-o", "out", "-verify", "main.o"]).expect("the argv parses");
    assert!(o.verify, "the gate rides the options");
    let plain = parse(&["-o", "out", "main.o"]).expect("the argv parses");
    assert!(!plain.verify, "the gate is off by default");
}

#[test]
fn the_flag_refuses_where_it_cannot_apply() {
    // The relocatable output is an object: the verifier's object face
    // gates it as a tool, never a link gate.
    let relocatable = parse(&["-o", "out", "-r", "-verify", "main.o"]);
    assert!(relocatable.is_err(), "-verify refuses on -r");
    // The relink ladder carries its own gate.
    let incremental = parse(&["-o", "out", "-incremental", "-verify", "main.o"]);
    assert!(incremental.is_err(), "-verify refuses on -incremental");
    let err = incremental.unwrap_err();
    let rendered = format!("{:?}", miette::Report::new(err));
    assert!(
        rendered.contains("-incremental-verify"),
        "the help names the ladder's own gate: {rendered}"
    );
}

// ---- the gate ----------------------------------------------------------------

#[test]
fn the_gate_rides_the_outcome_on_a_clean_link() {
    let dir = scratch("clean");
    let objs = corpus(&dir);
    let out_path = dir.join("hello");
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string()];
    argv.push("-verify".into());
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    let summary = outcome
        .verify
        .expect("the gate's verdict rides the outcome");
    assert!(summary.ok, "the clean link passes its own gate");
    assert_eq!(summary.errors, 0);
    assert_eq!(summary.warnings, 0, "the strict pass names no warnings");
    assert!(out_path.is_file(), "the gate wrote the image");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failing_gate_names_the_issues_and_the_fix() {
    let dir = scratch("refusal");
    let objs = corpus(&dir);
    let out_path = dir.join("hello");
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string()];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    assert!(outcome.verify.is_none(), "no flag, no gate");

    // The gate's refusal face: the produced image, corrupted past the
    // segment contract — the strict pass names the issues, the refusal
    // renders the fix (the miette help text), the driver maps it to
    // `DriverError::Verify` (exit 1, nothing shipped).
    let mut corrupted = std::fs::read(&out_path).unwrap();
    let mid = corrupted.len() / 2 + 0x4000;
    corrupted[mid] ^= 0xff;
    let gate = pgr_driver::verify_gate(&corrupted, true);
    assert!(!gate.summary.ok, "the corrupted image fails its gate");
    assert!(gate.summary.errors > 0, "the segment contract refuses");
    let rendered = gate.refusal().render();
    assert!(
        rendered.contains("failed the link's verify gate"),
        "the refusal names the gate: {rendered}"
    );
    assert!(
        rendered.to_lowercase().contains("help") || rendered.contains("─"),
        "the refusal renders with its help text: {rendered}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

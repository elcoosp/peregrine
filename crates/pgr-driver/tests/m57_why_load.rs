//! M57 — the `-why_load` driver surface: the load-provenance report
//! rides the command line as a boolean (ld64's own form), defaults to
//! silence, refuses the fast-path lanes (the pull's record is the
//! one-shot pipeline's, never the wire's), and completes a real link —
//! the relocatable shape included (the pull is the same fixpoint on
//! `-r`; the dylib rows ride empty there, the knob is refused).

use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m57_load_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// `main.o`: `_main` + a data pointer at `_greet` — the reference the
/// S7 pull rides.
fn main_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
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
    let greet = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(greet as u32).at(0)],
    ));
    b.build().expect("the fixture object builds")
}

/// `greet.o`: `_greet` — the pulled member.
fn greet_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Writes the corpus (`main.o` + `libgreet.a`) and returns the paths.
fn corpus(dir: &Path) -> (PathBuf, PathBuf) {
    let main = dir.join("main.o");
    let archive = dir.join("libgreet.a");
    std::fs::write(&main, main_object()).unwrap();
    let mut a = ArchiveBuilder::new("libgreet.a");
    a.add_member("greet.o", greet_object());
    std::fs::write(&archive, a.build()).unwrap();
    (main, archive)
}

/// Parses the argv (inputs appended) into [`pgr_driver::opts::Options`].
fn parse(
    dir: &Path,
    extra: &[&str],
) -> Result<pgr_driver::opts::Options, pgr_driver::opts::OptsError> {
    let (main, archive) = corpus(dir);
    let mut argv: Vec<String> = vec!["-o".into(), dir.join("out").display().to_string()];
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    argv.push(main.display().to_string());
    argv.push(archive.display().to_string());
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    pgr_driver::opts::parse(&argv)
}

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flag_parses_and_defaults_off() {
    let dir = scratch("parse");
    let o = parse(&dir, &["-why_load"]).expect("the argv parses");
    assert!(o.why_load, "the flag rides");
    let quiet = parse(&dir, &[]).expect("the argv parses");
    assert!(!quiet.why_load, "the default reports nothing");
}

#[test]
fn the_report_rides_the_resident_lane() {
    // M79: the resident lane serves the report — the pull's record is
    // the session's own (wire v45), so the M57 resident refusal flipped
    // to service; the surface parses and carries the flag.
    let dir = scratch("resident");
    let o = parse(&dir, &["-why_load", "-resident"]).expect("the resident lane serves");
    assert!(o.resident && o.why_load, "the flag rides the lane");
}

#[test]
fn the_report_serves_the_incremental_lane() {
    // M84: the ladder's own walk collects the pull record (the relink
    // re-parses the inputs and re-runs the S7 fixpoint), so the M57
    // incremental refusal flipped to service — the report rides either
    // lane.
    let dir = scratch("incremental");
    let o = parse(&dir, &["-why_load", "-incremental"]).expect("the lane serves");
    assert!(o.incremental && o.why_load, "the flags ride");
}

// ---- the run ------------------------------------------------------------------

#[test]
fn a_link_with_the_report_completes() {
    let dir = scratch("run");
    let o = parse(&dir, &["-why_load"]).expect("the argv parses");
    let outcome = pgr_driver::run(&o).expect("the link runs with the report");
    assert!(outcome.file_size > 0);
    assert!(Path::new(&dir.join("out")).exists(), "the image ships");
}

#[test]
fn the_report_rides_the_relocatable_output() {
    let dir = scratch("reloc");
    let o = parse(&dir, &["-r", "-why_load"]).expect("the argv parses");
    let outcome = pgr_driver::run(&o).expect("the relocatable link runs");
    assert!(outcome.file_size > 0);
}

#[test]
fn the_report_composes_with_the_query() {
    let dir = scratch("compose");
    let o = parse(&dir, &["-why_load", "-why_export", "_greet"]).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs with both reports");
}

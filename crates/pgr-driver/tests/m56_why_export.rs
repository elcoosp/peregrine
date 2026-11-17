//! M56 — the `-why_export <symbol>` driver surface: the provenance
//! query joins the command line — repeatable, an empty name refuses
//! (the flag-grammar convention), the fast-path lanes refuse the query
//! (a served or patched relink's Pass-2 product never crosses the wire
//! — the query runs on the one-shot link's own arena), and a one-shot
//! link under the flag completes with the query answered (a misspelled
//! name refuses the *run* with the misspelling named — a vacuous
//! decision is never silently dropped).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m56_why_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// The M56 corpus: `main.o` references `_greet` (defined in `greet.o`)
/// through two 8-byte data pointers.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut main = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
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
    let greet = main.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    main.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 16],
        vec![
            pgr_fixtures::ObjectReloc::unsigned(greet as u32).at(0),
            pgr_fixtures::ObjectReloc::unsigned(greet as u32).at(8),
        ],
    ));
    let mut lib = ObjectBuilder::new("greet.o").set_subsections_via_symbols(true);
    let ltext = lib.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    lib.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: ltext,
        value: 0,
        weak: false,
    });
    let a = dir.join("main.o");
    let b = dir.join("greet.o");
    std::fs::write(&a, main.build().expect("main.o builds")).unwrap();
    std::fs::write(&b, lib.build().expect("greet.o builds")).unwrap();
    vec![a, b]
}

/// Parses the argv (inputs appended) into [`pgr_driver::opts::Options`].
fn parse(
    dir: &Path,
    extra: &[&str],
) -> Result<pgr_driver::opts::Options, pgr_driver::opts::OptsError> {
    let objs = corpus(dir);
    let mut argv: Vec<String> = vec!["-o".into(), dir.join("out").display().to_string()];
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    pgr_driver::opts::parse(&argv)
}

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flag_parses_repeatable() {
    let dir = scratch("parse");
    let o =
        parse(&dir, &["-why_export", "_greet", "-why_export", "_main"]).expect("the argv parses");
    assert_eq!(
        o.why_export,
        vec!["_greet".to_string(), "_main".to_string()]
    );
}

#[test]
fn an_empty_name_refuses() {
    let dir = scratch("empty");
    let err = parse(&dir, &["-why_export", ""]).expect_err("the empty name refuses");
    let rendered = err.to_string();
    assert!(
        rendered.contains("-why_export"),
        "the flag is named: {rendered}"
    );
}

#[test]
fn the_query_refuses_the_resident_lane() {
    let dir = scratch("resident");
    let err = parse(&dir, &["-why_export", "_greet", "-resident"])
        .expect_err("the resident conflict refuses");
    let rendered = err.to_string();
    assert!(
        rendered.contains("-why_export") && rendered.contains("-resident"),
        "the conflict names both flags: {rendered}"
    );
    assert!(
        rendered.contains("one-shot"),
        "the fix names the lane the query runs on: {rendered}"
    );
}

#[test]
fn the_query_refuses_the_incremental_lane() {
    let dir = scratch("incremental");
    let err = parse(&dir, &["-why_export", "_greet", "-incremental"])
        .expect_err("the incremental conflict refuses");
    let rendered = err.to_string();
    assert!(
        rendered.contains("-why_export") && rendered.contains("-incremental"),
        "the conflict names both flags: {rendered}"
    );
}

// ---- the run ------------------------------------------------------------------

#[test]
fn a_one_shot_link_with_a_query_completes() {
    let dir = scratch("run");
    let o = parse(&dir, &["-why_export", "_greet"]).expect("the argv parses");
    let outcome = pgr_driver::run(&o).expect("the link runs with the query");
    assert!(outcome.file_size > 0);
    assert!(Path::new(&dir.join("out")).exists(), "the image ships");
}

#[test]
fn a_misspelled_query_refuses_the_run() {
    let dir = scratch("misspelled");
    let o = parse(&dir, &["-why_export", "_grete"]).expect("the argv parses");
    let err = pgr_driver::run(&o).expect_err("the vacuous query refuses");
    let rendered = err.to_string();
    assert!(
        rendered.contains("_grete"),
        "the misspelling is named: {rendered}"
    );
}

#[test]
fn the_query_rides_the_relocatable_output() {
    let dir = scratch("reloc");
    let o = parse(&dir, &["-r", "-why_export", "_greet"]).expect("the argv parses");
    let outcome = pgr_driver::run(&o).expect("the relocatable link runs");
    assert!(outcome.file_size > 0);
}

#[test]
fn the_default_stays_quiet() {
    let dir = scratch("quiet");
    let o = parse(&dir, &[]).expect("the argv parses");
    assert!(o.why_export.is_empty(), "the default queries nothing");
    pgr_driver::run(&o).expect("the plain link runs");
}

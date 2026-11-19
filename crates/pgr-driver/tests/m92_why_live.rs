//! M92 — the `-why_live <symbol>` driver surface: the liveness query
//! joins the command line — repeatable, an empty name refuses (the
//! flag-grammar convention), and the resident lanes refuse the flag
//! (the wire's provenance tail v45 carries the `-why_export`/
//! `-why_load` asks; the liveness ask joins at a later rung — the M56
//! contract's own shape, the served rung a later milestone). A one-shot
//! link under the flag completes with the chain answered (a misspelled
//! name refuses the *run* with the misspelling named — a vacuous
//! decision is never silently dropped), a link without `-dead_strip`
//! refuses the query's premise (the strip is the question's subject),
//! and the in-process incremental ladder answers from its own walk's
//! record (the relink re-runs the full Passes 1–3, the record rides
//! `LinkResult::liveness`).

use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m92_live_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// The M92 corpus: `main.o` calls `_greet` (defined in `greet.o`)
/// through a `branch26` — the entry atom carries the edge the strip
/// follows, so `-dead_strip` keeps both and the chain is one hop.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut main = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    main.add_section(ObjectSection::text(
        "__text",
        [0x9400_0000u32.to_le_bytes(), 0xD65F_03C0u32.to_le_bytes()].concat(),
        vec![],
    ));
    main.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    let _ = main.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    main.section_mut(0)
        .relocs
        .push(ObjectReloc::branch26(1).at(0));

    let mut lib = ObjectBuilder::new("greet.o").set_subsections_via_symbols(true);
    let ltext = lib.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
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
    let o = parse(&dir, &["-why_live", "_greet", "-why_live", "_main"]).expect("the argv parses");
    assert_eq!(o.why_live, vec!["_greet".to_string(), "_main".to_string()]);
}

#[test]
fn an_empty_name_refuses() {
    let dir = scratch("empty");
    let err = parse(&dir, &["-why_live", ""]).expect_err("the empty name refuses");
    let rendered = err.to_string();
    assert!(
        rendered.contains("-why_live"),
        "the flag is named: {rendered}"
    );
}

#[test]
fn the_resident_lane_refuses_the_flag() {
    // The wire's provenance tail (v45) carries the why_export/why_load
    // asks; the liveness ask joins at a later rung. The refusal is the
    // M56 contract's own shape: the verdict names the rung, the fix
    // names the lane.
    let dir = scratch("resident");
    let err = parse(&dir, &["-why_live", "_greet", "-resident"])
        .expect_err("the resident lane refuses the flag");
    let rendered = err.to_string();
    assert!(
        rendered.contains("resident"),
        "the lane is named: {rendered}"
    );
}

#[test]
fn the_incremental_ladder_parses_the_flag() {
    // The in-process ladder answers from its own walk's record — the
    // flag rides beside `-incremental` (no surface refusal).
    let dir = scratch("incremental");
    let o =
        parse(&dir, &["-why_live", "_greet", "-incremental"]).expect("the ladder parses the flag");
    assert!(o.incremental, "the lane rides");
    assert_eq!(o.why_live, vec!["_greet".to_string()]);
}

// ---- the run ------------------------------------------------------------------

#[test]
fn a_one_shot_link_with_a_query_completes() {
    let dir = scratch("run");
    let o = parse(&dir, &["-dead_strip", "-why_live", "_greet"]).expect("the argv parses");
    let outcome = pgr_driver::run(&o).expect("the link runs with the query");
    assert!(outcome.file_size > 0);
    assert!(Path::new(&dir.join("out")).exists(), "the image ships");
}

#[test]
fn a_misspelled_query_refuses_the_run() {
    let dir = scratch("misspelled");
    let o = parse(&dir, &["-dead_strip", "-why_live", "_grete"]).expect("the argv parses");
    let err = pgr_driver::run(&o).expect_err("the vacuous query refuses");
    let rendered = err.to_string();
    assert!(
        rendered.contains("_grete"),
        "the misspelling is named: {rendered}"
    );
}

#[test]
fn a_query_without_the_strip_refuses_the_premise() {
    let dir = scratch("nostrip");
    let o = parse(&dir, &["-why_live", "_greet"]).expect("the argv parses");
    let err = pgr_driver::run(&o).expect_err("no strip: nothing to explain");
    let rendered = err.to_string();
    assert!(
        rendered.contains("-dead_strip"),
        "the premise names the fix: {rendered}"
    );
}

#[test]
fn the_default_stays_quiet() {
    let dir = scratch("quiet");
    let o = parse(&dir, &[]).expect("the argv parses");
    assert!(o.why_live.is_empty(), "the default queries nothing");
    pgr_driver::run(&o).expect("the plain link runs");
}

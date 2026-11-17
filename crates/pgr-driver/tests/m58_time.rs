//! M58 — the `--time` driver surface: the per-pass wall report rides
//! the command line as a pair of Peregrine-specific query flags
//! (`--time` the text table, `--time-json` the interchange line),
//! defaults to silence, refuses the fast-path lanes (the one-shot
//! pipeline is what the observer sees — the resident relink runs on
//! the wire, the incremental ladder runs in the engine), and completes
//! a real link — the relocatable shape included — without moving a
//! byte of the output (the parity gate on the driver surface).
//!
//! Gate matrix:
//! * the parse — both flags parse, the default reports nothing, the
//!   lane conflicts name both flags and their fix;
//! * the run — a linked image carries the printed table (the real
//!   binary's stdout, the surface's consumer face) and the JSON line;
//! * the parity — a `--time` link's bytes are the plain link's bytes;
//! * the composition — `--time` rides with the other reports
//!   (`-why_load`) and with `-r` (the object shape's own run).

use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectSection, ObjectSymbol};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m58_time_{}_{}", tag, std::process::id()));
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
        vec![pgr_fixtures::ObjectReloc::unsigned(greet as u32).at(0)],
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
fn the_flags_parse_and_default_off() {
    let dir = scratch("parse");
    let o = parse(&dir, &["--time"]).expect("the argv parses");
    assert!(o.time, "--time rides");
    assert!(!o.time_json, "--time stays off when only --time rides");
    let j = parse(&dir, &["--time-json"]).expect("the argv parses");
    assert!(j.time_json, "--time-json rides");
    assert!(!j.time, "--time stays off when only --time-json rides");
    let quiet = parse(&dir, &[]).expect("the argv parses");
    assert!(
        !quiet.time && !quiet.time_json,
        "the default reports nothing"
    );
    let both = parse(&dir, &["--time", "--time-json"]).expect("the argv parses");
    assert!(both.time && both.time_json, "the two faces compose");
}

/// M65: the in-process incremental ladder rides the report — the §7.3
/// rungs joined the observation seam's vocabulary (the run gate lives in
/// `m65_relink_timeline.rs`). M66: the fusion lane rides too — the
/// session's ladder reports its own rungs beside the warm pipeline and
/// the reply's tail carries the report (wire v42 in service).
#[test]
fn the_report_rides_the_ladder_and_the_fusion_lane() {
    let dir = scratch("json");
    let o = parse(&dir, &["--time-json", "-incremental"]).expect("the ladder rides");
    assert!(
        o.time_json && o.incremental,
        "--time-json rides beside -incremental"
    );
    let f = parse(&dir, &["--time", "-resident", "-incremental"]).expect("the fusion lane rides");
    assert!(
        f.time && f.resident && f.incremental,
        "--time rides beside -resident -incremental"
    );
}

/// M59 (wire v40): the resident lane carries the report — the parse
/// admits `--time` beside `-resident` (the session observes its own
/// pipeline and serves the table; the client's fallback re-runs the
/// one-shot link, whose report prints the same way).
#[test]
fn the_resident_lane_carries_the_report() {
    let dir = scratch("resident");
    let o = parse(&dir, &["--time", "-resident"]).expect("the resident lane parses");
    assert!(o.time, "--time rides beside -resident");
    let j = parse(&dir, &["--time-json", "-resident"]).expect("the resident lane parses");
    assert!(j.time_json, "--time-json rides beside -resident");
}

// ---- the run ------------------------------------------------------------------

/// Runs the real `pgr` binary over the corpus and returns stdout.
fn run_binary(dir: &Path, out: &str, extra: &[&str]) -> String {
    let (main, archive) = corpus(dir);
    let mut args: Vec<String> = vec![
        "-o".into(),
        dir.join(out).display().to_string(),
        "-platform_version".into(),
        "macos".into(),
        "12.0".into(),
        "14.0".into(),
    ];
    args.extend(extra.iter().map(std::string::ToString::to_string));
    args.push(main.display().to_string());
    args.push(archive.display().to_string());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pgr"))
        .args(&args)
        .output()
        .expect("the pgr binary spawns");
    assert!(
        output.status.success(),
        "the link succeeds: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout is text")
}

#[test]
fn the_table_prints_beside_a_real_link() {
    let dir = scratch("binary");
    let stdout = run_binary(&dir, "timed", &["--time"]);
    assert!(
        stdout.contains("the per-pass wall report"),
        "the table rides stdout:\n{stdout}"
    );
    for phase in ["parse", "archive_pull", "intern", "resolve", "layout"] {
        assert!(stdout.contains(phase), "the {phase} row rides: {stdout}");
    }
    assert!(stdout.contains("  emit "), "the emit band rides: {stdout}");
    assert!(
        stdout.contains("  total "),
        "the total band rides: {stdout}"
    );
    assert!(Path::new(&dir.join("timed")).exists(), "the image ships");
}

#[test]
fn the_json_line_prints_beside_a_real_link() {
    let dir = scratch("json_binary");
    let stdout = run_binary(&dir, "timed_json", &["--time-json"]);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("{\"phases\":["))
        .expect("one interchange line rides stdout");
    assert!(
        line.contains("\"phase\":\"parse\"")
            && line.contains("\"emit_us\":")
            && line.contains("\"total_us\":"),
        "the line carries the phases and the bands: {line}"
    );
}

#[test]
fn the_timed_link_matches_the_plain_link_byte_for_byte() {
    let dir = scratch("parity");
    let plain = parse(&dir, &[]).expect("the argv parses");
    let quiet = pgr_driver::run(&plain).expect("the plain link runs");
    let mut timed = parse(&dir, &["--time"]).expect("the argv parses");
    timed.output = dir.join("timed").display().to_string();
    let tracked = pgr_driver::run(&timed).expect("the timed link runs");
    let plain_bytes = std::fs::read(dir.join(&plain.output)).expect("the plain image reads");
    let timed_bytes = std::fs::read(dir.join(&timed.output)).expect("the timed image reads");
    assert_eq!(plain_bytes, timed_bytes, "reporting never moves a byte");
    assert_eq!(quiet.file_size, tracked.file_size);
}

#[test]
fn the_report_rides_the_relocatable_output() {
    let dir = scratch("reloc");
    let o = parse(&dir, &["-r", "--time"]).expect("the argv parses");
    let outcome = pgr_driver::run(&o).expect("the relocatable link runs");
    assert!(outcome.file_size > 0);
}

#[test]
fn the_report_composes_with_the_other_reports() {
    let dir = scratch("compose");
    let o = parse(&dir, &["--time", "-why_load"]).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs with both reports");
}

/// M59: a `-resident --time` link completes and prints the table —
/// the session's served report when the daemon answers, the one-shot
/// fallback's report when it does not (either way the run is observed
/// and the table prints).
#[test]
fn the_resident_cycle_prints_the_table() {
    let dir = scratch("resident_binary");
    let stdout = run_binary(&dir, "resident_timed", &["--time", "-resident"]);
    assert!(
        stdout.contains("the per-pass wall report"),
        "the table rides stdout (served or fallback):\n{stdout}"
    );
    assert!(
        Path::new(&dir.join("resident_timed")).exists(),
        "the image ships"
    );
}

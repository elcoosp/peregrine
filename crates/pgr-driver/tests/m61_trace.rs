//! M61 — the `--trace` driver surface: the link's Chrome-trace timeline
//! rides the command line as a Peregrine-specific query flag (the
//! roadmap §9.4 toolbox's `--trace <path>`), defaults to silence,
//! refuses the fast-path lanes (the one-shot pipeline is what the
//! collector sees — the resident session's timeline rides wire v41, the
//! incremental ladder runs in the engine), and completes a real link —
//! the relocatable shape included — without moving a byte of the output
//! (the parity gate on the driver surface).
//!
//! Gate matrix:
//! * the parse — the flag parses with its path, the default writes
//!   nothing, an empty path refuses, the lane conflicts name both flags
//!   and their fix;
//! * the run — a linked image carries the timeline file beside it (the
//!   real binary's sidecar, the surface's consumer face), and the file
//!   parses back through the core seam's strict reader;
//! * the parity — a `--trace` link's bytes are the plain link's bytes;
//! * the composition — `--trace` rides with the other reports (`--time`)
//!   and with `-r` (the object shape's own run).

use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectSection, ObjectSymbol};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m61_trace_{}_{}", tag, std::process::id()));
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
fn the_flag_parses_and_defaults_off() {
    let dir = scratch("parse");
    let o = parse(&dir, &["--trace", "t.json"]).expect("the argv parses");
    assert_eq!(
        o.trace_path.as_deref(),
        Some("t.json"),
        "--trace rides with its path"
    );
    let quiet = parse(&dir, &[]).expect("the argv parses");
    assert!(quiet.trace_path.is_none(), "the default writes nothing");
    let empty = parse(&dir, &["--trace", ""]);
    assert!(empty.is_err(), "an empty path refuses");
    // A pathless flag rides last — `next_value` consumes the next argv
    // element, so a mid-line `--trace` takes the input's place (the
    // getopt shape every value flag here shares).
    let (main, archive) = corpus(&dir);
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("out").display().to_string(),
        main.display().to_string(),
        archive.display().to_string(),
        "--trace".to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    assert!(
        pgr_driver::opts::parse(&argv).is_err(),
        "a pathless flag refuses"
    );
}

#[test]
fn the_timeline_rides_the_engine_lane_and_the_resident_lane() {
    let dir = scratch("lanes");
    // M65: the in-process incremental ladder rides the timeline — the
    // §7.3 rungs joined the seam's vocabulary, so `--trace` beside
    // `-incremental` no longer refuses (the run gate lives in
    // `m65_relink_timeline.rs`).
    let ladder = parse(&dir, &["--trace", "t.json", "-incremental"]).expect("the lane rides");
    assert!(
        ladder.trace_path.is_some() && ladder.incremental,
        "--trace rides beside -incremental"
    );
    // M66: the fusion lane rides too — the session's ladder reports its
    // rungs beside the warm pipeline and the reply's tail carries the
    // rendered document (wire v42 in service; the run gate lives in
    // `m65_relink_timeline.rs`).
    let fusion = parse(&dir, &["--trace", "t.json", "-resident", "-incremental"])
        .expect("the fusion lane rides");
    assert!(
        fusion.trace_path.is_some() && fusion.resident && fusion.incremental,
        "--trace rides beside -resident -incremental"
    );
    // M62 (wire v41): the resident lane carries the timeline — the
    // session observes its own pipeline and the reply's tail serves the
    // rendered document (the client writes it to `--trace`'s path).
    let resident = parse(&dir, &["--trace", "t.json", "-resident"]).expect("the lane parses");
    assert!(
        resident.trace_path.is_some() && resident.resident,
        "--trace rides beside -resident"
    );
    // The resident lane keeps serving the time report (wire v40): the
    // two faces compose on the same request.
    let both =
        parse(&dir, &["--time", "--trace", "t.json", "-resident"]).expect("the paired faces parse");
    assert!(both.time && both.trace_path.is_some());
}

// ---- the run ------------------------------------------------------------------

/// Runs the real `pgr` binary over the corpus (stdout returned; the link
/// must succeed).
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
fn the_timeline_writes_beside_the_link_and_round_trips() {
    let dir = scratch("run");
    let trace = dir.join("trace.json");
    run_binary(&dir, "out", &["--trace", trace.to_str().unwrap()]);
    let raw = std::fs::read_to_string(&trace).expect("the timeline file writes");
    let report = pgr_core::trace::parse_trace_json(&raw)
        .expect("the written timeline parses (the strict reader)");
    let phases: Vec<pgr_core::Phase> = report.spans.iter().map(|s| s.phase).collect();
    assert_eq!(
        phases,
        vec![
            pgr_core::Phase::Parse,
            pgr_core::Phase::ArchivePull,
            pgr_core::Phase::Intern,
            pgr_core::Phase::Resolve,
            pgr_core::Phase::Liveness,
            pgr_core::Phase::Fold,
            pgr_core::Phase::Layout,
        ],
        "the real link's seven phases ride the timeline"
    );
    assert_eq!(
        report.lanes,
        vec![pgr_core::trace::TraceLane {
            id: 1,
            name: "pgr link".to_string(),
        }],
        "one lane (the pipeline thread)"
    );
    // The starts never move backwards (the seam's arrival order).
    for pair in report.spans.windows(2) {
        assert!(pair[0].start_us <= pair[1].start_us, "the ts order rides");
    }
    // The interchange re-renders byte-identically (the reader restored
    // the writer's data).
    assert_eq!(report.render(), raw);
}

#[test]
fn the_traced_link_matches_the_plain_link() {
    let dir = scratch("parity");
    let trace = dir.join("trace.json");
    run_binary(&dir, "plain", &[]);
    run_binary(&dir, "traced", &["--trace", trace.to_str().unwrap()]);
    let plain = std::fs::read(dir.join("plain")).expect("the plain image");
    let traced = std::fs::read(dir.join("traced")).expect("the traced image");
    assert_eq!(
        plain, traced,
        "the traced link plans the identical image (the parity gate)"
    );
}

#[test]
fn the_timeline_composes_with_the_time_report() {
    let dir = scratch("compose");
    let trace = dir.join("trace.json");
    run_binary(&dir, "out", &["--time", "--trace", trace.to_str().unwrap()]);
    let raw = std::fs::read_to_string(&trace).expect("the timeline writes beside the report");
    let report = pgr_core::trace::parse_trace_json(&raw).expect("the timeline parses");
    assert!(
        report
            .spans
            .iter()
            .any(|s| s.phase == pgr_core::Phase::Resolve),
        "the paired collectors saw the same run"
    );
}

#[test]
fn the_reloc_shape_rides_its_own_timeline() {
    let dir = scratch("reloc");
    let trace = dir.join("trace.json");
    run_binary(&dir, "out.o", &["-r", "--trace", trace.to_str().unwrap()]);
    let raw = std::fs::read_to_string(&trace).expect("the object shape's timeline writes");
    let report = pgr_core::trace::parse_trace_json(&raw).expect("the timeline parses");
    assert!(
        report
            .spans
            .iter()
            .any(|s| s.phase == pgr_core::Phase::Reloc),
        "the reloc row rides the object shape's run"
    );
    assert!(
        !report
            .spans
            .iter()
            .any(|s| s.phase == pgr_core::Phase::Layout),
        "the object shape plans no segment layout"
    );
}

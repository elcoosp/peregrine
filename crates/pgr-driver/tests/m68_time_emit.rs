//! M68 — the emit half joins the `--time`/`--time-json`/`--trace` faces:
//! the one-shot pipeline's Passes 4–5 stop being the caller's opaque band
//! and ride the observation seam — the report's rows name `emit` (the
//! fused tile emit) and `flush` (the pooled atomic write) beside the
//! pipeline's passes, the timeline carries their spans, and the parity
//! gate holds: a timing link ships the plain link's bytes.
//!
//! Gate matrix:
//! * the table — a `--time` link prints the emit and flush rows with
//!   their detail (tiles/bytes, blocks/writers) and the total band;
//! * the interchange — the `--time-json` line carries the two rows and
//!   keeps the band keys (`emit_us` stays the library caller's `null`);
//! * the timeline — the `--trace` document carries the emit/flush spans;
//! * the parity — the timed link's bytes are the plain link's bytes.

use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectSection, ObjectSymbol};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m68_emit_{}_{}", tag, std::process::id()));
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
        vec![
            pgr_fixtures::ObjectReloc::unsigned(
                u32::try_from(greet).expect("the symbol index fits u32"),
            )
            .at(0),
        ],
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

// ---- the table ----------------------------------------------------------------

#[test]
fn the_emit_and_flush_rows_ride_the_table() {
    let dir = scratch("table");
    let stdout = run_binary(&dir, "timed", &["--time"]);
    assert!(
        stdout.contains("the per-pass wall report"),
        "the table rides stdout:\n{stdout}"
    );
    let emit_at = stdout.find("  emit ").expect("the emit row rides");
    let flush_at = stdout.find("  flush ").expect("the flush row rides");
    assert!(
        emit_at < flush_at,
        "the rows ride in link order (emit, flush):\n{stdout}"
    );
    assert!(
        stdout.contains("tiles=") && stdout.contains("bytes="),
        "the emit row names the plan's shape:\n{stdout}"
    );
    assert!(
        stdout.contains("blocks=") && stdout.contains("writers="),
        "the flush row names the pool's shape:\n{stdout}"
    );
    assert!(
        stdout.contains("  total "),
        "the total band rides: {stdout}"
    );
    assert!(Path::new(&dir.join("timed")).exists(), "the image ships");
}

#[test]
fn the_json_line_carries_the_emit_rows() {
    let dir = scratch("json");
    let stdout = run_binary(&dir, "timed_json", &["--time-json"]);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("{\"phases\":["))
        .expect("one interchange line rides stdout");
    assert!(
        line.contains("\"phase\":\"emit\"") && line.contains("\"kind\":\"emitted\""),
        "the emitted row rides the interchange: {line}"
    );
    assert!(
        line.contains("\"phase\":\"flush\"") && line.contains("\"kind\":\"flushed\""),
        "the flushed row rides the interchange: {line}"
    );
    assert!(
        line.contains("\"emit_us\":null") && line.contains("\"total_us\":"),
        "the band keys stay the library caller's; the total rides: {line}"
    );
}

// ---- the timeline -------------------------------------------------------------

#[test]
fn the_timeline_carries_the_emit_spans() {
    let dir = scratch("trace");
    let trace_path = dir.join("trace.json");
    let stdout = run_binary(
        &dir,
        "traced",
        &["--trace", trace_path.display().to_string().as_str()],
    );
    let _ = stdout;
    let timeline = std::fs::read_to_string(&trace_path).expect("the timeline writes");
    assert!(
        timeline.contains("\"name\":\"emit\"") && timeline.contains("\"name\":\"flush\""),
        "the emit and flush spans ride the timeline: {timeline}"
    );
    assert!(
        timeline.contains("\"kind\":\"emitted\"") && timeline.contains("\"kind\":\"flushed\""),
        "the spans carry their details: {timeline}"
    );
}

// ---- the parity ---------------------------------------------------------------

#[test]
fn the_timed_link_matches_the_plain_link_byte_for_byte() {
    let dir = scratch("parity");
    let plain = parse(&dir, &[]).expect("the argv parses");
    let quiet = pgr_driver::run(&plain).expect("the plain link runs");
    let mut timed = parse(&dir, &["--time"]).expect("the argv parses");
    timed.output = dir.join("timed").display().to_string();
    let loud = pgr_driver::run(&timed).expect("the timed link runs");
    assert_eq!(
        std::fs::read(&quiet.output).expect("the plain image reads"),
        std::fs::read(&loud.output).expect("the timed image reads"),
        "the parity gate: the observed run ships the plain run's bytes"
    );
}

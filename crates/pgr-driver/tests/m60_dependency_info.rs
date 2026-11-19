//! M60 — the `-dependency_info <path>` driver surface: ld64's
//! build-system sidecar rides Peregrine. After a successful link the
//! driver writes the binary dependency record (the ld64 format the
//! `pgr_core::dep_info` seam validates and renders): the linker-version
//! row, every file the link read as a `0x10` input row (objects,
//! archives, resolved `-l`/`-framework` libraries, `-sectcreate`
//! payloads, the export-filter lists, `-bundle_loader`), every
//! probed-but-missing `-l` candidate as `0x11`, and the output (the
//! `-map` beside it) as `0x40`. The record is the link's read set —
//! never plan-derived — so it composes with every lane that actually
//! reads the files (the resident lane's client-side list included) and —
//! since M85 — the incremental ladder (the relink's Pass 0 re-reads
//! every input it maps and records the read set while the reads happen).
//!
//! Gate matrix:
//! * the record — a real link writes the file; the parsed rows name the
//!   read set (the output, the inputs, the probes);
//! * the composition — `-map` rides the output opcode, `-r` writes the
//!   object link's record, `-resident` writes from the client-side list
//!   (the fallback keeps the one link's record);
//! * the parity — a record-writing link plans the identical image the
//!   plain link does (a sidecar never moves a byte);
//! * the refusals — an empty path refuses at parse; the M60
//!   `-incremental` refusal flipped to service in M85 (`m85_incremental_dep_info.rs`
//!   gates the ladder's own record).

use pgr_core::dep_info::{DependencyRecord, INPUT, NOT_FOUND, OUTPUT};
use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectSection, ObjectSymbol};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m60_dep_info_{}_{}", tag, std::process::id()));
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

/// Writes `main.o` and `libgreet.a` into `dir`.
fn corpus(dir: &Path) -> (PathBuf, PathBuf) {
    let main = dir.join("main.o");
    let archive = dir.join("libgreet.a");
    std::fs::write(&main, main_object()).unwrap();
    let mut a = ArchiveBuilder::new("libgreet.a");
    a.add_member("greet.o", greet_object());
    std::fs::write(&archive, a.build()).unwrap();
    (main, archive)
}

/// Runs the real `pgr` binary over the corpus with `extra` argv and
/// asserts the link succeeded.
fn run_link(dir: &Path, out: &str, extra: &[&str]) {
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
}

/// Parses the dependency file the link wrote.
fn read_record(dir: &Path, name: &str) -> DependencyRecord {
    let bytes = std::fs::read(dir.join(name)).expect("the dependency file exists");
    DependencyRecord::parse(&bytes).expect("the record parses")
}

/// The record's rows as `(opcode, path)` pairs.
fn rows(r: &DependencyRecord) -> Vec<(u8, String)> {
    r.entries()
        .iter()
        .map(|e| (e.opcode, String::from_utf8_lossy(&e.path).into_owned()))
        .collect()
}

// ---- the record ---------------------------------------------------------------

#[test]
fn the_record_writes_beside_a_real_link() {
    let dir = scratch("record");
    run_link(
        &dir,
        "app",
        &["-dependency_info", dir.join("app.deps").to_str().unwrap()],
    );
    let r = read_record(&dir, "app.deps");
    assert!(
        r.linker_version().starts_with("pgr "),
        "the version row names the tool: {}",
        r.linker_version()
    );
    let got = rows(&r);
    let output = dir.join("app").display().to_string();
    let main = dir.join("main.o").display().to_string();
    let archive = dir.join("libgreet.a").display().to_string();
    assert!(
        got.contains(&(OUTPUT, output.clone())),
        "the output row rides 0x40: {got:?}"
    );
    assert!(
        got.contains(&(INPUT, main.clone())),
        "the object rides an input row: {got:?}"
    );
    assert!(
        got.contains(&(INPUT, archive.clone())),
        "the archive rides an input row: {got:?}"
    );
    assert!(
        got.iter()
            .all(|(op, _)| matches!(*op, INPUT | NOT_FOUND | OUTPUT)),
        "only the ld64 opcodes ride: {got:?}"
    );
}

#[test]
fn the_library_search_rides_probes_and_hits() {
    // `-lgreet` with only `libgreet.a` on the search path: the
    // `.tbd`/`.dylib` candidates probe and miss (the `0x11` rows ld64's
    // `checkFileExists` records), then the `.a` candidate hits (the
    // `0x10` row).
    let dir = scratch("search");
    let (main, _) = corpus(&dir);
    let deps = dir.join("search.deps");
    let mut args: Vec<String> = vec![
        "-o".into(),
        dir.join("searched").display().to_string(),
        "-dependency_info".into(),
        deps.display().to_string(),
        "-L".into(),
        dir.display().to_string(),
        "-lgreet".into(),
    ];
    args.push(main.display().to_string());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pgr"))
        .args(&args)
        .output()
        .expect("the pgr binary spawns");
    assert!(
        output.status.success(),
        "the link succeeds: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let r = read_record(&dir, "search.deps");
    let got = rows(&r);
    assert!(
        got.contains(&(INPUT, dir.join("libgreet.a").display().to_string())),
        "the resolved archive rides an input row: {got:?}"
    );
    let misses: Vec<&String> = got
        .iter()
        .filter(|(op, _)| *op == NOT_FOUND)
        .map(|(_, p)| p)
        .collect();
    assert!(
        misses.contains(&&dir.join("libgreet.tbd").display().to_string()),
        "the missed tbd candidate rides a not-found row: {got:?}"
    );
    assert!(
        misses.contains(&&dir.join("libgreet.dylib").display().to_string()),
        "the missed dylib candidate rides a not-found row: {got:?}"
    );
}

#[test]
fn the_map_rides_the_output_opcode() {
    // ld64 records the map beside the output under `depOutputFile` — the
    // map is a build artifact of the same link, and a build system
    // re-links when either moves.
    let dir = scratch("map");
    let map = dir.join("app.map");
    run_link(
        &dir,
        "app",
        &[
            "-map",
            map.to_str().unwrap(),
            "-dependency_info",
            dir.join("app.deps").to_str().unwrap(),
        ],
    );
    let r = read_record(&dir, "app.deps");
    let got = rows(&r);
    assert!(
        got.contains(&(OUTPUT, map.display().to_string())),
        "the map rides a 0x40 row beside the output: {got:?}"
    );
}

// ---- the lanes ----------------------------------------------------------------

#[test]
fn the_incremental_lane_serves_the_record() {
    // M85: the relink's Pass 0 re-reads every input it maps (the
    // re-parse is the digest source) and records the read set while the
    // reads happen, so the M60 incremental refusal flipped to service —
    // the record rides either lane.
    let dir = scratch("refuse");
    let deps = dir.join("app.deps");
    let mut argv: Vec<std::ffi::OsString> = vec![
        "-o".into(),
        dir.join("app").as_os_str().to_os_string(),
        "-incremental".into(),
        "-dependency_info".into(),
        deps.as_os_str().to_os_string(),
    ];
    argv.push(std::ffi::OsString::from("x.o"));
    let o = pgr_driver::opts::parse(&argv).expect("the lane serves the record");
    assert!(
        o.incremental && o.dependency_info.is_some(),
        "the record rides"
    );
}

#[test]
fn an_empty_path_refuses_at_parse() {
    let dir = scratch("empty");
    let mut argv: Vec<std::ffi::OsString> = vec![
        "-o".into(),
        dir.join("app").as_os_str().to_os_string(),
        "-dependency_info".into(),
        "".into(),
    ];
    argv.push(std::ffi::OsString::from("x.o"));
    let err = pgr_driver::opts::parse(&argv).expect_err("the empty path refuses");
    assert!(
        err.to_string().contains("-dependency_info"),
        "the refusal names the flag: {err}"
    );
}

#[test]
fn the_resident_lane_writes_the_record() {
    // The record is the client-side read set (the request's own input
    // list), so `-resident` rides: the daemon falls back on this host
    // (no session) and the one-shot link writes the same record — either
    // way the file names the files the link read. The daemon never
    // touches the filesystem.
    let dir = scratch("resident");
    run_link(
        &dir,
        "app",
        &[
            "-resident",
            "-dependency_info",
            dir.join("app.deps").to_str().unwrap(),
        ],
    );
    let r = read_record(&dir, "app.deps");
    let got = rows(&r);
    assert!(
        got.contains(&(OUTPUT, dir.join("app").display().to_string())),
        "the output row rides: {got:?}"
    );
}

#[test]
fn the_relocatable_link_writes_the_record() {
    // `-r` reads its inputs exactly as the image pipeline does — the
    // record names them (ld64 serves the file for every link kind).
    let dir = scratch("reloc");
    let (main, archive) = corpus(&dir);
    let deps = dir.join("obj.deps");
    let mut args: Vec<String> = vec![
        "-o".into(),
        dir.join("out.o").display().to_string(),
        "-r".into(),
        "-dependency_info".into(),
        deps.display().to_string(),
    ];
    args.push(main.display().to_string());
    args.push(archive.display().to_string());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pgr"))
        .args(&args)
        .output()
        .expect("the pgr binary spawns");
    assert!(
        output.status.success(),
        "the relocatable link succeeds: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let r = read_record(&dir, "obj.deps");
    let got = rows(&r);
    assert!(
        got.contains(&(OUTPUT, dir.join("out.o").display().to_string())),
        "the object output rides a 0x40 row: {got:?}"
    );
    assert!(
        got.contains(&(INPUT, main.display().to_string())),
        "the input rides a 0x10 row: {got:?}"
    );
}

// ---- the parity ----------------------------------------------------------------

#[test]
fn the_recorded_link_plans_the_identical_image() {
    // The record is a sidecar: writing it never moves a byte of the
    // image (the M55/M56/M57 reporting seams' parity gate, on the
    // driver surface).
    let plain = scratch("parity_plain");
    run_link(&plain, "app", &[]);
    let recorded = scratch("parity_recorded");
    run_link(
        &recorded,
        "app",
        &[
            "-dependency_info",
            recorded.join("app.deps").to_str().unwrap(),
        ],
    );
    let a = std::fs::read(plain.join("app")).expect("the plain image");
    let b = std::fs::read(recorded.join("app")).expect("the recorded image");
    assert_eq!(a, b, "the image bytes are identical");
    assert!(recorded.join("app.deps").exists(), "the record ships");
}

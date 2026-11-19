//! M85 — the incremental ladder's dependency record: the M60 lane
//! contract (`-dependency_info` refused beside `-incremental` — "the
//! relink patches the recorded plan and re-reads no input file") flips
//! to service the M84 way: the premise was outdated, because the
//! relink's Pass 0 (`prepare_link`) re-reads every input it maps — the
//! re-parse is the digest source — and records the read set while the
//! reads happen (`PreparedLink::deps`, the same recording the one-shot's
//! Pass 0 runs). The record the ladder writes names the files the
//! ladder actually read, not the previous link's list; the output row
//! joins at the write site. The fusion lane keeps its edge: the
//! session's reads live inside the daemon and the wire carries no read
//! set, so a record-bearing relink stands the resident attempt down to
//! the in-process ladder — the next rung in order, always available.
//!
//! Gate matrix:
//! * the surface — the argv that refused since M60 parses now;
//! * the record — after an edited relink the sidecar is the ladder's
//!   own read set (the inputs the relink's Pass 0 mapped, the output
//!   row beside them), and after an untouched relink it still rides
//!   (the walk ran, the reads are real);
//! * the fusion handover — a record beside `-resident -incremental`
//!   stands the resident attempt down; the in-process ladder writes its
//!   own record (the outcome rides no transport).

use pgr_core::dep_info::{self, DependencyRecord};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// hello.o: 16 KiB of `__text` (the tier-1 edit shape), `_main` defined,
/// a BL `_greet` site (the pull and the read set ride it).
fn hello(text_flip: bool) -> Vec<u8> {
    let mut text = vec![0xD5u8, 0x03, 0x20, 0x1F]; // nop
    text.resize(16 * 1024, 0xD5);
    if text_flip {
        let base = 8 * 1024 + 16;
        for i in 0..8 {
            text[base + i * 4] = 0xAA;
        }
    }
    let mut b = ObjectBuilder::new("hello.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        text,
        vec![ObjectReloc::branch26(1).at(40)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.build().expect("the fixture object builds")
}

/// greet.o: `_greet` — the linked definition.
fn greet() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m85_deps_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// Writes the corpus in the requested edit state.
fn corpus(dir: &Path, text_flip: bool) -> (PathBuf, PathBuf) {
    let hello_path = dir.join("hello.o");
    let greet_path = dir.join("greet.o");
    std::fs::write(&hello_path, hello(text_flip)).expect("hello.o writes");
    std::fs::write(&greet_path, greet()).expect("greet.o writes");
    (hello_path, greet_path)
}

/// Parses the argv (inputs appended) into [`pgr_driver::opts::Options`].
fn parse(
    out: &Path,
    inputs: &[&Path],
    extra: &[&str],
) -> Result<pgr_driver::opts::Options, pgr_driver::opts::OptsError> {
    let mut argv: Vec<String> = vec!["-o".into(), out.display().to_string()];
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    argv.extend(inputs.iter().map(|p| p.display().to_string()));
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    pgr_driver::opts::parse(&argv)
}

/// One in-process daemon on a test-unique socket.
fn start_daemon(tag: &str) -> PathBuf {
    let sock = std::env::temp_dir().join(format!("pgr-m85-deps-{tag}.sock"));
    let _ = std::fs::remove_file(&sock);
    let owned = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(120));
    });
    for _ in 0..500 {
        if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
            return sock;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("daemon socket {} never came up", sock.display());
}

/// The record's input rows (the read set, decoded back).
fn input_paths(bytes: &[u8]) -> Vec<String> {
    let record = DependencyRecord::parse(bytes).expect("the record decodes");
    record
        .entries()
        .iter()
        .filter(|e| e.opcode == dep_info::INPUT)
        .map(|e| String::from_utf8_lossy(&e.path).into_owned())
        .collect()
}

/// The record's output rows.
fn output_paths(bytes: &[u8]) -> Vec<String> {
    let record = DependencyRecord::parse(bytes).expect("the record decodes");
    record
        .entries()
        .iter()
        .filter(|e| e.opcode == dep_info::OUTPUT)
        .map(|e| String::from_utf8_lossy(&e.path).into_owned())
        .collect()
}

// ---- the surface -----------------------------------------------------------

/// The argv that refused since M60 parses now: the ladder's Pass 0 reads
/// the inputs (the re-parse is the digest source), so the record reports
/// the read set the run actually paid.
#[test]
fn the_surface_serves_the_record_beside_the_ladder() {
    let dir = scratch("parse");
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let o = parse(
        &out,
        &[&a, &b],
        &[
            "-incremental",
            "-dependency_info",
            &dir.join("app.deps").display().to_string(),
        ],
    )
    .expect("the record rides the ladder now");
    assert!(
        o.incremental && o.dependency_info.is_some(),
        "the record rides"
    );
}

// ---- the record -------------------------------------------------------------

/// After an edited relink the sidecar is the ladder's own read set: the
/// inputs the relink's Pass 0 mapped and the output row beside them —
/// never the previous link's list, never a missing sidecar.
#[test]
fn the_ladder_writes_its_own_read_set_record() {
    let dir = scratch("record");
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let deps_path = dir.join("app.deps");
    let deps = deps_path.display().to_string();

    let capture = parse(
        &out,
        &[&a, &b],
        &["-incremental", "-dependency_info", &deps],
    )
    .expect("the capture parses");
    pgr_driver::run(&capture).expect("the capture link runs");
    let capture_record = std::fs::read(&deps_path).expect("the capture record exists");
    let capture_inputs = input_paths(&capture_record);
    assert!(
        capture_inputs.iter().any(|p| p.ends_with("hello.o")),
        "the capture record names hello.o: {capture_inputs:?}"
    );

    let (a, b) = corpus(&dir, true);
    let relink = parse(
        &out,
        &[&a, &b],
        &["-incremental", "-dependency_info", &deps],
    )
    .expect("the relink parses");
    let outcome = pgr_driver::run(&relink).expect("the record-bearing relink runs");
    let patch = outcome.patch.expect("the relink reports its patch");
    assert!(!patch.untouched, "the edit patches");

    let relink_record = std::fs::read(&deps_path).expect("the relink rewrote the record");
    let relink_inputs = input_paths(&relink_record);
    assert!(
        relink_inputs.iter().any(|p| p.ends_with("hello.o"))
            && relink_inputs.iter().any(|p| p.ends_with("greet.o")),
        "the relink's record names the inputs its Pass 0 mapped: {relink_inputs:?}"
    );
    assert_eq!(
        output_paths(&relink_record),
        vec![out.display().to_string()],
        "the output row joins at the write site"
    );
}

/// An untouched relink still writes the record: the walk ran (the reads
/// are real), the plan is the walk's product — the sidecar reports the
/// run's own read set.
#[test]
fn the_untouched_relink_writes_the_record() {
    let dir = scratch("untouched");
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let deps_path = dir.join("app.deps");
    let deps = deps_path.display().to_string();

    let capture = parse(
        &out,
        &[&a, &b],
        &["-incremental", "-dependency_info", &deps],
    )
    .expect("the capture parses");
    pgr_driver::run(&capture).expect("the capture link runs");

    let relink = parse(
        &out,
        &[&a, &b],
        &["-incremental", "-dependency_info", &deps],
    )
    .expect("the relink parses");
    let outcome = pgr_driver::run(&relink).expect("the untouched relink answers");
    let patch = outcome.patch.expect("the relink reports its patch");
    assert!(patch.untouched, "the same inputs patch nothing");

    let record = std::fs::read(&deps_path).expect("the untouched relink wrote the record");
    let inputs = input_paths(&record);
    assert!(
        inputs.iter().any(|p| p.ends_with("hello.o")),
        "the untouched relink's record names its read set: {inputs:?}"
    );
}

// ---- the fusion handover ----------------------------------------------------

/// The fusion lane keeps its edge: the session's reads live inside the
/// daemon and the wire carries no read set, so a record beside
/// `-resident -incremental` stands the resident attempt down — the
/// in-process ladder writes its own record (the outcome rides no
/// transport).
#[test]
fn the_fusion_lane_hands_the_record_to_the_ladder() {
    let dir = scratch("fusion");
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let deps_path = dir.join("app.deps");
    let deps = deps_path.display().to_string();
    let sock = start_daemon("fusion");

    let capture = parse(&out, &[&a, &b], &["-incremental"]).expect("the capture parses");
    pgr_driver::run(&capture).expect("the capture link runs");
    let (a, b) = corpus(&dir, true);
    let fusion = parse(
        &out,
        &[&a, &b],
        &["-incremental", "-resident", "-dependency_info", &deps],
    )
    .expect("the fusion argv parses");
    let outcome = pgr_driver::run(&fusion).expect("the record hands over and rides");
    assert!(
        outcome.transport.is_none(),
        "the in-process ladder served the record (the session's patch rides none)"
    );
    let record = std::fs::read(&deps_path).expect("the ladder wrote the record");
    assert!(
        input_paths(&record).iter().any(|p| p.ends_with("hello.o")),
        "the record names the ladder's read set"
    );
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
}

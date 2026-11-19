//! M89 — the fusion ladder's dependency record: the M85 lane contract (a
//! record-bearing fusion relink stands the resident attempt down — "the
//! fusion ladder's reads live inside the daemon") flips to service the
//! M88 way: the daemon reads no files at all (the §7.2 contract), so the
//! reads the M85 stand-down worried about never happen — the relink
//! cycle's real reads are the client's own Pass 0, which
//! `resident_relink` already runs to build the job
//! ([`pgr_driver`]'s `prepare_link`). The sidecar the fusion relink
//! writes is the same read-set-derived document the in-process ladder
//! writes over the same cycle (the M60 rule intact: every lane that
//! reads the files records them), the output row joins at the write
//! site, and the map lands before the record write so the record's
//! output row names a sidecar that exists (the M86 ordering, mirrored).
//!
//! Gate matrix:
//! * the served face — a record-bearing fusion relink rides the session
//!   (the outcome's transport names it), the sidecar written beside the
//!   patched image with the cycle's read set and the output rows;
//! * the parity — the fusion lane's record and the in-process ladder's
//!   record over the same cycle name the same read set (the same files,
//!   the same rows) — either lane, one Pass 0, one document;
//! * the untouched exit — a record-bearing untouched fusion relink
//!   rewrites the sidecar too (the mapping rode, the record is real);
//! * the stand-down — a dead socket hands the record to the in-process
//!   ladder (the next rung in order, always available).

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
    let dir = std::env::temp_dir().join(format!(
        "pgr_m89_fusion_deps_{}_{}",
        tag,
        std::process::id()
    ));
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
    let sock = std::env::temp_dir().join(format!("pgr-m89-fusion-deps-{tag}.sock"));
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

/// The record's input rows (the read set).
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

/// One relink cycle (capture, edit, record-bearing relink). Returns the
/// scratch dir, the outcome and the sidecar bytes.
fn record_cycle(tag: &str, extra: &[&str]) -> (PathBuf, pgr_driver::LinkOutcome, Vec<u8>) {
    let dir = scratch(tag);
    let deps_path = dir.join("app.deps");
    let deps_arg = deps_path.display().to_string();
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let capture = parse(&out, &[&a, &b], &["-incremental"]).expect("the capture parses");
    pgr_driver::run(&capture).expect("the capture link runs");
    let (a, b) = corpus(&dir, true);
    let mut extra = extra.to_vec();
    extra.push("-incremental");
    extra.push("-dependency_info");
    extra.push(&deps_arg);
    let relink = parse(&out, &[&a, &b], &extra).expect("the relink parses");
    let outcome = pgr_driver::run(&relink).expect("the record-bearing relink runs");
    let record = std::fs::read(&deps_path).expect("the relink wrote the record");
    (dir, outcome, record)
}

/// The served face: a record-bearing fusion relink rides the session —
/// the transport names it — and the sidecar written beside the patched
/// image is the cycle's own read set (the client's Pass 0, the same
/// rows the one-shot records), the output rows beside them.
#[test]
fn the_fusion_ladder_serves_the_record() {
    let sock = start_daemon("served");
    let (dir, outcome, record) = record_cycle(
        "served",
        &["-resident", "-resident_socket", &sock.display().to_string()],
    );
    assert!(
        outcome.transport.is_some(),
        "the session served the record-bearing relink"
    );
    let patch = outcome.patch.expect("the relink reports its patch");
    assert!(!patch.untouched, "the edit patches");
    let inputs = input_paths(&record);
    assert!(
        inputs.iter().any(|p| p.ends_with("hello.o"))
            && inputs.iter().any(|p| p.ends_with("greet.o")),
        "the record names the cycle's read set: {inputs:?}"
    );
    let outputs = output_paths(&record);
    assert!(
        outputs.iter().any(|p| p.ends_with("out")),
        "the record names the output: {outputs:?}"
    );
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The parity: the fusion lane's record and the in-process ladder's
/// record over the same cycle name the same read set — either lane, one
/// Pass 0, one document (the same files in the same order, the same
/// output rows).
#[test]
fn the_served_record_is_the_ladder_record() {
    let sock = start_daemon("parity");
    let (served_dir, served, served_record) = record_cycle(
        "parity-served",
        &["-resident", "-resident_socket", &sock.display().to_string()],
    );
    assert!(served.transport.is_some(), "the session served the run");
    let (ladder_dir, ladder, ladder_record) = record_cycle("parity-ladder", &[]);
    assert!(ladder.transport.is_none(), "the ladder served its own");
    let served_inputs = input_paths(&served_record);
    let ladder_inputs = input_paths(&ladder_record);
    let names = |paths: &[String]| {
        let mut v: Vec<String> = paths
            .iter()
            .map(|p| {
                Path::new(p)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        names(&served_inputs),
        names(&ladder_inputs),
        "either lane, one Pass 0, one read set"
    );
    assert_eq!(
        output_paths(&served_record)
            .iter()
            .map(|p| Path::new(p)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned())
            .collect::<Vec<_>>(),
        output_paths(&ladder_record)
            .iter()
            .map(|p| Path::new(p)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned())
            .collect::<Vec<_>>(),
        "the output rows name the same files"
    );
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&served_dir);
    let _ = std::fs::remove_dir_all(&ladder_dir);
}

/// The untouched exit: a record-bearing untouched fusion relink rewrites
/// the sidecar too — the mapping rode (the walk ran), the record is the
/// cycle's real one, not the previous link's.
#[test]
fn the_untouched_relink_writes_the_record() {
    let sock = start_daemon("untouched");
    let dir = scratch("untouched");
    let deps_path = dir.join("app.deps");
    let deps_arg = deps_path.display().to_string();
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let capture = parse(&out, &[&a, &b], &["-incremental"]).expect("the capture parses");
    pgr_driver::run(&capture).expect("the capture link runs");
    let relink = parse(
        &out,
        &[&a, &b],
        &[
            "-incremental",
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
            "-dependency_info",
            &deps_arg,
        ],
    )
    .expect("the relink parses");
    let outcome = pgr_driver::run(&relink).expect("the untouched relink writes its record");
    assert!(
        outcome.transport.is_some(),
        "the session served the untouched relink"
    );
    let patch = outcome.patch.expect("the relink reports its patch");
    assert!(patch.untouched, "the relink patched nothing");
    let record = std::fs::read(&deps_path).expect("the untouched relink wrote the record");
    assert!(
        input_paths(&record).iter().any(|p| p.ends_with("hello.o")),
        "the record names the read set"
    );
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The stand-down: a dead socket hands the record-bearing relink to the
/// in-process ladder — the next rung in order, always available (the
/// ladder's own Pass 0 records the files it mapped; the outcome rides no
/// transport).
#[test]
fn a_dead_socket_hands_the_record_to_the_ladder() {
    let dead = scratch("dead-sock").join("dead.sock");
    let (dir, outcome, record) = record_cycle(
        "dead",
        &["-resident", "-resident_socket", &dead.display().to_string()],
    );
    assert!(
        outcome.transport.is_none(),
        "the in-process ladder served the run"
    );
    assert!(
        input_paths(&record).iter().any(|p| p.ends_with("hello.o")),
        "the ladder's record names its own read set"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

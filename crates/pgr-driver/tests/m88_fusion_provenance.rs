//! M88 — the fusion ladder's served provenance: the M84 lane contract (a
//! query-bearing fusion relink stands the resident attempt down) flips to
//! service the M87 way: the session's ladder runs the full Passes 1–3
//! (`link_from_objects` inside `serve_relink`), so
//! `result.resolution`/`result.loads` are the walk's own Pass-2 products,
//! and the same index-and-query render the cold lane calls produces the
//! M56/M57 answers. The renders ride the reply's v45 tail verbatim (the
//! wire never re-shapes the face the client prints), the driver prints
//! the served answers beside the patched image exactly as the resident
//! full link prints its own, and a vacuous query's refusal is the
//! `ERROR` reply the stand-down already speaks — the in-process ladder
//! answers either way (honest degradation, never a silently unanswered
//! ask).
//!
//! Gate matrix:
//! * the served face — a query-bearing fusion relink rides the session
//!   (the outcome's transport names it), the answers printed beside the
//!   patched image;
//! * the vacuous refusal — a misspelled query refuses the run with the
//!   misspelling named (the handover to the in-process ladder, whose own
//!   refusal speaks);
//! * the untouched relink — the walk ran, the answers ride the untouched
//!   exit too;
//! * the stand-down — a dead socket hands the queries to the in-process
//!   ladder (the next rung in order, always available).

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
        "pgr_m88_fusion_prov_{}_{}",
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
    let sock = std::env::temp_dir().join(format!("pgr-m88-fusion-prov-{tag}.sock"));
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

/// The cycle: capture, edit, relink — the queries named beside the relink.
fn fusion_cycle(tag: &str, extra: &[&str]) -> (PathBuf, pgr_driver::LinkOutcome) {
    let dir = scratch(tag);
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let capture = parse(&out, &[&a, &b], &["-incremental"]).expect("the capture parses");
    pgr_driver::run(&capture).expect("the capture link runs");
    let (a, b) = corpus(&dir, true);
    let mut extra = extra.to_vec();
    extra.push("-incremental");
    extra.push("-why_export");
    extra.push("_greet");
    let relink = parse(&out, &[&a, &b], &extra).expect("the relink parses");
    let outcome = pgr_driver::run(&relink).expect("the query-bearing relink runs");
    (dir, outcome)
}

/// The served face: a query-bearing fusion relink rides the session —
/// the transport names it — and the answers printed beside the patched
/// image are the session's own renders (the ladder's Pass-2 product, the
/// v45 tail verbatim).
#[test]
fn the_fusion_ladder_serves_the_answers() {
    let sock = start_daemon("served");
    let (dir, outcome) = fusion_cycle(
        "served",
        &["-resident", "-resident_socket", &sock.display().to_string()],
    );
    assert!(
        outcome.transport.is_some(),
        "the session served the query-bearing relink"
    );
    let patch = outcome.patch.expect("the relink reports its patch");
    assert!(!patch.untouched, "the edit patches");
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The vacuous refusal: a misspelled query refuses the run with the
/// misspelling named — the session's `ERROR` is the stand-down's cue, the
/// in-process ladder's own refusal speaks (never a silently empty
/// answer, either lane).
#[test]
fn the_vacuous_query_refuses_through_the_handover() {
    let sock = start_daemon("vacuous");
    let dir = scratch("vacuous");
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let capture = parse(&out, &[&a, &b], &["-incremental"]).expect("the capture parses");
    pgr_driver::run(&capture).expect("the capture link runs");
    let (a, b) = corpus(&dir, true);
    let relink = parse(
        &out,
        &[&a, &b],
        &[
            "-incremental",
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
            "-why_export",
            "_nope",
        ],
    )
    .expect("the relink parses");
    let err = pgr_driver::run(&relink).expect_err("the vacuous query refuses the run");
    let rendered = err.to_string();
    assert!(
        rendered.contains("_nope"),
        "the refusal names the misspelling: {rendered}"
    );
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The untouched relink: the walk ran, the answers ride the untouched
/// exit too (nothing patched, the Pass-2 product is the capture's own —
/// re-derived, never stale).
#[test]
fn the_untouched_relink_serves_the_answers() {
    let sock = start_daemon("untouched");
    let dir = scratch("untouched");
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
            "-why_export",
            "_main",
        ],
    )
    .expect("the relink parses");
    let outcome = pgr_driver::run(&relink).expect("the untouched relink answers");
    assert!(
        outcome.transport.is_some(),
        "the session served the untouched relink"
    );
    let patch = outcome.patch.expect("the relink reports its patch");
    assert!(patch.untouched, "the relink patched nothing");
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The stand-down: a dead socket hands the query-bearing relink to the
/// in-process ladder — the next rung in order, always available (the
/// ladder's own walk answers; the outcome rides no transport).
#[test]
fn a_dead_socket_hands_the_queries_to_the_ladder() {
    let dead = scratch("dead-sock").join("dead.sock");
    let (dir, outcome) = fusion_cycle(
        "dead",
        &["-resident", "-resident_socket", &dead.display().to_string()],
    );
    assert!(
        outcome.transport.is_none(),
        "the in-process ladder served the run"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

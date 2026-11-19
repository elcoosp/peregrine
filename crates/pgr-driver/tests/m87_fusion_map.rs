//! M87 — the fusion ladder's served map: the M86 lane contract (a
//! map-bearing fusion relink stands the resident attempt down) flips to
//! service the M80/M86 way: the session's ladder runs the full Passes
//! 1–3 (`link_from_objects` inside `serve_relink`), so
//! `result.layout` is the walk's own Pass-3 product, and
//! [`pgr_core::map::build_link_map`] — the same pure function the cold
//! lane's `-map` calls — renders it. The document rides the reply's v46
//! tail verbatim (the wire never re-shapes the face the client writes),
//! the client writes the served bytes to the `-map` path exactly as the
//! in-process ladder writes its own, and an old server's refusal is the
//! `ERROR` reply the stand-down already speaks — the in-process ladder
//! answers either way (honest degradation, never a silently unanswered
//! ask).
//!
//! Gate matrix:
//! * the served face — a map-bearing fusion relink rides the session
//!   (the outcome's transport names it), the document written beside the
//!   patched image;
//! * the parity — the served document is byte-identical to the
//!   in-process ladder's render over the same cycle (either lane, one
//!   walk, one document);
//! * the stand-down — a dead socket hands the map to the in-process
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
    let dir =
        std::env::temp_dir().join(format!("pgr_m87_fusion_map_{}_{}", tag, std::process::id()));
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
    let sock = std::env::temp_dir().join(format!("pgr-m87-fusion-map-{tag}.sock"));
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

/// The cycle: capture, edit, relink — the map path named beside each run.
fn fusion_cycle(tag: &str, extra: &[&str], map_path: &Path) -> (pgr_driver::LinkOutcome, String) {
    let dir = scratch(tag);
    let map_arg = map_path.display().to_string();
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let capture = parse(&out, &[&a, &b], &["-incremental"]).expect("the capture parses");
    pgr_driver::run(&capture).expect("the capture link runs");
    let (a, b) = corpus(&dir, true);
    let mut extra = extra.to_vec();
    extra.push("-incremental");
    extra.push("-map");
    extra.push(&map_arg);
    let relink = parse(&out, &[&a, &b], &extra).expect("the relink parses");
    let outcome = pgr_driver::run(&relink).expect("the map-bearing relink runs");
    let document =
        std::fs::read_to_string(map_path).expect("the relink wrote the map beside the image");
    let _ = std::fs::remove_dir_all(&dir);
    (outcome, document)
}

/// The served face: a map-bearing fusion relink rides the session — the
/// transport names it — and the document written beside the patched
/// image is the session's own render (the ladder's Pass-3 product, the
/// v46 tail verbatim).
#[test]
fn the_fusion_ladder_serves_the_map() {
    let sock = start_daemon("served");
    let map_path = scratch("served-map").join("hello.map");
    let (outcome, document) = fusion_cycle(
        "served",
        &["-resident", "-resident_socket", &sock.display().to_string()],
        &map_path,
    );
    assert!(
        outcome.transport.is_some(),
        "the session served the map-bearing relink"
    );
    let patch = outcome.patch.expect("the relink reports its patch");
    assert!(!patch.untouched, "the edit patches");
    assert!(
        document.contains("__TEXT") && document.contains("__LINKEDIT"),
        "the served map names the placed segments"
    );
    assert!(
        document.contains("_main"),
        "the served map carries the symbol rows"
    );
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(map_path.parent().expect("the map dir"));
}

/// The parity: the served document is byte-identical to the in-process
/// ladder's render over the same cycle — either lane, one walk, one
/// document.
#[test]
fn the_served_map_is_the_ladder_document() {
    let sock = start_daemon("parity");
    let served_map = scratch("parity-served").join("hello.map");
    let ladder_map = scratch("parity-ladder").join("hello.map");
    let (served, served_document) = fusion_cycle(
        "parity-served",
        &["-resident", "-resident_socket", &sock.display().to_string()],
        &served_map,
    );
    assert!(served.transport.is_some(), "the session served the run");
    let (_ladder, ladder_document) = fusion_cycle("parity-ladder", &[], &ladder_map);
    assert_eq!(
        served_document, ladder_document,
        "either lane, one walk, one document"
    );
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(served_map.parent().expect("the served dir"));
    let _ = std::fs::remove_dir_all(ladder_map.parent().expect("the ladder dir"));
}

/// The stand-down: a dead socket hands the map-bearing relink to the
/// in-process ladder — the next rung in order, always available (the
/// document is the ladder's own render; the outcome rides no transport).
#[test]
fn a_dead_socket_hands_the_map_to_the_ladder() {
    let dead = scratch("dead-sock").join("dead.sock");
    let map_path = scratch("dead-map").join("hello.map");
    let (outcome, document) = fusion_cycle(
        "dead",
        &["-resident", "-resident_socket", &dead.display().to_string()],
        &map_path,
    );
    assert!(
        outcome.transport.is_none(),
        "the in-process ladder served the run"
    );
    assert!(
        document.contains("_main"),
        "the ladder's map renders beside the image"
    );
    let _ = std::fs::remove_dir_all(dead.parent().expect("the sock dir"));
    let _ = std::fs::remove_dir_all(map_path.parent().expect("the map dir"));
}

//! M86 — the incremental ladder's link map: the M11/M80 lane contract
//! (`-map` refused beside `-incremental` — "the map reports the full
//! emit's layout") flips to service the M84/M85 way: the premise was
//! outdated, because the relink's walk runs the full Passes 1–3
//! (`pgr_core::link_cached` inside `incremental_relink`), so
//! `result.layout` is the walk's Pass-3 product, in the relink's own
//! memory, and [`pgr_core::map::build_link_map`] renders the same face
//! the one-shot writes. The map the ladder writes is the relink's own
//! placed image — never the previous link's document — at both success
//! exits (the patched exit and the untouched one; the walk ran either
//! way). The fusion lane keeps its edge for now: the session's patch
//! serves bytes, not the placed layout, so a map-bearing relink stands
//! the resident attempt down to the in-process ladder (the next rung in
//! order, always available).
//!
//! Gate matrix:
//! * the surface — the argv that refused since M11 parses now;
//! * the map — after an edited relink the sidecar is the ladder's own
//!   placed image (the segments the relink laid out, the symbol rows
//!   beside them), and after an untouched relink it still rides (the
//!   walk ran, the layout is the walk's product) and equals the
//!   capture's document (nothing moved);
//! * the fusion handover — a map beside `-resident -incremental` stands
//!   the resident attempt down; the in-process ladder renders its own
//!   map (the outcome rides no transport).

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
    let dir = std::env::temp_dir().join(format!("pgr_m86_map_{}_{}", tag, std::process::id()));
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
    let sock = std::env::temp_dir().join(format!("pgr-m86-map-{tag}.sock"));
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

// ---- the surface -----------------------------------------------------------

/// The argv that refused since M11 parses now: the relink's walk runs
/// the full Passes 1–3, so the placed image the map reports exists on
/// the ladder too — the knob is never a silently dropped one.
#[test]
fn the_surface_serves_the_map_beside_the_ladder() {
    let dir = scratch("parse");
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let o = parse(
        &out,
        &[&a, &b],
        &[
            "-incremental",
            "-map",
            &dir.join("hello.map").display().to_string(),
        ],
    )
    .expect("the map rides the ladder now");
    assert!(o.incremental && o.map_path.is_some(), "the map rides");
}

// ---- the map ----------------------------------------------------------------

/// After an edited relink the sidecar is the ladder's own placed image:
/// the segments the relink's Pass 3 laid out and the symbol rows beside
/// them — the same face the one-shot writes, rendered from the walk the
/// relink just patched from.
#[test]
fn the_ladder_writes_its_own_map() {
    let dir = scratch("map");
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let map_path = dir.join("hello.map");
    let map_arg = map_path.display().to_string();

    let capture =
        parse(&out, &[&a, &b], &["-incremental", "-map", &map_arg]).expect("the capture parses");
    pgr_driver::run(&capture).expect("the capture link runs");
    let capture_map = std::fs::read_to_string(&map_path).expect("the capture map exists");
    assert!(
        capture_map.contains("__TEXT") && capture_map.contains("__LINKEDIT"),
        "the capture map names the placed segments"
    );

    let (a, b) = corpus(&dir, true);
    let relink =
        parse(&out, &[&a, &b], &["-incremental", "-map", &map_arg]).expect("the relink parses");
    let outcome = pgr_driver::run(&relink).expect("the map-bearing relink runs");
    let patch = outcome.patch.expect("the relink reports its patch");
    assert!(!patch.untouched, "the edit patches");

    let relink_map = std::fs::read_to_string(&map_path).expect("the relink rewrote the map");
    assert!(
        relink_map.contains("__TEXT") && relink_map.contains("__LINKEDIT"),
        "the relink's map names its own placed segments"
    );
    assert!(
        relink_map.contains("_main"),
        "the relink's map carries the symbol rows"
    );
}

/// An untouched relink still writes the map: the walk ran (the plan is
/// the walk's product), and the document it renders is the capture's own
/// — nothing moved, so the placed image reports the same segments,
/// sections and symbols.
#[test]
fn the_untouched_relink_writes_the_capture_map() {
    let dir = scratch("untouched");
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let map_path = dir.join("hello.map");
    let map_arg = map_path.display().to_string();

    let capture =
        parse(&out, &[&a, &b], &["-incremental", "-map", &map_arg]).expect("the capture parses");
    pgr_driver::run(&capture).expect("the capture link runs");
    let capture_map = std::fs::read_to_string(&map_path).expect("the capture map exists");

    let relink =
        parse(&out, &[&a, &b], &["-incremental", "-map", &map_arg]).expect("the relink parses");
    let outcome = pgr_driver::run(&relink).expect("the untouched relink answers");
    let patch = outcome.patch.expect("the relink reports its patch");
    assert!(patch.untouched, "the same inputs patch nothing");

    let relink_map =
        std::fs::read_to_string(&map_path).expect("the untouched relink wrote the map");
    assert_eq!(
        relink_map, capture_map,
        "the untouched relink's map is the capture's document — nothing moved"
    );
}

// ---- the fusion handover ----------------------------------------------------

/// The fusion lane keeps its edge: the session's patch serves bytes, not
/// the placed layout, so a map beside `-resident -incremental` stands
/// the resident attempt down — the in-process ladder renders its own map
/// (the outcome rides no transport).
#[test]
fn the_fusion_lane_hands_the_map_to_the_ladder() {
    let dir = scratch("fusion");
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let map_path = dir.join("hello.map");
    let map_arg = map_path.display().to_string();
    let sock = start_daemon("fusion");

    let capture = parse(&out, &[&a, &b], &["-incremental"]).expect("the capture parses");
    pgr_driver::run(&capture).expect("the capture link runs");
    let (a, b) = corpus(&dir, true);
    let fusion = parse(
        &out,
        &[&a, &b],
        &["-incremental", "-resident", "-map", &map_arg],
    )
    .expect("the fusion argv parses");
    let outcome = pgr_driver::run(&fusion).expect("the map hands over and rides");
    assert!(
        outcome.transport.is_none(),
        "the in-process ladder served the map (the session's patch rides none)"
    );
    let relink_map = std::fs::read_to_string(&map_path).expect("the ladder wrote the map");
    assert!(
        relink_map.contains("_main"),
        "the map renders the ladder's own walk"
    );
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
}

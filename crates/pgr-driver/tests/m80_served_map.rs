//! M80 — the resident lane's served map: the M11 lane contract (`-map`
//! reads the one-shot link's layout, so the resident lane refused it —
//! "never returns the layout the map reports") flips to service the
//! M76/M79 way: the session's warm pipeline *is* a full walk, the layout
//! and interner are in its memory, and wire v46 carries the rendered
//! document verbatim (the M62 convention — the wire never re-shapes).
//! The client writes the served document to the `-map` path exactly as
//! the cold lane writes its own render; the fallback story stays honest
//! (a resident attempt that stands down hands over to the one-shot link,
//! whose own render writes the file); the fusion ladder keeps refusing
//! at the wire (the replay patches the recorded plan in place — the map
//! reports the full emit's layout, the `protocol.rs` gates pin that
//! shape), and `-map × -incremental` refuses at the surface unchanged.
//!
//! Gate matrix:
//! * the served map — a resident link asking for the map writes the
//!   document the cold lane writes for the same corpus (byte parity:
//!   one walk, one render, either lane);
//! * the fallback — a resident attempt that stands down hands over to
//!   the one-shot link, whose own render writes the same document;
//! * the surface — `-map` beside `-incremental` still refuses (the
//!   patch tiers produce no full-emit layout to report);
//! * the served map rides only when asked — a plain resident link
//!   writes no map file.

use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;

/// main.o: `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret (greet.o is
/// the second direct input and defines `_greet`).
fn main_object() -> Vec<u8> {
    let words: Vec<u32> = vec![
        0x9000_0000, // adrp x0, _msg@page
        0x9100_0000, // add x0, x0, #_msg@pageoff
        0x9400_0000, // bl _greet
        0xD65F_03C0, // ret
    ];
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut b = ObjectBuilder::new("main.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        text,
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12(1).at(4),
            ObjectReloc::branch26(2).at(8),
        ],
    ));
    let msg = b.add_section(ObjectSection::cstring("hello, peregrine\n"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_msg".into(),
        section_index: msg,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.build().expect("the fixture object builds")
}

/// greet.o: `_greet` body (a bare ret).
fn greet_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Writes the corpus: main.o beside greet.o.
fn corpus(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("pgr_m80_{}_{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).expect("the fixture object writes");
    let greet = dir.join("greet.o");
    std::fs::write(&greet, greet_object()).expect("the fixture object writes");
    (dir, main, greet)
}

/// Unique socket path for one test.
fn socket_for(test: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pgr-m80-{}-{test}.sock", std::process::id()))
}

/// Starts an in-process daemon on `sock` and waits until it accepts.
fn start_daemon(sock: &Path) {
    let owned = sock.to_path_buf();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, std::time::Duration::from_secs(120));
    });
    for _ in 0..500 {
        if UnixStream::connect(sock).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("daemon socket {} never came up", sock.display());
}

/// Runs the built `pgr` binary with `extra` args (the corpus rides) and
/// returns (exit ok, stdout, stderr).
fn run_pgr(out: &Path, main: &Path, greet: &Path, extra: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_pgr"))
        .arg("-o")
        .arg(out)
        .args(extra)
        .arg(main)
        .arg(greet)
        .output()
        .expect("the pgr child runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn the_served_map_matches_the_cold_render() {
    let (dir, main, greet) = corpus("served");
    let sock = socket_for("served");
    start_daemon(&sock);
    // The cold lane's own render first: the reference document.
    let (ok, _stdout, stderr) = run_pgr(
        &dir.join("cold-out"),
        &main,
        &greet,
        &["-map", &dir.join("cold.map").display().to_string()],
    );
    assert!(ok, "the cold link runs: {stderr}");
    let cold = std::fs::read_to_string(dir.join("cold.map")).expect("the cold map writes");
    assert!(
        cold.contains("__TEXT"),
        "the map reports the segments: {cold}"
    );
    // The resident link asking for the map: the session's own walk
    // renders the placed image's report, the reply's IMAGE tail carries
    // it verbatim, the client writes the file.
    let (ok, _stdout, stderr) = run_pgr(
        &dir.join("warm-out"),
        &main,
        &greet,
        &[
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
            "-map",
            &dir.join("warm.map").display().to_string(),
        ],
    );
    assert!(ok, "the resident link runs: {stderr}");
    let warm = std::fs::read_to_string(dir.join("warm.map")).expect("the served map writes");
    assert_eq!(
        cold, warm,
        "one walk, one render — the served document is the cold lane's"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn the_fallback_writes_the_one_shot_map() {
    let (dir, main, greet) = corpus("fallback");
    let (ok, _stdout, stderr) = run_pgr(
        &dir.join("cold-out"),
        &main,
        &greet,
        &["-map", &dir.join("cold.map").display().to_string()],
    );
    assert!(ok, "the cold link runs: {stderr}");
    let cold = std::fs::read_to_string(dir.join("cold.map")).expect("the cold map writes");
    // A socket nothing answers: the resident attempt stands down and the
    // one-shot link (whose own render writes) produces the outcome.
    let dead = socket_for("fallback");
    let _ = std::fs::remove_file(&dead);
    let (ok, _stdout, stderr) = run_pgr(
        &dir.join("warm-out"),
        &main,
        &greet,
        &[
            "-resident",
            "-resident_socket",
            &dead.display().to_string(),
            "-map",
            &dir.join("warm.map").display().to_string(),
        ],
    );
    assert!(ok, "the fallback link runs: {stderr}");
    let warm = std::fs::read_to_string(dir.join("warm.map")).expect("the fallback map writes");
    assert_eq!(
        cold, warm,
        "either lane, one render — the fallback writes the one-shot's own document"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_map_beside_incremental_still_refuses() {
    let (dir, main, greet) = corpus("surface");
    let argv: Vec<String> = vec![
        "-o".into(),
        dir.join("out").display().to_string(),
        "-map".into(),
        dir.join("out.map").display().to_string(),
        "-incremental".into(),
    ];
    let argv: Vec<std::ffi::OsString> = argv
        .into_iter()
        .map(Into::into)
        .chain([
            std::ffi::OsString::from(main),
            std::ffi::OsString::from(greet),
        ])
        .collect();
    let err = pgr_driver::opts::parse(&argv).unwrap_err();
    assert!(
        err.to_string().contains("patch tiers"),
        "the surface refusal names the lane: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unasked_resident_link_writes_no_map() {
    let (dir, main, greet) = corpus("quiet");
    let sock = socket_for("quiet");
    start_daemon(&sock);
    let (ok, _stdout, stderr) = run_pgr(
        &dir.join("out"),
        &main,
        &greet,
        &["-resident", "-resident_socket", &sock.display().to_string()],
    );
    assert!(ok, "the resident link runs: {stderr}");
    assert!(
        !dir.join("out.map").exists(),
        "an unasked map never crosses, and no file is written"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

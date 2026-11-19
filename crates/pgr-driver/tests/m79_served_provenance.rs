//! M79 — the resident lane's served provenance: the M56/M57 lane
//! contract (`-why_export`/`-why_load` read the one-shot link's Pass-2
//! product, so the resident lane refused them — the product never
//! crossed the wire) flips to service the M76 way: the session's own
//! warm pipeline *is* a full walk, the product is in its memory, and
//! wire v45 carries the rendered answers (the M62 convention — the wire
//! never re-shapes). The client prints the served answers beside the
//! resident link exactly as the cold lane prints its own; the fusion
//! ladder hands a query-bearing relink to the in-process ladder since
//! M84 (the patch serves bytes, not answers — the in-process walk
//! serves them); a vacuous query is the `TAG_ERROR` the one-shot
//! fallback reproduces — the same refusal either lane.
//!
//! Gate matrix:
//! * the served answers — a resident link asking both questions prints
//!   the export answer and the load report the cold lane's shape
//!   (the session's own renders, verbatim);
//! * the fallback — a resident attempt that stands down hands over to
//!   the one-shot link, whose own queries print the same rows;
//! * the vacuous query — the misspelling refuses through the fallback
//!   (the daemon's error is the fallback's cue, the cold refusal is the
//!   answer);
//! * the surface — a query-bearing fusion relink (`-incremental`)
//!   hands over to the in-process ladder since M84, whose own walk
//!   serves the answer (the run answers either way).

use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;

/// main.o: `_main` BL `_greet` (greet.o, in the archive, defines it).
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

/// greet.o: `_greet` body (the archive member the lazy pull admits).
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

/// Writes the corpus: main.o beside libgreet.a holding greet.o.
fn corpus(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("pgr_m79_{}_{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).expect("the fixture object writes");
    let archive = dir.join("libgreet.a");
    let mut a = ArchiveBuilder::new("libgreet.a");
    a.add_member("greet.o", greet_object());
    std::fs::write(&archive, a.build()).expect("the archive writes");
    (dir, main, archive)
}

/// Unique socket path for one test.
fn socket_for(test: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pgr-m79-{}-{test}.sock", std::process::id()))
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
fn run_pgr(dir: &Path, main: &Path, archive: &Path, extra: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_pgr"))
        .arg("-o")
        .arg(dir.join("out"))
        .args(extra)
        .arg(main)
        .arg(archive)
        .output()
        .expect("the pgr child runs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_served_answers_print_beside_the_resident_link() {
    let (dir, main, archive) = corpus("served");
    let sock = socket_for("served");
    start_daemon(&sock);
    let (ok, stdout, stderr) = run_pgr(
        &dir,
        &main,
        &archive,
        &[
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
            "-why_export",
            "_greet",
            "-why_load",
        ],
    );
    assert!(ok, "the resident link runs: {stderr}");
    assert!(
        stdout.contains("_greet"),
        "the served export answer names the query: {stdout}"
    );
    assert!(
        stdout.contains("greet.o"),
        "the served answer names the definition's file: {stdout}"
    );
    assert!(
        stdout.contains("libgreet.a") && stdout.contains("pulled for _greet"),
        "the served load report names the pulled member: {stdout}"
    );
    assert!(
        Path::new(&dir.join("out")).is_file(),
        "the link wrote the image"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn the_fallback_prints_the_one_shot_answers() {
    let (dir, main, archive) = corpus("fallback");
    // A socket nothing answers: the resident attempt stands down and the
    // one-shot link (whose own queries print) produces the outcome.
    let dead = socket_for("fallback");
    let _ = std::fs::remove_file(&dead);
    let (ok, stdout, stderr) = run_pgr(
        &dir,
        &main,
        &archive,
        &[
            "-resident",
            "-resident_socket",
            &dead.display().to_string(),
            "-why_export",
            "_greet",
            "-why_load",
        ],
    );
    assert!(ok, "the fallback link runs: {stderr}");
    assert!(
        stdout.contains("_greet") && stdout.contains("pulled for _greet"),
        "the cold answers print beside the fallback: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_vacuous_query_refuses_through_the_fallback() {
    let (dir, main, archive) = corpus("vacuous");
    let sock = socket_for("vacuous");
    start_daemon(&sock);
    // The daemon's TAG_ERROR is the fallback's cue; the one-shot lane's
    // own query refuses with the misspelling named — the same refusal
    // either lane, never a silently empty answer.
    let (ok, _stdout, stderr) = run_pgr(
        &dir,
        &main,
        &archive,
        &[
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
            "-why_export",
            "_nope",
        ],
    );
    assert!(!ok, "the vacuous query refuses the run");
    assert!(
        stderr.contains("_nope"),
        "the refusal names the misspelling: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn the_fusion_relink_prints_the_served_answers() {
    let (dir, main, archive) = corpus("fusion");
    let sock = socket_for("fusion");
    start_daemon(&sock);
    let sock_arg = sock.display().to_string();
    // The capture: a full link through the session (the record rides the
    // reply; the queries ride nothing yet).
    let (ok, _stdout, stderr) = run_pgr(
        &dir,
        &main,
        &archive,
        &["-resident", "-resident_socket", &sock_arg, "-incremental"],
    );
    assert!(ok, "the capture link runs: {stderr}");
    // M88: a query-bearing fusion relink rides the session's replay —
    // the ladder's own Pass-2 product renders the answers the v45 tail
    // carries verbatim, and the client prints the served renders beside
    // the patched image (the same print face the full-link lane rides).
    // (The pre-M88 stand-down handed the queries to the in-process
    // ladder, which answered identically — the transport named the lane,
    // `m88_fusion_provenance.rs` pins it.)
    let (ok, stdout, stderr) = run_pgr(
        &dir,
        &main,
        &archive,
        &[
            "-resident",
            "-resident_socket",
            &sock_arg,
            "-incremental",
            "-why_export",
            "_greet",
            "-why_load",
        ],
    );
    assert!(ok, "the fusion relink answers: {stderr}");
    assert!(
        stdout.contains("_greet"),
        "the served export answer names the query: {stdout}"
    );
    assert!(
        stdout.contains("libgreet.a") && stdout.contains("pulled for _greet"),
        "the served load report names the pulled member: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

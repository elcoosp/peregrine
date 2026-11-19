//! M93 — the resident lane's served liveness: the M92 `-why_live` lane
//! contract (the one-shot and the in-process ladder answer; the resident
//! lanes refuse — the wire's provenance tail v45 carries only the
//! `-why_export`/`-why_load` asks) flips to service the M79 way: the
//! session's own walk runs the full Passes 1–3, so the mark phase's
//! first-marker record (`LinkResult::liveness`) is in its memory, and
//! wire v48 carries the liveness ask and the rendered chains (the M62
//! convention — the wire never re-shapes the face the client prints).
//! The client prints the served chains beside the resident link exactly
//! as the cold lane prints its own; a vacuous query is the `TAG_ERROR`
//! the one-shot fallback reproduces — the same refusal either lane.
//!
//! Gate matrix:
//! * the served chain — a resident `-dead_strip` link asking the query
//!   prints the chain the cold lane's shape (the session's own render,
//!   verbatim: the keeper rows and the root decision);
//! * the dead answer — a definition nothing reaches answers the verdict
//!   it states (`dropped by the strip`), on the resident lane as cold;
//! * the vacuous query — the misspelling refuses through the fallback
//!   (the daemon's error is the fallback's cue, the cold refusal is the
//!   answer);
//! * the premise — a resident link without `-dead_strip` refuses
//!   through the fallback (no strip, no chain to walk);
//! * the fusion relink — a query-bearing relink rides the session's
//!   replay (the ladder's own walk re-runs the full Passes 1–3, the
//!   record rides `LinkResult::liveness`, the v48 tail carries the
//!   renders verbatim).

use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;

/// main.o: `_main` BL `_greet` (greet.o defines it) — the entry atom
/// carries the edge the strip follows, so `-dead_strip` keeps both and
/// the chain is one hop.
fn main_object() -> Vec<u8> {
    let mut main = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    main.add_section(ObjectSection::text(
        "__text",
        [0x9400_0000u32.to_le_bytes(), 0xD65F_03C0u32.to_le_bytes()].concat(),
        vec![ObjectReloc::branch26(1).at(0)],
    ));
    main.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    let _ = main.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    main.build().expect("main.o builds")
}

/// greet.o: `_greet` as a bare ret (the definition the chain walks).
fn greet_object() -> Vec<u8> {
    let mut lib = ObjectBuilder::new("greet.o").set_subsections_via_symbols(true);
    let ltext = lib.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    lib.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: ltext,
        value: 0,
        weak: false,
    });
    lib.build().expect("greet.o builds")
}

/// orphan.o: `_orphan` defined, referenced by nothing — the strip drops
/// it, and the honest answer is the verdict that says so.
fn orphan_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("orphan.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_orphan".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("orphan.o builds")
}

/// Writes the corpus: main.o, greet.o, orphan.o.
fn corpus(name: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("pgr_m93_{}_{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).expect("the fixture object writes");
    let greet = dir.join("greet.o");
    std::fs::write(&greet, greet_object()).expect("the fixture object writes");
    let orphan = dir.join("orphan.o");
    std::fs::write(&orphan, orphan_object()).expect("the fixture object writes");
    (dir, main, greet, orphan)
}

/// Unique socket path for one test.
fn socket_for(test: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pgr-m93-{}-{test}.sock", std::process::id()))
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
fn run_pgr(
    dir: &Path,
    main: &Path,
    greet: &Path,
    orphan: &Path,
    extra: &[&str],
) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_pgr"))
        .arg("-o")
        .arg(dir.join("out"))
        .args(extra)
        .arg(main)
        .arg(greet)
        .arg(orphan)
        .output()
        .expect("the pgr child runs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_served_chain_prints_beside_the_resident_link() {
    let (dir, main, greet, orphan) = corpus("served");
    let sock = socket_for("served");
    start_daemon(&sock);
    let (ok, stdout, stderr) = run_pgr(
        &dir,
        &main,
        &greet,
        &orphan,
        &[
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
            "-dead_strip",
            "-why_live",
            "_greet",
        ],
    );
    assert!(ok, "the resident link runs: {stderr}");
    assert!(
        stdout.contains("_greet: kept by the strip"),
        "the served chain answers the query: {stdout}"
    );
    assert!(
        stdout.contains("rooted at the entry point (-e)"),
        "the served chain names the root decision: {stdout}"
    );
    assert!(
        stdout.contains("main.o"),
        "the served chain names the keeper's file: {stdout}"
    );
    assert!(
        Path::new(&dir.join("out")).is_file(),
        "the link wrote the image"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn the_dead_answer_rides_the_resident_link() {
    let (dir, main, greet, orphan) = corpus("dead");
    let sock = socket_for("dead");
    start_daemon(&sock);
    // `_orphan` is referenced by nothing: the honest answer is the
    // verdict that says so — the resident lane answers it exactly as
    // the cold lane does (the verdict is the answer, not an error).
    let (ok, stdout, stderr) = run_pgr(
        &dir,
        &main,
        &greet,
        &orphan,
        &[
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
            "-dead_strip",
            "-why_live",
            "_orphan",
        ],
    );
    assert!(ok, "the resident link runs: {stderr}");
    assert!(
        stdout.contains("_orphan: dropped by the strip"),
        "the dead answer states the verdict: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn the_vacuous_query_refuses_through_the_fallback() {
    let (dir, main, greet, orphan) = corpus("vacuous");
    let sock = socket_for("vacuous");
    start_daemon(&sock);
    // The daemon's TAG_ERROR is the fallback's cue; the one-shot lane's
    // own query refuses with the misspelling named — the same refusal
    // either lane, never a silently empty answer.
    let (ok, _stdout, stderr) = run_pgr(
        &dir,
        &main,
        &greet,
        &orphan,
        &[
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
            "-dead_strip",
            "-why_live",
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
fn the_fallback_prints_the_cold_answers() {
    let (dir, main, greet, orphan) = corpus("fallback");
    // A socket nothing answers: the resident attempt stands down and the
    // one-shot link (whose own queries print) produces the outcome.
    let dead = socket_for("fallback");
    let _ = std::fs::remove_file(&dead);
    let (ok, stdout, stderr) = run_pgr(
        &dir,
        &main,
        &greet,
        &orphan,
        &[
            "-resident",
            "-resident_socket",
            &dead.display().to_string(),
            "-dead_strip",
            "-why_live",
            "_greet",
        ],
    );
    assert!(ok, "the fallback link runs: {stderr}");
    assert!(
        stdout.contains("_greet: kept by the strip"),
        "the cold answers print beside the fallback: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_query_without_the_strip_refuses_the_resident_premise() {
    let (dir, main, greet, orphan) = corpus("nostrip");
    let sock = socket_for("nostrip");
    start_daemon(&sock);
    // No `-dead_strip`, no record to walk: the session's refusal is the
    // `ERROR` the fallback reproduces with the cold lane's own premise
    // (the strip is the question's subject — the fix names the flag).
    let (ok, _stdout, stderr) = run_pgr(
        &dir,
        &main,
        &greet,
        &orphan,
        &[
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
            "-why_live",
            "_greet",
        ],
    );
    assert!(!ok, "the premise mismatch refuses the run");
    assert!(
        stderr.contains("-dead_strip"),
        "the refusal names the fix: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn the_fusion_relink_serves_the_chain() {
    let (dir, main, greet, orphan) = corpus("fusion");
    let sock = socket_for("fusion");
    start_daemon(&sock);
    let sock_arg = sock.display().to_string();
    // The capture: a full link through the session (the record rides the
    // reply; the query rides nothing yet).
    let (ok, _stdout, stderr) = run_pgr(
        &dir,
        &main,
        &greet,
        &orphan,
        &[
            "-resident",
            "-resident_socket",
            &sock_arg,
            "-incremental",
            "-dead_strip",
        ],
    );
    assert!(ok, "the capture link runs: {stderr}");
    // M93: a query-bearing fusion relink rides the session's replay —
    // the ladder's own walk re-ran the full Passes 1–3, so the mark
    // record is the replay's own and the v48 tail carries the chain
    // verbatim (the same print face the full-link lane rides).
    let (ok, stdout, stderr) = run_pgr(
        &dir,
        &main,
        &greet,
        &orphan,
        &[
            "-resident",
            "-resident_socket",
            &sock_arg,
            "-incremental",
            "-dead_strip",
            "-why_live",
            "_greet",
        ],
    );
    assert!(ok, "the fusion relink answers: {stderr}");
    assert!(
        stdout.contains("_greet: kept by the strip"),
        "the served chain answers the query: {stdout}"
    );
    assert!(
        stdout.contains("rooted at the entry point (-e)"),
        "the served chain names the root decision: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

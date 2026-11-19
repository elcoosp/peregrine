//! M84 — the incremental ladder's provenance queries: the M56/M57 lane
//! contract (`-why_export`/`-why_load` read the one-shot link's own
//! Pass-2 product, so the ladder refused them — "the ladder's replay
//! product is the record's, not the walk's") flips to service the M79
//! way: the ladder's own relink *is* the walk — `incremental_relink`
//! re-parses the inputs and runs the full Passes 1–3
//! (`pgr_core::link_cached`), so `result.resolution` and `result.loads`
//! are the walk's products, in the relink's own memory, and the answers
//! serve from them exactly as the one-shot serves its own. The fusion
//! lane serves its own replay's answers since M88 (the session's ladder
//! runs the same walk — `m88_fusion_provenance.rs` pins that face); the
//! in-process walk here answers the cold ladder either way.
//!
//! Gate matrix:
//! * the surface — the argv that refused since M56 parses now;
//! * the answers — the ladder's `-why_export` report is byte-for-byte
//!   the one-shot's answer to the same query over the same corpus (one
//!   walk, either lane, the same answer), and `-why_load` names the
//!   pulled member after an edited relink;
//! * the edges — a vacuous query refuses the relink (the misspelling
//!   named, never silently empty), and an untouched relink (the walk
//!   ran, nothing patched) still answers;
//! * the fusion face — a query beside `-resident -incremental` rides
//!   the session since M88 (the outcome's transport names the lane; the
//!   pre-M88 stand-down is `m88_fusion_provenance.rs`'s dead-socket
//!   row).

use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// hello.o: 16 KiB of `__text` (the tier-1 edit shape — same-size edits
/// patch a minority of the tiles), `_main` defined, a BL `_greet` site
/// the export query rides (the reverse index's one reference).
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

/// greet.o: `_greet` — the queried definition.
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
    let dir = std::env::temp_dir().join(format!("pgr_m84_prov_{}_{}", tag, std::process::id()));
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

/// One `pgr` invocation; stdout captured (the answers are the run's own
/// print face). The inputs ride explicitly — the pull gate links the
/// archive, the query gates the object pair.
fn pgr_link(dir: &Path, out: &Path, inputs: &[&Path], extra: &[&str]) -> std::process::Output {
    let mut argv: Vec<String> = vec!["-o".into(), out.display().to_string()];
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    argv.extend(inputs.iter().map(|p| p.display().to_string()));
    Command::new(env!("CARGO_BIN_EXE_pgr"))
        .args(&argv)
        .current_dir(dir)
        .output()
        .expect("the pgr binary runs")
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The run's answer face: everything before the driver's outcome line
/// (`pgr: wrote …` / the patch report) — the part both lanes print
/// identically for one question.
fn answer_of(s: &str) -> String {
    s.lines()
        .take_while(|line| !line.starts_with("pgr:"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One in-process daemon on a test-unique socket.
fn start_daemon(tag: &str) -> PathBuf {
    let sock = std::env::temp_dir().join(format!("pgr-m84-prov-{tag}.sock"));
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

/// The argv that refused since M56 parses now: the ladder's own walk is
/// the Pass-2 product, and the queries read it — either flag, both
/// flags, either spelling.
#[test]
fn the_surface_serves_the_queries_beside_the_ladder() {
    let dir = scratch("parse");
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let o = parse(&out, &[&a, &b], &["-why_export", "_greet", "-incremental"])
        .expect("the query rides the ladder now");
    assert!(!o.why_export.is_empty() && o.incremental, "the query rides");
    let o = parse(&out, &[&a, &b], &["-why_load", "-incremental"])
        .expect("the report rides the ladder now");
    assert!(o.why_load && o.incremental, "the report rides");
    let o = parse(
        &out,
        &[&a, &b],
        &["-why_export", "_main", "-why_load", "-incremental"],
    )
    .expect("both faces ride one run");
    assert!(o.why_load && o.why_export.len() == 1, "both faces ride");
}

// ---- the answers ------------------------------------------------------------

/// The ladder's `-why_export` answer is byte-for-byte the one-shot's
/// answer to the same query over the same corpus: the relink's own
/// Pass-2 product is the walk's, so one question has one answer either
/// lane.
#[test]
fn the_ladder_answers_the_one_shot_s_question() {
    let dir = scratch("parity");
    let (a, b) = corpus(&dir, true);
    let cold_out = dir.join("cold");
    let cold = pgr_link(&dir, &cold_out, &[&a, &b], &["-why_export", "_greet"]);
    assert!(cold.status.success(), "the one-shot link runs: {cold:?}");
    let cold_answer = stdout(&cold);
    assert!(
        cold_answer.contains("_greet"),
        "the answer names the queried symbol: {cold_answer}"
    );
    assert!(
        cold_answer.contains("hello.o"),
        "the answer names the reference site's file: {cold_answer}"
    );

    let warm_out = dir.join("warm");
    let capture = pgr_link(&dir, &warm_out, &[&a, &b], &["-incremental"]);
    assert!(
        capture.status.success(),
        "the capture link runs: {capture:?}"
    );
    let (a, _) = corpus(&dir, false);
    let relink = pgr_link(
        &dir,
        &warm_out,
        &[&a, &b],
        &["-incremental", "-why_export", "_greet"],
    );
    assert!(
        relink.status.success(),
        "the queried relink runs: {relink:?}"
    );
    let relink_answer = stdout(&relink);
    assert!(
        relink_answer.contains("_greet"),
        "the relink answers: {relink_answer}"
    );
    assert_eq!(
        answer_of(&cold_answer),
        answer_of(&relink_answer),
        "one walk — either lane, the same answer"
    );
}

/// `-why_load` beside the ladder: after an edited relink the report
/// names the pulled member (the walk's pull record is the relink's own,
/// not the previous link's).
#[test]
fn the_ladder_reports_the_pulled_member() {
    let dir = scratch("pull");
    let hello_path = dir.join("hello.o");
    std::fs::write(&hello_path, hello(false)).expect("hello.o writes");
    let mut a = pgr_fixtures::ArchiveBuilder::new("libgreet.a");
    a.add_member("greet.o", greet());
    let archive = dir.join("libgreet.a");
    std::fs::write(&archive, a.build()).expect("the archive writes");

    let out = dir.join("out");
    let capture = pgr_link(&dir, &out, &[&hello_path, &archive], &["-incremental"]);
    assert!(
        capture.status.success(),
        "the capture link runs: {capture:?}"
    );

    std::fs::write(&hello_path, hello(true)).expect("the edit writes");
    let relink = pgr_link(
        &dir,
        &out,
        &[&hello_path, &archive],
        &["-incremental", "-why_load"],
    );
    assert!(
        relink.status.success(),
        "the queried relink runs: {relink:?}"
    );
    let report = stdout(&relink);
    assert!(
        report.contains("greet.o"),
        "the relink's report names the pulled member: {report}"
    );
}

/// A vacuous query refuses the relink — the misspelling named, never
/// silently empty (the one-shot's own refusal, the ladder's too).
#[test]
fn a_vacuous_query_refuses_the_relink() {
    let dir = scratch("vacuous");
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let capture = parse(&out, &[&a, &b], &["-incremental"]).expect("the capture parses");
    pgr_driver::run(&capture).expect("the capture link runs");
    let (a, b) = corpus(&dir, true);
    let relink = parse(&out, &[&a, &b], &["-incremental", "-why_export", "_nope"])
        .expect("the relink parses");
    let err = pgr_driver::run(&relink).expect_err("the vacuous query refuses the run");
    let rendered = err.to_string();
    assert!(
        rendered.contains("_nope"),
        "the refusal names the misspelling: {rendered}"
    );
}

/// An untouched relink (the walk ran, nothing patched) still answers —
/// the answers are the walk's product, not the patch's.
#[test]
fn the_untouched_relink_still_answers() {
    let dir = scratch("untouched");
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let capture = parse(&out, &[&a, &b], &["-incremental"]).expect("the capture parses");
    pgr_driver::run(&capture).expect("the capture link runs");
    let relink = parse(&out, &[&a, &b], &["-incremental", "-why_export", "_main"])
        .expect("the relink parses");
    let outcome = pgr_driver::run(&relink).expect("the untouched relink answers");
    let patch = outcome.patch.expect("the relink reports its patch");
    assert!(patch.untouched, "the relink patched nothing");
}

// ---- the fusion handover ----------------------------------------------------

/// The fusion lane serves the queries now (M88): the session's ladder is
/// not a byte-replay — `serve_relink` runs the full Passes 1–3, so its
/// own Pass-2 product renders the answers the v45 tail carries verbatim
/// (the M87 precedent over the M84 stand-down). The in-process ladder
/// answers either way — a dead server's refusal is the handover it
/// always was (pinned in `m88_fusion_provenance.rs`).
#[test]
fn the_fusion_lane_serves_the_queries() {
    let dir = scratch("fusion");
    let (a, b) = corpus(&dir, false);
    let out = dir.join("out");
    let sock = start_daemon("fusion");

    let capture = parse(&out, &[&a, &b], &["-incremental"]).expect("the capture parses");
    pgr_driver::run(&capture).expect("the capture link runs");
    let (a, b) = corpus(&dir, true);
    let fusion = parse(
        &out,
        &[&a, &b],
        &[
            "-incremental",
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
            "-why_export",
            "_greet",
        ],
    )
    .expect("the fusion argv parses");
    assert!(
        fusion.resident && fusion.incremental,
        "the fusion surface rides"
    );
    let outcome = pgr_driver::run(&fusion).expect("the query rides the session and answers");
    assert!(
        outcome.transport.is_some(),
        "the session's ladder served the answer (the M88 service)"
    );
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
}

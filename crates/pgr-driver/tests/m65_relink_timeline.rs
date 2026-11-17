//! M65 — the relink ladder rides the observation seam: the §7.3 ladder's
//! engine rungs (the integrity gate, the patch plan, the clone-and-patch,
//! the `-incremental-verify` audit) join the M54 seam's phase vocabulary,
//! and the ladder's fallback rungs join the note vocabulary — so the
//! timing faces (`--time`/`--time-json`, the Chrome-trace timeline)
//! complete a real incremental cycle beside the ladder instead of
//! refusing it. The observation is read-only (the seam's own contract):
//! the observed relink patches the identical bytes the plain relink does.
//!
//! Gate matrix:
//! * the run — an edited relink under `--time` prints the rungs in
//!   ladder order (`relink_gate`, the warm pipeline's rows, `relink_plan`,
//!   `relink_patch`; `relink_audit` beside `-incremental-verify`), and the
//!   patched output is byte-identical to the full link's (the parity gate);
//! * the timeline — `--trace` beside the ladder writes the document the
//!   strict reader restores exactly (the rung rows ride it, the round-trip
//!   convention);
//! * the untouched relink — the plan names an empty dirty set and no patch
//!   row rides (the ladder's job was done; the report names the run it
//!   timed);
//! * the fallback — a handover to the full link names itself as a note on
//!   the full link's own report (one report per run: the run that produced
//!   the output, and the reason the ladder's rungs stop where they do).

use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectSection, ObjectSymbol};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m65_ladder_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// `main.o`: `_main` + a data pointer at `_greet`. `bump` rewrites the
/// body (the one-function edit the §7.3 ladder exists for) without
/// moving the shape — the relink patches in place.
fn main_object(bump: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let mut body = [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2);
    if bump {
        body[0] = 0xD5;
    }
    let text = b.add_section(ObjectSection::text("__text", body, vec![]));
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

/// Writes the corpus (`main.o` + `libgreet.a`); `bump` shapes the edit.
fn write_corpus(dir: &Path, bump: bool) {
    let main = dir.join("main.o");
    let archive = dir.join("libgreet.a");
    std::fs::write(&main, main_object(bump)).unwrap();
    let mut a = ArchiveBuilder::new("libgreet.a");
    a.add_member("greet.o", greet_object());
    std::fs::write(&archive, a.build()).unwrap();
}

/// Runs the real `pgr` binary and returns stdout (the surface's face).
/// The corpus stays as the caller wrote it — the edit is the caller's.
fn run_binary(dir: &Path, out: &str, extra: &[&str]) -> String {
    let main = dir.join("main.o");
    let archive = dir.join("libgreet.a");
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
    String::from_utf8(output.stdout).expect("stdout is text")
}

/// The full ladder cycle: the recording first link, the edit, the relink
/// under `extra` — returns the relink's stdout.
fn cycle(dir: &Path, out: &str, extra: &[&str]) -> String {
    write_corpus(dir, false);
    run_binary(dir, out, &["-incremental"]);
    // The one-function edit: the body's first instruction byte moves, the
    // shape holds — the ladder patches in place.
    write_corpus(dir, true);
    run_binary(dir, out, extra)
}

#[test]
fn the_ladder_times_its_rungs() {
    let dir = scratch("time");
    let stdout = cycle(
        &dir,
        "app",
        &["-incremental", "--time", "-incremental-verify"],
    );
    // The rungs ride the table in ladder order, the warm pipeline's rows
    // between the gate and the plan (the relink re-parses the edited
    // input — the POIs are file-side, not session state).
    let gate = stdout.find("relink_gate").expect("the gate row rides");
    let parse_row = stdout.find("parse").expect("the warm pipeline rides");
    let plan = stdout.find("relink_plan").expect("the plan row rides");
    let patch = stdout.find("relink_patch").expect("the patch row rides");
    let audit = stdout.find("relink_audit").expect("the audit row rides");
    assert!(
        gate < parse_row && parse_row < plan && plan < patch && patch < audit,
        "the rungs ride in ladder order:\n{stdout}"
    );
    assert!(
        stdout.contains("tiles=") && stdout.contains("dirty=1"),
        "the plan names the edited tile:\n{stdout}"
    );
    assert!(
        stdout.contains("healed=false, issues=0"),
        "the audit names its verdict:\n{stdout}"
    );
}

#[test]
fn the_ladder_traces_its_rungs_and_keeps_the_parity() {
    let dir = scratch("trace");
    let trace_path = dir.join("ladder.json");
    let trace = trace_path.display().to_string();
    let stdout = cycle(&dir, "app", &["-incremental", "--trace", &trace]);
    let _ = stdout; // the timeline file is the face under test

    // The document is the strict reader's own face: it restores the
    // writer's data exactly (the round-trip convention), the rung rows
    // riding beside the warm pipeline's spans.
    let raw = std::fs::read_to_string(&trace_path).expect("the timeline writes");
    let report = pgr_core::trace::parse_trace_json(&raw).expect("the ladder timeline parses");
    let restored =
        pgr_core::trace::parse_trace_json(&report.render()).expect("the round trip parses");
    assert_eq!(restored, report, "the round trip restores the data exactly");
    let phases: Vec<pgr_core::observe::Phase> = report.spans.iter().map(|s| s.phase).collect();
    for rung in [
        pgr_core::observe::Phase::RelinkGate,
        pgr_core::observe::Phase::RelinkPlan,
        pgr_core::observe::Phase::RelinkPatch,
    ] {
        assert!(
            phases.contains(&rung),
            "the {rung:?} span rides the timeline: {phases:?}"
        );
    }
    assert!(
        report.lanes.iter().any(|l| l.name == "pgr link"),
        "the pipeline's lane rides the registry"
    );

    // The parity gate: the observed relink patches the identical bytes
    // the plain relink does — the seam never moves a byte. (The
    // reference is the incremental cycle's own full-link shape: the
    // ladder stands on the slack anchors, so the plain link runs the
    // same implied-slack first link the cycle records.)
    let patched = std::fs::read(dir.join("app")).unwrap();
    let plain_dir = scratch("plain");
    write_corpus(&plain_dir, true);
    run_binary(&plain_dir, "plain", &["-incremental"]);
    assert_eq!(
        patched,
        std::fs::read(plain_dir.join("plain")).unwrap(),
        "the observed relink patches the full link's bytes"
    );
}

#[test]
fn the_untouched_relink_names_no_patch_row() {
    let dir = scratch("untouched");
    write_corpus(&dir, false);
    run_binary(&dir, "app", &["-incremental"]);
    // No edit: the plan's dirty set is empty, the ladder's job is done.
    let stdout = run_binary(&dir, "app", &["-incremental", "--time"]);
    assert!(
        stdout.contains("relink_plan"),
        "the plan row rides the untouched relink:\n{stdout}"
    );
    assert!(
        !stdout.contains("relink_patch"),
        "no patch row rides a relink that patched nothing:\n{stdout}"
    );
    assert!(
        stdout.contains("relink_gate"),
        "the gate still gates (and reports) the untouched run:\n{stdout}"
    );
}

#[test]
fn the_fallback_names_itself_on_the_full_link_report() {
    let dir = scratch("fallback");
    write_corpus(&dir, false);
    run_binary(&dir, "app", &["-incremental"]);
    write_corpus(&dir, true);
    // The unreadable record: the ladder's decode rung refuses, the full
    // link re-records — and the report the run prints names the handover
    // (one report per run: the full link's phases, the note leading).
    let record = dir.join("app.pgr-inc");
    std::fs::write(&record, b"not a record").unwrap();
    let stdout = run_binary(&dir, "app", &["-incremental", "--time"]);
    assert!(
        stdout.contains("note: record unreadable"),
        "the handover note leads the report:\n{stdout}"
    );
    assert!(
        !stdout.contains("relink_plan") && !stdout.contains("relink_patch"),
        "no rung rows ride the run the ladder did not finish:\n{stdout}"
    );
    assert!(
        stdout.contains("parse") && stdout.contains("layout"),
        "the full link's own phases ride the report:\n{stdout}"
    );
}

/// M66 (v42 in service): the fusion lane rides — the session's ladder
/// reports its rungs beside the warm pipeline, the served report prints
/// beside the relink and the served timeline writes to `--trace`'s path
/// (the same face either lane writes). The cycle runs against an
/// in-process daemon on a test-unique socket; the rung rows in the
/// served report name the run the session actually executed.
#[test]
fn the_fusion_lane_serves_the_ladder_faces() {
    let dir = scratch("fusion");
    write_corpus(&dir, false);
    let sock = dir.join("fusion.sock");
    let server_sock = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&server_sock, std::time::Duration::from_secs(120));
    });
    let mut linked = false;
    for _ in 0..500 {
        if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
            linked = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(linked, "the daemon socket came up");

    // The recording first link (the daemon captures the record; the
    // cycle's full link runs warm over the session's POIs).
    run_binary(
        &dir,
        "app",
        &[
            "-incremental",
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
        ],
    );
    write_corpus(&dir, true);
    let trace = dir.join("fusion.json");
    let stdout = run_binary(
        &dir,
        "app",
        &[
            "-incremental",
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
            "--time",
            "--trace",
            &trace.display().to_string(),
            "-incremental-verify",
        ],
    );
    // The served report names the session's rungs in ladder order — the
    // no-Parse-row shape would be the POIs' (the session re-parses the
    // edited input, so the parse row rides its own event).
    let gate = stdout.find("relink_gate").expect("the gate row rides");
    let plan = stdout.find("relink_plan").expect("the plan row rides");
    let patch = stdout.find("relink_patch").expect("the patch row rides");
    let audit = stdout.find("relink_audit").expect("the audit row rides");
    assert!(
        gate < plan && plan < patch && patch < audit,
        "ladder order:\n{stdout}"
    );
    // The served timeline is the strict reader's own face: it restores
    // exactly, the rung rows riding it.
    let raw = std::fs::read_to_string(&trace).expect("the served timeline writes");
    let report = pgr_core::trace::parse_trace_json(&raw).expect("the served timeline parses");
    assert!(
        report
            .spans
            .iter()
            .any(|s| s.phase == pgr_core::observe::Phase::RelinkPatch),
        "the patch span rides the served timeline"
    );
    assert_eq!(
        pgr_core::trace::parse_trace_json(&report.render()).expect("the round trip parses"),
        report,
        "the round trip restores the data exactly"
    );
}

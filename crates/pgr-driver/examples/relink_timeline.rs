//! The relink-ladder consumer example (M65): the §7.3 ladder's own rungs
//! ride the M54 observation seam, so the timing faces complete a real
//! incremental cycle instead of refusing it. The example walks the whole
//! cycle — the recording first link, the untouched relink (the plan names
//! an empty dirty set and no patch row rides), the one-function edit and
//! its patched relink (the gate, the warm pipeline, the plan, the patch
//! and the audit rows in ladder order) — reading each timeline back
//! through the core seam's strict reader (`pgr_core::trace::
//! parse_trace_json`) to show the round trip, and printing the time
//! report's table beside it. The observation is read-only: the patched
//! image is byte-identical to the full link's (the parity gate is the
//! seam's own contract).
//!
//! Run: `cargo run -p pgr-driver --example relink_timeline`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use; the written
//! `ladder.json` opens in `chrome://tracing` or the Perfetto UI, the
//! `relink_*` rows sitting between the pipeline's spans).

use pgr_driver::opts;
use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::path::Path;

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
        vec![ObjectReloc::unsigned(greet as u32).at(0)],
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

/// Writes the corpus; `bump` shapes the edit.
fn write_corpus(dir: &Path, bump: bool) {
    std::fs::write(dir.join("main.o"), main_object(bump)).unwrap();
    let mut a = ArchiveBuilder::new("libgreet.a");
    a.add_member("greet.o", greet_object());
    std::fs::write(dir.join("libgreet.a"), a.build()).unwrap();
}

/// Links the corpus through the driver's own parse + run pair with
/// `extra` argv.
fn run(dir: &Path, out: &str, extra: &[&str]) {
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join(out).as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    argv.push(dir.join("main.o").as_os_str().to_os_string());
    argv.push(dir.join("libgreet.a").as_os_str().to_os_string());
    let parsed = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&parsed).expect("the link runs");
}

/// Prints what the strict reader restored: the lanes with their names
/// (M64's registry) and the run's spans — the pipeline's passes beside
/// the ladder's rungs, each with its own detail.
fn show_timeline(path: &Path, label: &str) {
    let raw = std::fs::read_to_string(path).expect("the timeline writes");
    let report = pgr_core::trace::parse_trace_json(&raw).expect("the timeline parses");
    println!("--- {label}: the timeline the reader restored ---");
    for lane in &report.lanes {
        println!("  lane {} = {}", lane.id, lane.name);
    }
    for span in &report.spans {
        println!(
            "  {:>12}  ts={:>6}µs dur={:>6}µs",
            span.phase.as_str(),
            span.start_us,
            span.dur_us,
        );
    }
    for note in &report.notes {
        println!("  note [{}] {}", note.kind, note.reason);
    }
}

fn main() {
    let dir = std::env::temp_dir().join(format!("pgr_relink_timeline_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");

    // 1. The recording first link (the full link behind `-incremental`
    //    re-records so the first edit can patch).
    write_corpus(&dir, false);
    run(&dir, "app", &["-incremental"]);

    // 2. The untouched relink: the plan's dirty set is empty, the ladder's
    //    job is done — the report names `relink_plan` and no patch row.
    let untouched_trace = dir.join("untouched.json");
    let untouched = untouched_trace.display().to_string();
    println!("== the untouched relink ==");
    run(
        &dir,
        "app",
        &["-incremental", "--time", "--trace", &untouched],
    );
    show_timeline(&untouched_trace, "untouched relink");

    // 3. The edited relink: the one-function edit patches in place (the
    //    audit rides beside `-incremental-verify`).
    write_corpus(&dir, true);
    let ladder_trace = dir.join("ladder.json");
    let ladder = ladder_trace.display().to_string();
    println!("== the edited relink (the ladder's rungs) ==");
    run(
        &dir,
        "app",
        &[
            "-incremental",
            "--time",
            "--trace",
            &ladder,
            "-incremental-verify",
        ],
    );
    show_timeline(&ladder_trace, "edited relink");

    // 4. The parity gate: the patched image is byte-identical to the
    //    incremental cycle's own full-link shape (the same implied slack
    //    the ladder stands on) — the observation never moved a byte.
    let ref_dir = dir.join("reference-inputs");
    std::fs::create_dir_all(&ref_dir).expect("the reference dir builds");
    write_corpus(&ref_dir, true);
    run(&ref_dir, "reference", &["-incremental"]);
    let patched = std::fs::read(dir.join("app")).expect("the patched image reads");
    let full = std::fs::read(ref_dir.join("reference")).expect("the reference image reads");
    println!(
        "== parity: the relinked image {} the full link's bytes ({} bytes) ==",
        if patched == full {
            "matches"
        } else {
            "DIVERGES FROM"
        },
        patched.len(),
    );
}

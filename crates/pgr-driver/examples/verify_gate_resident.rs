//! The resident lane's verify gate, runnable (M76): a dylib link under
//! `-resident -verify` — the request asks the session for its own strict
//! pass (v43's flag, M72's served verdict), the client gates the write
//! on the served verdict, and the verdict rides the outcome exactly like
//! the cold lane's. One verifier pass per link, not two: the session ran
//! it on the exact bytes the reply carries, and
//! [`pgr_driver::gate_from_served`] shapes the gate face from it. The
//! fallback story stays honest — a resident attempt that stands down
//! hands over to the one-shot link, whose own M73 gate runs the pass
//! locally — and the corrupted twin through the served face renders the
//! same refusal the cold gate does.
//!
//! ```sh
//! cargo run -p pgr-driver --example verify_gate_resident
//! ```

use pgr_driver::gate_from_served;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// One input object: `_main` and `_helper` over a small `__text`.
fn object(name: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (i, sym) in ["_main", "_helper"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.build().expect("the fixture object builds")
}

/// Starts an in-process daemon on `sock` and waits until it accepts.
fn start_daemon(sock: &std::path::Path) {
    let owned = sock.to_path_buf();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(120));
    });
    for _ in 0..500 {
        if UnixStream::connect(sock).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("daemon socket {} never came up", sock.display());
}

fn main() {
    // The demo runs unobserved by default; `PGR_TRACING=1` installs the
    // house tracing subscriber (the workspace convention — the demo
    // prints its own verdict either way).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt::init();
    }

    let dir = std::env::temp_dir().join("pgr_example_verify_gate_resident");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let obj = dir.join("main.o");
    std::fs::write(&obj, object("main.o")).expect("the object writes");
    let out = dir.join("hello.dylib");
    let sock: PathBuf = dir.join("demo.sock");
    start_daemon(&sock);

    // The resident link under `-verify`: the flag rides the request, the
    // session's own strict pass gates the write through the served
    // verdict, and the outcome's summary is that verdict's.
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        out.display().to_string(),
        "-dylib".to_string(),
        "-resident".to_string(),
        "-resident_socket".to_string(),
        sock.display().to_string(),
        "-verify".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let opts = pgr_driver::opts::parse(&argv).expect("the argv parses");
    let cold = pgr_driver::run(&opts).expect("the resident link runs");
    let cold_summary = cold
        .verify
        .expect("the served verdict rides the resident outcome");
    let transport_line = match cold.transport {
        Some(pgr_daemon::Transport::Full) => "the image crossed in full".to_string(),
        Some(pgr_daemon::Transport::Tiles { tiles, bytes }) => {
            format!("{tiles} tile(s), {bytes} bytes crossed")
        }
        None => "no transport recorded".to_string(),
    };
    println!(
        "resident cold link {} ({} bytes, {}) — the served verdict: ok={} ({} error(s), {} warning(s))",
        cold.output,
        cold.file_size,
        transport_line,
        cold_summary.ok,
        cold_summary.errors,
        cold_summary.warnings,
    );

    // The warm relink on the same session: the served verdict rides the
    // same way — the gate is a property of the flag, not of the lane's
    // temperature.
    let warm = pgr_driver::run(&opts).expect("the warm resident link runs");
    let warm_summary = warm
        .verify
        .expect("the served verdict rides the warm outcome too");
    println!(
        "resident warm link — the served verdict: ok={} ({} error(s), {} warning(s))",
        warm_summary.ok, warm_summary.errors, warm_summary.warnings,
    );
    assert!(out.is_file(), "a passing gate ships the file");

    // The corrupted twin through the served face: the session's verdict
    // answers for the exact bytes the reply carries; a report the strict
    // pass seeded with findings refuses through the same help-texted
    // error the cold gate renders (`gate_from_served` prices O(issues),
    // never the verifier pass).
    let mut corrupted = std::fs::read(&out).expect("the image reads");
    let mid = corrupted.len() / 2 + 0x4000;
    corrupted[mid] ^= 0xff;
    let strict = pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let served = pgr_verify::verify(&corrupted, &strict);
    let gate = gate_from_served(&served);
    println!(
        "the corrupted twin's served verdict: ok={} ({} issue(s) named):",
        gate.summary.ok,
        gate.issues.len()
    );
    for issue in &gate.issues {
        println!("    {issue}");
    }
    let rendered = gate.refusal().render();
    println!("-- the refusal the driver would have printed --");
    println!("{rendered}");
    assert!(!gate.summary.ok, "the corrupted image fails its gate");

    // The fallback story: a socket nothing answers stands the resident
    // attempt down, and the one-shot link's own gate (M73) runs the pass
    // locally — either lane, one gate, one outcome shape.
    let dead = dir.join("dead.sock");
    let _ = std::fs::remove_file(&dead);
    let mut fallback = opts.clone();
    fallback.resident_socket = Some(dead.display().to_string());
    let outcome = pgr_driver::run(&fallback).expect("the fallback link runs");
    let fallback_summary = outcome
        .verify
        .expect("the one-shot gate rides the fallback outcome");
    println!(
        "fallback (no daemon) — the local gate: ok={} ({} error(s), {} warning(s))",
        fallback_summary.ok, fallback_summary.errors, fallback_summary.warnings,
    );
}

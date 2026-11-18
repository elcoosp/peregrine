//! M76 — the resident lane's verify gate: `-verify` beside `-resident`
//! flips to service. The flag rides the resident request (v43's
//! `verify` flag, M72's served verdict), the client gates the write on
//! the session's own strict pass — a failing served verdict refuses to
//! ship (the audit's rule: the file is never written), a passing one
//! rides `LinkOutcome::verify` like the cold lane's. The gate keeps its
//! refusals (`-r`, `-incremental`) and its fallback story: a resident
//! attempt that stands down hands over to the one-shot link, whose own
//! M73 gate still runs.

use pgr_driver::opts::Options;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// hello.o: `_main` ret (the smallest image the pipeline produces).
fn hello_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Writes the corpus and returns options for a resident link over it.
fn corpus(name: &str) -> (Options, PathBuf) {
    let dir = std::env::temp_dir().join(format!("pgr_m76_{}_{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let hello = dir.join("hello.o");
    std::fs::write(&hello, hello_object()).expect("the fixture object writes");
    let mut opts = Options::default();
    opts.inputs.push(hello.display().to_string());
    opts.output = dir.join("hello").display().to_string();
    opts.config.ident = format!("m76-resident-{name}");
    (opts, dir)
}

/// Unique socket path for one test.
fn socket_for(test: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pgr-m76-{}-{test}.sock", std::process::id()))
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

// ---- the served gate -----------------------------------------------------------

#[test]
fn the_flag_rides_the_resident_request_and_the_verdict_gates_the_outcome() {
    let (mut opts, dir) = corpus("clean");
    let sock = socket_for("clean");
    start_daemon(&sock);
    opts.resident = true;
    opts.resident_socket = Some(sock.display().to_string());
    opts.verify = true;

    let cold = pgr_driver::run(&opts).expect("the resident link runs");
    let summary = cold
        .verify
        .expect("the served verdict rides the resident outcome");
    assert!(summary.ok, "the clean link passes its own gate");
    assert_eq!(summary.errors, 0);
    assert_eq!(summary.warnings, 0, "the strict pass names no warnings");
    assert!(
        Path::new(&opts.output).is_file(),
        "the gate wrote the image"
    );

    // A warm relink on the same session serves the verdict the same way —
    // the flag rides every resident link, not just the session's first.
    let warm = pgr_driver::run(&opts).expect("the warm resident link runs");
    let warm_summary = warm
        .verify
        .expect("the served verdict rides the warm outcome too");
    assert!(warm_summary.ok, "the warm link passes its own gate");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn the_fallback_one_shot_link_still_gates() {
    let (mut opts, dir) = corpus("fallback");
    // A socket nothing answers: the resident attempt stands down and the
    // one-shot link (whose own M73 gate runs) produces the outcome.
    let dead_sock = socket_for("fallback");
    let _ = std::fs::remove_file(&dead_sock);
    opts.resident = true;
    opts.resident_socket = Some(dead_sock.display().to_string());
    opts.verify = true;

    let outcome = pgr_driver::run(&opts).expect("the fallback link runs");
    let summary = outcome
        .verify
        .expect("the one-shot gate rides the fallback outcome");
    assert!(summary.ok, "the clean link passes its own gate");
    assert!(
        Path::new(&opts.output).is_file(),
        "the gate wrote the image"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_served_face_names_the_issues_and_the_fix() {
    // The gate face over a served report: the produced image, corrupted
    // past the segment contract — the strict pass names the issues, the
    // refusal renders the fix (the miette help text), the driver maps it
    // to `DriverError::Verify` (exit 1, nothing shipped). The session's
    // pass answers for the exact bytes the reply carries; the client's
    // consumption of it prices O(issues), never the verifier pass.
    let (opts, dir) = corpus("refusal");
    let image = pgr_driver::link_to_bytes(&opts).expect("the link runs");
    let mut corrupted = image;
    let mid = corrupted.len() / 2 + 0x4000;
    corrupted[mid] ^= 0xff;
    let strict = pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let served = pgr_verify::verify(&corrupted, &strict);
    let gate = pgr_driver::gate_from_served(&served);
    assert!(!gate.summary.ok, "the corrupted image fails its gate");
    assert!(gate.summary.errors > 0, "the segment contract refuses");
    let rendered = gate.refusal().render();
    assert!(
        rendered.contains("failed the link's verify gate"),
        "the refusal names the gate: {rendered}"
    );
    assert!(
        rendered.to_lowercase().contains("help") || rendered.contains("─"),
        "the refusal renders with its help text: {rendered}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_served_face_keeps_the_strict_contract() {
    // The served face counts warnings as blocking (the strict pass the
    // session runs) — the summary the outcome carries answers for both
    // severities, like the cold lane's.
    let (opts, dir) = corpus("strict");
    let image = pgr_driver::link_to_bytes(&opts).expect("the link runs");
    let strict = pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let clean = pgr_verify::verify(&image, &strict);
    let gate = pgr_driver::gate_from_served(&clean);
    assert!(
        gate.summary.ok,
        "a clean image's served verdict passes: {:?}",
        gate.summary
    );
    assert_eq!(gate.summary.errors + gate.summary.warnings, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

//! M8 resident-server end-to-end gates (architecture doc §10.4 row M8):
//!
//! * **byte-identity** — a `-resident` link is byte-identical to the
//!   one-shot link in deterministic mode (the §7.2 constraint, asserted
//!   over executables, dylibs and archive corpora);
//! * **transparency** — an unreachable daemon falls back to the one-shot
//!   link silently and the output stays correct;
//! * **crash/restart safety** — a daemon restart between links never
//!   corrupts output (the daemon holds no output state; the client writes);
//! * **concurrent-build safety** — queued clients all get the correct,
//!   identical bytes;
//! * **diagnostics parity** — a `-u` failure surfaces the same error
//!   through the resident attempt + fallback.

use pgr_daemon::DaemonClient;
use pgr_driver::opts::Options;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// hello.o: `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret.
fn hello_main() -> Vec<u8> {
    let text: Vec<u8> = [
        0x9000_0000u32, // adrp x0, _msg@page
        0x9100_0000u32, // add x0, x0, #_msg@pageoff
        0x9400_0000u32, // bl _greet
        0x5280_0000u32, // mov w0, #0
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("hello.o");
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
    b.add_section(ObjectSection::cstring("hello, peregrine\n"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_msg".into(),
        section_index: 1,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.build().unwrap()
}

/// greet.o: `_greet` body + a `__data` pointer to `_greet` (a chained
/// rebase slot).
fn greet() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.section_mut(data).relocs = vec![ObjectReloc::unsigned(0).at(0)];
    b.build().unwrap()
}

fn unused_member() -> Vec<u8> {
    let mut b = ObjectBuilder::new("unused.o");
    let t = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_unused".into(),
        section_index: t,
        value: 0,
        weak: false,
    });
    b.build().unwrap()
}

const TBD: &str = "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: /usr/lib/libgreet.dylib\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _greet ]\n...\n";

/// Writes the corpus to a temp dir and returns `Options` for it.
fn corpus(name: &str, dylib: bool, archive: bool) -> (Options, PathBuf) {
    let dir = std::env::temp_dir().join(format!("pgr_m8_{}_{}", std::process::id(), name));
    std::fs::create_dir_all(&dir).unwrap();
    let hello = dir.join("hello.o");
    std::fs::write(&hello, hello_main()).unwrap();
    let mut opts = Options::default();
    opts.inputs.push(hello.display().to_string());
    if archive {
        let mut arch = pgr_fixtures::ArchiveBuilder::new("libutil.a");
        arch.add_member("greet.o", greet());
        arch.add_member("unused.o", unused_member());
        let a = dir.join("libutil.a");
        std::fs::write(&a, arch.build()).unwrap();
        opts.lib_dirs.push(dir.display().to_string());
        opts.libs.push("util".into());
    } else if dylib {
        let stub = dir.join("libgreet.tbd");
        std::fs::write(&stub, TBD).unwrap();
        opts.lib_dirs.push(dir.display().to_string());
        opts.libs.push("greet".into());
    } else {
        let g = dir.join("greet.o");
        std::fs::write(&g, greet()).unwrap();
        opts.inputs.push(g.display().to_string());
    }
    opts.output = dir.join(format!("out-{name}")).display().to_string();
    opts.config.ident = format!("m8-resident-{name}");
    (opts, dir)
}

/// Unique socket path for one test.
fn socket_for(test: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pgr-m8-{}-{test}.sock", std::process::id()))
}

/// Starts an in-process daemon on `sock` and waits until it accepts.
fn start_daemon(sock: &Path) {
    let owned = sock.to_path_buf();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(120));
    });
    wait_for_socket(sock.to_path_buf());
}

fn wait_for_socket(sock: PathBuf) {
    for _ in 0..500 {
        if UnixStream::connect(&sock).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("daemon socket {} never came up", sock.display());
}

#[test]
fn resident_output_is_byte_identical_to_one_shot() {
    for (name, dylib, archive) in [
        ("exec", false, false),
        ("dylib", true, false),
        ("archive", false, true),
    ] {
        let (one_shot_opts, _dir) = corpus(name, dylib, archive);
        let expected = pgr_driver::link_to_bytes(&one_shot_opts).unwrap();

        let sock = socket_for(name);
        start_daemon(&sock);
        let mut resident_opts = one_shot_opts.clone();
        resident_opts.resident = true;
        resident_opts.resident_socket = Some(sock.display().to_string());
        // Two resident links: cold session, then warm — both must match the
        // one-shot bytes exactly.
        let cold = pgr_driver::link_to_bytes(&resident_opts).unwrap();
        let warm = pgr_driver::link_to_bytes(&resident_opts).unwrap();
        assert_eq!(
            cold, expected,
            "{name}: resident cold link must be byte-identical to one-shot"
        );
        assert_eq!(
            warm, expected,
            "{name}: resident warm link must be byte-identical to one-shot"
        );
    }
}

#[test]
fn warm_session_reuses_parsed_state_across_the_wire() {
    // Daemon-level gate: the second identical link reports POI hits (the
    // parse was skipped), and the bytes are unchanged.
    let dir = std::env::temp_dir().join(format!("pgr_m8_warm_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let hello = dir.join("hello.o");
    std::fs::write(&hello, hello_main()).unwrap();
    let greet_path = dir.join("greet.o");
    std::fs::write(&greet_path, greet()).unwrap();
    let inputs = vec![
        pgr_core::LinkInput {
            name: "hello.o".into(),
            bytes: hello_main(),
        },
        pgr_core::LinkInput {
            name: "greet.o".into(),
            bytes: greet(),
        },
    ];
    let cfg = pgr_core::layout::LinkConfig {
        ident: "m8-warm".into(),
        ..pgr_core::layout::LinkConfig::default()
    };
    let job = pgr_daemon::LinkJob::build(&cfg, &[], &inputs, &[]);

    let sock = socket_for("warm");
    start_daemon(&sock);
    let mut client = DaemonClient::connect(&sock).unwrap();
    client.hello().unwrap();
    let first = client.link(&job).unwrap();
    let second = client.link(&job).unwrap();
    assert_eq!(first.image, second.image, "warm relink bytes identical");
    assert!(
        second.poi_hits >= 2,
        "second link must report POI hits, got hits={} misses={}",
        second.poi_hits,
        second.poi_misses
    );
    client.shutdown().unwrap();
}

#[test]
fn resident_falls_back_when_the_daemon_is_absent() {
    let (opts, _dir) = corpus("fallback", false, false);
    let expected = pgr_driver::link_to_bytes(&opts).unwrap();

    let mut resident_opts = opts.clone();
    resident_opts.resident = true;
    // A socket path under a fresh temp name: nothing listens there, and no
    // pgrd binary sits beside the test executable, so auto-start fails too.
    resident_opts.resident_socket = Some(
        std::env::temp_dir()
            .join(format!("pgr-m8-absent-{}.sock", std::process::id()))
            .display()
            .to_string(),
    );
    let bytes = pgr_driver::link_to_bytes(&resident_opts).unwrap();
    assert_eq!(
        bytes, expected,
        "the one-shot fallback must produce the correct bytes"
    );
}

#[test]
fn resident_link_survives_a_daemon_restart() {
    let (opts, _dir) = corpus("restart", false, false);
    let expected = pgr_driver::link_to_bytes(&opts).unwrap();
    let sock = socket_for("restart");

    start_daemon(&sock);
    let mut resident_opts = opts.clone();
    resident_opts.resident = true;
    resident_opts.resident_socket = Some(sock.display().to_string());
    let first = pgr_driver::link_to_bytes(&resident_opts).unwrap();

    // Shutdown the daemon (the `pgrd --shutdown` path) and wait for the
    // socket file to go away.
    DaemonClient::connect(&sock).unwrap().shutdown().unwrap();
    for _ in 0..500 {
        if !sock.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    // A fresh daemon on the same socket: the session is rebuilt from
    // scratch, the output is still exactly the one-shot bytes.
    start_daemon(&sock);
    let second = pgr_driver::link_to_bytes(&resident_opts).unwrap();
    assert_eq!(first, expected);
    assert_eq!(
        second, expected,
        "a restarted daemon must not change a single output byte"
    );
}

#[test]
fn concurrent_resident_links_are_all_correct() {
    let (opts, _dir) = corpus("concurrent", false, false);
    let expected = pgr_driver::link_to_bytes(&opts).unwrap();
    let sock = socket_for("concurrent");
    start_daemon(&sock);

    let mut resident_opts = opts.clone();
    resident_opts.resident = true;
    resident_opts.resident_socket = Some(sock.display().to_string());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let o = resident_opts.clone();
            std::thread::spawn(move || pgr_driver::link_to_bytes(&o).unwrap())
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), expected, "queued client got wrong bytes");
    }
}

#[test]
fn force_load_failure_surfaces_through_the_fallback() {
    let (mut opts, _dir) = corpus("force", false, false);
    opts.force_load.push("_missing".into());
    let one_shot_err = format!("{}", pgr_driver::link_to_bytes(&opts).unwrap_err());

    let sock = socket_for("force");
    start_daemon(&sock);
    opts.resident = true;
    opts.resident_socket = Some(sock.display().to_string());
    let resident_err = format!("{}", pgr_driver::link_to_bytes(&opts).unwrap_err());
    assert_eq!(
        resident_err, one_shot_err,
        "the -u gate must report the same error through the fallback"
    );
    assert!(one_shot_err.contains("_missing"), "{one_shot_err}");
}

/// The binary artifact sanity gate: the daemon and the driver agree on the
/// wire (a client that never says HELLO gets served anyway, and a LINK over
/// a plain connection works).
#[test]
fn daemon_serves_a_link_without_handshake() {
    let (opts, _dir) = corpus("nohello", false, false);
    let expected = pgr_driver::link_to_bytes(&opts).unwrap();
    let sock = socket_for("nohello");
    start_daemon(&sock);

    let job = pgr_daemon::LinkJob::build(
        &opts.config,
        &opts
            .force_load
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect::<Vec<_>>(),
        &opts
            .inputs
            .iter()
            .map(|p| pgr_core::LinkInput {
                name: p.clone(),
                bytes: std::fs::read(p).unwrap(),
            })
            .collect::<Vec<_>>(),
        &[],
    );
    let mut client = DaemonClient::connect(&sock).unwrap();
    let image = client.link(&job).unwrap();
    assert_eq!(image.image, expected);
    client.shutdown().unwrap();
    // The daemon removed its socket on shutdown; the path may linger for a
    // few ms, so poll briefly.
    let mut gone = false;
    for _ in 0..500 {
        if !sock.exists() {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(gone, "the daemon must unlink its socket on shutdown");
}

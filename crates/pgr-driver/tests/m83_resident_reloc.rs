//! M83 — the resident lane's relocatable shape: the M8 lane contract
//! (`-r` named "no resident shape; drop -resident") flips to service the
//! M80/M81/M82 way: the session's walk serves the object shape — Passes
//! 1–2 over the raw blobs (`pgr_core::link_reloc`, the same walk the cold
//! lane runs; the POI cache is the segmented pipeline's optimization and
//! the object path re-parses) and `pgr_emit::build_object_image` assembles
//! the `MH_OBJECT` — and the reply's IMAGE tail carries it verbatim. The
//! daemon never touches the filesystem, the client writes the object;
//! a resident attempt that stands down hands over to the one-shot
//! relocatable link, whose own walk produces the same bytes. The surface
//! keeps its edges: every knob the relocatable output refuses (the map,
//! the order file, `-incremental`, `-verify`, the dead-strip roots)
//! refuses unchanged, so the served shape never carries them.
//!
//! Gate matrix:
//! * the served parity — a resident `-r` link plans the object the cold
//!   `-r` link plans (byte-identical; the header names `MH_OBJECT`);
//! * the fallback — a resident attempt that stands down hands over to
//!   the one-shot relocatable link;
//! * self-consumption — the served object is a real link input: the M10
//!   two-step gate relinks it into an executable (the open `_greet`
//!   resolves), and the strict pass walks the result.

use pgr_driver::run;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `hello_main.o`: `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret — the
/// M10 relocatable fixture's shape (an open `_greet` the two-step gate
/// resolves in step two).
fn main_object(dir: &Path) -> PathBuf {
    let mut b = ObjectBuilder::new("hello_main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![
            0x90, 0x00, 0x00, 0x00, // adrp x0, _msg@page
            0x91, 0x00, 0x00, 0x00, // add x0, x0, #_msg@pageoff
            0x94, 0x00, 0x00, 0x00, // bl _greet
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ],
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
        section_index: text,
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
    let path = dir.join("hello_main.o");
    std::fs::write(&path, b.build().expect("the fixture object builds"))
        .expect("the object writes");
    path
}

/// greet.o (never edited): `_greet`.
fn greet_object(dir: &Path) -> PathBuf {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let path = dir.join("greet.o");
    std::fs::write(&path, b.build().expect("the fixture object builds"))
        .expect("the object writes");
    path
}

/// Relocatable one-shot options over the two objects.
fn reloc_opts(out: &Path, a: &Path, b: &Path) -> pgr_driver::opts::Options {
    pgr_driver::opts::Options {
        output: out.display().to_string(),
        inputs: vec![a.display().to_string(), b.display().to_string()],
        config: pgr_core::layout::LinkConfig {
            filetype: pgr_core::layout::OutputType::Relocatable,
            ..pgr_core::layout::LinkConfig::default()
        },
        ..pgr_driver::opts::Options::default()
    }
}

/// Adds the resident lane flags to `opts`.
fn resident(opts: &mut pgr_driver::opts::Options, sock: &Path) {
    opts.resident = true;
    opts.resident_socket = Some(sock.display().to_string());
}

fn strict_errors(path: &Path) -> Vec<String> {
    let bytes = std::fs::read(path).unwrap();
    let opts = pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    pgr_verify::verify(&bytes, &opts)
        .issues
        .iter()
        .filter(|i| i.severity == pgr_verify::Severity::Error)
        .map(|i| i.message.clone())
        .collect()
}

/// One in-process daemon on a test-unique socket.
fn start_daemon(tag: &str) -> PathBuf {
    let sock = std::env::temp_dir().join(format!("pgr-m83-reloc-{tag}.sock"));
    let _ = std::fs::remove_file(&sock);
    let owned = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(120));
    });
    for _ in 0..500 {
        if UnixStream::connect(&sock).is_ok() {
            return sock;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("daemon socket {} never came up", sock.display());
}

/// The served parity: a resident `-r` link plans the object the cold `-r`
/// link plans — one walk, either lane, the same bytes. The header names
/// `MH_OBJECT` (the served shape is the relocatable one, not a segmented
/// image), and the object carries no signature (the emit's contract).
#[test]
fn the_resident_relocatable_link_matches_the_cold_bytes() {
    let dir = std::env::temp_dir().join(format!("pgr_m83_parity_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let a = main_object(&dir);
    let b = greet_object(&dir);
    let sock = start_daemon("parity");

    let mut cold = reloc_opts(&dir.join("cold.o"), &a, &b);
    run(&cold).expect("the cold relocatable link runs");
    let cold_bytes = std::fs::read(dir.join("cold.o")).unwrap();

    resident(&mut cold, &sock);
    cold.output = dir.join("warm.o").display().to_string();
    let outcome = run(&cold).expect("the resident relocatable link runs");
    assert_eq!(
        outcome.transport,
        Some(pgr_daemon::Transport::Full),
        "the session served the object (the one-shot rides no transport)"
    );
    assert!(
        outcome.entryoff == 0 && outcome.fixup_slots == 0,
        "the object shape reports no entry, no fixup slots"
    );
    let warm_bytes = std::fs::read(dir.join("warm.o")).unwrap();
    assert_eq!(
        cold_bytes, warm_bytes,
        "one walk — either lane, the same object bytes"
    );
    let hdr = pgr_format::MachHeader64::parse(&warm_bytes).expect("the header parses");
    assert_eq!(
        hdr.filetype,
        pgr_format::consts::MH_OBJECT,
        "the served shape is the relocatable one"
    );
    assert!(
        strict_errors(&dir.join("warm.o")).is_empty(),
        "the served object verifies"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

/// The fallback: a resident attempt that stands down (no daemon answers)
/// hands over to the one-shot relocatable link, whose own walk produces
/// the same bytes the served shape would have.
#[test]
fn the_fallback_relocates_the_one_shot_link() {
    let dir = std::env::temp_dir().join(format!("pgr_m83_fallback_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let a = main_object(&dir);
    let b = greet_object(&dir);
    // A socket nothing answers: the resident attempt stands down and the
    // one-shot link produces the outcome.
    let dead = std::env::temp_dir().join(format!("pgr-m83-reloc-dead-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&dead);
    let mut opts = reloc_opts(&dir.join("warm.o"), &a, &b);
    resident(&mut opts, &dead);
    run(&opts).expect("the fallback relocatable link runs");
    let warm = std::fs::read(dir.join("warm.o")).unwrap();

    let cold = reloc_opts(&dir.join("cold.o"), &a, &b);
    run(&cold).expect("the one-shot relocatable link runs");
    assert_eq!(
        std::fs::read(dir.join("cold.o")).unwrap(),
        warm,
        "the fallback's object is the one-shot's walk"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Self-consumption: the served object is a real link input. Step one
/// (the resident `-r` link) leaves `_greet`'s reference open; step two
/// (the cold executable link over the served object) resolves it — the
/// M10 two-step gate through the served bytes.
#[test]
fn the_served_object_stays_a_link_input() {
    let dir = std::env::temp_dir().join(format!("pgr_m83_twostep_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let a = main_object(&dir);
    let b = greet_object(&dir);
    let sock = start_daemon("twostep");

    let mut opts = reloc_opts(&dir.join("out.o"), &a, &b);
    resident(&mut opts, &sock);
    let served = run(&opts).expect("the resident relocatable link runs");
    assert_eq!(
        served.transport,
        Some(pgr_daemon::Transport::Full),
        "the session served the object"
    );
    assert!(
        strict_errors(&dir.join("out.o")).is_empty(),
        "step-one output verifies"
    );

    // Step two: the served object links into an executable — the open
    // `_greet` resolves against the served object's own definition.
    let relink = pgr_driver::opts::Options {
        output: dir.join("exe").display().to_string(),
        inputs: vec![dir.join("out.o").display().to_string()],
        config: pgr_core::layout::LinkConfig {
            ident: "pgr-m83-twostep".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        ..pgr_driver::opts::Options::default()
    };
    run(&relink).expect("the two-step relink runs");
    assert!(
        strict_errors(&dir.join("exe")).is_empty(),
        "the executable over the served object verifies"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

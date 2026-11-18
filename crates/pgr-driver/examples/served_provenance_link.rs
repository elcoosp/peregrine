//! The resident lane's served provenance, runnable (M79): a link under
//! `-resident -why_export -why_load` — the request asks the session's
//! own full walk for the M56/M57 answers (wire v45), the reply's IMAGE
//! tail carries the rendered text verbatim (the M62 convention — the
//! wire never re-shapes the face the client prints), and the driver
//! prints the served answers beside the resident link exactly as the
//! cold lane prints its own. The fallback story stays honest: a resident
//! attempt that stands down hands over to the one-shot link, whose own
//! queries print the same rows — and the vacuous query is the session's
//! `ERROR`, the cue for that fallback, so the misspelling refuses with
//! the same message either lane.
//!
//! ```sh
//! cargo run -p pgr-driver --example served_provenance_link
//! ```

use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// main.o: `_main` ADRP+ADD loads `_msg`, BL `_greet` (the archive
/// member greet.o defines it — the lazy pull's question `-why_load`
/// answers).
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

/// The resident link's argv over the corpus.
fn resident_argv(dir: &std::path::Path, sock: &std::path::Path) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<String> = [
        "-o".to_string(),
        dir.join("hello").display().to_string(),
        "-resident".to_string(),
        "-resident_socket".to_string(),
        sock.display().to_string(),
    ]
    .to_vec();
    argv.extend(std::env::args().skip(1));
    argv.iter().map(std::ffi::OsString::from).collect()
}

fn main() {
    // The demo runs unobserved by default; `PGR_TRACING=1` installs the
    // house tracing subscriber (the workspace convention).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt::init();
    }

    let dir = std::env::temp_dir().join("pgr_example_served_provenance");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).expect("the object writes");
    let archive = dir.join("libgreet.a");
    let mut a = ArchiveBuilder::new("libgreet.a");
    a.add_member("greet.o", greet_object());
    std::fs::write(&archive, a.build()).expect("the archive writes");
    let sock: PathBuf = dir.join("demo.sock");
    start_daemon(&sock);

    // The served face: the queries ride the request, the session's own
    // Pass-2 product renders the answers, and the driver prints them
    // beside the resident link — the cold lane's rows, served warm.
    println!("== the served answers (the session's own renders) ==");
    let mut argv = resident_argv(&dir, &sock);
    for flag in ["-why_export", "_greet", "-why_load"] {
        argv.push(std::ffi::OsString::from(flag));
    }
    argv.push(main.display().to_string().into());
    argv.push(archive.display().to_string().into());
    let opts = pgr_driver::opts::parse(&argv).expect("the argv parses");
    let served = pgr_driver::run(&opts).expect("the resident link runs");
    println!(
        "== the link shipped ({} bytes, {:?}) ==",
        served.file_size, served.transport,
    );

    // The vacuous query: the session's ERROR is the fallback's cue, and
    // the one-shot lane's own query refuses with the misspelling named —
    // the same refusal either lane, never a silently empty answer.
    println!("== the vacuous query (through the fallback) ==");
    let mut argv = resident_argv(&dir, &sock);
    argv.extend(["-why_export".into(), "_nope".into()]);
    argv.push(main.display().to_string().into());
    argv.push(archive.display().to_string().into());
    match pgr_driver::opts::parse(&argv)
        .map_err(pgr_driver::DriverError::from)
        .and_then(|opts| pgr_driver::run(&opts))
    {
        Ok(_) => panic!("the vacuous query refuses the run"),
        Err(e) => println!("the run refused (exit 1): {e}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

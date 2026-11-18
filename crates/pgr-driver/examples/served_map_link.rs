//! The resident lane's served map, runnable (M80, wire v46): a link under
//! `-resident -map` — the request asks the session's own full walk for
//! the placed image's report, the reply's IMAGE tail carries the
//! rendered document verbatim (the M62 convention — the wire never
//! re-shapes), and the driver writes the served bytes to the `-map`
//! path exactly as the cold lane writes its own render. The parity gate
//! is the seam's own contract: the cold link's map and the served map
//! are byte-identical — one walk, one render, either lane. The fallback
//! story stays honest: a resident attempt that stands down hands over
//! to the one-shot link, whose own render writes the same document.
//!
//! ```sh
//! cargo run -p pgr-driver --example served_map_link
//! ```

use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// main.o: `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret (greet.o is
/// the second direct input and defines `_greet`).
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

/// greet.o: `_greet` body (a bare ret).
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

/// The link's argv over the corpus: the map ask beside the given lane.
fn argv(
    dir: &std::path::Path,
    sock: Option<&std::path::Path>,
    map: &Path,
) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<String> = vec![
        "-o".to_string(),
        dir.join("hello").display().to_string(),
        "-map".to_string(),
        map.display().to_string(),
    ];
    if let Some(sock) = sock {
        argv.push("-resident".to_string());
        argv.push("-resident_socket".to_string());
        argv.push(sock.display().to_string());
    }
    argv.iter().map(std::ffi::OsString::from).collect()
}

fn main() {
    // The demo runs unobserved by default; `PGR_TRACING=1` installs the
    // house tracing subscriber (the workspace convention).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt::init();
    }

    let dir = std::env::temp_dir().join("pgr_example_served_map");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).expect("the object writes");
    let greet = dir.join("greet.o");
    std::fs::write(&greet, greet_object()).expect("the object writes");
    let sock: PathBuf = dir.join("demo.sock");
    start_daemon(&sock);

    // The cold lane's own render: the reference document (the one-shot
    // `-map` contract, unchanged).
    let cold_map = dir.join("cold.map");
    let mut argv_cold = argv(&dir, None, &cold_map);
    argv_cold.push(main.clone().into_os_string());
    argv_cold.push(greet.clone().into_os_string());
    let opts = pgr_driver::opts::parse(&argv_cold).expect("the argv parses");
    pgr_driver::run(&opts).expect("the cold link runs");
    let cold = std::fs::read_to_string(&cold_map).expect("the cold map writes");
    println!("== the cold map ({} bytes) ==", cold.len());
    for line in cold.lines().take(4) {
        println!("    {line}");
    }

    // The served face: the session's own walk renders the placed image's
    // report, the tail carries it verbatim, the client writes the file —
    // byte-identical to the cold render (one walk, one render).
    let warm_map = dir.join("warm.map");
    let mut argv_warm = argv(&dir, Some(&sock), &warm_map);
    argv_warm.push(main.into_os_string());
    argv_warm.push(greet.into_os_string());
    let opts = pgr_driver::opts::parse(&argv_warm).expect("the argv parses");
    pgr_driver::run(&opts).expect("the resident link runs");
    let warm = std::fs::read_to_string(&warm_map).expect("the served map writes");
    println!("== the served map ({} bytes) ==", warm.len());
    assert_eq!(
        cold, warm,
        "one walk, one render — either lane, the same document"
    );
    println!("== the served document is the cold render, byte-for-byte ==");

    // The fallback: a socket nothing answers hands over to the one-shot
    // link, whose own render writes the same document.
    let dead = dir.join("dead.sock");
    let _ = std::fs::remove_file(&dead);
    let fallback_map = dir.join("fallback.map");
    let mut argv_fallback = argv(&dir, Some(&dead), &fallback_map);
    argv_fallback.push(dir.join("main.o").into_os_string());
    argv_fallback.push(dir.join("greet.o").into_os_string());
    let opts = pgr_driver::opts::parse(&argv_fallback).expect("the argv parses");
    pgr_driver::run(&opts).expect("the fallback link runs");
    let fallback = std::fs::read_to_string(&fallback_map).expect("the fallback map writes");
    assert_eq!(
        cold, fallback,
        "the fallback writes the one-shot's own render"
    );
    println!("== the fallback's map is the cold render too ==");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

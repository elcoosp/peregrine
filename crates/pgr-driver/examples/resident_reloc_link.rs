//! The resident lane's relocatable shape, runnable (M83): a link under
//! `-r -resident` — the session's walk runs the object path over the raw
//! blobs (`pgr_core::link_reloc`, the cold lane's own entry; the POI
//! cache is the segmented pipeline's optimization, the object path
//! re-parses) and `pgr_emit::build_object_image` assembles the
//! `MH_OBJECT` the reply carries verbatim. The parity gate is the
//! rung's own contract: the cold relocatable link and the resident
//! relocatable link plan byte-identical objects. The replay faces have
//! no object shape (no record, no tiles, no audit, no `-verify`, no
//! `-map` beside `-r` — the surface refuses the knobs, the wire refuses
//! the request), and a resident attempt that stands down hands over to
//! the one-shot relocatable link, whose own walk produces the same
//! bytes.
//!
//! ```sh
//! cargo run -p pgr-driver --example resident_reloc_link
//! ```

use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `hello_main.o`: `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret — an
/// open `_greet` the two-step gate resolves in step two.
fn hello_main() -> Vec<u8> {
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
    b.build().expect("the fixture object builds")
}

/// greet.o (never edited): `_greet`.
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

/// The relocatable link's argv: `-r`, the named lane flags.
fn argv(dir: &Path, resident: bool, obj: &Path) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<String> = vec![
        "-o".to_string(),
        dir.join("out.o").display().to_string(),
        "-r".to_string(),
    ];
    if resident {
        argv.push("-resident".to_string());
        argv.push("-resident_socket".to_string());
        argv.push(dir.join("demo.sock").display().to_string());
    }
    argv.push(dir.join("greet.o").display().to_string());
    argv.push(obj.display().to_string());
    argv.iter().map(std::ffi::OsString::from).collect()
}

fn main() {
    // The demo runs unobserved by default; `PGR_TRACING=1` installs the
    // house tracing subscriber (the workspace convention).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt::init();
    }

    let dir = std::env::temp_dir().join("pgr_example_resident_reloc");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let obj = dir.join("hello_main.o");
    std::fs::write(&obj, hello_main()).expect("the object writes");
    std::fs::write(dir.join("greet.o"), greet_object()).expect("the object writes");
    let sock: PathBuf = dir.join("demo.sock");
    start_daemon(&sock);

    // The cold relocatable link: the reference bytes (the object's open
    // `_greet` stays open — the object is a link input).
    let opts = pgr_driver::opts::parse(&argv(&dir, false, &obj)).expect("the cold argv parses");
    pgr_driver::run(&opts).expect("the cold relocatable link runs");
    let cold = std::fs::read(dir.join("out.o")).expect("the cold object reads");
    let hdr = pgr_format::MachHeader64::parse(&cold).expect("the header parses");
    println!(
        "== the cold relocatable link ({} bytes, filetype {}) ==",
        cold.len(),
        hdr.filetype
    );

    // The resident relocatable link: the session's walk runs the object
    // path over the raw blobs — the bytes the reply carries are the cold
    // lane's.
    let opts = pgr_driver::opts::parse(&argv(&dir, true, &obj)).expect("the resident argv parses");
    let outcome = pgr_driver::run(&opts).expect("the resident relocatable link runs");
    let warm = std::fs::read(dir.join("out.o")).expect("the served object reads");
    println!(
        "== the resident relocatable link ({} bytes, transport {:?}) ==",
        warm.len(),
        outcome.transport
    );
    assert_eq!(cold, warm, "one walk — either lane, the same object bytes");
    println!("== the served object is the cold walk, byte-for-byte ==");

    // Self-consumption: the served object links into an executable — the
    // open `_greet` resolves against the served object's own definition.
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("exe").display().to_string(),
        dir.join("out.o").display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let relink = pgr_driver::opts::parse(&argv).expect("the two-step argv parses");
    pgr_driver::run(&relink).expect("the two-step relink runs");
    let exe = std::fs::read(dir.join("exe")).expect("the executable reads");
    let hdr = pgr_format::MachHeader64::parse(&exe).expect("the header parses");
    println!(
        "== the served object relinks into an executable (filetype {}) ==",
        hdr.filetype
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

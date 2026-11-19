//! The fusion ladder's served-map consumer example (M87): the capture
//! link records the state, one function's body changes, and the
//! map-bearing fusion relink rides the resident session — the daemon's
//! ladder runs the full Passes 1–3 over its warm POIs, renders its own
//! Pass-3 product (`pgr_core::map::build_link_map`, the cold lane's own
//! pure function), and the reply's v46 tail carries the document
//! verbatim; the client writes the served bytes to the `-map` path
//! exactly as the in-process ladder writes its own. Either lane, one
//! walk, one document.
//!
//! Run: `cargo run -p pgr-driver --example fusion_map_link`

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::time::Duration;

/// hello.o: `_main` over 16 KiB of `__text` (the tier-1 edit shape),
/// a BL `_greet` site — the link the ladder records and patches. The
/// `flip` variant rewrites eight words mid-text: the edit the relink
/// patches.
fn hello(flip: bool) -> Vec<u8> {
    let mut text = vec![0xD5u8, 0x03, 0x20, 0x1F]; // nop
    text.resize(16 * 1024, 0xD5);
    if flip {
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

/// greet.o: `_greet` — the linked definition.
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

/// Links `argv` (the corpus paths appended) through the driver's own
/// parse + run pair.
fn run(
    dir: &std::path::Path,
    out: &str,
    extra: &[&str],
) -> Result<pgr_driver::LinkOutcome, String> {
    let hello_path = dir.join("hello.o");
    let greet_path = dir.join("greet.o");
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join(out).as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    argv.push(hello_path.as_os_str().to_os_string());
    argv.push(greet_path.as_os_str().to_os_string());
    let parsed = opts::parse(&argv).map_err(|e| format!("{:?}", miette::Report::new(e)))?;
    pgr_driver::run(&parsed).map_err(|e| e.to_string())
}

/// Prints the map's segment rows (the served document the client wrote,
/// read back line by line).
fn print_map(path: &std::path::Path) {
    let text = std::fs::read_to_string(path).expect("the map exists");
    println!("-- {} --", path.display());
    let mut shown = 0;
    for line in text.lines() {
        if shown < 10 && !line.starts_with(' ') {
            println!("   {line}");
            shown += 1;
        }
    }
    println!("   … ({} bytes of map)", text.len());
}

fn main() {
    // The resident session: one in-process daemon on a scratch socket
    // (the binary the example links; a real `pgrd` serves the same wire).
    let sock = std::env::temp_dir().join(format!("pgr_fusion_map_{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);
    let owned = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(60));
    });
    for _ in 0..500 {
        if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let dir = std::env::temp_dir().join(format!("pgr_fusion_map_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("hello.o"), hello(false)).unwrap();
    std::fs::write(dir.join("greet.o"), greet()).unwrap();
    let map = dir.join("hello.map");
    let map_arg = map.display().to_string();
    let sock_arg = sock.display().to_string();

    // 1. The capture link: the ladder's first rung records the state
    //    beside the output (a full link through the session).
    println!("== the capture link (the record is written) ==");
    run(
        &dir,
        "hello",
        &["-incremental", "-resident", "-resident_socket", &sock_arg],
    )
    .expect("the capture link runs");

    // 2. The edit: the same object, eight words flipped mid-text — the
    //    tier-1 edit the anchored relink patches in place.
    std::fs::write(dir.join("hello.o"), hello(true)).unwrap();

    // 3. The map-bearing fusion relink: the session's ladder runs the
    //    full Passes 1–3 over its warm POIs, renders its own Pass-3
    //    product, and the reply's v46 tail carries the document verbatim
    //    — the client writes the served bytes (the daemon never touches
    //    the filesystem). A dead server's refusal is the stand-down the
    //    in-process ladder answers; the transport names the lane.
    println!("== the map-bearing fusion relink: -resident -incremental -map ==");
    let outcome = run(
        &dir,
        "hello",
        &[
            "-incremental",
            "-resident",
            "-resident_socket",
            &sock_arg,
            "-map",
            &map_arg,
        ],
    )
    .expect("the fusion relink runs");
    println!("transport: {:?}", outcome.transport);
    let patch = outcome.patch.expect("the relink reports its patch");
    println!(
        "outcome: {} of {} tiles patched ({} bytes, untouched={})",
        patch.dirty_tiles, patch.total_tiles, patch.bytes_patched, patch.untouched
    );
    print_map(&map);

    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
}

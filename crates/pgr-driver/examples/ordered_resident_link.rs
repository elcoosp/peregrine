//! The resident lane's ordered link, runnable (M81, wire v47): a link
//! under `-resident -order_file` — the rank table rides the request's
//! config tail (the entries in rank order, each with its scope and its
//! diagnostics line), and the session's own walk ranks the entries the
//! client named. The parity gate is the rung's own contract: the cold
//! ordered link and the resident ordered link plan byte-identical
//! images — one table, one walk, either lane. The fallback story stays
//! honest: a resident attempt that stands down hands over to the
//! one-shot link, whose own table ranks the same rows.
//!
//! ```sh
//! cargo run -p pgr-driver --example ordered_resident_link
//! ```

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// hello.o with `MH_SUBSECTIONS_VIA_SYMBOLS`: four functions (one ret
/// each) plus `_main`, so the order file has real atoms to rank.
fn hello_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(4),
        vec![],
    ));
    b.add_section(ObjectSection::cstring("hi\n"));
    for (i, name) in ["_main", "_second", "_third", "_tail"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*name).into(),
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

/// The ordered link's argv: the rank table beside the given lane.
fn argv(
    dir: &std::path::Path,
    sock: Option<&std::path::Path>,
    obj: &Path,
) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<String> = vec![
        "-o".to_string(),
        dir.join(if sock.is_some() { "warm" } else { "cold" })
            .display()
            .to_string(),
        "-order_file".to_string(),
        dir.join("order.txt").display().to_string(),
    ];
    if let Some(sock) = sock {
        argv.push("-resident".to_string());
        argv.push("-resident_socket".to_string());
        argv.push(sock.display().to_string());
    }
    argv.push(obj.display().to_string());
    argv.iter().map(std::ffi::OsString::from).collect()
}

fn main() {
    // The demo runs unobserved by default; `PGR_TRACING=1` installs the
    // house tracing subscriber (the workspace convention).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt::init();
    }

    let dir = std::env::temp_dir().join("pgr_example_ordered_resident");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).expect("the object writes");
    // The rank table: `_tail` leads, `_second` follows (the unranked
    // rows keep their canonical order behind them).
    let order = dir.join("order.txt");
    std::fs::write(&order, "_tail\n_second\n").expect("the order file writes");
    let sock: PathBuf = dir.join("demo.sock");
    start_daemon(&sock);

    // The cold ordered link: the reference bytes (the ranked symbol
    // leads `__text`).
    let opts = pgr_driver::opts::parse(&argv(&dir, None, &obj)).expect("the argv parses");
    pgr_driver::run(&opts).expect("the cold ordered link runs");
    let cold = std::fs::read(dir.join("cold")).expect("the cold image reads");
    println!("== the cold ordered link ({} bytes) ==", cold.len());

    // The resident ordered link: the table rides the config tail, the
    // session's own walk ranks the entries the client named — the bytes
    // the reply carries are the cold lane's.
    let opts = pgr_driver::opts::parse(&argv(&dir, Some(&sock), &obj)).expect("the argv parses");
    pgr_driver::run(&opts).expect("the resident ordered link runs");
    let warm = std::fs::read(dir.join("warm")).expect("the served image reads");
    println!("== the resident ordered link ({} bytes) ==", warm.len());
    assert_eq!(
        cold, warm,
        "one table, one walk — either lane, the same bytes"
    );
    println!("== the served image is the cold plan, byte-for-byte ==");

    // The ranked order holds in the bytes (the symtab lists externals
    // in placed order — `_tail` leads `__text`).
    let hdr = pgr_format::MachHeader64::parse(&cold).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        &cold,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut text_addr = 0u64;
    let mut externs: Vec<(String, u64)> = Vec::new();
    while let Some(cmd) = it.next_command().expect("the commands iterate") {
        match cmd.kind {
            pgr_format::LoadCommandKind::Segment64 => {
                let seg =
                    pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
                for s in seg
                    .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                    .expect("the sections walk")
                {
                    if s.name() == Ok("__text") {
                        text_addr = s.addr;
                    }
                }
            }
            pgr_format::LoadCommandKind::Symtab => {
                let st = pgr_format::SymtabCommand::parse(cmd.bytes, 0).expect("the symtab parses");
                let strtab = &cold[st.stroff as usize..st.stroff as usize + st.strsize as usize];
                for i in 0..st.nsyms {
                    let nl: pgr_format::symtab::Nlist64 =
                        pgr_format::cursor::pod_read_unaligned_at(
                            &cold,
                            st.symoff as usize + i as usize * 16,
                        )
                        .expect("the symbol reads");
                    if nl.n_type & pgr_format::consts::N_EXT != 0
                        && nl.n_type & pgr_format::consts::N_TYPE == pgr_format::consts::N_SECT
                        && nl.n_value >= text_addr
                    {
                        let name = &strtab[nl.n_strx as usize..];
                        let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
                        externs.push((String::from_utf8_lossy(name).into_owned(), nl.n_value));
                    }
                }
            }
            _ => {}
        }
    }
    externs.sort_by_key(|(_, v)| *v);
    let placed: Vec<&str> = externs.iter().map(|(n, _)| n.as_str()).collect();
    println!("== the placed __text externals: {} ==", placed.join(", "));
    assert_eq!(placed.first(), Some(&"_tail"), "the ranked symbol leads");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

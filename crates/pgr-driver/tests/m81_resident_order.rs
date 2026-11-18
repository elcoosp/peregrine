//! M81 — the wire carries the order-file rank table: the M11 lane
//! contract (`-order_file` reads the driver-side Pass-3 input, so the
//! resident lane refused it — the surface's own verdict named the wire
//! config "not carrying the rank table") flips to service the M79/M80
//! way: the table is config, the config crosses the wire, and the
//! session's warm pipeline *is* the walk that consumes it. The rank
//! table rides the request's config tail now (v47 — the entries in
//! rank order, each with its scope and its diagnostics line; a table
//! the constructor refuses is a malformed request, never a silently
//! misread table), so `-resident -order_file` links with the same
//! layout the cold lane plans — the parity gate is the rung's own
//! contract (identical bytes, either lane). The fallback story stays
//! honest: a resident attempt that stands down hands over to the
//! one-shot link, whose own table ranks the same rows. The unmatched-name
//! advisory stays lane-local (the cold lane's stderr face — the same
//! shape the export-filter advisory rides; the product is the bytes,
//! and the bytes are what cross).
//!
//! Gate matrix:
//! * the served parity — a resident ordered link plans the image the
//!   cold ordered link plans (byte-identical; the ranked symbol leads
//!   `__text` in both);
//! * the fallback — a resident attempt that stands down hands over to
//!   the one-shot link, whose own table ranks the same rows;
//! * the advisory — an unmatched rank name warns on the cold lane (the
//!   lane-local face) and never blocks the link.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m81_order").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// hello.o with `MH_SUBSECTIONS_VIA_SYMBOLS`: four functions (one ret
/// each) plus `_main`, so the order file has real atoms to rank.
fn hello_o(dir: &std::path::Path) -> PathBuf {
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
    let path = dir.join("hello.o");
    std::fs::write(&path, b.build().expect("the fixture object builds"))
        .expect("the object writes");
    path
}

fn order_file(dir: &std::path::Path, text: &str) -> PathBuf {
    let path = dir.join("order.txt");
    std::fs::write(&path, text).expect("the order file writes");
    path
}

/// Unique socket path for one test.
fn socket_for(test: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pgr-m81-{}-{test}.sock", std::process::id()))
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

/// Runs the built `pgr` binary with `extra` args and returns (exit ok,
/// stdout, stderr).
fn run_pgr(out: &Path, obj: &Path, extra: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_pgr"))
        .arg("-o")
        .arg(out)
        .args(extra)
        .arg(obj)
        .output()
        .expect("the pgr child runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The `__text`-defined externals in placed (address) order — the rows
/// the rank table rearranges.
fn text_externs(bytes: &[u8]) -> Vec<(String, u64)> {
    let hdr = pgr_format::MachHeader64::parse(bytes).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut text_addr = 0u64;
    while let Some(cmd) = it.next_command().expect("the commands iterate") {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
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
    }
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut externs: Vec<(String, u64)> = Vec::new();
    while let Some(cmd) = it.next_command().expect("the commands iterate") {
        if let pgr_format::LoadCommandKind::Symtab = cmd.kind {
            let st = pgr_format::SymtabCommand::parse(cmd.bytes, 0).expect("the symtab parses");
            let strtab = &bytes[st.stroff as usize..st.stroff as usize + st.strsize as usize];
            for i in 0..st.nsyms {
                let nl: pgr_format::symtab::Nlist64 = pgr_format::cursor::pod_read_unaligned_at(
                    bytes,
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
    }
    externs
}

/// The ranked symbol leads `__text` (the symtab lists externals in
/// placed order — the rows the table rearranged).
fn assert_ranked(bytes: &[u8]) {
    let externs = text_externs(bytes);
    let value_of = |name: &str| {
        externs
            .iter()
            .find(|(n, _)| n == name)
            .map_or_else(|| panic!("{name} in the symtab: {externs:?}"), |(_, v)| *v)
    };
    assert!(
        value_of("_tail") < value_of("_main"),
        "the ranked symbol leads __text: {externs:?}"
    );
}

#[test]
fn the_resident_ordered_link_matches_the_cold_bytes() {
    let dir = scratch("parity");
    let obj = hello_o(&dir);
    let order = order_file(&dir, "_tail\n_second\n");
    let sock = socket_for("parity");
    start_daemon(&sock);
    // The cold ordered link: the reference bytes.
    let (ok, _stdout, stderr) = run_pgr(
        &dir.join("cold"),
        &obj,
        &["-order_file", order.to_str().unwrap()],
    );
    assert!(ok, "the cold ordered link runs: {stderr}");
    let cold = std::fs::read(dir.join("cold")).expect("the cold image reads");
    assert_ranked(&cold);
    // The resident ordered link: the table rides the config tail, the
    // session's own walk ranks the entries the client named — the bytes
    // the reply carries are the cold lane's.
    let (ok, _stdout, stderr) = run_pgr(
        &dir.join("warm"),
        &obj,
        &[
            "-order_file",
            order.to_str().unwrap(),
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
        ],
    );
    assert!(ok, "the resident ordered link runs: {stderr}");
    let warm = std::fs::read(dir.join("warm")).expect("the served image reads");
    assert_eq!(
        cold, warm,
        "one table, one walk — either lane, the same bytes"
    );
    assert_ranked(&warm);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn the_fallback_orders_the_one_shot_link() {
    let dir = scratch("fallback");
    let obj = hello_o(&dir);
    let order = order_file(&dir, "_tail\n_second\n");
    // A socket nothing answers: the resident attempt stands down and
    // the one-shot link (whose own table ranks) produces the outcome.
    let dead = socket_for("fallback");
    let _ = std::fs::remove_file(&dead);
    let (ok, _stdout, stderr) = run_pgr(
        &dir.join("warm"),
        &obj,
        &[
            "-order_file",
            order.to_str().unwrap(),
            "-resident",
            "-resident_socket",
            &dead.display().to_string(),
        ],
    );
    assert!(ok, "the fallback link runs: {stderr}");
    let warm = std::fs::read(dir.join("warm")).expect("the fallback image reads");
    assert_ranked(&warm);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unmatched_rank_name_warns_and_links() {
    let dir = scratch("advisory");
    let obj = hello_o(&dir);
    let order = order_file(&dir, "_nope\n");
    // The cold lane's advisory: the typo is named, the link is correct
    // (the layout plans what the inputs define — ld64 warns the same
    // way on order files). The product is the bytes; the warning is
    // the lane-local stderr face.
    let (ok, _stdout, stderr) = run_pgr(
        &dir.join("out"),
        &obj,
        &["-order_file", order.to_str().unwrap()],
    );
    assert!(ok, "the unmatched name never blocks the link: {stderr}");
    assert!(
        stderr.contains("_nope"),
        "the advisory names the misspelling: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

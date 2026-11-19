//! M90 — the `-sectorder` driver surface: ld64's per-section order flag
//! (`-sectorder <segment> <section> <file>`) rides the M11 rank seam the
//! classification names. The rank-append face reads its file at link
//! time (the M11 convention), records it in the dependency record (M60)
//! and composes with `-order_file` in command-line order (ld64 appends
//! every order source into one global rank table — repeated
//! `-order_file`s included, the last-wins read the surface carried is
//! retired with the seam); the `__TEXT,__literal*` face is the warned
//! no-op (the file is never read — a missing path links); the
//! `__TEXT,__cstring` face is the literal ordering, refused this rung
//! with the fix named (M91 hands it its own rung). `-r` refuses the
//! rank surface (no segment layout exists to rank) — the M11 shape; the
//! resident lane serves the composed table the way it serves the rank
//! table since M81 (the config tail carries it; the session's own walk
//! ranks).
//!
//! Gate matrix:
//! * the rank-append link — verifies strict, the ranked symbol leads
//!   `__text` (the M11 assertion, the sectorder file's rows);
//! * the command-line composition — `-order_file` then `-sectorder`
//!   ranks in flag order; a repeated `-order_file` composes (never
//!   last-wins);
//! * the literal no-op — the warned face links without reading its file;
//! * the refusals — `-r` names the shape conflict, a malformed file
//!   names its line, a missing file is an io refusal;
//! * the served parity — `-resident -sectorder` plans the cold lane's
//!   bytes (one composed table, one walk, either lane).

use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m90_sectorder").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

fn args(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

/// hello.o with `MH_SUBSECTIONS_VIA_SYMBOLS`: four functions (one ret
/// each) plus `_main`, so the order sources have real atoms to rank.
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

fn order_file(dir: &std::path::Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).expect("the order file writes");
    path
}

/// Unique socket path for one test.
fn socket_for(test: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pgr-m90-{}-{test}.sock", std::process::id()))
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

/// The values of `names` in the symtab, asserted ascending (the placed
/// order the ranks rearranged).
fn assert_lead_in_order(bytes: &[u8], names: &[&str]) {
    let externs = text_externs(bytes);
    let value_of = |name: &str| {
        externs
            .iter()
            .find(|(n, _)| n == name)
            .map_or_else(|| panic!("{name} in the symtab: {externs:?}"), |(_, v)| *v)
    };
    for pair in names.windows(2) {
        let (before, after) = (pair[0], pair[1]);
        assert!(
            value_of(before) < value_of(after),
            "{before} places before {after}: {externs:?}"
        );
    }
}

fn strict_ok(bytes: &[u8]) -> bool {
    verify(
        bytes,
        &VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    )
    .is_ok(&VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    })
}

#[test]
fn the_sectorder_link_ranks_and_verifies() {
    let dir = scratch("rank");
    let obj = hello_o(&dir);
    let order = order_file(&dir, "sect.txt", "_tail\n_second\n");
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        "-sectorder",
        "__TEXT",
        "__text",
        order.to_str().unwrap(),
        obj.to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the sectorder argv parses");
    let outcome = pgr_driver::run(&o).expect("the sectorder link runs");
    assert!(outcome.file_size > 0);
    let bytes = std::fs::read(&out).expect("the image reads");
    assert!(
        strict_ok(&bytes),
        "the sectorder image verifies strict: {:?}",
        verify(
            &bytes,
            &VerifyOptions {
                strict_warnings: true,
                skip_hash_recompute: false,
            }
        )
        .issues
    );
    assert_lead_in_order(&bytes, &["_tail", "_second", "_main"]);
}

#[test]
fn the_composition_ranks_in_command_line_order() {
    let dir = scratch("compose");
    let obj = hello_o(&dir);
    let first = order_file(&dir, "order.txt", "_second\n");
    let second = order_file(&dir, "sect.txt", "_tail\n");
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        "-order_file",
        first.to_str().unwrap(),
        "-sectorder",
        "__TEXT",
        "__text",
        second.to_str().unwrap(),
        obj.to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the composed argv parses");
    pgr_driver::run(&o).expect("the composed link runs");
    let bytes = std::fs::read(&out).expect("the image reads");
    // The `-order_file` ranks first (its flag parsed first), the
    // sectorder's rows follow — one table, command-line order.
    assert_lead_in_order(&bytes, &["_second", "_tail", "_main"]);
}

#[test]
fn a_repeated_order_file_composes() {
    let dir = scratch("repeat");
    let obj = hello_o(&dir);
    let first = order_file(&dir, "a.txt", "_second\n");
    let second = order_file(&dir, "b.txt", "_tail\n");
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        "-order_file",
        first.to_str().unwrap(),
        "-order_file",
        second.to_str().unwrap(),
        obj.to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the repeated argv parses");
    pgr_driver::run(&o).expect("the composed link runs");
    let bytes = std::fs::read(&out).expect("the image reads");
    assert_lead_in_order(&bytes, &["_second", "_tail", "_main"]);
}

#[test]
fn the_literal_face_warns_and_never_reads_its_file() {
    let dir = scratch("literal");
    let obj = hello_o(&dir);
    let out = dir.join("hello");
    // ld64's literal face warns and ranks nothing — the file is never
    // opened, so a missing path cannot fail the link.
    let (ok, _stdout, stderr) = run_pgr(
        &out,
        &obj,
        &[
            "-sectorder",
            "__TEXT",
            "__literal4",
            dir.join("never.txt").to_str().unwrap(),
        ],
    );
    assert!(
        ok,
        "the literal face links (the file is never read): {stderr}"
    );
    assert!(
        stderr.contains("sorting of __literal"),
        "the ld64 warning wording rides the face: {stderr}"
    );
}

#[test]
fn the_rank_surface_refuses_the_relocatable_output() {
    let dir = scratch("reloc");
    let obj = hello_o(&dir);
    let order = order_file(&dir, "sect.txt", "_tail\n");
    let argv = args(&[
        "-o",
        "out.o",
        "-r",
        "-sectorder",
        "__TEXT",
        "__text",
        order.to_str().unwrap(),
        obj.to_str().unwrap(),
    ]);
    let err = opts::parse(&argv).unwrap_err();
    assert!(err.to_string().contains("no segment layout"), "{err}");
}

#[test]
fn a_malformed_sectorder_file_names_its_line() {
    let dir = scratch("malformed");
    let obj = hello_o(&dir);
    let order = order_file(&dir, "sect.txt", "_tail\na:b:c\n");
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        "-sectorder",
        "__TEXT",
        "__text",
        order.to_str().unwrap(),
        obj.to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the argv parses (the file is read at link time)");
    let err = pgr_driver::run(&o).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("line 2"), "{text}");
    assert!(text.contains("colons"), "{text}");
}

#[test]
fn a_missing_sectorder_file_is_an_io_refusal() {
    let dir = scratch("missing");
    let obj = hello_o(&dir);
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        "-sectorder",
        "__TEXT",
        "__text",
        dir.join("nowhere.txt").to_str().unwrap(),
        obj.to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the argv parses");
    let err = pgr_driver::run(&o).unwrap_err();
    assert!(err.to_string().contains("nowhere.txt"), "{err}");
}

#[test]
fn the_resident_sectorder_link_matches_the_cold_bytes() {
    let dir = scratch("parity");
    let obj = hello_o(&dir);
    let order = order_file(&dir, "sect.txt", "_tail\n_second\n");
    let sock = socket_for("parity");
    start_daemon(&sock);
    let cold_path = dir.join("cold");
    let (ok, _stdout, stderr) = run_pgr(
        &cold_path,
        &obj,
        &["-sectorder", "__TEXT", "__text", order.to_str().unwrap()],
    );
    assert!(ok, "the cold sectorder link runs: {stderr}");
    let cold = std::fs::read(&cold_path).expect("the cold image reads");
    // The resident lane: the composed table rides the config tail (the
    // M81 carriage — one table, the session's own walk ranks it).
    let warm_path = dir.join("warm");
    let (ok, _stdout, stderr) = run_pgr(
        &warm_path,
        &obj,
        &[
            "-sectorder",
            "__TEXT",
            "__text",
            order.to_str().unwrap(),
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
        ],
    );
    assert!(ok, "the resident sectorder link runs: {stderr}");
    let warm = std::fs::read(&warm_path).expect("the served image reads");
    assert_eq!(
        cold, warm,
        "one table, one walk — either lane, the same bytes"
    );
    assert_lead_in_order(&warm, &["_tail", "_second", "_main"]);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

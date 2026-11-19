//! M91 — the `-sectorder __TEXT __cstring` driver surface: the cstring
//! face serves (the M90 rung's refusal retires). The file's escape-decoded
//! literal contents rank the `__cstring` sections (the D4 canonical
//! instances sort by content rank), the image verifies strict, the
//! advisory warns for entries that name no placed literal, a duplicate
//! rank refuses with both lines, a missing file is an io refusal, and
//! the resident lane serves the table (wire v48 — the session's own walk
//! ranks, the bytes the reply carries the cold lane's).
//!
//! Gate matrix:
//! * the ranked link — the placed `__cstring` bytes carry the literals
//!   in rank order (the image's own `__cstring` section read back);
//! * the refusals — a duplicate literal names both lines, a missing
//!   file names its path;
//! * the advisory — an unmatched literal warns and links;
//! * the served parity — `-resident -sectorder __TEXT __cstring` plans
//!   the cold lane's bytes (one table, one walk, either lane).

use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m91_cstring").join(format!(
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

/// hello.o: `_main` over a small `__text`, `__cstring` carrying the
/// named literals (one NUL-terminated atom each).
fn hello_o(dir: &std::path::Path, literals: &[&str]) -> PathBuf {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    let mut data = Vec::new();
    for literal in literals {
        data.extend_from_slice(literal.as_bytes());
        data.push(0);
    }
    b.add_section(ObjectSection {
        name: "__cstring".into(),
        segment: "__TEXT".into(),
        align_log2: 0,
        flags: pgr_format::consts::S_CSTRING_LITERALS,
        data,
        relocs: Vec::new(),
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
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

fn socket_for(test: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pgr-m91-{}-{test}.sock", std::process::id()))
}

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

/// The placed `__cstring` bytes of the image as the literal list.
fn placed_literals(bytes: &[u8]) -> Vec<String> {
    let hdr = pgr_format::MachHeader64::parse(bytes).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut sect = None;
    while let Some(cmd) = it.next_command().expect("the commands iterate") {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            for s in seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .expect("the sections walk")
            {
                if s.name() == Ok("__cstring") {
                    sect = Some((s.addr, s.offset, s.size));
                }
            }
        }
    }
    let (_addr, off, size) = sect.expect("the cstring section places");
    let raw = &bytes[off..off + usize::from(size)];
    raw.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

fn strict_ok(bytes: &[u8]) -> bool {
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    verify(bytes, &opts).is_ok(&opts)
}

#[test]
fn the_cstring_ordered_link_ranks_and_verifies() {
    let dir = scratch("rank");
    let obj = hello_o(&dir, &["alpha\n", "beta", "shared", "delta"]);
    let order = order_file(&dir, "lit.txt", "delta\nbeta\n");
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        "-sectorder",
        "__TEXT",
        "__cstring",
        order.to_str().unwrap(),
        obj.to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the cstring argv parses");
    pgr_driver::run(&o).expect("the cstring link runs");
    let bytes = std::fs::read(&out).expect("the image reads");
    assert!(
        strict_ok(&bytes),
        "the cstring-ordered image verifies strict"
    );
    let placed = placed_literals(&bytes);
    assert_eq!(
        placed[..2],
        ["delta", "beta"],
        "the ranked literals lead in rank order: {placed:?}"
    );
}

#[test]
fn a_duplicate_cstring_rank_refuses_with_both_lines() {
    let dir = scratch("dup");
    let obj = hello_o(&dir, &["alpha", "beta"]);
    let order = order_file(&dir, "lit.txt", "alpha\nbeta\nalpha\n");
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        "-sectorder",
        "__TEXT",
        "__cstring",
        order.to_str().unwrap(),
        obj.to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the argv parses (the file is read at link time)");
    let err = pgr_driver::run(&o).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("already ranked"), "{text}");
    assert!(text.contains("line 3"), "{text}");
}

#[test]
fn a_missing_cstring_file_is_an_io_refusal() {
    let dir = scratch("missing");
    let obj = hello_o(&dir, &["alpha"]);
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        "-sectorder",
        "__TEXT",
        "__cstring",
        dir.join("nowhere.txt").to_str().unwrap(),
        obj.to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the argv parses");
    let err = pgr_driver::run(&o).unwrap_err();
    assert!(err.to_string().contains("nowhere.txt"), "{err}");
}

#[test]
fn an_unmatched_cstring_rank_warns_and_links() {
    let dir = scratch("advisory");
    let obj = hello_o(&dir, &["alpha"]);
    let order = order_file(&dir, "lit.txt", "nomatch\nalpha\n");
    let out = dir.join("hello");
    let (ok, _stdout, stderr) = run_pgr(
        &out,
        &obj,
        &["-sectorder", "__TEXT", "__cstring", order.to_str().unwrap()],
    );
    assert!(ok, "the advisory never blocks the link: {stderr}");
    assert!(
        stderr.contains("not matched by any input"),
        "the unmatched literal warns: {stderr}"
    );
}

#[test]
fn the_resident_cstring_link_matches_the_cold_bytes() {
    let dir = scratch("parity");
    let obj = hello_o(&dir, &["alpha\n", "beta", "shared", "delta"]);
    let order = order_file(&dir, "lit.txt", "delta\nshared\n");
    let sock = socket_for("parity");
    start_daemon(&sock);
    let cold_path = dir.join("cold");
    let (ok, _stdout, stderr) = run_pgr(
        &cold_path,
        &obj,
        &["-sectorder", "__TEXT", "__cstring", order.to_str().unwrap()],
    );
    assert!(ok, "the cold cstring link runs: {stderr}");
    let cold = std::fs::read(&cold_path).expect("the cold image reads");
    let warm_path = dir.join("warm");
    let (ok, _stdout, stderr) = run_pgr(
        &warm_path,
        &obj,
        &[
            "-sectorder",
            "__TEXT",
            "__cstring",
            order.to_str().unwrap(),
            "-resident",
            "-resident_socket",
            &sock.display().to_string(),
        ],
    );
    assert!(ok, "the resident cstring link runs: {stderr}");
    let warm = std::fs::read(&warm_path).expect("the served image reads");
    assert_eq!(
        cold, warm,
        "one table, one walk — either lane, the same bytes"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

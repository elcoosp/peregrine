//! M11 rung 1 — the `-order_file` driver surface: the flag parses, the
//! rank table rides the link, the output verifies strict with the ranked
//! symbol first in `__text`, and the combinations that cannot carry the
//! rank table refuse with the fix in the message (`-r`, `-resident`).
//! A malformed order file refuses with its line; a missing file is an
//! io error, never a silent drop.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m11_order").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn args(items: &[&str]) -> Vec<OsString> {
    items.iter().map(|s| OsString::from(*s)).collect()
}

/// hello.o with `MH_SUBSECTIONS_VIA_SYMBOLS`: three functions (one ret
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
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

fn order_file(dir: &std::path::Path, text: &str) -> PathBuf {
    let path = dir.join("order.txt");
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn the_ordered_link_verifies_and_ranks_the_symbol() {
    let dir = scratch("m11");
    let obj = hello_o(&dir);
    let order = order_file(&dir, "_tail\n_second\n");
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        obj.to_str().unwrap(),
        "-order_file",
        order.to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the ordered argv parses");
    let outcome = pgr_driver::run(&o).expect("the ordered link runs");
    assert!(outcome.file_size > 0);

    let bytes = std::fs::read(&out).unwrap();
    let report = verify(
        &bytes,
        &VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    assert!(
        report.is_ok(&VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false
        }),
        "the ordered image verifies strict: {:#?}",
        report.issues
    );

    // The symtab's first-defined extern is the ranked `_tail`: the rank
    // moved the atom ahead of `_main` inside `__text` (the symtab lists
    // externals in address order — the placed order).
    let hdr = pgr_format::MachHeader64::parse(&bytes).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        &bytes,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .unwrap();
    let mut text_addr = 0u64;
    while let Some(cmd) = it.next_command().unwrap() {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).unwrap();
            for s in seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .unwrap()
            {
                if s.name() == Ok("__text") {
                    text_addr = s.addr;
                }
            }
        }
    }
    let mut it = pgr_format::LoadCommandIter::new(
        &bytes,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .unwrap();
    let mut externs: Vec<(String, u64)> = Vec::new();
    while let Some(cmd) = it.next_command().unwrap() {
        if let pgr_format::LoadCommandKind::Symtab = cmd.kind {
            let st = pgr_format::SymtabCommand::parse(cmd.bytes, 0).unwrap();
            for i in 0..st.nsyms {
                let nl: pgr_format::symtab::Nlist64 = pgr_format::cursor::pod_read_unaligned_at(
                    &bytes,
                    st.symoff as usize + i as usize * 16,
                )
                .unwrap();
                if nl.n_type & pgr_format::consts::N_EXT != 0
                    && nl.n_type & pgr_format::consts::N_TYPE == pgr_format::consts::N_SECT
                    && nl.n_value >= text_addr
                {
                    let strtab =
                        &bytes[st.stroff as usize..st.stroff as usize + st.strsize as usize];
                    let name = &strtab[nl.n_strx as usize..];
                    let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
                    externs.push((String::from_utf8_lossy(name).into_owned(), nl.n_value));
                }
            }
        }
    }
    let value_of = |name: &str| {
        externs
            .iter()
            .find(|(n, _)| n == name)
            .map_or_else(|| panic!("{name} in the symtab: {externs:?}"), |(_, v)| *v)
    };
    assert!(
        value_of("_tail") < value_of("_main"),
        "the ranked symbol lands below _main in __text: {externs:?}"
    );
    assert!(
        value_of("_tail") < value_of("_second"),
        "the entry-order ranks hold: {externs:?}"
    );
}

#[test]
fn an_order_file_refuses_the_combinations_that_cannot_carry_it() {
    let dir = scratch("m11");
    let obj = hello_o(&dir);
    let order = order_file(&dir, "_tail\n");

    // `-r`: no segment layout exists to rank.
    let argv = args(&[
        "-o",
        "out.o",
        "-r",
        obj.to_str().unwrap(),
        "-order_file",
        order.to_str().unwrap(),
    ]);
    let err = opts::parse(&argv).unwrap_err();
    assert!(err.to_string().contains("no segment layout"), "{err}");

    // `-resident`: the v6 wire config does not carry the rank table.
    let argv = args(&[
        "-o",
        "out",
        obj.to_str().unwrap(),
        "-order_file",
        order.to_str().unwrap(),
        "-resident",
    ]);
    let err = opts::parse(&argv).unwrap_err();
    assert!(err.to_string().contains("resident"), "{err}");
}

#[test]
fn a_malformed_order_file_names_its_line() {
    let dir = scratch("m11");
    let obj = hello_o(&dir);
    let order = order_file(&dir, "_tail\na:b:c\n");
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        obj.to_str().unwrap(),
        "-order_file",
        order.to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the argv parses (the file is read at link time)");
    let err = pgr_driver::run(&o).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("line 2"), "{text}");
    assert!(text.contains("colons"), "{text}");
}

#[test]
fn a_missing_order_file_is_an_io_refusal() {
    let dir = scratch("m11");
    let obj = hello_o(&dir);
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        obj.to_str().unwrap(),
        "-order_file",
        dir.join("nowhere.txt").to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the argv parses");
    let err = pgr_driver::run(&o).unwrap_err();
    assert!(err.to_string().contains("nowhere.txt"), "{err}");
}

#[test]
fn dead_strip_and_the_order_file_cooperate() {
    // Both knobs split atoms (the split flag is shared); the ranked
    // link strips the dead atoms and keeps the ranked order among the
    // live ones.
    let dir = scratch("m11");
    let obj = hello_o(&dir);
    let order = order_file(&dir, "_tail\n");
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        obj.to_str().unwrap(),
        "-dead_strip",
        "-order_file",
        order.to_str().unwrap(),
        "-u",
        "_third",
    ]);
    let o = opts::parse(&argv).expect("the argv parses");
    let outcome = pgr_driver::run(&o).expect("the stripped ordered link runs");
    assert!(outcome.file_size > 0);
    let bytes = std::fs::read(&out).unwrap();
    let report = verify(
        &bytes,
        &VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    assert!(
        report.is_ok(&VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false
        }),
        "the stripped ordered image verifies strict: {:#?}",
        report.issues
    );
}

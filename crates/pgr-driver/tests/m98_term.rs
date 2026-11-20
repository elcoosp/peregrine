//! M98 — the dylib terminator on the driver surface: `-term <symbol>`
//! rides the argv on a `-dylib` link (the SAME `LC_ROUTINES_64` M48's
//! `-init` composes into carries the resolved terminator beside it —
//! one command, two fields), the default plans no command, and the
//! knob refuses where `-init` refuses — executables, bundles and `-r`
//! — with the fix, plus the missing-argument refusal and the
//! verifier's `term_address` contract (a terminator naming no executable
//! mapping is the hostile shape).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m98_term").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// lib.o: `_my_init` (the initializer body), `_my_term` (the terminator
/// body) and `_api` (the exported surface), all `ret` bodies in one
/// `__text`.
fn lib_o(dir: &Path) -> PathBuf {
    let mut b = ObjectBuilder::new("lib.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![
            0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6,
        ], // ret; ret; ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_my_init".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_my_term".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_api".into(),
        section_index: text,
        value: 8,
        weak: false,
    });
    let path = dir.join("lib.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// Walks the image's load commands; returns `(count, init_address,
/// term_address)` over the `LC_ROUTINES` family.
fn routines_fields(image: &[u8]) -> (usize, u64, u64) {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut count = 0usize;
    let mut init = 0u64;
    let mut term = 0u64;
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if let pgr_format::LoadCommandKind::Routines = cmd.kind {
            count += 1;
            init = u64::from_le_bytes(
                cmd.bytes[8..16]
                    .try_into()
                    .expect("init_address rides byte 8"),
            );
            term = u64::from_le_bytes(
                cmd.bytes[16..24]
                    .try_into()
                    .expect("term_address rides byte 16"),
            );
        }
    }
    (count, init, term)
}

/// The byte offset of the first `LC_ROUTINES` command in the image (the
/// tamper gate patches `term_address` in place).
fn routines_offset(image: &[u8]) -> Option<usize> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if let pgr_format::LoadCommandKind::Routines = cmd.kind {
            return Some(cmd.offset);
        }
    }
    None
}

/// The symtab row's `n_value` for the named symbol (the expected
/// terminator address).
fn symbol_value(image: &[u8], name: &[u8]) -> Option<u64> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if let pgr_format::LoadCommandKind::Symtab = cmd.kind {
            let st = pgr_format::SymtabCommand::parse(image, cmd.offset).expect("the lc parses");
            let strtab = &image[st.stroff as usize..(st.stroff + st.strsize) as usize];
            for i in 0..st.nsyms {
                let at = st.symoff as usize + i as usize * 16;
                let n_strx =
                    u32::from_le_bytes(image[at..at + 4].try_into().expect("n_strx rides byte 0"));
                let n_value = u64::from_le_bytes(
                    image[at + 8..at + 16]
                        .try_into()
                        .expect("n_value rides byte 8"),
                );
                let nul = strtab[n_strx as usize..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(0);
                if &strtab[n_strx as usize..n_strx as usize + nul] == name {
                    return Some(n_value);
                }
            }
        }
    }
    None
}

fn strict_ok(image: &[u8]) -> bool {
    verify(
        image,
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

fn link_dylib(dir: &Path, extra: &[&str], tag: &str) -> Vec<u8> {
    let lib = lib_o(dir);
    let out = dir.join(format!("lib-{tag}.dylib"));
    let mut argv = vec![
        OsString::from("-o"),
        OsString::from(out.to_str().unwrap()),
        OsString::from(lib.to_str().unwrap()),
        OsString::from("-dylib"),
        OsString::from("-install_name"),
        OsString::from("@rpath/lib.dylib"),
    ];
    for a in extra {
        argv.push(OsString::from(*a));
    }
    let o = opts::parse(&argv).expect("the dylib argv parses");
    pgr_driver::run(&o).expect("the dylib link runs");
    std::fs::read(&out).expect("the image reads")
}

#[test]
fn the_default_dylib_carries_no_routines_command() {
    let dir = scratch("default");
    let image = link_dylib(&dir, &[], "plain");
    assert!(strict_ok(&image), "the default image verifies strict");
    assert!(
        routines_fields(&image).0 == 0,
        "the default plans no LC_ROUTINES"
    );
}

#[test]
fn term_names_the_terminator_and_verifies_strict() {
    let dir = scratch("named");
    let image = link_dylib(&dir, &["-term", "_my_term"], "named");
    assert!(strict_ok(&image), "the terminated image verifies strict");
    let (count, init, term) = routines_fields(&image);
    assert!(count >= 1, "LC_ROUTINES rides the header");
    assert_eq!(count, 1, "one command carries the terminator");
    assert_eq!(init, 0, "the initializer slot rides zero without -init");
    let expected = symbol_value(&image, b"_my_term").expect("_my_term rides the symtab");
    assert_eq!(term, expected, "term_address names the resolved terminator");
}

#[test]
fn init_and_term_compose_into_one_command() {
    // The compose gate on the served face: both flags ride the SAME
    // LC_ROUTINES_64, each address beside the other.
    let dir = scratch("compose");
    let image = link_dylib(&dir, &["-init", "_my_init", "-term", "_my_term"], "compose");
    assert!(strict_ok(&image), "the composed image verifies strict");
    let (count, init, term) = routines_fields(&image);
    assert_eq!(count, 1, "-init + -term never plan a duplicate command");
    let init_expected = symbol_value(&image, b"_my_init").expect("_my_init rides the symtab");
    let term_expected = symbol_value(&image, b"_my_term").expect("_my_term rides the symtab");
    assert_eq!(init, init_expected, "init_address names the initializer");
    assert_eq!(term, term_expected, "term_address names the terminator");
}

#[test]
fn term_refuses_where_init_refuses() {
    // The -init surface one field over: executables, bundles and the
    // relocatable output refuse the knob at the parse (the miette
    // help-text convention), and the bare flag refuses the missing
    // argument.
    let dir = scratch("refusals");
    let lib = lib_o(&dir);
    for (kind, hint) in [
        (&["-o", "exe"] as &[&str], "executable"),
        (&["-o", "bun", "-bundle"], "bundle"),
        (&["-o", "reloc", "-r"], "relocatable"),
    ] {
        let mut argv = vec![
            OsString::from(kind[0]),
            OsString::from(dir.join(kind[1]).to_str().unwrap()),
        ];
        if kind.len() > 2 {
            argv.push(OsString::from(kind[2]));
        }
        argv.push(OsString::from(lib.to_str().unwrap()));
        argv.push(OsString::from("-term"));
        argv.push(OsString::from("_my_term"));
        let err = opts::parse(&argv).expect_err("the non-dylib argv refuses");
        let message = err.to_string();
        assert!(
            message.contains("-term"),
            "the {hint} refusal names the knob: {message}"
        );
    }
    let argv: Vec<OsString> = [
        "-o",
        dir.join("x").to_str().unwrap(),
        lib.to_str().unwrap(),
        "-term",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let err = opts::parse(&argv).expect_err("the bare -term refuses");
    assert!(
        err.to_string().contains("-term"),
        "the missing-argument refusal names the flag: {err}"
    );
}

#[test]
fn the_verifier_flags_a_term_address_off_every_mapping() {
    // The M98 gate: a `term_address` naming no executable mapping is
    // the hostile shape (dyld calls the address when the image unloads;
    // a vaddr outside every VM_PROT_EXECUTE segment is a mis-derived or
    // tampered terminator).
    let dir = scratch("tamper");
    let image = link_dylib(&dir, &["-term", "_my_term"], "tamper");
    let at = routines_offset(&image).expect("LC_ROUTINES rides the header");
    let mut tampered = image.clone();
    // term_address rides bytes 16..24 of the command; a vaddr far past
    // every planned segment is the hostile shape.
    let hostile = 0x0000_dead_0000_u64;
    tampered[at + 16..at + 24].copy_from_slice(&hostile.to_le_bytes());
    let report = verify(
        &tampered,
        &VerifyOptions {
            strict_warnings: false,
            skip_hash_recompute: true,
        },
    );
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("term_address")),
        "the verifier names the hostile terminator: {:?}",
        report.issues.iter().map(|i| &i.message).collect::<Vec<_>>()
    );
}

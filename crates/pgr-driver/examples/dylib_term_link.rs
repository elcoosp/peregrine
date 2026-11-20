//! The dylib-terminator consumer example (M98): shipping a dylib with a
//! load-time terminator — `-term <symbol>` — the sibling of M48's
//! `-init` (the resolved terminator's image-space vaddr rides
//! `term_address` in the SAME `LC_ROUTINES_64`, one command two fields
//! — dyld calls the initializer when the image loads and the terminator
//! when it unloads). The default plans no command; the knob refuses
//! where `-init` refuses — executables, bundles and `-r`. Both dylib
//! images verify strict; the command's fields are read back — the
//! surface a build system audits after the link.
//!
//! Run: `cargo run -p pgr-driver --example dylib_term_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// lib.o: `_my_init` (the initializer body), `_my_term` (the terminator
/// body) and `_api` (the exported surface), all `ret` bodies in one
/// `__text`.
fn lib_object() -> Vec<u8> {
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
    b.build().expect("the fixture object builds")
}

/// Walks the image's load commands; returns `(count, init_address,
/// term_address)` over the `LC_ROUTINES_64` family.
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
            let size =
                u32::from_le_bytes(cmd.bytes[4..8].try_into().expect("cmdsize rides byte 4"));
            assert_eq!(
                size, 72,
                "the command rides the 72-byte routines_command_64"
            );
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

/// The symtab row's `n_value` for the named symbol (the expected
/// routine address).
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
                // The 16-byte nlist_64: n_strx, n_type, n_sect, n_desc,
                // n_value (the TDD §3.3 layout).
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

/// Links the dylib with the named extra flags; returns the image bytes.
fn link_dylib(extra: &[&str], tag: &str) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!("pgr_dylib_term_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lib = dir.join("lib.o");
    std::fs::write(&lib, lib_object()).unwrap();
    let out = dir.join(format!("lib-{tag}.dylib"));
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        std::ffi::OsString::from(out.to_str().unwrap()),
        std::ffi::OsString::from(lib.to_str().unwrap()),
        std::ffi::OsString::from("-dylib"),
        std::ffi::OsString::from("-install_name"),
        std::ffi::OsString::from("@rpath/lib.dylib"),
    ];
    for a in extra {
        argv.push(std::ffi::OsString::from(*a));
    }
    let o = opts::parse(&argv).expect("the dylib argv parses");
    pgr_driver::run(&o).expect("the dylib link runs");
    std::fs::read(&out).expect("the image reads")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    // The default: no LC_ROUTINES_64 rides — the pre-M98 command set.
    let plain = link_dylib(&[], "plain");
    assert!(strict_ok(&plain), "the default image verifies strict");
    assert!(
        routines_fields(&plain).0 == 0,
        "the default plans no LC_ROUTINES_64"
    );
    println!("default: {} bytes — no LC_ROUTINES_64 rides", plain.len());

    // The named terminator: one command, `term_address` naming the
    // resolved routine (the symtab row confirms the value), the
    // initializer slot riding zero.
    let named = link_dylib(&["-term", "_my_term"], "named");
    assert!(strict_ok(&named), "the terminated image verifies strict");
    let (count, init, term) = routines_fields(&named);
    assert!(count >= 1, "LC_ROUTINES_64 rides the header");
    let expected = symbol_value(&named, b"_my_term").expect("_my_term rides the symtab");
    assert_eq!(count, 1, "one command carries the terminator");
    assert_eq!(init, 0, "the initializer slot rides zero without -init");
    assert_eq!(term, expected, "term_address names the resolved terminator");
    println!(
        "named:   {} bytes — LC_ROUTINES_64 term_address {term:#x} == _my_term's symtab value",
        named.len()
    );

    // The compose: both halves ride the SAME command — never a
    // duplicate.
    let both = link_dylib(&["-init", "_my_init", "-term", "_my_term"], "compose");
    assert!(strict_ok(&both), "the composed image verifies strict");
    let (count, init, term) = routines_fields(&both);
    assert_eq!(count, 1, "-init + -term never plan a duplicate command");
    let init_expected = symbol_value(&both, b"_my_init").expect("_my_init rides the symtab");
    let term_expected = symbol_value(&both, b"_my_term").expect("_my_term rides the symtab");
    assert_eq!(init, init_expected, "init_address names the initializer");
    assert_eq!(term, term_expected, "term_address names the terminator");
    println!(
        "compose: {} bytes — one LC_ROUTINES_64, init {init:#x} + term {term:#x}",
        both.len()
    );

    // The refusals: the -init surface one field over — executables,
    // bundles and the relocatable output refuse the knob.
    for (kind, argv) in [
        ("executable", vec!["-o", "exe"]),
        ("bundle", vec!["-o", "bun", "-bundle"]),
        ("relocatable", vec!["-o", "reloc", "-r"]),
    ] {
        let dir = std::env::temp_dir().join(format!("pgr_dylib_term_{}", std::process::id()));
        let lib = dir.join("lib.o");
        let mut argv: Vec<std::ffi::OsString> = argv
            .iter()
            .map(|a| {
                if *a == "exe" || *a == "bun" || *a == "reloc" {
                    std::ffi::OsString::from(dir.join(a).to_str().unwrap())
                } else {
                    std::ffi::OsString::from(*a)
                }
            })
            .collect();
        argv.push(std::ffi::OsString::from(lib.to_str().unwrap()));
        argv.push(std::ffi::OsString::from("-term"));
        argv.push(std::ffi::OsString::from("_my_term"));
        let err = opts::parse(&argv).expect_err("the non-dylib argv refuses");
        println!("{kind}: refuses — {err}");
    }
    println!(
        "\nLC_ROUTINES_64's term_address is the dylib-terminator contract dyld reads on \
         unload; try PGR_TRACING=1 to watch the pipeline"
    );
}

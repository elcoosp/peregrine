//! The dylib-initializer consumer example (M48): shipping a dylib with
//! a load-time initializer — `-init <symbol>` — ld64's flag
//! (*"Specifies the name of an initializer to be called by dyld when
//! the image is loaded"*). The resolved initializer's address rides
//! `LC_ROUTINES_64` (the 72-byte `routines_command_64` — dyld's
//! `hasInitializer` walk reads the command before the `__mod_init_func`
//! sections). The default plans no command; the knob refuses where
//! ld64 refuses it — executables, bundles and `-r`. Both dylib images
//! verify strict; the command's fields are read back — the surface a
//! build system audits after the link.
//!
//! Run: `cargo run -p pgr-driver --example dylib_init_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// lib.o: `_my_init` (the initializer body) and `_api` (the exported
/// surface), both `ret` bodies in one `__text`.
fn lib_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("lib.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6], // ret; ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_my_init".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_api".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Walks the image's load commands; returns the first `LC_ROUTINES_64`
/// command's `(cmdsize, init_address)`.
fn routines_fields(image: &[u8]) -> Option<(u32, u64)> {
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
            let size =
                u32::from_le_bytes(cmd.bytes[4..8].try_into().expect("cmdsize rides byte 4"));
            let addr = u64::from_le_bytes(
                cmd.bytes[8..16]
                    .try_into()
                    .expect("init_address rides byte 8"),
            );
            return Some((size, addr));
        }
    }
    None
}

/// The symtab row's `n_value` for the named symbol (the initializer's
/// expected address).
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
    let dir = std::env::temp_dir().join(format!("pgr_dylib_init_{}", std::process::id()));
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

    // The default: no LC_ROUTINES_64 rides — the pre-M48 command set.
    let plain = link_dylib(&[], "plain");
    assert!(strict_ok(&plain), "the default image verifies strict");
    assert!(
        routines_fields(&plain).is_none(),
        "the default plans no LC_ROUTINES_64"
    );
    println!("default: {} bytes — no LC_ROUTINES_64 rides", plain.len());

    // The named initializer: the 72-byte command with the resolved
    // address (the symtab row confirms the value).
    let named = link_dylib(&["-init", "_my_init"], "named");
    assert!(strict_ok(&named), "the initialized image verifies strict");
    let (size, addr) = routines_fields(&named).expect("LC_ROUTINES_64 rides the header");
    let expected = symbol_value(&named, b"_my_init").expect("_my_init rides the symtab");
    assert_eq!(
        size, 72,
        "the command rides the 72-byte routines_command_64"
    );
    assert_eq!(
        addr, expected,
        "init_address names the resolved initializer"
    );
    println!(
        "named:   {} bytes — LC_ROUTINES_64 init_address {addr:#x} == _my_init's symtab value",
        named.len()
    );

    // The refusals: ld64's own validation — "-init can only be used
    // with -dynamiclib".
    for (kind, argv) in [
        ("executable", vec!["-o", "exe"]),
        ("bundle", vec!["-o", "bun", "-bundle"]),
        ("relocatable", vec!["-o", "reloc", "-r"]),
    ] {
        let dir = std::env::temp_dir().join(format!("pgr_dylib_init_{}", std::process::id()));
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
        argv.push(std::ffi::OsString::from("-init"));
        argv.push(std::ffi::OsString::from("_my_init"));
        let err = opts::parse(&argv).expect_err("the non-dylib argv refuses");
        println!("{kind}: refuses — {err}");
    }
    println!(
        "\nLC_ROUTINES_64 is the dylib-initializer contract dyld reads; \
         try PGR_TRACING=1 to watch the pipeline"
    );
}

//! M48 — the dylib initializer on the driver surface: `-init
//! <symbol>` rides the argv on a `-dylib` link (the `LC_ROUTINES`
//! command carries the resolved initializer, the image verifies
//! strict), the default plans no command, and the knob refuses where
//! ld64 refuses it — executables, bundles and `-r` — with the fix
//! ("only used with -dynamiclib"), plus the missing-argument refusal.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m48_init").join(format!(
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

/// lib.o: `_my_init` (the initializer body) and `_api` (the exported
/// surface), both `ret` bodies in one `__text`.
fn lib_o(dir: &Path) -> PathBuf {
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
    let path = dir.join("lib.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// Walks the image's load commands; returns the first `LC_ROUTINES`
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

/// The symtab row's `n_value` for the named symbol (the expected
/// initializer address: `_my_init` rides the `__text` start).
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
        routines_fields(&image).is_none(),
        "the default plans no LC_ROUTINES"
    );
}

#[test]
fn init_names_the_initializer_and_verifies_strict() {
    let dir = scratch("named");
    let image = link_dylib(&dir, &["-init", "_my_init"], "named");
    assert!(strict_ok(&image), "the initialized image verifies strict");
    let (size, addr) = routines_fields(&image).expect("LC_ROUTINES rides the header");
    assert_eq!(
        size, 72,
        "LC_ROUTINES rides the 72-byte routines_command_64"
    );
    let expected = symbol_value(&image, b"_my_init").expect("_my_init rides the symtab");
    assert_eq!(
        addr, expected,
        "init_address names the resolved initializer"
    );
}

#[test]
fn init_refuses_where_ld64_refuses_it() {
    // ld64's validation: "-init can only be used with -dynamiclib". An
    // executable, a bundle and the relocatable output refuse the knob
    // at the surface (the miette help-text convention), and the bare
    // flag refuses the missing argument.
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
        argv.push(OsString::from("-init"));
        argv.push(OsString::from("_my_init"));
        let err = opts::parse(&argv).expect_err("the non-dylib argv refuses");
        let message = err.to_string();
        assert!(
            message.contains("-init"),
            "the {hint} refusal names the knob: {message}"
        );
    }
    let argv = args(&[
        "-o",
        dir.join("x").to_str().unwrap(),
        lib.to_str().unwrap(),
        "-init",
    ]);
    let err = opts::parse(&argv).expect_err("the bare -init refuses");
    assert!(
        err.to_string().contains("-init"),
        "the missing-argument refusal names the flag: {err}"
    );
}

#[test]
fn the_verifier_flags_a_routines_command_off_a_dylib() {
    // The M48 gate: `LC_ROUTINES_64` is a dylib command — the same
    // image with its filetype word flipped to `MH_EXECUTE` is the
    // hostile shape the structural family refuses (dyld's
    // hasInitializer reads the command from dylibs; an executable's
    // initializer surface is LC_MAIN).
    let dir = scratch("tamper");
    let image = link_dylib(&dir, &["-init", "_my_init"], "tamper");
    let mut tampered = image.clone();
    // MH_EXECUTE rides the filetype word at byte 12.
    tampered[12..16].copy_from_slice(&pgr_format::consts::MH_EXECUTE.to_le_bytes());
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
            .any(|i| i.message.contains("LC_ROUTINES_64")),
        "the verifier names the foreign command: {:?}",
        report.issues.iter().map(|i| &i.message).collect::<Vec<_>>()
    );
}

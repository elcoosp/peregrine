//! M23 — the `-reexport_framework <name>` driver surface: the framework
//! form of the M3 re-export (`-reexport_library` rides path inputs) —
//! the flag searches `-F` dirs like `-framework` (the M5 search), the
//! resolved dylib loads as `LC_REEXPORT_DYLIB`, its exports join this
//! image's export trie as REEXPORT nodes, and the image verifies
//! strict.

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m23_reexport").join(format!(
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

/// hello.o: `_main` BLs `_greet` and returns — one external bind.
fn hello_o(dir: &Path) -> PathBuf {
    let text: Vec<u8> = [
        0x9400_0000u32, // bl _greet
        0x5280_0000u32, // mov w0, #0
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("hello.o");
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let greet = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    let _ = main_sym;
    b.section_mut(sect)
        .relocs
        .push(ObjectReloc::branch26(u32::try_from(greet).unwrap()).at(0));
    let path = dir.join("hello.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// An `Other.framework/Other.tbd` stub exporting `_other_fn`.
fn framework(dir: &Path, name: &str, symbol: &str) -> PathBuf {
    let fw = dir.join(format!("{name}.framework"));
    std::fs::create_dir_all(&fw).unwrap();
    let tbd = fw.join(name);
    std::fs::write(
        &tbd,
        format!(
            "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: @rpath/{name}.framework/{name}\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ {symbol} ]\n...\n"
        ),
    )
    .unwrap();
    tbd
}

/// Every load command as `(kind, raw bytes)`.
fn load_commands(bytes: &[u8]) -> Vec<(pgr_format::LoadCommandKind, Vec<u8>)> {
    let header = pgr_format::MachHeader64::parse(bytes).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut out = Vec::new();
    while let Ok(Some(cmd)) = it.next_command() {
        out.push((cmd.kind, cmd.bytes.to_vec()));
    }
    out
}

/// The image's dylib commands: `(opcode, install name)` in order.
fn dylib_commands(image: &[u8]) -> Vec<(u32, String)> {
    load_commands(image)
        .iter()
        .filter(|(k, _)| {
            matches!(
                k,
                pgr_format::LoadCommandKind::LoadDylib | pgr_format::LoadCommandKind::ReexportDylib
            )
        })
        .filter_map(|(_, bytes)| {
            let opcode = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            let name = pgr_format::DylibCommand::parse(bytes)
                .ok()?
                .name(bytes)
                .ok()?;
            Some((
                opcode,
                String::from_utf8_lossy(name)
                    .trim_end_matches('\0')
                    .to_string(),
            ))
        })
        .collect()
}

/// The export trie payload bytes.
fn find_trie(bytes: &[u8]) -> Vec<u8> {
    for (kind, raw) in load_commands(bytes) {
        if let pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_EXPORTS_TRIE) =
            kind
        {
            return pgr_format::LinkeditDataCommand::parse(&raw)
                .unwrap()
                .data(bytes)
                .unwrap()
                .to_vec();
        }
    }
    panic!("image carries no LC_DYLD_EXPORTS_TRIE");
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// Links `hello.o` with the given extra argv; returns the image bytes.
fn link_exe(dir: &Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let obj = hello_o(dir);
    let mut argv: Vec<String> = vec!["-o".into(), dir.join(out).display().to_string()];
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    argv.push(obj.display().to_string());
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(dir.join(out)).unwrap()
}

// ---- the surface -------------------------------------------------------------

#[test]
fn a_reexport_framework_resolves_through_the_framework_search() {
    let dir = scratch("resolve");
    framework(&dir, "Greet", "_greet");
    let image = link_exe(
        &dir,
        "hello",
        &[
            "-F",
            &dir.display().to_string(),
            "-reexport_framework",
            "Greet",
        ],
    );
    // LC_REEXPORT_DYLIB carries the framework's install name (the M3
    // re-export shape the path-input form rides).
    let cmds = dylib_commands(&image);
    let (_, name) = cmds
        .iter()
        .find(|(op, _)| *op == pgr_format::consts::LC_REEXPORT_DYLIB)
        .expect("LC_REEXPORT_DYLIB present");
    assert_eq!(
        name, "@rpath/Greet.framework/Greet",
        "the framework install name rides the re-export"
    );

    // The trie lists `_greet` as a re-export (no address, an ordinal).
    let trie = find_trie(&image);
    let mut report = pgr_verify::Report::default();
    let exports = pgr_verify::export_trie::check_export_trie(&trie, &mut report);
    let entry = exports
        .entries
        .iter()
        .find(|e| e.name == "_greet")
        .expect("the re-exported name rides the trie");
    assert_eq!(
        entry.reexport_ordinal,
        Some(1),
        "the framework is the image's first dylib ordinal"
    );
    assert_eq!(entry.address, None, "re-exports carry no address");

    // The header drops MH_NO_REEXPORTED_DYLIBS (the M3 convention).
    let hflags = u32::from_le_bytes(image[24..28].try_into().unwrap());
    assert!(
        hflags & pgr_format::consts::MH_NO_REEXPORTED_DYLIBS == 0,
        "re-exports clear the flag"
    );

    // Strict verification stays clean.
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the re-exporting executable verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_flag_keeps_the_framework_ordinal_order() {
    // The lists are separate in `Options` (the M14 convention); the LC
    // order — and with it the two-level ordinals — is plain frameworks,
    // then re-export frameworks, then weak, then lazy. The command-line
    // position of the two flags does not reorder the commands (and the
    // two-level bind lands on the first-exporting ordinal).
    let dir = scratch("order");
    framework(&dir, "Plain", "_greet");
    framework(&dir, "Rexp", "_greet");
    let image = link_exe(
        &dir,
        "hello",
        &[
            "-reexport_framework",
            "Rexp",
            "-F",
            &dir.display().to_string(),
            "-framework",
            "Plain",
        ],
    );
    let cmds = dylib_commands(&image);
    assert_eq!(
        cmds,
        vec![
            (
                pgr_format::consts::LC_LOAD_DYLIB,
                "@rpath/Plain.framework/Plain".to_string()
            ),
            (
                pgr_format::consts::LC_REEXPORT_DYLIB,
                "@rpath/Rexp.framework/Rexp".to_string()
            ),
        ],
        "the plain framework leads the ordinal space even when the \
         re-export flag came first"
    );
}

#[test]
fn an_unresolvable_reexport_framework_names_the_surface() {
    let dir = scratch("missing");
    let obj = hello_o(&dir);
    let argv = args(&[
        "-o",
        &dir.join("hello").display().to_string(),
        "-F",
        &dir.display().to_string(),
        "-reexport_framework",
        "Missing",
        &obj.display().to_string(),
    ]);
    let o = opts::parse(&argv).expect("the argv parses");
    let err = pgr_driver::run(&o).expect_err("the missing framework refuses");
    assert!(
        err.to_string().contains("Missing.framework"),
        "the refusal names the searched surface: {err}"
    );
}

#[test]
fn a_plain_link_carries_no_reexports() {
    let dir = scratch("plain");
    // A self-contained object (no undefined externals): the plain
    // pre-M23 shape carries no dylib commands at all.
    let mut b = ObjectBuilder::new("main.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        [0xD65F_03C0u32.to_le_bytes()].repeat(2).concat(),
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    let obj = dir.join("main.o");
    std::fs::write(&obj, b.build().expect("the fixture object builds")).unwrap();
    let argv = args(&[
        "-o",
        &dir.join("hello").display().to_string(),
        &obj.display().to_string(),
    ]);
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(dir.join("hello")).unwrap();
    assert!(
        dylib_commands(&image).is_empty(),
        "the pre-M23 shape carries no dylib commands"
    );
}

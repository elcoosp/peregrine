//! M14 rung 2 — the lazy/weak dylib surface released: `-weak_framework`,
//! `-lazy_framework` and `-lazy_library` stop refusing and shape their
//! ld64 commands (`LC_LOAD_WEAK_DYLIB` / `LC_LAZY_LOAD_DYLIB`), the
//! lazy command rides the same two-level ordinal space (the verifier's
//! walk and pair gate count it), and every image verifies strict.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m14_lazy").join(format!(
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

/// A greet `.tbd` (v4) exporting `_greet`.
fn greet_tbd() -> &'static str {
    "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: @rpath/libgreet.dylib\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _greet ]\n...\n"
}

/// A `Greet.framework/Greet.tbd` stub for the framework flags.
fn framework(dir: &Path, name: &str) -> PathBuf {
    let fw = dir.join(format!("{name}.framework"));
    std::fs::create_dir_all(&fw).unwrap();
    let tbd = fw.join(name);
    std::fs::write(
        &tbd,
        format!(
            "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: @rpath/{name}.framework/{name}\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _greet ]\n...\n"
        ),
    )
    .unwrap();
    tbd
}

/// The image's dylib load commands: `(cmd opcode, install name)`.
fn dylib_commands(image: &[u8]) -> Vec<(u32, String)> {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut out = Vec::new();
    while let Ok(Some(cmd)) = it.next_command() {
        // The dylib-command family: load/weak/upward/lazy all decode as
        // `LoadDylib` (same `dylib_command` layout), re-exports decode
        // as their own kind — the opcode byte is read verbatim so the
        // gate can tell the commands apart.
        if cmd.kind == pgr_format::LoadCommandKind::LoadDylib
            || cmd.kind == pgr_format::LoadCommandKind::ReexportDylib
        {
            if let Ok(d) = pgr_format::DylibCommand::parse(cmd.bytes) {
                if let Ok(name) = d.name(cmd.bytes) {
                    let opcode = u32::from_le_bytes(cmd.bytes[0..4].try_into().unwrap());
                    out.push((
                        opcode,
                        String::from_utf8_lossy(name)
                            .trim_end_matches('\0')
                            .to_string(),
                    ));
                }
            }
        }
    }
    out
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

#[test]
fn lazy_library_loads_as_the_lazy_command() {
    let dir = scratch("lazy_lib");
    let obj = hello_o(&dir);
    let tbd = dir.join("libgreet.tbd");
    std::fs::write(&tbd, greet_tbd()).unwrap();
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        obj.to_str().unwrap(),
        "-lazy_library",
        tbd.to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the lazy argv parses");
    pgr_driver::run(&o).expect("the lazy link runs");
    let image = std::fs::read(&out).unwrap();
    assert!(strict_ok(&image), "the lazy image verifies strict");
    let cmds = dylib_commands(&image);
    let lazy = pgr_format::consts::LC_LAZY_LOAD_DYLIB;
    assert!(
        cmds.iter()
            .any(|(op, name)| *op == lazy && name.contains("libgreet")),
        "LC_LAZY_LOAD_DYLIB carries the install name: {cmds:?}"
    );
    assert!(
        !cmds
            .iter()
            .any(|(op, _)| *op == pgr_format::consts::LC_LOAD_DYLIB),
        "no plain load command for the lazy dylib: {cmds:?}"
    );
}

#[test]
fn weak_and_lazy_frameworks_shape_their_commands() {
    // -weak_framework: LC_LOAD_WEAK_DYLIB.
    let dir = scratch("weak_fw");
    let obj = hello_o(&dir);
    let fw = framework(&dir, "Greet");
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        obj.to_str().unwrap(),
        "-F",
        dir.to_str().unwrap(),
        "-weak_framework",
        "Greet",
    ]);
    let _ = fw;
    let o = opts::parse(&argv).expect("the weak-framework argv parses");
    pgr_driver::run(&o).expect("the weak link runs");
    let image = std::fs::read(&out).unwrap();
    assert!(strict_ok(&image), "the weak image verifies strict");
    let cmds = dylib_commands(&image);
    assert!(
        cmds.iter()
            .any(|(op, _)| *op == pgr_format::consts::LC_LOAD_WEAK_DYLIB),
        "LC_LOAD_WEAK_DYLIB rides: {cmds:?}"
    );

    // -lazy_framework: LC_LAZY_LOAD_DYLIB.
    let dir2 = scratch("lazy_fw");
    let obj2 = hello_o(&dir2);
    let _fw2 = framework(&dir2, "Greet");
    let out2 = dir2.join("hello");
    let argv2 = args(&[
        "-o",
        out2.to_str().unwrap(),
        obj2.to_str().unwrap(),
        "-F",
        dir2.to_str().unwrap(),
        "-lazy_framework",
        "Greet",
    ]);
    let o2 = opts::parse(&argv2).expect("the lazy-framework argv parses");
    pgr_driver::run(&o2).expect("the lazy link runs");
    let image2 = std::fs::read(&out2).unwrap();
    assert!(strict_ok(&image2), "the lazy image verifies strict");
    let cmds2 = dylib_commands(&image2);
    assert!(
        cmds2
            .iter()
            .any(|(op, _)| *op == pgr_format::consts::LC_LAZY_LOAD_DYLIB),
        "LC_LAZY_LOAD_DYLIB rides: {cmds2:?}"
    );
}

#[test]
fn lazy_dylib_binds_in_the_two_level_space() {
    // A load dylib and a lazy dylib side by side: the bind to the lazy
    // library's export carries the lazy library's ordinal (dyld counts
    // LC_LAZY_LOAD_DYLIB in the two-level space — the verifier's walk
    // enforces it, so a strict pass is the ordinal gate).
    let dir = scratch("ordinals");
    let obj = hello_o(&dir);
    let eager = dir.join("libeager.tbd");
    std::fs::write(
        &eager,
        "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: @rpath/libeager.dylib\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _eager ]\n...\n",
    )
    .unwrap();
    let lazy = dir.join("libgreet.tbd");
    std::fs::write(&lazy, greet_tbd()).unwrap();
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        obj.to_str().unwrap(),
        "-lazy_library",
        lazy.to_str().unwrap(),
        eager.to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the mixed argv parses");
    pgr_driver::run(&o).expect("the mixed link runs");
    let image = std::fs::read(&out).unwrap();
    assert!(strict_ok(&image), "the mixed image verifies strict");
    let cmds = dylib_commands(&image);
    assert_eq!(cmds.len(), 2, "both dylibs ride: {cmds:?}");
    // LC order follows argv order: the lazy library (named first on the
    // command line) carries ordinal 1, the eager input ordinal 2 — the
    // verifier's strict walk just enforced every bind against it.
    assert!(
        cmds[0].1.contains("libgreet") && cmds[0].0 == pgr_format::consts::LC_LAZY_LOAD_DYLIB,
        "argv order + lazy kind: {cmds:?}"
    );
    assert!(cmds[1].1.contains("libeager"), "{cmds:?}");
}

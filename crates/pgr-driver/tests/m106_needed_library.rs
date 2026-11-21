//! M106 — the `-needed_library <path>` / `-needed_framework <name>` /
//! `-needed-l <name>` driver surface: the needed-dylib mark (ld64's
//! "needed" loads — the dylib really rides even when no symbol binds
//! against it, the `ld` man page). The mark rides the same `-F` search
//! `-framework` uses (the M5/M23 pattern), composes with
//! `-dead_strip_dylibs` as the per-dylib survival opt-out, and the image
//! verifies strict. The relocatable output refuses the knob (the object
//! carries no load commands — the M42 refusal shape).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m106_needed").join(format!(
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

/// A `lib<name>.tbd` stub exporting `symbol` in the given dir.
fn lib_tbd(dir: &Path, name: &str, symbol: &str) -> PathBuf {
    let tbd = dir.join(format!("lib{name}.tbd"));
    std::fs::write(
        &tbd,
        format!(
            "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: @rpath/lib{name}.tbd\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ {symbol} ]\n...\n"
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
fn a_needed_library_survives_the_dead_strip_dylibs_drop() {
    let dir = scratch("library");
    lib_tbd(&dir, "greet", "_greet");
    lib_tbd(&dir, "idle", "_idle_fn");
    // Under the drop the unused plain dylib leaves; the needed one rides
    // even though nothing binds against it (ld64: "means to really link
    // with the dylib even if no symbols are used from it").
    let image = link_exe(
        &dir,
        "hello",
        &[
            "-L",
            &dir.display().to_string(),
            "-needed_library",
            &dir.join("libidle.tbd").display().to_string(),
            "-dead_strip_dylibs",
            "-l",
            "greet",
        ],
    );
    let cmds = dylib_commands(&image);
    assert_eq!(
        cmds,
        vec![
            (
                pgr_format::consts::LC_LOAD_DYLIB,
                "@rpath/libidle.tbd".to_string()
            ),
            (
                pgr_format::consts::LC_LOAD_DYLIB,
                "@rpath/libgreet.tbd".to_string()
            ),
        ],
        "the needed dylib rides beside the used one; the LC kind stays a plain load"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the needed-dylib image verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn an_unneeded_unused_library_drops_under_the_knob() {
    let dir = scratch("drop");
    lib_tbd(&dir, "greet", "_greet");
    lib_tbd(&dir, "idle", "_idle_fn");
    // The same shape without the mark: the unused dylib leaves the header
    // (the M42 drop — the mark's reason to exist).
    let image = link_exe(
        &dir,
        "hello",
        &[
            "-L",
            &dir.display().to_string(),
            "-l",
            "idle",
            "-dead_strip_dylibs",
            "-l",
            "greet",
        ],
    );
    let cmds = dylib_commands(&image);
    let names: Vec<&str> = cmds.iter().map(|(_, n)| n.as_str()).collect();
    assert_eq!(
        names,
        vec!["@rpath/libgreet.tbd"],
        "the unused plain dylib drops; the used one rides"
    );
}

#[test]
fn a_needed_framework_resolves_through_the_framework_search() {
    let dir = scratch("framework");
    framework(&dir, "Idle", "_idle_fn");
    framework(&dir, "Greet", "_greet");
    // The needed framework resolves through the `-F` search (the M23
    // pattern) and survives the drop without a bind.
    let image = link_exe(
        &dir,
        "hello",
        &[
            "-F",
            &dir.display().to_string(),
            "-needed_framework",
            "Idle",
            "-dead_strip_dylibs",
            "-framework",
            "Greet",
        ],
    );
    let cmds = dylib_commands(&image);
    let names: Vec<&str> = cmds.iter().map(|(_, n)| n.as_str()).collect();
    assert!(
        names.contains(&"@rpath/Idle.framework/Idle"),
        "the needed framework rides: {names:?}"
    );
    assert!(
        names.contains(&"@rpath/Greet.framework/Greet"),
        "the used framework rides: {names:?}"
    );
}

#[test]
fn a_needed_framework_keeps_the_kind_order_and_a_plain_load() {
    // The needed frameworks resolve after the upward ones (the M45
    // convention — the newest list rides last) and load as `LC_LOAD_DYLIB`
    // (the mark names survival, not a command kind).
    let dir = scratch("order");
    framework(&dir, "Plain", "_greet");
    framework(&dir, "Needed", "_idle_fn");
    let image = link_exe(
        &dir,
        "hello",
        &[
            "-needed_framework",
            "Needed",
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
                pgr_format::consts::LC_LOAD_DYLIB,
                "@rpath/Needed.framework/Needed".to_string()
            ),
        ],
        "the plain framework leads the ordinal space even when the needed \
         flag came first; both load as plain loads"
    );
}

#[test]
fn a_needed_l_library_survives_the_drop() {
    let dir = scratch("needed_l");
    lib_tbd(&dir, "greet", "_greet");
    lib_tbd(&dir, "idle", "_idle_fn");
    // The `-l` form: the basename rides the `-L` search with the mark.
    let image = link_exe(
        &dir,
        "hello",
        &[
            "-L",
            &dir.display().to_string(),
            "-needed-l",
            "idle",
            "-dead_strip_dylibs",
            "-l",
            "greet",
        ],
    );
    let cmds = dylib_commands(&image);
    let names: Vec<&str> = cmds.iter().map(|(_, n)| n.as_str()).collect();
    assert!(
        names.contains(&"@rpath/libidle.tbd"),
        "the -needed-l dylib rides the drop: {names:?}"
    );
}

#[test]
fn an_unresolvable_needed_framework_names_the_surface() {
    let dir = scratch("missing");
    let obj = hello_o(&dir);
    let argv = args(&[
        "-o",
        &dir.join("hello").display().to_string(),
        "-F",
        &dir.display().to_string(),
        "-needed_framework",
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
fn the_relocatable_output_refuses_the_needed_flags() {
    let dir = scratch("reloc");
    lib_tbd(&dir, "idle", "_idle_fn");
    framework(&dir, "Idle", "_idle_fn");
    let obj = hello_o(&dir);
    let out = dir.join("hello.o.out").display().to_string();
    let lib_dir = dir.display().to_string();
    let tbd = dir.join("libidle.tbd").display().to_string();
    for flag_form in [
        vec!["-needed_library", &tbd],
        vec!["-needed-l", "idle"],
        vec!["-needed_framework", "Idle"],
    ] {
        let mut argv: Vec<String> = vec![
            "-o".into(),
            out.clone(),
            "-r".into(),
            "-L".into(),
            lib_dir.clone(),
            "-F".into(),
            lib_dir.clone(),
        ];
        argv.extend(flag_form.iter().map(std::string::ToString::to_string));
        argv.push(obj.display().to_string());
        let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
        // The relocatable refusal is the parse surface's (finish sees
        // the whole surface): the argv refuses at the parse.
        let err = opts::parse(&argv).expect_err("the relocatable output refuses the mark");
        assert!(
            err.to_string().contains("-needed"),
            "the refusal names the knob: {err}"
        );
    }
}

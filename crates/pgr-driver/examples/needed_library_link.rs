//! The needed-library consumer example (M106): ld64's "needed" loads —
//! `hello.o` linked with `-dead_strip_dylibs` three ways, the
//! `-needed_library` mark read back from the images (the dylib really
//! rides even when no symbol binds against it, the `ld` man page), the
//! `-needed_framework` and `-needed-l` forms through their searches, the
//! strict verifier on the survivors, and the relocatable refusal
//! rendered as miette help text (the fix, not just the verdict: the
//! house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example needed_library_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// hello.o: `_main` BLs `_greet` and returns — one external bind (the
/// unused dylib exports `_idle_fn`, a name nothing references).
fn hello_object() -> Vec<u8> {
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
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.section_mut(sect)
        .relocs
        .push(ObjectReloc::branch26(u32::try_from(greet).unwrap()).at(0));
    b.build().expect("the fixture object builds")
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

/// An `<Name>.framework/<Name>` stub exporting `_idle_fn` under `dir`.
fn framework(dir: &Path, name: &str) -> PathBuf {
    let fw = dir.join(format!("{name}.framework"));
    std::fs::create_dir_all(&fw).unwrap();
    std::fs::write(
        fw.join(name),
        format!(
            "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: @rpath/{name}.framework/{name}\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _idle_fn ]\n...\n"
        ),
    )
    .unwrap();
    fw
}

/// The image's dylib install names, in command order.
fn dylib_names(image: &[u8]) -> Vec<String> {
    let header = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut out = Vec::new();
    while let Ok(Some(cmd)) = it.next_command() {
        if matches!(
            cmd.kind,
            pgr_format::LoadCommandKind::LoadDylib | pgr_format::LoadCommandKind::ReexportDylib
        ) {
            let d = pgr_format::DylibCommand::parse(cmd.bytes).expect("the dylib command parses");
            let name = d.name(cmd.bytes).expect("the install name reads");
            out.push(
                String::from_utf8_lossy(name)
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
    }
    out
}

fn link(dir: &Path, out: &str, extra: &[&str], obj: &Path) -> Vec<u8> {
    let mut argv: Vec<String> = vec!["-o".into(), dir.join(out).display().to_string()];
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    argv.push(obj.display().to_string());
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(dir.join(out)).expect("the image reads")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_needed_lib_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
    lib_tbd(&dir, "greet", "_greet");
    lib_tbd(&dir, "idle", "_idle_fn");
    framework(&dir, "Idle");
    let lib_dir = dir.display().to_string();
    let idle_tbd = dir.join("libidle.tbd").display().to_string();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // Face 1 — the carried default: without the drop every dylib rides
    // its `LC_LOAD_DYLIB` command (the pre-M106 shape, ld64's own).
    let image = link(
        &dir,
        "hello_carried",
        &["-L", &lib_dir, "-l", "greet", "-l", "idle"],
        &obj,
    );
    let names = dylib_names(&image);
    println!("carried default: {names:?}");
    assert_eq!(
        names.len(),
        2,
        "the carried default rides both dylibs (the pre-M106 shape)"
    );
    assert!(
        verify(&image, &opts_strict).is_ok(&opts_strict),
        "the carried image verifies strict"
    );

    // Face 2 — the drop: under `-dead_strip_dylibs` the unused dylib
    // leaves the header (the M42 drop — the mark's reason to exist).
    let image = link(
        &dir,
        "hello_dropped",
        &[
            "-L",
            &lib_dir,
            "-l",
            "greet",
            "-l",
            "idle",
            "-dead_strip_dylibs",
        ],
        &obj,
    );
    let names = dylib_names(&image);
    println!("dropped: {names:?}");
    assert_eq!(
        names,
        vec!["@rpath/libgreet.tbd".to_string()],
        "the unused plain dylib drops under the knob"
    );

    // Face 3 — the needed mark: the same drop with
    // `-needed_library libidle.tbd`; the dylib really rides (ld64:
    // "means to really link with the dylib even if no symbols are used
    // from it").
    let image = link(
        &dir,
        "hello_needed",
        &[
            "-L",
            &lib_dir,
            "-needed_library",
            &idle_tbd,
            "-dead_strip_dylibs",
            "-l",
            "greet",
        ],
        &obj,
    );
    let names = dylib_names(&image);
    println!("needed: {names:?}");
    assert!(
        names.contains(&"@rpath/libidle.tbd".to_string()),
        "the needed dylib survives the drop"
    );
    assert!(
        verify(&image, &opts_strict).is_ok(&opts_strict),
        "the needed image verifies strict"
    );

    // Face 4 — the framework form: the mark resolves through the `-F`
    // search (the M23 pattern).
    let image = link(
        &dir,
        "hello_needed_fw",
        &[
            "-L",
            &lib_dir,
            "-F",
            &lib_dir,
            "-needed_framework",
            "Idle",
            "-dead_strip_dylibs",
            "-l",
            "greet",
        ],
        &obj,
    );
    let names = dylib_names(&image);
    println!("needed framework: {names:?}");
    assert!(
        names.contains(&"@rpath/Idle.framework/Idle".to_string()),
        "the needed framework rides the drop"
    );

    // Face 5 — the `-l` form: the basename rides the `-L` search with
    // the mark (ld64's `-needed-l<name>`).
    let image = link(
        &dir,
        "hello_needed_l",
        &[
            "-L",
            &lib_dir,
            "-needed-l",
            "idle",
            "-dead_strip_dylibs",
            "-l",
            "greet",
        ],
        &obj,
    );
    let names = dylib_names(&image);
    println!("needed-l: {names:?}");
    assert!(
        names.contains(&"@rpath/libidle.tbd".to_string()),
        "the -needed-l dylib rides the drop"
    );

    // The refusal: the relocatable output carries no load commands —
    // the mark has nothing to keep (the M42 refusal shape, the parse
    // surface's conflict rendered as miette help text).
    let argv: Vec<OsString> = [
        "-o".to_string(),
        dir.join("hello_reloc.o").display().to_string(),
        "-r".to_string(),
        "-L".to_string(),
        lib_dir.clone(),
        "-needed_library".to_string(),
        idle_tbd.clone(),
        obj.display().to_string(),
    ]
    .iter()
    .map(OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the relocatable output refuses the mark"),
        Err(err) => {
            eprintln!("\nthe refusal:");
            eprintln!("{err}");
        }
    }

    println!("\nneeded_library_link: ok");
}

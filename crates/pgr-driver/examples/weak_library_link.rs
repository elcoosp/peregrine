//! The weak-library consumer example: ld64's `-weak_library <path>` /
//! `-weak_framework <name>` — the whole dylib loads weakly
//! (`LC_LOAD_WEAK_DYLIB`) and every bind to it is weak (dyld looks the
//! symbol up at launch and survives its absence with NULL), the
//! `MH_BINDS_TO_WEAK` header flag read back, the strict verifier on the
//! image, and the weak-load command walked (the house consumer-example
//! convention).
//!
//! Run: `cargo run -p pgr-driver --example weak_library_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::path::PathBuf;

/// hello.o: `_main` BLs `_greet` — one external bind into the weak
/// dylib.
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

/// A `libgreet.tbd` stub exporting `_greet` under `dir`.
fn greet_tbd(dir: &std::path::Path) -> PathBuf {
    let tbd = dir.join("libgreet.tbd");
    std::fs::write(
        &tbd,
        "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: @rpath/libgreet.tbd\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _greet ]\n...\n",
    )
    .unwrap();
    tbd
}

/// The image's dylib commands: `(opcode, install name)` in order.
fn dylib_commands(image: &[u8]) -> Vec<(u32, String)> {
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
            let opcode = u32::from_le_bytes(cmd.bytes[0..4].try_into().expect("the opcode"));
            let d = pgr_format::DylibCommand::parse(cmd.bytes).expect("the dylib command parses");
            let name = d.name(cmd.bytes).expect("the install name reads");
            out.push((
                opcode,
                String::from_utf8_lossy(name)
                    .trim_end_matches('\0')
                    .to_string(),
            ));
        }
    }
    out
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_weak_lib_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
    let _tbd = greet_tbd(&dir);
    let lib_dir = dir.display().to_string();

    let link = |out: &str, extra: &[&str]| -> Vec<u8> {
        let mut argv: Vec<String> = vec!["-o".into(), dir.join(out).display().to_string()];
        argv.extend(extra.iter().map(std::string::ToString::to_string));
        argv.push(obj.display().to_string());
        let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
        let o = opts::parse(&argv).expect("the argv parses");
        pgr_driver::run(&o).expect("the link runs");
        std::fs::read(dir.join(out)).expect("the image reads")
    };

    // The plain face: `LC_LOAD_DYLIB` (the strong load).
    let plain = link("hello_plain", &["-L", &lib_dir, "-l", "greet"]);
    let cmds = dylib_commands(&plain);
    println!("plain: {cmds:?}");
    assert_eq!(
        cmds[0].0,
        pgr_format::consts::LC_LOAD_DYLIB,
        "the plain load rides the strong command"
    );

    // The weak face: `-weak_library` — `LC_LOAD_WEAK_DYLIB` (dyld
    // survives the dylib's absence with NULL binds) and the image's
    // `MH_BINDS_TO_WEAK` flag word.
    let weak = link(
        "hello_weak",
        &[
            "-L",
            &lib_dir,
            "-weak_library",
            &dir.join("libgreet.tbd").display().to_string(),
        ],
    );
    let cmds = dylib_commands(&weak);
    println!("weak: {cmds:?}");
    assert_eq!(
        cmds[0].0,
        pgr_format::consts::LC_LOAD_WEAK_DYLIB,
        "the weak load rides LC_LOAD_WEAK_DYLIB"
    );
    let hflags = u32::from_le_bytes(weak[24..28].try_into().expect("flags word"));
    assert!(
        hflags & pgr_format::consts::MH_BINDS_TO_WEAK != 0,
        "the weak bind sets MH_BINDS_TO_WEAK"
    );

    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    assert!(
        verify(&weak, &opts_strict).is_ok(&opts_strict),
        "the weak-loading image verifies strict"
    );

    println!("\nweak_library_link: ok");
}

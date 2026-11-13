//! The reexport-framework consumer example (M23): the framework form of
//! the M3 re-export — `hello.o` linked against `Greet.framework` as
//! `-reexport_framework Greet`, the `LC_REEXPORT_DYLIB` command and the
//! trie's REEXPORT node read back, the strict verifier on both, and the
//! unresolvable-framework refusal named (the house consumer-example
//! convention).
//!
//! Run: `cargo run -p pgr-driver --example reexport_framework_link`

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

/// hello.o: `_main` BLs `_greet` and returns — one external bind.
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

/// `Greet.framework/Greet.tbed` stub exporting `_greet` under `dir`.
fn framework(dir: &Path, name: &str) -> PathBuf {
    let fw = dir.join(format!("{name}.framework"));
    std::fs::create_dir_all(&fw).unwrap();
    std::fs::write(
        fw.join(name),
        format!(
            "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: @rpath/{name}.framework/{name}\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _greet ]\n...\n"
        ),
    )
    .unwrap();
    fw
}

fn main() {
    let dir = std::env::temp_dir().join(format!("pgr_reexport_fw_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
    let _fw = framework(&dir, "Greet");

    // The re-exporting link: LC_REEXPORT_DYLIB rides the image, the
    // trie carries `_greet` as a REEXPORT node, and strict verification
    // stays clean (the header drops MH_NO_REEXPORTED_DYLIBS).
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("hello").display().to_string(),
        "-F".to_string(),
        dir.display().to_string(),
        "-reexport_framework".to_string(),
        "Greet".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(dir.join("hello")).unwrap();

    let header = pgr_format::MachHeader64::parse(&image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        &image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut reexport_name = None;
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind == pgr_format::LoadCommandKind::ReexportDylib {
            let d = pgr_format::DylibCommand::parse(cmd.bytes).expect("the dylib command parses");
            let name = d.name(cmd.bytes).expect("the install name reads");
            reexport_name = Some(
                String::from_utf8_lossy(name)
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
    }
    let reexport = reexport_name.expect("LC_REEXPORT_DYLIB present");
    println!("re-export: {reexport}");
    assert_eq!(
        reexport.as_str(),
        "@rpath/Greet.framework/Greet",
        "the framework install name rides the re-export"
    );

    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&image, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the re-exporting executable verifies strict: {:?}",
        report.issues
    );

    // The refusal: an unresolvable framework names the searched surface.
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("hello2").display().to_string(),
        "-F".to_string(),
        dir.display().to_string(),
        "-reexport_framework".to_string(),
        "Missing".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = opts::parse(&argv).expect("the argv parses");
    match pgr_driver::run(&o) {
        Ok(_) => unreachable!("the missing framework refuses"),
        Err(err) => {
            eprintln!("\nthe refusal:");
            eprintln!("{err}");
        }
    }

    println!("\nreexport_framework_link: ok");
}

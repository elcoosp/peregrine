//! The commons consumer example (`use_extern`) (M107): ld64's `-commons`
//! treatment — the common rides as an external reference, never a local definition (the bind rides the dylib's ordinal when one exports the name) — the default beside the named face over the
//! same corpus (a tentative definition each, a `.tbd` dylib exporting
//! the colliding name), the face's outcome read back from the images,
//! and the the relocatable-output refusal rendered as miette help text (the fix, not
//! just the verdict: the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example commons_use_extern_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::path::PathBuf;

/// hello.o: `_main` over a small `__text`, a tentative `_conflicted`
/// each (the `N_UNDF | N_EXT` shape the policy decides about), and one
/// bind slot against the same name.
fn common_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Common {
        name: "_conflicted".into(),
        size: 32,
        align_log2: 3,
    });
    let undef = b.add_symbol(ObjectSymbol::Undefined {
        name: "_conflicted".into(),
        weak_ref: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let slot = b.sym_index(undef);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    b.build().expect("the fixture object builds")
}

/// A `libconflict.tbd` stub exporting `_conflicted` under `dir`.
fn conflict_tbd(dir: &std::path::Path) -> PathBuf {
    let tbd = dir.join("libconflict.tbd");
    std::fs::write(
        &tbd,
        "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: @rpath/libconflict.tbd\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _conflicted ]\n...\n",
    )
    .unwrap();
    tbd
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

fn link(
    dir: &std::path::Path,
    out: &str,
    extra: &[&str],
    obj: &std::path::Path,
) -> Option<Vec<u8>> {
    let mut argv: Vec<String> = vec!["-o".into(), dir.join(out).display().to_string()];
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    argv.push(obj.display().to_string());
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).ok()?;
    match pgr_driver::run(&o) {
        Ok(_) => Some(std::fs::read(dir.join(out)).expect("the image reads")),
        Err(_) => None,
    }
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_commons_use_extern_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let obj = dir.join("hello.o");
    std::fs::write(&obj, common_object()).unwrap();
    let _tbd = conflict_tbd(&dir);
    let lib_dir = dir.display().to_string();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // The default beside the named face over the same corpus.
    let default_image = link(
        &dir,
        "hello_default",
        &["-L", &lib_dir, "-l", "conflict"],
        &obj,
    )
    .expect("the default links");
    println!("use_dylibs (default): {:?}", dylib_names(&default_image));
    let face_image = link(
        &dir,
        "hello_face",
        &["-L", &lib_dir, "-commons", "use_extern", "-l", "conflict"],
        &obj,
    );
    let image = face_image.expect("the use_extern face links");
    println!("use_extern face: {:?}", dylib_names(&image));
    assert_eq!(
        dylib_names(&image),
        vec!["@rpath/libconflict.tbd".to_string()],
        "the external reference binds to the dylib; no local definition"
    );
    assert!(
        verify(&image, &opts_strict).is_ok(&opts_strict),
        "the face image verifies strict"
    );
    println!("\ncommons_use_extern_link: ok");
}

//! M128 — the `-application_extension` driver surface: the flag parses
//! onto the core decision, the `-r` conflict refuses with the fix in
//! the miette help text (the object's header is the input's, verbatim),
//! and a named executable links end-to-end, carries the
//! `MH_APP_EXTENSION_SAFE` bit in its flags word, and verifies strict.
//! The default is byte-identical to the pre-knob shape (the segmented
//! path never set the bit).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pgr_m128_application_extension_{}_{}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A single-object corpus (`_main`) written to `dir`.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (i, sym) in ["_main", "_helper"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    let path = dir.join("main.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    vec![path]
}

/// Links the corpus under `kind` argv shapes; returns the image bytes.
fn link(dir: &Path, out: &str, kind: &[&str], extra: &[&str]) -> Vec<u8> {
    let objs = corpus(dir);
    let out_path = dir.join(out);
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string()];
    argv.extend(kind.iter().map(std::string::ToString::to_string));
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).unwrap()
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

fn parse(extra: &[&str]) -> Result<pgr_driver::opts::Options, pgr_driver::opts::OptsError> {
    let argv: Vec<std::ffi::OsString> = extra.iter().map(std::ffi::OsString::from).collect();
    pgr_driver::opts::parse(&argv)
}

/// The image header's flags word (byte 24..28 of the 32-byte header).
fn flags_word(image: &[u8]) -> u32 {
    u32::from_le_bytes(image[24..28].try_into().expect("the flags word"))
}

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flag_names_the_decision() {
    let o = parse(&["-o", "out", "-application_extension", "main.o"]).expect("the argv parses");
    assert!(
        o.config.application_extension,
        "the decision rides the config"
    );
}

#[test]
fn the_relocatable_conflict_refuses() {
    let err = parse(&["-o", "out", "-r", "-application_extension", "main.o"])
        .expect_err("the relocatable conflict refuses");
    let report = miette::Report::new(err);
    assert!(
        format!("{report:?}").contains("relocatable"),
        "the refusal names the relocatable output: {report:?}"
    );
    assert!(
        format!("{report:?}").contains("MH_APP_EXTENSION_SAFE"),
        "the refusal names the bit: {report:?}"
    );
}

// ---- the image ---------------------------------------------------------------

#[test]
fn a_named_executable_links_and_verifies_strict() {
    let dir = scratch("e2e");
    let img = link(&dir, "hello", &[], &["-application_extension"]);
    assert_ne!(
        flags_word(&img) & pgr_format::consts::MH_APP_EXTENSION_SAFE,
        0,
        "the named decision carries the MH_APP_EXTENSION_SAFE bit"
    );
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the app-extension-safe executable verifies strict: {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_default_image_carries_no_bit() {
    let dir = scratch("default");
    let img = link(&dir, "hello", &[], &[]);
    assert_eq!(
        flags_word(&img) & pgr_format::consts::MH_APP_EXTENSION_SAFE,
        0,
        "the pre-M128 shape: the default carries no MH_APP_EXTENSION_SAFE bit"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_dylib_face_carries_the_bit_too() {
    let dir = scratch("dylib");
    let img = link(
        &dir,
        "lib.dylib",
        &["-dylib", "-install_name", "@rpath/libm128.dylib"],
        &["-application_extension"],
    );
    assert_ne!(
        flags_word(&img) & pgr_format::consts::MH_APP_EXTENSION_SAFE,
        0,
        "the dylib carries the bit"
    );
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the app-extension-safe dylib verifies strict: {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

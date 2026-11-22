//! M127 — the `-interposable` driver surface: the flag parses onto the
//! core decision, the output-kind conflicts (executable, bundle, `-r`)
//! refuse with the fix in the miette help text, and a named dylib links
//! end-to-end, carries the `MH_WEAK_DEFINES | MH_BINDS_TO_WEAK` bits in
//! its flags word, and verifies strict. The default (the off face) is
//! byte-identical to the pre-knob shape (the bits are off by default on
//! a no-weak-define dylib).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pgr_m127_interposable_{}_{}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A single-object corpus (`_main` exported) written to `dir`.
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

/// Links the corpus as a dylib (or the named kind) under `extra` argv;
/// returns the image bytes.
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

const INTERPOSE_BITS: u32 =
    pgr_format::consts::MH_WEAK_DEFINES | pgr_format::consts::MH_BINDS_TO_WEAK;

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flag_names_the_decision() {
    let o = parse(&[
        "-o",
        "out",
        "-dylib",
        "-install_name",
        "@rpath/lib.dylib",
        "-interposable",
        "main.o",
    ])
    .expect("the argv parses");
    assert!(o.config.interposable, "the decision rides the config");
}

#[test]
fn the_output_kind_conflicts_refuse() {
    // An executable, a bundle and the relocatable output all refuse —
    // interposability is a dylib's property.
    for (argv, label) in [
        (vec!["-o", "out"], "executable"),
        (vec!["-o", "out", "-bundle"], "bundle"),
        (vec!["-o", "out", "-r"], "relocatable"),
    ] {
        let mut argv = argv;
        argv.extend(["-interposable", "main.o"]);
        let err = parse(&argv).expect_err("the output kind refuses");
        let report = miette::Report::new(err);
        assert!(
            format!("{report:?}").contains(label),
            "the refusal names the output kind ({label}): {report:?}"
        );
    }
}

// ---- the image ---------------------------------------------------------------

#[test]
fn a_named_dylib_links_and_verifies_strict() {
    let dir = scratch("e2e");
    let img = link(
        &dir,
        "lib.dylib",
        &["-dylib", "-install_name", "@rpath/libm127.dylib"],
        &["-interposable"],
    );
    assert_eq!(
        flags_word(&img) & INTERPOSE_BITS,
        INTERPOSE_BITS,
        "the named decision carries both interpose bits"
    );
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the interposable dylib verifies strict: {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_default_dylib_carries_no_interpose_bits() {
    let dir = scratch("default");
    let img = link(
        &dir,
        "lib.dylib",
        &["-dylib", "-install_name", "@rpath/libm127.dylib"],
        &[],
    );
    assert_eq!(
        flags_word(&img) & INTERPOSE_BITS,
        0,
        "the pre-M127 shape: the default carries no interpose bits"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_off_face_is_byte_identical_to_the_default() {
    // The off face names the default (the bits are off either way on a
    // no-weak-define dylib) — the byte-identity lock.
    let dir = scratch("byte_identity");
    let default = link(
        &dir,
        "default.dylib",
        &["-dylib", "-install_name", "@rpath/libm127.dylib"],
        &[],
    );
    // The off face is the default spelling: there's no `-no_interposable`
    // (the decision is one-byte, the default is off), so a re-link with
    // the same argv reproduces byte-identical bytes (determinism lock).
    let again = link(
        &dir,
        "again.dylib",
        &["-dylib", "-install_name", "@rpath/libm127.dylib"],
        &[],
    );
    assert_eq!(default, again, "the double link is stable (the off face)");
    let _ = std::fs::remove_dir_all(&dir);
}

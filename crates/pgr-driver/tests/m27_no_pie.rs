//! M27 — the `-no_pie` driver surface: the flag parses onto the core
//! decision, refuses where the output kind cannot carry the bit
//! (`MH_PIE` is an executable-only flag — the kernel loads a dylib or
//! a bundle itself), and a non-PIE executable links end-to-end,
//! carries the cleared bit and verifies strict (the strict contract
//! reads the decision, not a constant).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m27_pie_{}_{}", tag, std::process::id()));
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
fn header_flags(image: &[u8]) -> u32 {
    u32::from_le_bytes(image[24..28].try_into().expect("flags word"))
}

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flag_names_the_decision() {
    let o = parse(&["-o", "out", "-no_pie", "main.o"]).expect("the argv parses");
    assert!(o.config.no_pie, "the decision rides the config");
}

#[test]
fn the_conflicts_name_the_output_kind() {
    // A dylib's or a bundle's loader is the kernel itself — `MH_PIE`
    // is an executable-only bit; the fix names the shapes (the miette
    // render carries it).
    for (argv, label) in [
        (vec!["-o", "out", "-dylib"], "dylib"),
        (vec!["-o", "out", "-bundle"], "bundle"),
        (vec!["-o", "out", "-r"], "relocatable"),
    ] {
        let mut argv = argv;
        argv.extend(["-no_pie", "main.o"]);
        let err = parse(&argv).expect_err("the knob refuses off an executable");
        let report = miette::Report::new(err);
        assert!(
            format!("{report:?}").contains("executable-only"),
            "the refusal names the executable-only bit ({label}): {report:?}"
        );
    }
}

// ---- the image ---------------------------------------------------------------

#[test]
fn a_non_pie_executable_links_and_verifies_strict() {
    let dir = scratch("e2e");
    let img = link(&dir, "hello", &[], &["-no_pie"]);
    assert_eq!(
        header_flags(&img) & pgr_format::consts::MH_PIE,
        0,
        "the named decision drops MH_PIE"
    );
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the non-PIE executable verifies strict: {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_default_image_carries_mh_pie() {
    let dir = scratch("default");
    let img = link(&dir, "hello", &[], &[]);
    assert_eq!(
        header_flags(&img) & pgr_format::consts::MH_PIE,
        pgr_format::consts::MH_PIE,
        "the pre-M27 shape: every default executable is PIE"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

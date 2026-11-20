//! M102 — the `-bind_at_load`/`-no_bind_at_load` driver surface: the
//! flag pair parses onto the core decision (the last flag wins),
//! refuses where the output kind cannot carry the bit
//! (`MH_BINDATLOAD` is an executable-only flag — dyld binds the exec'd
//! main executable's undefineds before `main` runs, the
//! `dlopen(RTLD_NOW)` contract), and a bind-at-load executable links
//! end-to-end, carries the set bit and verifies strict (the strict
//! contract reads the decision, not a constant). The default keeps
//! every pre-knob link byte-identical.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m102_bind_{}_{}", tag, std::process::id()));
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
fn the_flag_pair_names_the_decision_last_flag_wins() {
    let o = parse(&["-o", "out", "-bind_at_load", "main.o"]).expect("the argv parses");
    assert!(o.config.bind_at_load, "the positive face sets the decision");
    let o = parse(&["-o", "out", "-bind_at_load", "-no_bind_at_load", "main.o"])
        .expect("the argv parses");
    assert!(
        !o.config.bind_at_load,
        "-no_bind_at_load drops the decision (the last flag wins)"
    );
    let o = parse(&["-o", "out", "-no_bind_at_load", "-bind_at_load", "main.o"])
        .expect("the argv parses");
    assert!(
        o.config.bind_at_load,
        "a later -bind_at_load re-sets the decision (the last flag wins)"
    );
}

#[test]
fn the_conflicts_name_the_output_kind() {
    // A dylib's or a bundle's loader is the kernel itself and the
    // relocatable output carries no loader semantics —
    // `MH_BINDATLOAD` is an executable-only bit; the fix names the
    // shapes (the miette render carries it).
    for (argv, label) in [
        (vec!["-o", "out", "-dylib"], "dylib"),
        (vec!["-o", "out", "-bundle"], "bundle"),
        (vec!["-o", "out", "-r"], "relocatable"),
    ] {
        let mut argv = argv;
        argv.extend(["-bind_at_load", "main.o"]);
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
fn a_bind_at_load_executable_links_and_verifies_strict() {
    let dir = scratch("e2e");
    let img = link(&dir, "hello", &[], &["-bind_at_load"]);
    assert_eq!(
        header_flags(&img) & pgr_format::consts::MH_BINDATLOAD,
        pgr_format::consts::MH_BINDATLOAD,
        "the named decision sets MH_BINDATLOAD"
    );
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the bind-at-load executable verifies strict: {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_classic_opcode_path_carries_the_bit_end_to_end() {
    let dir = scratch("classic");
    let img = link(&dir, "hello", &[], &["-bind_at_load", "-no_fixup_chains"]);
    assert_eq!(
        header_flags(&img) & pgr_format::consts::MH_BINDATLOAD,
        pgr_format::consts::MH_BINDATLOAD,
        "the bit is header-level, not fixup-level"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_default_image_carries_no_bind_at_load_bit() {
    let dir = scratch("default");
    let img = link(&dir, "hello", &[], &[]);
    assert_eq!(
        header_flags(&img) & pgr_format::consts::MH_BINDATLOAD,
        0,
        "the pre-M102 shape: no default executable binds at load"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

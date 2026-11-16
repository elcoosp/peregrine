//! M52 — the `-no_dead_strip_inits_and_terms` driver surface: the flag
//! parses onto the core decision, the term routines survive a
//! `-dead_strip` relink end-to-end, the default keeps the pre-M52
//! bytes, and the knob verifies strict on both shapes (the strict
//! contract reads the decision, not a constant).

use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m52_inits_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// The corpus: main.o (the entry) + routines.o (an unreferenced
/// initializer and terminator with their pointer sections), written to
/// `dir`.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut main = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = main.add_section(ObjectSection::text(
        "__text",
        [0xD65F_03C0u32.to_le_bytes()].concat(),
        vec![],
    ));
    main.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });

    let mut routines = ObjectBuilder::new("routines.o").set_subsections_via_symbols(true);
    let rtext = routines.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    let init_sym = routines.add_symbol(ObjectSymbol::Defined {
        name: "_init_fn".into(),
        section_index: rtext,
        value: 0,
        weak: false,
    });
    let term_sym = routines.add_symbol(ObjectSymbol::Defined {
        name: "_term_fn".into(),
        section_index: rtext,
        value: 4,
        weak: false,
    });
    let modinit = routines.add_section(ObjectSection::data(
        "__mod_init_func",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(init_sym as u32).at(0)],
    ));
    routines.section_mut(modinit).flags = pgr_format::consts::S_MOD_INIT_FUNC_POINTERS;
    let modterm = routines.add_section(ObjectSection::data(
        "__mod_term_func",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(term_sym as u32).at(0)],
    ));
    routines.section_mut(modterm).flags = pgr_format::consts::S_MOD_TERM_FUNC_POINTERS;

    let mut paths = Vec::new();
    for (name, b) in [("main.o", main), ("routines.o", routines)] {
        let path = dir.join(name);
        std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
        paths.push(path);
    }
    paths
}

/// Links the corpus; returns the image bytes.
fn link(dir: &Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let objs = corpus(dir);
    let out_path = dir.join(out);
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string()];
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

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flag_names_the_decision() {
    let o = parse(&[
        "-o",
        "out",
        "-dead_strip",
        "-no_dead_strip_inits_and_terms",
        "main.o",
    ])
    .expect("the argv parses");
    assert!(
        o.config.no_dead_strip_inits_and_terms,
        "the decision rides the config"
    );
    assert!(o.config.dead_strip, "the decision prices the strip");
}

#[test]
fn the_flag_composes_with_the_other_lanes() {
    // No output-kind conflict: the knob parses beside the relocatable
    // output (the decision is inert there — the M41/M43/M47 shape) and
    // beside the fast paths.
    for extra in [
        vec!["-r"],
        vec!["-dead_strip", "-incremental"],
        vec!["-cache", "cache-dir"],
    ] {
        let mut argv = vec!["-o", "out"];
        argv.extend(&extra);
        argv.push("-no_dead_strip_inits_and_terms");
        argv.push("main.o");
        let o = parse(&argv).expect("the argv parses");
        assert!(
            o.config.no_dead_strip_inits_and_terms,
            "the decision rides beside {extra:?}"
        );
    }
}

// ---- the image ---------------------------------------------------------------

#[test]
fn the_default_strips_the_term_routine() {
    let dir = scratch("default");
    let img = link(&dir, "hello", &["-dead_strip"]);
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the pre-M52 shape verifies strict: {:?}",
        report.issues
    );
    // The term routine's symtab row is gone (the strip dropped it).
    let needle = b"_term_fn";
    assert!(
        !img.windows(needle.len()).any(|w| w == needle),
        "the unreferenced terminator stripped with the image: {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_knob_keeps_the_term_routine_and_verifies_strict() {
    let dir = scratch("knob");
    let img = link(
        &dir,
        "hello",
        &["-dead_strip", "-no_dead_strip_inits_and_terms"],
    );
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the rooted terminator verifies strict: {:?}",
        report.issues
    );
    let needle = b"_term_fn";
    assert!(
        img.windows(needle.len()).any(|w| w == needle),
        "the termination routine never strips under the knob"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn without_dead_strip_both_shapes_are_byte_identical() {
    let dir = scratch("inert");
    let plain = link(&dir, "hello_plain", &[]);
    let knobbed = link(&dir, "hello_knob", &["-no_dead_strip_inits_and_terms"]);
    assert_eq!(
        plain, knobbed,
        "off the strip the decision never fires — the bytes do not move"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

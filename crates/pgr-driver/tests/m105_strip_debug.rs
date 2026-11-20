//! M105 — the `-S` driver surface: the flag parses onto the core
//! debug-section suppression (the Pass-1 classification's debug shapes:
//! the `__DWARF` segments the sweep always kept out, plus the
//! `__debug_*` / `S_ATTR_DEBUG` sections the segment-name rule misses),
//! refuses where the output kind cannot serve it (the relocatable
//! output's sections are the input's, verbatim — nothing to strip), and
//! an `-S` executable links end-to-end with the debug pieces, their
//! symtab entries and the `LC_FUNCTION_STARTS` / `LC_DATA_IN_CODE`
//! commands gone, still verifying strict (debug metadata is a
//! dyld-consumed surface, never a format defect). The default keeps
//! every pre-knob link byte-identical.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::{S_ATTR_DEBUG, S_REGULAR};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m105_strip_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A corpus with debug shapes: an `S_ATTR_DEBUG` `__debug_info` section
/// inside `__TEXT`, a `__DWARF,__debug_info` section, function starts
/// and data-in-code inputs.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    let debug_sect = b.add_section(ObjectSection {
        name: "__debug_info".into(),
        segment: "__TEXT".into(),
        align_log2: 0,
        flags: S_ATTR_DEBUG,
        data: vec![0xAA; 16],
        relocs: vec![],
    });
    let _dwarf = b.add_section(ObjectSection {
        name: "__debug_info".into(),
        segment: "__DWARF".into(),
        align_log2: 0,
        flags: S_REGULAR,
        data: vec![0xBB; 8],
        relocs: vec![],
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::LocalDefined {
        name: "_debug_local".into(),
        section_index: debug_sect,
        value: 0,
    });
    let b = b.set_data_in_code(vec![pgr_format::DataInCodeEntry {
        offset: 0,
        length: 4,
        kind: 1,
    }]);
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

/// True when the image header carries `kind` (a `LC_LINKEDIT_DATA`).
fn carries_linkedit_data(image: &[u8], kind: u32) -> bool {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::LinkeditData(k) = cmd.kind
            && k == kind
        {
            return true;
        }
    }
    false
}

// ---- the surface ---------------------------------------------------------------

#[test]
fn the_flag_names_the_suppression() {
    let o = parse(&["-o", "out", "main.o"]).expect("the argv parses");
    assert!(
        !o.config.strip_debug,
        "the default strips nothing (the pre-M105 shape)"
    );
    let o = parse(&["-o", "out", "-S", "main.o"]).expect("the argv parses");
    assert!(o.config.strip_debug, "-S names the suppression");
}

#[test]
fn the_relocatable_output_refuses_the_s_face() {
    // The relocatable output's sections are the input's, verbatim: the
    // suppression has nothing to apply to (the surface's knob refusal —
    // the miette render carries the fix).
    let err =
        parse(&["-o", "out", "-r", "-S", "main.o"]).expect_err("the relocatable output refuses -S");
    let report = miette::Report::new(err);
    let rendered = format!("{report:?}");
    assert!(
        rendered.contains("-S"),
        "the refusal names the flag: {rendered}"
    );
    assert!(
        rendered.contains("verbatim") || rendered.contains("relocatable"),
        "the refusal names the contract: {rendered}"
    );
}

// ---- the image -----------------------------------------------------------------

#[test]
fn the_default_image_carries_the_debug_free_shape_nothing() {
    let dir = scratch("default");
    let img = link(&dir, "hello", &[], &[]);
    assert!(
        carries_linkedit_data(&img, pgr_format::consts::LC_FUNCTION_STARTS),
        "the default plans LC_FUNCTION_STARTS (the precondition)"
    );
    assert!(
        carries_linkedit_data(&img, pgr_format::consts::LC_DATA_IN_CODE),
        "the default plans LC_DATA_IN_CODE (the precondition)"
    );
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the default verifies strict: {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_s_executable_links_verifies_strict_and_drops_the_debug_shape() {
    let dir = scratch("s");
    let default = link(&dir, "hello_default", &[], &[]);
    let stripped = link(&dir, "hello_stripped", &[], &["-S"]);
    assert!(
        !carries_linkedit_data(&stripped, pgr_format::consts::LC_FUNCTION_STARTS),
        "-S drops LC_FUNCTION_STARTS"
    );
    assert!(
        !carries_linkedit_data(&stripped, pgr_format::consts::LC_DATA_IN_CODE),
        "-S drops LC_DATA_IN_CODE"
    );
    assert!(
        stripped.len() < default.len(),
        "the debug pieces leave the file ({} < {})",
        stripped.len(),
        default.len()
    );
    let report = verify(&stripped, &strict());
    assert!(
        report.is_ok(&strict()),
        "the stripped image verifies strict (debug metadata is a dyld-consumed \
         surface, never a format defect): {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_s_face_composes_with_no_function_starts_end_to_end() {
    let dir = scratch("compose");
    let stripped = link(&dir, "hello_s", &[], &["-S"]);
    let composed = link(&dir, "hello_s_nf", &[], &["-S", "-no_function_starts"]);
    assert_eq!(
        stripped, composed,
        "-S plans the -no_function_starts shape for the command it suppresses"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

//! M53 — the `-rename_section` driver surface: the four-argument flag
//! parses onto the core decision (`LinkConfig::renames`), the value
//! grammar the core seam pays refuses at parse (the miette render
//! carries the fix — names over the Mach-O 16-byte field width, a
//! doubled source, a synthetic target), and a renamed link runs
//! end-to-end: the image's `LC_SEGMENT_64` section entries carry the
//! new `(segname, sectname)` pair and verify strict. The default keeps
//! the pre-M53 shape, and the relocatable output never reads the
//! decision (its section table is the input's, verbatim).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m53_rename_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A two-section corpus (`__DATA,__mydata` + `__TEXT,__text`, `_main`
/// exported) written to `dir`.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__mydata", vec![0x41u8; 16], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_mydata_sym".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    let path = dir.join("main.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    vec![path]
}

/// Links the corpus with `extra` argv; returns the image bytes.
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

/// The `(segname, sectname)` pairs the image's `LC_SEGMENT_64` entries
/// record, in command order.
fn section_pairs(image: &[u8]) -> Vec<(String, String)> {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut pairs = Vec::new();
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            let seg_name = seg.name().expect("the segment name reads").to_string();
            let sections = seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .expect("the sections parse");
            for sect in sections {
                let name_end = sect
                    .sectname
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(sect.sectname.len());
                pairs.push((
                    seg_name.clone(),
                    String::from_utf8_lossy(&sect.sectname[..name_end]).into_owned(),
                ));
            }
        }
    }
    pairs
}

// ---- the surface ---------------------------------------------------------------

#[test]
fn the_flag_names_the_decision() {
    let o = parse(&[
        "-o",
        "out",
        "-rename_section",
        "__DATA",
        "__mydata",
        "__DATA_CONST",
        "__mydata",
        "main.o",
    ])
    .expect("the argv parses");
    assert_eq!(
        o.config.renames.len(),
        1,
        "the rename rides the config table"
    );
}

#[test]
fn a_name_over_the_16_byte_field_width_refuses_with_the_fix() {
    let long = "___________seventeen";
    let err = parse(&[
        "-o",
        "out",
        "-rename_section",
        "__DATA",
        "__mydata",
        "__DATA",
        long,
        "main.o",
    ])
    .expect_err("the over-wide name refuses");
    let report = miette::Report::new(err);
    assert!(
        format!("{report:?}").contains("16"),
        "the refusal names the 16-byte field width: {report:?}"
    );
}

#[test]
fn a_rename_into_a_synthetic_target_refuses_with_the_fix() {
    let err = parse(&[
        "-o",
        "out",
        "-rename_section",
        "__DATA",
        "__mydata",
        "__TEXT",
        "__unwind_info",
        "main.o",
    ])
    .expect_err("the synthetic target refuses");
    let report = miette::Report::new(err);
    assert!(
        format!("{report:?}").contains("__unwind_info"),
        "the refusal names the synthetic target: {report:?}"
    );
}

// ---- the image -----------------------------------------------------------------

#[test]
fn a_renamed_link_carries_the_new_section_entry_and_verifies_strict() {
    let dir = scratch("e2e");
    let img = link(
        &dir,
        "hello",
        &[],
        &[
            "-rename_section",
            "__DATA",
            "__mydata",
            "__DATA_CONST",
            "__mydata",
        ],
    );
    let pairs = section_pairs(&img);
    assert!(
        pairs.contains(&("__DATA_CONST".to_string(), "__mydata".to_string())),
        "the renamed section entry rides the image: {pairs:?}"
    );
    assert!(
        !pairs.contains(&("__DATA".to_string(), "__mydata".to_string())),
        "the old pair is gone: {pairs:?}"
    );
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the renamed image verifies strict: {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_default_image_carries_the_input_names() {
    let dir = scratch("default");
    let img = link(&dir, "hello", &[], &[]);
    let pairs = section_pairs(&img);
    assert!(
        pairs.contains(&("__DATA".to_string(), "__mydata".to_string())),
        "the pre-M53 shape: the input names ride unnamed: {pairs:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_relocatable_output_never_reads_the_decision() {
    // `-r` carries the input's section table verbatim — the rename
    // decision never reads there (the M41/M43/M47 shape), so both links
    // plan identical bytes.
    let a = link(
        &scratch("r1"),
        "out1",
        &["-r"],
        &[
            "-rename_section",
            "__DATA",
            "__mydata",
            "__DATA_CONST",
            "__mydata",
        ],
    );
    let b = link(&scratch("r2"), "out2", &["-r"], &[]);
    assert_eq!(
        a, b,
        "the relocatable output is identical under either decision"
    );
}

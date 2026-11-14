//! M29 — the `-headerpad` driver surface: the flag the surface carried
//! as an advisory no-op since M1 parses onto the core decision, the
//! grammar refusals render as miette help text (the fix, not just the
//! verdict), the relocatable conflict refuses at `finish`, and a
//! padded executable links end-to-end with the raised boundary and
//! verifies strict.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("pgr_m29_headerpad_{}_{}", tag, std::process::id()));
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

/// The first `__TEXT` section's file offset (from the `section_64` row).
fn first_text_offset(image: &[u8]) -> u32 {
    let header = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            if seg.name() == Ok("__TEXT") {
                let sects = seg
                    .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                    .expect("the sections parse");
                return sects
                    .first()
                    .expect("the text segment carries a section")
                    .offset;
            }
        }
    }
    unreachable!("a segmented image carries a __TEXT section")
}

// ---- the surface ---------------------------------------------------------------

#[test]
fn the_flag_names_the_floor() {
    let o = parse(&["-o", "out", "-headerpad", "0x2000", "main.o"]).expect("the argv parses");
    let floor = o.config.header_pad.expect("the decision rides the config");
    assert_eq!(floor.floor_bytes(), 0x2000);
}

#[test]
fn the_grammar_refusals_render_the_fix() {
    for (argv, needle) in [
        (
            vec!["-o", "out", "-headerpad", "0", "main.o"],
            // Wrap-safe needles: miette folds the help text, so a
            // multi-word needle can split across lines.
            "absence",
        ),
        (
            vec!["-o", "out", "-headerpad", "0x2001", "main.o"],
            "multiple",
        ),
        (
            vec!["-o", "out", "-headerpad", "0x8000", "main.o"],
            "0x4000",
        ),
    ] {
        let err = parse(&argv).expect_err("the grammar refuses");
        let report = miette::Report::new(err);
        assert!(
            format!("{report:?}").contains(needle),
            "the refusal names the fix ({needle}): {report:?}"
        );
    }
}

#[test]
fn the_relocatable_conflict_refuses_at_finish() {
    let err = parse(&["-o", "out", "-r", "-headerpad", "0x2000", "main.o"])
        .expect_err("the relocatable output refuses the knob");
    let report = miette::Report::new(err);
    let rendered = format!("{report:?}");
    assert!(
        rendered.contains("relocatable"),
        "the verdict names the output kind: {rendered}"
    );
    assert!(
        rendered.contains("drop -headerpad"),
        "the help names the fix: {rendered}"
    );
}

// ---- the image -----------------------------------------------------------------

#[test]
fn a_padded_executable_links_and_verifies_strict() {
    let dir = scratch("e2e");
    let img = link(&dir, "hello", &[], &["-headerpad", "0x2000"]);
    let offset = first_text_offset(&img);
    assert_eq!(
        u64::from(offset),
        0x2000,
        "the first section sits past the named floor"
    );
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the padded executable verifies strict: {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_default_image_plans_the_natural_region() {
    let dir = scratch("default");
    let img = link(&dir, "hello", &[], &[]);
    let offset = first_text_offset(&img);
    assert!(
        offset < 0x2000,
        "the pre-M29 shape: the natural header region rides ({offset})"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

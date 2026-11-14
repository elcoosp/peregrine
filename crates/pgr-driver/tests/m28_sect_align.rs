//! M28 — the `-sectalign` driver surface: the flag parses onto the core
//! decision table, the grammar refusals render as miette help text (the
//! fix, not just the verdict), the relocatable conflict refuses at
//! `finish`, and a floored executable links end-to-end with the raised
//! boundary and verifies strict.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("pgr_m28_sectalign_{}_{}", tag, std::process::id()));
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
    b.add_section(ObjectSection::data("__data", vec![0xAA; 8], vec![]));
    b.add_section(ObjectSection::data("__more", vec![0x55; 12], vec![]));
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

/// The image's `section_64` rows: `(segment, section, addr, align)`.
fn sections_of(image: &[u8]) -> Vec<(String, String, u64, u32)> {
    let header = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut out = Vec::new();
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
            for s in seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .expect("the sections parse")
            {
                out.push((
                    seg.name().expect("utf8 segment").to_string(),
                    s.name().expect("utf8 section").to_string(),
                    s.addr,
                    s.align,
                ));
            }
        }
    }
    out
}

// ---- the surface ---------------------------------------------------------------

#[test]
fn the_flag_names_the_floor() {
    let o = parse(&[
        "-o",
        "out",
        "-sectalign",
        "__DATA",
        "__data",
        "0x4000",
        "main.o",
    ])
    .expect("the argv parses");
    let floors: Vec<_> = o.config.sect_aligns.iter().collect();
    assert_eq!(floors.len(), 1, "the decision rides the config");
    assert_eq!(floors[0].segment().name(), "__DATA");
    assert_eq!(floors[0].section(), "__data");
    assert_eq!(floors[0].align_log2(), 14);
}

#[test]
fn the_grammar_refusals_render_the_fix() {
    for (argv, needle) in [
        (
            vec![
                "-o",
                "out",
                "-sectalign",
                "__FOO",
                "__data",
                "0x1000",
                "main.o",
            ],
            "planned segments",
        ),
        (
            vec![
                "-o",
                "out",
                "-sectalign",
                "__DATA",
                "__data",
                "3000",
                "main.o",
            ],
            "power of two",
        ),
        (
            vec![
                "-o",
                "out",
                "-sectalign",
                "__DATA",
                "__data",
                "0x8000",
                "main.o",
            ],
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
    let err = parse(&[
        "-o",
        "out",
        "-r",
        "-sectalign",
        "__DATA",
        "__data",
        "0x1000",
        "main.o",
    ])
    .expect_err("the relocatable output refuses the knob");
    let report = miette::Report::new(err);
    let rendered = format!("{report:?}");
    assert!(
        rendered.contains("relocatable"),
        "the verdict names the output kind: {rendered}"
    );
    assert!(
        rendered.contains("drop -sectalign"),
        "the help names the fix: {rendered}"
    );
}

// ---- the image -----------------------------------------------------------------

#[test]
fn a_floored_executable_links_and_verifies_strict() {
    let dir = scratch("e2e");
    let img = link(
        &dir,
        "hello",
        &[],
        &["-sectalign", "__DATA", "__data", "0x4000"],
    );
    let secs = sections_of(&img);
    let data = secs
        .iter()
        .find(|(seg, name, _, _)| seg == "__DATA" && name == "__data")
        .expect("the named section exists");
    assert_eq!(data.3, 14, "the image carries the raised exponent");
    assert_eq!(data.2 % 0x4000, 0, "the address lands on the boundary");
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the floored executable verifies strict: {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_default_image_plans_the_input_alignments() {
    let dir = scratch("default");
    let img = link(&dir, "hello", &[], &[]);
    let secs = sections_of(&img);
    let data = secs
        .iter()
        .find(|(seg, name, _, _)| seg == "__DATA" && name == "__data")
        .expect("the data section exists");
    assert_eq!(data.3, 3, "the pre-M28 shape: the input alignment rides");
    let _ = std::fs::remove_dir_all(&dir);
}

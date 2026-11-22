//! M124 — the `-seg1addr` driver surface: the flag parses onto the
//! core decision, the value validates against the core seam's grammar
//! (a non-zero multiple of the 16 KiB arm64 page), the output-kind
//! conflicts (bundles, `-r`) and the one-base-per-kind overlaps
//! (`-seg1addr` beside `-pagezero_size` or `-image_base`) refuse with
//! the fix in the miette help text, and a named-base executable links
//! end-to-end, carries the shifted `__PAGEZERO` vmsize and `__TEXT`
//! vmaddr, and verifies strict (the strict contract reads the shifted
//! shape, not a constant).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("pgr_m124_seg1addr_{}_{}", tag, std::process::id()));
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

/// The `(vmaddr, vmsize)` of a named segment in the image header.
fn segment(image: &[u8], name: &str) -> (u64, u64) {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands walk");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            if seg.name() == Ok(name) {
                return (seg.vmaddr, seg.vmsize);
            }
        }
    }
    panic!("the {name} segment is present");
}

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flag_names_the_decision() {
    let o = parse(&["-o", "out", "-seg1addr", "0x40000000", "main.o"]).expect("the argv parses");
    assert_eq!(
        o.config.seg1addr.map(pgr_core::Seg1Addr::vmaddr),
        Some(0x4000_0000),
        "the decision rides the config"
    );
}

#[test]
fn the_invalid_value_names_the_grammar() {
    // A misaligned base and a non-numeric value both refuse with the
    // grammar (the same validation the core seam pays — the help names
    // the 16 KiB page).
    for bad in ["0x3000", "bogus", "0"] {
        let err = parse(&["-o", "out", "-seg1addr", bad, "main.o"]).expect_err("the value refuses");
        let report = miette::Report::new(err);
        assert!(
            format!("{report:?}").contains("16 KiB") || format!("{report:?}").contains("seg1addr"),
            "the refusal names the grammar ({bad}): {report:?}"
        );
    }
}

#[test]
fn the_output_kind_conflicts_name_the_shape() {
    // A bundle's preferred load address is its loader's job; the
    // relocatable output carries no segments — the fix names the shapes
    // (the miette render carries it).
    for (argv, label) in [
        (vec!["-o", "out", "-bundle"], "bundle"),
        (vec!["-o", "out", "-r"], "relocatable"),
    ] {
        let mut argv = argv;
        argv.extend(["-seg1addr", "0x40000000", "main.o"]);
        let err = parse(&argv).expect_err("the knob refuses the output kind");
        let report = miette::Report::new(err);
        assert!(
            format!("{report:?}").contains(label),
            "the refusal names the output kind ({label}): {report:?}"
        );
    }
}

#[test]
fn the_one_base_per_kind_overlap_refuses() {
    // `-seg1addr` beside `-pagezero_size` (an executable) or
    // `-image_base` (a dylib) names the same `__TEXT` floor twice — the
    // overlap refuses with the fix.
    let err = parse(&[
        "-o",
        "out",
        "-seg1addr",
        "0x40000000",
        "-pagezero_size",
        "0x80000000",
        "main.o",
    ])
    .expect_err("the executable overlap refuses");
    let report = miette::Report::new(err);
    assert!(
        format!("{report:?}").contains("one base"),
        "the refusal names the overlap: {report:?}"
    );
    let err = parse(&[
        "-o",
        "out",
        "-dylib",
        "-install_name",
        "@rpath/lib.dylib",
        "-seg1addr",
        "0x60000",
        "-image_base",
        "0x80000",
        "main.o",
    ])
    .expect_err("the dylib overlap refuses");
    let report = miette::Report::new(err);
    assert!(
        format!("{report:?}").contains("one base"),
        "the refusal names the overlap: {report:?}"
    );
}

// ---- the image ---------------------------------------------------------------

#[test]
fn a_named_base_executable_links_and_verifies_strict() {
    let dir = scratch("e2e");
    let img = link(&dir, "hello", &[], &["-seg1addr", "0x40000000"]);
    let (pz_vmaddr, pz_vmsize) = segment(&img, "__PAGEZERO");
    let (text_vmaddr, _) = segment(&img, "__TEXT");
    assert_eq!(pz_vmaddr, 0, "__PAGEZERO.vmaddr stays 0");
    assert_eq!(pz_vmsize, 0x4000_0000, "the named floor");
    assert_eq!(text_vmaddr, 0x4000_0000, "__TEXT.vmaddr == the named floor");
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the named-base executable verifies strict: {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_default_image_carries_the_constant_delta_floor() {
    let dir = scratch("default");
    let img = link(&dir, "hello", &[], &[]);
    let (_, pz_vmsize) = segment(&img, "__PAGEZERO");
    let (text_vmaddr, _) = segment(&img, "__TEXT");
    assert_eq!(pz_vmsize, 0x1_0000_0000, "the pre-M124 4 GiB constant");
    assert_eq!(text_vmaddr, 0x1_0000_0000, "the constant-delta floor");
    let _ = std::fs::remove_dir_all(&dir);
}

//! M104 — the `-keep_local_symbols` / `-x` driver surface: the flag
//! pair parses onto the core symtab-shaping decision (the last flag
//! wins — ld64's symtab knob, the other half of the local-symbol
//! contract M33 named the filter-hidden shape of), refuses where the
//! output kind cannot serve it (the relocatable output's symtab is the
//! input's, verbatim — nothing to shape), and an `-x` executable links
//! end-to-end with the locals subrange emptied and verifies strict
//! (local symbols are a dyld-consumed surface, never a format defect —
//! the verifier's symtab contract reads both faces). The default keeps
//! every pre-knob link byte-identical.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::LoadCommandKind;
use pgr_format::MachHeader64;
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m104_locals_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A corpus with locals: `_main` exported, `_local_fn` a
/// section-defined static (the `N_SECT` without `N_EXT` shape) and
/// `local_abs` a name-only local — both in the default symtab's
/// locals subrange.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::LocalDefined {
        name: "_local_fn".into(),
        section_index: text,
        value: 8,
    });
    b.add_symbol(ObjectSymbol::Local("local_abs".into()));
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

/// The output image's dysymtab subrange counts.
fn subranges(image: &[u8]) -> (u32, u32, u32, u32) {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::Dysymtab = cmd.kind {
            let d =
                pgr_format::DysymtabCommand::parse(image, cmd.offset).expect("the dysymtab parses");
            return (d.ilocalsym, d.nlocalsym, d.iextdefsym, d.nextdefsym);
        }
    }
    panic!("no LC_DYSYMTAB in the linked image");
}

// ---- the surface ---------------------------------------------------------------

#[test]
fn the_flag_pair_names_the_decision_last_flag_wins() {
    let o = parse(&["-o", "out", "main.o"]).expect("the argv parses");
    assert!(
        o.config.keep_local_symbols,
        "the default keeps the locals subrange (the pre-M104 shape)"
    );
    let o = parse(&["-o", "out", "-x", "main.o"]).expect("the argv parses");
    assert!(!o.config.keep_local_symbols, "-x names the drop face");
    let o = parse(&["-o", "out", "-x", "-keep_local_symbols", "main.o"]).expect("the argv parses");
    assert!(
        o.config.keep_local_symbols,
        "a later -keep_local_symbols re-sets the decision (the last flag wins)"
    );
    let o = parse(&["-o", "out", "-keep_local_symbols", "-x", "main.o"]).expect("the argv parses");
    assert!(
        !o.config.keep_local_symbols,
        "a later -x re-sets the decision (the last flag wins)"
    );
}

#[test]
fn the_relocatable_output_refuses_the_drop_face() {
    // The relocatable output's symtab is the input's, verbatim: the
    // drop face has nothing to shape (the surface's knob refusal —
    // the miette render carries the fix).
    let err =
        parse(&["-o", "out", "-r", "-x", "main.o"]).expect_err("the relocatable output refuses -x");
    let report = miette::Report::new(err);
    let rendered = format!("{report:?}");
    assert!(
        rendered.contains("-x"),
        "the refusal names the drop face: {rendered}"
    );
    assert!(
        rendered.contains("verbatim") || rendered.contains("relocatable"),
        "the refusal names the contract: {rendered}"
    );
    // The keep face is the default's mirror — it never refuses.
    parse(&["-o", "out", "-r", "-keep_local_symbols", "main.o"])
        .expect("the named keep rides the relocatable surface");
}

// ---- the image -----------------------------------------------------------------

#[test]
fn the_default_image_keeps_the_locals_range() {
    let dir = scratch("default");
    let img = link(&dir, "hello", &[], &[]);
    let (ilocal, nlocal, iextdef, _) = subranges(&img);
    assert_eq!(nlocal, 2, "the two plain locals ride the subrange");
    assert_eq!(ilocal, 0, "the locals subrange starts at 0");
    assert_eq!(iextdef, nlocal, "the extdef range follows the locals");
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the kept face verifies strict: {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_x_executable_links_verifies_strict_and_empties_the_range() {
    let dir = scratch("x");
    let img = link(&dir, "hello", &[], &["-x"]);
    let (_ilocal, nlocal, iextdef, nextdef) = subranges(&img);
    assert_eq!(nlocal, 0, "-x empties the locals subrange");
    assert_eq!(iextdef, 0, "the extdef range starts where the locals ended");
    assert!(nextdef >= 1, "_main rides the extdef range");
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the dropped face verifies strict (local symbols are a dyld-consumed \
         surface, never a format defect): {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_named_keep_links_byte_identical_to_the_default() {
    let dir = scratch("keep");
    let default = link(&dir, "hello_default", &[], &[]);
    let kept = link(&dir, "hello_kept", &[], &["-keep_local_symbols"]);
    assert_eq!(
        default, kept,
        "-keep_local_symbols is the default's mirror: the same bytes"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_x_image_is_strictly_narrower_than_the_default() {
    let dir = scratch("shrink");
    let default = link(&dir, "hello_default", &[], &[]);
    let dropped = link(&dir, "hello_dropped", &[], &["-x"]);
    assert!(
        dropped.len() < default.len(),
        "the dropped face plans a narrower image ({} < {})",
        dropped.len(),
        default.len()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

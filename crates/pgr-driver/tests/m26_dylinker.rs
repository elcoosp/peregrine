//! M26 — the `-dylinker <path>` driver surface: the flag parses onto
//! the validated core decision, refuses where the output kind cannot
//! carry the command (`LC_LOAD_DYLINKER` is the main-executable
//! command — the §8.2 loader-configuration adjacency), and a configured
//! executable links end-to-end and verifies strict (the named loader
//! rides the emitted image before `LC_MAIN`).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m26_loader_{}_{}", tag, std::process::id()));
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

/// The image's `LC_LOAD_DYLINKER` names (there is at most one).
fn loader_names(image: &[u8]) -> Vec<String> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut rows = Vec::new();
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::LoadDylinker {
            let off = u32::from_le_bytes(cmd.bytes[8..12].try_into().expect("lc_str")) as usize;
            let tail = &cmd.bytes[off..];
            let end = tail.iter().position(|&b| b == 0).expect("terminated");
            rows.push(String::from_utf8_lossy(&tail[..end]).into_owned());
        }
    }
    rows
}

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flag_names_the_loader() {
    let o = parse(&["-o", "out", "-dylinker", "/usr/local/bin/mydyld", "main.o"])
        .expect("the argv parses");
    let named = o
        .config
        .dylinker
        .as_ref()
        .map(pgr_core::Dylinker::path)
        .expect("the decision rides the config");
    assert_eq!(named, "/usr/local/bin/mydyld");
    // One decision per link: the later flag replaces the earlier (the
    // `Option` the seam rides).
    let o = parse(&[
        "-o",
        "out",
        "-dylinker",
        "/usr/lib/dyld",
        "-dylinker",
        "/usr/local/bin/mydyld",
        "main.o",
    ])
    .expect("the argv parses");
    assert_eq!(
        o.config
            .dylinker
            .as_ref()
            .map(pgr_core::Dylinker::path)
            .expect("the decision rides"),
        "/usr/local/bin/mydyld",
        "the last decision wins"
    );
}

#[test]
fn refusals_name_the_grammar() {
    // Empty: the default IS the absence of the knob — the grammar
    // rides the miette help (the house convention).
    let err = parse(&["-o", "out", "-dylinker", "", "main.o"]).expect_err("empty refuses");
    let report = miette::Report::new(err);
    assert!(format!("{report:?}").contains("empty"), "{report:?}");
    // NUL: the lc_str is a C string.
    let err =
        parse(&["-o", "out", "-dylinker", "/usr/bin/dy\0ld", "main.o"]).expect_err("NUL refuses");
    let report = miette::Report::new(err);
    assert!(format!("{report:?}").contains("NUL"), "{report:?}");
    // Relative: the kernel resolves the loader path from the process
    // root at exec time.
    let err =
        parse(&["-o", "out", "-dylinker", "bin/dyld", "main.o"]).expect_err("relative refuses");
    let report = miette::Report::new(err);
    assert!(
        format!("{report:?}").contains("absolute") && format!("{report:?}").contains("bin/dyld"),
        "{report:?}"
    );
}

#[test]
fn the_conflicts_name_the_output_kind() {
    // A dylib's loader is the kernel itself — no LC_LOAD_DYLINKER to
    // land on; the fix rides the miette help.
    for (argv, label) in [
        (vec!["-o", "out", "-dylib"], "dylib"),
        (vec!["-o", "out", "-bundle"], "bundle"),
        (vec!["-o", "out", "-r"], "relocatable"),
    ] {
        let mut argv = argv;
        argv.extend(["-dylinker", "/usr/local/bin/mydyld", "main.o"]);
        let err = parse(&argv).expect_err("the knob refuses off an executable");
        let report = miette::Report::new(err);
        assert!(
            format!("{report:?}").contains(label),
            "the refusal names the output kind ({label}): {report:?}"
        );
        assert!(
            format!("{report:?}").contains("executable"),
            "the refusal names where the command lands: {report:?}"
        );
    }
}

// ---- the image ---------------------------------------------------------------

#[test]
fn a_configured_executable_links_and_verifies_strict() {
    let dir = scratch("e2e");
    let img = link(&dir, "hello", &[], &["-dylinker", "/usr/local/bin/mydyld"]);
    // The named loader rides the emitted image — exactly one command.
    assert_eq!(
        loader_names(&img),
        ["/usr/local/bin/mydyld"],
        "the named loader lands in the image"
    );
    // And the image verifies strict: the loader-path contract accepts
    // a configured executable exactly like the default one.
    let report = verify(&img, &strict());
    assert!(
        report.is_ok(&strict()),
        "the configured executable verifies strict: {:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_default_image_carries_usr_lib_dyld() {
    let dir = scratch("default");
    let img = link(&dir, "hello", &[], &[]);
    assert_eq!(
        loader_names(&img),
        ["/usr/lib/dyld"],
        "the default names the loader it always named"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

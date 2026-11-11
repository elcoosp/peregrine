//! M20 — the `-sub_umbrella` / `-sub_library` driver surface: the flags
//! parse repeatable onto the validated core table, refuse where the
//! output kind cannot carry the region (the umbrella commands are a
//! dylib's identity block), and an umbrella dylib links end-to-end and
//! verifies strict (the region rides the emitted image).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m20_umbrella_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A single-object corpus (`_main`, `_umb_fn`) written to `dir`.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut b = ObjectBuilder::new("umb.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (i, sym) in ["_main", "_umb_init", "_umb_read"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    let path = dir.join("umb.o");
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

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flags_parse_repeatable_onto_the_table() {
    let o = parse(&[
        "-o",
        "out",
        "-dylib",
        "-install_name",
        "@rpath/libumb.dylib",
        "-sub_umbrella",
        "libsub.dylib",
        "-sub_library",
        "liblegacy.dylib",
        "-sub_umbrella",
        "libsub2.dylib",
        "umb.o",
    ])
    .expect("the argv parses");
    let names: Vec<(&str, &str)> = o
        .config
        .umbrella
        .iter()
        .map(|m| (m.kind().as_str(), m.name()))
        .collect();
    assert_eq!(
        names,
        [
            ("sub-umbrella", "libsub.dylib"),
            ("sub-library", "liblegacy.dylib"),
            ("sub-umbrella", "libsub2.dylib"),
        ],
        "the flags land in command order"
    );
}

#[test]
fn an_invalid_name_refuses_at_parse() {
    let err = parse(&["-o", "out", "-dylib", "-sub_umbrella", "", "umb.o"])
        .expect_err("an empty member refuses");
    // The fix rides the miette help (the house convention): render the
    // report, not just the verdict line.
    let report = miette::Report::new(err);
    assert!(
        format!("{report:?}").contains("non-empty"),
        "the refusal names the fix: {report:?}"
    );
}

#[test]
fn the_kind_conflicts_refuse_with_the_fix() {
    for (kind, label) in [
        (vec!["-o", "out"], "executable"),
        (vec!["-o", "out", "-bundle"], "bundle"),
        (vec!["-o", "out", "-r"], "relocatable"),
    ] {
        let mut argv = kind.clone();
        argv.extend(["-sub_umbrella", "libsub.dylib", "umb.o"]);
        let err = parse(&argv).expect_err("the knob refuses off a dylib");
        let report = miette::Report::new(err);
        assert!(
            format!("{report:?}").contains(label),
            "the refusal names the output kind ({label}): {report:?}"
        );
        assert!(
            format!("{report:?}").contains("dylib"),
            "the refusal names where the knob lands: {report:?}"
        );
    }
}

// ---- end to end --------------------------------------------------------------

#[test]
fn an_umbrella_dylib_links_and_verifies_strict() {
    let dir = scratch("e2e");
    let image = link(
        &dir,
        "libumb.dylib",
        &["-dylib", "-install_name", "@rpath/libumb.dylib"],
        &[
            "-sub_umbrella",
            "libsub.dylib",
            "-sub_library",
            "liblegacy.dylib",
        ],
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the umbrella dylib verifies strict: {:?}",
        report.issues
    );
    // The image carries both commands with the named members.
    let header = pgr_format::MachHeader64::parse(&image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        &image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut seen = Vec::new();
    while let Some(cmd) = it.next_command().expect("the chain walks") {
        if matches!(
            cmd.kind,
            pgr_format::LoadCommandKind::SubUmbrella | pgr_format::LoadCommandKind::SubLibrary
        ) {
            let off = u32::from_le_bytes(cmd.bytes[8..12].try_into().expect("lc_str")) as usize;
            let name = String::from_utf8_lossy(&cmd.bytes[off..]).to_string();
            let name = name.trim_end_matches('\0').to_string();
            seen.push((cmd.hdr().0, name));
        }
    }
    assert_eq!(
        seen,
        [
            (
                pgr_format::consts::LC_SUB_UMBRELLA,
                "libsub.dylib".to_string()
            ),
            (
                pgr_format::consts::LC_SUB_LIBRARY,
                "liblegacy.dylib".to_string()
            ),
        ],
        "both region commands ride the image"
    );
}

#[test]
fn a_default_dylib_carries_no_region_commands() {
    let dir = scratch("default");
    let image = link(
        &dir,
        "libplain.dylib",
        &["-dylib", "-install_name", "@rpath/libplain.dylib"],
        &[],
    );
    let header = pgr_format::MachHeader64::parse(&image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        &image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    while let Some(cmd) = it.next_command().expect("the chain walks") {
        assert!(
            !matches!(
                cmd.kind,
                pgr_format::LoadCommandKind::SubUmbrella | pgr_format::LoadCommandKind::SubLibrary
            ),
            "the pre-M20 shape carries no region commands"
        );
    }
}

//! M31 — the `-no_function_starts` driver surface: the flag the
//! surface carried as a no-op since M1 parses onto the core
//! suppression decision, a corpus links end-to-end with the
//! `LC_FUNCTION_STARTS` command present (default) and absent (the
//! suppression — one 16-byte command narrower), and both images
//! verify strict.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m31_fs_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A single-object corpus (`_main` over three RET functions).
fn corpus(dir: &Path, tag: &str) -> PathBuf {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (i, sym) in ["_main", "_fn_1", "_fn_2"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    let path = dir.join(format!("main_{tag}.o"));
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// Links `obj` under `extra` argv; returns the image bytes.
fn link(dir: &Path, out: &str, obj: &Path, extra: &[&str]) -> Vec<u8> {
    let out_path = dir.join(out);
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string()];
    argv.push(obj.display().to_string());
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

/// True when the image carries `LC_FUNCTION_STARTS`.
fn has_function_starts(image: &[u8]) -> bool {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::LinkeditData(pgr_format::consts::LC_FUNCTION_STARTS) = cmd.kind {
            return true;
        }
    }
    false
}

// ---- the flag ------------------------------------------------------------------

#[test]
fn the_flag_names_the_suppression() {
    let dir = scratch("flag");
    let obj = corpus(&dir, "flag");
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("out").display().to_string(),
        "-no_function_starts".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = pgr_driver::opts::parse(&argv).expect("the flag parses");
    assert!(
        !o.config.function_starts,
        "the flag parses onto the suppression decision"
    );
    let default_argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("out_default").display().to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    assert!(
        pgr_driver::opts::parse(&default_argv)
            .expect("the default surface parses")
            .config
            .function_starts,
        "the default carries the stream"
    );
}

// ---- the end-to-end shapes -------------------------------------------------------

#[test]
fn the_default_link_carries_the_command_and_verifies_strict() {
    let dir = scratch("carry");
    let obj = corpus(&dir, "carry");
    let image = link(&dir, "hello_fs", &obj, &[]);
    assert!(
        has_function_starts(&image),
        "the default plans the pre-M31 command"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the carrying image verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_suppressed_link_drops_the_command_and_verifies_strict() {
    let dir = scratch("drop");
    let obj = corpus(&dir, "drop");
    let carrying = link(&dir, "hello_carry", &obj, &[]);
    let image = link(&dir, "hello_plain", &obj, &["-no_function_starts"]);
    assert!(
        !has_function_starts(&image),
        "the suppression drops the command end-to-end"
    );
    assert_eq!(
        usize::try_from(
            MachHeader64::parse(&carrying).expect("parses").sizeofcmds
                - MachHeader64::parse(&image).expect("parses").sizeofcmds
        )
        .unwrap(),
        16,
        "the suppression is one 16-byte command narrower in sizeofcmds"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the suppressed image verifies strict like the default one: {:?}",
        report.issues
    );
}

//! M32 — the `-no_uuid` driver surface: the flag the surface carried
//! as a no-op since M1 parses onto the core suppression decision, a
//! corpus links end-to-end with the `LC_UUID` command present (the
//! default — the derived 16 bytes non-zero) and absent (the
//! suppression — one 24-byte command narrower), and both images
//! verify strict.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, UuidCommand};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m32_uuid_{}_{}", tag, std::process::id()));
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

/// The image's `LC_UUID` payload when the command rides.
fn uuid_of(image: &[u8]) -> Option<UuidCommand> {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::Uuid = cmd.kind {
            return UuidCommand::parse(cmd.bytes).ok();
        }
    }
    None
}

// ---- the flag ------------------------------------------------------------------

#[test]
fn the_flag_names_the_suppression() {
    let dir = scratch("flag");
    let obj = corpus(&dir, "flag");
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("out").display().to_string(),
        "-no_uuid".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = pgr_driver::opts::parse(&argv).expect("the flag parses");
    assert!(
        o.config.uuid_source == pgr_core::layout::UuidSource::None,
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
    assert_eq!(
        pgr_driver::opts::parse(&default_argv)
            .expect("the default surface parses")
            .config
            .uuid_source,
        pgr_core::layout::UuidSource::Content,
        "the default derives the UUID"
    );
}

// ---- the end-to-end shapes -------------------------------------------------------

#[test]
fn the_default_link_carries_the_derived_uuid_and_verifies_strict() {
    let dir = scratch("carry");
    let obj = corpus(&dir, "carry");
    let image = link(&dir, "hello_uuid", &obj, &[]);
    let uuid = uuid_of(&image).expect("the default plans the LC_UUID command");
    assert_ne!(
        uuid.uuid, [0u8; 16],
        "the emit derives the UUID from the page hashes — never zero in the output"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the carrying image verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_suppressed_link_drops_the_uuid_and_verifies_strict() {
    let dir = scratch("drop");
    let obj = corpus(&dir, "drop");
    let carrying = link(&dir, "hello_carry", &obj, &[]);
    let image = link(&dir, "hello_plain", &obj, &["-no_uuid"]);
    assert!(
        uuid_of(&image).is_none(),
        "the suppression drops the command end-to-end"
    );
    assert_eq!(
        usize::try_from(
            MachHeader64::parse(&carrying).expect("parses").sizeofcmds
                - MachHeader64::parse(&image).expect("parses").sizeofcmds
        )
        .unwrap(),
        24,
        "the suppression is one 24-byte command narrower in sizeofcmds"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the suppressed image verifies strict like the default one: {:?}",
        report.issues
    );
}

//! M30 — the `-no_data_in_code` driver surface: the flag the surface
//! accepted as a no-op since M1 parses onto the core suppression
//! decision, an entry-carrying corpus links end-to-end with the
//! `LC_DATA_IN_CODE` command present (and verifies strict), the
//! suppression links without it, and the incremental relink of an
//! entry-carrying image stays byte-identical to the full link (the
//! link record's `__LINKEDIT` plan carries the new chunk).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m30_dice_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// An entry-carrying corpus (`_main` over three RET functions, one
/// data-in-code entry per function).
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
    let b = b.set_data_in_code(
        (0..3)
            .map(|f| pgr_format::DataInCodeEntry {
                offset: (f * 4) as u32,
                length: 4,
                kind: 1,
            })
            .collect(),
    );
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

/// True when the image carries `LC_DATA_IN_CODE`.
fn has_dice(image: &[u8]) -> bool {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::LinkeditData(pgr_format::consts::LC_DATA_IN_CODE) = cmd.kind {
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
        "-no_data_in_code".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = pgr_driver::opts::parse(&argv).expect("the flag parses");
    assert!(
        !o.config.data_in_code,
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
            .data_in_code,
        "the default carries the metadata"
    );
}

// ---- the end-to-end shapes -------------------------------------------------------

#[test]
fn an_entry_carrying_link_carries_the_command_and_verifies_strict() {
    let dir = scratch("carry");
    let obj = corpus(&dir, "carry");
    let image = link(&dir, "hello_dice", &obj, &[]);
    assert!(
        has_dice(&image),
        "the carriage lands the LC_DATA_IN_CODE command"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the carrying image verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_suppressed_link_drops_the_command() {
    let dir = scratch("drop");
    let obj = corpus(&dir, "drop");
    let image = link(&dir, "hello_plain", &obj, &["-no_data_in_code"]);
    assert!(
        !has_dice(&image),
        "the suppression drops the command end-to-end"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the suppressed image verifies strict like the default one: {:?}",
        report.issues
    );
}

// ---- the incremental relink ------------------------------------------------------

#[test]
fn the_incremental_relink_freezes_the_entry_carrying_skeleton() {
    // The house incremental gates (M9): the first link records, an
    // unchanged relink is a reported noop (0 bytes patched), the
    // skeleton is frozen (the file size never moves), and the
    // relinked image still carries the data-in-code command — the
    // record v6 `__LINKEDIT` plan rides the chunk like every other.
    let dir = scratch("inc");
    let obj = corpus(&dir, "inc");
    let out = dir.join("hello_inc");
    let inc_argv = |_dir: &Path, out: &Path, obj: &Path| {
        let argv: Vec<String> = vec![
            "-o".into(),
            out.display().to_string(),
            obj.display().to_string(),
            "-incremental".into(),
        ];
        let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
        pgr_driver::opts::parse(&argv).expect("the argv parses")
    };
    pgr_driver::run(&inc_argv(&dir, &out, &obj)).expect("the recording link runs");
    let first = std::fs::read(&out).unwrap();
    assert!(has_dice(&first), "the recorded image carries the command");
    let second = pgr_driver::run(&inc_argv(&dir, &out, &obj)).expect("the relink runs");
    let patch = second.patch.expect("the relink goes through the engine");
    assert!(patch.untouched, "identical inputs touch nothing");
    assert_eq!(patch.bytes_patched, 0, "the noop ships no bytes");
    let relinked = std::fs::read(&out).unwrap();
    assert_eq!(
        relinked.len(),
        first.len(),
        "the skeleton is frozen across the relink"
    );
    assert!(
        has_dice(&relinked),
        "the relinked image carries the command"
    );
}

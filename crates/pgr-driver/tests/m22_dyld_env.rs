//! M22 — the `-dyld_env DYLD_<var>=<value>` driver surface: the flag
//! parses repeatable onto the validated core table, refuses where the
//! output kind cannot carry the command (dyld reads
//! `LC_DYLD_ENVIRONMENT` from the main executable only), and a
//! configured executable links end-to-end and verifies strict (the
//! pairs ride the emitted image after `LC_MAIN`).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m22_env_{}_{}", tag, std::process::id()));
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

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flag_parses_repeatable_onto_the_table() {
    let o = parse(&[
        "-o",
        "out",
        "-dyld_env",
        "DYLD_PRINT_LIBRARIES=1",
        "-dyld_env",
        "DYLD_PRINT_RPATHS=1",
        "main.o",
    ])
    .expect("the argv parses");
    let pairs: Vec<&str> = o
        .config
        .dyld_envs
        .iter()
        .map(pgr_core::dyld_env::DyldEnvEntry::pair)
        .collect();
    assert_eq!(
        pairs,
        ["DYLD_PRINT_LIBRARIES=1", "DYLD_PRINT_RPATHS=1"],
        "the flags land in command order"
    );
}

#[test]
fn a_malformed_pair_refuses_at_parse() {
    // No `=` is not a pair — the grammar rides the miette help (the
    // house convention).
    let err = parse(&["-o", "out", "-dyld_env", "DYLD_PRINT_LIBRARIES", "main.o"])
        .expect_err("a pair-less value refuses");
    let report = miette::Report::new(err);
    assert!(
        format!("{report:?}").contains("DYLD_"),
        "the refusal names the grammar: {report:?}"
    );
    // dyld honors `DYLD_`-prefixed variables from this command only.
    let err = parse(&["-o", "out", "-dyld_env", "PATH=/bin", "main.o"])
        .expect_err("a non-DYLD_ variable refuses");
    let report = miette::Report::new(err);
    assert!(
        format!("{report:?}").contains("DYLD_"),
        "the refusal names the grammar: {report:?}"
    );
}

#[test]
fn the_kind_conflicts_refuse_with_the_fix() {
    for (kind, label) in [
        (
            vec!["-o", "out", "-dylib", "-install_name", "@rpath/libm.dylib"],
            "dylib",
        ),
        (vec!["-o", "out", "-bundle"], "bundle"),
        (vec!["-o", "out", "-r"], "relocatable"),
    ] {
        let mut argv = kind.clone();
        argv.extend(["-dyld_env", "DYLD_PRINT_LIBRARIES=1", "main.o"]);
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

// ---- end to end --------------------------------------------------------------

#[test]
fn a_configured_executable_links_and_verifies_strict() {
    let dir = scratch("e2e");
    let image = link(
        &dir,
        "hello",
        &[],
        &[
            "-dyld_env",
            "DYLD_PRINT_LIBRARIES=1",
            "-dyld_env",
            "DYLD_PRINT_RPATHS=1",
        ],
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the configured executable verifies strict: {:?}",
        report.issues
    );
    // The image carries the environment commands after LC_MAIN, with
    // the named pairs.
    let header = pgr_format::MachHeader64::parse(&image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        &image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut seen = Vec::new();
    let mut main_seen = false;
    while let Some(cmd) = it.next_command().expect("the chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::Main {
            main_seen = true;
        }
        if cmd.kind == pgr_format::LoadCommandKind::DyldEnvironment {
            assert!(main_seen, "the environment commands ride after LC_MAIN");
            let off = u32::from_le_bytes(cmd.bytes[8..12].try_into().expect("lc_str")) as usize;
            let pair = String::from_utf8_lossy(&cmd.bytes[off..]).to_string();
            let pair = pair.trim_end_matches('\0').to_string();
            seen.push(pair);
        }
        if cmd.kind == pgr_format::LoadCommandKind::Symtab {
            assert_eq!(
                seen.len(),
                2,
                "both environment commands land before LC_SYMTAB"
            );
        }
    }
    assert_eq!(
        seen,
        ["DYLD_PRINT_LIBRARIES=1", "DYLD_PRINT_RPATHS=1"],
        "the pairs ride the image in flag order"
    );
}

#[test]
fn a_default_executable_carries_no_env_commands() {
    let dir = scratch("default");
    let image = link(&dir, "hello_plain", &[], &[]);
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
            cmd.kind != pgr_format::LoadCommandKind::DyldEnvironment,
            "the pre-M22 shape carries no environment commands"
        );
    }
}

#[test]
fn the_resident_cycle_carries_the_pairs() {
    // One-shot reference.
    let dir = scratch("resident_ref");
    let one_shot = link(
        &dir,
        "hello_ref",
        &[],
        &["-dyld_env", "DYLD_PRINT_LIBRARIES=1"],
    );

    // The same link through the resident path: the daemon relinks with
    // the same config, so the named pairs crossed the wire (v15).
    let dir2 = scratch("resident");
    let sock = dir2.join("pgrd.sock");
    let owned = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(120));
    });
    std::thread::sleep(Duration::from_millis(50));

    let objs = corpus(&dir2);
    let out_path = dir2.join("hello");
    let mut argv = vec![
        "-o".to_string(),
        out_path.display().to_string(),
        "-dyld_env".to_string(),
        "DYLD_PRINT_LIBRARIES=1".to_string(),
        "-resident".to_string(),
        "-resident_socket".to_string(),
        sock.display().to_string(),
    ];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the resident argv parses");
    pgr_driver::run(&o).expect("the resident link runs");
    let resident = std::fs::read(&out_path).unwrap();
    assert_eq!(
        one_shot, resident,
        "the resident cycle plans the same bytes with the named pairs"
    );
}

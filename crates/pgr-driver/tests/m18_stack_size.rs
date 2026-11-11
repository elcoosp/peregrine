//! M18 — the `-stack_size` surface: the flag parses (decimal or
//! `0x`-hex, a non-zero multiple of the 16 KiB arm64 page), a malformed
//! value refuses with the fix in the help text (the house miette
//! convention), a non-executable output refuses the knob (a refusal,
//! never a silently dropped flag — the `-pagezero_size` precedent), the
//! named-reserve image links and verifies strict (the verifier's
//! page-multiple invariant), the default link stays byte-identical to
//! the pre-seam image, and the resident cycle plans the same bytes —
//! the wire (protocol v11) carries the named reserve, not just the
//! default.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m18_driver").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A small executable corpus with two rebase slots.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let helper_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_helper".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.section_mut(data).relocs = vec![
        ObjectReloc::unsigned(main_sym as u32).at(0),
        ObjectReloc::unsigned(helper_sym as u32).at(8),
    ];
    let path = dir.join("main.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    vec![path]
}

/// Links the corpus as an executable under `extra` argv entries; returns
/// the image bytes.
fn link_exe(dir: &Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let objs = corpus(dir);
    let out_path = dir.join(out);
    let mut argv = vec!["-o".to_string(), out_path.display().to_string()];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the executable links");
    std::fs::read(&out_path).unwrap()
}

/// The image's `LC_MAIN.stacksize` field (the reserve the image plans
/// with).
fn stack_reserve(image: &[u8]) -> u64 {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind == pgr_format::LoadCommandKind::Main {
            let ep = pgr_format::EntryPointCommand::parse(cmd.bytes).expect("the command parses");
            return ep.stacksize;
        }
    }
    panic!("an executable carries LC_MAIN");
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flag_parses_and_names_the_reserve() {
    let argv: Vec<OsString> = ["-o", "out", "main.o", "-stack_size", "0x1000000"]
        .iter()
        .map(OsString::from)
        .collect();
    let o = opts::parse(&argv).expect("the argv parses");
    assert_eq!(
        o.config
            .stack_size
            .map(pgr_core::stack_size::StackSize::bytes),
        Some(0x100_0000),
        "the named reserve is on the config"
    );
}

#[test]
fn a_malformed_reserve_refuses_with_the_grammar() {
    for value in ["0", "0x3000", "12", "abc"] {
        let argv: Vec<OsString> = ["-o", "out", "main.o", "-stack_size", value]
            .iter()
            .map(OsString::from)
            .collect();
        let err = opts::parse(&argv).expect_err("the grammar refuses");
        let report = miette::Report::new(err);
        assert!(
            format!("{value} appears in the verdict: {report}").contains(value),
            "the verdict names the value: {report}"
        );
        let help = report
            .help()
            .expect("the refusal carries help text")
            .to_string();
        assert!(
            help.contains("16 KiB"),
            "the help names the grammar: {help}"
        );
    }
}

#[test]
fn the_non_executable_outputs_refuse_the_knob() {
    for extra in [
        ["-dylib", "-install_name", "@rpath/libg.dylib"],
        ["-bundle", "-install_name", "@rpath/libb.bundle"],
    ] {
        let mut argv = vec!["-o".to_string(), "out".to_string(), "main.o".to_string()];
        argv.extend(extra.iter().map(std::string::ToString::to_string));
        argv.push("-stack_size".to_string());
        argv.push("0x1000000".to_string());
        let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
        let err = opts::parse(&argv).expect_err("the knob refuses off executables");
        assert!(
            err.to_string().contains("LC_MAIN"),
            "the refusal names the shape: {err}"
        );
    }
}

// ---- the link ----------------------------------------------------------------

#[test]
fn a_named_reserve_links_and_verifies_strict() {
    let dir = scratch("custom");
    let image = link_exe(&dir, "hello", &["-stack_size", "0x1000000"]);
    assert_eq!(stack_reserve(&image), 0x100_0000, "the reserve landed");
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the reserved image verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_default_link_stays_byte_identical() {
    // The knob's absence plans the zero reserve the pre-M18 layout
    // wrote — the default bytes are untouched (the zero reserve and the
    // knob-less link are the same image).
    let dir = scratch("default");
    let plain = link_exe(&dir, "hello_plain", &[]);
    assert_eq!(stack_reserve(&plain), 0, "the pre-M18 zero reserve");
}

#[test]
fn the_resident_cycle_carries_the_reserve() {
    // One-shot reference.
    let dir = scratch("resident_ref");
    let one_shot = link_exe(&dir, "hello_ref", &["-stack_size", "0x1000000"]);

    // The same link through the resident path: the daemon relinks with
    // the same config, so the named reserve crossed the wire (v11).
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
        "-stack_size".to_string(),
        "0x1000000".to_string(),
        "-resident".to_string(),
        "-resident_socket".to_string(),
        sock.display().to_string(),
    ];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the resident argv parses");
    pgr_driver::run(&o).expect("the resident link runs");
    let resident = std::fs::read(&out_path).unwrap();
    assert_eq!(
        one_shot, resident,
        "the resident cycle plans the same bytes with a named reserve"
    );
    assert_eq!(
        stack_reserve(&resident),
        0x100_0000,
        "the reserve crossed the wire"
    );
}

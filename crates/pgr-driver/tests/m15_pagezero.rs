//! M15 — the `-pagezero_size` surface: the flag parses (decimal or
//! `0x`-hex), a malformed value refuses with the fix in the help text
//! (the house miette convention), a non-executable output refuses the
//! knob (a refusal, never a silently dropped flag — the
//! `-fixup_chains_format` precedent), the custom-base image links and
//! verifies strict (the verifier's generalized segment contract), the
//! default link stays byte-identical to the pre-seam image, and the
//! resident cycle plans the same bytes — the wire (protocol v8) carries
//! the configured base, not just the default.

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
    let dir = std::env::temp_dir().join("pgr_m15_driver").join(format!(
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

/// The first `LC_SEGMENT_64` command's `(name, vmaddr, vmsize, fileoff)`
/// rows.
fn segment_rows(image: &[u8]) -> Vec<(String, u64, u64, u64)> {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut rows = Vec::new();
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the LC parses");
            rows.push((
                seg.name().unwrap_or("<non-utf8>").to_string(),
                seg.vmaddr,
                seg.vmsize,
                seg.fileoff,
            ));
        }
    }
    rows
}

/// Strict verification passes (the driver's own contract gate).
fn strict_ok(image: &[u8]) -> bool {
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    verify(image, &opts).is_ok(&opts)
}

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flag_parses_decimal_and_hex() {
    let dir = scratch("parse");
    let _objs = corpus(&dir);
    for (raw, expect) in [("1073741824", 0x4000_0000u64), ("0x40000000", 0x4000_0000)] {
        let argv = args(&["-o", "out", "-pagezero_size", raw, "main.o"]);
        let o = opts::parse(&argv).expect("the flag parses");
        assert_eq!(o.config.pagezero.vmsize(), expect, "{raw} rides the config");
    }
    let argv = args(&["-o", "out", "-pagezero_size", "0x100000000", "main.o"]);
    let o = opts::parse(&argv).expect("the default spelling parses");
    assert_eq!(o.config.pagezero.vmsize(), 0x1_0000_0000);
}

#[test]
fn malformed_values_refuse_with_the_fix() {
    for raw in ["0", "0x3000", "0x4001", "abc", ""] {
        let argv = args(&["-o", "out", "-pagezero_size", raw, "main.o"]);
        let err = opts::parse(&argv).expect_err("the malformed value refuses");
        let rendered = err.to_string();
        assert!(rendered.contains("-pagezero_size"), "{rendered}");
        assert!(
            rendered.contains(raw),
            "the refusal names the value: {rendered}"
        );
        // The miette help names the grammar (the fix, not the verdict).
        let help = miette::Report::new(err)
            .help()
            .map(|h| h.to_string())
            .unwrap_or_default();
        assert!(
            help.contains("16 KiB"),
            "the help names the alignment rule: {help}"
        );
    }
}

#[test]
fn non_executable_outputs_refuse_the_flag() {
    let dir = scratch("refuse_dylib");
    let objs = corpus(&dir);
    let out_path = dir.join("lib.o");
    let argv = args(&[
        "-o",
        out_path.display().to_string().as_str(),
        "-r",
        "-pagezero_size",
        "0x40000000",
        objs[0].display().to_string().as_str(),
    ]);
    let err = opts::parse(&argv).expect_err("the relocatable link refuses the knob");
    let rendered = err.to_string();
    assert!(rendered.contains("-pagezero_size"), "{rendered}");

    let dir2 = scratch("refuse_dylib2");
    let objs = corpus(&dir2);
    let out_path = dir2.join("libsdk.dylib");
    let argv = args(&[
        "-o",
        out_path.display().to_string().as_str(),
        "-dylib",
        "-install_name",
        "@rpath/libsdk.dylib",
        "-pagezero_size",
        "0x40000000",
        objs[0].display().to_string().as_str(),
    ]);
    let err = opts::parse(&argv).expect_err("the dylib link refuses the knob");
    let rendered = err.to_string();
    assert!(rendered.contains("__PAGEZERO"), "{rendered}");
}

#[test]
fn the_flag_carries_a_value_in_executable_links() {
    // `-pagezero_size 0x4000_0000` names the image base: __PAGEZERO
    // plans the configured vmsize, __TEXT lands on it, and the image
    // verifies strict (the contract is general now, not a constant).
    let dir = scratch("custom");
    let image = link_exe(&dir, "hello", &["-pagezero_size", "0x40000000"]);
    let rows = segment_rows(&image);
    let pz = rows
        .iter()
        .find(|(n, _, _, _)| n == "__PAGEZERO")
        .expect("__PAGEZERO");
    assert_eq!(pz.1, 0, "__PAGEZERO.vmaddr");
    assert_eq!(
        pz.2, 0x4000_0000,
        "__PAGEZERO.vmsize is the configured base"
    );
    let text = rows
        .iter()
        .find(|(n, _, _, _)| n == "__TEXT")
        .expect("__TEXT");
    assert_eq!(text.1, 0x4000_0000, "__TEXT.vmaddr == the base");
    assert_eq!(text.3, 0, "__TEXT.fileoff");
    assert!(
        strict_ok(&image),
        "the custom-base image verifies strict: {rows:?}"
    );
}

#[test]
fn the_default_link_stays_byte_identical() {
    // The seam adds nothing on a clean link: a default-base link and an
    // explicit `-pagezero_size 0x100000000` link plan the same bytes.
    let dir = scratch("identity");
    let implicit = link_exe(&dir, "hello_a", &[]);
    let explicit = link_exe(&dir, "hello_b", &["-pagezero_size", "0x100000000"]);
    assert_eq!(implicit, explicit, "the default is the explicit default");
    // The control: a genuinely moved base does change the bytes.
    let moved = link_exe(&dir, "hello_c", &["-pagezero_size", "0x40000000"]);
    assert_ne!(implicit, moved, "the base is on the image");
}

#[test]
fn the_resident_cycle_carries_the_custom_base() {
    // One-shot reference.
    let dir = scratch("resident_ref");
    let one_shot = link_exe(&dir, "hello_ref", &["-pagezero_size", "0x40000000"]);

    // The same link through the resident path: the daemon relinks with
    // the same config, so the configured base crossed the wire (v8).
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
        "-pagezero_size".to_string(),
        "0x40000000".to_string(),
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
        "the resident cycle plans the same bytes with a custom base"
    );
    let rows = segment_rows(&resident);
    let pz = rows
        .iter()
        .find(|(n, _, _, _)| n == "__PAGEZERO")
        .expect("__PAGEZERO");
    assert_eq!(pz.2, 0x4000_0000, "the base crossed the wire");
}

/// `OsString` argv from `&str` pairs (the house test helper shape).
fn args(pairs: &[&str]) -> Vec<OsString> {
    pairs.iter().map(|s| OsString::from(*s)).collect()
}

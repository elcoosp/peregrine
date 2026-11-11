//! M19 — the `-image_base` surface: the flag parses (decimal or
//! `0x`-hex), validates through the core seam, refuses where the knob
//! cannot land (an executable's base is `__PAGEZERO`'s job — M15; the
//! relocatable output carries no segments), and a named dylib link
//! lands the base end-to-end: one-shot, resident (the wire v12 carries
//! the named base), and strict-verified.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn scratch(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("pgr_m19_image_base_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A single-object corpus (`_main`, `_sdk_init`, `_sdk_read`) linked as
/// a dylib under `extra` argv entries; returns the image bytes.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut b = ObjectBuilder::new("sdk.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (i, sym) in ["_main", "_sdk_init", "_sdk_read"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    let path = dir.join("sdk.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    vec![path]
}

/// Links the corpus as a dylib under `extra` argv entries; returns the
/// image bytes.
fn link_dylib(dir: &Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let objs = corpus(dir);
    let out_path = dir.join(out);
    let mut argv = vec![
        "-o".to_string(),
        out_path.display().to_string(),
        "-dylib".to_string(),
        "-install_name".to_string(),
        "@rpath/libsdk.dylib".to_string(),
    ];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the dylib links");
    std::fs::read(&out_path).unwrap()
}

/// The image's `__TEXT` `(vmaddr, fileoff)` row.
fn text_vmaddr(image: &[u8]) -> (u64, u64) {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    while let Ok(Some(cmd)) = it.next_command().map_err(|e| panic!("{e}")) {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            if seg.name() == Ok("__TEXT") {
                return (seg.vmaddr, seg.fileoff);
            }
        }
    }
    panic!("an image carries __TEXT");
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flag_parses_and_names_the_base() {
    let argv: Vec<std::ffi::OsString> = [
        "-o",
        "out",
        "-dylib",
        "-install_name",
        "@rpath/libm.dylib",
        "sdk.o",
        "-image_base",
        "0x4000",
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    assert_eq!(
        o.config
            .image_base
            .map(pgr_core::image_base::ImageBase::vmaddr),
        Some(0x4000),
        "the named base is on the config"
    );
}

#[test]
fn a_malformed_base_refuses_with_the_grammar() {
    for value in ["0", "0x3000", "12", "abc"] {
        let argv: Vec<std::ffi::OsString> = [
            "-o",
            "out",
            "-dylib",
            "-install_name",
            "@rpath/libm.dylib",
            "sdk.o",
            "-image_base",
            value,
        ]
        .iter()
        .map(std::ffi::OsString::from)
        .collect();
        let err = pgr_driver::opts::parse(&argv).expect_err("the grammar refuses");
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
fn the_unapplyable_outputs_refuse_the_knob() {
    // An executable's constant-delta base is `__PAGEZERO`'s job (M15
    // named `-pagezero_size` for it); the relocatable output carries no
    // segments at all. A named knob that cannot apply is a refusal,
    // never a silently dropped decision.
    let surfaces: [&[&str]; 2] = [&["-image_base", "0x4000"], &["-r", "-image_base", "0x4000"]];
    for extra in surfaces {
        let mut argv = vec!["-o".to_string(), "out".to_string(), "sdk.o".to_string()];
        argv.extend(extra.iter().map(std::string::ToString::to_string));
        let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
        let err = pgr_driver::opts::parse(&argv).expect_err("the knob refuses the shape");
        let text = err.to_string();
        assert!(
            text.contains("executable") || text.contains("relocatable"),
            "the refusal names the shape: {text}"
        );
    }
}

// ---- the link ----------------------------------------------------------------

#[test]
fn a_named_base_links_and_verifies_strict() {
    let dir = scratch("custom");
    let image = link_dylib(&dir, "libm.dylib", &["-image_base", "0x80000"]);
    let (vmaddr, fileoff) = text_vmaddr(&image);
    assert_eq!(fileoff, 0, "__TEXT keeps its file offset");
    assert_eq!(vmaddr, 0x80000, "the named base is the __TEXT vmaddr");
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the named-base dylib verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_default_dylib_stays_at_the_m3_constant() {
    let dir = scratch("default");
    let plain = link_dylib(&dir, "libplain.dylib", &[]);
    assert_eq!(
        text_vmaddr(&plain),
        (0, 0),
        "None keeps the pre-M19 __TEXT.vmaddr == fileoff contract"
    );
}

#[test]
fn a_named_base_double_link_is_byte_identical() {
    let dir = scratch("determinism");
    let a = link_dylib(&dir, "liba.dylib", &["-image_base", "0x80000"]);
    let b = link_dylib(&dir, "libb.dylib", &["-image_base", "0x80000"]);
    assert_eq!(a, b, "TDD §4.3: the deterministic-output lock");
}

#[test]
fn the_resident_cycle_carries_the_base() {
    // One-shot reference.
    let dir = scratch("resident_ref");
    let one_shot = link_dylib(&dir, "libref.dylib", &["-image_base", "0x80000"]);

    // The same link through the resident path: the daemon relinks with
    // the same config, so the named base crossed the wire (v12).
    let dir2 = scratch("resident");
    let sock = dir2.join("pgrd.sock");
    let owned = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(120));
    });
    std::thread::sleep(Duration::from_millis(50));

    let objs = corpus(&dir2);
    let out_path = dir2.join("libm.dylib");
    let mut argv = vec![
        "-o".to_string(),
        out_path.display().to_string(),
        "-dylib".to_string(),
        "-install_name".to_string(),
        "@rpath/libsdk.dylib".to_string(),
        "-image_base".to_string(),
        "0x80000".to_string(),
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
        "the resident cycle plans the same bytes with a named base"
    );
    assert_eq!(
        text_vmaddr(&resident).0,
        0x80000,
        "the base crossed the wire"
    );
}

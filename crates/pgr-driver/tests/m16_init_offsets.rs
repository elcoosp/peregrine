//! M16 — the `-init_offsets` surface: the flag pair parses (the named
//! form and the explicit off), the named form links an executable whose
//! `__mod_init_func` pointers became a `__TEXT,__init_offsets` section
//! of u32 offsets that verifies strict, the default (and the explicit
//! off) stay byte-identical to the pre-seam image, the below-floor
//! target and the relocatable output refuse with the fix in the help
//! text (the house miette convention), and the resident cycle plans the
//! same bytes — the wire (protocol v9) carries the configured form, not
//! just the default.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{S_INIT_FUNC_OFFSETS, S_MOD_INIT_FUNC_POINTERS, SECTION_TYPE_MASK};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SegmentCommand64};
use pgr_verify::{Options as VerifyOptions, verify};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m16_driver").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A small executable corpus: `_main` plus two initializer functions,
/// each targeted by one 8-byte pointer in a `__mod_init_func` section.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (f, name) in ["_main", "_init_one", "_init_two"].into_iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: name.into(),
            section_index: text,
            value: (f * 4) as u64,
            weak: false,
        });
    }
    let modinit = b.add_section(ObjectSection::data(
        "__mod_init_func",
        vec![0u8; 16],
        vec![
            ObjectReloc::unsigned(1).at(0),
            ObjectReloc::unsigned(2).at(8),
        ],
    ));
    b.section_mut(modinit).flags = S_MOD_INIT_FUNC_POINTERS;
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

/// A segment record: `(name, vmaddr, vmsize, fileoff)`.
fn segment_rows(image: &[u8]) -> Vec<(String, u64, u64, u64)> {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands walk");
    let mut rows = Vec::new();
    while let Ok(Some(cmd)) = it.next_command() {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg = SegmentCommand64::parse(cmd.bytes, 0).expect("the LC parses");
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

/// A section record: `(seg, name, flags, addr, size, file_off)`.
fn section_rows(image: &[u8]) -> Vec<(String, String, u32, u64, u64, u64)> {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands walk");
    let mut rows = Vec::new();
    while let Ok(Some(cmd)) = it.next_command() {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg = SegmentCommand64::parse(cmd.bytes, 0).expect("the LC parses");
            let seg_name = seg.name().unwrap_or("<non-utf8>").to_string();
            let sects = seg.sections(cmd.bytes, SegmentCommand64::SIZE).unwrap();
            for s in sects {
                rows.push((
                    seg_name.clone(),
                    s.name().unwrap_or("<non-utf8>").to_string(),
                    s.flags,
                    s.addr,
                    s.size,
                    u64::from(s.offset),
                ));
            }
        }
    }
    rows
}

/// The `__init_offsets` content bytes, if the image carries the section.
fn init_offsets_bytes(image: &[u8]) -> Option<Vec<u8>> {
    section_rows(image)
        .iter()
        .find(|(_, name, _, _, _, _)| name == "__init_offsets")
        .map(|(_, _, _, _, size, off)| image[*off as usize..(*off + *size) as usize].to_vec())
}

/// Strict verification passes (the driver's own contract gate).
fn strict_ok(image: &[u8]) -> bool {
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    verify(image, &opts).is_ok(&opts)
}

/// `OsString` argv from `&str` pairs (the house test helper shape).
fn args(pairs: &[&str]) -> Vec<OsString> {
    pairs.iter().map(|s| OsString::from(*s)).collect()
}

// ---- the surface ---------------------------------------------------------

#[test]
fn the_flag_pair_parses() {
    let dir = scratch("parse");
    let _objs = corpus(&dir);
    let argv = args(&["-o", "out", "-init_offsets", "main.o"]);
    let o = opts::parse(&argv).expect("the named form parses");
    assert_eq!(
        o.init_offsets_flag,
        Some(true),
        "the named form is explicit"
    );
    let argv = args(&["-o", "out", "-no_init_offsets", "main.o"]);
    let o = opts::parse(&argv).expect("the explicit off parses");
    assert_eq!(
        o.init_offsets_flag,
        Some(false),
        "the explicit off is explicit"
    );
    let argv = args(&["-o", "out", "main.o"]);
    let o = opts::parse(&argv).expect("the flag-less argv parses");
    assert_eq!(o.init_offsets_flag, None, "the default stays unnamed");
}

#[test]
fn the_named_form_reaches_the_image() {
    // `-init_offsets` names the transform: the pointer section leaves
    // the image, the u32-offset section rides __TEXT with the dyld
    // shape (4-byte aligned, S_INIT_FUNC_OFFSETS), and the image
    // verifies strict.
    let dir = scratch("link");
    let image = link_exe(&dir, "hello", &["-init_offsets"]);
    let rows = section_rows(&image);
    assert!(
        !rows
            .iter()
            .any(|(_, name, _, _, _, _)| name == "__mod_init_func"),
        "the pointer section leaves the image: {rows:?}"
    );
    let sect = rows
        .iter()
        .find(|(_, name, _, _, _, _)| name == "__init_offsets")
        .expect("the offsets section exists");
    assert_eq!(sect.0, "__TEXT", "the section rides __TEXT");
    assert_eq!(
        sect.2 & SECTION_TYPE_MASK,
        S_INIT_FUNC_OFFSETS,
        "the dyld-walkable section type"
    );
    assert_eq!(sect.4, 8, "two u32 entries");
    let bytes = init_offsets_bytes(&image).expect("the content reads");
    let entries: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().expect("4-byte entry")))
        .collect();
    assert_eq!(entries.len(), 2, "two entries");
    // The entries are offsets from the image's load address (the __TEXT
    // segment vmaddr — the base), not from the __text section's addr.
    let base = segment_rows(&image)
        .iter()
        .find(|(n, _, _, _)| n == "__TEXT")
        .expect("__TEXT segment")
        .1;
    let text = rows
        .iter()
        .find(|(_, name, _, _, _, _)| name == "__text")
        .expect("__text");
    for (i, off) in entries.iter().enumerate() {
        let target = base + u64::from(*off);
        assert!(
            target >= text.3 && target < text.3 + text.4,
            "entry {i} ({off:#x}) lands inside __text"
        );
    }
    assert_ne!(entries[0], entries[1], "two distinct initializers");
    assert!(
        strict_ok(&image),
        "the offsets image verifies strict: {rows:?}"
    );
}

#[test]
fn the_default_and_the_explicit_off_stay_byte_identical() {
    // The seam adds nothing on a clean link: a flag-less link and an
    // explicit `-no_init_offsets` link plan the same bytes, and the
    // offsets form moves them (the control).
    let dir = scratch("identity");
    let implicit = link_exe(&dir, "hello_a", &[]);
    let explicit_off = link_exe(&dir, "hello_b", &["-no_init_offsets"]);
    assert_eq!(
        implicit, explicit_off,
        "the default is the explicit off (the M1-locked classic form)"
    );
    let named = link_exe(&dir, "hello_c", &["-init_offsets"]);
    assert_ne!(implicit, named, "the form is on the image");
}

#[test]
fn the_floor_refuses_with_the_fix() {
    // iOS 14.0 sits below the platform's chained-fixups floor (15.0):
    // that dyld cannot consume S_INIT_FUNC_OFFSETS at all.
    let dir = scratch("floor");
    let objs = corpus(&dir);
    let out = dir.join("hello");
    let mut argv = vec![
        "-o".to_string(),
        out.display().to_string(),
        "-platform_version".to_string(),
        "ios".to_string(),
        "14.0".to_string(),
        "14.0".to_string(),
        "-init_offsets".to_string(),
    ];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let err = opts::parse(&argv).expect_err("the below-floor form refuses");
    let rendered = err.to_string();
    assert!(rendered.contains("-init_offsets"), "{rendered}");
    assert!(
        rendered.contains("15.0.0"),
        "the floor is named: {rendered}"
    );
    // The miette help names the fix (the house convention).
    let help = miette::Report::new(err)
        .help()
        .map(|h| h.to_string())
        .unwrap_or_default();
    assert!(
        help.contains("-no_init_offsets") || help.contains("-platform_version"),
        "the help names the fix: {help}"
    );
    // The explicit off (and the flag-less default) never consult the
    // floor — the classic form is valid on every target.
    let mut argv = vec![
        "-o".to_string(),
        out.display().to_string(),
        "-platform_version".to_string(),
        "ios".to_string(),
        "14.0".to_string(),
        "14.0".to_string(),
        "-no_init_offsets".to_string(),
    ];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the explicit off is always valid");
    pgr_driver::run(&o).expect("the classic form links below the floor");
}

#[test]
fn the_relocatable_output_refuses_the_flag() {
    let dir = scratch("reloc");
    let objs = corpus(&dir);
    let out_path = dir.join("out.o");
    let mut argv = vec![
        "-o".to_string(),
        out_path.display().to_string(),
        "-r".to_string(),
        "-init_offsets".to_string(),
    ];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let err = opts::parse(&argv).expect_err("the relocatable link refuses the knob");
    let rendered = err.to_string();
    assert!(
        rendered.contains("-r") || rendered.contains("relocatable"),
        "the verdict names the output kind: {rendered}"
    );
    let help = miette::Report::new(err)
        .help()
        .map(|h| h.to_string())
        .unwrap_or_default();
    assert!(
        help.contains("-init_offsets"),
        "the help names the fix: {help}"
    );
}

#[test]
fn the_resident_cycle_carries_the_form() {
    // One-shot reference.
    let dir = scratch("resident_ref");
    let one_shot = link_exe(&dir, "hello_ref", &["-init_offsets"]);

    // The same link through the resident path: the daemon relinks with
    // the same config, so the configured form crossed the wire (v9).
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
        "-init_offsets".to_string(),
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
        "the resident cycle plans the same bytes with the named form"
    );
    assert!(
        init_offsets_bytes(&resident).is_some(),
        "the form crossed the wire"
    );
}

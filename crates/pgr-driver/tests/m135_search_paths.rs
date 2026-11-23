//! M135 — the library-search-order face (`-search_paths_first` /
//! `-search_dylibs_first`): ld64's man page names the two alphabets
//! (the post-Xcode4 default searches *each directory* for the dylib
//! forms then the archive before moving on; `-search_dylibs_first`
//! "restores the search behavior of the linker prior to Xcode4" — the
//! dylib forms across every directory first, the archive forms
//! second). The house default already rode the per-directory shape
//! (the `resolve_lib` contract since M2/M5); the face names both
//! decisions on the command line — the named default (the M104
//! `-keep_local_symbols` pattern) beside the old shape restored.
//!
//! The decision is Pass 0's own: it names *which files* the link
//! consumes, and the picked file's bytes ride the driver's mapped
//! inputs (the daemon request carries resolved inputs, not `-l`
//! names) — so the resident lane inherits the decision through the
//! existing input transport, no wire byte (the M53-rename precedent:
//! a surface decision the machinery already carries).
//!
//! Gate matrix:
//! * the surface — both flags parse (last-wins, the M102 pair shape),
//!   the named default is byte-identical to the unnamed default;
//! * the decision — a two-directory corpus where dir one carries the
//!   archive and dir two the dylib splits the faces: the default picks
//!   the archive in the first directory, `-search_dylibs_first` picks
//!   the dylib in the second (the images differ, the load command
//!   names it);
//! * the probe record — the M60 dependency record's not-found rows
//!   follow the rounds (the search's own story, recorded at probe
//!   time);
//! * the link — a `-search_dylibs_first` image links and verifies
//!   strict, and the resident cycle plans the same bytes (the decision
//!   rides the resolved inputs).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pgr_driver::opts;
use pgr_fixtures::{
    ArchiveBuilder, ImageBuilder, ObjectBuilder, ObjectSection, ObjectSymbol, SectionSpec,
    SegmentSpec, SymbolSpec, filler,
};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Options as VerifyOptions, verify};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m135_driver").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `main.o`: `_main` referencing the library's `_greet` export.
fn main_object(dir: &Path) -> PathBuf {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    let path = dir.join("main.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// dir one's library: the static archive form (`libgreet.a`, a member
/// defining `_greet`) — the form the default's per-directory walk
/// reaches first when it owns the first directory.
fn archive_library(dir: &Path) -> PathBuf {
    let mut member = ObjectBuilder::new("greet.o");
    let text = member.add_section(ObjectSection::text(
        "__text",
        [0x90u8, 0x02, 0x00, 0x94].repeat(2),
        vec![],
    ));
    member.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let bytes = member.build().expect("the fixture object builds");
    let mut archive = ArchiveBuilder::new("libgreet.a");
    archive.add_member("greet.o", bytes);
    let path = dir.join("libgreet.a");
    std::fs::write(&path, archive.build()).unwrap();
    path
}

/// dir two's library: the dylib form (`libgreet.dylib`, install name
/// `@rpath/libgreet.dylib`, exporting `_greet`) — the form
/// `-search_dylibs_first` reaches first across every directory.
fn dylib_library(dir: &Path) -> PathBuf {
    let mut b = ImageBuilder::dylib("@rpath/libgreet.dylib", "pgr-m135-dylib");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0x7070, 64),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_greet".into(),
        section_index: 0,
    });
    let image = b.build().expect("the fixture dylib builds");
    let path = dir.join("libgreet.dylib");
    std::fs::write(&path, image.bytes).unwrap();
    path
}

/// Builds the split corpus: dir one owns the archive, dir two the
/// dylib, both exporting `_greet`. Returns the object and the two
/// search *directories* (the `-L` operands).
fn split_corpus(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let dir_a = dir.join("search_a");
    let dir_b = dir.join("search_dylib");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();
    let obj = main_object(dir);
    let _archive = archive_library(&dir_a);
    let _dylib = dylib_library(&dir_b);
    (obj, dir_a, dir_b)
}

/// Links `main.o` with `-L dir_a -L dir_b -lgreet` under `extra` argv;
/// returns the image bytes.
fn link_image(dir: &Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let (obj, dir_a, dir_b) = split_corpus(dir);
    let out_path = dir.join(out);
    let mut argv = vec![
        "-o".to_string(),
        out_path.display().to_string(),
        obj.display().to_string(),
        "-L".to_string(),
        dir_a.display().to_string(),
        "-L".to_string(),
        dir_b.display().to_string(),
        "-lgreet".to_string(),
    ];
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).unwrap()
}

/// The image's dylib load commands: `(opcode, install name)` pairs (the
/// m45 reader shape).
fn load_commands(image: &[u8]) -> Vec<(u32, String)> {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut out = Vec::new();
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind == pgr_format::LoadCommandKind::LoadDylib
            && let Ok(d) = pgr_format::DylibCommand::parse(cmd.bytes)
            && let Ok(name) = d.name(cmd.bytes)
        {
            let opcode = u32::from_le_bytes(cmd.bytes[0..4].try_into().unwrap());
            out.push((
                opcode,
                String::from_utf8_lossy(name)
                    .trim_end_matches('\0')
                    .to_string(),
            ));
        }
    }
    out
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flags_parse_and_name_the_decision() {
    for extra in [
        vec!["-search_paths_first"],
        vec!["-search_dylibs_first"],
        // Last-wins: the pair composes, the later flag is the decision.
        vec!["-search_dylibs_first", "-search_paths_first"],
        vec!["-search_paths_first", "-search_dylibs_first"],
    ] {
        let dir = scratch("parse");
        let (obj, dir_a, dir_b) = split_corpus(&dir);
        let mut argv = vec!["-o", "out"];
        argv.push(obj.to_str().unwrap());
        argv.extend([
            "-L",
            dir_a.to_str().unwrap(),
            "-L",
            dir_b.to_str().unwrap(),
            "-lgreet",
        ]);
        argv.extend(extra.iter().copied());
        let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
        let o = opts::parse(&argv).expect("both faces parse");
        let _ = o;
    }
}

#[test]
fn the_explicit_paths_first_face_is_byte_identical_to_the_default() {
    let dir = scratch("default_parity");
    let default = link_image(&dir, "hello_default", &[]);
    let dir2 = scratch("explicit_parity");
    let explicit = link_image(&dir2, "hello_explicit", &["-search_paths_first"]);
    assert_eq!(
        default, explicit,
        "naming the default face plans the default bytes"
    );
}

// ---- the decision -------------------------------------------------------------

#[test]
fn the_default_picks_the_first_directorys_archive() {
    let dir = scratch("default");
    let image = link_image(&dir, "hello_default", &[]);
    let loads = load_commands(&image);
    assert!(
        !loads
            .iter()
            .any(|(_, name)| name == "@rpath/libgreet.dylib"),
        "the default's per-directory walk takes dir one's archive: {loads:?}"
    );
}

#[test]
fn dylibs_first_picks_the_dylib_across_the_directories() {
    let dir = scratch("dylibs_first");
    let image = link_image(&dir, "hello_dylibs_first", &["-search_dylibs_first"]);
    let loads = load_commands(&image);
    assert!(
        loads
            .iter()
            .any(|(_, name)| name == "@rpath/libgreet.dylib"),
        "the dylibs-first round takes dir two's dylib: {loads:?}"
    );
}

#[test]
fn the_faces_link_different_images() {
    let dir = scratch("split");
    let default = link_image(&dir, "hello_default", &[]);
    let dir2 = scratch("split2");
    let dylibs_first = link_image(&dir2, "hello_flag", &["-search_dylibs_first"]);
    assert_ne!(
        default, dylibs_first,
        "the two search orders pick different libraries"
    );
}

#[test]
fn a_dylibs_first_image_verifies_strict() {
    let dir = scratch("strict");
    let image = link_image(&dir, "hello", &["-search_dylibs_first"]);
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the dylibs-first image verifies strict: {:?}",
        report.issues
    );
}

// ---- the probe record ---------------------------------------------------------

#[test]
fn resolve_lib_probe_order_follows_the_face() {
    let dir = scratch("probes");
    let (_, dir_a, dir_b) = split_corpus(&dir);
    let dirs = vec![dir_a.display().to_string(), dir_b.display().to_string()];

    // Default: per-directory — every dir one candidate before dir two.
    let mut misses = Vec::new();
    let default_path =
        pgr_driver::resolve_lib("greet", &dirs, opts::SearchOrder::PathsFirst, &mut misses)
            .expect("the search walks")
            .expect("dir one's archive wins the default walk")
            .0;
    assert!(
        default_path.ends_with("libgreet.a"),
        "the archive rides first: {default_path}"
    );
    // The hit stopped the walk at dir one: the misses are dir one's
    // dylib-form candidates (the archive form hit).
    assert_eq!(misses.len(), 4, "dir one's dylib forms missed: {misses:?}");
    assert!(
        misses.iter().all(|p| p.starts_with(dirs[0].as_str())),
        "the default walk never reached dir two: {misses:?}"
    );

    // Dylibs-first: the dylib round sweeps dir one (four misses) and
    // dir two (the stub miss), then dir two's dylib hits — the archive
    // round never starts, the probe record is the round's own story.
    let mut misses = Vec::new();
    let dylibs_path =
        pgr_driver::resolve_lib("greet", &dirs, opts::SearchOrder::DylibsFirst, &mut misses)
            .expect("the search walks")
            .expect("dir two's dylib wins the dylibs-first walk")
            .0;
    assert!(
        dylibs_path.ends_with("libgreet.dylib"),
        "the dylib rides first: {dylibs_path}"
    );
    assert_eq!(
        misses.len(),
        6,
        "the dylib round probed both dirs: {misses:?}"
    );
    assert!(
        misses.iter().any(|p| p.starts_with(dirs[1].as_str())),
        "the dylib round reached dir two (a probe the default never made)"
    );
    assert_ne!(
        default_path, dylibs_path,
        "the two faces resolve different files"
    );
}

// ---- the resident cycle -------------------------------------------------------

#[test]
fn the_resident_cycle_plans_the_same_bytes() {
    // One-shot reference under the flag.
    let dir = scratch("resident_ref");
    let one_shot = link_image(&dir, "hello_ref", &["-search_dylibs_first"]);

    // The same link through the resident path: the client resolves the
    // search itself (Pass 0), the request carries the resolved bytes.
    let dir2 = scratch("resident");
    let sock = dir2.join("pgrd.sock");
    let owned = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(120));
    });
    std::thread::sleep(Duration::from_millis(50));

    let (obj, dir_a, dir_b) = split_corpus(&dir2);
    let out_path = dir2.join("hello");
    let argv = vec![
        "-o".to_string(),
        out_path.display().to_string(),
        obj.display().to_string(),
        "-L".to_string(),
        dir_a.display().to_string(),
        "-L".to_string(),
        dir_b.display().to_string(),
        "-lgreet".to_string(),
        "-search_dylibs_first".to_string(),
        "-resident".to_string(),
        "-resident_socket".to_string(),
        sock.display().to_string(),
    ];
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the resident argv parses");
    pgr_driver::run(&o).expect("the resident link runs");
    let resident = std::fs::read(&out_path).unwrap();
    assert_eq!(
        one_shot, resident,
        "the resident cycle plans the same bytes with the named search order"
    );
}

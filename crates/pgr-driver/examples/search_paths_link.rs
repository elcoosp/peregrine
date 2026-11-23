//! The library-search-order consumer example (M135): ld64's
//! `-search_paths_first` / `-search_dylibs_first` — the `-l` search's
//! two alphabets. The default (the post-Xcode4 shape the house carried
//! since M2/M5) walks each directory for the dylib forms then the
//! archive before moving on; `-search_dylibs_first` restores the
//! pre-Xcode4 rounds (the dylib forms sweep every directory first).
//! The split corpus makes both walks honest: dir one carries
//! `libgreet.a`, dir two `libgreet.dylib`, both exporting `_greet` —
//! the default takes dir one's archive, the flag takes dir two's
//! dylib, and the picked file's install name names the face (the house
//! consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example search_paths_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{
    ArchiveBuilder, ImageBuilder, ObjectBuilder, ObjectSection, ObjectSymbol, SectionSpec,
    SegmentSpec, SymbolSpec, filler,
};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;

/// `main.o`: `_main` referencing the library's `_greet` export.
fn main_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6],
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
    b.build().expect("the fixture object builds")
}

/// The archive form: `libgreet.a`, a member defining `_greet`.
fn archive_library(dir: &std::path::Path) {
    let mut member = ObjectBuilder::new("greet.o");
    let text = member.add_section(ObjectSection::text(
        "__text",
        vec![0x90, 0x02, 0x00, 0x94, 0x90, 0x02, 0x00, 0x94],
        vec![],
    ));
    member.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let mut archive = ArchiveBuilder::new("libgreet.a");
    archive.add_member(
        "greet.o",
        member.build().expect("the fixture object builds"),
    );
    std::fs::write(dir.join("libgreet.a"), archive.build()).unwrap();
}

/// The dylib form: `libgreet.dylib` (install name `@rpath/libgreet.dylib`),
/// exporting `_greet`.
fn dylib_library(dir: &std::path::Path) {
    let mut b = ImageBuilder::dylib("@rpath/libgreet.dylib", "pgr-search-paths");
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
    std::fs::write(
        dir.join("libgreet.dylib"),
        b.build().expect("the fixture dylib builds").bytes,
    )
    .unwrap();
}

/// The image's dylib load commands' install names (the m45 reader shape).
fn load_names(image: &[u8]) -> Vec<String> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut out = Vec::new();
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::LoadDylib
            && let Ok(d) = pgr_format::DylibCommand::parse(cmd.bytes)
            && let Ok(name) = d.name(cmd.bytes)
        {
            out.push(
                String::from_utf8_lossy(name)
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
    }
    out
}

fn run(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let obj = dir.join("main.o");
    let dir_a = dir.join("search_a");
    let dir_b = dir.join("search_dylib");
    let mut argv: Vec<String> = vec![
        "-o".into(),
        dir.join(out).display().to_string(),
        obj.display().to_string(),
        "-L".into(),
        dir_a.display().to_string(),
        "-L".into(),
        dir_b.display().to_string(),
        "-lgreet".into(),
    ];
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link ships");
    std::fs::read(dir.join(out)).expect("the image reads")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_search_paths_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dir_a = dir.join("search_a");
    let dir_b = dir.join("search_dylib");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();
    std::fs::write(dir.join("main.o"), main_object()).unwrap();
    archive_library(&dir_a);
    dylib_library(&dir_b);

    // The two faces: the default takes dir one's archive (the
    // per-directory walk), `-search_dylibs_first` takes dir two's dylib
    // (the rounds) — the load commands name the picked file.
    let default = run(&dir, "app_default", &[]);
    let dylibs_first = run(&dir, "app_dylibs_first", &["-search_dylibs_first"]);
    println!("default (per-directory):      {:?}", load_names(&default));
    println!(
        "-search_dylibs_first (rounds): {:?}",
        load_names(&dylibs_first)
    );
    assert!(
        load_names(&default).is_empty(),
        "the default binds the archive's body inline (no load command)"
    );
    assert_eq!(
        load_names(&dylibs_first),
        vec!["@rpath/libgreet.dylib".to_string()],
        "the dylibs-first round names dir two's dylib"
    );

    // The named default: byte-identical to the unnamed default (the
    // M104 named-default pattern).
    let named = run(&dir, "app_named_default", &["-search_paths_first"]);
    assert_eq!(default, named, "naming the default plans the default bytes");

    // Both images verify strict (the verifier is the face-blind gate).
    let strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    for (label, image) in [("default", &default), ("dylibs_first", &dylibs_first)] {
        let report = verify(image, &strict);
        assert!(
            report.is_ok(&strict),
            "the {label} image verifies strict: {:#?}",
            report.issues
        );
    }

    println!(
        "\nimages: {} (strict-verified; try PGR_TRACING=1 to watch the Pass-0 search)",
        dir.display()
    );
    println!("search_paths_link: ok");
}

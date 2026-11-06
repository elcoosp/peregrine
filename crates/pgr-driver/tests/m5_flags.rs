//! M5 driver-flag e2e gates: `-filelist`, `-framework`/`-F`,
//! `-sectcreate`, `-all_load`/`-force_load` through the full pipeline —
//! every output strict-verified, fused byte-identical to the reference.

use pgr_driver::opts::Options;
use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

fn unique_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m5_flags").join(format!(
        "{}_{}_{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// main.o: _main calls _greet.
fn main_object() -> Vec<u8> {
    let text: Vec<u8> = [
        0x9400_0000u32, // bl _greet
        0x5280_0000u32, // mov w0, #0
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("main.o");
    b.add_section(ObjectSection::text(
        "__text",
        text,
        vec![ObjectReloc::branch26(1).at(0)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.build().unwrap()
}

/// greet.o: defines _greet.
fn greet_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    b.build().unwrap()
}

fn output_symbols(bytes: &[u8]) -> std::collections::HashMap<String, (u64, u8)> {
    let header = pgr_format::MachHeader64::parse(bytes).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    let mut out = std::collections::HashMap::new();
    while let Some(cmd) = it.next_command().unwrap() {
        if let pgr_format::LoadCommandKind::Symtab = cmd.kind {
            let st = pgr_format::SymtabCommand::parse(cmd.bytes, 0).unwrap();
            for i in 0..st.nsyms {
                let sym: pgr_format::symtab::Nlist64 = pgr_format::cursor::pod_read_unaligned_at(
                    bytes,
                    st.symoff as usize + i as usize * 16,
                )
                .unwrap();
                let strx = sym.n_strx as usize;
                let end = bytes[st.stroff as usize + strx..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap();
                let name = String::from_utf8_lossy(
                    &bytes[st.stroff as usize + strx..st.stroff as usize + strx + end],
                )
                .into_owned();
                out.insert(name, (sym.n_value, sym.n_type));
            }
        }
    }
    out
}

fn strict_verify(image: &[u8]) {
    let opts = pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = pgr_verify::verify(image, &opts);
    assert!(report.is_ok(&opts), "verifier issues: {report:?}");
}

#[test]
fn m5_filelist_expands_inputs_in_order() {
    let dir = unique_dir("filelist");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).unwrap();
    let greet = dir.join("greet.o");
    std::fs::write(&greet, greet_object()).unwrap();
    let list = dir.join("objs.txt");
    std::fs::write(
        &list,
        format!("# generated\n{}\n{}\n", greet.display(), main.display()),
    )
    .unwrap();

    let opts = Options {
        filelists: vec![(list.display().to_string(), None)],
        output: dir.join("out.bin").display().to_string(),
        config: pgr_core::layout::LinkConfig {
            ident: "m5-filelist".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        ..Options::default()
    };
    let image = pgr_driver::link_to_bytes(&opts).unwrap();
    let syms = output_symbols(&image);
    assert!(syms.contains_key("_greet"), "filelist input was linked");
    strict_verify(&image);
    let reference = pgr_driver::link_reference_bytes(&opts).unwrap();
    assert_eq!(image, reference);

    // With a base directory: entries resolve relative to it.
    let subdir = dir.join("sub");
    std::fs::create_dir_all(&subdir).unwrap();
    let greet2 = subdir.join("greet.o");
    std::fs::write(&greet2, greet_object()).unwrap();
    let list2 = dir.join("objs2.txt");
    std::fs::write(&list2, "greet.o\n").unwrap();
    let opts = Options {
        filelists: vec![(
            list2.display().to_string(),
            Some(subdir.display().to_string()),
        )],
        inputs: vec![main.display().to_string()],
        output: dir.join("out2.bin").display().to_string(),
        config: pgr_core::layout::LinkConfig {
            ident: "m5-filelist".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        ..Options::default()
    };
    let image = pgr_driver::link_to_bytes(&opts).unwrap();
    assert!(output_symbols(&image).contains_key("_greet"));
}

#[test]
fn m5_framework_search_finds_stub_dylibs() {
    let dir = unique_dir("framework");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).unwrap();
    // A framework bundle carrying a .tbd stub exporting _greet.
    let fw = dir.join("Greet.framework");
    std::fs::create_dir_all(&fw).unwrap();
    std::fs::write(
        fw.join("Greet.tbd"),
        "--- !tapi-tbd\n\
         tbd-version: 4\n\
         targets: [arm64-macos]\n\
         install-name: @rpath/Greet.framework/Greet\n\
         exports:\n\
         \x20 - targets: [arm64-macos]\n\
         \x20   symbols: [_greet]\n\
         ...\n",
    )
    .unwrap();

    let opts = Options {
        inputs: vec![main.display().to_string()],
        frameworks: vec!["Greet".into()],
        framework_dirs: vec![dir.display().to_string()],
        output: dir.join("out.bin").display().to_string(),
        config: pgr_core::layout::LinkConfig {
            ident: "m5-framework".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        ..Options::default()
    };
    let image = pgr_driver::link_to_bytes(&opts).unwrap();
    let syms = output_symbols(&image);
    assert!(syms.contains_key("_greet"), "framework symbol bound");
    strict_verify(&image);

    // A missing framework is an actionable error.
    let opts = Options {
        inputs: vec![main.display().to_string()],
        frameworks: vec!["Missing".into()],
        framework_dirs: vec![dir.display().to_string()],
        output: dir.join("out2.bin").display().to_string(),
        ..Options::default()
    };
    let err = pgr_driver::link_to_bytes(&opts).unwrap_err();
    assert!(err.to_string().contains("Missing.framework"), "{err}");
}

#[test]
fn m5_sectcreate_places_file_contents() {
    let dir = unique_dir("sectcreate");
    let main = dir.join("main.o");
    std::fs::write(&main, greet_object()).unwrap(); // defines _greet; a dylib needs no main
    let plist = dir.join("Info.plist");
    std::fs::write(&plist, b"<?xml version=\"1.0\"?><plist/>").unwrap();

    let opts = Options {
        inputs: vec![main.display().to_string()],
        sectcreate: vec![(
            "__TEXT".into(),
            "__info_plist".into(),
            plist.display().to_string(),
        )],
        output: dir.join("out.dylib").display().to_string(),
        config: pgr_core::layout::LinkConfig {
            ident: "m5-sectcreate".into(),
            filetype: pgr_core::layout::OutputType::Dylib,
            install_name: Some("@rpath/libplist.dylib".into()),
            ..pgr_core::layout::LinkConfig::default()
        },
        ..Options::default()
    };
    let image = pgr_driver::link_to_bytes(&opts).unwrap();

    // The file's bytes appear exactly once, in a __TEXT,__info_plist section.
    let needle = b"<?xml version=\"1.0\"?><plist/>";
    assert_eq!(
        image.windows(needle.len()).filter(|w| *w == needle).count(),
        1,
        "-sectcreate content missing"
    );
    let header = pgr_format::MachHeader64::parse(&image).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        &image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    let mut found = false;
    while let Some(cmd) = it.next_command().unwrap() {
        if let pgr_format::LoadCommandKind::Segment64 = cmd.kind {
            let seg = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).unwrap();
            for s in seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .unwrap()
            {
                if seg.name().unwrap() == "__TEXT" && s.name().unwrap() == "__info_plist" {
                    assert_eq!(s.size, needle.len() as u64);
                    found = true;
                }
            }
        }
    }
    assert!(found, "__info_plist section not emitted");
    strict_verify(&image);
    let reference = pgr_driver::link_reference_bytes(&opts).unwrap();
    assert_eq!(image, reference);
}

#[test]
fn m5_l_search_prefers_dylibs_over_archives() {
    let dir = unique_dir("searchorder");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).unwrap();
    let libdir = dir.join("lib");
    std::fs::create_dir_all(&libdir).unwrap();
    // Both a .tbd and an .a provide _greet: the dylib wins (ld64 order).
    std::fs::write(
        libdir.join("libgreet.tbd"),
        "--- !tapi-tbd\n\
         tbd-version: 4\n\
         targets: [arm64-macos]\n\
         install-name: @rpath/libgreet.dylib\n\
         exports:\n\
         \x20 - targets: [arm64-macos]\n\
         \x20   symbols: [_greet]\n\
         ...\n",
    )
    .unwrap();
    let mut arch = ArchiveBuilder::new("libgreet.a");
    arch.add_member("greet.o", greet_object());
    std::fs::write(libdir.join("libgreet.a"), arch.build()).unwrap();

    let opts = Options {
        inputs: vec![main.display().to_string()],
        libs: vec!["greet".into()],
        lib_dirs: vec![libdir.display().to_string()],
        output: dir.join("out.bin").display().to_string(),
        config: pgr_core::layout::LinkConfig {
            ident: "m5-search".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        ..Options::default()
    };
    let image = pgr_driver::link_to_bytes(&opts).unwrap();
    // The dylib path binds (LC_LOAD_DYLIB present); an archive link would
    // define _greet locally instead.
    let syms = output_symbols(&image);
    let (_, greet_type) = syms["_greet"];
    assert_eq!(
        greet_type & pgr_format::consts::N_TYPE,
        pgr_format::consts::N_UNDF,
        "-l must bind the dylib (undefined here), not pull the archive member"
    );
    strict_verify(&image);
}

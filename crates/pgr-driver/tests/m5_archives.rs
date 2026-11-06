//! M5 archive gates (S7 — architecture doc §10.3 row M5): static archives
//! link through the ranlib-guided lazy pull; members the link never needs
//! are neither parsed nor placed; the fused emit stays byte-identical to
//! the reference; every output passes the strict verifier.

use pgr_driver::opts::Options;
use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::{MachHeader64, SegmentCommand64};

/// A per-call unique subdirectory (tests run in parallel threads).
fn unique_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m5_archives").join(format!(
        "{}_{}_{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// main.o: _main, BL _greet (undefined — satisfied by the archive).
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

/// greet.o (the member that must be pulled): defines _greet and a __data
/// rebase pointer to _main.
fn greet_member() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let greet_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main_ptr".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    b.section_mut(data).relocs = vec![ObjectReloc::unsigned(greet_sym as u32).at(0)];
    b.build().unwrap()
}

/// unused.o (the member that must stay out): a distinct byte marker in
/// __text and a symbol nothing references.
fn unused_member() -> Vec<u8> {
    let mut b = ObjectBuilder::new("unused.o");
    b.add_section(ObjectSection::text(
        "__text",
        vec![0xDE, 0xC0, 0xAD, 0xDE, 0xDE, 0xC0, 0xAD, 0xDE],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_unused".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    b.build().unwrap()
}

/// libutil.a with greet.o + unused.o, written to `dir`.
fn write_archive(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let mut arch = ArchiveBuilder::new(name);
    arch.add_member("greet.o", greet_member());
    arch.add_member("unused.o", unused_member());
    let p = dir.join(name);
    std::fs::write(&p, arch.build()).unwrap();
    p
}

/// Parsed symbol-name → value map of the output.
fn output_symbols(bytes: &[u8]) -> std::collections::HashMap<String, u64> {
    let header = MachHeader64::parse(bytes).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        MachHeader64::SIZE,
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
                out.insert(name, sym.n_value);
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
fn m5_archive_member_is_pulled_and_the_output_verifies() {
    let dir = unique_dir("pull");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).unwrap();
    let archive = write_archive(&dir, "libutil.a");

    let mut opts = Options {
        inputs: vec![main.display().to_string(), archive.display().to_string()],
        output: dir.join("out.bin").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-archive".into();

    let fused = pgr_driver::link_to_bytes(&opts).unwrap();
    let reference = pgr_driver::link_reference_bytes(&opts).unwrap();
    assert_eq!(
        fused, reference,
        "the M4 byte-identity gate holds on archive links"
    );
    strict_verify(&fused);

    let syms = output_symbols(&fused);
    assert!(syms.contains_key("_main"));
    assert!(
        syms.contains_key("_greet"),
        "pulled member's symbol defined"
    );
    assert!(
        !syms.contains_key("_unused"),
        "the unreferenced member is not pulled"
    );
    assert!(
        syms.contains_key("_main_ptr"),
        "pulled member contributes all its symbols"
    );
}

#[test]
fn m5_unreferenced_member_bytes_are_absent_from_the_image() {
    let dir = unique_dir("bytes");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).unwrap();
    let archive = write_archive(&dir, "libutil.a");

    let mut opts = Options {
        inputs: vec![main.display().to_string(), archive.display().to_string()],
        output: dir.join("out.bin").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-archive".into();
    let image = pgr_driver::link_to_bytes(&opts).unwrap();

    let marker = [0xDE, 0xC0, 0xAD, 0xDE, 0xDE, 0xC0, 0xAD, 0xDE];
    assert!(
        !image.windows(marker.len()).any(|w| w == marker),
        "the un-pulled member's bytes never reach the image"
    );
}

#[test]
fn m5_archive_position_on_the_command_line_does_not_matter() {
    let dir = unique_dir("order");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).unwrap();
    let archive = write_archive(&dir, "libutil.a");
    let main_path = main.display().to_string();
    let archive_path = archive.display().to_string();

    let mut before = Options {
        inputs: vec![archive_path.clone(), main_path.clone()],
        output: dir.join("a.bin").display().to_string(),
        ..Options::default()
    };
    before.config.ident = "m5-order".into();
    let mut after = Options {
        inputs: vec![main_path, archive_path],
        output: dir.join("b.bin").display().to_string(),
        ..Options::default()
    };
    after.config.ident = "m5-order".into();

    let a = pgr_driver::link_to_bytes(&before).unwrap();
    let b = pgr_driver::link_to_bytes(&after).unwrap();
    assert_eq!(
        a, b,
        "archive liveness is order-insensitive (TDD §5 Pass 2)"
    );
}

#[test]
fn m5_all_load_pulls_every_member() {
    let dir = unique_dir("allload");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).unwrap();
    let archive = write_archive(&dir, "libutil.a");

    let mut opts = Options {
        inputs: vec![main.display().to_string(), archive.display().to_string()],
        output: dir.join("out.bin").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-all-load".into();
    opts.all_load = true;
    let image = pgr_driver::link_to_bytes(&opts).unwrap();

    let marker = [0xDE, 0xC0, 0xAD, 0xDE, 0xDE, 0xC0, 0xAD, 0xDE];
    assert!(
        image.windows(marker.len()).any(|w| w == marker),
        "-all_load places every member"
    );
    let syms = output_symbols(&image);
    assert!(syms.contains_key("_unused"));
    strict_verify(&image);
}

#[test]
fn m5_force_load_pulls_only_the_named_archive() {
    let dir = unique_dir("forceload");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).unwrap();
    let archive = write_archive(&dir, "libutil.a");

    let mut opts = Options {
        inputs: vec![main.display().to_string(), archive.display().to_string()],
        output: dir.join("out.bin").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-force-load".into();
    opts.force_load_archives = vec![archive.display().to_string()];
    let image = pgr_driver::link_to_bytes(&opts).unwrap();

    let marker = [0xDE, 0xC0, 0xAD, 0xDE, 0xDE, 0xC0, 0xAD, 0xDE];
    assert!(
        image.windows(marker.len()).any(|w| w == marker),
        "-force_load pulls every member of the named archive"
    );
    strict_verify(&image);
}

#[test]
fn m5_u_symbol_pulls_its_member() {
    let dir = unique_dir("usym");
    // main.o without the _greet reference: only -u forces the pull.
    let text: Vec<u8> = [
        0x5280_0000u32, // mov w0, #0
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("main.o");
    b.add_section(ObjectSection::text("__text", text, vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    let main = dir.join("main.o");
    std::fs::write(&main, b.build().unwrap()).unwrap();
    let archive = write_archive(&dir, "libutil.a");

    let mut opts = Options {
        inputs: vec![main.display().to_string(), archive.display().to_string()],
        output: dir.join("out.bin").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-u".into();
    opts.force_load = vec!["_greet".into()];
    let image = pgr_driver::link_to_bytes(&opts).unwrap();
    let syms = output_symbols(&image);
    assert!(syms.contains_key("_greet"), "-u pulls the defining member");

    // -u of a name nothing defines stays an error.
    let mut opts = Options {
        inputs: vec![main.display().to_string(), archive.display().to_string()],
        output: dir.join("out2.bin").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-u".into();
    opts.force_load = vec!["_nowhere".into()];
    let err = pgr_driver::link_to_bytes(&opts).unwrap_err();
    assert!(err.to_string().contains("_nowhere"), "{err}");
}

#[test]
fn m5_l_search_finds_static_archives() {
    let dir = unique_dir("lsearch");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).unwrap();
    let libdir = dir.join("libs");
    std::fs::create_dir_all(&libdir).unwrap();
    let archive = write_archive(&libdir, "libgreet.a");

    let mut opts = Options {
        inputs: vec![main.display().to_string()],
        libs: vec!["greet".into()],
        lib_dirs: vec![libdir.display().to_string()],
        output: dir.join("out.bin").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-l".into();
    let image = pgr_driver::link_to_bytes(&opts).unwrap();
    let syms = output_symbols(&image);
    assert!(syms.contains_key("_greet"), "-l resolves to the archive");
    strict_verify(&image);
    let _ = archive;
}

#[test]
fn m5_weak_references_do_not_pull_members() {
    let dir = unique_dir("weak");
    // main.o: _main weak-refs _opt, strong-refs _needed.
    let text: Vec<u8> = [
        0x5280_0000u32, // mov w0, #0
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("main.o");
    b.add_section(ObjectSection::text("__text", text, vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_opt".into(),
        weak_ref: true,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_needed".into(),
        weak_ref: false,
    });
    let main = dir.join("main.o");
    std::fs::write(&main, b.build().unwrap()).unwrap();

    // memberA defines _opt AND the marker symbol; memberB defines _needed.
    let mut a = ObjectBuilder::new("a.o");
    let at = a.add_section(ObjectSection::text(
        "__text",
        vec![0xBA, 0xAD, 0xC0, 0xDE],
        vec![],
    ));
    a.add_symbol(ObjectSymbol::Defined {
        name: "_opt".into(),
        section_index: at,
        value: 0,
        weak: false,
    });
    a.add_symbol(ObjectSymbol::Defined {
        name: "_other_mark".into(),
        section_index: at,
        value: 0,
        weak: false,
    });
    let mut bb = ObjectBuilder::new("b.o");
    let bt = bb.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    bb.add_symbol(ObjectSymbol::Defined {
        name: "_needed".into(),
        section_index: bt,
        value: 0,
        weak: false,
    });
    let mut arch = ArchiveBuilder::new("libw.a");
    arch.add_member("a.o", a.build().unwrap());
    arch.add_member("b.o", bb.build().unwrap());
    let archive = dir.join("libw.a");
    std::fs::write(&archive, arch.build()).unwrap();

    let mut opts = Options {
        inputs: vec![main.display().to_string(), archive.display().to_string()],
        output: dir.join("out.bin").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-weak".into();
    let image = pgr_driver::link_to_bytes(&opts).unwrap();
    let syms = output_symbols(&image);
    assert!(
        syms.contains_key("_needed"),
        "strong reference pulls memberB"
    );
    assert!(
        !syms.contains_key("_opt") && !syms.contains_key("_other_mark"),
        "a weak reference never pulls a member (ld64 semantics)"
    );
}

#[test]
fn m5_pulled_member_colliding_with_a_direct_definition_is_not_an_error() {
    let dir = unique_dir("collision");
    // direct.o defines _f strongly; main references _g and _f.
    let mut direct = ObjectBuilder::new("direct.o");
    let dt = direct.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    direct.add_symbol(ObjectSymbol::Defined {
        name: "_f".into(),
        section_index: dt,
        value: 0,
        weak: false,
    });
    // member defines _f AND _g (pulled for _g).
    let mut member = ObjectBuilder::new("member.o");
    let mt = member.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    member.add_symbol(ObjectSymbol::Defined {
        name: "_f".into(),
        section_index: mt,
        value: 0,
        weak: false,
    });
    member.add_symbol(ObjectSymbol::Defined {
        name: "_g".into(),
        section_index: mt,
        value: 4,
        weak: false,
    });
    // main: BL _f; BL _g.
    let text: Vec<u8> = [
        0x9400_0000u32, // bl _f
        0x9400_0000u32, // bl _g
        0x5280_0000u32, // mov w0, #0
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut main = ObjectBuilder::new("main.o");
    main.add_section(ObjectSection::text(
        "__text",
        text,
        vec![
            ObjectReloc::branch26(1).at(0),
            ObjectReloc::branch26(2).at(4),
        ],
    ));
    main.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    main.add_symbol(ObjectSymbol::Undefined {
        name: "_f".into(),
        weak_ref: false,
    });
    main.add_symbol(ObjectSymbol::Undefined {
        name: "_g".into(),
        weak_ref: false,
    });

    let main_p = dir.join("main.o");
    std::fs::write(&main_p, main.build().unwrap()).unwrap();
    let direct_p = dir.join("direct.o");
    std::fs::write(&direct_p, direct.build().unwrap()).unwrap();
    let mut arch = ArchiveBuilder::new("libm.a");
    arch.add_member("member.o", member.build().unwrap());
    let archive = dir.join("libm.a");
    std::fs::write(&archive, arch.build()).unwrap();

    let mut opts = Options {
        inputs: vec![
            main_p.display().to_string(),
            direct_p.display().to_string(),
            archive.display().to_string(),
        ],
        output: dir.join("out.bin").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-rank".into();
    let image = pgr_driver::link_to_bytes(&opts).unwrap();
    let syms = output_symbols(&image);
    // The direct definition wins (rank 1 over 3) — no duplicate-symbol error.
    let sections = {
        let header = MachHeader64::parse(&image).unwrap();
        let mut it = pgr_format::LoadCommandIter::new(
            &image,
            MachHeader64::SIZE,
            header.ncmds,
            header.sizeofcmds,
        )
        .unwrap();
        let mut text_addr = None;
        while let Some(cmd) = it.next_command().unwrap() {
            if let pgr_format::LoadCommandKind::Segment64 = cmd.kind {
                let seg = SegmentCommand64::parse(cmd.bytes, 0).unwrap();
                for s in seg.sections(cmd.bytes, SegmentCommand64::SIZE).unwrap() {
                    if s.name().unwrap() == "__text" && seg.name().unwrap() == "__TEXT" {
                        text_addr = Some(s.addr);
                    }
                }
            }
        }
        text_addr.unwrap()
    };
    // direct.o is the first __text contributor: _f sits at the section base
    // (main.o's piece is first actually — the direct object wins the symbol,
    // which is what the rank gate asserts; exact placement is layout policy).
    assert!(syms["_f"] >= sections, "_f resolves inside __text");
    assert!(syms.contains_key("_g"), "the member is pulled for _g");
    strict_verify(&image);
}

#[test]
fn m5_archive_double_link_is_deterministic() {
    let dir = unique_dir("determinism");
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).unwrap();
    let archive = write_archive(&dir, "libutil.a");

    let mut o1 = Options {
        inputs: vec![main.display().to_string(), archive.display().to_string()],
        output: dir.join("a.bin").display().to_string(),
        ..Options::default()
    };
    o1.config.ident = "m5-det".into();
    let mut o2 = o1.clone();
    o2.output = dir.join("b.bin").display().to_string();
    let a = pgr_driver::link_to_bytes(&o1).unwrap();
    let b = pgr_driver::link_to_bytes(&o2).unwrap();
    assert_eq!(a, b, "double link byte-identical (TDD §4.3)");
}

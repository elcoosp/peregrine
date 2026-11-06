//! M6 ecosystem gates (architecture doc §10.3 row M6): LTO bitcode objects
//! are detected and diagnosed up front, and ObjC/Swift metadata sections
//! pass through the pipeline untouched — placed, relocated (their class
//! and selector pointers become chained rebases) and verifier-clean.

use pgr_driver::opts::Options;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

fn unique_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m6_eco").join(format!(
        "{}_{}_{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn strict_verify(image: &[u8]) {
    let vopts = pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = pgr_verify::verify(image, &vopts);
    assert!(report.is_ok(&vopts), "verifier issues: {report:?}");
}

/// An LLVM bitcode object (raw `BC\xC0\xDE` magic) is rejected with the
/// clear M6 diagnostic — not a deep Mach-O parse failure.
#[test]
fn m6_lto_bitcode_objects_are_detected_and_diagnosed() {
    let dir = unique_dir("lto");
    let p = dir.join("giant.bc");
    // Raw bitcode magic + some payload.
    let mut bc = b"BC\xC0\xDE".to_vec();
    bc.extend_from_slice(&[0u8; 64]);
    std::fs::write(&p, bc).unwrap();
    let opts = Options {
        inputs: vec![p.display().to_string()],
        output: dir.join("out.bin").display().to_string(),
        ..Options::default()
    };
    let err = pgr_driver::link_to_bytes(&opts).unwrap_err();
    assert!(err.to_string().contains("LLVM bitcode"), "{err}");
    assert!(err.to_string().contains("-fno-lto"), "{err}");
    // The wrapper magic is detected too.
    let p2 = dir.join("wrapped.bc");
    std::fs::write(&p2, [0xDE, 0xC0, 0x17, 0x0B, 0, 0, 0, 0]).unwrap();
    let opts2 = Options {
        inputs: vec![p2.display().to_string()],
        output: dir.join("out2.bin").display().to_string(),
        ..Options::default()
    };
    let err2 = pgr_driver::link_to_bytes(&opts2).unwrap_err();
    assert!(err2.to_string().contains("LLVM bitcode"), "{err2}");
}

/// An ObjC-flavored corpus: `__objc_classlist` / `__objc_selrefs` pointer
/// sections (rebases) plus a `__ swift5`-style metadata blob. The sections
/// pass through untouched and verify.
#[test]
fn m6_objc_and_swift_sections_pass_through_and_verify() {
    let dir = unique_dir("objc");
    // hello.o: main + class object + selref table + swift metadata.
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [
            0x9000_0000u32, // adrp x0, msg@page
            0xD65F_03C0u32, // ret
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect(),
        vec![ObjectReloc::addend(0).at(0), ObjectReloc::page21(1).at(0)],
    ));
    // __objc_classrefs: one 8-byte pointer to the class symbol (rebase).
    let classrefs = b.add_section(ObjectSection {
        name: "__objc_classrefs".into(),
        segment: "__DATA".into(),
        align_log2: 3,
        flags: pgr_format::consts::S_REGULAR,
        data: vec![0u8; 8],
        relocs: vec![],
    });
    // __objc_selrefs: one 8-byte pointer into __cstring (the selector).
    let selrefs = b.add_section(ObjectSection {
        name: "__objc_selrefs".into(),
        segment: "__DATA_CONST".into(),
        align_log2: 3,
        flags: pgr_format::consts::S_REGULAR,
        data: vec![0u8; 8],
        relocs: vec![],
    });
    let cstr = b.add_section(ObjectSection::cstring("foo\x00"));
    // __swift5_types: a payload blob with one pointer slot.
    let swift5 = b.add_section(ObjectSection {
        name: "__swift5_types".into(),
        segment: "__TEXT".into(),
        align_log2: 3,
        flags: pgr_format::consts::S_REGULAR,
        data: vec![0u8; 16],
        relocs: vec![],
    });
    let class_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_OBJC_CLASS_$_Foobar".into(),
        section_index: classrefs,
        value: 0,
        weak: false,
    });
    let sel_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_sel_foo".into(),
        section_index: cstr,
        value: 0,
        weak: false,
    });
    let swift_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "__swift5_types_foo".into(),
        section_index: swift5,
        value: 0,
        weak: false,
    });
    b.section_mut(classrefs).relocs = vec![ObjectReloc::unsigned(class_sym as u32).at(0)];
    b.section_mut(selrefs).relocs = vec![ObjectReloc::unsigned(sel_sym as u32).at(0)];
    b.section_mut(swift5).relocs = vec![ObjectReloc::unsigned(swift_sym as u32).at(0)];
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let obj_p = dir.join("hello.o");
    std::fs::write(&obj_p, b.build().unwrap()).unwrap();

    let opts = Options {
        inputs: vec![obj_p.display().to_string()],
        output: dir.join("out.bin").display().to_string(),
        config: pgr_core::layout::LinkConfig {
            ident: "m6-objc".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        ..Options::default()
    };

    let image = pgr_driver::link_to_bytes(&opts).unwrap();
    // Every section survived into the output.
    let header = pgr_format::MachHeader64::parse(&image).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        &image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    let mut names = Vec::new();
    while let Some(cmd) = it.next_command().unwrap() {
        if let pgr_format::LoadCommandKind::Segment64 = cmd.kind {
            let seg = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).unwrap();
            for sect in seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .unwrap()
            {
                names.push((
                    seg.name().unwrap().to_string(),
                    sect.name().unwrap().to_string(),
                ));
            }
        }
    }
    for want in [
        ("__TEXT", "__text"),
        ("__TEXT", "__swift5_types"),
        ("__TEXT", "__cstring"),
        ("__DATA_CONST", "__objc_selrefs"),
        ("__DATA", "__objc_classrefs"),
    ] {
        assert!(
            names.iter().any(|(seg, n)| seg == want.0 && n == want.1),
            "section {want:?} missing from {names:?}"
        );
    }
    strict_verify(&image);

    // Determinism (TDD §4.3).
    let dir2 = unique_dir("objc2");
    let obj2 = dir2.join("hello.o");
    std::fs::write(&obj2, b.build().unwrap()).unwrap();
    let opts2 = Options {
        inputs: vec![obj2.display().to_string()],
        output: dir2.join("out.bin").display().to_string(),
        config: pgr_core::layout::LinkConfig {
            ident: "m6-objc".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        ..Options::default()
    };
    assert_eq!(image, pgr_driver::link_to_bytes(&opts2).unwrap());
}

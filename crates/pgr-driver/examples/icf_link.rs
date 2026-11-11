//! The ICF consumer example (M6's `-icf=safe` as a story): one
//! `main.o` carrying two byte-identical functions (`_greet_a`,
//! `_greet_b`) that `_main` calls only by `Branch26` — the reference
//! shape `-icf=safe` folds — linked twice, once at the default
//! (`-icf=none`) and once under `-icf=safe`, with the symbol table read
//! back from both images and the strict verifier on both.
//!
//! The honest shape: under folding the two bodies share one canonical
//! copy (the image shrinks by one body), both names stay visible in the
//! symbol table and land on the same address (ld64's alias semantics);
//! the default keeps both copies at distinct addresses.
//!
//! Run: `cargo run -p pgr-driver --example icf_link`

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// The corpus: `main.o` calls two greet functions; `greet_a.o` and
/// `greet_b.o` each define one byte-identical 8-byte body called only
/// by `Branch26` (the foldable reference shape under `-icf=safe`; a
/// data pointer would take the address and safe would refuse). The
/// per-symbol atom split rides dead-strip's `compute_atoms` gate, so the
/// foldable bodies ride as separate single-function objects — the same
/// shape the M6 ICF gates link.
fn corpus(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut main_b = ObjectBuilder::new("main.o");
    let text = main_b.add_section(ObjectSection::text(
        "__text",
        vec![
            0x00u8, 0x00, 0x00, 0x94, // bl +0 (patched to _greet_a)
            0x00u8, 0x00, 0x00, 0x94, // bl +4 (patched to _greet_b)
            0xC0u8, 0x03, 0x5F, 0xD6, // retp
        ],
        vec![],
    ));
    let greet_a = main_b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet_a".into(),
        weak_ref: false,
    });
    let greet_b = main_b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet_b".into(),
        weak_ref: false,
    });
    main_b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    main_b.section_mut(text).relocs = vec![
        ObjectReloc::branch26(u32::try_from(greet_a).unwrap()).at(0),
        ObjectReloc::branch26(u32::try_from(greet_b).unwrap()).at(4),
    ];
    let greet_body = |sym: &str| {
        let mut b = ObjectBuilder::new(&format!("{sym}.o"));
        let body = b.add_section(ObjectSection::text(
            "__text",
            vec![
                0xC0u8, 0x03, 0x5F, 0xD6, // retp
                0xC0u8, 0x03, 0x5F, 0xD6, // retp
            ],
            vec![],
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: sym.into(),
            section_index: body,
            value: 0,
            weak: false,
        });
        b.build().expect("the fixture object builds")
    };
    let paths = vec![
        dir.join("main.o"),
        dir.join("greet_a.o"),
        dir.join("greet_b.o"),
    ];
    std::fs::write(
        &paths[0],
        main_b.build().expect("the fixture object builds"),
    )
    .unwrap();
    std::fs::write(&paths[1], greet_body("_greet_a")).unwrap();
    std::fs::write(&paths[2], greet_body("_greet_b")).unwrap();
    paths
}

/// The image's defined symbol names with their addresses
/// (`(name, value)` pairs — the fold aliasing reads off the symtab).
fn symbol_rows(image: &[u8]) -> Vec<(String, u64)> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::Symtab {
            let st: pgr_format::SymtabCommand =
                pgr_format::cursor::pod_read_unaligned_at(image, cmd.offset)
                    .expect("the command parses");
            let mut rows = Vec::new();
            for i in 0..st.nsyms {
                let sym: pgr_format::symtab::Nlist64 = pgr_format::cursor::pod_read_unaligned_at(
                    image,
                    st.symoff as usize + i as usize * 16,
                )
                .expect("the symbol parses");
                if sym.n_type & 0x0e != 0 {
                    let str_at = st.stroff as usize + sym.n_strx as usize;
                    let end = image[str_at..]
                        .iter()
                        .position(|b| *b == 0)
                        .expect("the name is NUL-terminated");
                    rows.push((
                        String::from_utf8_lossy(&image[str_at..str_at + end]).into_owned(),
                        sym.n_value,
                    ));
                }
            }
            return rows;
        }
    }
    panic!("the image carries LC_SYMTAB");
}

fn link(dir: &std::path::Path, out: &str, icf: Option<&str>) -> Vec<u8> {
    let objs = corpus(dir);
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
    ];
    for obj in &objs {
        argv.push(obj.as_os_str().to_os_string());
    }
    if let Some(level) = icf {
        argv.push(std::ffi::OsString::from("-icf"));
        argv.push(std::ffi::OsString::from(level));
    }
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).expect("the image reads")
}

/// The `__TEXT,__text` section's size (the fold's honest byte win —
/// the file size is segment-padded either way).
fn text_size(image: &[u8]) -> u64 {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the command parses");
            if seg.name().expect("utf8") != "__TEXT" {
                continue;
            }
            for s in seg
                .sections(cmd.bytes, 72)
                .expect("the section table parses")
            {
                if s.name().expect("utf8") == "__text" {
                    return s.size;
                }
            }
        }
    }
    panic!("the image carries __text");
}

fn main() {
    let dir = std::env::temp_dir().join(format!("pgr_icf_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let plain = link(&dir, "app_plain", None);
    let folded = link(&dir, "app_folded", Some("safe"));

    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    for (label, image) in [("plain", &plain), ("-icf=safe", &folded)] {
        let report = verify(image, &opts);
        assert!(
            report.is_ok(&opts),
            "the {label} image verifies strict: {:#?}",
            report.issues
        );
        println!(
            "{label:>10}: {} bytes, symbols {:?}",
            image.len(),
            symbol_rows(image)
        );
    }

    let addr = |rows: &[(String, u64)], name: &str| {
        rows.iter()
            .find(|(n, _)| n == name)
            .map_or_else(|| panic!("{name} is in the symtab"), |(_, v)| *v)
    };
    let plain_rows = symbol_rows(&plain);
    let folded_rows = symbol_rows(&folded);
    assert_ne!(
        addr(&plain_rows, "_greet_a"),
        addr(&plain_rows, "_greet_b"),
        "the default keeps both copies"
    );
    assert_eq!(
        addr(&folded_rows, "_greet_a"),
        addr(&folded_rows, "_greet_b"),
        "the fold aliases both names onto the canonical copy"
    );
    let (plain_text, folded_text) = (text_size(&plain), text_size(&folded));
    assert!(
        folded_text < plain_text,
        "the fold drops one body ({folded_text} < {plain_text} __text bytes)"
    );
    println!(
        "__text: {plain_text} bytes plain, {folded_text} bytes folded (one body \
         reclaimed; the file size is segment-padded either way)"
    );

    println!(
        "\nimages: {} (both strict-verified; the twins share a body, the aliases stay)",
        dir.display()
    );
}

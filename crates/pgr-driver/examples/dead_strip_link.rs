//! The dead-strip consumer example (M5's `-dead_strip` as a story):
//! one `main.o` carrying a live call chain (`_main` → `_live_fn`) and a
//! dead island — `_dead_fn`, referenced by nothing, whose only content
//! is a data pointer into a `__TEXT,__const` table (`_table`, built with
//! [`pgr_fixtures::ObjectSection::rodata`]) — linked twice, once plain
//! and once under `-dead_strip`, with the symbol table read back from
//! both images and the strict verifier on both.
//!
//! The honest shape: the dead island costs two symbols and one const
//! table in the plain image, and the mark-sweep reclaims exactly those
//! (the live chain and the rebase slots it owns stay put) — the image
//! shrinks, `_dead_fn`/`_table` leave the symbol table, and both images
//! verify strict.
//!
//! Run: `cargo run -p pgr-driver --example dead_strip_link`

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// main.o: `_main` calls `_live_fn` (a `Branch26` pair with a `retp`
/// body); the dead island is `_dead_fn` (a `retp` nothing references),
/// a `__DATA` pointer slot aimed at the `_table` const, and the table
/// itself (built with [`pgr_fixtures::ObjectSection::rodata`]) — the
/// slot is the island's only edge, so the mark-sweep takes the slot,
/// the table and the body together.
fn main_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o");
    let live = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6, 0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    let dead = b.add_section(ObjectSection::text(
        "__dead",
        vec![0xC0u8, 0x03, 0x5F, 0xD6], // retp (the dead body)
        vec![],
    ));
    // The const table the dead pointer slot names (`__TEXT,__const`;
    // the rodata constructor is the section's natural form).
    let table = b.add_section(ObjectSection::rodata(
        "__const",
        vec![0xDEu8, 0xAD, 0xBE, 0xEF, 0x42, 0x42, 0x42, 0x42],
        vec![],
    ));
    // The dead pointer slot (`__DATA`, 8-byte aligned — the slot's
    // content is the link-time value the rebase delta applies to).
    let slot = b.add_section(ObjectSection::data("__deadslot", vec![0u8; 8], vec![]));
    let live_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_live_fn".into(),
        section_index: live,
        value: 4,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_dead_fn".into(),
        section_index: dead,
        value: 0,
        weak: false,
    });
    let table_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_table".into(),
        section_index: table,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: live,
        value: 0,
        weak: false,
    });
    // `_main` calls `_live_fn`; the slot reads the table (the island's
    // only edge — nothing references the slot or the body).
    b.section_mut(live).relocs =
        vec![ObjectReloc::branch26(u32::try_from(live_sym).unwrap()).at(4)];
    b.section_mut(slot).relocs =
        vec![ObjectReloc::unsigned(u32::try_from(table_sym).unwrap()).at(0)];
    b.build().expect("the fixture object builds")
}

/// The image's defined symbol names (the symtab rows the example
/// asserts against).
fn symbol_names(image: &[u8]) -> Vec<String> {
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
            let mut names = Vec::new();
            for i in 0..st.nsyms {
                let sym: pgr_format::symtab::Nlist64 = pgr_format::cursor::pod_read_unaligned_at(
                    image,
                    st.symoff as usize + i as usize * 16,
                )
                .expect("the symbol parses");
                if sym.n_type & 0x0e != 0 {
                    // N_TYPE: a defined/undefined external, not a debug row.
                    let str_at = st.stroff as usize + sym.n_strx as usize;
                    let end = image[str_at..]
                        .iter()
                        .position(|b| *b == 0)
                        .expect("the name is NUL-terminated");
                    names.push(String::from_utf8_lossy(&image[str_at..str_at + end]).into_owned());
                }
            }
            return names;
        }
    }
    panic!("the image carries LC_SYMTAB");
}

fn link(dir: &std::path::Path, out: &str, dead_strip: bool) -> Vec<u8> {
    let obj = dir.join("main.o");
    std::fs::write(&obj, main_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    if dead_strip {
        argv.push(std::ffi::OsString::from("-dead_strip"));
    }
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).expect("the image reads")
}

fn main() {
    let dir = std::env::temp_dir().join(format!("pgr_dead_strip_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let plain = link(&dir, "app_plain", false);
    let stripped = link(&dir, "app_stripped", true);

    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    for (label, image) in [("plain", &plain), ("-dead_strip", &stripped)] {
        let report = verify(image, &opts);
        assert!(
            report.is_ok(&opts),
            "the {label} image verifies strict: {:#?}",
            report.issues
        );
        println!(
            "{label:>12}: {} bytes, symbols {:?}",
            image.len(),
            symbol_names(image)
        );
    }

    let plain_names = symbol_names(&plain);
    let stripped_names = symbol_names(&stripped);
    assert!(
        plain_names.iter().any(|n| n == "_dead_fn") && plain_names.iter().any(|n| n == "_table"),
        "the plain image keeps the dead island"
    );
    assert!(
        !stripped_names.iter().any(|n| n == "_dead_fn")
            && !stripped_names.iter().any(|n| n == "_table"),
        "the mark-sweep reclaims the dead island"
    );
    assert!(
        stripped.len() < plain.len(),
        "the stripped image is smaller ({stripped_len} < {plain_len})",
        stripped_len = stripped.len(),
        plain_len = plain.len()
    );
    assert!(
        stripped_names.iter().any(|n| n == "_live_fn"),
        "the live chain stays put"
    );

    println!(
        "\nimages: {} (both strict-verified; the island went, the live chain stayed)",
        dir.display()
    );
}

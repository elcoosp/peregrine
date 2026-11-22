//! The debug-map consumer example (M129): the `ld64`-shaped `n_type` rows
//! the producer's debug-map plan re-addresses onto placed live atoms so
//! `lldb`/`dsymutil` find the DWARF in the `.o` files. The plan emits
//! `N_SO` (the source-file anchor), `N_OSO` (the object-file path + the
//! fixed deterministic mtime `dsymutil` opens), and the `N_FUN` begin/end
//! pair (re-addressed onto the placed live atom) as the first locals
//! (clang's order). The walk: the stab-carrying object, the linked
//! image's debug-map rows, the strict verifier gating the `debugmap`
//! family, and the `dsymutil`-readiness contract (the `N_OSO` mtime is
//! the file-existence gate). Run:
//! `cargo run -p pgr-driver --example debug_map_link`

use pgr_driver::opts;
use pgr_fixtures::{FIXTURE_OSO_MTIME, ObjectBuilder, ObjectSection, ObjectStab, ObjectSymbol};
use pgr_format::consts::{N_FUN, N_OSO, N_SO, N_STAB};
use pgr_format::symtab::Nlist64;
use pgr_verify::{Options as VerifyOptions, verify};

/// main.o: `_main` over a small `__text`, with the minimal debug-map stab
/// set — `N_SO` (the source anchor), `N_OSO` (the object path + mtime),
/// `N_FUN` begin/end (re-addressed onto the placed `_main` atom).
fn stab_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_stab(ObjectStab::So {
        path: "main.c".into(),
    });
    b.add_stab(ObjectStab::Oso {
        path: "main.o".into(),
    });
    b.add_stab(ObjectStab::Fun {
        name: "_main".into(),
        section_index: text,
        value: 0,
    });
    b.add_stab(ObjectStab::FunEnd { size: 8 });
    b.build().expect("the fixture object builds")
}

/// Reads the output symtab's `nlist_64` entries from the image.
fn symtab_entries(image: &[u8]) -> Vec<Nlist64> {
    let Ok(hdr) = pgr_format::MachHeader64::parse(image) else {
        return Vec::new();
    };
    let Ok(mut it) = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    ) else {
        return Vec::new();
    };
    let mut st: Option<pgr_format::SymtabCommand> = None;
    while let Ok(Some(cmd)) = it.next_command() {
        if let pgr_format::LoadCommandKind::Symtab = cmd.kind {
            st = pgr_format::SymtabCommand::parse(cmd.bytes, 0).ok();
        }
    }
    let Some(st) = st else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(st.nsyms as usize);
    for i in 0..st.nsyms {
        if let Ok(sym) = pgr_format::cursor::pod_read_unaligned_at::<Nlist64>(
            image,
            st.symoff as usize + i as usize * 16,
        ) {
            out.push(sym);
        }
    }
    out
}

fn main() {
    let dir = std::env::temp_dir().join("pgr_example_debug_map_link");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");

    let obj = dir.join("main.o");
    std::fs::write(&obj, stab_object()).expect("the object writes");
    let out_path = dir.join("hello");
    let argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(&out_path).expect("the image reads");

    let syms = symtab_entries(&image);
    // The debug-map stabs ride as the first locals (clang's order — stabs
    // precede the plain locals, the extern defs and the undefineds).
    let stab_rows: Vec<&Nlist64> = syms.iter().filter(|s| s.n_type & N_STAB != 0).collect();
    assert!(
        !stab_rows.is_empty(),
        "the linked image carries the debug-map stabs"
    );
    // The four-row shape: N_SO, N_OSO, N_FUN begin, N_FUN end (the first
    // four locals, in emission order).
    let head: Vec<u8> = syms.iter().take(4).map(|s| s.n_type).collect();
    assert_eq!(
        head,
        [N_SO, N_OSO, N_FUN, N_FUN],
        "the debug-map stabs ride as the first four locals"
    );
    // The N_OSO row (row 1) carries the fixed deterministic mtime — the
    // file-existence gate dsymutil keys on.
    assert_eq!(
        syms[1].n_value, FIXTURE_OSO_MTIME,
        "the N_OSO row carries the fixed deterministic mtime"
    );

    // The image verifies strict (the debugmap family rides the full
    // verify pass — the read-side backstop the producer's emit-side gate
    // mirrors).
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&image, &opts);
    assert!(
        report.is_ok(&opts),
        "the stab-carrying image verifies strict: {:#?}",
        report.issues
    );
    println!(
        "the debug-map stabs ride the linked image ({} symtab rows, N_OSO mtime {:#x}); dsymutil-readiness verified strict",
        syms.len(),
        syms[1].n_value
    );

    let _ = std::fs::remove_dir_all(&dir);
}

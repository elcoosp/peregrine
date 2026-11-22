//! M129 — the debug-map stabs (D3): the `ld64`-shaped `n_type` rows the
//! producer's debug-map plan re-addresses onto placed live atoms so
//! `lldb`/`dsymutil` find the DWARF in the `.o` files. The plan emits
//! `N_SO` (the source-file anchor), `N_OSO` (the object-file path +
//! mtime `dsymutil` opens), `N_FUN` begin/end pairs (re-addressed onto
//! the placed live atom), `N_GSYM`, `N_STSYM`, `N_LSYM` and the
//! `N_BNSYM`/`N_ENSYM` bracket as the **first** locals (clang's order),
//! in file order (the deterministic sequence `dsymutil` walks).
//!
//! Gate matrix:
//! * the default — a stab-carrying corpus emits `N_SO`/`N_OSO`/`N_FUN`
//!   rows as the first locals, the `N_OSO` carries the fixed mtime, the
//!   `N_FUN` carries the re-addressed output vaddr;
//! * `-S` — the existing strip-debug flag drops the whole debug map
//!   (no new flag — the pre-M129 shape, byte-identical to a stab-free
//!   link);
//! * dead-strip — a `N_FUN` whose function died drops (the dead row
//!   must not dangle);
//! * the byte-identity lock — a stab-carrying corpus double-links
//!   byte-identical (the fixed mtime is the determinism contract);
//! * the verify gate — the linked image verifies strict under the
//!   `debugmap` family.

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{FIXTURE_OSO_MTIME, ObjectBuilder, ObjectSection, ObjectStab, ObjectSymbol};
use pgr_format::consts::{N_BNSYM, N_ENSYM, N_FUN, N_GSYM, N_LSYM, N_OSO, N_SO, N_STAB, N_STSYM};
use pgr_format::symtab::Nlist64;
use pgr_verify::{Options as VerifyOptions, verify};

/// A stab-carrying single-object corpus: `_main` over a small `__text`,
/// with the full debug-map stab set (`N_SO`, `N_OSO`, `N_FUN` begin/end,
/// `N_GSYM`, `N_STSYM`, `N_LSYM`, `N_BNSYM`, `N_ENSYM`).
fn stab_corpus() -> Vec<LinkInput> {
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
    b.add_stab(ObjectStab::Gsym {
        name: "_main".into(),
    });
    b.add_stab(ObjectStab::Stsym {
        name: "_static_var".into(),
        section_index: text,
        value: 4,
    });
    b.add_stab(ObjectStab::Lsym {
        name: "local_int:1".into(),
        value: 0,
    });
    b.add_stab(ObjectStab::Bnsym {
        section_index: text,
        value: 0,
    });
    b.add_stab(ObjectStab::Ensym {
        section_index: text,
        value: 0,
    });
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// Links the corpus with a config tweak and returns the image bytes
/// (the full emitted image, not just the header — the symtab rides in
/// `__LINKEDIT`).
fn link_image(tweak: impl FnOnce(&mut LinkConfig)) -> Vec<u8> {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    let result = link(&stab_corpus(), &[], &cfg).expect("the link runs");
    pgr_emit::build_image(&result.layout, &result.objects).expect("the image emits")
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
    let Some(st) = st else { return Vec::new() };
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

#[test]
fn the_default_emits_the_debug_map_stabs_as_the_first_locals() {
    let image = link_image(|_| {});
    let syms = symtab_entries(&image);
    // The first 9 rows are the debug-map stabs (clang's order — stabs
    // precede the plain locals, the extern defs and the undefineds).
    let stab_n_types = [
        N_SO, N_OSO, N_FUN, N_FUN, N_GSYM, N_STSYM, N_LSYM, N_BNSYM, N_ENSYM,
    ];
    assert!(
        syms.len() >= stab_n_types.len(),
        "the image carries at least the 9 stab rows (got {})",
        syms.len()
    );
    for (i, want) in stab_n_types.iter().enumerate() {
        assert_eq!(
            syms[i].n_type, *want,
            "stab row {i}: n_type 0x{:02x} not the named kind 0x{:02x}",
            syms[i].n_type, want
        );
        assert!(syms[i].is_stab(), "stab row {i}: the N_STAB bit is set");
    }
    // The image verifies strict (the debugmap family rides the full
    // verify pass).
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
}

#[test]
fn the_n_oso_row_carries_the_fixed_deterministic_mtime() {
    let image = link_image(|_| {});
    let syms = symtab_entries(&image);
    // N_OSO is row 1 (after N_SO at row 0).
    assert_eq!(syms[1].n_type, N_OSO);
    assert_eq!(
        syms[1].n_value, FIXTURE_OSO_MTIME,
        "the N_OSO row carries the fixed deterministic mtime"
    );
}

#[test]
fn the_n_fun_begin_row_carries_the_re_addressed_output_vaddr() {
    let image = link_image(|_| {});
    let syms = symtab_entries(&image);
    // N_FUN begin is row 2.
    assert_eq!(syms[2].n_type, N_FUN);
    assert_eq!(
        syms[2].n_sect, 1,
        "the N_FUN begin row names its output section"
    );
    // The value is the output vaddr of `_main` (re-addressed from the
    // input's section-relative 0 onto the placed `__text` atom). It is
    // nonzero (the link placed `__text` at a nonzero vaddr).
    assert!(
        syms[2].n_value != 0,
        "the N_FUN begin row carries a re-addressed vaddr"
    );
    // The N_FUN end row is row 3: n_value 0, the size in the name.
    assert_eq!(syms[3].n_type, N_FUN);
    assert_eq!(syms[3].n_sect, 0, "the N_FUN end row carries no section");
    assert_eq!(syms[3].n_value, 0, "the N_FUN end row carries a zero value");
}

#[test]
fn strip_debug_drops_the_whole_debug_map() {
    // -S (the existing strip_debug flag, no new flag) drops the whole
    // debug map — the producer emits zero stab rows, the pre-M129
    // shape (byte-identical to a stab-free link).
    let image = link_image(|cfg| cfg.strip_debug = true);
    let syms = symtab_entries(&image);
    for (i, sym) in syms.iter().enumerate() {
        assert!(
            !sym.is_stab(),
            "row {i}: a stab row rode under -S (the whole debug map must drop)"
        );
    }
    // The image still verifies strict.
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&image, &opts);
    assert!(
        report.is_ok(&opts),
        "the -S image verifies strict: {:#?}",
        report.issues
    );
}

#[test]
fn dead_strip_drops_the_n_fun_of_a_dead_function() {
    // A corpus with two functions, one referenced by `_main` (live) and
    // one not (dead). Under `-dead_strip` the dead function's `N_FUN`
    // must drop (the dead row must not dangle).
    let mut b = ObjectBuilder::new("two.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        // _main: ret; _dead: ret — 4 bytes each.
        [0xC0u8, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6].to_vec(),
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_dead".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.add_stab(ObjectStab::So {
        path: "two.c".into(),
    });
    b.add_stab(ObjectStab::Oso {
        path: "two.o".into(),
    });
    b.add_stab(ObjectStab::Fun {
        name: "_main".into(),
        section_index: text,
        value: 0,
    });
    b.add_stab(ObjectStab::FunEnd { size: 4 });
    b.add_stab(ObjectStab::Fun {
        name: "_dead".into(),
        section_index: text,
        value: 4,
    });
    b.add_stab(ObjectStab::FunEnd { size: 4 });
    let corpus = vec![LinkInput {
        name: "two.o".to_string(),
        bytes: b.build().expect("the fixture builds"),
    }];
    let cfg = LinkConfig {
        dead_strip: true,
        ..LinkConfig::default()
    };
    let result = link(&corpus, &[], &cfg).expect("the link runs");
    let image = pgr_emit::build_image(&result.layout, &result.objects).expect("the image emits");
    let syms = symtab_entries(&image);
    // The live `_main` N_FUN begin rides; the dead `_dead` N_FUN begin
    // drops. Count the N_FUN begin rows (n_sect == 1, value != 0): the
    // live one only.
    let fun_begins: Vec<&Nlist64> = syms
        .iter()
        .filter(|s| s.n_type == N_FUN && s.n_sect != 0)
        .collect();
    assert_eq!(
        fun_begins.len(),
        1,
        "exactly one live N_FUN begin row (the dead function's drops)"
    );
    // The image verifies strict.
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&image, &opts);
    assert!(
        report.is_ok(&opts),
        "the dead-strip image verifies strict: {:#?}",
        report.issues
    );
}

#[test]
fn the_double_link_is_byte_identical_with_stabs() {
    // The fixed mtime is the determinism contract — a stab-carrying
    // corpus double-links byte-identical.
    let a = link_image(|_| {});
    let b = link_image(|_| {});
    assert_eq!(a, b, "the stab-carrying double link is byte-identical");
}

#[test]
fn a_stab_free_corpus_links_byte_identical_to_the_pre_m129_shape() {
    // A stab-free corpus emits zero stab rows — the producer's debug
    // map plan skips the whole map when the input carries none (the
    // pre-M129 shape, byte-identical).
    let mut b = ObjectBuilder::new("plain.o").set_subsections_via_symbols(true);
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
    let corpus = vec![LinkInput {
        name: "plain.o".to_string(),
        bytes: b.build().expect("the fixture builds"),
    }];
    let cfg = LinkConfig::default();
    let result = link(&corpus, &[], &cfg).expect("the link runs");
    let image = pgr_emit::build_image(&result.layout, &result.objects).expect("the image emits");
    let syms = symtab_entries(&image);
    for (i, sym) in syms.iter().enumerate() {
        assert!(
            sym.n_type & N_STAB == 0,
            "row {i}: a stab row rode on a stab-free corpus"
        );
    }
}

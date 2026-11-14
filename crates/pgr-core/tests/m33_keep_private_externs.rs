//! M33 — the private-extern decision (`-keep_private_externs`): the
//! flag the driver surface accepted as a no-op since M1 becomes the
//! real decision on [`pgr_core::layout::LinkConfig`]. The input
//! `N_PEXT` bit (the compilers mark private externs with it) has been
//! dropped at parse until now — a private extern exported publicly,
//! exactly what ld64 would not do. M33 carries the bit and names the
//! decision: the default (ld64's shape) **converts** a private-extern
//! definition into a local (`N_SECT | N_PEXT`, the same row the
//! export filter's hidden path emits, absent from the export trie,
//! counted in the dysymtab locals range); `-keep_private_externs`
//! **holds** it external (`N_EXT | N_SECT | N_PEXT`, exported like any
//! other definition). A corpus without private externs plans the
//! pre-M33 bytes byte-identically under either decision — the bit is
//! the only trigger.
//!
//! Gate matrix:
//! * the conversion — the private extern lands in the locals range,
//!   absent from the trie;
//! * the keep — the row stays external, exported, `N_PEXT` set;
//! * the parity — a pext-free corpus is byte-identical under either
//!   decision;
//! * the determinism — the converted link is stable (the double-link
//!   gate).

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::{N_EXT, N_PEXT, N_SECT};

/// A corpus: `_main` a plain external, `_helper` a private external
/// (the compilers' `.private_extern` — the input `N_PEXT` bit).
fn pext_corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::DefinedPrivate {
        name: "_helper".into(),
        section_index: text,
        value: 4,
    });
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// A corpus without any private extern — the parity gate's shape.
fn plain_corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (i, sym) in ["_main", "_helper"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

fn plan(inputs: &[LinkInput], tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::layout::Layout {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(inputs, &[], &cfg).expect("the corpus links").layout
}

/// The output symtab row for `name` (`str_offsets` runs parallel to
/// `symbols`, so the row index reads its own `n_strx`).
fn row_of(
    layout: &pgr_core::layout::Layout,
    name: &[u8],
) -> Option<pgr_core::layout::OutputSymbol> {
    for (i, s) in layout.symbols.iter().enumerate() {
        let off = usize::try_from(layout.str_offsets[i]).expect("offset");
        let end = layout.strtab[off..]
            .iter()
            .position(|&b| b == 0)
            .expect("NUL");
        if &layout.strtab[off..off + end] == name {
            return Some(s.clone());
        }
    }
    None
}

/// The exported names the trie carries.
fn trie_names(layout: &pgr_core::layout::Layout) -> Vec<Vec<u8>> {
    pgr_format::trie::exports(&layout.trie)
        .expect("the trie walks")
        .into_iter()
        .map(|e| e.name)
        .collect()
}

// ---- the conversion and the keep ------------------------------------------------

#[test]
fn a_private_extern_defines_as_a_local_by_default() {
    assert!(
        !LinkConfig::default().keep_private_externs,
        "the default converts (ld64's shape)"
    );
    let layout = plan(&pext_corpus(), |_| {});
    let row = row_of(&layout, b"_helper").expect("the private extern lands in the symtab");
    assert!(
        row.n_type == N_SECT | N_PEXT && !row.external,
        "the conversion is the filter-hidden shape: N_SECT | N_PEXT, a local — got {:#x}",
        row.n_type
    );
    assert!(
        !trie_names(&layout).contains(&b"_helper".to_vec()),
        "the converted row never reaches the export trie"
    );
}

#[test]
fn the_keep_decision_holds_it_external() {
    let layout = plan(&pext_corpus(), |c| c.keep_private_externs = true);
    let row = row_of(&layout, b"_helper").expect("the kept private extern lands in the symtab");
    assert!(
        row.n_type == N_EXT | N_SECT | N_PEXT && row.external,
        "the keep holds the row external with N_PEXT set — got {:#x}",
        row.n_type
    );
    assert!(
        trie_names(&layout).contains(&b"_helper".to_vec()),
        "the kept row exports like any other definition"
    );
}

// ---- the parity and the determinism ---------------------------------------------

#[test]
fn a_pext_free_corpus_plans_byte_identically() {
    // The decision only fires on the input N_PEXT bit — a corpus
    // without it plans the pre-M33 bytes under either decision.
    let default = plan(&plain_corpus(), |_| {});
    let kept = plan(&plain_corpus(), |c| c.keep_private_externs = true);
    assert_eq!(default.header_bytes, kept.header_bytes);
    assert_eq!(default.symbols, kept.symbols);
    assert_eq!(default.trie, kept.trie);
}

#[test]
fn the_converted_link_is_deterministic() {
    let a = plan(&pext_corpus(), |_| {}).header_bytes;
    let b = plan(&pext_corpus(), |_| {}).header_bytes;
    assert_eq!(a, b, "the double link is stable");
}

// ---- the dysymtab range ---------------------------------------------------------

#[test]
fn the_converted_row_rides_the_locals_range() {
    // The dysymtab ranges are the loader's partition: the converted
    // row counts as a local, the kept one as a defined external.
    let carrying = plan(&pext_corpus(), |_| {});
    let kept = plan(&pext_corpus(), |c| c.keep_private_externs = true);
    assert_eq!(
        nlocalsym(&carrying.header_bytes),
        1,
        "the conversion counts the private extern in the locals range"
    );
    assert_eq!(
        nlocalsym(&kept.header_bytes),
        0,
        "the keep counts no locals (the row rides the extdef range)"
    );
}

/// The dysymtab `nlocalsym` the header carries.
fn nlocalsym(header: &[u8]) -> u32 {
    let h = pgr_format::MachHeader64::parse(header).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        header,
        pgr_format::MachHeader64::SIZE,
        h.ncmds,
        h.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let pgr_format::LoadCommandKind::Dysymtab = cmd.kind {
            return pgr_format::DysymtabCommand::parse(header, cmd.offset)
                .expect("the dysymtab parses")
                .nlocalsym;
        }
    }
    0
}

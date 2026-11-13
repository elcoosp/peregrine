//! M24 — the symbol-alias seam (`pgr_core::alias`): the
//! `-alias <alias_name> <definition_name>` decisions stop being an
//! unnameable symtab/trie shape and become a validated table on
//! [`pgr_core::layout::LinkConfig`] — the extra exported symbol names
//! ld64's `-alias` creates, each pointing at the same definition as the
//! named symbol (an ABI shim: the old name keeps resolving, the image
//! ships one body).
//!
//! Gate matrix:
//! * the seam — an alias validates (non-empty, NUL-free, the two names
//!   distinct) with the fix in the refusal, a repeated alias name
//!   refuses (one decision per name), and the table keeps flag order;
//! * layout — a named alias rides the symtab as a defined external row
//!   carrying the definition's section, value and weak mark, and joins
//!   the export trie at the same address (dyld resolves both names to
//!   one body), in flag order;
//! * the refusals — an alias of a name no input defines (the refusal
//!   names the misspelling), an alias name already defined in the image
//!   (one symtab row per external name — the duplicate would silently
//!   shadow), and the relocatable output (the object surface carries
//!   the input symtab verbatim);
//! * the lock — the default (empty) table plans what the pre-seam
//!   layout planned, and a double link stays byte-identical (TDD §4.3);
//! * dead-strip — an alias is an export root: under `-dead_strip` on an
//!   executable nothing references the target, the alias still does.

use pgr_core::alias::{Alias, AliasTable};
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// A two-function corpus (`_main`, `_lib_fn` in one `__text`) linkable
/// as any kind.
fn corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    for (i, sym) in ["_main", "_lib_fn"].iter().enumerate() {
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

/// Links the corpus with a config tweak and returns the layout.
fn link_layout(tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::Layout {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(&corpus(), &[], &cfg).expect("the corpus links").layout
}

/// A table with the two aliases the layout gates use, in flag order.
fn table() -> AliasTable {
    let mut t = AliasTable::new();
    t.push(Alias::from_parts("_pgr_alias_new", "_lib_fn").expect("validates"))
        .expect("lands");
    t.push(Alias::from_parts("_pgr_alias_second", "_main").expect("validates"))
        .expect("lands");
    t
}

// ---- the seam ----------------------------------------------------------------

#[test]
fn an_alias_validates_and_keeps_flag_order() {
    let a = Alias::from_parts("_new", "_old").expect("validates");
    assert_eq!(a.alias(), "_new");
    assert_eq!(a.definition(), "_old");
    let t = table();
    let aliases: Vec<&str> = t.iter().map(Alias::alias).collect();
    assert_eq!(
        aliases,
        ["_pgr_alias_new", "_pgr_alias_second"],
        "the table keeps flag order"
    );
    assert_eq!(t.count(), 2);
    assert!(!t.is_empty());
}

#[test]
fn refusals_name_the_fix() {
    // An empty name names no symbol.
    let err = Alias::from_parts("", "_old").expect_err("an empty alias refuses");
    assert!(err.to_string().contains("non-empty"), "{err}");
    let err = Alias::from_parts("_new", "").expect_err("an empty definition refuses");
    assert!(err.to_string().contains("non-empty"), "{err}");
    // The symtab strings are C strings: an interior NUL would silently
    // truncate the name to a different one.
    let err = Alias::from_parts("_new\0x", "_old").expect_err("NUL refuses");
    assert!(err.to_string().contains("NUL"), "{err}");
    let err = Alias::from_parts("_new", "_old\0").expect_err("NUL refuses");
    assert!(err.to_string().contains("NUL"), "{err}");
    // An alias of itself is a tautology — a silently dropped decision.
    let err = Alias::from_parts("_same", "_same").expect_err("identity refuses");
    assert!(err.to_string().contains("distinct"), "{err}");
}

#[test]
fn duplicate_alias_names_refuse() {
    let mut t = AliasTable::new();
    t.push(Alias::from_parts("_dup", "_old").expect("validates"))
        .expect("first lands");
    let err = t
        .push(Alias::from_parts("_dup", "_other").expect("validates"))
        .expect_err("duplicate refuses");
    assert!(err.to_string().contains("_dup"), "{err}");
    assert_eq!(t.count(), 1, "the refusal left the table untouched");
}

// ---- layout ------------------------------------------------------------------

#[test]
fn a_named_alias_rides_the_symtab_and_the_trie() {
    let cfg = LinkConfig {
        aliases: table(),
        ..LinkConfig::default()
    };
    let result = link(&corpus(), &[], &cfg).expect("the corpus links");
    let layout = &result.layout;

    // The alias rows: defined externals at the definition's value, in
    // flag order after the plain definitions.
    let alias_of = |name: &[u8]| {
        layout
            .symbols
            .iter()
            .find(|s| result.interner.bytes(s.name) == name)
            .unwrap_or_else(|| panic!("{:?} rides the symtab", String::from_utf8_lossy(name)))
    };
    let alias_new = alias_of(b"_pgr_alias_new");
    let alias_second = alias_of(b"_pgr_alias_second");
    let lib_fn = alias_of(b"_lib_fn");
    let main = alias_of(b"_main");
    for row in [alias_new, alias_second] {
        assert!(
            row.external && row.n_type & pgr_format::consts::N_TYPE == pgr_format::consts::N_SECT,
            "the alias is a defined external"
        );
    }
    assert_eq!(
        result.interner.bytes(alias_new.name),
        b"_pgr_alias_new",
        "flag order: the first alias is the first flag"
    );
    assert_eq!(
        alias_new.value, lib_fn.value,
        "the alias points at the body"
    );
    assert_eq!(alias_new.n_sect, lib_fn.n_sect, "same section");
    assert_eq!(alias_new.n_desc, lib_fn.n_desc, "same weak mark");
    assert_eq!(alias_second.value, main.value);
    assert_eq!(alias_second.n_desc, main.n_desc);

    // The trie: both alias names export at the definition's address.
    let exports = pgr_format::trie::exports(&layout.trie).expect("the trie walks");
    for (alias, target) in [
        (&b"_pgr_alias_new"[..], &b"_lib_fn"[..]),
        (&b"_pgr_alias_second"[..], &b"_main"[..]),
    ] {
        let a = exports
            .iter()
            .find(|e| e.name == alias)
            .unwrap_or_else(|| panic!("{alias:?} exports"));
        let t = exports
            .iter()
            .find(|e| e.name == target)
            .unwrap_or_else(|| panic!("{target:?} exports"));
        assert_eq!(a.address, t.address, "the alias exports at the body");
        assert_eq!(a.flags, t.flags, "the alias carries the definition's marks");
    }
}

#[test]
fn the_refusals_name_the_shape_that_cannot_land() {
    // The definition is nowhere: the refusal names the misspelling.
    let mut cfg = LinkConfig::default();
    cfg.aliases
        .push(Alias::from_parts("_alias", "_nowhere").expect("validates"))
        .expect("lands");
    let err = link(&corpus(), &[], &cfg).expect_err("the undefined definition refuses");
    assert!(err.to_string().contains("_nowhere"), "{err}");

    // The alias name is already defined: one symtab row per external
    // name — the duplicate would silently shadow.
    let mut cfg = LinkConfig::default();
    cfg.aliases
        .push(Alias::from_parts("_lib_fn", "_main").expect("validates"))
        .expect("lands");
    let err = link(&corpus(), &[], &cfg).expect_err("the defined alias name refuses");
    assert!(err.to_string().contains("_lib_fn"), "{err}");

    // The relocatable output: the object surface carries the input
    // symtab verbatim — an alias is an image-surface decision.
    let mut cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        ..LinkConfig::default()
    };
    cfg.aliases = table();
    let err = link(&corpus(), &[], &cfg).expect_err("the relocatable output refuses");
    assert!(
        err.to_string().contains("relocatable"),
        "the refusal names the output kind: {err}"
    );
}

// ---- the lock ----------------------------------------------------------------

#[test]
fn the_default_links_byte_identical_and_alias_free() {
    let a = link_layout(|_| {});
    let b = link_layout(|_| {});
    assert_eq!(a.header_bytes, b.header_bytes, "the double link is stable");
    let exports = pgr_format::trie::exports(&a.trie).expect("the trie walks");
    assert!(
        exports.iter().all(|e| !e.name.starts_with(b"_pgr_alias")),
        "the default carries no alias exports"
    );
}

// ---- dead-strip --------------------------------------------------------------

/// A corpus whose `_lib_fn` nothing references — only an alias could
/// keep it alive.
fn unreferenced_corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
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
    b.add_symbol(ObjectSymbol::Defined {
        name: "_lib_fn".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

#[test]
fn an_alias_keeps_its_definition_alive_under_dead_strip() {
    let corpus = unreferenced_corpus();
    let mut aliases = AliasTable::new();
    aliases
        .push(Alias::from_parts("_pgr_alias_new", "_lib_fn").expect("validates"))
        .expect("lands");
    let cfg = LinkConfig {
        dead_strip: true,
        aliases,
        ..LinkConfig::default()
    };
    let layout = link(&corpus, &[], &cfg).expect("the corpus links").layout;
    let exports = pgr_format::trie::exports(&layout.trie).expect("the trie walks");
    assert!(
        exports.iter().any(|e| e.name == b"_lib_fn"),
        "the aliased definition survives the strip: {:?}",
        exports.iter().map(|e| e.name.clone()).collect::<Vec<_>>()
    );
    assert!(exports.iter().any(|e| e.name == b"_pgr_alias_new"));

    // The control: without the alias the unreferenced body dies (the
    // ld64 shape the export root prevents).
    let cfg = LinkConfig {
        dead_strip: true,
        ..LinkConfig::default()
    };
    let control = link(&corpus, &[], &cfg).expect("the corpus links").layout;
    let exports = pgr_format::trie::exports(&control.trie).expect("the trie walks");
    assert!(
        exports.iter().all(|e| e.name != b"_lib_fn"),
        "the control: the unreferenced body strips"
    );
}

//! M14 — the export-filter glob seam (`pgr_core::export_filter`): the
//! `-exported_symbols_list`/`-unexported_symbols_list` entries stop being
//! exact-name byte strings and become named `SymbolPattern`s — an exact
//! name or a `*` wildcard glob (the ld64 subset: each `*` matches any,
//! possibly empty, byte run; every other byte is literal). The M3
//! semantics survive unchanged under all-exact filters: the same visible
//! set plans the same bytes, so the M3 gates hold bit-for-bit.
//!
//! Gate matrix:
//! * parse — exact, globs, `**` collapse; empty and whitespace-carrying
//!   lines refuse with the fix in the message;
//! * match — prefix/middle/suffix stars, the empty-match rule, the
//!   [`pgr_core::export_filter::SymbolMatcher`] trait on single patterns
//!   and slices;
//! * visibility — the M3 contract (the only-list gates, the unexported
//!   list removes) through the new types;
//! * links — a glob-filtered link exports exactly the matched surface,
//!   an all-exact filter plans the same bytes as the glob that matches
//!   the same names, and a glob-filtered double link stays identical
//!   (TDD §4.3).

use pgr_core::export_filter::{SymbolMatcher, SymbolPattern, is_export_visible};
use pgr_core::layout::{Layout, LinkConfig};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// Two-object corpus: an SDK-looking surface (`_sdk_*`), an internal
/// helper and a util object — enough names for the filter to select.
fn corpus() -> Vec<LinkInput> {
    fn object(name: &str, syms: &[&str]) -> LinkInput {
        let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
        let text = b.add_section(ObjectSection::text(
            "__text",
            [0xC0u8, 0x03, 0x5F, 0xD6].repeat(syms.len()),
            vec![],
        ));
        for (i, sym) in syms.iter().enumerate() {
            b.add_symbol(ObjectSymbol::Defined {
                name: (*sym).into(),
                section_index: text,
                value: (i * 4) as u64,
                weak: false,
            });
        }
        LinkInput {
            name: name.to_string(),
            bytes: b.build().expect("the fixture object builds"),
        }
    }
    vec![
        object(
            "sdk.o",
            &["_main", "_sdk_init", "_sdk_read", "_internal_seed"],
        ),
        object("util.o", &["_sdk_write", "_util_helper"]),
    ]
}

/// Links the corpus with a config tweak and returns the Pass-3 product
/// (the trie and the symtab are the filter's own surfaces).
fn link_layout(tweak: impl FnOnce(&mut LinkConfig)) -> (Layout, pgr_core::Interner) {
    let mut cfg = LinkConfig {
        entry_symbol: "_main".into(),
        ..LinkConfig::default()
    };
    tweak(&mut cfg);
    let result = link(&corpus(), &[], &cfg).expect("the corpus links");
    (result.layout, result.interner)
}

/// The trie's export names, read back through the format layer.
fn exported_names(layout: &Layout) -> Vec<String> {
    pgr_format::trie::exports(&layout.trie)
        .expect("the layout trie parses")
        .into_iter()
        .map(|e| String::from_utf8_lossy(&e.name).into_owned())
        .collect()
}

/// The symtab's `n_type` for `name` (`None` when absent).
fn symtab_n_type(layout: &Layout, interner: &pgr_core::Interner, name: &[u8]) -> Option<u8> {
    layout
        .symbols
        .iter()
        .find(|s| interner.bytes(s.name) == name)
        .map(|s| s.n_type)
}

/// The filter-visible plan shape: header bytes, trie bytes and the
/// symtab rows by `(name, n_type, n_sect, n_value)` — everything the
/// export filter can move.
fn visible_plan(
    layout: &Layout,
    interner: &pgr_core::Interner,
) -> (Vec<u8>, Vec<u8>, Vec<(Vec<u8>, u8, u8, u64)>) {
    let rows = layout
        .symbols
        .iter()
        .map(|s| (interner.bytes(s.name).to_vec(), s.n_type, s.n_sect, s.value))
        .collect();
    (layout.header_bytes.clone(), layout.trie.clone(), rows)
}

#[test]
fn parse_accepts_exact_and_glob_forms() {
    assert_eq!(
        SymbolPattern::parse(b"_foo_add").unwrap(),
        SymbolPattern::exact(b"_foo_add")
    );
    // A single star, a star-only pattern, and a multi-star pattern parse.
    assert!(matches!(
        SymbolPattern::parse(b"_sdk_*"),
        Ok(SymbolPattern::Glob(_))
    ));
    assert!(matches!(
        SymbolPattern::parse(b"*"),
        Ok(SymbolPattern::Glob(_))
    ));
    assert!(matches!(
        SymbolPattern::parse(b"_*classref*"),
        Ok(SymbolPattern::Glob(_))
    ));
    // `**` carries the same meaning as `*` (each star matches any run,
    // so the pair matches exactly what one star matches).
    let two = SymbolPattern::parse(b"_sdk_**").unwrap();
    assert!(two.matches(b"_sdk_init"));
    assert!(two.matches(b"_sdk_"));
    assert!(!two.matches(b"_sdk"));
}

#[test]
fn parse_refuses_empty_and_whitespace_with_the_fix() {
    // An empty pattern matches nothing: refuse, name the fix.
    let err = SymbolPattern::parse(b"").unwrap_err();
    assert!(err.to_string().contains("empty"), "{err}");
    // Interior whitespace is a typo (Mach-O names cannot carry it).
    let err = SymbolPattern::parse(b"_foo bar").unwrap_err();
    assert!(err.to_string().contains("_foo bar"), "{err}");
    let err = SymbolPattern::parse(b"_foo\tbar").unwrap_err();
    assert!(err.to_string().contains("_foo\tbar"), "{err}");
}

#[test]
fn exact_matches_byte_for_byte_and_globs_wildcard() {
    let exact = SymbolPattern::parse(b"_sdk_init").unwrap();
    assert!(exact.matches(b"_sdk_init"));
    assert!(!exact.matches(b"_sdk_ini"));
    assert!(!exact.matches(b"_sdk_init2"));

    let prefix = SymbolPattern::parse(b"_sdk_*").unwrap();
    assert!(prefix.matches(b"_sdk_init"));
    assert!(prefix.matches(b"_sdk_"), "the star may match the empty run");
    assert!(!prefix.matches(b"_sdk"));
    assert!(!prefix.matches(b"_internal_seed"));

    let suffix = SymbolPattern::parse(b"*_init").unwrap();
    assert!(suffix.matches(b"_sdk_init"));
    assert!(suffix.matches(b"_init"), "the star may match the empty run");
    assert!(!suffix.matches(b"_sdk_read"));

    let middle = SymbolPattern::parse(b"_*class*").unwrap();
    assert!(middle.matches(b"__objc_classrefs"));
    assert!(!middle.matches(b"__objc_selrefs"));

    let all = SymbolPattern::parse(b"*").unwrap();
    assert!(all.matches(b"_anything"));
    assert!(all.matches(b""));
}

#[test]
fn the_matcher_trait_covers_patterns_and_slices() {
    let list = [
        SymbolPattern::parse(b"_sdk_init").unwrap(),
        SymbolPattern::parse(b"_util_*").unwrap(),
    ];
    assert!(list.matches(b"_sdk_init"));
    assert!(list.matches(b"_util_helper"));
    assert!(!list.matches(b"_internal_seed"));
    // A single pattern is its own matcher.
    let one = SymbolPattern::parse(b"_sdk_*").unwrap();
    assert!(one.matches(b"_sdk_read"));
}

#[test]
fn visibility_semantics_mirror_m3_through_the_new_types() {
    let only = |pats: &[&[u8]]| -> Option<Vec<SymbolPattern>> {
        Some(
            pats.iter()
                .map(|p| SymbolPattern::parse(p).unwrap())
                .collect(),
        )
    };
    let unexported: Vec<SymbolPattern> = vec![SymbolPattern::parse(b"_internal_*").unwrap()];

    // The only-list gates: a name outside it never exports, even when
    // the unexported list would allow it.
    assert!(!is_export_visible(
        only(&[b"_sdk_*"]).as_deref(),
        &[],
        b"_internal_seed"
    ));
    // The unexported list removes: a name inside it never exports,
    // only-list or not.
    assert!(!is_export_visible(
        only(&[b"_*"]).as_deref(),
        &unexported,
        b"_internal_seed"
    ));
    // Inside the only-list and outside the unexported list: visible.
    assert!(is_export_visible(
        only(&[b"_sdk_*"]).as_deref(),
        &unexported,
        b"_sdk_init"
    ));
    // No lists at all: everything is visible (the M3 default).
    assert!(is_export_visible(None, &[], b"_internal_seed"));
}

#[test]
fn glob_filtered_link_exports_only_the_matched_surface() {
    let (layout, _interner) = link_layout(|cfg| {
        cfg.exported_only = Some(vec![
            SymbolPattern::exact(b"__mh_execute_header"),
            SymbolPattern::parse(b"_sdk_*").unwrap(),
        ]);
    });
    let names = exported_names(&layout);
    assert!(names.contains(&"_sdk_init".to_string()), "{names:?}");
    assert!(names.contains(&"_sdk_read".to_string()), "{names:?}");
    assert!(names.contains(&"_sdk_write".to_string()), "{names:?}");
    assert!(
        names.contains(&"__mh_execute_header".to_string()),
        "{names:?}"
    );
    assert!(!names.contains(&"_internal_seed".to_string()), "{names:?}");
    assert!(!names.contains(&"_util_helper".to_string()), "{names:?}");
}

#[test]
fn unexported_glob_hides_the_matched_surface() {
    let (layout, interner) = link_layout(|cfg| {
        cfg.unexported = vec![SymbolPattern::parse(b"_internal_*").unwrap()];
    });
    let names = exported_names(&layout);
    assert!(!names.contains(&"_internal_seed".to_string()), "{names:?}");
    assert!(names.contains(&"_sdk_init".to_string()), "{names:?}");
    // The hidden name survives in the symtab as a private external
    // (`N_PEXT`, no `N_EXT`) — ld64's behavior, now glob-driven.
    let n_type =
        symtab_n_type(&layout, &interner, b"_internal_seed").expect("_internal_seed in the symtab");
    assert_eq!(
        n_type & pgr_format::consts::N_TYPE,
        pgr_format::consts::N_SECT,
        "still a section symbol"
    );
    assert_eq!(n_type & pgr_format::consts::N_EXT, 0, "no longer external");
    assert!(n_type & pgr_format::consts::N_PEXT != 0, "marked private");
}

#[test]
fn all_exact_filters_plan_the_same_bytes_as_the_equivalent_glob() {
    // The matching widened; the plan did not: an exact list and the glob
    // that selects the same names produce the same visible plan.
    let (exact, interner1) = link_layout(|cfg| {
        cfg.exported_only = Some(vec![
            SymbolPattern::exact(b"__mh_execute_header"),
            SymbolPattern::exact(b"_sdk_init"),
            SymbolPattern::exact(b"_sdk_read"),
            SymbolPattern::exact(b"_sdk_write"),
        ]);
    });
    let (globbed, interner2) = link_layout(|cfg| {
        cfg.exported_only = Some(vec![
            SymbolPattern::exact(b"__mh_execute_header"),
            SymbolPattern::parse(b"_sdk_*").unwrap(),
        ]);
    });
    assert_eq!(
        visible_plan(&exact, &interner1),
        visible_plan(&globbed, &interner2),
        "same visible set, same plan bytes"
    );
}

#[test]
fn glob_filtered_double_link_is_identical() {
    let plan = || {
        let (layout, interner) = link_layout(|cfg| {
            cfg.exported_only = Some(vec![
                SymbolPattern::exact(b"__mh_execute_header"),
                SymbolPattern::parse(b"_sdk_*").unwrap(),
            ]);
            cfg.unexported = vec![SymbolPattern::parse(b"_internal_*").unwrap()];
        });
        visible_plan(&layout, &interner)
    };
    assert_eq!(plan(), plan(), "double link must be identical (TDD §4.3)");
}

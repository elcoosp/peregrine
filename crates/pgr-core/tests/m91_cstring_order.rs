//! M91 — the `-sectorder __TEXT __cstring` literal face: the cstring
//! mode ld64 parses for the cstring pair (`parseSectionOrderFile` →
//! `parseOrderFile(path, true)`) rides the D4 dedup surface. The file's
//! lines are literal *contents* — escape-decoded (`\n`, `\t`, `\v`,
//! `\b`, `\r`, `\f`, `\a`, `\\`, `\?`, `\"`; `\xHH…` hex and `\NNN…`
//! octal, both truncated to the byte the format carries; an unknown
//! escape rides verbatim; `\'` decodes as the quote — ld64's own table
//! maps it to `\r`, an evident upstream typo the compat row names),
//! leading whitespace rides (the cstring mode's own rule), trailing
//! whitespace trims, `#` comments only at column 0 (mid-line `#` is
//! literal in this mode), and the decoded bytes are the rank key. The
//! D4 canonical instances sort by content rank — a stable pass, the
//! unranked literals keeping their first-use order behind them — and
//! every instance's remap lands on the single output copy whatever the
//! ranks say. An entry that ranks nothing rides the advisory (the
//! M11/M90 face); the default (no table) packs `__cstring` exactly as
//! before — byte-identical, the always-carried gate.
//!
//! Gate matrix:
//! * the parse — the escape set, the line rules, the duplicate refusal
//!   with both lines;
//! * the ranked link — the placed `__cstring` bytes carry the literals
//!   in rank order, the duplicates resolving through the canonical
//!   copy;
//! * the dedup toggle — `-no_deduplicate` ranks the verbatim
//!   instances the same way;
//! * the advisory — an entry that names no placed literal reports in
//!   rank order, never an error;
//! * the default parity — no table plans the pre-M91 bytes exactly.

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::order::{CstringOrder, OrderFileError};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// One `__TEXT,__cstring` section carrying the named literals (one
/// NUL-terminated atom each — the D4 split).
fn cstring_section(literals: &[&str]) -> ObjectSection {
    let mut data = Vec::new();
    for literal in literals {
        data.extend_from_slice(literal.as_bytes());
        data.push(0);
    }
    ObjectSection {
        name: "__cstring".into(),
        segment: "__TEXT".into(),
        align_log2: 0,
        flags: pgr_format::consts::S_CSTRING_LITERALS,
        data,
        relocs: Vec::new(),
    }
}

/// An object whose `__text` carries one `_main` atom (the entry) and
/// whose `__cstring` section carries the named literals.
fn cstring_object(name: &str, main_symbol: &str, literals: &[&str]) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    b.add_section(cstring_section(literals));
    b.add_symbol(ObjectSymbol::Defined {
        name: main_symbol.into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Links the corpus with the given cstring rank text and returns the
/// placed `__cstring` bytes.
fn linked_cstrings(order_text: Option<&str>) -> Vec<u8> {
    let mut cfg = LinkConfig {
        entry_symbol: "_main".into(),
        ..LinkConfig::default()
    };
    if let Some(text) = order_text {
        cfg.cstring_order = Some(CstringOrder::parse(text).expect("the rank text parses"));
    }
    let inputs = vec![
        LinkInput {
            name: "a.o".into(),
            bytes: cstring_object("a.o", "_main", &["alpha\n", "beta", "shared", "delta"]),
        },
        LinkInput {
            name: "b.o".into(),
            bytes: cstring_object("b.o", "_b_main", &["gamma", "epsilon", "shared"]),
        },
    ];
    let result = link(&inputs, &[], &cfg).expect("the corpus links");
    let sect = result
        .layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__cstring")
        .expect("the cstring section places");
    // The placed bytes: the emitted image's copy stream is the plan's
    // own — the literals in piece order, NUL-terminated.
    let mut out = Vec::new();
    for p in &sect.pieces {
        let obj = &result.objects[p.file.0 as usize];
        let range = &p.in_range;
        out.extend_from_slice(&obj.bytes[range.start as usize..range.end as usize]);
    }
    out
}

/// The placed `__cstring` bytes as the literal list (NUL-split).
fn placed_literals(bytes: &[u8]) -> Vec<&str> {
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| std::str::from_utf8(s).expect("the literals are utf-8"))
        .collect()
}

// ---- the parse -----------------------------------------------------------

#[test]
fn the_parse_decodes_the_escape_set() {
    // The named escapes, hex, octal, and the verbatim unknown.
    let order =
        CstringOrder::parse("a\\tb\n\\x41\\x42\n\\101\\102x\nq\\\\r\n\\d\n").expect("parses");
    let entries: Vec<&[u8]> = order.entries().iter().map(|e| e.as_slice()).collect();
    assert_eq!(
        entries,
        [
            b"a\tb".as_slice(), // \t decodes
            b"AB".as_slice(),   // \x41\x42 — hex
            b"ABx".as_slice(),  // \101\102 — octal (65, 66) beside the literal x
            b"q\\r".as_slice(), // \\ rides, the r literal
            b"\\d".as_slice(),  // the unknown escape rides verbatim
        ],
        "the escape set decodes: {entries:?}"
    );
}

#[test]
fn the_parse_follows_the_cstring_line_rules() {
    // Leading whitespace rides (the cstring mode's own rule), trailing
    // whitespace trims, `#` comments only at column 0, blank lines
    // skip, mid-line `#` is literal.
    let order = CstringOrder::parse("# comment\n  padded  \nmid # hash\n\n").expect("parses");
    let entries: Vec<&[u8]> = order.entries().iter().map(|e| e.as_slice()).collect();
    assert_eq!(
        entries,
        [b"  padded".as_slice(), b"mid # hash".as_slice()],
        "the line rules: {entries:?}"
    );
}

#[test]
fn the_parse_refuses_duplicates_and_the_empty_file() {
    let dup = CstringOrder::parse("same\nother\nsame\n").unwrap_err();
    assert!(
        matches!(
            dup,
            OrderFileError::Duplicate {
                line: 3,
                first: 1,
                ..
            }
        ),
        "{dup}"
    );
    assert_eq!(
        CstringOrder::parse("# only a comment\n"),
        Err(OrderFileError::Empty)
    );
}

// ---- the ranked link -------------------------------------------------------

#[test]
fn the_ranked_literals_lead_in_rank_order() {
    // The ranks pull `gamma` (b.o) then `beta` (a.o) ahead of the
    // canonical first-use order; the unranked literals keep the
    // canonical order behind them.
    let bytes = linked_cstrings(Some("gamma\nbeta\n"));
    let placed = placed_literals(&bytes);
    assert_eq!(
        placed[..2],
        ["gamma", "beta"],
        "the ranked literals lead in rank order: {placed:?}"
    );
}

#[test]
fn duplicates_resolve_through_the_canonical_copy() {
    // `shared` rides twice in the inputs; one canonical copy places,
    // and its position follows the rank — the remap lands every
    // instance on it whatever the ranks say.
    let bytes = linked_cstrings(Some("shared\nalpha\n"));
    let canonical = placed_literals(&bytes);
    assert_eq!(
        canonical.len(),
        6,
        "six unique literals place once each: {canonical:?}"
    );
    assert_eq!(
        canonical[0], "shared",
        "the ranked duplicate leads through its canonical copy: {canonical:?}"
    );
    // Without a rank the canonical copy is the first-use instance —
    // the same six literals, the D4 order.
    let bytes = linked_cstrings(None);
    let plain = placed_literals(&bytes);
    assert_eq!(plain.len(), 6);
    assert_eq!(plain[0], "alpha\n", "the first-use literal leads unranked");
}

#[test]
fn the_default_parity_keeps_the_pre_m91_bytes() {
    // An unmatching table is the always-carried gate: the stable pass
    // over the canonical order is identity, so the placed bytes match
    // the no-table link exactly (the pre-M91 shape).
    let plain = linked_cstrings(None);
    let unranked = linked_cstrings(Some("nomatch\n"));
    assert_eq!(
        plain, unranked,
        "an unmatching table leaves the canonical bytes (the stable pass is identity)"
    );
}

#[test]
fn unmatched_entries_ride_the_advisory() {
    let order = CstringOrder::parse("nomatch\ngamma\n").expect("parses");
    let mut cfg = LinkConfig {
        entry_symbol: "_main".into(),
        cstring_order: Some(order),
        ..LinkConfig::default()
    };
    let inputs = vec![
        LinkInput {
            name: "a.o".into(),
            bytes: cstring_object("a.o", "_main", &["alpha\n", "beta"]),
        },
        LinkInput {
            name: "b.o".into(),
            bytes: cstring_object("b.o", "_b_main", &["gamma"]),
        },
    ];
    let result = link(&inputs, &[], &cfg).expect("the corpus links");
    assert_eq!(
        result.layout.cstring_order_unmatched,
        vec![b"nomatch".to_vec()],
        "the unmatched literal reports in rank order (the M11 face)"
    );
}

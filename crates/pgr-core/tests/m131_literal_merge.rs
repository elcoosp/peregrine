//! M131 — the D4 literal-merge completion: the fixed-width literal
//! sections (`S_4BYTE_LITERALS`, `S_8BYTE_LITERALS`, `S_16BYTE_LITERALS`)
//! the parser splits at their 4/8/16-byte widths now ride the D4 dedup
//! machinery the cstrings have used since M5 — one canonical output copy
//! per unique value, every duplicate's symbol remapped onto the canonical
//! address. No new flag (ld64's `-no_deduplicate` already named the whole
//! D4 surface at M41; the fixed-width literals inherit the decision).
//!
//! Gate matrix:
//! * the default — duplicate values across inputs merge into one output
//!   copy and the duplicate's symbol remaps to the canonical address (the
//!   D4 contract, widened from cstrings to the fixed-width literals);
//! * the suppression — `-no_deduplicate` keeps every copy (the verbatim
//!   pass-through, the M41 polarity);
//! * dead-strip — a dead literal drops under both decisions (the strip
//!   widens the merge off, never the strip — the M41 liveness contract,
//!   one section type over);
//! * the byte-identity lock — the fused tile emit matches the reference
//!   emit byte-for-byte, and a double-link is byte-identical (the M4
//!   discipline the new path inherits);
//! * the verify gate — the linked image verifies strict under the new
//!   `literal` family (the stride + alignment backstop).

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::{
    S_4BYTE_LITERALS, S_8BYTE_LITERALS, S_16BYTE_LITERALS, SECTION_TYPE_MASK,
};
use pgr_verify::{Options as VerifyOptions, verify};

/// One object: `_main` (or `_<name>`) over a small `__text`, plus a
/// fixed-width literal section carrying `values` (each exactly `width`
/// bytes), with `first_sym` rooted at offset 0 (the first value). Mirrors
/// the M41 `ret_object` shape over the cstring face.
fn literal_object(
    name: &str,
    width: u32,
    sect_name: &str,
    flags: u32,
    align_log2: u32,
    values: &[&[u8]],
    first_sym: &str,
) -> Vec<u8> {
    for (i, v) in values.iter().enumerate() {
        assert_eq!(
            v.len(),
            width as usize,
            "value {i} is not the named {width}-byte width"
        );
    }
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: if name == "a.o" {
            "_main".into()
        } else {
            format!("_{}", name.trim_end_matches(".o"))
        },
        section_index: text,
        value: 0,
        weak: false,
    });
    let mut data = Vec::with_capacity(values.len() * width as usize);
    for v in values {
        data.extend_from_slice(v);
    }
    let lit = b.add_section(ObjectSection {
        name: sect_name.into(),
        segment: "__TEXT".into(),
        align_log2,
        flags,
        data,
        relocs: Vec::new(),
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: first_sym.into(),
        section_index: lit,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// The output `__TEXT,<sect_name>` placed section.
fn literal_section<'a>(
    layout: &'a pgr_core::layout::Layout,
    sect_name: &str,
) -> &'a pgr_core::layout::PlacedSection {
    layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == sect_name)
        .expect("the corpus carries the literal bucket")
}

/// The input symbol index of the object's one literal-section symbol
/// (each fixture object defines exactly one named literal at offset 0).
fn literal_sym_index(obj: &pgr_core::object::InputObject, sect_type: u32) -> usize {
    let lit_sect = obj
        .sections
        .iter()
        .position(|s| s.flags & SECTION_TYPE_MASK == sect_type)
        .expect("the fixture carries the literal section");
    obj.symbols
        .iter()
        .position(|s| s.section == Some(lit_sect))
        .expect("the fixture symbol names the literal")
}

/// Asserts the default dedups duplicate values across two inputs: the
/// output carries one copy per unique value, and the two objects' offset-0
/// symbols (both naming the shared value) resolve to the same address.
fn assert_default_dedups(
    width: u32,
    sect_name: &str,
    flags: u32,
    align_log2: u32,
    sect_type: u32,
    shared: &[u8],
    only_a: &[u8],
    only_b: &[u8],
) {
    let a = literal_object(
        "a.o",
        width,
        sect_name,
        flags,
        align_log2,
        &[shared, only_a],
        "_s1",
    );
    let b_bytes = literal_object(
        "b.o",
        width,
        sect_name,
        flags,
        align_log2,
        &[shared, only_b],
        "_s2",
    );
    let cfg = LinkConfig {
        load_symbols: vec![b"_s1".to_vec(), b"_s2".to_vec()],
        ..LinkConfig::default()
    };
    let inputs = vec![
        LinkInput {
            name: "a.o".to_string(),
            bytes: a,
        },
        LinkInput {
            name: "b.o".to_string(),
            bytes: b_bytes,
        },
    ];
    let result = link(&inputs, &[], &cfg).expect("the corpus links");
    let sect = literal_section(&result.layout, sect_name);
    // Three unique values (shared, only_a, only_b) → one canonical copy
    // each, three pieces, size = 3 * width.
    assert_eq!(
        sect.size,
        u64::from(width) * 3,
        "the default carries one output copy per unique {sect_name} value"
    );
    assert_eq!(sect.pieces.len(), 3, "one canonical piece per unique value");
    // The duplicate's symbol remaps to the canonical address (the D4
    // remap — both _s1 and _s2 name the shared value).
    let i1 = literal_sym_index(&result.objects[0], sect_type);
    let i2 = literal_sym_index(&result.objects[1], sect_type);
    let v1 = result.layout.resolved[0].syms[i1];
    let v2 = result.layout.resolved[1].syms[i2];
    assert_eq!(
        v1, v2,
        "the duplicate {sect_name} value resolves to the canonical copy"
    );
    // The fused emit matches the reference emit (the M4 byte-identity
    // discipline the new dedup path inherits).
    let reference = pgr_emit::build_image(&result.layout, &result.objects).expect("the ref emits");
    let fused =
        pgr_emit::build_image_fused(&result.layout, &result.objects).expect("the fused emits");
    assert_eq!(
        reference, fused,
        "the fused {sect_name} emit matches the reference emit byte-for-byte"
    );
    // The image verifies strict (the literal backstop passes on the
    // well-formed deduped pool).
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&fused, &opts);
    assert!(
        report.is_ok(&opts),
        "the {sect_name} image verifies strict: {:#?}",
        report.issues
    );
}

#[test]
fn the_default_dedups_literal4_duplicates() {
    assert_default_dedups(
        4,
        "__literal4",
        S_4BYTE_LITERALS,
        2,
        S_4BYTE_LITERALS,
        &[0x01, 0x02, 0x03, 0x04],
        &[0xAA, 0xBB, 0xCC, 0xDD],
        &[0x11, 0x22, 0x33, 0x44],
    );
}

#[test]
fn the_default_dedups_literal8_duplicates() {
    assert_default_dedups(
        8,
        "__literal8",
        S_8BYTE_LITERALS,
        3,
        S_8BYTE_LITERALS,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
        &[0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99],
    );
}

#[test]
fn the_default_dedups_literal16_duplicates() {
    assert_default_dedups(
        16,
        "__literal16",
        S_16BYTE_LITERALS,
        4,
        S_16BYTE_LITERALS,
        &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ],
        &[
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ],
        &[
            0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE,
            0x0F, 0x10,
        ],
    );
}

// ---- the suppression (the M41 polarity) --------------------------------------

#[test]
fn no_deduplicate_passes_literal4_through() {
    let shared = [0x01u8, 0x02, 0x03, 0x04];
    let only_a = [0xAAu8, 0xBB, 0xCC, 0xDD];
    let only_b = [0x11u8, 0x22, 0x33, 0x44];
    let a = literal_object(
        "a.o",
        4,
        "__literal4",
        S_4BYTE_LITERALS,
        2,
        &[&shared, &only_a],
        "_s1",
    );
    let b_bytes = literal_object(
        "b.o",
        4,
        "__literal4",
        S_4BYTE_LITERALS,
        2,
        &[&shared, &only_b],
        "_s2",
    );
    let cfg = LinkConfig {
        deduplicate: false,
        load_symbols: vec![b"_s1".to_vec(), b"_s2".to_vec()],
        ..LinkConfig::default()
    };
    let inputs = vec![
        LinkInput {
            name: "a.o".to_string(),
            bytes: a,
        },
        LinkInput {
            name: "b.o".to_string(),
            bytes: b_bytes,
        },
    ];
    let result = link(&inputs, &[], &cfg).expect("the corpus links");
    let sect = literal_section(&result.layout, "__literal4");
    // The suppression keeps every input copy: four values placed
    // verbatim (no merge), size = 4 * 4 = 16.
    assert_eq!(
        sect.size, 16,
        "the suppression keeps every literal4 copy (the verbatim pass-through)"
    );
    // The two offset-0 symbols (both naming the shared value) land on
    // distinct instances — the verbatim pass-through, no remap.
    let i1 = literal_sym_index(&result.objects[0], S_4BYTE_LITERALS);
    let i2 = literal_sym_index(&result.objects[1], S_4BYTE_LITERALS);
    let v1 = result.layout.resolved[0].syms[i1];
    let v2 = result.layout.resolved[1].syms[i2];
    assert_ne!(v1, v2, "the copies stay distinct under -no_deduplicate");
}

// ---- the liveness contract ---------------------------------------------------

#[test]
fn dead_literals_strip_under_both_decisions() {
    // Each object roots its first literal (`-u`-style load symbol) and
    // carries a second, symbol-less literal nothing references.
    let keep = [0x01u8, 0x02, 0x03, 0x04];
    let dead = [0xDEu8, 0xAD, 0xBE, 0xEF];
    let a = literal_object(
        "a.o",
        4,
        "__literal4",
        S_4BYTE_LITERALS,
        2,
        &[&keep, &dead],
        "_s1",
    );
    let b_bytes = literal_object(
        "b.o",
        4,
        "__literal4",
        S_4BYTE_LITERALS,
        2,
        &[&keep, &dead],
        "_s2",
    );
    let inputs = vec![
        LinkInput {
            name: "a.o".to_string(),
            bytes: a,
        },
        LinkInput {
            name: "b.o".to_string(),
            bytes: b_bytes,
        },
    ];
    for dedup in [true, false] {
        let cfg = LinkConfig {
            dead_strip: true,
            deduplicate: dedup,
            load_symbols: vec![b"_s1".to_vec(), b"_s2".to_vec()],
            ..LinkConfig::default()
        };
        let result = link(&inputs, &[], &cfg).expect("links");
        let sect = literal_section(&result.layout, "__literal4");
        // The dead literal drops under both decisions; the merge follows
        // the decision over the surviving live value (dedup → one copy,
        // no_dedup → two).
        let expected = if dedup { 4 } else { 8 };
        assert_eq!(
            sect.size, expected,
            "dead literal4 strips; the merge follows the decision (dedup={dedup})"
        );
    }
}

// ---- the byte-identity lock --------------------------------------------------

#[test]
fn the_double_link_is_byte_identical() {
    // The dedup is deterministic — a literal-carrying corpus double-links
    // byte-identical (the M4 determinism contract the new path inherits).
    let shared = [0x01u8, 0x02, 0x03, 0x04];
    let only_a = [0xAAu8, 0xBB, 0xCC, 0xDD];
    let only_b = [0x11u8, 0x22, 0x33, 0x44];
    let make = || {
        let a = literal_object(
            "a.o",
            4,
            "__literal4",
            S_4BYTE_LITERALS,
            2,
            &[&shared, &only_a],
            "_s1",
        );
        let b_bytes = literal_object(
            "b.o",
            4,
            "__literal4",
            S_4BYTE_LITERALS,
            2,
            &[&shared, &only_b],
            "_s2",
        );
        let cfg = LinkConfig {
            load_symbols: vec![b"_s1".to_vec(), b"_s2".to_vec()],
            ..LinkConfig::default()
        };
        let inputs = vec![
            LinkInput {
                name: "a.o".to_string(),
                bytes: a,
            },
            LinkInput {
                name: "b.o".to_string(),
                bytes: b_bytes,
            },
        ];
        let result = link(&inputs, &[], &cfg).expect("links");
        pgr_emit::build_image(&result.layout, &result.objects).expect("emits")
    };
    let first = make();
    let second = make();
    assert_eq!(first, second, "the literal double-link is byte-identical");
}

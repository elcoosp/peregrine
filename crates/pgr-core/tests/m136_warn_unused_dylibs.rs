//! M136 — the unused-dylib advisory: ld64's `-warn_unused_dylibs` face
//! is the advisory faces' next member — the M42 unused-dylib drop's
//! predicate (`pgr_core::resolve::Resolution::unused_dylibs` +
//! `LinkConfig::warn_unused_dylibs`) made nameable read-side, a
//! measurement over data the resolution already had, never a layout
//! product.
//!
//! Gate matrix:
//! * the query — a riding dylib zero binding references name lists (in
//!   command order); a dylib an export served rides silent; the
//!   dynamic-lookup escape rides silent (the provider cannot be proven
//!   unreachable — the M42 rule the face shares);
//! * the exemptions — re-exports (identity obligations, their REEXPORT
//!   nodes join the trie) and hidden dylibs (no command rides) never
//!   name; a needed-marked unbound dylib names (the mark is the
//!   survival opt-out, the face reports the fact — ld64's own mark text
//!   concedes "even if no symbols are used from it");
//! * the composition — under `-dead_strip_dylibs` the unbound dylib
//!   drops before the query runs (the drop is the fix), so only the
//!   mark-kept survivors name;
//! * the decision — `LinkConfig::warn_unused_dylibs` gates the driver's
//!   print face; the core query itself is decision-free (the default is
//!   the face's silence, the bytes never move — the byte-identity lock
//!   pins a warned link's image against the un-named decision's);
//! * the refusal — the relocatable output refuses the knob (the object
//!   carries no load commands to advise about — the M116 advisory
//!   shape), backed by `link_reloc`;
//! * the lock — the warned link double-links byte-identical and
//!   verifies strict.

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::Dylib;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// One object: `_main`, optionally referencing `_greet` through a
/// `__data` bind slot (the honest two-level bind the used-marks walk
/// reads).
fn corpus(refer: bool) -> Vec<LinkInput> {
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
    if refer {
        let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
        let undef = b.add_symbol(ObjectSymbol::Undefined {
            name: "_greet".into(),
            weak_ref: false,
        });
        b.section_mut(data)
            .relocs
            .push(ObjectReloc::unsigned(undef as u32).at(0));
    }
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// One dylib: the named install name exporting `exports`, the marks
/// riding per flag.
fn dylib(install_name: &str, exports: &[&str], mark: fn(&mut Dylib)) -> Dylib {
    let mut d = Dylib {
        install_name: install_name.to_string(),
        current_version: 0,
        compatibility_version: 0,
        exports: exports.iter().map(|e| e.as_bytes().to_vec()).collect(),
        weak: false,
        lazy: false,
        upward: false,
        reexport: false,
        needed: false,
        hidden: false,
    };
    mark(&mut d);
    d
}

/// Links the corpus under `tweak`; returns the result. `refer` names the
/// corpus shape (the `_greet` bind or the clean entry).
fn plan_dylibs(
    refer: bool,
    dylibs: Vec<Dylib>,
    tweak: impl FnOnce(&mut LinkConfig),
) -> pgr_core::link::LinkResult {
    let mut cfg = LinkConfig {
        dylibs,
        entry_symbol: "_main".into(),
        ..LinkConfig::default()
    };
    tweak(&mut cfg);
    link(&corpus(refer), &[], &cfg).expect("the corpus links")
}

/// The advisory's read: the riding-but-unbound install names, in command
/// order.
fn unused(result: &pgr_core::link::LinkResult) -> Vec<String> {
    result.resolution.unused_dylibs()
}

// ---- the query ---------------------------------------------------------------

#[test]
fn an_unbound_dylib_names_and_a_bound_one_rides_silent() {
    // `libbound` serves the `_greet` bind; `libunused` rides unbound.
    let result = plan_dylibs(
        true,
        vec![
            dylib("@rpath/libbound.dylib", &["_greet"], |_| {}),
            dylib("@rpath/libunused.dylib", &["_noone_uses_this"], |_| {}),
        ],
        |_| {},
    );
    assert_eq!(
        unused(&result),
        vec!["@rpath/libunused.dylib".to_string()],
        "the unbound rider names, the bound provider stays silent"
    );
}

#[test]
fn the_dynamic_lookup_escape_rides_silent() {
    // A dynamic-lookup reference cannot prove its provider unreachable —
    // the M42 rule the advisory shares (the escape marks every dylib).
    let mut b = ObjectBuilder::new("flat.o");
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
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_flat_fn".into(),
        weak_ref: false,
    });
    let inputs = vec![LinkInput {
        name: "flat.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }];
    let cfg = LinkConfig {
        dylibs: vec![dylib("@rpath/libflat.dylib", &["_flat_fn"], |_| {})],
        entry_symbol: "_main".into(),
        undefined_policy: pgr_core::resolve::UndefinedPolicy::DynamicLookup,
        ..LinkConfig::default()
    };
    let result = link(&inputs, &[], &cfg).expect("the flat link runs");
    assert!(
        unused(&result).is_empty(),
        "the dynamic-lookup escape keeps the provider silent"
    );
}

#[test]
fn reexport_and_hidden_dylibs_never_name() {
    let result = plan_dylibs(
        false,
        vec![
            dylib("@rpath/libre.dylib", &["_re_fn"], |d| d.reexport = true),
            dylib("@rpath/libhidden.dylib", &["_hidden_fn"], |d| {
                d.hidden = true;
            }),
            dylib("@rpath/libplain.dylib", &["_plain_fn"], |_| {}),
        ],
        |_| {},
    );
    assert_eq!(
        unused(&result),
        vec!["@rpath/libplain.dylib".to_string()],
        "the identity obligation and the commandless mark stay exempt"
    );
}

#[test]
fn a_needed_marked_unbound_dylib_names() {
    // The mark keeps the dylib riding; the face reports the fact (the
    // mark's own man text concedes "even if no symbols are used").
    let result = plan_dylibs(
        false,
        vec![dylib("@rpath/libneeded.dylib", &["_needed_fn"], |d| {
            d.needed = true;
        })],
        |_| {},
    );
    assert_eq!(
        unused(&result),
        vec!["@rpath/libneeded.dylib".to_string()],
        "the kept-but-unbound rider names"
    );
}

// ---- the composition ----------------------------------------------------------

#[test]
fn dead_strip_dylibs_is_the_fix_the_query_reports_what_survives() {
    // Under the drop the unbound dylib leaves the header before the
    // query runs — nothing unbound rides, nothing names.
    let result = plan_dylibs(
        true,
        vec![
            dylib("@rpath/libbound.dylib", &["_greet"], |_| {}),
            dylib("@rpath/libunused.dylib", &["_noone_uses_this"], |_| {}),
        ],
        |cfg| cfg.dead_strip_dylibs = true,
    );
    assert!(
        unused(&result).is_empty(),
        "the drop removed the unbound rider (the fix, not the warning)"
    );

    // The mark-kept survivor rides the drop and names (the mark is the
    // per-dylib opt-out, the face reports the fact).
    let result = plan_dylibs(
        true,
        vec![
            dylib("@rpath/libbound.dylib", &["_greet"], |_| {}),
            dylib("@rpath/libneeded.dylib", &["_needed_fn"], |d| {
                d.needed = true;
            }),
        ],
        |cfg| cfg.dead_strip_dylibs = true,
    );
    assert_eq!(
        unused(&result),
        vec!["@rpath/libneeded.dylib".to_string()],
        "the mark-kept survivor names beside the drop"
    );
}

// ---- the decision -------------------------------------------------------------

#[test]
fn the_decision_never_moves_the_bytes() {
    let warned = plan_dylibs(
        false,
        vec![dylib("@rpath/libunused.dylib", &["_noone"], |_| {})],
        |cfg| cfg.warn_unused_dylibs = true,
    );
    let silent = plan_dylibs(
        false,
        vec![dylib("@rpath/libunused.dylib", &["_noone"], |_| {})],
        |_| {},
    );
    let emit = |r: &pgr_core::link::LinkResult| {
        pgr_emit::build_image(&r.layout, &r.objects).expect("the image emits")
    };
    assert_eq!(
        emit(&warned),
        emit(&silent),
        "the advisory is a measurement, never a layout product"
    );
}

// ---- the refusal --------------------------------------------------------------

#[test]
fn the_relocatable_output_refuses_the_knob() {
    let mut cfg = LinkConfig {
        warn_unused_dylibs: true,
        ..LinkConfig::default()
    };
    cfg.filetype = pgr_core::layout::OutputType::Relocatable;
    let err = link(&corpus(false), &[], &cfg).expect_err("-r carries no load commands");
    assert!(
        err.to_string().contains("relocatable"),
        "the refusal names the shape: {err}"
    );
}

// ---- the lock -----------------------------------------------------------------

#[test]
fn the_warned_link_determinism_and_strict_gates() {
    let result = plan_dylibs(
        true,
        vec![
            dylib("@rpath/libbound.dylib", &["_greet"], |_| {}),
            dylib("@rpath/libunused.dylib", &["_noone"], |_| {}),
        ],
        |cfg| cfg.warn_unused_dylibs = true,
    );
    let again = plan_dylibs(
        true,
        vec![
            dylib("@rpath/libbound.dylib", &["_greet"], |_| {}),
            dylib("@rpath/libunused.dylib", &["_noone"], |_| {}),
        ],
        |cfg| cfg.warn_unused_dylibs = true,
    );
    let emit = |r: &pgr_core::link::LinkResult| {
        pgr_emit::build_image(&r.layout, &r.objects).expect("the image emits")
    };
    assert_eq!(
        emit(&result),
        emit(&again),
        "a double link under the face is byte-identical"
    );
    let image = emit(&result);
    let report = pgr_verify::verify(
        &image,
        &pgr_verify::Options {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    assert!(
        report.is_ok(&pgr_verify::Options {
            strict_warnings: true,
            skip_hash_recompute: false,
        }),
        "the warned image verifies strict: {:?}",
        report.issues
    );
}

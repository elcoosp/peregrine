//! M50 — the weak-import refusal: `-no_weak_imports` — ld64's flag is
//! the Pass-2 decision the resolve's undefined walk reads: a weak
//! reference (`N_WEAK_REF`, or any bind a weak-loaded dylib would
//! carry) that no input, no dylib and no loader resolves — a bind dyld
//! must look up at runtime (ld64's `definitionProxy`) — refuses the
//! link with the symbol named (ld64: "weak import of symbol '%s' not
//! supported because of option: `-no_weak_imports"`). The default
//! (`false`) keeps every pre-M50 link byte-identical: an unresolvable
//! weak reference rides dyld's runtime lookup exactly as it did. A weak
//! reference that *resolves at link time* — against an input
//! definition or a dylib export, weak-loaded or not — is not a proxy
//! and never refuses: the knob prices the runtime lookup, not the
//! weakness. The relocatable output never reads the decision (its
//! undefineds stay open; `-r` resolves nothing).
//!
//! Gate matrix:
//! * the default — an unresolvable weak reference ships the dyld
//!   lookup bind (the pre-M50 shape, byte-identical);
//! * the refusal — the named decision refuses the same link, the
//!   message naming the symbol, the knob and the fix;
//! * the resolved weak bind — a weak reference against an input
//!   definition (and against a weak-loaded dylib's export) links
//!   under the knob, byte-identical to the default;
//! * the non-weak lane — an unresolved non-weak reference keeps the
//!   `-undefined` refusal (and rides the lookup under
//!   `-undefined dynamic_lookup`) exactly as before;
//! * the dynamic-lookup policy — the knob reads the
//!   `-undefined dynamic_lookup` lane too (a weak unresolved refuses
//!   there, the non-weak ones ship);
//! * the relocatable path — `-r` never reads the decision;
//! * determinism — a corpus the knob never fires on plans identical
//!   bytes under both decisions.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_core::resolve::{Dylib, UndefinedPolicy};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// `weakref.o`: `_main` over two RET functions and a weak undefined
/// `_maybe` (`N_WEAK_REF`) — the reference whose bind the decision
/// reads. `weak` flips the reference's `N_WEAK_REF` bit.
fn weakref_object(name: &str, weak: bool, undef: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name);
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
        name: undef.into(),
        weak_ref: weak,
    });
    b.build().expect("the fixture object builds")
}

/// `provider.o`: defines `name` over one RET body (the link-time
/// resolution the knob never refuses).
fn provider_object(name: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new("provider.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: name.into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn inputs(objs: Vec<Vec<u8>>) -> Vec<LinkInput> {
    objs.into_iter()
        .enumerate()
        .map(|(i, bytes)| LinkInput {
            name: format!("in{i}.o"),
            bytes,
        })
        .collect()
}

fn cfg(no_weak_imports: bool) -> LinkConfig {
    LinkConfig {
        filetype: OutputType::Execute,
        ident: "m50".into(),
        no_weak_imports,
        ..LinkConfig::default()
    }
}

#[test]
fn the_default_ships_the_dyld_lookup_weak_import() {
    // Pre-M50 shape: an unresolvable weak reference rides dyld's
    // runtime lookup — the image builds and the name never refuses.
    link(
        &inputs(vec![weakref_object("weakref.o", true, "_maybe")]),
        &[],
        &cfg(false),
    )
    .expect("the weak dynamic lookup ships");
}

#[test]
fn the_knob_refuses_the_runtime_lookup_weak_import() {
    // ld64: "weak import of symbol '%s' not supported because of
    // option: -no_weak_imports" — the refusal names the symbol, the
    // knob and the fix.
    let err = link(
        &inputs(vec![weakref_object("weakref.o", true, "_maybe")]),
        &[],
        &cfg(true),
    )
    .expect_err("the runtime-lookup weak import refuses");
    let message = err.to_string();
    assert!(
        message.contains("_maybe"),
        "the refusal names the symbol: {message}"
    );
    assert!(
        message.contains("-no_weak_imports"),
        "the refusal names the knob: {message}"
    );
    assert!(
        message.contains("weak"),
        "the refusal names the weak import: {message}"
    );
}

#[test]
fn the_resolved_weak_bind_never_refuses() {
    // A weak reference against a link-time definition is not a proxy:
    // the knob prices the runtime lookup, not the weakness — the image
    // builds and plans the default's bytes.
    let objs = vec![
        weakref_object("weakref.o", true, "_maybe"),
        provider_object("_maybe"),
    ];
    let default = link(&inputs(objs.clone()), &[], &cfg(false)).expect("the default links");
    let named = link(&inputs(objs), &[], &cfg(true)).expect("the resolved weak bind links");
    assert_eq!(
        default.layout.header_bytes, named.layout.header_bytes,
        "a link-time resolution plans identical bytes under both decisions"
    );
    assert_eq!(default.layout.file_size, named.layout.file_size);
}

#[test]
fn the_weak_dylib_export_never_refuses() {
    // A weak-loaded dylib's export resolves at link time (the bind
    // carries weakness — MH_BINDS_TO_WEAK — but dyld never looks it
    // up at runtime): the knob does not touch it.
    let mut c = cfg(true);
    c.dylibs = vec![Dylib {
        install_name: "@rpath/libw.dylib".into(),
        current_version: 0,
        compatibility_version: 0,
        exports: vec![b"_maybe".to_vec()],
        weak: true,
        reexport: false,
        lazy: false,
        upward: false,
    }];
    let result = link(
        &inputs(vec![weakref_object("weakref.o", true, "_maybe")]),
        &[],
        &c,
    )
    .expect("the weak dylib's export resolves at link time");
    let default = {
        let mut d = cfg(false);
        d.dylibs = c.dylibs.clone();
        link(
            &inputs(vec![weakref_object("weakref.o", true, "_maybe")]),
            &[],
            &d,
        )
        .expect("the default links the same bind")
    };
    assert_eq!(
        default.layout.header_bytes, result.layout.header_bytes,
        "the dylib-resolved weak bind plans identical bytes either way"
    );
}

#[test]
fn the_non_weak_lane_keeps_its_own_policy() {
    // The knob reads weak imports only: an unresolved non-weak
    // reference keeps the `-undefined error` refusal shape...
    let err = link(
        &inputs(vec![weakref_object("plain.o", false, "_gone")]),
        &[],
        &cfg(true),
    )
    .expect_err("the non-weak unresolved refuses as always");
    let message = err.to_string();
    assert!(
        message.contains("undefined symbol"),
        "the non-weak refusal keeps the undefined-symbol shape: {message}"
    );
    assert!(
        !message.contains("-no_weak_imports"),
        "the non-weak refusal does not name the knob: {message}"
    );
    // ...and under `-undefined dynamic_lookup` the non-weak reference
    // still ships while the weak one refuses under the knob.
    let mut lookup = cfg(true);
    lookup.undefined_policy = UndefinedPolicy::DynamicLookup;
    link(
        &inputs(vec![weakref_object("plain.o", false, "_gone")]),
        &[],
        &lookup,
    )
    .expect("the non-weak dynamic lookup ships under the knob");
    let mut weak_lookup = cfg(true);
    weak_lookup.undefined_policy = UndefinedPolicy::DynamicLookup;
    let objs = vec![weakref_object("weakref.o", true, "_maybe")];
    let err = link(&inputs(objs.clone()), &[], &weak_lookup)
        .expect_err("the weak dynamic lookup refuses under the knob");
    assert!(
        err.to_string().contains("_maybe"),
        "the policy-lane refusal names the symbol: {err}"
    );
    // The default policy ships the same weak reference (pre-M50 shape).
    let mut weak_default = cfg(false);
    weak_default.undefined_policy = UndefinedPolicy::DynamicLookup;
    link(&inputs(objs), &[], &weak_default)
        .expect("the dynamic_lookup policy ships the weak reference by default");
}

#[test]
fn the_relocatable_path_never_reads_the_decision() {
    // The object output's undefineds stay open — `-r` resolves nothing,
    // so the decision is never read (the M41/M43/M47 inert shape).
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        no_weak_imports: true,
        ..LinkConfig::default()
    };
    let rel = link_reloc(
        &inputs(vec![weakref_object("weakref.o", true, "_maybe")]),
        &[],
        &cfg,
        Parallelism::Serial,
    )
    .expect("the relocatable output ignores the knob");
    assert!(
        rel.objects
            .iter()
            .any(|o| o.symbols.iter().any(|s| s.external && !s.is_defined())),
        "the open weak undefined rides the object verbatim"
    );
}

#[test]
fn a_corpus_the_knob_never_fires_on_is_byte_identical() {
    // The decision's honesty gate: a corpus with no weak references
    // plans identical bytes under both decisions (the knob widens one
    // refusal lane, nothing else moves).
    let objs = vec![
        weakref_object("plain.o", false, "_gone"),
        provider_object("_gone"),
    ];
    let default = link(&inputs(objs.clone()), &[], &cfg(false)).expect("the default links");
    let named = link(&inputs(objs), &[], &cfg(true)).expect("the knob-satisfied link plans");
    assert_eq!(
        default.layout.header_bytes, named.layout.header_bytes,
        "the knob-satisfied link is byte-identical"
    );
}

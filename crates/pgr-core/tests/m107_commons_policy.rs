//! M107 — the commons resolution policy (`-commons <policy>`): ld64's
//! common-symbol treatment, the other half of the `N_UNDF | N_EXT`
//! contract. A tentative definition is both a would-be definition and a
//! reference; when a linked dylib also exports the name, the policy
//! decides the tentative's fate:
//!
//! * `use_dylibs` (the default) — the house shape: the tentative
//!   coalesces (max size/align) and rides as a local definition; the
//!   in-image definition beats the two-level export (the resolver's own
//!   rank order — rank 5 common over rank 6 dylib), so the dylib is
//!   consulted only for names nothing in the image claims. Every
//!   pre-knob link is byte-identical (ld64's default treatment — the
//!   tentative becomes a real definition).
//! * `search_dylibs` — the dylibs are searched first: a dylib's
//!   definition replaces the tentative (the reference binds to the
//!   exporting dylib, no local definition lands); when no dylib exports
//!   the name, the common rides as a local definition (ld64's
//!   `use_dylibs` treatment).
//! * `use_extern` — the common rides as an external reference, never a
//!   local definition: the definition side drops, the references
//!   resolve against a dylib export when one exists and follow the
//!   `-undefined` policy otherwise.
//! * `error` — a tentative whose name a linked dylib also exports
//!   refuses the link with the symbol named (ld64's `error` face); with
//!   no dylib exporting the name the common rides.
//!
//! Gate matrix:
//! * the default — the common rides as a local definition, the dylib
//!   export is shadowed (the pre-M107 shape, byte-identical);
//! * `search_dylibs` — the dylib's definition replaces the tentative,
//!   the bind names the dylib's ordinal, no `__common` definition
//!   lands;
//! * `search_dylibs` without a dylib export — the common rides;
//! * `use_extern` — no local definition, the bind rides the dylib when
//!   one exports the name, and the `-undefined` escalation decides
//!   otherwise;
//! * `error` — the conflict refuses with the symbol named; no conflict
//!   links;
//! * the relocatable refusal — the non-default policies refuse (the
//!   object's symtab is the input's, verbatim).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_core::resolve::{CommonsPolicy, Dylib, UndefinedPolicy};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// An object whose `__data` carries one rebase-style bind slot per
/// named undefined, and whose `__data` also defines the named common
/// (the tentative the policy decides about) when asked.
fn caller(name: &str, refs: &[&str], common: Option<&str>) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: if name == "a.o" {
            "_main".into()
        } else {
            format!("_{name}_fn")
        },
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 8 * (refs.len() + usize::from(common.is_some()))],
        vec![],
    ));
    for (i, r) in refs.iter().enumerate() {
        let undef = b.add_symbol(ObjectSymbol::Undefined {
            name: (*r).into(),
            weak_ref: false,
        });
        let slot = b.sym_index(undef);
        b.section_mut(data)
            .relocs
            .push(ObjectReloc::unsigned(slot).at((i * 8) as u32));
    }
    if let Some(c) = common {
        // The tentative definition — the `N_UNDF | N_EXT` shape the
        // policy decides about (a common is external, undefined-class,
        // non-zero value).
        b.add_symbol(ObjectSymbol::Common {
            name: c.into(),
            size: 32,
            align_log2: 3,
        });
    }
    b.build().expect("the fixture object builds")
}

fn dylib(install_name: &str, exports: &[&str]) -> Dylib {
    Dylib {
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
    }
}

fn corpus(bytes: Vec<u8>) -> Vec<LinkInput> {
    vec![LinkInput {
        name: "a.o".to_string(),
        bytes,
    }]
}

/// Links the corpus under `tweak`; returns the full Pass 1–3 result.
fn plan(
    bytes: Vec<u8>,
    dylibs: Vec<Dylib>,
    tweak: impl FnOnce(&mut LinkConfig),
) -> pgr_core::link::LinkResult {
    let mut cfg = LinkConfig {
        dylibs,
        ..LinkConfig::default()
    };
    tweak(&mut cfg);
    link(&corpus(bytes), &[], &cfg).expect("the corpus links")
}

// ---- the gate matrix ---------------------------------------------------------

#[test]
fn the_default_rides_the_common_as_a_local_definition() {
    // `use_dylibs` (the default): the tentative coalesces and rides as a
    // local definition; the in-image definition beats the two-level
    // export (the pre-M107 shape — the bind stays local).
    let bytes = caller("a.o", &["_conflicted"], Some("_conflicted"));
    let dylibs = vec![dylib("@rpath/libconflict.dylib", &["_conflicted"])];
    let result = plan(bytes, dylibs, |c| c.commons = CommonsPolicy::UseDylibs);
    let id = result
        .interner
        .lookup(b"_conflicted")
        .expect("the name interned");
    let def = result
        .resolution
        .def(id)
        .expect("the default keeps the common's definition");
    assert_eq!(
        def.rank,
        pgr_core::resolve::Rank::Common,
        "the common rides as a local definition"
    );
    assert_eq!(def.common_size, 32, "the common's size rides the winner");
}

#[test]
fn search_dylibs_lets_the_dylib_replace_the_tentative() {
    // `search_dylibs`: the dylibs are searched first — a dylib's
    // definition replaces the tentative (the bind names the dylib's
    // ordinal; no local definition lands).
    let bytes = caller("a.o", &["_conflicted"], Some("_conflicted"));
    let dylibs = vec![dylib("@rpath/libconflict.dylib", &["_conflicted"])];
    let result = plan(bytes, dylibs, |c| c.commons = CommonsPolicy::SearchDylibs);
    let id = result
        .interner
        .lookup(b"_conflicted")
        .expect("the name interned");
    assert!(
        result.resolution.def(id).is_none(),
        "the dylib's definition replaced the tentative — no local definition lands"
    );
    // The bind names the dylib: the first (and only) import's ordinal is
    // 1 — the exporting dylib's two-level slot.
    let ord = result
        .layout
        .fixups
        .imports
        .first()
        .map(|i| i.lib_ordinal)
        .expect("the bind rides the fixup plan");
    assert_eq!(ord, 1, "the bind carries the dylib's two-level ordinal");
}

#[test]
fn search_dylibs_without_a_dylib_export_rides_the_common() {
    // `search_dylibs` with no dylib exporting the name: the dylibs are
    // searched first, miss, and the common rides as a local definition
    // (the default's shape — the search changed nothing).
    let bytes = caller("a.o", &["_unconflicted"], Some("_unconflicted"));
    let dylibs = vec![dylib("@rpath/libother.dylib", &["_other"])];
    let result = plan(bytes, dylibs, |c| c.commons = CommonsPolicy::SearchDylibs);
    let id = result
        .interner
        .lookup(b"_unconflicted")
        .expect("the name interned");
    let def = result
        .resolution
        .def(id)
        .expect("the common rides when the search misses");
    assert_eq!(def.rank, pgr_core::resolve::Rank::Common);
}

#[test]
fn use_extern_rides_the_common_as_an_external_reference() {
    // `use_extern`: the definition side drops — the references resolve
    // against the dylib export when one exists (the bind names the
    // dylib's ordinal), and the tentative never lands as a definition.
    let bytes = caller("a.o", &["_conflicted"], Some("_conflicted"));
    let dylibs = vec![dylib("@rpath/libconflict.dylib", &["_conflicted"])];
    let result = plan(bytes, dylibs, |c| c.commons = CommonsPolicy::UseExtern);
    let id = result
        .interner
        .lookup(b"_conflicted")
        .expect("the name interned");
    assert!(
        result.resolution.def(id).is_none(),
        "use_extern never lands a local definition"
    );
    let ord = result
        .layout
        .fixups
        .imports
        .first()
        .map(|i| i.lib_ordinal)
        .expect("the bind rides the fixup plan");
    assert_eq!(ord, 1, "the external reference binds to the dylib");
}

#[test]
fn use_extern_without_a_dylib_export_follows_the_undefined_policy() {
    // `use_extern` with no dylib exporting the name: the definition side
    // drops and the references follow the `-undefined` policy — the
    // default escalation refuses with the symbol named.
    let bytes = caller("a.o", &["_loose"], Some("_loose"));
    let dylibs = vec![dylib("@rpath/libother.dylib", &["_other"])];
    let mut cfg = LinkConfig {
        dylibs,
        commons: CommonsPolicy::UseExtern,
        ..LinkConfig::default()
    };
    let err = link(&corpus(bytes), &[], &cfg).expect_err("the unresolved external escalates");
    assert!(
        err.to_string().contains("_loose"),
        "the escalation names the symbol: {err}"
    );
    // `-undefined dynamic_lookup`: the same link rides (the reference is
    // left to dyld — the external-reference face).
    cfg.undefined_policy = UndefinedPolicy::DynamicLookup;
    let bytes = caller("a.o", &["_loose"], Some("_loose"));
    let result = link(&corpus(bytes), &[], &cfg).expect("the dynamic lookup rides");
    let id = result
        .interner
        .lookup(b"_loose")
        .expect("the name interned");
    assert!(result.resolution.def(id).is_none());
    assert!(
        result.resolution.is_dynamic_lookup(id),
        "the external reference rides the flat-lookup slot"
    );
}

#[test]
fn error_refuses_the_conflict_with_the_symbol_named() {
    // `error`: a tentative whose name a linked dylib also exports
    // refuses the link with the symbol named (ld64's error face).
    let bytes = caller("a.o", &["_conflicted"], Some("_conflicted"));
    let dylibs = vec![dylib("@rpath/libconflict.dylib", &["_conflicted"])];
    let cfg = LinkConfig {
        dylibs,
        commons: CommonsPolicy::Error,
        ..LinkConfig::default()
    };
    let err = link(&corpus(bytes), &[], &cfg).expect_err("the conflict refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("_conflicted"),
        "the refusal names the symbol: {msg}"
    );
    assert!(
        msg.contains("-commons error") || msg.contains("common"),
        "the refusal names the policy: {msg}"
    );
    // No conflict: the common rides (the error face is the conflict's).
    let bytes = caller("a.o", &["_unconflicted"], Some("_unconflicted"));
    let dylibs = vec![dylib("@rpath/libother.dylib", &["_other"])];
    let cfg = LinkConfig {
        dylibs,
        commons: CommonsPolicy::Error,
        ..LinkConfig::default()
    };
    let result = link(&corpus(bytes), &[], &cfg).expect("the conflict-free link rides");
    let id = result
        .interner
        .lookup(b"_unconflicted")
        .expect("the name interned");
    assert!(result.resolution.def(id).is_some());
}

#[test]
fn the_non_default_policies_refuse_on_the_relocatable_output() {
    // The relocatable output's symtab is the input's, verbatim — the
    // non-default policies have no tentative fate to decide (the M104/
    // M105 refusal shape; the default never refuses).
    for policy in [
        CommonsPolicy::SearchDylibs,
        CommonsPolicy::UseExtern,
        CommonsPolicy::Error,
    ] {
        let bytes = caller("a.o", &[], Some("_conflicted"));
        let dylibs = vec![dylib("@rpath/libconflict.dylib", &["_conflicted"])];
        let cfg = LinkConfig {
            dylibs,
            commons: policy,
            filetype: OutputType::Relocatable,
            ..LinkConfig::default()
        };
        let err = link_reloc(&corpus(bytes), &[], &cfg, Parallelism::default())
            .expect_err("the relocatable output refuses the non-default policy");
        assert!(
            err.to_string().contains("-commons"),
            "the refusal names the knob: {err}"
        );
    }
    // The default rides the relocatable output (the pre-M107 shape).
    let bytes = caller("a.o", &[], Some("_conflicted"));
    let dylibs = vec![dylib("@rpath/libconflict.dylib", &["_conflicted"])];
    let cfg = LinkConfig {
        dylibs,
        commons: CommonsPolicy::UseDylibs,
        filetype: OutputType::Relocatable,
        ..LinkConfig::default()
    };
    link_reloc(&corpus(bytes), &[], &cfg, Parallelism::default())
        .expect("the default rides the relocatable output");
}

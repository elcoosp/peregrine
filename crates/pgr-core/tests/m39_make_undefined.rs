//! M39 — the make-undefined seam (`pgr_core::make_undefined`): the `-U
//! <name>` decisions ld64 names turn a common or defined symbol, *as it
//! is being linked*, into an undefined one — the overridable-symbol
//! escape hatch (the archive's strong `_f` stops answering references so
//! the host's runtime definition can). The decision rides Pass 2: the
//! named keys never install (definition or common), the stripped
//! references follow the `-undefined` policy like any unresolved name,
//! and the empty table plans the pre-M39 bytes.
//!
//! Gate matrix:
//! * the seam — a name validates (non-empty, NUL-free), a name enters
//!   the table once (a repeated decision is a typo), and the empty
//!   table plans byte-identically (the lock);
//! * the mark — a defined-and-referenced symbol stops being a
//!   definition: no symtab row, no export-trie node, the reference
//!   rides the dynamic-lookup bind (the flat-lookup ordinal under
//!   `-undefined dynamic_lookup`), and a common stops claiming its
//!   `__common` slot;
//! * the refusals — the policy refusal (`-U` with the default
//!   `-undefined error` names the fix), the vacuous decision (a name no
//!   input defines — nothing to strip — with the misspelling named) and
//!   the relocatable output (the `-r` path carries the input symbols
//!   verbatim);
//! * the neighbors — a duplicate strong definition under the mark
//!   stops erroring (both candidates were marked while linking), a
//!   stripped definition rebinds against the dylib that exports the
//!   name (the two-level ordinal, never the flat lookup), and the mark
//!   unroots the defining atom under `-dead_strip` (nothing references
//!   the local body anymore);
//! * the reuse path — a relink replaying the recorded Pass-2 decisions
//!   honors the mark like the full walk (the equality gate).

use pgr_core::ids::FileId;
use pgr_core::interner::Interner;
use pgr_core::layout::{Layout, LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link};
use pgr_core::make_undefined::MakeUndefined;
use pgr_core::object::InputObject;
use pgr_core::propagate::{SectionDigest, section_digests};
use pgr_core::resolve::{Dylib, Resolution, ResolutionSnapshot, UndefinedPolicy};
use pgr_core::resolve_reuse::{install_reused, plan_reuse};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// `_main` (RET) with a second defined atom (`_f`, the marked body) —
/// the no-strip link carries both, the dead strip drops the second.
fn main_with_f_body() -> ObjectBuilder {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6], // ret; ret
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_f".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b
}

/// `_main` (RET) plus a `__data` pointer slot referencing `_f`
/// (`ARM64_RELOC_UNSIGNED`) — the slot rides the import table.
fn main_pointing_at_f() -> ObjectBuilder {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], Vec::new()));
    let f = b.add_symbol(ObjectSymbol::Defined {
        name: "_f".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    let slot = b.sym_index(f);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    b
}

/// A one-symbol dylib exporting `_f` (the rebind target).
fn f_dylib() -> Dylib {
    Dylib {
        install_name: "@rpath/libf.dylib".to_string(),
        current_version: 0,
        compatibility_version: 0,
        exports: vec![b"_f".to_vec()],
        weak: false,
        lazy: false,
        upward: false,
        reexport: false,
        needed: false,
    }
}

fn table(names: &[&str]) -> MakeUndefined {
    let mut t = MakeUndefined::new();
    for n in names {
        t.push(pgr_core::make_undefined::MakeUndefinedName::from_flag(n).expect("valid"))
            .expect("unique");
    }
    t
}

fn cfg_with(mark: MakeUndefined, tweak: impl FnOnce(&mut LinkConfig)) -> LinkConfig {
    let mut cfg = LinkConfig {
        make_undefined: mark,
        undefined_policy: UndefinedPolicy::DynamicLookup,
        ..LinkConfig::default()
    };
    tweak(&mut cfg);
    cfg
}

fn build_one(spec: &ObjectBuilder) -> Vec<LinkInput> {
    vec![LinkInput {
        name: spec.name().to_string(),
        bytes: spec.build().expect("the fixture object builds"),
    }]
}

/// The name bytes of the i-th output symbol (its `n_strx` into the
/// string table, NUL-trimmed).
fn sym_name(layout: &Layout, i: usize) -> Vec<u8> {
    let off = layout.str_offsets[i] as usize;
    let bytes = &layout.strtab[off..];
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    bytes[..end].to_vec()
}

// ---- the seam ----------------------------------------------------------------

#[test]
fn the_table_grammar_refuses_the_typos() {
    assert!(
        pgr_core::make_undefined::MakeUndefinedName::from_flag("").is_err(),
        "an empty name is a typo, not a decision"
    );
    assert!(
        pgr_core::make_undefined::MakeUndefinedName::from_flag("_bad\0name").is_err(),
        "an interior NUL cannot ride the symtab string"
    );
    let mut t = MakeUndefined::new();
    t.push(pgr_core::make_undefined::MakeUndefinedName::from_flag("_f").expect("valid"))
        .expect("first decision lands");
    assert!(
        t.push(pgr_core::make_undefined::MakeUndefinedName::from_flag("_f").expect("valid"))
            .is_err(),
        "a repeated decision is a typo"
    );
}

#[test]
fn the_empty_table_plans_the_pre_m39_bytes() {
    let spec = main_pointing_at_f();
    let plain = link(&build_one(&spec), &[], &LinkConfig::default()).expect("links");
    let marked = link(
        &build_one(&spec),
        &[],
        &cfg_with(MakeUndefined::new(), |_| {}),
    )
    .expect("links");
    assert_eq!(
        plain.layout.header_bytes, marked.layout.header_bytes,
        "an empty table is the default — the same header bytes"
    );
    assert_eq!(plain.layout.trie, marked.layout.trie);
    assert_eq!(plain.layout.symbols.len(), marked.layout.symbols.len());
}

// ---- the mark ------------------------------------------------------------------

#[test]
fn the_mark_strips_the_definition_and_rebinds_dynamic() {
    let spec = main_pointing_at_f();
    let layout = link(&build_one(&spec), &[], &cfg_with(table(&["_f"]), |_| {}))
        .expect("links")
        .layout;
    let f_idx = (0..layout.symbols.len())
        .find(|i| sym_name(&layout, *i) == b"_f")
        .expect("the marked name still rides the symtab (as a reference)");
    let f = &layout.symbols[f_idx];
    assert!(
        f.external && f.n_type & pgr_format::consts::N_TYPE == pgr_format::consts::N_UNDF,
        "the definition became an undefined row: n_type {:#x}",
        f.n_type
    );
    assert_eq!(
        f.n_desc >> 8,
        pgr_format::consts::BIND_SPECIAL_DYLIB_FLAT_LOOKUP,
        "the dynamic lookup binds with the flat-lookup ordinal"
    );
    let exports = pgr_format::trie::exports(&layout.trie).expect("the trie walks");
    assert!(
        !exports.iter().any(|e| e.name == b"_f"),
        "the marked name exports nothing"
    );
}

#[test]
fn the_mark_strips_a_common() {
    let mut b = ObjectBuilder::new("common.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], Vec::new()));
    let buf = b.add_symbol(ObjectSymbol::Common {
        name: "_buf".into(),
        size: 32,
        align_log2: 4,
    });
    let slot = b.sym_index(buf);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    let layout = link(&build_one(&b), &[], &cfg_with(table(&["_buf"]), |_| {}))
        .expect("links")
        .layout;
    assert!(
        !layout
            .sections
            .iter()
            .any(|s| s.seg_name == "__DATA" && s.name == "__common"),
        "the marked common claims no __common slot"
    );
    assert!(
        (0..layout.symbols.len()).any(|i| {
            let s = &layout.symbols[i];
            s.external
                && s.n_type & pgr_format::consts::N_TYPE == pgr_format::consts::N_UNDF
                && sym_name(&layout, i) == b"_buf"
        }),
        "the marked common rides as an undefined reference"
    );
}

// ---- the refusals ----------------------------------------------------------------

#[test]
fn the_policy_refusal_names_the_fix() {
    let spec = main_pointing_at_f();
    let cfg = LinkConfig {
        make_undefined: table(&["_f"]),
        ..LinkConfig::default() // `-undefined error` is the default policy
    };
    let err = link(&build_one(&spec), &[], &cfg).expect_err("the default policy refuses");
    let msg = err.to_string();
    assert!(msg.contains("-U"), "the refusal names the knob: {msg}");
    assert!(
        msg.contains("dynamic_lookup"),
        "the refusal names the fix: {msg}"
    );
}

#[test]
fn the_vacuous_decision_refuses_with_the_misspelling() {
    let spec = main_pointing_at_f();
    let cfg = cfg_with(table(&["_typo"]), |_| {});
    let err = link(&build_one(&spec), &[], &cfg)
        .expect_err("a name nothing defines has nothing to strip");
    let msg = err.to_string();
    assert!(msg.contains("_typo"), "the misspelling is named: {msg}");
    assert!(msg.contains("-U"), "the refusal names the knob: {msg}");
}

#[test]
fn the_referenced_only_name_refuses_as_vacuous() {
    let mut b = ObjectBuilder::new("ref.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_f".into(),
        weak_ref: false,
    });
    let cfg = cfg_with(table(&["_f"]), |_| {});
    let err = link(&build_one(&b), &[], &cfg)
        .expect_err("the reference is already undefined — nothing to strip");
    assert!(err.to_string().contains("nothing to strip"));
}

#[test]
fn the_relocatable_output_refuses_the_knob() {
    let spec = main_pointing_at_f();
    let cfg = cfg_with(table(&["_f"]), |c| {
        c.filetype = OutputType::Relocatable;
    });
    let err = pgr_core::link::link_reloc(&build_one(&spec), &[], &cfg, Parallelism::Serial)
        .expect_err("the relocatable output refuses the knob");
    let msg = err.to_string();
    assert!(msg.contains("-U"), "the refusal names the knob: {msg}");
}

// ---- the neighbors -----------------------------------------------------------------

#[test]
fn the_mark_silences_a_duplicate_strong_definition() {
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut objects = Vec::new();
    for (i, name) in ["a.o", "b.o"].iter().enumerate() {
        let mut spec = ObjectBuilder::new(name);
        let t = spec.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        spec.add_symbol(ObjectSymbol::Defined {
            name: "_dup".into(),
            section_index: t,
            value: 0,
            weak: false,
        });
        let bytes = spec.build().unwrap();
        let mut obj = InputObject::parse(FileId(i as u32), name, bytes).unwrap();
        names.append(&mut obj.take_symbol_names());
        objects.push(obj);
    }
    let (interner, ids) = Interner::build(&names);
    let mut cursor = 0usize;
    for obj in &mut objects {
        let take = obj.symbols.len();
        obj.finish(&ids[cursor..cursor + take]).unwrap();
        cursor += take;
    }
    // Both definitions were marked while linking — the duplicate error
    // never fires, and nothing references the name, so no row rides.
    let mut res = Resolution::default();
    res.install_make_undefined(
        &[interner.lookup(b"_dup").expect("the name is interned")],
        &objects,
        &interner,
    )
    .expect("the mark lands on a real definition");
    res.install(
        &objects,
        &interner,
        pgr_core::resolve::MultiplyDefinedPolicy::Error,
    )
    .expect("the marked candidates skip");
    assert!(res.def(interner.lookup(b"_dup").unwrap()).is_none());
}

#[test]
fn the_stripped_definition_rebinds_against_the_dylib() {
    let spec = main_pointing_at_f();
    let layout = link(
        &build_one(&spec),
        &[],
        &cfg_with(table(&["_f"]), |c| {
            c.dylibs = vec![f_dylib()];
        }),
    )
    .expect("links")
    .layout;
    let f_idx = (0..layout.symbols.len())
        .find(|i| sym_name(&layout, *i) == b"_f")
        .expect("the rebind rides the symtab");
    assert_eq!(
        layout.symbols[f_idx].n_desc >> 8,
        1,
        "the bind takes the dylib's two-level ordinal (the first LC_LOAD_DYLIB)"
    );
}

#[test]
fn the_mark_unroots_the_atom_under_dead_strip() {
    let spec = main_with_f_body();
    let text_size = |l: &pgr_core::layout::Layout| {
        l.sections
            .iter()
            .find(|s| s.seg_name == "__TEXT" && s.name == "__text")
            .map(|s| s.size)
            .unwrap_or_default()
    };
    let unstripped = link(&build_one(&spec), &[], &cfg_with(table(&["_f"]), |_| {}))
        .expect("links")
        .layout;
    assert_eq!(
        text_size(&unstripped),
        8,
        "the no-strip link carries both atoms (main + the marked body)"
    );
    let kept = link(
        &build_one(&spec),
        &[],
        &cfg_with(table(&["_f"]), |c| {
            c.dead_strip = true;
        }),
    )
    .expect("links")
    .layout;
    assert_eq!(
        text_size(&kept),
        4,
        "the dead strip drops the marked body — nothing references it"
    );
}

// ---- the reuse path ------------------------------------------------------------------

/// The Pass-2 harness (the m9 shape): full install beside the reuse
/// replay, both honoring the mark.
fn harness(
    spec: &ObjectBuilder,
    mark: &[&str],
) -> (
    Interner,
    Vec<InputObject>,
    Resolution,
    ResolutionSnapshot,
    Vec<SectionDigest>,
) {
    let bytes = spec.build().unwrap();
    let mut obj = InputObject::parse(FileId(0), spec.name(), bytes).unwrap();
    let names = obj.take_symbol_names();
    let (interner, ids) = Interner::build(&names);
    obj.finish(&ids).unwrap();
    let objects = vec![obj];
    let mark_ids: Vec<pgr_core::ids::StringId> = mark
        .iter()
        .map(|n| {
            interner
                .lookup(n.as_bytes())
                .expect("the marked name is interned")
        })
        .collect();
    let mut full = Resolution::default();
    full.install_make_undefined(&mark_ids, &objects, &interner)
        .unwrap();
    full.install(
        &objects,
        &interner,
        pgr_core::resolve::MultiplyDefinedPolicy::Error,
    )
    .unwrap();
    full.require_all_resolved(&interner, &objects, UndefinedPolicy::DynamicLookup, false)
        .unwrap();
    let snapshot = ResolutionSnapshot::capture(&objects, &interner, &full, &[], &[]);
    let digests = section_digests(&objects);
    (interner, objects, full, snapshot, digests)
}

#[test]
fn the_reuse_replay_honors_the_mark() {
    let spec = main_pointing_at_f();
    let (interner, objects, full, snapshot, digests) = harness(&spec, &["_f"]);
    let mark_ids = vec![interner.lookup(b"_f").expect("interned")];
    let plan =
        plan_reuse(&snapshot, &digests, &interner, &objects, &[], &[]).expect("the shape holds");
    let reused = install_reused(
        &plan,
        &snapshot,
        &interner,
        &objects,
        &[],
        &[],
        &mark_ids,
        UndefinedPolicy::DynamicLookup,
        false,
        pgr_core::resolve::MultiplyDefinedPolicy::Error,
    )
    .expect("the replay installs");
    let f = interner.lookup(b"_f").unwrap();
    assert!(full.def(f).is_none(), "the full path stripped the def");
    assert!(reused.def(f).is_none(), "the replay stripped it too");
    assert!(
        full.is_dynamic_lookup(f) && reused.is_dynamic_lookup(f),
        "both paths land the reference on the dynamic lookup"
    );
    assert!(
        full.equivalent(&reused),
        "the reused state is indistinguishable from the full one"
    );
}

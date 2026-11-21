//! M108 — the multiply-defined symbol resolution policy
//! (`-multiply_defined <policy>`): the resolver's other half. Two strong
//! definitions of one name is the collision Pass 2's install walk refuses —
//! the policy decides what the collision becomes: `error` (the ld64 and
//! peregrine default — the refusal, the symbol named), `warning` (the first
//! definition wins, the collision is recorded, the exit policy prints it and
//! still exits 0), `suppress` (the same first-wins product, nothing printed),
//! `dynamic_lookup` (the duplicated name leaves the winners' table, the
//! references ride the flat-lookup slot — the M103 undefined face pattern).
//! The decision rides both resolve paths (the full install and the M9 reuse
//! replay — the policy is config, not a lane product, the M81/M107 pattern);
//! the relocatable output refuses the non-default faces (the object's symtab
//! is the input's, verbatim).

use pgr_core::LinkError;
use pgr_core::ids::FileId;
use pgr_core::interner::Interner;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_core::object::InputObject;
use pgr_core::propagate::{SectionDigest, section_digests};
use pgr_core::resolve::{MultiplyDefinedPolicy, Resolution, ResolutionSnapshot, UndefinedPolicy};
use pgr_core::resolve_reuse::{install_reused, plan_reuse};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// A small object defining `name` strongly over its `__text` (one `ret`),
/// plus a distinct `_main` for the first object so the image has an entry.
fn definer(object_name: &str, symbol: &str, with_main: bool) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(object_name);
    let sect = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: symbol.into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    if with_main {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
    }
    b
}

/// Parses the builders in command-line order and interns every symbol name
/// (the same Pass 1 + interning batch `link` runs).
fn parse(builders: &[ObjectBuilder]) -> (Interner, Vec<InputObject>) {
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut objects = Vec::new();
    for (i, spec) in builders.iter().enumerate() {
        let bytes = spec.build().unwrap();
        let mut obj = InputObject::parse(FileId(i as u32), spec.name(), bytes).unwrap();
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
    (interner, objects)
}

/// The full Pass 2 under `policy` (the reference shape the reuse path must
/// reproduce).
fn full_resolve(
    objects: &[InputObject],
    interner: &Interner,
    policy: MultiplyDefinedPolicy,
) -> Result<Resolution, LinkError> {
    let mut res = Resolution::default();
    res.install(objects, interner, policy)?;
    res.require_all_resolved(interner, objects, UndefinedPolicy::Error, false)?;
    res.apply_multiply_defined_policy(policy, interner, objects)?;
    Ok(res)
}

/// The reused Pass 2: plan the reuse from the recorded state, then install
/// it — the collision decision rides the replay (the policy is config).
fn reused_resolve(
    recorded: &ResolutionSnapshot,
    prev: &[SectionDigest],
    objects: &[InputObject],
    interner: &Interner,
    policy: MultiplyDefinedPolicy,
) -> Result<Resolution, LinkError> {
    let plan = plan_reuse(recorded, prev, interner, objects, &[], &[])
        .map_err(|f| panic!("unexpected reuse fallback: {f}"))?;
    let mut res = install_reused(
        &plan,
        recorded,
        interner,
        objects,
        &[],
        &[],
        &[],
        UndefinedPolicy::Error,
        false,
        policy,
    )?;
    res.apply_multiply_defined_policy(policy, interner, objects)?;
    Ok(res)
}

#[test]
fn the_default_refuses_with_the_symbol_named() {
    // `error` (the default): the collision refuses the link with the symbol
    // named (the pre-M108 escalation, ld64's error face).
    let a = definer("a.o", "_dup", true);
    let b = definer("b.o", "_dup", false);
    let cfg = LinkConfig::default();
    let err = link(&corpus(a, b), &[], &cfg).expect_err("the collision refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("duplicate strong"),
        "the face names itself: {msg}"
    );
    assert!(msg.contains("_dup"), "the refusal names the symbol: {msg}");
}

#[test]
fn warning_and_suppress_keep_the_first_definition_and_record() {
    // `warning`/`suppress`: the first definition wins (command-line order —
    // the pre-M108 tie shape), the collision is recorded as the walk's own
    // product (the exit policy decides what surfaces — the M103 convention).
    for policy in [
        MultiplyDefinedPolicy::Warning,
        MultiplyDefinedPolicy::Suppress,
    ] {
        let a = definer("a.o", "_dup", true);
        let b = definer("b.o", "_dup", false);
        let cfg = LinkConfig {
            multiply_defined: policy,
            ..LinkConfig::default()
        };
        let result = link(&corpus(a, b), &[], &cfg).expect("the first definition wins");
        let id = result.interner.lookup(b"_dup").expect("the name interned");
        let def = result
            .resolution
            .def(id)
            .expect("the first definition rides");
        assert_eq!(def.file, FileId(0), "the first object's definition wins");
        let entries: Vec<&str> = result.resolution.multiply_defined_open().collect();
        assert_eq!(
            entries.len(),
            1,
            "the collision is recorded once: {entries:?}"
        );
        assert!(
            entries[0].contains("_dup") && entries[0].contains("input 0"),
            "the entry names the symbol and the winner: {entries:?}"
        );
    }
}

#[test]
fn dynamic_lookup_leaves_the_name_flat() {
    // `dynamic_lookup`: the duplicated name leaves the winners' table, the
    // references ride the flat-lookup slot (the M103 undefined face pattern).
    // The reference matters: the flat ride is the *reference's* bind, so the
    // fixture carries one undefined row against the duplicated name.
    let mut a = definer("a.o", "_dup", true);
    let undef = a.add_symbol(ObjectSymbol::Undefined {
        name: "_dup".into(),
        weak_ref: false,
    });
    let data = a.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let slot = a.sym_index(undef);
    a.section_mut(data)
        .relocs
        .push(pgr_fixtures::ObjectReloc::unsigned(slot).at(0));
    let b = definer("b.o", "_dup", false);
    let cfg = LinkConfig {
        multiply_defined: MultiplyDefinedPolicy::DynamicLookup,
        ..LinkConfig::default()
    };
    let result = link(&corpus(a, b), &[], &cfg).expect("the flat ride links");
    let id = result.interner.lookup(b"_dup").expect("the name interned");
    assert!(
        result.resolution.def(id).is_none(),
        "the duplicated definition leaves the winners' table"
    );
    assert!(
        result.resolution.is_dynamic_lookup(id),
        "the name rides the flat-lookup slot"
    );
    assert!(
        result.resolution.multiply_defined_open().next().is_none(),
        "the lookup face intends the ride — nothing recorded"
    );
}

#[test]
fn a_strong_weak_collision_is_not_a_duplicate() {
    // The rank order still decides: a strong definition beats a weak one
    // without a collision (the policy prices strong-strong ties only).
    let strong = definer("a.o", "_dup", true);
    let mut weak = ObjectBuilder::new("b.o");
    let sect = weak.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    weak.add_symbol(ObjectSymbol::Defined {
        name: "_dup".into(),
        section_index: sect,
        value: 0,
        weak: true,
    });
    let cfg = LinkConfig::default();
    let result = link(&corpus(strong, weak), &[], &cfg).expect("the strong side wins");
    let id = result.interner.lookup(b"_dup").expect("the name interned");
    assert_eq!(
        result.resolution.def(id).expect("the winner").file,
        FileId(0),
        "the strong definition wins without a collision"
    );
}

#[test]
fn the_non_default_policies_refuse_on_the_relocatable_output() {
    // The object's symtab is the input's, verbatim — there is no winner to
    // decide about (the M104/M105/M107 refusal shape, the re-check backing
    // the driver surface).
    for policy in [
        MultiplyDefinedPolicy::Warning,
        MultiplyDefinedPolicy::Suppress,
        MultiplyDefinedPolicy::DynamicLookup,
    ] {
        let cfg = LinkConfig {
            filetype: OutputType::Relocatable,
            multiply_defined: policy,
            ..LinkConfig::default()
        };
        let err = link_reloc(
            &corpus(definer("a.o", "_dup", true), definer("b.o", "_dup", false)),
            &[],
            &cfg,
            Parallelism::default(),
        )
        .expect_err("the relocatable output refuses the knob");
        assert!(
            err.to_string().contains("-multiply_defined"),
            "the refusal names the knob: {err}"
        );
    }
    // The default rides the relocatable output (the pre-M108 shape) — the
    // duplicate-free corpus links; the duplicated one still refuses (the
    // install site's escalation is the pre-M108 shape on every output).
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        ..LinkConfig::default()
    };
    link_reloc(
        &corpus(
            definer("a.o", "_solo", true),
            definer("b.o", "_other", false),
        ),
        &[],
        &cfg,
        Parallelism::default(),
    )
    .expect("the default rides the relocatable output");
    let err = link_reloc(
        &corpus(definer("a.o", "_dup", true), definer("b.o", "_dup", false)),
        &[],
        &cfg,
        Parallelism::default(),
    )
    .expect_err("the duplicated corpus refuses under the default");
    assert!(
        err.to_string().contains("duplicate strong"),
        "the pre-M108 escalation holds on the relocatable output: {err}"
    );
}

fn corpus(a: ObjectBuilder, b: ObjectBuilder) -> Vec<LinkInput> {
    vec![
        LinkInput {
            name: a.name().to_string(),
            bytes: a.build().expect("the fixture object builds"),
        },
        LinkInput {
            name: b.name().to_string(),
            bytes: b.build().expect("the fixture object builds"),
        },
    ]
}

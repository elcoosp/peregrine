//! M103 — the non-escalating undefined policies (`-undefined warning` /
//! `-undefined suppress`): ld64's two remaining faces of the
//! `-undefined` surface, the other halves of M2's `error` and
//! `dynamic_lookup`. The unresolved references ride the SAME flat-lookup
//! slot `dynamic_lookup` always encoded
//! (`BIND_SPECIAL_DYLIB_FLAT_LOOKUP`) — what changes is the escalation:
//! the walk records the unresolved names instead of refusing, and the
//! exit policy reads the record (the warning face prints, the suppress
//! face stays silent — both exit 0).
//!
//! Gate matrix:
//! * the bind shape — warning and suppress plan the exact bytes
//!   `dynamic_lookup` plans (the policy is the exit's, never the
//!   image's; the bind words and the `MH_NOUNDEFS` absence ride
//!   identically);
//! * the record — the walk's `unresolved_open` product carries one
//!   deterministic entry per unresolved reference (the `-U` relocation
//!   sites included), the escalation lanes never record;
//! * the replay — the resolve-reuse replay rides the policy the way the
//!   cold ladder always has (the policy is config, not a product);
//! * the refusal — the relocatable output refuses the policies (an
//!   object has no load-time bind to warn or suppress; the layout's
//!   re-check backs the driver surface);
//! * the lock — double-link determinism holds across the policies.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_core::resolve::UndefinedPolicy;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// A corpus whose every object references one unresolved external
/// (`_hole`) through a GOT-form pointer pair — the reference no input
/// and no dylib resolves, the policy's subject.
fn corpus() -> Vec<LinkInput> {
    (0..2)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(8),
                vec![],
            ));
            for f in 0..2 {
                b.add_symbol(ObjectSymbol::Defined {
                    name: if i == 0 && f == 0 {
                        "_main".into()
                    } else {
                        format!("_fn_{i}_{f}")
                    },
                    section_index: text,
                    value: (f * 16) as u64,
                    weak: false,
                });
            }
            let hole = b.add_symbol(ObjectSymbol::Undefined {
                name: "_hole".into(),
                weak_ref: false,
            });
            b.section_mut(text)
                .relocs
                .push(ObjectReloc::got_page21(hole as u32).at(4));
            b.section_mut(text)
                .relocs
                .push(ObjectReloc::got_pageoff12(hole as u32).at(8));
            LinkInput {
                name: format!("obj_{i}.o"),
                bytes: b.build().expect("the fixture object builds"),
            }
        })
        .collect()
}

fn link_with(policy: UndefinedPolicy) -> pgr_core::LinkResult {
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        undefined_policy: policy,
        ..LinkConfig::default()
    };
    link(&corpus(), &[], &cfg).expect("the non-escalating policy links")
}

// ---- the bind shape -----------------------------------------------------------

#[test]
fn the_non_escalating_policies_plan_the_dynamic_lookup_bytes() {
    let lookup = link_with(UndefinedPolicy::DynamicLookup);
    for policy in [UndefinedPolicy::Warning, UndefinedPolicy::Suppress] {
        let shaped = link_with(policy);
        assert_eq!(
            lookup.layout.header_bytes, shaped.layout.header_bytes,
            "the {policy:?} face plans the dynamic_lookup bytes: the policy is the \
             exit's, never the image's"
        );
    }
    // The flat-lookup slot: the hole binds through a GOT slot whose bind
    // word names no dylib ordinal — the flat lookup dynamic_lookup
    // always encoded (the bind rides, the image carries the hole).
    assert!(
        !lookup.layout.header_bytes.is_empty(),
        "the plans exist to compare"
    );
}

#[test]
fn the_escalating_policy_refuses_the_same_corpus() {
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        undefined_policy: UndefinedPolicy::Error,
        ..LinkConfig::default()
    };
    let err = link(&corpus(), &[], &cfg).expect_err("the default policy escalates");
    let message = err.to_string();
    assert!(
        message.contains("undefined symbol") && message.contains("_hole"),
        "the refusal names the hole: {message}"
    );
}

// ---- the record ---------------------------------------------------------------

#[test]
fn the_walk_records_the_unresolved_open_entries() {
    for policy in [UndefinedPolicy::Warning, UndefinedPolicy::Suppress] {
        let result = link_with(policy);
        let entries: Vec<&str> = result.resolution.unresolved_open().collect();
        assert_eq!(
            entries.len(),
            1,
            "one entry per unresolved NAME (both objects reference `_hole`; the \
             entry names the first referencing site) ({policy:?}): {entries:?}"
        );
        assert!(
            entries.iter().all(|e| e.contains("_hole")),
            "each entry names the hole ({policy:?}): {entries:?}"
        );
        assert!(
            entries.iter().all(|e| e.contains("referenced from")),
            "each entry names its reference site ({policy:?}): {entries:?}"
        );
    }
}

#[test]
fn the_escalation_lanes_record_nothing() {
    // `dynamic_lookup` intends the lookup — nothing to report; `error`
    // never returns a resolution to read.
    let result = link_with(UndefinedPolicy::DynamicLookup);
    assert_eq!(
        result.resolution.unresolved_open().count(),
        0,
        "the intended lookups record no unresolved-open entries"
    );
}

#[test]
fn the_lookup_bind_rides_the_flat_slot() {
    let result = link_with(UndefinedPolicy::Warning);
    // The hole is a dynamic lookup in the resolution — the same slot
    // `dynamic_lookup` uses, whatever the exit face prints.
    let hole = result
        .interner
        .lookup(b"_hole")
        .expect("the link's own interner interned the hole");
    assert!(
        result.resolution.is_dynamic_lookup(hole),
        "the unresolved reference rides the dynamic-lookup slot"
    );
}

// ---- the replay ---------------------------------------------------------------

#[test]
fn the_resolve_reuse_replay_rides_the_policy() {
    // The manual Pass 2 under the warning face (the m9 shape: parse,
    // intern, finish, atomize, install, walk) — the replay's dylib
    // install + policy walk runs over the recorded winners, the same
    // record product either path.
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut objects = Vec::new();
    for (i, input) in corpus().iter().enumerate() {
        let mut obj = pgr_core::object::InputObject::parse(
            pgr_core::ids::FileId(i as u32),
            &input.name,
            input.bytes.clone(),
        )
        .expect("the corpus parses");
        names.append(&mut obj.take_symbol_names());
        objects.push(obj);
    }
    let (interner, ids) = pgr_core::Interner::build(&names);
    let mut cursor = 0usize;
    for obj in &mut objects {
        let take = obj.symbols.len();
        obj.finish(&ids[cursor..cursor + take])
            .expect("the names bind");
        cursor += take;
        obj.compute_atoms(true);
    }
    let mut resolution = pgr_core::resolve::Resolution::default();
    resolution
        .install(
            &objects,
            &interner,
            pgr_core::resolve::MultiplyDefinedPolicy::Error,
        )
        .expect("the names install");
    resolution
        .require_all_resolved(&interner, &objects, UndefinedPolicy::Warning, false)
        .expect("the warning face resolves");
    assert!(
        resolution.unresolved_open().count() > 0,
        "the replay's walk records the same product"
    );
}

// ---- the refusal ---------------------------------------------------------------

#[test]
fn the_relocatable_output_refuses_the_policies() {
    for policy in [UndefinedPolicy::Warning, UndefinedPolicy::Suppress] {
        let cfg = LinkConfig {
            filetype: OutputType::Relocatable,
            undefined_policy: policy,
            ..LinkConfig::default()
        };
        let err = link_reloc(&corpus(), &[], &cfg, Parallelism::Auto)
            .expect_err("the -r path refuses the policies");
        let message = err.to_string();
        assert!(
            message.contains("load-time bind"),
            "the refusal names the missing bind ({policy:?}): {message}"
        );
    }
}

// ---- the lock ------------------------------------------------------------------

#[test]
fn double_link_is_byte_identical_across_the_policies() {
    let a = link_with(UndefinedPolicy::Warning).layout.header_bytes;
    let b = link_with(UndefinedPolicy::Warning).layout.header_bytes;
    assert_eq!(a, b, "the warning face is deterministic");
    let a = link_with(UndefinedPolicy::Suppress).layout.header_bytes;
    let b = link_with(UndefinedPolicy::Suppress).layout.header_bytes;
    assert_eq!(a, b, "the suppress face is deterministic");
}

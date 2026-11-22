//! M121 — the `-warn_duplicate` duplicate-symbol advisory: ld64's flag
//! ("Cause ld to print a warning when a duplicate symbol definition is
//! found") is the advisory decision the Pass-2 resolver's duplicate-strong
//! tally reads. Distinct from `-multiply_defined warning` (which changes
//! the resolution policy to first-wins), `-warn_duplicate` is purely
//! advisory: it tallies the duplicate strong definitions found during
//! Pass 2 resolve and emits a warning to stderr, but the resolution
//! policy itself is unchanged (the default `error` still applies unless
//! overridden).
//!
//! Gate matrix:
//! * the default records nothing (the advisory is a measurement, never a
//!   layout product — every pre-knob link byte-identical);
//! * the advisory tallies the duplicate strong-strong collisions the
//!   `multiply_defined` policy prices (the same `install_sect_def` tie),
//!   derived from the resolved state on both resolve paths;
//! * the advisory never changes the resolution policy — under the default
//!   `error` a duplicate strong definition still refuses the link;
//! * the byte-identity lock — the bytes never move under either face;
//! * the ladder replay rides the decision (the M81 pattern — config, not
//!   a product);
//! * the relocatable refusal — the object's symtab is the input's,
//!   verbatim (the layout re-check and `link_reloc` back the driver
//!   surface).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_cached, link_reloc};
use pgr_core::propagate::section_digests;
use pgr_core::resolve::MultiplyDefinedPolicy;
use pgr_core::resolve_reuse::ResolveReuseSeed;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// One object whose `__text` defines the named strong external — the
/// duplicate the advisory tallies (two of these under the same name
/// collide at the `install_sect_def` `Equal`/`Strong` tie).
fn dup_corpus(name: &str, sym: &str) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(4),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: sym.into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b
}

/// One object defining `_main` (the entry) — keeps the executable
/// resolvable beside the duplicate.
fn main_corpus(name: &str) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(4),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b
}

fn inputs(builders: &[ObjectBuilder]) -> Vec<LinkInput> {
    builders
        .iter()
        .map(|b| LinkInput {
            name: b.name().into(),
            bytes: b.build().expect("the fixture object builds"),
        })
        .collect()
}

fn dup_cfg(tweak: impl FnOnce(&mut LinkConfig)) -> LinkConfig {
    let mut c = LinkConfig {
        filetype: OutputType::Execute,
        multiply_defined: MultiplyDefinedPolicy::Warning,
        ..LinkConfig::default()
    };
    tweak(&mut c);
    c
}

#[test]
fn the_default_records_nothing() {
    // The default (`warn_duplicate = false`) records nothing — the walk
    // never runs, the advisory is a measurement, never a layout product
    // (every pre-knob link byte-identical).
    let builders = vec![
        main_corpus("m.o"),
        dup_corpus("a.o", "_dup"),
        dup_corpus("b.o", "_dup"),
    ];
    let result =
        link(&inputs(&builders), &[], &dup_cfg(|_| ())).expect("the warning-policy link runs");
    assert!(
        result.resolution.warn_duplicate_open().next().is_none(),
        "the default records no duplicate advisory"
    );
}

#[test]
fn the_advisory_tallies_duplicate_strong_collisions() {
    // Under `-warn_duplicate` the duplicate strong-strong collision the
    // `multiply_defined` policy prices tallies — one entry per collision
    // (the same `install_sect_def` tie, derived from the resolved state).
    let builders = vec![
        main_corpus("m.o"),
        dup_corpus("a.o", "_dup"),
        dup_corpus("b.o", "_dup"),
    ];
    let result = link(
        &inputs(&builders),
        &[],
        &dup_cfg(|c| c.warn_duplicate = true),
    )
    .expect("the warning-policy link runs");
    let entries: Vec<String> = result
        .resolution
        .warn_duplicate_open()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "the advisory tallies the one duplicate collision: {entries:?}"
    );
    assert!(
        entries[0].contains("_dup") && entries[0].contains("input"),
        "the entry names the symbol and the colliding inputs: {}",
        entries[0]
    );
}

#[test]
fn the_advisory_never_changes_the_resolution_policy() {
    // Under the default `error` policy a duplicate strong definition still
    // refuses the link — `-warn_duplicate` is advisory, the policy is
    // unchanged (the default `error` still applies unless overridden).
    let builders = vec![dup_corpus("a.o", "_dup"), dup_corpus("b.o", "_dup")];
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        warn_duplicate: true,
        ..LinkConfig::default()
    };
    let err = link(&inputs(&builders), &[], &cfg)
        .expect_err("the default error policy still refuses the duplicate");
    let text = err.to_string();
    assert!(
        text.contains("duplicate strong definition") && text.contains("_dup"),
        "the refusal names the duplicate and the unchanged policy: {text}"
    );
}

#[test]
fn the_byte_identity_lock() {
    // The advisory never moves the bytes — the on and off faces link
    // byte-identical under the same warning policy (the tally is a
    // measurement, never a layout product).
    let builders = vec![
        main_corpus("m.o"),
        dup_corpus("a.o", "_dup"),
        dup_corpus("b.o", "_dup"),
    ];
    let off = link(&inputs(&builders), &[], &dup_cfg(|_| ())).expect("the off face links");
    let on = link(
        &inputs(&builders),
        &[],
        &dup_cfg(|c| c.warn_duplicate = true),
    )
    .expect("the on face links");
    assert_eq!(
        off.layout.header_bytes, on.layout.header_bytes,
        "the advisory never moves the bytes"
    );
}

#[test]
fn the_ladder_replay_rides_the_decision() {
    // The M81 pattern: the decision is config, not a product — the
    // resolve-reuse relink re-plans the same tally the cold walk plans
    // (the advisory walk reads the post-replay resolved state, both lanes
    // reach it).
    let builders = vec![
        main_corpus("m.o"),
        dup_corpus("a.o", "_dup"),
        dup_corpus("b.o", "_dup"),
    ];
    let ins = inputs(&builders);
    let recording = link_cached(
        &ins,
        &[],
        &dup_cfg(|c| {
            c.record_resolution = true;
            c.warn_duplicate = true;
        }),
        Parallelism::Serial,
        None,
    )
    .expect("the recording link runs");
    let snapshot = recording
        .resolve_snapshot
        .clone()
        .expect("a recording link captures the snapshot");
    let replayed = link_cached(
        &ins,
        &[],
        &dup_cfg(|c| {
            c.resolve_reuse = Some(ResolveReuseSeed {
                snapshot,
                digests: section_digests(&recording.objects),
            });
            c.warn_duplicate = true;
        }),
        Parallelism::Serial,
        None,
    )
    .expect("the seeded relink runs");
    let cold: Vec<String> = recording
        .resolution
        .warn_duplicate_open()
        .map(str::to_owned)
        .collect();
    let replay: Vec<String> = replayed
        .resolution
        .warn_duplicate_open()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        cold, replay,
        "the replay derives the same duplicate tally (the M81 parity)"
    );
    assert_eq!(
        cold.len(),
        1,
        "the replay tallies the one duplicate collision: {cold:?}"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob_in_link_reloc() {
    // The object's symtab is the input's, verbatim — there is no
    // resolution landing to tally (the M104/M105/M116 pattern; the layout
    // re-check backs this in `layout`). A single object (no duplicate) so
    // the resolve succeeds and the re-check fires.
    let builders = vec![main_corpus("a.o")];
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        warn_duplicate: true,
        ..LinkConfig::default()
    };
    let err = link_reloc(&inputs(&builders), &[], &cfg, Parallelism::Serial)
        .expect_err("the relocatable output refuses the knob");
    let text = err.to_string();
    assert!(
        text.contains("-warn_duplicate") && text.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {text}"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob_in_layout() {
    // The layout's own re-check: no library caller plans the shape either
    // (the M104/M105/M116 refusal shape). A single object (no duplicate)
    // so the resolve succeeds and the layout re-check fires.
    let builders = vec![main_corpus("a.o")];
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        warn_duplicate: true,
        ..LinkConfig::default()
    };
    let err = link(&inputs(&builders), &[], &cfg).expect_err("the layout re-check refuses");
    let text = err.to_string();
    assert!(
        text.contains("-warn_duplicate") && text.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {text}"
    );
}

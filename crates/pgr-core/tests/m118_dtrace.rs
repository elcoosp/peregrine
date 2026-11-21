//! M118 — the `-dtrace` decision: ld64's dtrace `DOF` section processing —
//! a `__dtrace_dof` (`S_DTRACE_DOF`) section is recognized as a dtrace
//! payload (Pass 1, distinct from the generic `S_ATTR_DEBUG` debug class),
//! the emit validates its `DOF` header (the identification magic and the
//! bounds the `DTrace` consumer gates on) before the section links into the
//! output, and the verifier backstops the contract read-side on every
//! `S_DTRACE_DOF` section. The default carries a `__dtrace_dof` section's
//! bytes verbatim (no emit validation; the read-side backstop still gates)
//! and keeps every pre-knob link byte-identical; a corpus without a
//! `__dtrace_dof` section links byte-identical under either face.
//!
//! Gate matrix:
//! * the default carries the `__dtrace_dof` section (the pre-M118 shape);
//! * `-dtrace` carries the section too (the classification recognizes the
//!   payload, never drops it — the M105/M118 distinction);
//! * `-dtrace` is distinct from the debug class — under `-S` the dtrace
//!   payload rides (the debug strip never drops a payload the decision
//!   recognized);
//! * the decision threads to the layout (the echo the emit reads);
//! * the byte-identity lock — a corpus without a `__dtrace_dof` section
//!   links byte-identical under either face;
//! * the ladder replay rides the decision (the M81 pattern — config, not
//!   a product);
//! * the relocatable refusal — the object's sections are the input's,
//!   verbatim (the layout re-check and `link_reloc` back the driver
//!   surface).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_cached, link_reloc};
use pgr_core::propagate::section_digests;
use pgr_core::resolve_reuse::ResolveReuseSeed;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::S_DTRACE_DOF;
use pgr_format::dof::DOF_MAGIC;

/// One object: `_main`, a `__text` body, and one `__dtrace_dof`
/// (`S_DTRACE_DOF`) section carrying a `DOF` header whose leading bytes
/// are the identification magic (the valid face) or a stand-in (the
/// invalid face the producer's emit-side gate would refuse under
/// `-dtrace` and the verifier's read-side backstop reports either way).
fn dtrace_corpus(name: &str, valid_dof: bool) -> ObjectBuilder {
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
    // The DOF payload: 32 bytes, the identification magic at the head
    // (the valid face) or a stand-in (the invalid face). 32 bytes covers
    // the DOF_ID_SIZE identification region either way.
    let mut dof = vec![0u8; 32];
    dof[..DOF_MAGIC.len()].copy_from_slice(if valid_dof { &DOF_MAGIC } else { b"XXXX" });
    let dof_sect = b.add_section(ObjectSection::text("__dtrace_dof", dof, vec![]));
    b.section_mut(dof_sect).flags = S_DTRACE_DOF;
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

fn cfg(tweak: impl FnOnce(&mut LinkConfig)) -> LinkConfig {
    let mut c = LinkConfig::default();
    tweak(&mut c);
    c
}

fn placed_sections(layout: &pgr_core::Layout) -> Vec<String> {
    layout
        .sections
        .iter()
        .map(|s| format!("{},{}", s.seg_name, s.name))
        .collect()
}

#[test]
fn the_default_carries_the_dtrace_section() {
    // The pre-M118 shape: a `__dtrace_dof` section rides its regular
    // bucket as load-time bytes (the classification is inert without the
    // decision; the read-side backstop still gates the header).
    let builders = vec![dtrace_corpus("a.o", true)];
    let layout = link(&inputs(&builders), &[], &cfg(|_| ()))
        .expect("the default link plans")
        .layout;
    let names = placed_sections(&layout);
    assert!(
        names.iter().any(|n| n.contains("__dtrace_dof")),
        "the default carries the dtrace section: {names:?}"
    );
}

#[test]
fn the_dtrace_decision_carries_the_dtrace_section() {
    // The classification recognizes the payload — the section rides its
    // regular bucket under the decision too (carried, validated at emit;
    // never dropped, the M105/M118 distinction).
    let builders = vec![dtrace_corpus("a.o", true)];
    let layout = link(&inputs(&builders), &[], &cfg(|c| c.dtrace = true))
        .expect("the dtrace link plans")
        .layout;
    let names = placed_sections(&layout);
    assert!(
        names.iter().any(|n| n.contains("__dtrace_dof")),
        "the decision carries the dtrace section (validated at emit): {names:?}"
    );
}

#[test]
fn the_dtrace_decision_is_distinct_from_the_debug_class() {
    // The M105/M118 distinction: under `-S` the debug strip drops
    // `S_ATTR_DEBUG` shapes, but a dtrace payload the decision recognized
    // is not debug — the section rides (the bucketing consults the
    // classification before the debug gate).
    let builders = vec![dtrace_corpus("a.o", true)];
    let layout = link(
        &inputs(&builders),
        &[],
        &cfg(|c| {
            c.dtrace = true;
            c.strip_debug = true;
        }),
    )
    .expect("the dtrace + strip link plans")
    .layout;
    let names = placed_sections(&layout);
    assert!(
        names.iter().any(|n| n.contains("__dtrace_dof")),
        "the dtrace payload is distinct from the debug class (rides under -S): {names:?}"
    );
}

#[test]
fn the_dtrace_decision_threads_to_the_layout() {
    // The echo the emit reads — the decision crosses to the layout so
    // the producer-side gate fires regardless of which caller plans.
    let builders = vec![dtrace_corpus("a.o", true)];
    let layout = link(&inputs(&builders), &[], &cfg(|c| c.dtrace = true))
        .expect("the dtrace link plans")
        .layout;
    assert!(layout.dtrace, "the layout carries the dtrace decision");
}

#[test]
fn a_corpus_without_a_dtrace_section_links_byte_identical_under_either_face() {
    // The byte-identity lock: no `__dtrace_dof` machinery, nothing to
    // validate — the decision never moves a byte (every pre-knob link
    // included).
    let mut b = ObjectBuilder::new("plain.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let builders = vec![b];
    let default = link(&inputs(&builders), &[], &cfg(|_| ())).expect("the plain link plans");
    let decided =
        link(&inputs(&builders), &[], &cfg(|c| c.dtrace = true)).expect("the plain link plans");
    assert_eq!(
        default.layout.header_bytes, decided.layout.header_bytes,
        "a corpus without a dtrace section links byte-identical under either face"
    );
}

#[test]
fn the_ladder_replay_rides_the_decision() {
    // The M81 pattern: the decision is config, not a product — the
    // resolve-reuse relink re-plans the same DOF-validated shape the cold
    // walk plans (the layout reads the config, both lanes reach it).
    let builders = vec![dtrace_corpus("a.o", true)];
    let ins = inputs(&builders);
    let recording = link_cached(
        &ins,
        &[],
        &cfg(|c| {
            c.record_resolution = true;
            c.dtrace = true;
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
        &cfg(|c| {
            c.resolve_reuse = Some(ResolveReuseSeed {
                snapshot,
                digests: section_digests(&recording.objects),
            });
            c.dtrace = true;
        }),
        Parallelism::Serial,
        None,
    )
    .expect("the seeded relink runs");
    assert_eq!(
        placed_sections(&recording.layout),
        placed_sections(&replayed.layout),
        "the replay plans the same DOF-bearing shape (the M81 parity)"
    );
    assert!(
        replayed.layout.dtrace,
        "the replay carries the dtrace decision (config, not a product)"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob_in_link_reloc() {
    // The object's sections are the input's, verbatim — there is no DOF
    // header to validate at emit (the M104/M105/M117 pattern; the layout
    // re-check backs this in `layout`).
    let builders = vec![dtrace_corpus("a.o", true)];
    let cfg = cfg(|c| {
        c.filetype = OutputType::Relocatable;
        c.dtrace = true;
    });
    let err = link_reloc(&inputs(&builders), &[], &cfg, Parallelism::Serial)
        .expect_err("the relocatable output refuses the knob");
    let text = err.to_string();
    assert!(
        text.contains("-dtrace") && text.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {text}"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob_in_layout() {
    // The layout's own re-check: no library caller plans the shape
    // either (the M104/M105/M117 refusal shape).
    let builders = vec![dtrace_corpus("a.o", true)];
    let cfg = cfg(|c| {
        c.filetype = OutputType::Relocatable;
        c.dtrace = true;
    });
    let err = link(&inputs(&builders), &[], &cfg).expect_err("the layout re-check refuses");
    let text = err.to_string();
    assert!(
        text.contains("-dtrace") && text.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {text}"
    );
}

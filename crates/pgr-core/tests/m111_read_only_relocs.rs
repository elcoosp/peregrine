//! M111 — the read-only-relocations policy (`-read_only_relocs <policy>`):
//! the W^X contract's other half. A chained fixup or classic opcode whose
//! target segment's initial mapping (`initprot`, from `-segprot` or the
//! house defaults) lacks `VM_PROT_WRITE` is the write dyld cannot perform
//! at load time: `error` (the default) refuses the link — the M17 segprot
//! gate's W^X contract; `warning` derives the advisory entries and the
//! reloc rides; `suppress` rides silently. The `warning` and `suppress`
//! faces plan the identical image; the relocatable output refuses the
//! non-default faces (its sections are the input's, verbatim).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_core::resolve::ReadOnlyRelocsPolicy;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// An object whose `__TEXT,__const` carries one absolute pointer to an
/// in-image definition (the slot lands in a read-only segment — the
/// house `__TEXT` default is RX/RX).
fn text_pointer(name: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let def = b.add_symbol(ObjectSymbol::Defined {
        name: "_table".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    let slot = b.sym_index(def);
    let c = b.add_section(ObjectSection::data("__const", vec![0u8; 8], vec![]));
    b.section_mut(c)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    b.build().expect("the fixture object builds")
}

fn corpus(bytes: Vec<u8>) -> Vec<LinkInput> {
    vec![LinkInput {
        name: "a.o".to_string(),
        bytes,
    }]
}

/// The segprot decision: `__DATA` rides `rx`/`rx` — the initial
/// mapping lacks `VM_PROT_WRITE` (the M17 segprot grammar's own shape).
fn read_only_data_prots() -> pgr_core::segprot::SegProts {
    let mut prots = pgr_core::segprot::SegProts::default();
    prots
        .insert(
            pgr_core::segprot::SegName::Data,
            pgr_core::segprot::SegProt::parse("rx", "rx").expect("the rwx grammar"),
        )
        .expect("one decision per segment");
    prots
}

fn plan(
    bytes: Vec<u8>,
    policy: ReadOnlyRelocsPolicy,
) -> Result<pgr_core::link::LinkResult, pgr_core::LinkError> {
    let cfg = LinkConfig {
        read_only_relocs: policy,
        seg_prots: read_only_data_prots(),
        ..LinkConfig::default()
    };
    link(&corpus(bytes), &[], &cfg)
}

#[test]
fn the_error_face_refuses_the_read_only_target() {
    let err = plan(text_pointer("a.o"), ReadOnlyRelocsPolicy::Error)
        .expect_err("the default face refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("-read_only_relocs error") && msg.contains("read-only segment"),
        "the refusal names the policy and the contract: {msg}"
    );
}

#[test]
fn the_warning_face_rides_the_reloc_and_records_the_entries() {
    let result =
        plan(text_pointer("a.o"), ReadOnlyRelocsPolicy::Warning).expect("the advisory face rides");
    assert!(
        !result.layout.read_only_relocs.is_empty(),
        "the advisory entries ride the layout: {:?}",
        result.layout.read_only_relocs
    );
    // The advisory is the face's only product: the layout itself plans
    // the same sections the `error` face would have refused to write
    // (the exit owns the refusal, the image rides).
}

#[test]
fn the_suppress_face_plans_the_identical_image() {
    // The policy is the exit's: `warning` and `suppress` plan the
    // identical image (byte-for-byte) — only the advisory surfaces.
    let warning =
        plan(text_pointer("a.o"), ReadOnlyRelocsPolicy::Warning).expect("the warning face links");
    let suppress =
        plan(text_pointer("a.o"), ReadOnlyRelocsPolicy::Suppress).expect("the suppress face links");
    // The advisory is the faces' only delta — clear it and the plans
    // must be identical (the policy is the exit's, never the bytes').
    let mut bare = warning.layout.clone();
    bare.read_only_relocs.clear();
    assert_eq!(
        format!("{bare:?}"),
        format!("{:?}", suppress.layout),
        "the faces plan identical bytes"
    );
    assert!(
        !warning.layout.read_only_relocs.is_empty(),
        "the warning face's advisory rides the layout"
    );
    assert!(
        suppress.layout.read_only_relocs.is_empty(),
        "suppress records nothing"
    );
}

#[test]
fn the_relocatable_output_refuses_the_non_default_faces() {
    for policy in [
        ReadOnlyRelocsPolicy::Warning,
        ReadOnlyRelocsPolicy::Suppress,
    ] {
        let cfg = LinkConfig {
            read_only_relocs: policy,
            seg_prots: read_only_data_prots(),
            filetype: OutputType::Relocatable,
            ..LinkConfig::default()
        };
        let err = link_reloc(
            &corpus(text_pointer("a.o")),
            &[],
            &cfg,
            Parallelism::default(),
        )
        .expect_err("the relocatable output refuses the non-default faces");
        assert!(
            err.to_string().contains("-read_only_relocs"),
            "the refusal names the knob: {err}"
        );
    }
}

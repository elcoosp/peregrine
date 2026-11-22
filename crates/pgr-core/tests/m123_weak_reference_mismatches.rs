//! M123 — the weak-reference-mismatches policy
//! (`-weak_reference_mismatches <policy>`): ld64's policy for a symbol
//! referenced both weakly and strongly across the input set (the
//! `N_WEAK_REF` bit on a symbol's `n_desc`). A typed three-value
//! alphabet: `error` (the default — the link refuses when a name's
//! reference sites mix weak and strong), `weak` (the advisory face
//! records the mismatch, the resolution policy itself unchanged — the
//! bytes never move, the M109/M116 pattern), `non-weak` (the advisory
//! face records the mismatch the other way). The decision is a
//! measurement, never a layout product; the relocatable output refuses
//! the non-default faces.
//!
//! Gate matrix:
//! * the default `error` — a weak/strong reference mix refuses the link
//!   (the collision named — the two sites);
//! * the advisory `weak` / `non-weak` faces — the mismatch is recorded,
//!   the resolution policy itself unchanged, the bytes never move;
//! * the silent shape — a corpus with no mix records nothing under any
//!   face (every pre-knob link byte-identical);
//! * the relocatable refusal — the non-default faces refuse on `-r`
//!   (the object's references ride untouched, the M104/M105/M111
//!   pattern).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::WeakReferenceMismatchesPolicy;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// `ref.o`: a unique local function plus an undefined reference to
/// `name` (weak or strong — the `weak` bit flips the `N_WEAK_REF`
/// flag). `_main` rides only the object the caller marks as the entry
/// (the duplicate-strong-definition guard the M108 walk prices).
fn ref_object(file: &str, weak: bool, undef: &str, is_main: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new(file);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    let local_name = format!("_{}_fn", file.trim_end_matches(".o"));
    b.add_symbol(ObjectSymbol::Defined {
        name: if is_main { "_main".into() } else { local_name },
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
/// resolution both references bind against — the mix is the reference
/// sites' weakness, not the definition's).
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

/// The mixed corpus: a weak reference and a strong reference to the
/// same name, plus the provider that resolves both.
fn mixed_corpus() -> Vec<LinkInput> {
    vec![
        LinkInput {
            name: "weakref.o".to_string(),
            bytes: ref_object("weakref.o", true, "_sym", true),
        },
        LinkInput {
            name: "strongref.o".to_string(),
            bytes: ref_object("strongref.o", false, "_sym", false),
        },
        LinkInput {
            name: "provider.o".to_string(),
            bytes: provider_object("_sym"),
        },
    ]
}

/// A clean corpus: two strong references (no mix) — the silent shape.
fn clean_corpus() -> Vec<LinkInput> {
    vec![
        LinkInput {
            name: "strongref.o".to_string(),
            bytes: ref_object("strongref.o", false, "_sym", true),
        },
        LinkInput {
            name: "strongref2.o".to_string(),
            bytes: ref_object("strongref2.o", false, "_sym", false),
        },
        LinkInput {
            name: "provider.o".to_string(),
            bytes: provider_object("_sym"),
        },
    ]
}

#[test]
fn the_default_error_face_refuses_a_mix() {
    let cfg = LinkConfig {
        weak_reference_mismatches: WeakReferenceMismatchesPolicy::Error,
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let err = link(&mixed_corpus(), &[], &cfg).expect_err("the mix refuses under error");
    let msg = err.to_string();
    assert!(
        msg.contains("weakly") && msg.contains("strongly"),
        "the refusal names the weak/strong mix: {msg}"
    );
    assert!(
        msg.contains("-weak_reference_mismatches"),
        "the refusal names the knob and the fix: {msg}"
    );
}

#[test]
fn the_advisory_weak_face_records_and_exits_zero() {
    let cfg = LinkConfig {
        weak_reference_mismatches: WeakReferenceMismatchesPolicy::Weak,
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let result = link(&mixed_corpus(), &[], &cfg).expect("the advisory face exits 0");
    let entries: Vec<&str> = result.resolution.weak_reference_mismatches_open().collect();
    assert_eq!(entries.len(), 1, "the mismatch is recorded once");
    assert!(
        entries[0].contains("_sym")
            && entries[0].contains("weakly")
            && entries[0].contains("strongly"),
        "the entry names the symbol and the two sites: {}",
        entries[0]
    );
}

#[test]
fn the_advisory_non_weak_face_records_the_same_mismatch() {
    // The `non-weak` face is the advisory twin — same detection, same
    // record, same exit (the M103/M108 pattern's twin).
    let cfg = LinkConfig {
        weak_reference_mismatches: WeakReferenceMismatchesPolicy::NonWeak,
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let result = link(&mixed_corpus(), &[], &cfg).expect("the advisory face exits 0");
    let entries: Vec<&str> = result.resolution.weak_reference_mismatches_open().collect();
    assert_eq!(
        entries.len(),
        1,
        "the mismatch is recorded once (the twin face)"
    );
}

#[test]
fn the_silent_shape_records_nothing_under_any_face() {
    // A corpus with no weak/strong mix records nothing under any face
    // (every pre-knob link byte-identical — the M109 pattern's face).
    for policy in [
        WeakReferenceMismatchesPolicy::Error,
        WeakReferenceMismatchesPolicy::Weak,
        WeakReferenceMismatchesPolicy::NonWeak,
    ] {
        let cfg = LinkConfig {
            weak_reference_mismatches: policy,
            filetype: OutputType::Execute,
            ..LinkConfig::default()
        };
        let result = link(&clean_corpus(), &[], &cfg).expect("the clean corpus links");
        let entries: Vec<&str> = result.resolution.weak_reference_mismatches_open().collect();
        assert!(
            entries.is_empty(),
            "no mix records nothing under {:?}",
            policy
        );
    }
}

#[test]
fn the_advisory_face_plans_byte_identical_bytes_to_the_default() {
    // The advisory is a measurement, never a layout product — the bytes
    // never move (the M109 pattern). The image under `weak` is
    // byte-identical to the image under `error` (where the mix refuses)
    // on a *clean* corpus (no mix to refuse under `error`).
    let clean_default = link(&clean_corpus(), &[], &LinkConfig::default())
        .expect("the clean corpus links under the default");
    let clean_weak = link(
        &clean_corpus(),
        &[],
        &LinkConfig {
            weak_reference_mismatches: WeakReferenceMismatchesPolicy::Weak,
            filetype: OutputType::Execute,
            ..LinkConfig::default()
        },
    )
    .expect("the clean corpus links under weak");
    assert_eq!(
        clean_default.layout.header_bytes, clean_weak.layout.header_bytes,
        "the bytes never move under the advisory face"
    );
}

#[test]
fn the_relocatable_output_refuses_the_non_default_faces() {
    for policy in [
        WeakReferenceMismatchesPolicy::Weak,
        WeakReferenceMismatchesPolicy::NonWeak,
    ] {
        let cfg = LinkConfig {
            weak_reference_mismatches: policy,
            filetype: OutputType::Relocatable,
            ..LinkConfig::default()
        };
        let err = link(&mixed_corpus(), &[], &cfg).expect_err("the -r face refuses");
        let msg = err.to_string();
        assert!(
            msg.contains("-weak_reference_mismatches") && msg.contains("relocatable"),
            "the refusal names the knob and the relocatable shape ({:?}): {msg}",
            policy
        );
    }
}

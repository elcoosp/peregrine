//! M115 — the `ObjC` category-merging optimization: ld64's default-on
//! transform (the M43 `-ObjC` pattern's optimization). A category whose
//! base class rides the same image registers through its base class's
//! registration — the `__objc_catlist`/`__objc_nlcatlist` registration
//! section the metadata family names folds away — and
//! `-no_objc_category_merging` keeps every category's registration
//! verbatim (categories stay as separate sections). The decision is
//! Pass 3's layout decision point: the classifier consults the
//! resolution's own winners (the class families the image defines) and
//! the entries' relocation-bound metadata names (the M43/M49 families),
//! never mutating a shape it cannot parse. Corpora without mergeable
//! categories link byte-identical — every pre-knob link included.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// One object: a base class family (`_OBJC_CLASS_$_Dog<i>`, defined in
/// a data section), a category family (`_OBJC_CATEGORY_$_Dog<i>`), and
/// the category's registration section (`__DATA,__objc_catlist`, one
/// 8-byte pointer entry relocating against the category symbol) — the
/// shape the merge decision reads.
fn category_object(i: usize, with_class: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new(&format!("cat_{i}.o"));
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
    let data = b.add_section(ObjectSection::data("__objc_data", vec![0u8; 16], vec![]));
    let cat_sym = b.add_symbol(ObjectSymbol::Defined {
        name: format!("_OBJC_CATEGORY_$_Dog{i}"),
        section_index: data,
        value: 0,
        weak: false,
    });
    if with_class {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_OBJC_CLASS_$_Dog{i}"),
            section_index: data,
            value: 8,
            weak: false,
        });
    }
    let catlist = b.add_section(ObjectSection::data("__objc_catlist", vec![0u8; 8], vec![]));
    b.section_mut(catlist)
        .relocs
        .push(ObjectReloc::unsigned(cat_sym as u32).at(0));
    b.build().expect("the fixture object builds")
}

fn inputs(with_class: bool) -> Vec<LinkInput> {
    vec![LinkInput {
        name: "cat_0.o".into(),
        bytes: category_object(0, with_class),
    }]
}

fn cfg(disabled: bool) -> LinkConfig {
    LinkConfig {
        ident: "cat".into(),
        filetype: OutputType::Execute,
        objc_category_merging: !disabled,
        ..LinkConfig::default()
    }
}

/// The placed section names the plan carries.
fn placed_sections(layout: &pgr_core::Layout) -> Vec<String> {
    layout
        .sections
        .iter()
        .map(|s| format!("{},{}", s.seg_name, s.name))
        .collect()
}

#[test]
fn the_default_merges_the_registration_into_the_base_class() {
    // ld64's default: the category whose base class rides the image
    // registers through the class — the separate registration section
    // folds away (no `__objc_catlist` section, no load-time bytes).
    let layout = link(&inputs(true), &[], &cfg(false))
        .expect("the mergeable corpus links")
        .layout;
    let names = placed_sections(&layout);
    assert!(
        !names.iter().any(|n| n.contains("__objc_catlist")),
        "the merged link carries no registration section: {names:?}"
    );
}

#[test]
fn the_disabled_face_keeps_the_categories_separate() {
    // `-no_objc_category_merging`: categories stay as separate sections
    // — the registration rides verbatim (every load-time byte the
    // input carried).
    let layout = link(&inputs(true), &[], &cfg(true))
        .expect("the disabled link plans")
        .layout;
    let names = placed_sections(&layout);
    assert!(
        names.iter().any(|n| n.contains("__DATA,__objc_catlist")),
        "the disabled link keeps the registration section: {names:?}"
    );
}

#[test]
fn an_unmergeable_registration_rides_verbatim_under_either_face() {
    // A category whose base class does NOT ride the link must keep
    // registering (its class arrives at load time) — the conservative
    // verbatim face, byte-identical under the merge decision either
    // way (the pre-knob lock: no category, no byte moved).
    let merged = link(&inputs(false), &[], &cfg(false)).expect("the external-base link plans");
    let disabled = link(&inputs(false), &[], &cfg(true)).expect("the external-base link plans");
    assert!(
        placed_sections(&merged.layout)
            .iter()
            .any(|n| n.contains("__DATA,__objc_catlist")),
        "the external base keeps its registration"
    );
    assert_eq!(
        merged.layout.header_bytes, disabled.layout.header_bytes,
        "the unmergeable corpus links byte-identical under either face"
    );
    assert_eq!(
        merged.layout.file_size, disabled.layout.file_size,
        "the segment plans are identical (the classifier never mutates an \
         unmergeable shape)"
    );
}

#[test]
fn the_merge_moves_real_bytes_not_just_headers() {
    // The merged face drops the registration section's load-time bytes
    // (the file shrinks by the section's content + its header row); the
    // disabled face keeps them. The image is the plan's own product.
    let merged = link(&inputs(true), &[], &cfg(false)).expect("the merged plans");
    let disabled = link(&inputs(true), &[], &cfg(true)).expect("the disabled plans");
    assert!(
        disabled.layout.file_size > merged.layout.file_size,
        "the disabled face carries the registration section's bytes"
    );
}

#[test]
fn the_knob_refuses_on_the_relocatable_output() {
    // `-r` keeps its refusal: the object's sections are the input's,
    // verbatim — the surface's knob refusal mirrored exactly (the
    // M104/M105 pattern, `link_reloc` re-checking).
    let err = link_reloc(&inputs(true), &[], &cfg(true), Parallelism::Auto)
        .expect_err("the object refuses the disabling knob");
    let message = err.to_string();
    assert!(
        message.contains("-no_objc_category_merging") && message.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {message}"
    );
}

#[test]
fn the_default_is_the_merge() {
    // ld64's default is the merge — the field mirrors it; the flag is
    // the disable.
    assert!(LinkConfig::default().objc_category_merging);
}

#[test]
fn the_merge_is_deterministic() {
    // The classifier consults the resolution's winners and the entries'
    // names — a pure pass-3 decision, stable across runs.
    let a = link(&inputs(true), &[], &cfg(false))
        .expect("the first plans")
        .layout;
    let b = link(&inputs(true), &[], &cfg(false))
        .expect("the second plans")
        .layout;
    assert_eq!(
        a.header_bytes, b.header_bytes,
        "the merged plan is deterministic"
    );
}

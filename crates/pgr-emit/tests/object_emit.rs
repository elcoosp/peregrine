//! M10 rung 1 — the relocatable object emit (`build_object_image`): the
//! byte rules of a `-r` output and the retargeting contract.
//!
//! The assertions ride the pipeline's own parser (`link_reloc` over the
//! emitted bytes) — the emit's output is an input, by construction — plus
//! a few raw header words, and the verifier's strict gate.

use pgr_core::{FileId, InputObject, LinkConfig, Parallelism, link_reloc};
use pgr_emit::build_object_image;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{
    ARM64_RELOC_SUBTRACTOR, ARM64_RELOC_UNSIGNED, MH_MAGIC_64, MH_OBJECT, RELOC_LENGTH_8,
};

fn a_object() -> (String, Vec<u8>) {
    let mut b = ObjectBuilder::new("a.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![
            0x90, 0x00, 0x00, 0x00, // adrp x0, _ext@page
            0x91, 0x00, 0x00, 0x00, // add x0, x0, #_ext@pageoff
            0x94, 0x00, 0x00, 0x00, // bl _ext
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ],
        // Symtab indices follow the fixtures' output order (locals
        // first): 0=_lvar, 1=_a_main, 2=_ext.
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21(2).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12(2).at(4),
            ObjectReloc::branch26(2).at(8),
        ],
    ));
    b.add_section(ObjectSection::cstring("a-str"));
    let data = b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 16],
        vec![
            // pointer difference: _a_main - _ext (a SUBTRACTOR pair);
            // indices: minuend _a_main=1, subtrahend _ext=2
            ObjectReloc {
                offset: 0,
                symbolnum: 1,
                pcrel: false,
                length_log2: RELOC_LENGTH_8,
                extern_: true,
                rtype: ARM64_RELOC_SUBTRACTOR,
            },
            ObjectReloc::unsigned(2).at(0),
            // section-relative pointer into __data (ordinal 3 in a.o)
            ObjectReloc {
                offset: 8,
                symbolnum: 3,
                pcrel: false,
                length_log2: RELOC_LENGTH_8,
                extern_: false,
                rtype: ARM64_RELOC_UNSIGNED,
            },
        ],
    ));
    let _ = data;
    b.add_symbol(ObjectSymbol::Defined {
        name: "_a_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_ext".into(),
        weak_ref: false,
    });
    b.add_symbol(ObjectSymbol::Local("_lvar".into()));
    (String::from("a.o"), b.build().unwrap())
}

fn b_object() -> (String, Vec<u8>) {
    let mut b = ObjectBuilder::new("b.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_ext".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_b_extra".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Local("_bloc".into()));
    (String::from("b.o"), b.build().unwrap())
}

fn c_object() -> (String, Vec<u8>) {
    let mut b = ObjectBuilder::new("c.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0x94, 0x00, 0x00, 0x00], // bl _never
        vec![ObjectReloc::branch26(1).at(0)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_c_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_never".into(),
        weak_ref: false,
    });
    (String::from("c.o"), b.build().unwrap())
}

fn link(parts: &[(String, Vec<u8>)]) -> pgr_core::RelocLink {
    let inputs: Vec<pgr_core::LinkInput> = parts
        .iter()
        .map(|(name, bytes)| pgr_core::LinkInput {
            name: name.clone(),
            bytes: bytes.clone(),
        })
        .collect();
    link_reloc(&inputs, &[], &LinkConfig::default(), Parallelism::Auto).unwrap()
}

/// The relocation entry table of one output section, read back through the
/// pipeline's own parser (`raw_relocs` stays behind `pub` boundaries, so
/// the merged table is rebuilt from the decoded stream — the same stream
/// the next link consumes).
fn decoded_relocs(obj: &InputObject, section: usize) -> Vec<pgr_core::DecodedReloc> {
    obj.sections[section].relocs.clone()
}

#[test]
fn object_emit_header_carries_the_object_contract() {
    let corpus = vec![a_object(), b_object(), c_object()];
    let linked = link(&corpus);
    let out = build_object_image(&linked, &LinkConfig::default()).unwrap();
    // magic + filetype + zero flags (raw words, offsets fixed by Mach-O).
    let magic = u32::from_le_bytes(out[0..4].try_into().unwrap());
    assert_eq!(magic, MH_MAGIC_64);
    let filetype = u32::from_le_bytes(out[12..16].try_into().unwrap());
    assert_eq!(filetype, MH_OBJECT);
    let flags = u32::from_le_bytes(out[24..28].try_into().unwrap());
    assert_eq!(flags, 0, "a -r output carries no image flags");
    let ncmds = u32::from_le_bytes(out[16..20].try_into().unwrap());
    assert_eq!(ncmds, 4, "segment, build version, symtab, dysymtab");
}

#[test]
fn object_emit_output_is_an_input_sections_merge_in_first_seen_order() {
    let corpus = vec![a_object(), b_object(), c_object()];
    let linked = link(&corpus);
    let out = build_object_image(&linked, &LinkConfig::default()).unwrap();
    let reparsed = link_reloc(
        &[pgr_core::LinkInput {
            name: "out.o".into(),
            bytes: out.clone(),
        }],
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
    )
    .unwrap();
    let obj = &reparsed.objects[0];
    let names: Vec<&str> = obj.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["__text", "__cstring", "__data"], "first-seen order");
    let segments: Vec<&str> = obj.sections.iter().map(|s| s.segment.as_str()).collect();
    assert_eq!(segments, ["__TEXT", "__TEXT", "__DATA"]);
    // Sizes: __text merged a(16) + b(4) + c(4); __cstring a(6); __data a(16).
    assert_eq!(obj.sections[0].size, 24);
    assert_eq!(obj.sections[1].size, 6);
    assert_eq!(obj.sections[2].size, 16);
}

#[test]
fn object_emit_symbol_table_is_locals_then_globals_then_undefineds() {
    let corpus = vec![a_object(), b_object(), c_object()];
    let linked = link(&corpus);
    let out = build_object_image(&linked, &LinkConfig::default()).unwrap();
    let reparsed = link_reloc(
        &[pgr_core::LinkInput {
            name: "out.o".into(),
            bytes: out,
        }],
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
    )
    .unwrap();
    let obj = &reparsed.objects[0];
    let names: Vec<&[u8]> = obj
        .symbols
        .iter()
        .map(|s| reparsed.interner.bytes(s.name))
        .collect();
    assert_eq!(
        names,
        [
            b"_lvar".as_slice(),
            b"_bloc",
            b"_a_main",
            b"_ext",
            b"_b_extra",
            b"_c_main",
            b"_never",
        ],
        "locals, winner-backed globals, open undefineds"
    );
    // The winner mapping rode along: _ext's value is b.o's contribution
    // base inside the merged __text (a's 16 bytes, align 4 → base 16).
    let ext_id = reparsed.interner.lookup(b"_ext").unwrap();
    let def = reparsed.resolution.def(ext_id).unwrap();
    assert_eq!(def.file.0, 0, "the emitted object is the only input");
    assert_eq!(def.value, 16);
}

#[test]
fn object_emit_reloc_entries_retarget_through_the_resolution() {
    let corpus = vec![a_object(), b_object(), c_object()];
    let linked = link(&corpus);
    let out = build_object_image(&linked, &LinkConfig::default()).unwrap();
    let reparsed = link_reloc(
        &[pgr_core::LinkInput {
            name: "out.o".into(),
            bytes: out,
        }],
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
    )
    .unwrap();
    let obj = &reparsed.objects[0];
    // Symbol table indices (locals 0-1, globals 2-5, undefined 6).
    // __TEXT,__text: the ADDEND pairs survive, every extern entry names
    // _ext (the winner's output index 3), and the merged r_addresses
    // place a.o's contribution at 0.
    let text = decoded_relocs(obj, 0);
    // The merged __text carries a's three entries (the decoded stream
    // merges each ADDEND leader into its target) plus c's branch against
    // the open `_never` — while the ENCODED table carries the 6 raw
    // entries (2 leaders + 4 targets) again.
    assert_eq!(text.len(), 4, "2 paired entries + 2 branches");
    assert!(matches!(
        text[0].kind,
        pgr_core::RelocKind::Page21 { addend: 0 }
    ));
    assert!(matches!(
        text[1].kind,
        pgr_core::RelocKind::PageOff12 { addend: 0 }
    ));
    assert!(matches!(text[2].kind, pgr_core::RelocKind::Branch26));
    assert!(matches!(text[3].kind, pgr_core::RelocKind::Branch26));
    let name_of = |t: &pgr_core::RelocTarget| match t {
        pgr_core::RelocTarget::Extern(id) => reparsed.interner.bytes(*id).to_vec(),
        pgr_core::RelocTarget::Section(idx) => {
            panic!("unexpected section target {idx}")
        }
    };
    assert_eq!(
        name_of(&text[0].target),
        b"_ext",
        "the winner's output index"
    );
    assert_eq!(name_of(&text[2].target), b"_ext");
    assert_eq!(name_of(&text[3].target), b"_never", "undefineds stay open");
    assert_eq!(text[0].offset, 0);
    assert_eq!(text[2].offset, 8);
    assert_eq!(
        text[3].offset, 20,
        "c.o's contribution rides after b.o's (16..20)"
    );
    // __DATA,__data: the SUBTRACTOR pair re-encoded (minuend _a_main,
    // subtrahend _ext), the section-relative pointer re-ordinaled to the
    // merged __data ordinal 3.
    let data = decoded_relocs(obj, 2);
    assert_eq!(data.len(), 2);
    match data[0].kind {
        pgr_core::RelocKind::Subtractor { minuend } => match minuend {
            pgr_core::RelocTarget::Extern(id) => assert_eq!(
                reparsed.interner.bytes(id),
                b"_a_main",
                "the minuend re-points at the output symtab"
            ),
            pgr_core::RelocTarget::Section(idx) => {
                panic!("unexpected minuend Section({idx})")
            }
        },
        other => panic!("unexpected kind {other:?}"),
    }
    match data[0].target {
        pgr_core::RelocTarget::Extern(id) => {
            assert_eq!(reparsed.interner.bytes(id), b"_ext");
        }
        pgr_core::RelocTarget::Section(idx) => {
            panic!("unexpected subtrahend Section({idx})")
        }
    }
    assert_eq!(
        data[1].target,
        pgr_core::RelocTarget::Section(2),
        "the section-relative pointer names merged __data (0-based 2)"
    );
}

#[test]
fn object_emit_passes_the_strict_verifier() {
    let corpus = vec![a_object(), b_object(), c_object()];
    let linked = link(&corpus);
    let out = build_object_image(&linked, &LinkConfig::default()).unwrap();
    let report = pgr_verify::verify(
        &out,
        &pgr_verify::Options {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    let errors: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.severity == pgr_verify::Severity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "a -r output must be verifier-clean: {errors:?}"
    );
}

#[test]
fn extern_reloc_naming_a_local_refuses_with_help_text() {
    // A malformed input: r_extern=1 pointing at a local symbol entry. The
    // resolution has nothing to offer (locals never enter the extern
    // namespace) — the emit refuses with a miette help-text diagnostic
    // instead of writing an entry that names nothing.
    let mut b = ObjectBuilder::new("bad.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(0).at(0)],
    ));
    b.add_symbol(ObjectSymbol::Local("_secret".into()));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_d_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let corpus = vec![(String::from("bad.o"), b.build().unwrap())];
    let linked = link(&corpus);
    let err = build_object_image(&linked, &LinkConfig::default()).unwrap_err();
    let refusal = match &err {
        pgr_emit::EmitError::RelocRefusal { refusal } => refusal,
        other => panic!("expected the reloc refusal, got {other:?}"),
    };
    assert_eq!(refusal.section, "__TEXT,__text");
    let rendered = refusal.render();
    assert!(rendered.contains("rebuild"), "help text present");
}

#[test]
fn object_emit_is_deterministic() {
    let corpus = vec![a_object(), b_object(), c_object()];
    let first = build_object_image(&link(&corpus), &LinkConfig::default()).unwrap();
    let second = build_object_image(&link(&corpus), &LinkConfig::default()).unwrap();
    assert_eq!(first, second, "determinism policy §4.3");
}

#[test]
fn file_ids_never_leak_into_the_object_emit() {
    // The emit walks `FileId`s, not Vec indices — a corpus whose FileIds
    // are non-contiguous (the archive-pull shape) must lay out identically
    // to the contiguous shape.
    let corpus = vec![a_object(), b_object(), c_object()];
    let linked = link(&corpus);
    assert_eq!(linked.objects[0].file, FileId(0));
    assert_eq!(linked.objects[2].file, FileId(2));
}

//! M37 — the TLV carriage: the input `S_THREAD_LOCAL_*` sections the
//! pre-M37 pipeline rejected (`ARM64_RELOC_TLVP_LOAD_PAGE21`/`PAGEOFF12`
//! "parsed and rejected", the `S_THREAD_LOCAL_ZEROFILL` type mistaken for
//! byte-backed data) ride the atom map onto the output `__DATA` segment —
//! the `__thread_vars` descriptors (16-byte thunk/initializer pairs), the
//! `__thread_data` initializers and the `__thread_bss` zero-fills, the
//! descriptor loads patching ADRP/imm12 directly against the descriptor's
//! address (no GOT slot — the descriptor is always a local definition),
//! and the `MH_HAS_TLV_DESCRIPTORS` header flag the load-time TLV
//! allocation keys on.
//!
//! Gate matrix:
//! * the carriage — the TLV sections land in `__DATA` with their types
//!   carried (`S_THREAD_LOCAL_REGULAR`, `S_THREAD_LOCAL_VARIABLES`);
//! * the flag — an image carrying TLV sections sets
//!   `MH_HAS_TLV_DESCRIPTORS`; a TLV-free corpus keeps the flag clear;
//! * the patches — the TLVP page21/pageoff12 pairs patch ADRP/imm12
//!   against the descriptor's vaddr (imm12 scaled by the access size),
//!   never through a GOT slot;
//! * the zero-fills — `S_THREAD_LOCAL_ZEROFILL` is a zero-fill (VM-only,
//!   file_off 0, its own section — never merged into `__common`);
//! * the refusals — a descriptor section off the 16-byte stride refuses
//!   with the fix; a descriptor load past this image's own definitions
//!   refuses (thread-local variables cannot bind across a dylib
//!   boundary);
//! * the relocatable — `-r` carries the TLV sections and the decoded
//!   TLVP relocations (the pre-M37 parse refused the type outright);
//! * the cache — the POI cache keeps the TLV zero-fill classification.

use pgr_core::cache::{decode_poi, encode_poi};
use pgr_core::ids::FileId;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_core::object::{InputObject, RelocKind};
use pgr_core::resolve::UndefinedPolicy;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{
    MH_HAS_TLV_DESCRIPTORS, S_THREAD_LOCAL_REGULAR, S_THREAD_LOCAL_VARIABLES,
    S_THREAD_LOCAL_ZEROFILL,
};

/// Builds the M37 corpus: `_main` (RET), one `__thread int x` shape —
/// `__thread_data` initializer bytes, the `__thread_vars` descriptor
/// (thunk → `_tlv_get_addr`, initializer → `_x.init`) — and, optionally,
/// a `__thread_bss` zero-fill for `_y`. `__text` carries the
/// descriptor-load pair (`tlvp_page21` at 4, `tlvp_pageoff12` at 8)
/// targeting `_x`; with `define_x` false the target stays undefined
/// (dynamic lookup is the only resolution left, which the descriptor
/// load must refuse).
fn tlv_corpus(vars_bytes: Option<Vec<u8>>, define_x: bool, with_bss: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new("tlv.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        // RET + nops: the relocation sites are instruction words.
        vec![
            0xC0, 0x03, 0x5F, 0xD6, // RET
            0x00, 0x00, 0x00, 0x90, // adrp x0, <descriptor>@page (the TLVP page21 site)
            0x00, 0x00, 0x40,
            0xF9, // ldr x0, [x0, <descriptor>@pageoff] (the TLVP pageoff12 site)
        ],
        Vec::new(),
    ));
    let data = b.add_section(ObjectSection::thread_data(42u64.to_le_bytes().to_vec()));
    let vars = b.add_section(ObjectSection::thread_vars(
        vars_bytes.unwrap_or_else(|| vec![0u8; 16]),
        Vec::new(),
    ));
    if with_bss {
        b.add_section(ObjectSection::thread_bss(64, 3));
    }
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let x = if define_x {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_x".into(),
            section_index: vars,
            value: 0,
            weak: false,
        })
    } else {
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_x".into(),
            weak_ref: false,
        })
    };
    if with_bss {
        b.add_symbol(ObjectSymbol::Local("_y".into()));
    }
    let tlv_addr = b.add_symbol(ObjectSymbol::Undefined {
        name: "_tlv_get_addr".into(),
        weak_ref: false,
    });
    let sx = b.sym_index(x);
    let s = b.section_mut(text);
    s.relocs = vec![
        ObjectReloc::tlvp_page21(sx).at(4),
        ObjectReloc::tlvp_pageoff12(sx).at(8),
    ];
    let s_addr = b.sym_index(tlv_addr);
    let s = b.section_mut(vars);
    // The thunk binds `_tlv_get_addr` (external); the initializer rebases
    // into the `__thread_data` section (section-relative — clang's
    // descriptor shape; r_extern entries must name external symbols).
    s.relocs = vec![
        ObjectReloc::unsigned(s_addr).at(0),
        ObjectReloc::unsigned_sect(data as u32).at(8),
    ];
    b.build().expect("the fixture object builds")
}

/// A TLV-free corpus (`_main` only) — the flag-clear control.
fn plain_corpus() -> Vec<u8> {
    let mut b = ObjectBuilder::new("plain.o");
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
    b.build().expect("the fixture object builds")
}

/// A single-object corpus from raw bytes.
fn corpus(bytes: Vec<u8>) -> Vec<LinkInput> {
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes,
    }]
}

/// The dynamic-lookup config every TLV corpus links under (the
/// `_tlv_get_addr` thunk bind rides the flat-lookup ordinal, no dylib
/// fixture needed).
fn lookup_cfg() -> LinkConfig {
    let mut cfg = LinkConfig::default();
    cfg.flat_namespace = true;
    cfg.undefined_policy = UndefinedPolicy::DynamicLookup;
    cfg
}

/// Links the corpus under `tweak`.
fn plan(bytes: Vec<u8>, tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::layout::Layout {
    let mut cfg = lookup_cfg();
    tweak(&mut cfg);
    link(&corpus(bytes), &[], &cfg)
        .expect("the corpus links")
        .layout
}

fn section<'l>(
    layout: &'l pgr_core::layout::Layout,
    seg: &str,
    name: &str,
) -> &'l pgr_core::layout::PlacedSection {
    layout
        .sections
        .iter()
        .find(|s| s.seg_name == seg && s.name == name)
        .unwrap_or_else(|| panic!("the {seg},{name} section is placed"))
}

fn header_flags(layout: &pgr_core::layout::Layout) -> u32 {
    u32::from_le_bytes([
        layout.header_bytes[24],
        layout.header_bytes[25],
        layout.header_bytes[26],
        layout.header_bytes[27],
    ])
}

// ---- the carriage ----------------------------------------------------------

#[test]
fn the_tlv_sections_ride_the_data_segment() {
    let layout = plan(tlv_corpus(None, true, false), |_| {});
    let vars = section(&layout, "__DATA", "__thread_vars");
    assert_eq!(
        vars.flags & 0xff,
        S_THREAD_LOCAL_VARIABLES,
        "the descriptor section keeps its type"
    );
    assert_eq!(vars.size, 16, "one descriptor rides whole-section");
    let data = section(&layout, "__DATA", "__thread_data");
    assert_eq!(
        data.flags & 0xff,
        S_THREAD_LOCAL_REGULAR,
        "the initializer section keeps its type"
    );
    assert_eq!(data.pieces[0].size, 8, "the initializer rides its bytes");
}

#[test]
fn the_header_declares_the_tlv_descriptors() {
    let layout = plan(tlv_corpus(None, true, false), |_| {});
    assert!(
        header_flags(&layout) & MH_HAS_TLV_DESCRIPTORS != 0,
        "an image carrying TLV sections declares MH_HAS_TLV_DESCRIPTORS"
    );
    let plain = plan(plain_corpus(), |_| {});
    assert_eq!(
        header_flags(&plain) & MH_HAS_TLV_DESCRIPTORS,
        0,
        "a TLV-free image keeps the flag clear"
    );
}

// ---- the patches -----------------------------------------------------------

#[test]
fn the_descriptor_loads_patch_against_the_descriptor() {
    let layout = plan(tlv_corpus(None, true, false), |_| {});
    let vars = section(&layout, "__DATA", "__thread_vars");
    let text = section(&layout, "__TEXT", "__text");
    let desc_vaddr = vars.vm_addr;
    let slot_base = text.vm_addr;
    let piece = &text.pieces[0];
    let adrp = piece
        .patches
        .iter()
        .find(|p| matches!(p, pgr_core::layout::PatchOp::Adrp { in_offset: 4, .. }))
        .expect("the page21 site patches");
    let expected_delta = ((desc_vaddr as i64) >> 12) - (((slot_base + 4) as i64) >> 12);
    let pgr_core::layout::PatchOp::Adrp { page_delta, .. } = adrp else {
        unreachable!()
    };
    assert_eq!(
        *page_delta, expected_delta,
        "ADR P names the descriptor's page"
    );
    let ldr = piece
        .patches
        .iter()
        .find(|p| matches!(p, pgr_core::layout::PatchOp::PageOff12 { in_offset: 8, .. }))
        .expect("the pageoff12 site patches");
    let pgr_core::layout::PatchOp::PageOff12 { imm12, .. } = ldr else {
        unreachable!()
    };
    assert_eq!(
        *imm12,
        ((desc_vaddr & 0xFFF) >> 3) as u32,
        "the LDR imm12 rides the access size (8-byte loads)"
    );
    // The descriptor loads synthesize no GOT slot: the thunk/initializer
    // slots live in the descriptor section, the text carries two patches
    // and no fixup slots.
    assert!(
        piece.fixup_slots.is_empty(),
        "the descriptor load is a link-time patch, not a chain slot"
    );
}

// ---- the zero-fills --------------------------------------------------------

#[test]
fn thread_local_zerofill_stays_its_own_section() {
    let layout = plan(tlv_corpus(None, true, true), |_| {});
    let bss = section(&layout, "__DATA", "__thread_bss");
    assert!(bss.zerofill, "S_THREAD_LOCAL_ZEROFILL is a zero-fill");
    assert_eq!(bss.file_off, 0, "the zero-fill has no file bytes");
    assert_eq!(
        bss.flags & 0xff,
        S_THREAD_LOCAL_ZEROFILL,
        "the type rides the output section"
    );
    assert_eq!(bss.size, 64, "the zero-fill keeps its requested size");
    // VM-only: the segment's file bytes stop before the zero-fill tail.
    let seg = layout
        .segments
        .iter()
        .find(|s| s.name == "__DATA")
        .expect("the __DATA segment plans");
    assert!(
        seg.filesize < seg.vmsize,
        "the zero-fill advances VM only (filesize {:#x} < vmsize {:#x})",
        seg.filesize,
        seg.vmsize
    );
}

// ---- the refusals ----------------------------------------------------------

#[test]
fn a_descriptor_section_off_the_stride_refuses() {
    let err = link(
        &corpus(tlv_corpus(Some(vec![0u8; 20]), true, false)),
        &[],
        &lookup_cfg(),
    )
    .expect_err("the malformed descriptor stride refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("__thread_vars"),
        "the refusal names the section: {msg}"
    );
    assert!(
        msg.contains("16"),
        "the refusal names the descriptor stride: {msg}"
    );
}

#[test]
fn a_descriptor_load_beyond_this_image_refuses() {
    let err = link(&corpus(tlv_corpus(None, false, false)), &[], &lookup_cfg())
        .expect_err("the cross-image descriptor load refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("_x"),
        "the refusal names the descriptor symbol: {msg}"
    );
    assert!(
        msg.contains("descriptor"),
        "the refusal names the TLV descriptor contract: {msg}"
    );
}

// ---- the relocatable -------------------------------------------------------

#[test]
fn the_relocatable_output_carries_the_tlv_surface() {
    let mut cfg = lookup_cfg();
    cfg.filetype = OutputType::Relocatable;
    let rl = link_reloc(
        &corpus(tlv_corpus(None, true, false)),
        &[],
        &cfg,
        Parallelism::Auto,
    )
    .expect("the relocatable link parses the TLV surface");
    let obj = &rl.objects[0];
    let vars = obj
        .sections
        .iter()
        .find(|s| s.name == "__thread_vars")
        .expect("the descriptor section parses");
    assert_eq!(vars.flags & 0xff, S_THREAD_LOCAL_VARIABLES);
    let kinds: Vec<&RelocKind> = obj
        .sections
        .iter()
        .flat_map(|s| s.relocs.iter())
        .map(|r| &r.kind)
        .collect();
    assert!(
        kinds.iter().any(|k| matches!(k, RelocKind::TlvpLoadPage21)),
        "the TLVP page21 reloc decodes: {kinds:?}"
    );
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, RelocKind::TlvpLoadPageOff12)),
        "the TLVP pageoff12 reloc decodes: {kinds:?}"
    );
    assert!(
        kinds.iter().any(|k| matches!(k, RelocKind::Unsigned)),
        "the descriptor slots stay UNSIGNED (thunk bind + initializer rebase)"
    );
}

// ---- the cache -------------------------------------------------------------

#[test]
fn the_poi_cache_keeps_the_tlv_classification() {
    let built = tlv_corpus(None, true, true);
    let obj = InputObject::parse(FileId(0), "main.o", built).expect("the fixture object parses");
    let encoded = encode_poi(&obj, true);
    let decoded =
        decode_poi(&encoded, FileId(0), "main.o", true).expect("the cached parse decodes");
    let bss = decoded
        .sections
        .iter()
        .find(|s| s.name == "__thread_bss")
        .expect("the zero-fill section caches");
    assert!(
        bss.zerofill,
        "the TLV zero-fill classification survives the cache"
    );
    let vars = decoded
        .sections
        .iter()
        .find(|s| s.name == "__thread_vars")
        .expect("the descriptor section caches");
    assert_eq!(vars.flags & 0xff, S_THREAD_LOCAL_VARIABLES);
}

//! M19 — the dylib/bundle image base (`pgr_core::image_base`): the
//! preferred load address a non-executable image plans with stops being
//! the layout's hard-coded zero (`__TEXT.vmaddr == fileoff`, the M3
//! contract) and becomes a validated [`pgr_core::image_base::ImageBase`]
//! decision carried on [`pgr_core::layout::LinkConfig`] — the same
//! constant-delta resolver the executable's `__PAGEZERO` vmsize rides
//! (M15), one kind table, one reader.
//!
//! Gate matrix:
//! * the seam — an override validates (non-zero, a multiple of the
//!   16 KiB arm64 page) with the fix in the refusal, and the resolver
//!   keeps the M15 executable arm untouched;
//! * layout — a custom base shifts every dylib vmaddr by exactly the
//!   named delta (same skeleton, same file offsets, same sizes), the
//!   chained-fixup rebases encode `target − base` (the `64_OFFSET`
//!   contract), and no `__PAGEZERO` appears (dylibs carry none);
//! * the refusals — an image base on an executable or on the
//!   relocatable output is a layout error (the driver surface refuses
//!   earlier; the layout re-check so no caller can plan the shape);
//! * the lock — the default config plans what the pre-seam layout
//!   planned: `None` keeps `__TEXT.vmaddr == fileoff` and a
//!   double link stays byte-identical (TDD §4.3);
//! * the classic path — `-no_fixup_chains` opcodes carry the custom
//!   base the same way (the rebase opcodes are segment-relative).

use pgr_core::image_base::ImageBase;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// Two-object corpus with rebase slots (the gate needs addresses to
/// shift, not names to move): `_main` plus a `__data` pointer pair into
/// `__text` — the pointer slots are the chained-fixup rebases the base
/// rides.
fn corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let helper_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_helper".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_payload".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    b.section_mut(data).relocs = vec![
        ObjectReloc::unsigned(main_sym as u32).at(0),
        ObjectReloc::unsigned(helper_sym as u32).at(8),
    ];
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// Links the corpus with a config tweak and returns the layout.
fn link_layout(tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::Layout {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(&corpus(), &[], &cfg).expect("the corpus links").layout
}

// ---- the seam ----------------------------------------------------------------

#[test]
fn an_override_validates_nonzero_and_page_alignment() {
    // Accepted: any non-zero multiple of the 16 KiB arm64 page.
    for raw in [0x4000u64, 0x4000_0000, 0x1_0000_0000, 0x2_0000_0000] {
        let ib = ImageBase::from_override(raw).expect("the override validates");
        assert_eq!(ib.vmaddr(), raw);
    }
    // Zero refuses (a named zero is the default, not a decision).
    let err = ImageBase::from_override(0).expect_err("zero refuses");
    assert!(
        err.to_string().contains("the default"),
        "the refusal names the shape: {err}"
    );
    // A non-multiple refuses with the fix (round to a 0x4000 boundary).
    for raw in [0x3000u64, 0x1_0001, 0x4001] {
        let err = ImageBase::from_override(raw).expect_err("misaligned refuses");
        assert!(
            err.to_string().contains("16 KiB"),
            "the refusal names the alignment: {err}"
        );
    }
}

#[test]
fn the_resolver_keeps_the_m15_executable_arm() {
    // One kind table, one reader: the executable's constant-delta base
    // is the `__PAGEZERO` vmsize (M15) whatever a named dylib base says,
    // the relocatable output stays blob-relative (M3), and the dylib and
    // bundle arms read the named decision (0 when none — the M3 default).
    let named = Some(ImageBase::from_override(0x4000).expect("validates"));
    let pz = pgr_core::pagezero::PageZero::default();
    assert_eq!(
        pz.base_for(OutputType::Execute, None),
        0x1_0000_0000,
        "the executable base is the __PAGEZERO vmsize"
    );
    assert_eq!(
        pz.base_for(OutputType::Execute, named.as_ref()),
        0x1_0000_0000,
        "the dylib knob never moves an executable"
    );
    for kind in [OutputType::Dylib, OutputType::Bundle] {
        assert_eq!(pz.base_for(kind, None), 0, "{kind:?} default is 0 (M3)");
        assert_eq!(
            pz.base_for(kind, named.as_ref()),
            0x4000,
            "{kind:?} plans the named base"
        );
    }
    assert_eq!(
        pz.base_for(OutputType::Relocatable, named.as_ref()),
        0,
        "the relocatable output stays blob-relative"
    );
}

// ---- layout ------------------------------------------------------------------

#[test]
fn a_custom_base_shifts_every_dylib_vmaddr_by_exactly_the_delta() {
    let base = 0x4000_0000u64;
    let default = link_layout(|cfg| {
        cfg.filetype = OutputType::Dylib;
        cfg.install_name = Some("@rpath/libm19.dylib".into());
    });
    let custom = link_layout(|cfg| {
        cfg.filetype = OutputType::Dylib;
        cfg.install_name = Some("@rpath/libm19.dylib".into());
        cfg.image_base = Some(ImageBase::from_override(base).expect("validates"));
    });

    // The segment skeleton is untouched: same names, same file offsets,
    // same sizes — only vmaddr moves. No `__PAGEZERO` appears.
    assert!(
        custom.segments.iter().all(|s| s.name != "__PAGEZERO"),
        "a dylib carries no __PAGEZERO (M3 contract)"
    );
    assert_eq!(
        custom.segments.len(),
        default.segments.len(),
        "the segment set is shape-identical"
    );
    for (d, c) in default.segments.iter().zip(&custom.segments) {
        assert_eq!(d.name, c.name);
        assert_eq!(d.fileoff, c.fileoff, "{} fileoff", d.name);
        assert_eq!(d.vmsize, c.vmsize, "{} vmsize", d.name);
        assert_eq!(d.filesize, c.filesize, "{} filesize", d.name);
        assert_eq!(
            c.vmaddr - c.fileoff,
            base,
            "{}: vmaddr - fileoff == the named base",
            c.name
        );
    }
    // Sections shift by the same delta; their file offsets do not move.
    for (d, c) in default.sections.iter().zip(&custom.sections) {
        assert_eq!(d.file_off, c.file_off, "{} file offset", d.name);
        assert_eq!(d.size, c.size, "{} size", d.name);
        assert_eq!(
            c.vm_addr - d.vm_addr,
            base,
            "{} vmaddr shifts by exactly the named base",
            d.name
        );
    }
    assert_eq!(
        custom.image_base, base,
        "the layout names the base it planned with"
    );
}

#[test]
fn chained_rebase_words_encode_target_minus_base() {
    // The 64_OFFSET contract (TDD §7.2): a rebase word carries the
    // target's offset *from the image base*. For a dylib the base is
    // the named `__TEXT` vmaddr (0 by the M3 default) — the words move
    // when the base moves, not the slots they sit in.
    let base = 0x4000_0000u64;
    let custom = link_layout(|cfg| {
        cfg.filetype = OutputType::Dylib;
        cfg.install_name = Some("@rpath/libm19.dylib".into());
        cfg.image_base = Some(ImageBase::from_override(base).expect("validates"));
    });
    assert!(
        custom.fixups.slot_count > 0,
        "the corpus plans fixup slots (the fixture layout has data pointers)"
    );
    let default = link_layout(|cfg| {
        cfg.filetype = OutputType::Dylib;
        cfg.install_name = Some("@rpath/libm19.dylib".into());
    });
    assert_eq!(
        custom.fixups.slot_count, default.fixups.slot_count,
        "the base is address math, not a re-plan"
    );
}

#[test]
fn the_classic_opcode_path_carries_the_custom_base() {
    // `-no_fixup_chains` (the M6 classic path): the rebase opcodes are
    // segment-relative, so the plan shape is base-free — the segments
    // carry the base and dyld computes targets from them.
    let base = 0x4000_0000u64;
    let custom = link_layout(|cfg| {
        cfg.filetype = OutputType::Dylib;
        cfg.install_name = Some("@rpath/libm19.dylib".into());
        cfg.image_base = Some(ImageBase::from_override(base).expect("validates"));
        cfg.fixup_chains = false;
    });
    let default = link_layout(|cfg| {
        cfg.filetype = OutputType::Dylib;
        cfg.install_name = Some("@rpath/libm19.dylib".into());
        cfg.fixup_chains = false;
    });
    for (d, c) in default.segments.iter().zip(&custom.segments) {
        assert_eq!(d.fileoff, c.fileoff, "{} fileoff", d.name);
        assert_eq!(
            c.vmaddr - c.fileoff,
            base,
            "{}: the classic path plans the same constant delta",
            c.name
        );
    }
}

// ---- the refusals ------------------------------------------------------------

#[test]
fn an_image_base_on_an_executable_is_a_layout_error() {
    let err = link(
        &corpus(),
        &[],
        &LinkConfig {
            image_base: Some(ImageBase::from_override(0x4000).expect("validates")),
            ..LinkConfig::default()
        },
    )
    .expect_err("the executable refuses the dylib knob");
    assert!(
        err.to_string().contains("-pagezero_size"),
        "the refusal names the executable's own knob: {err}"
    );
}

#[test]
fn an_image_base_on_a_relocatable_output_is_a_layout_error() {
    let err = link(
        &corpus(),
        &[],
        &LinkConfig {
            filetype: OutputType::Relocatable,
            image_base: Some(ImageBase::from_override(0x4000).expect("validates")),
            ..LinkConfig::default()
        },
    )
    .expect_err("the relocatable output refuses the knob");
    assert!(
        err.to_string().contains("no segments"),
        "the refusal names the shape: {err}"
    );
}

// ---- the lock ----------------------------------------------------------------

#[test]
fn the_default_dylib_plans_vmaddr_zero() {
    let default = link_layout(|cfg| {
        cfg.filetype = OutputType::Dylib;
        cfg.install_name = Some("@rpath/libm19.dylib".into());
    });
    assert_eq!(
        default.image_base, 0,
        "None keeps the M3 constant (every pre-M19 dylib link byte-identical)"
    );
    for s in &default.segments {
        assert_eq!(s.vmaddr, s.fileoff, "{}: vmaddr == fileoff", s.name);
    }
}

#[test]
fn a_custom_base_double_link_stays_byte_identical() {
    // TDD §4.3: the deterministic-output lock. The base is config, not
    // schedule: the same config twice plans the same bytes.
    let mk = || {
        let mut cfg = LinkConfig {
            filetype: OutputType::Dylib,
            install_name: Some("@rpath/libm19.dylib".into()),
            ..LinkConfig::default()
        };
        cfg.image_base = Some(ImageBase::from_override(0x4000).expect("validates"));
        link(&corpus(), &[], &cfg).expect("the dylib links").layout
    };
    let (a, b) = (mk(), mk());
    assert_eq!(a.header_bytes, b.header_bytes, "the headers match");
    let shape = |l: &pgr_core::Layout| {
        l.segments
            .iter()
            .map(|s| {
                (
                    s.name.clone(),
                    s.vmaddr,
                    s.vmsize,
                    s.fileoff,
                    s.filesize,
                    s.maxprot,
                    s.initprot,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(shape(&a), shape(&b), "the segment tables match");
}

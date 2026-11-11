//! M18 — the stack-reserve seam (`pgr_core::stack_size`): the
//! executable's `LC_MAIN` stack size stops being the layout's
//! hard-coded zero (`w64(lc + 16, 0)` — dyld's default main-thread
//! stack) and becomes a validated
//! [`pgr_core::stack_size::StackSize`] decision carried on
//! [`pgr_core::layout::LinkConfig`] — the seam the header assembly
//! reads when it writes `LC_MAIN` (the `stacksize` field rides the
//! load command; nothing else in the plan moves).
//!
//! Gate matrix:
//! * the seam — the override validates (non-zero, a multiple of the
//!   16 KiB arm64 page) with the fix in the refusal;
//! * the decision — an executable link writes the named reserve into
//!   `LC_MAIN.stacksize` and touches nothing else in the plan (the
//!   load command is 24 bytes either way; every section, segment and
//!   `__LINKEDIT` chunk stays put);
//! * the refusal — a non-executable output carries no `LC_MAIN`, so a
//!   named reserve has no field to land on (a refusal, never a
//!   silently dropped knob — the `-init_offsets` precedent);
//! * the lock — the default config plans byte-for-byte what the
//!   pre-seam layout planned (the zero stacksize is the default), and
//!   the explicit-default decision is the default decision;
//! * determinism — a named-reserve double link stays byte-identical
//!   (TDD §4.3).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::stack_size::StackSize;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// One-object corpus with a bind-free surface: `_main` plus a `__data`
/// pointer pair into `__text` (the rebase slots give the link honest
/// fixup work, so the plan is the plan the reserve rides).
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
    let mut cfg = LinkConfig {
        entry_symbol: "_main".into(),
        ..LinkConfig::default()
    };
    tweak(&mut cfg);
    link(&corpus(), &[], &cfg).expect("the corpus links").layout
}

// ---- the seam ----------------------------------------------------------------

#[test]
fn overrides_validate_nonzero_and_page_alignment() {
    for raw in [0x4000u64, 0x100_0000, 0x4000_0000] {
        let s = StackSize::from_override(raw).expect("the override validates");
        assert_eq!(s.bytes(), raw);
    }
    // Zero refuses (the default is the absence of the knob, not a zero
    // reserve — a named zero is a typo, not a decision).
    let err = StackSize::from_override(0).expect_err("zero refuses");
    assert!(
        err.to_string().contains("non-zero"),
        "the refusal names the rule: {err}"
    );
    // A non-multiple of the 16 KiB arm64 page refuses (the kernel maps
    // the stack in pages).
    let err = StackSize::from_override(0x3000).expect_err("misaligned refuses");
    assert!(
        err.to_string().contains("16 KiB") && err.to_string().contains("0x3000"),
        "the refusal names the grammar and the value: {err}"
    );
}

#[test]
fn the_error_is_a_typed_surface() {
    let errors: [pgr_core::stack_size::StackSizeError; 2] = [
        pgr_core::stack_size::StackSizeError::Zero,
        pgr_core::stack_size::StackSizeError::Misaligned { raw: 0x3000 },
    ];
    for err in &errors {
        assert!(!err.to_string().is_empty(), "{err:?} renders");
    }
}

// ---- layout ------------------------------------------------------------------

#[test]
fn a_named_reserve_lands_in_lc_main() {
    // The header bytes carry `LC_MAIN` with the named stacksize at the
    // command's `+16` field (the layout's own emit contract).
    let layout = link_layout(|cfg| {
        cfg.stack_size = Some(StackSize::from_override(0x100_0000).expect("validates"));
    });
    let stacksize_at = layout.entryoff_at + 8;
    let bytes = &layout.header_bytes[stacksize_at as usize..stacksize_at as usize + 8];
    let mut raw = [0u8; 8];
    raw.copy_from_slice(bytes);
    assert_eq!(
        u64::from_le_bytes(raw),
        0x100_0000,
        "the named reserve rides LC_MAIN.stacksize"
    );
}

#[test]
fn the_reserve_moves_nothing_else_in_the_plan() {
    // `LC_MAIN` is 24 bytes with or without a reserve: every section,
    // segment and `__LINKEDIT` chunk stays put.
    let default = link_layout(|_| {});
    let reserved = link_layout(|cfg| {
        cfg.stack_size = Some(StackSize::from_override(0x100_0000).expect("validates"));
    });
    assert_eq!(default.file_size, reserved.file_size, "same file size");
    assert_eq!(
        default.segments.len(),
        reserved.segments.len(),
        "same segments"
    );
    for (x, y) in default.segments.iter().zip(&reserved.segments) {
        assert_eq!(x.name, y.name);
        assert_eq!(x.vmaddr, y.vmaddr, "{}: same vmaddr", x.name);
        assert_eq!(x.vmsize, y.vmsize, "{}: same vmsize", x.name);
        assert_eq!(x.fileoff, y.fileoff, "{}: same fileoff", x.name);
    }
    assert_eq!(default.entryoff, reserved.entryoff, "same entry");
}

#[test]
fn the_explicit_default_is_the_default_decision() {
    // The seam has no `Some(zero)` shape — the default is `None` — but
    // a `None`-named config and the plain default are the same decision
    // by construction; the gate pins that the knob's *absence* plans
    // the zero stacksize the pre-M18 layout wrote.
    let default = link_layout(|_| {});
    let bytes =
        &default.header_bytes[default.entryoff_at as usize + 8..default.entryoff_at as usize + 16];
    let mut raw = [0u8; 8];
    raw.copy_from_slice(bytes);
    assert_eq!(
        u64::from_le_bytes(raw),
        0,
        "the default reserve is the pre-M18 zero"
    );
}

// ---- the refusal -------------------------------------------------------------

#[test]
fn non_executable_outputs_refuse_the_knob() {
    // A dylib carries no `LC_MAIN` — the named reserve has no field to
    // land on. The layout refuses (the driver surface refuses earlier;
    // the library gate is the backstop every caller pays).
    let mut cfg = LinkConfig {
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libgreet.dylib".into()),
        stack_size: Some(StackSize::from_override(0x100_0000).expect("validates")),
        ..LinkConfig::default()
    };
    let err = link(&corpus(), &[], &cfg).expect_err("the knob refuses on a dylib");
    assert!(
        err.to_string().contains("LC_MAIN"),
        "the refusal names the shape: {err}"
    );
    cfg.filetype = OutputType::Bundle;
    let err = link(&corpus(), &[], &cfg).expect_err("the knob refuses on a bundle");
    assert!(
        err.to_string().contains("LC_MAIN"),
        "the refusal names the shape: {err}"
    );
}

#[test]
fn determinism_a_double_link_is_byte_identical() {
    let a = link_layout(|cfg| {
        cfg.stack_size = Some(StackSize::from_override(0x100_0000).expect("validates"));
    });
    let b = link_layout(|cfg| {
        cfg.stack_size = Some(StackSize::from_override(0x100_0000).expect("validates"));
    });
    assert_eq!(
        a.header_bytes, b.header_bytes,
        "TDD §4.3: identical headers"
    );
    assert_eq!(a.file_size, b.file_size);
}

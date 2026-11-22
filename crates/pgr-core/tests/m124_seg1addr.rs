//! M124 — the first segment's base address (`-seg1addr`): ld64's flag
//! ("Set the base address of the first segment") is the explicit
//! override of the constant-delta floor (the `__PAGEZERO` vmsize for
//! executables — M15; the `-image_base` vmaddr for dylibs — M19). The
//! default keeps the pre-M124 bytes (every executable already plans
//! `__TEXT` at `0x1_0000_0000`); the named decision shifts `__PAGEZERO`'s
//! vmsize and `__TEXT`'s vmaddr at once (the constant-delta contract
//! `vmaddr = fileoff + base` holds either way). Bundles refuse the knob
//! (the loader resolves the base) and the relocatable output refuses it
//! (no segments); one base knob per output kind means `-seg1addr` beside
//! `-image_base` names the same floor twice and the re-check refuses.
//!
//! Gate matrix:
//! * the default — an executable plans `__PAGEZERO.vmsize` and
//!   `__TEXT.vmaddr` at the 4 GiB constant (the pre-M124 shape), every
//!   pre-knob link byte-identical;
//! * the knob — a named `-seg1addr 0x40000000` shifts both words to the
//!   named floor (the constant-delta contract holds);
//! * the byte-identity lock — a `-seg1addr` naming the default floor
//!   plans byte-identical bytes to the pre-knob link;
//! * the refusals — a named `-seg1addr` on a bundle or the relocatable
//!   output is a layout error (the M15/M19 base-knob refusal shape,
//!   mirrored exactly so every caller pays it);
//! * the one-base-per-kind overlap — `-seg1addr` beside `-image_base`
//!   on a dylib names the same `__TEXT` floor twice and refuses;
//! * the lock — double-link determinism holds across the decision.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::seg1addr::Seg1Addr;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// A single-object corpus (`_main` exported) linkable as any kind.
fn corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    for (i, sym) in ["_main", "_lib_fn"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// Links the corpus with a config tweak and returns the header bytes.
fn link_header(tweak: impl FnOnce(&mut LinkConfig)) -> Vec<u8> {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(&corpus(), &[], &cfg)
        .expect("the corpus links")
        .layout
        .header_bytes
}

/// The `(vmaddr, vmsize)` of a named segment in the header bytes.
fn segment(header: &[u8], name: &str) -> (u64, u64) {
    let hdr = pgr_format::MachHeader64::parse(header).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        header,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands walk");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            if seg.name() == Ok(name) {
                return (seg.vmaddr, seg.vmsize);
            }
        }
    }
    panic!("the {name} segment is present");
}

#[test]
fn the_default_executable_plans_the_constant_delta_floor() {
    let header = link_header(|_| {});
    let (pz_vmaddr, pz_vmsize) = segment(&header, "__PAGEZERO");
    let (text_vmaddr, _) = segment(&header, "__TEXT");
    assert_eq!(pz_vmaddr, 0, "__PAGEZERO.vmaddr is always 0");
    assert_eq!(pz_vmsize, 0x1_0000_0000, "the pre-M124 4 GiB constant");
    assert_eq!(
        text_vmaddr, 0x1_0000_0000,
        "__TEXT.vmaddr == the constant-delta floor"
    );
}

#[test]
fn a_named_seg1addr_shifts_the_floor() {
    // The override shifts `__PAGEZERO.vmsize` and `__TEXT.vmaddr` at
    // once — the constant-delta contract holds (vmaddr = fileoff +
    // base; the override names the base).
    let header = link_header(|c| {
        c.seg1addr = Some(Seg1Addr::from_override(0x4000_0000).expect("validates"));
    });
    let (pz_vmaddr, pz_vmsize) = segment(&header, "__PAGEZERO");
    let (text_vmaddr, _) = segment(&header, "__TEXT");
    assert_eq!(pz_vmaddr, 0, "__PAGEZERO.vmaddr stays 0");
    assert_eq!(pz_vmsize, 0x4000_0000, "the named floor");
    assert_eq!(text_vmaddr, 0x4000_0000, "__TEXT.vmaddr == the named floor");
}

#[test]
fn a_named_seg1addr_at_the_default_plans_byte_identical_bytes() {
    // A `-seg1addr` naming the default floor (0x1_0000_0000) plans
    // byte-identical bytes to the pre-knob link — the override is the
    // default spelled out, never a layout product the bytes move on.
    let default = link_header(|_| {});
    let knobbed = link_header(|c| {
        c.seg1addr = Some(Seg1Addr::from_override(0x1_0000_0000).expect("validates"));
    });
    assert_eq!(
        knobbed, default,
        "the named-default face is the pre-knob shape"
    );
}

#[test]
fn a_named_seg1addr_shifts_a_dylib_text_vmaddr() {
    // A dylib carries no `__PAGEZERO` — the override names the
    // `__TEXT` vmaddr directly (the M19 `-image_base` shape, one base
    // knob over). The constant-delta contract holds.
    let mut cfg = LinkConfig {
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libm124.dylib".into()),
        seg1addr: Some(Seg1Addr::from_override(0x6_0000).expect("validates")),
        ..LinkConfig::default()
    };
    let _ = &mut cfg;
    let layout = link(&corpus(), &[], &cfg).expect("the dylib links");
    let (text_vmaddr, _) = segment(&layout.layout.header_bytes, "__TEXT");
    assert_eq!(
        text_vmaddr, 0x6_0000,
        "the dylib __TEXT.vmaddr == the named floor"
    );
}

#[test]
fn non_admitted_outputs_refuse_the_knob() {
    for (kind, label) in [
        (OutputType::Bundle, "bundle"),
        (OutputType::Relocatable, "relocatable"),
    ] {
        let cfg = LinkConfig {
            seg1addr: Some(Seg1Addr::from_override(0x4000_0000).expect("validates")),
            filetype: kind,
            ..LinkConfig::default()
        };
        let err = link(&corpus(), &[], &cfg).expect_err("the shape refuses");
        assert!(
            err.to_string().contains(label),
            "the refusal names the output kind ({label}): {err}"
        );
    }
}

#[test]
fn seg1addr_beside_image_base_refuses() {
    // One base knob per output kind: `-seg1addr` and `-image_base` both
    // name the dylib's `__TEXT` floor — the re-check refuses the pair
    // (the M19 overlap shape, one base over).
    let cfg = LinkConfig {
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libm124.dylib".into()),
        seg1addr: Some(Seg1Addr::from_override(0x6_0000).expect("validates")),
        image_base: Some(pgr_core::ImageBase::from_override(0x8_0000).expect("validates")),
        ..LinkConfig::default()
    };
    let err = link(&corpus(), &[], &cfg).expect_err("the overlap refuses");
    assert!(
        err.to_string().contains("one base knob"),
        "the refusal names the overlap: {err}"
    );
}

#[test]
fn the_decision_links_deterministically() {
    // Double-link determinism across the decision.
    let a = link_header(|c| {
        c.seg1addr = Some(Seg1Addr::from_override(0x4000_0000).expect("validates"));
    });
    let b = link_header(|c| {
        c.seg1addr = Some(Seg1Addr::from_override(0x4000_0000).expect("validates"));
    });
    assert_eq!(a, b, "the double link is stable");
}

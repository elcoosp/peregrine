//! M10 rung 5, slice 2 — the `x86_64` producer half: the pipeline
//! produces the second CPU family's image shape. Slice 1 gave the tree
//! the read side ("the verifier admits `CPU_TYPE_X86_64`, the page
//! gates read the family's 4 KiB page, the walk translates
//! `DYLD_CHAINED_PTR_64` rebase targets as VM addresses — TDD §15.8")
//! and named the next slice: "the producer half and the driver surface
//! are the rung's next slices". These gates pin the write side to the
//! words the verifier already walks — the plan's acceptance for the
//! rung, verbatim: *an `x86_64` image born at 4 KiB packing verifies
//! strict* (TDD §15.8 item 4), now born from the real Pass 1–3
//! pipeline instead of the fixtures.
//!
//! The contracts under test:
//!
//! * the produced header carries `CPU_TYPE_X86_64` /
//!   `CPU_SUBTYPE_X86_64_ALL` (the arm64 words are the default's, the
//!   family words are the named decision's);
//! * the produced packing rides the family page — 4 KiB segment
//!   congruence under `x86_64`, and the image verifies strict end to end
//!   (the pipeline → `pgr-emit` → `pgr-verify` pair, the slice-1 read
//!   side accepting the slice-2 write side);
//! * the fixup payload and the `__chain_starts` mirror name
//!   `DYLD_CHAINED_PTR_64` (format 2) under the `x86_64` family;
//! * the planner's `Format64` family composes rebase targets as VM
//!   addresses (the fixture builder's composition, one producer over),
//!   shares the `64_OFFSET` 4-byte strides and bind shape, and refuses
//!   the arm64e-only auth policy;
//! * the default path is untouched: `CpuFamily::Arm64` (explicit or
//!   default) plans byte-identical bytes — every pre-slice link;
//! * refusals name their cause: `arm64e` beside `x86_64`, and the
//!   Branch26 stub lane (the arm64 codegen the 4 KiB family cannot
//!   carry this rung) beside `x86_64`.

use pgr_core::cpu::CpuFamily;
use pgr_core::fixups::{
    FixupAuth, FixupKind, FixupPointerFormat, FixupSlot, plan_fixups_with_format,
};
use pgr_core::ids::StringId;
use pgr_core::interner::Interner;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{
    CPU_SUBTYPE_X86_64_ALL, CPU_TYPE_ARM64, CPU_TYPE_X86_64, DYLD_CHAINED_PTR_64, PAGE_SIZE_4K,
    PAGE_SIZE_16K,
};
use pgr_format::fixups::ChainWord64;
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SegmentCommand64};
use pgr_verify::{Options as VerifyOptions, verify};

const IMAGE_BASE: u64 = 0x1_0000_0000;
const TEXT_VM: u64 = IMAGE_BASE + 0x4000;
const PAGE_64: u64 = PAGE_SIZE_16K;

// ---- the pipeline corpus -------------------------------------------------------

/// One arm64 object whose content is pointer-shaped only: a `__data`
/// rebase slot against `_main` and a `_printf` GOT bind through the
/// dylib — the callsite shape `x86_64` emits natively (`call
/// *_printf@GOTPCREL(%rip)`), no Branch26 stub lane, so the family
/// carries it honestly. The instructions are the arm64 adrp/ldr pair
/// the arm64 inputs ride (the input surface stays arm64 this rung).
fn got_main() -> Vec<LinkInput> {
    let text: Vec<u8> = [
        0x9000_0000u32, // adrp x0, _printf@GOTPAGE
        0xF940_0000u32, // ldr x0, [x0, _printf@GOTPAGEOFF]
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("got_main.o");
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    let printf_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_printf".into(),
        weak_ref: false,
    });
    let main = b.sym_index(main_sym);
    let printf = b.sym_index(printf_sym);
    b.section_mut(sect).relocs = vec![
        ObjectReloc::got_page21(printf).at(0),
        ObjectReloc::got_pageoff12(printf).at(4),
    ];
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(main).at(0));
    vec![LinkInput {
        name: "got_main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// The dylib the GOT bind resolves against (the M106 helper's shape).
fn dylib() -> pgr_core::resolve::Dylib {
    pgr_core::resolve::Dylib {
        install_name: "/usr/lib/libSystem.B.dylib".into(),
        current_version: 0,
        compatibility_version: 0,
        exports: vec![b"_printf".to_vec()],
        weak: false,
        lazy: false,
        upward: false,
        reexport: false,
        needed: false,
        hidden: false,
    }
}

/// Links the corpus under `tweak`; returns the full Pass 1–3 result.
fn plan(tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::link::LinkResult {
    let cfg = LinkConfig {
        dylibs: vec![dylib()],
        ..LinkConfig::default()
    };
    let mut cfg = cfg;
    tweak(&mut cfg);
    link(&got_main(), &[], &cfg).expect("the link plans")
}

/// Emits the full image bytes (the Pass-4 shape the driver writes).
fn image(result: &pgr_core::link::LinkResult) -> Vec<u8> {
    pgr_emit::build_image(&result.layout, &result.objects).expect("the image emits")
}

/// One output segment's vmsize by name, read from the emitted image
/// (the plan → bytes agreement the pair gate rides).
fn segment_vmsize(image: &[u8], seg: &str) -> Option<u64> {
    let header = MachHeader64::parse(image).unwrap();
    let mut it =
        LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds).unwrap();
    while let Some(cmd) = it.next_command().unwrap() {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg_cmd = SegmentCommand64::parse(cmd.bytes, 0).unwrap();
            if seg_cmd.name().unwrap() == seg {
                return Some(seg_cmd.vmsize);
            }
        }
    }
    None
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// The `mach_header_64` cputype/subtype words (bytes 4..12).
fn cpu_words(header: &[u8]) -> (u32, u32) {
    (
        u32::from_le_bytes(header[4..8].try_into().expect("cputype")),
        u32::from_le_bytes(header[8..12].try_into().expect("cpusubtype")),
    )
}

// ---- the producer half ---------------------------------------------------------

#[test]
fn the_pipeline_produces_a_strict_x86_64_image() {
    // The plan's acceptance, verbatim (TDD §15.8 item 4): *an x86_64
    // image born at 4 KiB packing verifies strict* — born here from the
    // real pipeline, not the fixtures.
    let result = plan(|c| c.cpu = CpuFamily::X86_64);
    let bytes = image(&result);
    let report = verify(&bytes, &strict());
    assert!(
        report
            .issues
            .iter()
            .all(|i| i.severity != pgr_verify::Severity::Error),
        "the x86_64 image verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_producer_writes_the_family_header_words() {
    let header = plan(|c| c.cpu = CpuFamily::X86_64).layout.header_bytes;
    let (cputype, subtype) = cpu_words(&header);
    assert_eq!(
        cputype, CPU_TYPE_X86_64,
        "the family cputype rides the header"
    );
    assert_eq!(
        subtype, CPU_SUBTYPE_X86_64_ALL,
        "the family subtype rides the header"
    );
}

#[test]
fn the_family_packing_rides_4_kib_pages() {
    // The segment packing's page constant is the family's (TDD §15.8
    // item 3): a tiny __TEXT rounds to one 4 KiB page under x86_64,
    // one 16 KiB page under the arm64 default — read from the emitted
    // bytes, so the plan → image agreement rides the gate too.
    let x86e = image(&plan(|c| c.cpu = CpuFamily::X86_64));
    assert_eq!(
        segment_vmsize(&x86e, "__TEXT"),
        Some(PAGE_SIZE_4K),
        "the x86_64 packing rides the 4 KiB family page"
    );
    let arm64 = image(&plan(|c| c.cpu = CpuFamily::Arm64));
    assert_eq!(
        segment_vmsize(&arm64, "__TEXT"),
        Some(PAGE_SIZE_16K),
        "the arm64 packing rides the 16 KiB family page"
    );
}

#[test]
fn the_fixup_payload_names_the_64_family() {
    // The payload's `__chain_starts` mirror declares pointer format 2
    // under the x86_64 family (TDD §15.8 item 3: the walk's dispatch
    // key); the arm64 default stays format 6.
    let x86e = plan(|c| c.cpu = CpuFamily::X86_64);
    assert_eq!(
        x86e.layout.fixups.chain_word_format.pointer_format(),
        DYLD_CHAINED_PTR_64,
        "the family words declare format 2"
    );
    let arm64 = plan(|c| c.cpu = CpuFamily::Arm64);
    assert_ne!(
        arm64.layout.fixups.chain_word_format.pointer_format(),
        DYLD_CHAINED_PTR_64,
        "the default family stays off format 2"
    );
}

#[test]
fn the_arm64_default_is_byte_identical() {
    // Every pre-slice link: the default config and the explicit
    // `CpuFamily::Arm64` plan the same bytes (the seam is invisible
    // unless asked for).
    let default = plan(|_| ());
    let explicit = plan(|c| c.cpu = CpuFamily::Arm64);
    assert_eq!(
        image(&default),
        image(&explicit),
        "the explicit arm64 family is the pre-slice shape"
    );
    let (cputype, _) = cpu_words(&default.layout.header_bytes);
    assert_eq!(cputype, CPU_TYPE_ARM64, "the default header stays arm64");
}

// ---- the planner's Format64 family ---------------------------------------------

fn segments() -> Vec<(u64, u64, u64)> {
    vec![(TEXT_VM, PAGE_64, 0x4000)]
}

fn interner_with(names: &[&str]) -> (Interner, Vec<StringId>) {
    let owned: Vec<Vec<u8>> = names.iter().map(|n| n.as_bytes().to_vec()).collect();
    Interner::build(&owned)
}

fn rebase(vaddr: u64) -> FixupSlot {
    FixupSlot {
        vaddr,
        kind: FixupKind::Rebase {
            target_vaddr: vaddr,
        },
    }
}

fn word_at(plan: &pgr_core::FixupPlan, vaddr: u64) -> u64 {
    plan.slot_words
        .iter()
        .find(|(v, _)| *v == vaddr)
        .copied()
        .unwrap_or_else(|| panic!("no slot word at {vaddr:#x}"))
        .1
}

#[test]
fn format64_rebase_words_carry_vm_addresses() {
    // TDD §15.8 item 3: the 64 family shares the 64_OFFSET word layout
    // (same 4-byte strides) and composes the rebase target as a VM
    // address (`high8 << 56 | target` — the composition the slice-1
    // walk reads back).
    let (interner, _) = interner_with(&[]);
    let slot_vaddr = TEXT_VM + 0x100;
    let plan = plan_fixups_with_format(
        vec![rebase(slot_vaddr)],
        &segments(),
        IMAGE_BASE,
        PAGE_64,
        &interner,
        None,
        FixupPointerFormat::Format64,
    )
    .expect("the 64 family plans");
    let word = ChainWord64::new(word_at(&plan, slot_vaddr));
    let composed = (u64::from(word.rebase_high8()) << 56) | word.rebase_target();
    assert_eq!(
        composed, slot_vaddr,
        "the word carries the VM address the walk composes"
    );
    assert_eq!(plan.chain_word_format.pointer_format(), DYLD_CHAINED_PTR_64);
}

#[test]
fn format64_shares_the_offset64_stride_and_bind_shape() {
    let (interner, ids) = interner_with(&["_printf"]);
    let slots = vec![
        rebase(TEXT_VM + 0x100),
        rebase(TEXT_VM + 0x110),
        FixupSlot {
            vaddr: TEXT_VM + 0x200,
            kind: FixupKind::Bind {
                lib_ordinal: 1,
                name: ids[0],
                addend: 0x20,
                weak: false,
            },
        },
    ];
    let fmt64 = plan_fixups_with_format(
        slots.clone(),
        &segments(),
        IMAGE_BASE,
        PAGE_64,
        &interner,
        None,
        FixupPointerFormat::Format64,
    )
    .expect("the 64 family plans");
    let offset64 = plan_fixups_with_format(
        slots,
        &segments(),
        IMAGE_BASE,
        PAGE_64,
        &interner,
        None,
        FixupPointerFormat::Offset64,
    )
    .expect("the default family plans");
    // Same strides: the `next` fields match slot for slot (4-byte units).
    for (vaddr, _) in &fmt64.slot_words {
        let a = ChainWord64::new(word_at(&fmt64, *vaddr)).next();
        let b = ChainWord64::new(word_at(&offset64, *vaddr)).next();
        assert_eq!(a, b, "the 64 family counts the same 4-byte strides");
    }
    // The bind word shape is the 64_OFFSET shape (24-bit ordinal, 8-bit
    // inline addend) — only the rebase composition differs.
    let bind_vaddr = TEXT_VM + 0x200;
    let bind64 = ChainWord64::new(word_at(&fmt64, bind_vaddr));
    assert!(
        bind64.is_bind(),
        "the bind rides the shared bind discriminator"
    );
    assert_eq!(bind64.bind_ordinal(), 0);
    assert_eq!(bind64.bind_addend(), 0x20);
    // Same import table in both families (the declared format is a
    // separate payload field).
    assert_eq!(fmt64.imports.len(), offset64.imports.len());
}

#[test]
fn format64_refuses_a_target_across_the_field_gap() {
    // Bits 36..56 of the VM address have no field to ride in (the word
    // jumps from the 36-bit target to the high8 top byte) — a target
    // that lands there refuses instead of silently truncating (the
    // fixture builder's refusal, one producer over).
    let (interner, _) = interner_with(&[]);
    let slot_vaddr = TEXT_VM + 0x100;
    let target = IMAGE_BASE + (1u64 << 40); // bit 40: inside the gap
    let plan = plan_fixups_with_format(
        vec![FixupSlot {
            vaddr: slot_vaddr,
            kind: FixupKind::Rebase {
                target_vaddr: target,
            },
        }],
        &segments(),
        IMAGE_BASE,
        PAGE_64,
        &interner,
        None,
        FixupPointerFormat::Format64,
    );
    let err = plan.expect_err("the field-gap target refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("field gap") || msg.contains("no field"),
        "the refusal names the field gap: {msg}"
    );
}

#[test]
fn the_auth_policy_refuses_under_the_64_family() {
    // The auth shapes are arm64e-only (TDD §15.4's rule, one family
    // over): a signed slot under the 64 family refuses at plan time.
    let (interner, _) = interner_with(&[]);
    let slot_vaddr = TEXT_VM + 0x100;
    let err = plan_fixups_with_format(
        vec![rebase(slot_vaddr)],
        &segments(),
        IMAGE_BASE,
        PAGE_64,
        &interner,
        None,
        FixupPointerFormat::Format64,
    )
    .and_then(|_| {
        // The planner entry carries no auth policy; the auth planner
        // (slice 3's seam) is the refusal's home.
        pgr_core::fixups::plan_fixups_with_auth(
            vec![rebase(slot_vaddr)],
            &segments(),
            IMAGE_BASE,
            PAGE_64,
            &interner,
            None,
            FixupPointerFormat::Format64,
            &[FixupAuth {
                vaddr: slot_vaddr,
                key: 2,
                diversity: 0,
                addr_div: false,
            }],
        )
    })
    .expect_err("the auth policy refuses under the 64 family");
    let msg = err.to_string();
    assert!(
        msg.contains("arm64e"),
        "the refusal names the arm64e-only shapes: {msg}"
    );
}

// ---- the refusals ---------------------------------------------------------------

#[test]
fn arm64e_family_refuses_beside_x86_64() {
    // The arm64e word family is the arm64 CPU's (TDD §15.4): the
    // combination refuses with both names in the message.
    let err = link(
        &got_main(),
        &[],
        &LinkConfig {
            cpu: CpuFamily::X86_64,
            chain_word_format: FixupPointerFormat::Arm64e,
            dylibs: vec![dylib()],
            ..LinkConfig::default()
        },
    )
    .expect_err("the family combination refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("arm64e") && msg.contains("x86_64"),
        "the refusal names both families: {msg}"
    );
}

#[test]
fn the_branch26_stub_lane_refuses_under_x86_64() {
    // The `__stubs`/`__objc_stubs` lanes emit arm64 machine code (TDD
    // §3.4's stub shapes); the 4 KiB family carries no x86_64 stub
    // words this rung, so a Branch26 callsite refuses with the fix —
    // the GOT-indirect call x86_64 clang emits.
    let mut b = ObjectBuilder::new("stub_main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0x14u8, 0x00, 0x00, 0x94].to_vec(),
        vec![],
    ));
    let printf_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_printf".into(),
        weak_ref: false,
    });
    let printf = b.sym_index(printf_sym);
    b.section_mut(text).relocs = vec![ObjectReloc::branch26(printf).at(0)];
    let corpus = vec![LinkInput {
        name: "stub_main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }];
    let err = link(
        &corpus,
        &[],
        &LinkConfig {
            cpu: CpuFamily::X86_64,
            dylibs: vec![dylib()],
            ..LinkConfig::default()
        },
    )
    .expect_err("the stub lane refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("x86_64") && (msg.contains("GOT") || msg.contains("got")),
        "the refusal names the GOT-indirect fix: {msg}"
    );
}

#[test]
fn the_x86_64_dylib_link_verifies_strict() {
    // The family rides the non-executable shapes too (the slice-1
    // read side admitted a 4 KiB dylib base): a dylib at the family
    // packing verifies strict end to end.
    let result = link(
        &got_main(),
        &[],
        &LinkConfig {
            filetype: OutputType::Dylib,
            install_name: Some("@rpath/libx86e.dylib".into()),
            cpu: CpuFamily::X86_64,
            dylibs: vec![dylib()],
            ..LinkConfig::default()
        },
    )
    .expect("the dylib plans");
    let bytes = image(&result);
    let report = verify(&bytes, &strict());
    assert!(
        report
            .issues
            .iter()
            .all(|i| i.severity != pgr_verify::Severity::Error),
        "the x86_64 dylib verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_relocatable_output_refuses_the_family() {
    // The `-r` object's header is the input's, verbatim (the M10
    // rung-1 contract) — an x86_64 family decision would claim a
    // family the object cannot carry, so the re-check refuses (the
    // M125 pattern, one header word over).
    let err = pgr_core::link::link_reloc(
        &got_main(),
        &[],
        &LinkConfig {
            filetype: OutputType::Relocatable,
            cpu: CpuFamily::X86_64,
            dylibs: vec![dylib()],
            ..LinkConfig::default()
        },
        pgr_core::link::Parallelism::Auto,
    )
    .expect_err("the relocatable output refuses the family");
    let msg = err.to_string();
    assert!(
        msg.contains("x86_64") && msg.contains("relocatable"),
        "the refusal names the shape conflict: {msg}"
    );
}

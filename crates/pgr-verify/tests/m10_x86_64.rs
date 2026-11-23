//! M10 rung 5, slice 1 — the `x86_64` read side. The plan line this gate
//! matrix pins is the architecture doc's M10 row scope: "`x86_64` macOS
//! (4 KiB constants, same tree)" (docs/peregrine-performance-architecture-
//! and-roadmap.md §10.4, row M10; the slice record is TDD §15.8). Before
//! the slice the verifier refused the family outright (`cputype 0x1000007
//! is not CPU_TYPE_ARM64`), so an `x86_64` image could not pass `--strict`
//! at all, and the chain walk read every non-arm64e word as a `64_OFFSET`
//! image offset — the `DYLD_CHAINED_PTR_64` family's VM-address rebase
//! targets had no honest reader.
//!
//! Acceptance: an `x86_64` chained executable born at 4 KiB packing through
//! the builder's `CpuKind` knob verifies strict end to end; the format-2
//! walk translates rebase targets the way dyld reads them (VM addresses,
//! a target below the image base refuses with the slot named); every
//! page-contract gate reads the family's page (4 KiB packing and a
//! 4-KiB-multiple base verify, the 16 KiB controls refuse); the
//! `64_OFFSET` semantics stay byte-for-byte (the M2 lock).

use pgr_fixtures::{
    CpuKind, Image, ImageBuilder, PointerFormatKind, SectionSpec, SegmentSpec, SlotKind,
    SymbolSpec, filler,
};
use pgr_format::consts::{
    PLATFORM_MACOS, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
    VM_PROT_WRITE,
};
use pgr_format::fixups::{ChainWord64, parse_header, parse_imports, parse_starts_in_image};
use pgr_verify::{Options, Severity, verify};

fn strict() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// Signature recompute off: mutation tests patch bytes post-build, so the
/// stale page hashes would drown the chain findings being pinned.
fn structural_only() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: true,
    }
}

fn text_segment(bytes_len: usize) -> SegmentSpec {
    SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xA5A5, bytes_len),
            relocs: Vec::new(),
        }],
    }
}

fn data_const_segment() -> SegmentSpec {
    SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    }
}

/// An `x86_64` chained executable born through the builder's CPU knob: one
/// VM-address rebase (into `__text`) and one bind (the import), packed at
/// the family's 4 KiB page, at the macOS chained-fixups floor.
fn x86e_chained_exec() -> Image {
    let mut b = ImageBuilder::executable("x86e-gate");
    b.set_cputype(CpuKind::X86_64);
    b.set_pointer_format(PointerFormatKind::Format64);
    b.add_segment(text_segment(96));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![
        SlotKind::Rebase { target: 0x40 },
        SlotKind::Bind {
            sym_index: sym,
            addend: 0,
        },
    ]);
    b.set_entry(0x40);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    b.build().expect("the x86_64 fixture builds")
}

/// The arm64 `64_OFFSET` control: the same shape in the M2 family, the
/// semantics the slice must not move.
fn offset64_control() -> Image {
    let mut b = ImageBuilder::executable("offset64-control");
    b.set_pointer_format(PointerFormatKind::Offset64);
    b.add_segment(text_segment(96));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![
        SlotKind::Rebase { target: 0x40 },
        SlotKind::Bind {
            sym_index: sym,
            addend: 0,
        },
    ]);
    b.set_entry(0x40);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    b.build().expect("the control fixture builds")
}

/// The `LC_SEGMENT_64` command bytes for a named segment (a raw
/// load-command walk, not a string scan — section names repeat in the
/// file's other structures).
fn segment_cmd(img: &Image, name: &str) -> (u64, u64) {
    let bytes = &img.bytes;
    let ncmds = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    let mut at = 32usize;
    let mut segname = [0u8; 16];
    segname[..name.len()].copy_from_slice(name.as_bytes());
    for _ in 0..ncmds {
        let cmd = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let size = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if cmd == 0x19 && bytes[at + 8..at + 24] == segname {
            // LC_SEGMENT_64: vmaddr at +24, fileoff at +40.
            let vmaddr = u64::from_le_bytes(bytes[at + 24..at + 32].try_into().unwrap());
            let fileoff = u64::from_le_bytes(bytes[at + 40..at + 48].try_into().unwrap());
            return (vmaddr, fileoff);
        }
        at += size;
    }
    panic!("no {name} segment command");
}

/// The raw fixup payload: (header, imports, starts) for a built image.
fn fixup_payload(img: &Image) -> (Vec<u8>, u32) {
    let bytes = &img.bytes;
    // Scan the load commands for LC_DYLD_CHAINED_FIXUPS (cmd 0x26 | 0x8000_0000).
    let ncmds = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    let mut at = 32usize;
    for _ in 0..ncmds {
        let cmd = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let size = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if cmd == 0x8000_0034 {
            let off = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
            let len = u32::from_le_bytes(bytes[at + 12..at + 16].try_into().unwrap()) as usize;
            return (bytes[off..off + len].to_vec(), cmd);
        }
        at += size;
    }
    panic!("the fixture carries no LC_DYLD_CHAINED_FIXUPS");
}

fn issues_matching<'a>(report: &'a pgr_verify::Report, needle: &str) -> Vec<&'a pgr_verify::Issue> {
    report
        .issues
        .iter()
        .filter(|i| i.message.contains(needle))
        .collect()
}

#[test]
fn x86_64_chains_verify_strict() {
    let img = x86e_chained_exec();
    let report = verify(&img.bytes, &strict());
    assert!(
        report.is_ok(&strict()) && report.issues.is_empty(),
        "the x86_64 image must verify strict (the M10 row admits the family): {:#?}",
        report.issues
    );
    assert_eq!(report.stats.fixup_slots, 2, "both slots counted");
}

#[test]
fn x86_64_payload_page_size_is_the_family_page() {
    let img = x86e_chained_exec();
    let (payload, _) = fixup_payload(&img);
    let hdr = parse_header(&payload).expect("the payload header parses");
    let starts = parse_starts_in_image(&payload, hdr.starts_offset as usize)
        .expect("starts-in-image parses");
    let mut seen = Vec::new();
    for &off in &starts.seg_info_offset {
        if off == 0 {
            continue;
        }
        let rec = hdr.starts_offset as usize + off as usize;
        let seg = pgr_format::fixups::parse_starts_in_segment(&payload, rec)
            .expect("starts-in-segment parses");
        seen.push(seg.page_size);
    }
    assert_eq!(
        seen,
        vec![0x1000],
        "the payload's per-segment page_size is the x86_64 family's 4 KiB page"
    );
}

#[test]
fn x86_64_packing_is_4_kib_not_16_kib() {
    let img = x86e_chained_exec();
    // The `__DATA_CONST` segment rides the first 4 KiB page boundary after
    // `__TEXT` — under the old 16 KiB packing it would ride 0x4000.
    let (vmaddr, fileoff) = segment_cmd(&img, "__DATA_CONST");
    assert_eq!(fileoff % 0x1000, 0, "fileoff is 4 KiB aligned");
    assert_eq!(
        vmaddr.wrapping_sub(fileoff) % 0x4000,
        0,
        "the constant delta stays page-multiple"
    );
    assert_ne!(
        fileoff % 0x4000,
        0,
        "the second segment lands inside the first 16 KiB page — 4 KiB packing, not the old constant"
    );
}

#[test]
fn format64_rebase_walks_as_a_vm_address() {
    let img = x86e_chained_exec();
    // The honest word: the rebase slot's composed value is a VM address
    // above the 4 GiB image base; the walk translates `vmaddr - base` and
    // admits it.
    let got = img
        .map
        .sections
        .iter()
        .find(|s| s.name == "__got")
        .expect("the __got section is placed");
    let raw = u64::from_le_bytes(
        img.bytes[got.fileoff as usize..got.fileoff as usize + 8]
            .try_into()
            .unwrap_or([0; 8]),
    );
    let word = ChainWord64::new(raw);
    assert!(!word.is_bind(), "slot 0 is the rebase");
    let composed = (u64::from(word.rebase_high8()) << 56) | word.rebase_target();
    assert_eq!(
        composed, 0x1_0000_0040,
        "the word composes to the VM address (target 0x40 + the 4 GiB base)"
    );
}

#[test]
fn format64_rebase_below_the_image_base_refuses_with_the_slot_named() {
    let mut img = x86e_chained_exec();
    let got = img
        .map
        .sections
        .iter()
        .find(|s| s.name == "__got")
        .expect("the __got section is placed")
        .clone();
    // Rewrite the rebase target to a VM address below the image base: the
    // composition dyld reads names no real content.
    let raw = u64::from_le_bytes(
        img.bytes[got.fileoff as usize..got.fileoff as usize + 8]
            .try_into()
            .unwrap_or([0; 8]),
    );
    let broken = (raw & !0x000f_ffff_ffff) | 0x10;
    img.bytes[got.fileoff as usize..got.fileoff as usize + 8]
        .copy_from_slice(&broken.to_le_bytes());
    let report = verify(&img.bytes, &structural_only());
    let hits = issues_matching(&report, "below the image base");
    assert!(
        !hits.is_empty(),
        "the walk must refuse a format-2 rebase target below the image base \
         (the arm64e unauth shape's refusal, one family over): {:#?}",
        report.issues
    );
}

#[test]
fn offset64_control_semantics_unchanged() {
    let img = offset64_control();
    let report = verify(&img.bytes, &strict());
    assert!(
        report.is_ok(&strict()) && report.issues.is_empty(),
        "the 64_OFFSET control verifies strict (the M2 walk, byte-for-byte): {:#?}",
        report.issues
    );
}

#[test]
fn x86_64_dylib_at_a_4_kib_base_verifies_strict() {
    // A dylib born at a 4 KiB-multiple, non-16-KiB-multiple image base —
    // the shape only the family's page contract admits.
    let mut b = ImageBuilder::dylib("/usr/lib/libx86e.dylib", "x86e-dylib");
    b.set_cputype(CpuKind::X86_64);
    b.set_pointer_format(PointerFormatKind::Format64);
    b.set_image_base(0x1000);
    b.add_segment(text_segment(64));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![
        SlotKind::Rebase { target: 0x40 },
        SlotKind::Bind {
            sym_index: sym,
            addend: 0,
        },
    ]);
    b.add_symbol(SymbolSpec::Defined {
        name: "_x86e_export".into(),
        section_index: 0,
    });
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    let img = b.build().expect("the 4 KiB-base dylib builds");
    let report = verify(&img.bytes, &strict());
    assert!(
        report.is_ok(&strict()) && report.issues.is_empty(),
        "a 4 KiB-multiple base is a multiple of the x86_64 family page: {:#?}",
        report.issues
    );
}

#[test]
fn arm64_control_still_requires_the_16_kib_base() {
    // The arm64 face of the base gate reads its own family page — the
    // 4 KiB-multiple base refuses there exactly as before.
    let mut b = ImageBuilder::dylib("/usr/lib/libarm.dylib", "arm-dylib");
    b.set_image_base(0x1000);
    b.add_segment(text_segment(64));
    b.add_segment(data_const_segment());
    b.add_symbol(SymbolSpec::Defined {
        name: "_arm_export".into(),
        section_index: 0,
    });
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    let img = b.build().expect("the arm64 fixture builds");
    let report = verify(&img.bytes, &structural_only());
    assert!(
        !issues_matching(&report, "16 KiB").is_empty(),
        "the arm64 base gate keeps its 16 KiB contract: {:#?}",
        report.issues
    );
}

#[test]
fn stack_size_gate_reads_the_family_page() {
    // 0x3000 is a 4 KiB multiple and no 16 KiB multiple: admitted for the
    // x86_64 family, refused for arm64 (the M18 contract, per-family).
    let mut b = ImageBuilder::executable("x86e-stack");
    b.set_cputype(CpuKind::X86_64);
    b.set_pointer_format(PointerFormatKind::Format64);
    b.set_stack_size(0x3000);
    b.add_segment(text_segment(96));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![SlotKind::Bind {
        sym_index: sym,
        addend: 0,
    }]);
    b.set_entry(0x40);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    let img = b.build().expect("the stack fixture builds");
    let report = verify(&img.bytes, &strict());
    assert!(
        issues_matching(&report, "stacksize").is_empty(),
        "a 4 KiB-multiple stack reserve is a multiple of the x86_64 page: {:#?}",
        report.issues
    );

    let mut a = ImageBuilder::executable("arm-stack");
    a.set_stack_size(0x3000);
    a.add_segment(text_segment(96));
    a.add_segment(data_const_segment());
    let ord = a.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = a.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    a.set_got(vec![SlotKind::Bind {
        sym_index: sym,
        addend: 0,
    }]);
    a.set_entry(0x40);
    a.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    let img = a.build().expect("the arm stack fixture builds");
    let report = verify(&img.bytes, &structural_only());
    assert!(
        !issues_matching(&report, "stacksize").is_empty(),
        "the arm64 stack gate keeps its 16 KiB contract: {:#?}",
        report.issues
    );
}

#[test]
fn hand_broken_cpu_family_is_named() {
    // An unknown cputype names the admitted set (the gate's honest face).
    let mut img = x86e_chained_exec();
    img.bytes[4..8].copy_from_slice(&0x0100_0009u32.to_le_bytes());
    let report = verify(&img.bytes, &structural_only());
    let hits = issues_matching(&report, "cputype");
    assert!(
        hits.iter()
            .any(|i| i.message.contains("CPU_TYPE_X86_64") && i.message.contains("CPU_TYPE_ARM64")),
        "the cputype gate names the families it admits: {:#?}",
        report.issues
    );

    // A cpusubtype outside the x86_64 "all" constant warns, named.
    let mut img = x86e_chained_exec();
    img.bytes[8..12].copy_from_slice(&0x0000_0084u32.to_le_bytes());
    let report = verify(&img.bytes, &structural_only());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.severity == Severity::Warning && i.message.contains("cpusubtype")),
        "the subtype gate reads the family's own ALL constant: {:#?}",
        report.issues
    );
    let strict_report = verify(&img.bytes, &strict());
    assert!(
        !strict_report.is_ok(&strict()),
        "strict warnings fail the pass"
    );
}

#[test]
fn segment_congruence_gate_names_the_family_page() {
    // Break the congruence by a 4 KiB quantum (a multiple of neither the
    // family page nor anything else): the finding names the x86_64 page.
    let mut img = x86e_chained_exec();
    // Walk the load commands for the __DATA_CONST command's vmaddr field.
    let bytes = &img.bytes;
    let ncmds = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    let mut at = 32usize;
    let mut segname = [0u8; 16];
    segname[..12].copy_from_slice(b"__DATA_CONST");
    let mut cmd_at = None;
    for _ in 0..ncmds {
        let cmd = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let size = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if cmd == 0x19 && bytes[at + 8..at + 24] == segname {
            cmd_at = Some(at + 24);
            break;
        }
        at += size;
    }
    let field_at = cmd_at.expect("the __DATA_CONST segment command is present");
    let mut vmaddr = u64::from_le_bytes(bytes[field_at..field_at + 8].try_into().unwrap_or([0; 8]));
    vmaddr += 0x800;
    img.bytes[field_at..field_at + 8].copy_from_slice(&vmaddr.to_le_bytes());
    let report = verify(&img.bytes, &structural_only());
    assert!(
        !issues_matching(&report, "4 KiB").is_empty(),
        "the congruence gate reads the family page and names it: {:#?}",
        report.issues
    );
}

#[test]
fn auth_slots_refuse_under_the_64_family() {
    let mut b = ImageBuilder::executable("x86e-auth");
    b.set_cputype(CpuKind::X86_64);
    b.set_pointer_format(PointerFormatKind::Format64);
    b.add_segment(text_segment(96));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![SlotKind::AuthBind {
        sym_index: sym,
        diversity: 0x1234,
        addr_div: false,
        key: 0,
    }]);
    let err = b.build().expect_err("auth shapes refuse outside arm64e");
    assert!(
        err.0.contains("arm64e pointer format"),
        "the refusal names the family that owns the auth shapes: {err}"
    );
    // The payload the honest shape carries is the family the imports
    // decode against (a sanity read through the shared parser).
    let img = x86e_chained_exec();
    let (payload, _) = fixup_payload(&img);
    let hdr = parse_header(&payload).expect("the payload header parses");
    let imports = parse_imports(&payload, &hdr).expect("imports parse");
    assert_eq!(imports.len(), 1, "one import (the bind's dylib symbol)");
}

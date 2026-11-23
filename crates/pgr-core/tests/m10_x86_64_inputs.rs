//! M10 rung 5, slice 3 — the `x86_64` input surface: the Pass-1 read side
//! rides the CPU family. Slices 1–2 gave the tree the read side ("the
//! verifier admits `CPU_TYPE_X86_64` … — TDD §15.8") and the producer
//! half (`pgr_core::cpu::CpuFamily` on `LinkConfig` — TDD §15.9), and
//! slice 2's design record named the remaining half: *"The input
//! surface stays arm64 this rung (slice 1's honesty, unchanged) — the
//! family shapes the image contract"* (TDD §15.9). This slice flips
//! that line: the input surface rides the family — an `x86_64` object
//! parses, decodes its own relocation alphabet, and links end to end
//! under `-arch x86_64`, while the arm64 default keeps every pre-slice
//! link byte-identical (a foreign input refuses with the fix named).
//!
//! The honesty line rides with it (the slice-1/2 premise): the corpora
//! are pointer-shaped content the family carries honestly — absolute
//! pointer slots (chained fixups), GOT-indirect binds (the call shape
//! the slice-2 record named: `*_sym@GOTPCREL(%rip)` needs no stub
//! lane), rip-relative internal references, subtractor pairs, TLV
//! descriptor loads — and the forms the family cannot carry honestly
//! refuse with the type named (external branches and rip-relative
//! references to dylib exports — ld64 synthesizes a stub lane
//! Peregrine does not carry for `x86_64`; the `SIGNED_1/2/4` addend
//! correction family).

use pgr_core::cpu::CpuFamily;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_fixtures::{CpuKind, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{CPU_TYPE_ARM64, CPU_TYPE_X86_64, DYLD_CHAINED_PTR_64};
use pgr_format::fixups::ChainWord64;
use pgr_format::header::MachHeader64;
use pgr_format::{LoadCommandIter, LoadCommandKind, SegmentCommand64};
use pgr_verify::{Options as VerifyOptions, verify};

// ---- the pointer-shaped `x86_64` corpus ----------------------------------------

/// One `x86_64` object, every reference the family carries honestly:
///
/// * `movq _printf@GOTPCREL(%rip), %rax` — the GOT-indirect dylib call
///   the slice-2 record named ("the GOT-indirect call `x86_64` clang
///   emits needs no stub lane");
/// * `lea _local(%rip), %rax` / `call _local` — rip-relative internal
///   references (the `SIGNED`/`BRANCH` disp32 forms);
/// * `movq _x@TLVP(%rip), %rax` — the M37 TLV descriptor load, one
///   family over;
/// * an 8-byte `__data` pointer slot to `_main` (the chained-fixup
///   food) and a subtractor pair (`_delta_end - _delta_start`).
fn x86_main() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("x86e_main.o").set_cputype(CpuKind::X86_64);
    // __text: movq GOT | lea | call | movq TLVP | ret
    let text: Vec<u8> = [
        &[0x48u8, 0x8B, 0x05, 0xFC, 0xFF, 0xFF, 0xFF][..], // movq _printf@GOTPCREL(%rip)
        &[0x48, 0x8D, 0x05, 0xFC, 0xFF, 0xFF, 0xFF],       // lea _local(%rip)
        &[0xE8, 0xFC, 0xFF, 0xFF, 0xFF],                   // call _local
        &[0x48, 0x8B, 0x05, 0xFC, 0xFF, 0xFF, 0xFF],       // movq _x@TLVP(%rip)
        &[0xC3],                                           // ret
    ]
    .concat();
    let text_sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let data_sect = b.add_section(ObjectSection::data("__data", vec![0u8; 32], Vec::new()));
    let tv_sect = b.add_section(ObjectSection::thread_vars(vec![0u8; 16], Vec::new()));
    // The descriptors' initializer data (the M37 contract: a descriptor
    // with nothing to point at refuses read-side).
    b.add_section(ObjectSection::thread_data(vec![0u8; 16]));

    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text_sect,
        value: 0,
        weak: false,
    });
    let local_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_local".into(),
        section_index: text_sect,
        value: 7,
        weak: false,
    });
    let start_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_delta_start".into(),
        section_index: data_sect,
        value: 0,
        weak: false,
    });
    let end_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_delta_end".into(),
        section_index: data_sect,
        value: 8,
        weak: false,
    });
    let tlv_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_x".into(),
        section_index: tv_sect,
        value: 0,
        weak: false,
    });
    let printf_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_printf".into(),
        weak_ref: false,
    });

    // __text relocations: the disp32 sits at the last 4 bytes of each
    // instruction; the in-situ field is the clang placeholder (−4).
    b.section_mut(text_sect).relocs = vec![
        ObjectReloc::x86_got_load(b.sym_index(printf_sym)).at(3),
        ObjectReloc::x86_signed(b.sym_index(local_sym)).at(10),
        ObjectReloc::x86_branch(b.sym_index(local_sym)).at(15),
        ObjectReloc::x86_tlv(b.sym_index(tlv_sym)).at(22),
    ];
    // __data: the pointer slot (chained rebase) and the subtractor pair
    // (the x86_64 pairing order — SUBTRACTOR names the subtrahend, the
    // paired UNSIGNED names the minuend).
    b.section_mut(data_sect).relocs = vec![
        ObjectReloc::x86_unsigned(b.sym_index(main_sym)).at(0),
        ObjectReloc::x86_subtractor(b.sym_index(start_sym)).at(16),
        ObjectReloc::x86_unsigned(b.sym_index(end_sym)).at(16),
    ];
    vec![LinkInput {
        name: "x86e_main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

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

fn plan(tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::link::LinkResult {
    let mut cfg = LinkConfig {
        dylibs: vec![dylib()],
        ..LinkConfig::default()
    };
    tweak(&mut cfg);
    link(&x86_main(), &[], &cfg).expect("the link plans")
}

fn image(result: &pgr_core::link::LinkResult) -> Vec<u8> {
    pgr_emit::build_image(&result.layout, &result.objects).expect("the image emits")
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// One output section's bytes by name, read from the emitted image.
fn section_bytes(image: &[u8], seg: &str, sect: &str) -> Option<(u64, Vec<u8>)> {
    let header = MachHeader64::parse(image).ok()?;
    let mut it =
        LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds).ok()?;
    while let Some(cmd) = it.next_command().ok()? {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg_cmd = SegmentCommand64::parse(cmd.bytes, 0).ok()?;
            if seg_cmd.name().ok()? != seg {
                continue;
            }
            for s in seg_cmd.sections(cmd.bytes, SegmentCommand64::SIZE).ok()? {
                if s.name().ok()? == sect {
                    let start = s.offset as usize;
                    let size = s.size as usize;
                    let bytes = image.get(start..start + size)?.to_vec();
                    return Some((s.addr, bytes));
                }
            }
        }
    }
    None
}

fn disp32_at(bytes: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(bytes[at..at + 4].try_into().expect("the disp32 field"))
}

// ---- the input surface ---------------------------------------------------------

#[test]
fn the_x86_64_input_links_and_verifies_strict() {
    // The plan's acceptance, verbatim (TDD §15.9): *"The input surface
    // stays arm64 this rung"* — flipped: an x86_64-typed object parses,
    // decodes its own alphabet, and links end to end under `-arch
    // x86_64` into an image the slice-1 read side verifies strict.
    let result = plan(|c| c.cpu = CpuFamily::X86_64);
    let bytes = image(&result);
    let report = verify(&bytes, &strict());
    assert!(
        report
            .issues
            .iter()
            .all(|i| i.severity != pgr_verify::Severity::Error),
        "the x86_64 input verifies strict: {:?}",
        report.issues
    );
    let (cputype, _) = (
        u32::from_le_bytes(bytes[4..8].try_into().expect("cputype")),
        u32::from_le_bytes(bytes[8..12].try_into().expect("subtype")),
    );
    assert_eq!(cputype, CPU_TYPE_X86_64, "the family image carries x86_64");
}

#[test]
fn the_pointer_slot_rides_the_chained_rebase() {
    // The `__data` pointer slot is the chained-fixup food: under the
    // x86_64 family the payload declares `DYLD_CHAINED_PTR_64` and the
    // slot word composes the VM address (the slice-2 record's
    // composition), read back through the same word reader the walk
    // uses.
    let result = plan(|c| c.cpu = CpuFamily::X86_64);
    assert_eq!(
        result.layout.fixups.chain_word_format.pointer_format(),
        DYLD_CHAINED_PTR_64,
        "the family payload declares format 2"
    );
    let bytes = image(&result);
    let (_, data) = section_bytes(&bytes, "__DATA", "__data").expect("the __data section emits");
    let (text_base, _) =
        section_bytes(&bytes, "__TEXT", "__text").expect("the __text section emits");
    let word = ChainWord64::new(u64::from_le_bytes(
        data[0..8].try_into().expect("the slot word"),
    ));
    let composed = (u64::from(word.rebase_high8()) << 56) | word.rebase_target();
    assert_eq!(
        composed, text_base,
        "the slot word carries _main's VM address"
    );
}

#[test]
fn the_rip_relative_internal_references_patch_disp32() {
    // The SIGNED/BRANCH disp32 forms patch `S + embedded − P` (the
    // Mach-O x86_64 algebra: the in-situ field reconstructs the addend,
    // `embedded + 4`, and the pcrel base is the site + 4). `_local`
    // sits 7 bytes into __text, so the lea at 10 reads −7 and the call
    // at 15 reads −12.
    let result = plan(|c| c.cpu = CpuFamily::X86_64);
    let (text_base, text) =
        section_bytes(&image(&result), "__TEXT", "__text").expect("the __text section emits");
    assert_eq!(disp32_at(&text, 10), -7, "the lea patches _local");
    assert_eq!(disp32_at(&text, 15), -12, "the call patches _local");
    let _ = text_base;
}

#[test]
fn the_got_load_patches_a_disp32_to_the_slot() {
    // The GOT-indirect bind rides the synthesized `__DATA_CONST,__got`
    // slot: the callsite's disp32 names the slot (the bind travels in
    // the slot's chained word, not the callsite).
    let result = plan(|c| c.cpu = CpuFamily::X86_64);
    let bytes = image(&result);
    let (text_base, text) =
        section_bytes(&bytes, "__TEXT", "__text").expect("the __text section emits");
    let (got_base, got) =
        section_bytes(&bytes, "__DATA_CONST", "__got").expect("the __got section emits");
    assert!(!got.is_empty(), "the GOT slot synthesizes");
    let site = text_base + 3;
    let expected = (got_base as i64) - (site as i64) - 4;
    assert_eq!(
        i64::from(disp32_at(&text, 3)),
        expected,
        "the GOT load names the slot"
    );
    // The slot's chained word is a bind to _printf (the ordinal rides
    // the two-level table), not a rebase.
    let word = ChainWord64::new(u64::from_le_bytes(got[0..8].try_into().expect("slot word")));
    assert!(word.is_bind(), "the slot binds through the two-level space");
}

#[test]
fn the_subtractor_pair_writes_the_difference() {
    // `long delta = &_delta_end − &_delta_start` — the pair lands as a
    // static 8-byte patch (not a chained slot): the emitted bytes carry
    // the placed difference (8: the two symbols' __data values).
    let result = plan(|c| c.cpu = CpuFamily::X86_64);
    let (_, data) =
        section_bytes(&image(&result), "__DATA", "__data").expect("the __data section emits");
    let value = i64::from_le_bytes(data[16..24].try_into().expect("the subtractor slot"));
    assert_eq!(value, 8, "the placed difference rides the slot");
}

#[test]
fn the_tlv_descriptor_load_patches_the_descriptor() {
    // M37 one family over: `movq _x@TLVP(%rip)` patches a disp32 to the
    // `__thread_vars` descriptor's placed vaddr — no GOT slot, no chain
    // word (the descriptor is a local definition).
    let result = plan(|c| c.cpu = CpuFamily::X86_64);
    let bytes = image(&result);
    let (text_base, text) =
        section_bytes(&bytes, "__TEXT", "__text").expect("the __text section emits");
    let (tv_base, _) =
        section_bytes(&bytes, "__DATA", "__thread_vars").expect("the descriptor section emits");
    let site = text_base + 22;
    let expected = (tv_base as i64) - (site as i64) - 4;
    assert_eq!(
        i64::from(disp32_at(&text, 22)),
        expected,
        "the TLV load names the descriptor"
    );
}

#[test]
fn the_x86_64_link_is_byte_identical_twice() {
    // The determinism contract (TDD §4.3): two links of the same x86_64
    // corpus plan byte-identical images.
    let a = image(&plan(|c| c.cpu = CpuFamily::X86_64));
    let b = image(&plan(|c| c.cpu = CpuFamily::X86_64));
    assert_eq!(a, b, "the x86_64 link is deterministic");
}

#[test]
fn the_arm64_default_stays_byte_identical() {
    // Every pre-slice link: the default family plans the pre-slice
    // bytes over an arm64 corpus, and the explicit `CpuFamily::Arm64`
    // is the same shape (the slice is invisible unless asked for).
    let mut b = ObjectBuilder::new("arm64_ptr.o");
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], Vec::new()));
    let sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    let idx = b.sym_index(sym);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(idx).at(0));
    let corpus = vec![LinkInput {
        name: "arm64_ptr.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }];
    let default_cfg = LinkConfig::default();
    let default = link(&corpus, &[], &default_cfg).expect("the default plans");
    let explicit = link(
        &corpus,
        &[],
        &LinkConfig {
            cpu: CpuFamily::Arm64,
            ..LinkConfig::default()
        },
    )
    .expect("the explicit family plans");
    assert_eq!(
        image(&default),
        image(&explicit),
        "the explicit arm64 family is the pre-slice shape"
    );
}

// ---- the refusals --------------------------------------------------------------

#[test]
fn a_foreign_input_refuses_with_the_arch_fix_named() {
    // The family gate: an arm64-typed object under `-arch x86_64`
    // refuses with both families named (the input surface rides the
    // link's family — the gate runs before any parse work caches a
    // cross-family object).
    let mut b = ObjectBuilder::new("arm64_main.o"); // the arm64 default
    b.add_section(ObjectSection::text("__text", vec![0xC3], Vec::new()));
    let corpus = vec![LinkInput {
        name: "arm64_main.o".to_string(),
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
    .expect_err("the foreign input refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("arm64") && msg.contains("x86_64"),
        "the refusal names both families: {msg}"
    );
}

#[test]
fn an_x86_64_input_refuses_under_the_arm64_default() {
    // The default keeps every pre-slice link honest: an x86_64-typed
    // object under the arm64 default refuses with the `-arch x86_64`
    // fix named (the pre-slice refusal, now naming the cause).
    let err = link(&x86_main(), &[], &LinkConfig::default())
        .expect_err("the x86_64 input refuses under the default");
    let msg = err.to_string();
    assert!(
        msg.contains("x86_64") && msg.contains("-arch"),
        "the refusal names the family and the fix: {msg}"
    );
    let (cputype, _) = {
        let bytes = &x86_main()[0].bytes;
        (
            u32::from_le_bytes(bytes[4..8].try_into().expect("cputype")),
            CPU_TYPE_ARM64,
        )
    };
    assert_eq!(cputype, CPU_TYPE_X86_64, "the input really is x86_64");
}

#[test]
fn an_external_branch_refuses_with_the_got_indirect_fix_named() {
    // ld64 synthesizes an x86_64 `__stubs` lane for direct external
    // calls; Peregrine's x86_64 shape carries no stub words (the
    // slice-2 record's refusal, now over a genuinely x86_64 input) —
    // the fix is the GOT-indirect call `*_sym@GOTPCREL(%rip)`.
    let mut b = ObjectBuilder::new("stub_x86e.o").set_cputype(CpuKind::X86_64);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xE8, 0xFC, 0xFF, 0xFF, 0xFF],
        Vec::new(),
    ));
    let printf_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_printf".into(),
        weak_ref: false,
    });
    b.section_mut(text).relocs = vec![ObjectReloc::x86_branch(b.sym_index(printf_sym)).at(1)];
    let corpus = vec![LinkInput {
        name: "stub_x86e.o".to_string(),
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
    .expect_err("the external branch refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("x86_64") && (msg.contains("GOT") || msg.contains("got")),
        "the refusal names the GOT-indirect fix: {msg}"
    );
}

#[test]
fn an_external_rip_relative_reference_refuses() {
    // A rip-relative reference to a dylib export cannot bind (the
    // displacement cannot name a foreign vaddr; dyld binds only whole
    // slots) — the fix is the GOT-indirect form.
    let mut b = ObjectBuilder::new("lea_x86e.o").set_cputype(CpuKind::X86_64);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0x48, 0x8D, 0x05, 0xFC, 0xFF, 0xFF, 0xFF],
        Vec::new(),
    ));
    let printf_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_printf".into(),
        weak_ref: false,
    });
    b.section_mut(text).relocs = vec![ObjectReloc::x86_signed(b.sym_index(printf_sym)).at(3)];
    let corpus = vec![LinkInput {
        name: "lea_x86e.o".to_string(),
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
    .expect_err("the external rip-relative reference refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("GOT") || msg.contains("got"),
        "the refusal names the GOT-indirect fix: {msg}"
    );
}

#[test]
fn the_signed_addend_correction_family_refuses() {
    // The `SIGNED_1/2/4` addend-correction forms are outside the
    // pointer-shaped honesty line (the in-situ addend algebra above
    // covers `SIGNED` only) — the decode refuses with the type named,
    // never a silent mis-decode.
    let mut b = ObjectBuilder::new("signed1_x86e.o").set_cputype(CpuKind::X86_64);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0x48, 0x8D, 0x05, 0xFC, 0xFF, 0xFF, 0xFF],
        Vec::new(),
    ));
    let local_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_local".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let mut r = ObjectReloc::x86_signed(b.sym_index(local_sym)).at(3);
    r.rtype = 6; // X86_64_RELOC_SIGNED_1
    b.section_mut(text).relocs = vec![r];
    let corpus = vec![LinkInput {
        name: "signed1_x86e.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }];
    let err = link(
        &corpus,
        &[],
        &LinkConfig {
            cpu: CpuFamily::X86_64,
            ..LinkConfig::default()
        },
    )
    .expect_err("the SIGNED_1 form refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("SIGNED"),
        "the refusal names the relocation type: {msg}"
    );
}

#[test]
fn a_narrow_unsigned_pointer_refuses() {
    // Only 8-byte pointers chain (the arm64 rule, one family over): a
    // 4-byte UNSIGNED slot refuses with the width named.
    let mut b = ObjectBuilder::new("narrow_x86e.o").set_cputype(CpuKind::X86_64);
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 4], Vec::new()));
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    let mut r = ObjectReloc::x86_unsigned(b.sym_index(main_sym)).at(0);
    r.length_log2 = 2; // 4 bytes
    b.section_mut(data).relocs = vec![r];
    let corpus = vec![LinkInput {
        name: "narrow_x86e.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }];
    let err = link(
        &corpus,
        &[],
        &LinkConfig {
            cpu: CpuFamily::X86_64,
            ..LinkConfig::default()
        },
    )
    .expect_err("the narrow slot refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("8-byte") || msg.contains("8 byte"),
        "the refusal names the pointer width: {msg}"
    );
}

#[test]
fn an_external_subtractor_refuses() {
    // Relative-pointer pairs must target in-image symbols (the arm64
    // scan's rule, family-blind).
    let mut b = ObjectBuilder::new("extsub_x86e.o").set_cputype(CpuKind::X86_64);
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], Vec::new()));
    let printf_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_printf".into(),
        weak_ref: false,
    });
    let local_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_local".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    b.section_mut(data).relocs = vec![
        ObjectReloc::x86_subtractor(b.sym_index(local_sym)).at(0),
        ObjectReloc::x86_unsigned(b.sym_index(printf_sym)).at(0),
    ];
    let corpus = vec![LinkInput {
        name: "extsub_x86e.o".to_string(),
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
    .expect_err("the external subtractor refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("subtractor") || msg.contains("subtraction"),
        "the refusal names the pair: {msg}"
    );
}

#[test]
fn an_external_tlv_descriptor_load_refuses() {
    // Thread-local variables cannot bind across a dylib boundary (M37's
    // rule, family-blind): a descriptor load naming a foreign symbol
    // refuses with the fix.
    let mut b = ObjectBuilder::new("tlv_x86e.o").set_cputype(CpuKind::X86_64);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0x48, 0x8B, 0x05, 0xFC, 0xFF, 0xFF, 0xFF],
        Vec::new(),
    ));
    let ext_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_x".into(),
        weak_ref: false,
    });
    // The dylib exports the name so the undefined-walk passes and the
    // scan's TLV contract refusal is the observable face.
    let mut x_dylib = dylib();
    x_dylib.exports = vec![b"_x".to_vec()];
    b.section_mut(text).relocs = vec![ObjectReloc::x86_tlv(b.sym_index(ext_sym)).at(3)];
    let corpus = vec![LinkInput {
        name: "tlv_x86e.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }];
    let err = link(
        &corpus,
        &[],
        &LinkConfig {
            cpu: CpuFamily::X86_64,
            dylibs: vec![x_dylib],
            ..LinkConfig::default()
        },
    )
    .expect_err("the external TLV load refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("descriptor") || msg.contains("thread-local"),
        "the refusal names the TLV contract: {msg}"
    );
}

#[test]
fn the_relocatable_output_still_refuses_the_family() {
    // The `-r` object's header is the input's, verbatim (the M10
    // rung-1 contract) — the input gate admits the x86_64 family, and
    // the relocatable path's own refusal (slice 2) still fires.
    let err = link_reloc(
        &x86_main(),
        &[],
        &LinkConfig {
            filetype: OutputType::Relocatable,
            cpu: CpuFamily::X86_64,
            dylibs: vec![dylib()],
            ..LinkConfig::default()
        },
        Parallelism::Auto,
    )
    .expect_err("the relocatable output refuses the family");
    let msg = err.to_string();
    assert!(
        msg.contains("x86_64") && msg.contains("relocatable"),
        "the refusal names the shape conflict: {msg}"
    );
}

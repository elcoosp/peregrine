//! M10 rung 4, slice 2 — the Pass-3 producer arm64e gates: the fixup
//! planner encodes the `DYLD_CHAINED_PTR_ARM64E` word family (slice 1
//! gave the tree the read side; these gates pin the write side to the
//! words the verifier already walks).
//!
//! The contracts under test:
//!
//! * unauth rebase words carry the **VM address** (format-1 semantics —
//!   dyld subtracts the preferred load address walking back), not the
//!   image-base-relative offset the 64_OFFSET family carries;
//! * `next` counts **8-byte strides** and 0 terminates;
//! * bind words carry the 16-bit ordinal and the signed inline addend
//!   (bit 62 set, 63 clear);
//! * the payload's per-segment records and the `__chain_starts` mirror
//!   both name pointer format 1, and the import table stays
//!   `DYLD_CHAINED_IMPORT_ADDEND` (the declared table format is what a
//!   loader reads — independent of the pointer format);
//! * the default path is untouched: planning with `Offset64` explicitly
//!   is byte-identical to the M2 planner (the seam is invisible unless
//!   asked for);
//! * refusals name their cause: a rebase target the arm64e fields cannot
//!   represent, and an import table beyond the 16-bit arm64e ordinal.

use pgr_core::fixups::{FixupKind, FixupPointerFormat, FixupSlot, plan_fixups_with_format};
use pgr_core::ids::StringId;
use pgr_core::interner::Interner;
use pgr_core::LinkError;
use pgr_format::consts::{
    DYLD_CHAINED_IMPORT_ADDEND, DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_64_OFFSET,
    PAGE_SIZE_16K,
};
use pgr_format::fixups::{ChainWord64, ChainWordArm64e};

const PAGE: u64 = PAGE_SIZE_16K;
const IMAGE_BASE: u64 = 0x1_0000_0000;
const TEXT_VM: u64 = IMAGE_BASE + 0x4000; // __TEXT after __PAGEZERO

/// One segment (vmaddr, vmsize, fileoff) shaped like the layout's: the
/// file mirrors the vm layout under the constant-delta contract.
fn segments() -> Vec<(u64, u64, u64)> {
    vec![(TEXT_VM, PAGE, 0x4000)]
}

/// An interner over `names`, returning the interner and each name's id
/// (input order = id order for distinct names).
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
fn arm64e_rebase_words_carry_vm_addresses() {
    let (interner, _) = interner_with(&[]);
    let slot_vaddr = TEXT_VM + 0x100; // the slot's own vaddr (and target)
    let plan = plan_fixups_with_format(
        vec![rebase(slot_vaddr)],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
    )
    .expect("one rebase plans");

    let word = ChainWordArm64e::new(word_at(&plan, slot_vaddr));
    assert!(!word.is_bind(), "rebase words leave the bind bit clear");
    assert!(!word.is_auth(), "the producer plans unauth words only");
    // Format-1 semantics: the word carries the VM address itself, dyld
    // subtracts the preferred load address (the image base) walking back.
    assert_eq!(
        word.rebase_target(),
        slot_vaddr,
        "an arm64e unauth rebase carries the VM address, not the base-relative offset"
    );
    assert_eq!(
        word.rebase_target() - IMAGE_BASE,
        slot_vaddr - IMAGE_BASE,
        "the verifier's (vmaddr − base) walk reproduces the image offset"
    );
    assert_eq!(
        word.rebase_high8(),
        0,
        "in-image targets ride the 43-bit field"
    );
    assert_eq!(word.next(), 0, "a single-slot chain terminates");
    // Contrast with the 64_OFFSET control: the same slot encodes an
    // image-base-relative offset there.
    let offset_plan = plan_fixups_with_format(
        vec![rebase(slot_vaddr)],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Offset64,
    )
    .expect("the control plans");
    let offset_word = ChainWord64::new(word_at(&offset_plan, slot_vaddr));
    assert_eq!(
        (u64::from(offset_word.rebase_high8()) << 56) | offset_word.rebase_target(),
        slot_vaddr - IMAGE_BASE,
        "64_OFFSET carries the base-relative offset"
    );
}

#[test]
fn arm64e_next_counts_8_byte_strides() {
    let (interner, _) = interner_with(&[]);
    // Two slots 16 bytes apart in one page: one stride of 2 (16 / 8).
    let a = TEXT_VM + 0x100;
    let b = a + 16;
    let plan = plan_fixups_with_format(
        vec![rebase(a), rebase(b)],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
    )
    .expect("two slots plan");
    assert_eq!(
        ChainWordArm64e::new(word_at(&plan, a)).next(),
        2,
        "16 B = 2 strides of 8"
    );
    assert_eq!(
        ChainWordArm64e::new(word_at(&plan, b)).next(),
        0,
        "the tail terminates"
    );
    // The 64_OFFSET control counts 4-byte units: 16 B = 4 strides.
    let control = plan_fixups_with_format(
        vec![rebase(a), rebase(b)],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Offset64,
    )
    .expect("the control plans");
    assert_eq!(
        ChainWord64::new(word_at(&control, a)).next(),
        4,
        "16 B = 4 strides of 4"
    );
}

#[test]
fn arm64e_bind_words_carry_the_ordinal_and_inline_addend() {
    let (interner, ids) = interner_with(&["_printf"]);
    let slot_vaddr = TEXT_VM + 0x200;
    let plan = plan_fixups_with_format(
        vec![FixupSlot {
            vaddr: slot_vaddr,
            kind: FixupKind::Bind {
                lib_ordinal: 1,
                name: ids[0],
                addend: 0x20,
                weak: false,
            },
        }],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
    )
    .expect("one bind plans");

    let word = ChainWordArm64e::new(word_at(&plan, slot_vaddr));
    assert!(word.is_bind(), "bit 62 names the bind");
    assert!(!word.is_auth(), "plain binds stay unauth");
    assert_eq!(
        word.bind_ordinal(),
        0,
        "first-use order: the bind is import 0"
    );
    assert_eq!(
        word.bind_addend(),
        0x20,
        "the inline addend rides the signed 19-bit field"
    );
    assert_eq!(plan.imports.len(), 1, "one import entry");
    assert_eq!(
        plan.imports[0].addend,
        0,
        "0..=255 travels inline, not in the table"
    );
}

#[test]
fn the_payload_and_mirror_name_the_arm64e_format() {
    let (interner, _) = interner_with(&[]);
    let plan = plan_fixups_with_format(
        vec![rebase(TEXT_VM + 0x100)],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
    )
    .expect("plans");

    // The per-segment record's pointer_format field (offset +6, u16).
    let starts_offset = u32::from_le_bytes(plan.payload[4..8].try_into().unwrap()) as usize;
    let rec0 = starts_offset
        + u32::from_le_bytes(
            plan.payload[starts_offset + 4..starts_offset + 8].try_into().unwrap(),
        ) as usize;
    let pointer_format = u16::from_le_bytes(plan.payload[rec0 + 6..rec0 + 8].try_into().unwrap());
    assert_eq!(
        pointer_format, DYLD_CHAINED_PTR_ARM64E,
        "the segment record names the arm64e family"
    );
    // The `__chain_starts` static mirror names the same format.
    let mirror_format = u32::from_le_bytes(plan.chain_starts[0..4].try_into().unwrap());
    assert_eq!(
        mirror_format,
        u32::from(DYLD_CHAINED_PTR_ARM64E),
        "the mirror agrees"
    );
    // The import table stays the declared-ADDEND shape (its format is a
    // separate header field — the pointer family does not re-derive it).
    let imports_format = u32::from_le_bytes(plan.payload[20..24].try_into().unwrap());
    assert_eq!(
        imports_format, DYLD_CHAINED_IMPORT_ADDEND,
        "the table format is declared independently of the word family"
    );
}

#[test]
fn the_default_path_stays_byte_identical() {
    let (interner, ids) = interner_with(&["_printf"]);
    let slots = vec![
        rebase(TEXT_VM + 0x100),
        rebase(TEXT_VM + 0x110),
        FixupSlot {
            vaddr: TEXT_VM + 0x200,
            kind: FixupKind::Bind {
                lib_ordinal: 1,
                name: ids[0],
                addend: 0x300, // outlined: travels in the import entry
                weak: false,
            },
        },
    ];
    let explicit = plan_fixups_with_format(
        slots.clone(),
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Offset64,
    )
    .expect("plans");
    let legacy = pgr_core::fixups::plan_fixups_with_imports(
        slots,
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
    )
    .expect("the M2 planner plans");

    assert_eq!(
        explicit.payload, legacy.payload,
        "the seam is invisible on the default: same payload bytes"
    );
    assert_eq!(explicit.slot_words, legacy.slot_words, "same encoded words");
    assert_eq!(explicit.chain_starts, legacy.chain_starts, "same mirror bytes");
    assert_eq!(explicit.imports, legacy.imports, "same import table");
    // And the pointer format is the one the M2 planner locked (§7.2).
    assert_eq!(
        u32::from_le_bytes(explicit.chain_starts[0..4].try_into().unwrap()),
        u32::from(DYLD_CHAINED_PTR_64_OFFSET),
    );
}

#[test]
fn an_arm64e_target_beyond_the_rebase_field_refuses() {
    let (interner, _) = interner_with(&[]);
    // Bits 43..56 of a VM address have no home in the arm64e word (the
    // target field is 43 bits, the high8 covers 56..64): refuse instead
    // of silently truncating them.
    let impossible = TEXT_VM + (1 << 44);
    let err = plan_fixups_with_format(
        vec![rebase(impossible)],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
    )
    .expect_err("unrepresentable targets refuse");
    match &err {
        LinkError::Layout { message } => {
            assert!(
                message.contains("arm64e rebase target"),
                "the refusal names the field: {message}"
            );
        }
        other => panic!("expected a layout refusal, got {other:?}"),
    }
}

#[test]
fn an_arm64e_import_table_beyond_16_bits_refuses() {
    // The arm64e bind word carries a 16-bit ordinal; a bind surface that
    // outgrows it must refuse at plan time, not encode a truncated one.
    let names: Vec<Vec<u8>> = (0..=usize::from(u16::MAX))
        .map(|i| format!("_sym{i:06}").into_bytes())
        .collect();
    let (interner, ids) = Interner::build(&names);
    let slots: Vec<FixupSlot> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| FixupSlot {
            vaddr: TEXT_VM + (i as u64) * 8,
            kind: FixupKind::Bind {
                lib_ordinal: 1,
                name: *id,
                addend: 0,
                weak: false,
            },
        })
        .collect();
    let err = plan_fixups_with_format(
        slots,
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
    )
    .expect_err("65537 imports refuse");
    match &err {
        LinkError::Layout { message } => {
            assert!(
                message.contains("16-bit"),
                "the refusal names the ordinal field: {message}"
            );
        }
        other => panic!("expected a layout refusal, got {other:?}"),
    }
}

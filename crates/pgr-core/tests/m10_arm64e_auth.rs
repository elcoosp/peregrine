//! M10 rung 4, slice 3 — the authenticated producer gates: the fixup
//! planner encodes `DYLD_CHAINED_PTR_ARM64E` **auth** words (slices 1–2
//! gave the tree the read side and the unauth write side; these gates pin
//! the write side's authenticated half to the words the verifier already
//! walks — `pgr-verify/src/dynamic.rs` branches on `is_auth()` since
//! slice 1, and the format layer has carried the range-checked auth
//! encoders since then with no producer caller).
//!
//! The contracts under test:
//!
//! * an auth rebase word carries the **32-bit runtime offset**
//!   (`target − image base`, what dyld adds to the preferred load
//!   address) plus the diversity/addrDiv/key PAC triple (bit 63 set,
//!   62 clear);
//! * an auth bind word carries the 16-bit ordinal and the PAC triple,
//!   and **no inline addend** — the auth bind word has no addend field,
//!   so the full addend travels in the `DYLD_CHAINED_IMPORT_ADDEND`
//!   entry (the M2 split's named exception, not a silent divergence:
//!   the unauth bind beside it keeps the 0..=255-inline rule);
//! * an empty auth policy is byte-identical to the slice-2 planner (the
//!   §7.2 lock extends to the auth seam);
//! * the payload's per-segment records and the `__chain_starts` mirror
//!   still name pointer format 1 — authentication changes words, not
//!   the declared family;
//! * refusals name their cause: auth slots under the `64_OFFSET` family,
//!   an auth entry that names no fixup slot, an auth entry named twice,
//!   and an auth rebase target beyond the 32-bit runtime offset;
//! * the M9 import anchor holds: an auth bind's table key appends
//!   without renumbering the anchored ordinals (§7.3 step 5).

use pgr_core::LinkError;
use pgr_core::fixups::{
    FixupAuth, FixupKind, FixupPointerFormat, FixupSlot, plan_fixups_with_auth,
    plan_fixups_with_format,
};
use pgr_core::ids::StringId;
use pgr_core::interner::Interner;
use pgr_format::consts::{DYLD_CHAINED_IMPORT_ADDEND, DYLD_CHAINED_PTR_ARM64E, PAGE_SIZE_16K};
use pgr_format::fixups::ChainWordArm64e;

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

/// The PAC triple as the read side sees it (the fixtures' `SlotKind`
/// auth shapes carry the same fields).
fn auth(vaddr: u64, key: u8, diversity: u16, addr_div: bool) -> FixupAuth {
    FixupAuth {
        vaddr,
        key,
        diversity,
        addr_div,
    }
}

fn bind(vaddr: u64, name: StringId, addend: i64) -> FixupSlot {
    FixupSlot {
        vaddr,
        kind: FixupKind::Bind {
            lib_ordinal: 1,
            name,
            addend,
            weak: false,
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
fn an_auth_rebase_word_carries_the_runtime_offset_and_the_pac_triple() {
    let (interner, _) = interner_with(&[]);
    let slot_vaddr = TEXT_VM + 0x100;
    let target = TEXT_VM + 0x10;
    let plan = plan_fixups_with_auth(
        vec![FixupSlot {
            vaddr: slot_vaddr,
            kind: FixupKind::Rebase {
                target_vaddr: target,
            },
        }],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
        &[auth(slot_vaddr, 2, 0xBEEF, true)],
    )
    .expect("one auth rebase plans");

    let word = ChainWordArm64e::new(word_at(&plan, slot_vaddr));
    assert!(!word.is_bind(), "rebase words leave the bind bit clear");
    assert!(word.is_auth(), "the policy signs the word (bit 63)");
    assert_eq!(
        u64::from(word.auth_rebase_offset()),
        target - IMAGE_BASE,
        "an auth rebase carries the 32-bit runtime offset (target − image base), \
         what dyld adds to the preferred load address"
    );
    assert_eq!(
        word.auth_diversity(),
        0xBEEF,
        "the diversity value reads back"
    );
    assert!(word.auth_addr_div(), "address diversity reads back");
    assert_eq!(word.auth_key(), 2, "the 2-bit key reads back");
    assert_eq!(word.next(), 0, "a single-slot chain terminates");

    // The unauth control beside it: the same slot planned without the
    // policy carries the VM address (slice-2 semantics).
    let unauth = plan_fixups_with_format(
        vec![FixupSlot {
            vaddr: slot_vaddr,
            kind: FixupKind::Rebase {
                target_vaddr: target,
            },
        }],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
    )
    .expect("the control plans");
    let control = ChainWordArm64e::new(word_at(&unauth, slot_vaddr));
    assert!(!control.is_auth());
    assert_eq!(
        control.rebase_target(),
        target,
        "unauth carries the VM address, auth carries the runtime offset"
    );
}

#[test]
fn an_auth_bind_word_carries_the_ordinal_and_the_table_addend() {
    let (interner, ids) = interner_with(&["_printf"]);
    let slot_vaddr = TEXT_VM + 0x200;
    let plan = plan_fixups_with_auth(
        vec![bind(slot_vaddr, ids[0], 0x20)],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
        &[auth(slot_vaddr, 3, 0x1234, false)],
    )
    .expect("one auth bind plans");

    let word = ChainWordArm64e::new(word_at(&plan, slot_vaddr));
    assert!(word.is_bind(), "bit 62 names the bind");
    assert!(word.is_auth(), "bit 63 signs it");
    assert_eq!(
        word.bind_ordinal(),
        0,
        "first-use order: the bind is import 0"
    );
    assert_eq!(
        word.auth_diversity(),
        0x1234,
        "the PAC triple rides the word"
    );
    assert!(!word.auth_addr_div());
    assert_eq!(word.auth_key(), 3);
    // The auth bind word has no addend field: the full addend travels in
    // the import entry (the M2 split's named exception — the word's bits
    // 32..51 are the diversity value now, so an inline addend would be
    // unreadable).
    assert_eq!(
        plan.imports[0].addend, 0x20,
        "the auth bind's addend rides the DYLD_CHAINED_IMPORT_ADDEND entry"
    );
}

#[test]
fn the_auth_bind_split_does_not_disturb_the_unauth_beside_it() {
    let (interner, ids) = interner_with(&["_printf"]);
    // Address order fixes first-use: the unauth bind (addend 0x20, the
    // M2 inline rule) is import 0; the auth bind of the same name+addend
    // is a *different* table key (outlined 0x20), import 1.
    let unauth_at = TEXT_VM + 0x100;
    let auth_at = TEXT_VM + 0x200;
    let plan = plan_fixups_with_auth(
        vec![bind(unauth_at, ids[0], 0x20), bind(auth_at, ids[0], 0x20)],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
        &[auth(auth_at, 2, 1, true)],
    )
    .expect("two binds plan");

    let unauth = ChainWordArm64e::new(word_at(&plan, unauth_at));
    assert!(!unauth.is_auth());
    assert_eq!(unauth.bind_ordinal(), 0);
    assert_eq!(
        unauth.bind_addend(),
        0x20,
        "the unauth bind keeps the M2 inline addend"
    );
    let signed = ChainWordArm64e::new(word_at(&plan, auth_at));
    assert!(signed.is_auth());
    assert_eq!(
        signed.bind_ordinal(),
        1,
        "a distinct table key, second import"
    );
    assert_eq!(plan.imports.len(), 2, "the two splits are two imports");
    assert_eq!(
        plan.imports[0].addend, 0,
        "the unauth entry: 0..=255 travels inline"
    );
    assert_eq!(
        plan.imports[1].addend, 0x20,
        "the auth entry: the full addend travels in the table"
    );
}

#[test]
fn an_empty_auth_policy_is_byte_identical_to_the_family_plan() {
    let (interner, ids) = interner_with(&["_printf"]);
    let slots = vec![
        rebase(TEXT_VM + 0x100),
        rebase(TEXT_VM + 0x110),
        bind(TEXT_VM + 0x200, ids[0], 0x300), // outlined addend
    ];
    let with_auth_entry_point = plan_fixups_with_auth(
        slots.clone(),
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
        &[],
    )
    .expect("plans");
    let slice2 = plan_fixups_with_format(
        slots,
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
    )
    .expect("plans");

    assert_eq!(
        with_auth_entry_point.payload, slice2.payload,
        "the auth seam is invisible without a policy: same payload bytes"
    );
    assert_eq!(
        with_auth_entry_point.slot_words, slice2.slot_words,
        "same encoded words"
    );
    assert_eq!(
        with_auth_entry_point.chain_starts, slice2.chain_starts,
        "same mirror bytes"
    );
    assert_eq!(
        with_auth_entry_point.imports, slice2.imports,
        "same import table"
    );
}

#[test]
fn the_payload_and_mirror_still_name_pointer_format_1() {
    let (interner, _) = interner_with(&[]);
    let slot_vaddr = TEXT_VM + 0x100;
    let plan = plan_fixups_with_auth(
        vec![rebase(slot_vaddr)],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
        &[auth(slot_vaddr, 2, 7, false)],
    )
    .expect("plans");

    let starts_offset = u32::from_le_bytes(plan.payload[4..8].try_into().unwrap()) as usize;
    let rec0 = starts_offset
        + u32::from_le_bytes(
            plan.payload[starts_offset + 4..starts_offset + 8]
                .try_into()
                .unwrap(),
        ) as usize;
    let pointer_format = u16::from_le_bytes(plan.payload[rec0 + 6..rec0 + 8].try_into().unwrap());
    assert_eq!(
        pointer_format, DYLD_CHAINED_PTR_ARM64E,
        "authentication changes words, not the declared family"
    );
    let mirror_format = u32::from_le_bytes(plan.chain_starts[0..4].try_into().unwrap());
    assert_eq!(mirror_format, u32::from(DYLD_CHAINED_PTR_ARM64E));
    let imports_format = u32::from_le_bytes(plan.payload[20..24].try_into().unwrap());
    assert_eq!(
        imports_format, DYLD_CHAINED_IMPORT_ADDEND,
        "the table format is declared independently of the pointer format"
    );
}

#[test]
fn the_offset64_family_refuses_auth_slots_with_the_fix_in_the_message() {
    let (interner, _) = interner_with(&[]);
    let slot_vaddr = TEXT_VM + 0x100;
    let err = plan_fixups_with_auth(
        vec![rebase(slot_vaddr)],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Offset64,
        &[auth(slot_vaddr, 2, 7, false)],
    )
    .expect_err("the 64_OFFSET family has no auth discriminator to set");
    match &err {
        LinkError::Layout { message } => {
            assert!(
                message.contains("auth slots require the arm64e pointer format"),
                "the refusal names the family that carries auth words: {message}"
            );
        }
        other => panic!("expected a layout refusal, got {other:?}"),
    }
}

#[test]
fn an_auth_entry_that_names_no_slot_refuses() {
    let (interner, _) = interner_with(&[]);
    let orphan = TEXT_VM + 0x900;
    let err = plan_fixups_with_auth(
        vec![rebase(TEXT_VM + 0x100)],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
        &[auth(orphan, 2, 7, false)],
    )
    .expect_err("a policy for no slot is a plan bug");
    match &err {
        LinkError::Layout { message } => {
            assert!(
                message.contains(&format!("{orphan:#x}")),
                "the refusal names the orphaned vaddr: {message}"
            );
        }
        other => panic!("expected a layout refusal, got {other:?}"),
    }
}

#[test]
fn an_auth_entry_named_twice_refuses() {
    let (interner, _) = interner_with(&[]);
    let slot_vaddr = TEXT_VM + 0x100;
    let err = plan_fixups_with_auth(
        vec![rebase(slot_vaddr)],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
        &[auth(slot_vaddr, 2, 7, false), auth(slot_vaddr, 0, 1, false)],
    )
    .expect_err("one slot, one signer");
    match &err {
        LinkError::Layout { message } => {
            assert!(
                message.contains("twice"),
                "the refusal names the duplicate policy: {message}"
            );
        }
        other => panic!("expected a layout refusal, got {other:?}"),
    }
}

#[test]
fn an_auth_rebase_runtime_offset_beyond_32_bits_refuses() {
    let (interner, _) = interner_with(&[]);
    // The auth rebase word carries a 32-bit runtime offset; a target
    // whose (target − image base) needs more refuses instead of
    // silently truncating. The base sits at zero here so the offset is
    // the target itself; the slot stays inside its segment.
    let target = 0x1_0000_0000u64;
    let err = plan_fixups_with_auth(
        vec![FixupSlot {
            vaddr: TEXT_VM,
            kind: FixupKind::Rebase {
                target_vaddr: target,
            },
        }],
        &segments(),
        0,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
        &[auth(TEXT_VM, 2, 7, false)],
    )
    .expect_err("unrepresentable auth targets refuse");
    match &err {
        LinkError::Layout { message } => {
            assert!(
                message.contains("32-bit runtime offset"),
                "the refusal names the field: {message}"
            );
        }
        other => panic!("expected a layout refusal, got {other:?}"),
    }
}

#[test]
fn the_auth_bind_key_appends_to_the_anchor_table() {
    let (interner, ids) = interner_with(&["_printf", "_greet"]);
    // Previous link: one unauth bind (the anchor's ordinal 0).
    let previous = plan_fixups_with_format(
        vec![bind(TEXT_VM + 0x100, ids[0], 0x20)],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
    )
    .expect("the previous link plans");
    // Relink: the same bind, plus a new auth bind. The auth bind's key
    // (outlined 0x40) is genuinely new — it appends; the anchored
    // ordinal holds (§7.3 step 5).
    let relink = plan_fixups_with_auth(
        vec![
            bind(TEXT_VM + 0x100, ids[0], 0x20),
            bind(TEXT_VM + 0x200, ids[1], 0x40),
        ],
        &segments(),
        IMAGE_BASE,
        PAGE,
        &interner,
        Some(&previous.stable_keys),
        FixupPointerFormat::Arm64e,
        &[auth(TEXT_VM + 0x200, 2, 9, false)],
    )
    .expect("the relink plans");

    assert_eq!(relink.imports.len(), 2, "the new key appends");
    let anchored = ChainWordArm64e::new(word_at(&relink, TEXT_VM + 0x100));
    assert_eq!(
        anchored.bind_ordinal(),
        0,
        "the anchored ordinal holds across the auth seam"
    );
    let appended = ChainWordArm64e::new(word_at(&relink, TEXT_VM + 0x200));
    assert_eq!(
        appended.bind_ordinal(),
        1,
        "the auth bind is the new import"
    );
    assert_eq!(relink.imports[1].addend, 0x40, "its addend rides the table");
}

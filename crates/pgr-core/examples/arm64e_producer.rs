//! The rung-4 word-family seam's consumer cycle, runnable (M10 rung 4,
//! slice 2): the same fixup slots planned twice — once as the M2 default
//! `DYLD_CHAINED_PTR_64_OFFSET` family, once as the
//! `DYLD_CHAINED_PTR_ARM64E` family the verifier's dyld walk has accepted
//! since slice 1 — with both plans' words decoded back and printed
//! side by side. The consumer story: the family changes the *encoding*
//! (rebase targets ride VM addresses, `next` counts 8-byte strides, the
//! payload and mirror name pointer format 1), never the *fixups* — same
//! slots, same import table, same chain heads.
//!
//! Set `PGR_TRACING=1` to install a subscriber and watch the planner's
//! family span (`the chain word format encodes the plan` — inert without
//! a subscriber, the workspace convention).
//!
//! ```sh
//! cargo run -p pgr-core --example arm64e_producer
//! ```

use pgr_core::fixups::{FixupKind, FixupPointerFormat, FixupSlot, plan_fixups_with_format};
use pgr_core::interner::Interner;
use pgr_format::consts::{DYLD_CHAINED_PTR_64_OFFSET, DYLD_CHAINED_PTR_ARM64E};
use pgr_format::fixups::{ChainWord64, ChainWordArm64e};

/// One segment shaped like the layout's `__TEXT`: file mirrors vm under
/// the constant-delta contract.
const IMAGE_BASE: u64 = 0x1_0000_0000;
const TEXT_VM: u64 = IMAGE_BASE + 0x4000;
const SEG_SIZE: u64 = 0x4000;
const PAGE: u64 = pgr_format::consts::PAGE_SIZE_16K;

/// The slots both plans encode: two chained rebases (16 B apart) and one
/// bind with an inline addend — the three shapes the family changes.
fn slots() -> (Interner, Vec<FixupSlot>) {
    let (interner, ids) = Interner::build(&[b"_printf".to_vec()]);
    (
        interner,
        vec![
            FixupSlot {
                vaddr: TEXT_VM + 0x100,
                kind: FixupKind::Rebase {
                    target_vaddr: TEXT_VM + 0x10,
                },
            },
            FixupSlot {
                vaddr: TEXT_VM + 0x110,
                kind: FixupKind::Rebase {
                    target_vaddr: TEXT_VM + 0x20,
                },
            },
            FixupSlot {
                vaddr: TEXT_VM + 0x200,
                kind: FixupKind::Bind {
                    lib_ordinal: 1,
                    name: ids[0],
                    addend: 0x20,
                    weak: false,
                },
            },
        ],
    )
}

/// One planned slot word, decoded into the family's own reader.
fn word_of(plan: &pgr_core::FixupPlan, vaddr: u64) -> u64 {
    plan.slot_words
        .iter()
        .find(|(v, _)| *v == vaddr)
        .copied()
        .expect("every slot encodes")
        .1
}

fn main() {
    // The planner's family span stays inert until a subscriber installs;
    // PGR_TRACING=1 turns it into a stderr line (the binaries do the same
    // under their debug envs).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let (interner, slots) = slots();
    let segments = [(TEXT_VM, SEG_SIZE, 0x4000)];
    let offset = plan_fixups_with_format(
        slots.clone(),
        &segments,
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Offset64,
    )
    .expect("the default family plans");
    let arm64e = plan_fixups_with_format(
        slots,
        &segments,
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
    )
    .expect("the rung-4 family plans");

    println!("the same slots, two word families");
    println!(
        "  payload/mirror pointer_format: offset64 = \
         {DYLD_CHAINED_PTR_64_OFFSET}, arm64e = {DYLD_CHAINED_PTR_ARM64E}"
    );
    println!(
        "  chain heads: offset64 = {}, arm64e = {} (same fixups, same packer)",
        offset.chain_starts.len() / 4 - 2,
        arm64e.chain_starts.len() / 4 - 2,
    );
    println!(
        "  import table: {} entry/entries each (the declared format is a separate field)",
        offset.imports.len()
    );

    for (vaddr, target) in [
        (TEXT_VM + 0x100, TEXT_VM + 0x10),
        (TEXT_VM + 0x110, TEXT_VM + 0x20),
    ] {
        let o = ChainWord64::new(word_of(&offset, vaddr));
        let a = ChainWordArm64e::new(word_of(&arm64e, vaddr));
        println!("rebase slot at {vaddr:#x} (target {target:#x}):");
        println!(
            "    offset64 : target = {:#x} (base-relative), next = {} (strides of 4)",
            (u64::from(o.rebase_high8()) << 56) | o.rebase_target(),
            o.next()
        );
        println!(
            "    arm64e   : target = {:#x} (VM address), next = {} (strides of 8)",
            a.rebase_target(),
            a.next()
        );
    }

    let vaddr = TEXT_VM + 0x200;
    let o = ChainWord64::new(word_of(&offset, vaddr));
    let a = ChainWordArm64e::new(word_of(&arm64e, vaddr));
    println!("bind slot at {vaddr:#x} (import _printf, inline addend 0x20):");
    println!(
        "    offset64 : ordinal = {}, addend = {} (8-bit inline field)",
        o.bind_ordinal(),
        o.bind_addend()
    );
    println!(
        "    arm64e   : ordinal = {}, addend = {} (signed 19-bit inline field)",
        a.bind_ordinal(),
        a.bind_addend()
    );
}

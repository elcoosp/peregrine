//! The rung-5 word-family seam's consumer cycle, runnable (M10 rung 5,
//! slice 2 — the `x86_64` producer half): the same fixup slots planned
//! twice — once as the M2 default `DYLD_CHAINED_PTR_64_OFFSET` family,
//! once as the `DYLD_CHAINED_PTR_64` family the `x86_64` producer encodes
//! and the verifier's dyld walk has translated since slice 1 — with
//! both plans' words decoded back and printed side by side. The
//! consumer story: the CPU family changes the *composition* (rebase
//! targets ride VM addresses instead of image offsets, the payload and
//! mirror name pointer format 2), never the *fixups* — same slots, same
//! strides, same import table, same chain heads.
//!
//! Set `PGR_TRACING=1` to install a subscriber and watch the planner's
//! family span (`the chain word format encodes the plan` — inert without
//! a subscriber, the workspace convention).
//!
//! ```sh
//! cargo run -p pgr-core --example x86_64_producer
//! ```

use pgr_core::fixups::{FixupKind, FixupPointerFormat, FixupSlot, plan_fixups_with_format};
use pgr_core::interner::Interner;
use pgr_format::consts::{DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET};
use pgr_format::fixups::ChainWord64;

/// One segment shaped like the layout's `__TEXT`: file mirrors vm under
/// the constant-delta contract.
const IMAGE_BASE: u64 = 0x1_0000_0000;
const TEXT_VM: u64 = IMAGE_BASE + 0x4000;
const SEG_SIZE: u64 = 0x4000;
/// The page both families stride (the bench fixes one page for both so
/// the only variable is the rebase composition).
const PAGE: u64 = pgr_format::consts::PAGE_SIZE_16K;

/// The slots both plans encode: two chained rebases (16 B apart) and one
/// bind with an inline addend — the shapes the family's composition and
/// the shared layout price.
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
    let fmt64 = plan_fixups_with_format(
        slots,
        &segments,
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Format64,
    )
    .expect("the rung-5 family plans");

    println!("the same slots, two 4-byte-stride word families");
    println!(
        "  payload/mirror pointer_format: offset64 = \
         {DYLD_CHAINED_PTR_64_OFFSET}, 64 = {DYLD_CHAINED_PTR_64}"
    );
    println!(
        "  chain heads: offset64 = {}, 64 = {} (same fixups, same packer)",
        offset.chain_starts.len() / 4 - 2,
        fmt64.chain_starts.len() / 4 - 2,
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
        let f = ChainWord64::new(word_of(&fmt64, vaddr));
        let o_composed = (u64::from(o.rebase_high8()) << 56) | o.rebase_target();
        let f_composed = (u64::from(f.rebase_high8()) << 56) | f.rebase_target();
        println!("rebase slot at {vaddr:#x} (target {target:#x}):");
        println!(
            "    offset64 : composed = {o_composed:#x} (image offset; dyld adds the \
             preferred load address), next = {} (strides of 4)",
            o.next()
        );
        println!(
            "    64       : composed = {f_composed:#x} (VM address; dyld validates \
             it against the image span), next = {} (strides of 4)",
            f.next()
        );
    }

    let vaddr = TEXT_VM + 0x200;
    let o = ChainWord64::new(word_of(&offset, vaddr));
    let f = ChainWord64::new(word_of(&fmt64, vaddr));
    println!("bind slot at {vaddr:#x} (import _printf, inline addend 0x20):");
    println!(
        "    offset64 : ordinal = {}, addend = {} (the shared bind shape)",
        o.bind_ordinal(),
        o.bind_addend()
    );
    println!(
        "    64       : ordinal = {}, addend = {} (the shared bind shape)",
        f.bind_ordinal(),
        f.bind_addend()
    );
}

//! The authenticated producer's consumer cycle, runnable (M10 rung 4,
//! slice 3): a small fixup surface — two rebases and one bind — planned
//! three ways. First as the 64_OFFSET family *with* an auth policy: the
//! planner refuses (that word family has no auth discriminator to set),
//! and the refusal renders as a miette diagnostic with help text — the
//! fix, not just the verdict, the same convention the driver's option
//! refusals and the below-floor advisory use. Then as the arm64e family
//! without and with the policy, with the plan's words decoded back and
//! printed side by side: the policy swaps the rebase shape (VM address →
//! 32-bit runtime offset plus the diversity/addrDiv/key PAC triple), the
//! auth bind moves its whole addend into the import entry (the auth bind
//! word has no addend field), and the chain heads, slot count, declared
//! pointer format and import-table format never move — same fixups, same
//! packer, signed words.
//!
//! Set `PGR_TRACING=1` to install a subscriber and watch the planner's
//! spans (`the chain word format encodes the plan`, `the fixup auth
//! policy signs the plan` — inert without a subscriber, the workspace
//! convention).
//!
//! ```sh
//! cargo run -p pgr-driver --example fixup_chains_auth
//! ```

use miette::Diagnostic;
use pgr_core::fixups::{
    FixupAuth, FixupKind, FixupPointerFormat, FixupSlot, plan_fixups_with_auth,
    plan_fixups_with_format,
};
use pgr_core::interner::Interner;
use pgr_core::LinkError;
use pgr_format::consts::{DYLD_CHAINED_PTR_ARM64E, PAGE_SIZE_16K};
use pgr_format::fixups::ChainWordArm64e;
use thiserror::Error;

/// One segment shaped like the layout's `__TEXT`: file mirrors vm under
/// the constant-delta contract.
const IMAGE_BASE: u64 = 0x1_0000_0000;
const TEXT_VM: u64 = IMAGE_BASE + 0x4000;
const SEG_SIZE: u64 = 0x4000;
const PAGE: u64 = PAGE_SIZE_16K;

/// The slots all three plans encode: two rebases and one bind — the
/// shapes the auth policy changes.
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

/// The auth policy: the first rebase and the bind are signed (the PAC
/// triple the fixtures' `SlotKind::AuthRebase`/`AuthBind` shapes carry).
fn policies() -> Vec<FixupAuth> {
    vec![
        FixupAuth {
            vaddr: TEXT_VM + 0x100,
            key: 2,
            diversity: 0xBEEF,
            addr_div: true,
        },
        FixupAuth {
            vaddr: TEXT_VM + 0x200,
            key: 3,
            diversity: 0x1234,
            addr_div: false,
        },
    ]
}

/// The 64_OFFSET-family refusal, re-rendered as a miette diagnostic: the
/// planner's [`LinkError::Layout`] names the cause; the help names the
/// fix. The miette seam the core planner stays out of (the workspace
/// keeps `pgr-core` diagnostic-free) lands here, at the consumer.
#[derive(Debug, Error, Diagnostic)]
#[error("the plan refuses the auth policy: {0}")]
#[diagnostic(help(
    "re-plan with the arm64e family (`-fixup_chains_format arm64e`) — \
     a `DYLD_CHAINED_PTR_64_OFFSET` word has no auth discriminator to set; \
     the auth slots keep their fixups, only the words change family"
))]
struct AuthFamilyRefusal(#[source] LinkError);

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
    // The planner's spans stay inert until a subscriber installs;
    // PGR_TRACING=1 turns them into stderr lines (the binaries do the
    // same under their debug envs).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let (interner, slots) = slots();
    let segments = [(TEXT_VM, SEG_SIZE, 0x4000)];
    let policies = policies();

    // The refusal path: a policy under the 64_OFFSET family, rendered
    // with the fix in the help text.
    let refused = plan_fixups_with_auth(
        slots.clone(),
        &segments,
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Offset64,
        &policies,
    )
    .expect_err("the 64_OFFSET family refuses auth slots");
    println!("the same slots, one auth policy, three plans");
    println!("  [refused] 64_OFFSET + auth policy:");
    println!(
        "{:?}",
        miette::Report::new(AuthFamilyRefusal(refused))
    );

    // The accepted paths: the slice-2 unauth family beside the slice-3
    // signed one.
    let unauth = plan_fixups_with_format(
        slots.clone(),
        &segments,
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
    )
    .expect("the unauth family plans");
    let signed = plan_fixups_with_auth(
        slots,
        &segments,
        IMAGE_BASE,
        PAGE,
        &interner,
        None,
        FixupPointerFormat::Arm64e,
        &policies,
    )
    .expect("the auth policy plans");

    println!("  unauth     arm64e + no policy");
    println!("  signed     arm64e + the policy");
    println!(
        "  declared pointer_format = {} in every plan; chain heads and \
         import tables match",
        DYLD_CHAINED_PTR_ARM64E
    );

    for (vaddr, target) in [
        (TEXT_VM + 0x100, TEXT_VM + 0x10),
        (TEXT_VM + 0x110, TEXT_VM + 0x20),
    ] {
        let u = ChainWordArm64e::new(word_of(&unauth, vaddr));
        let s = ChainWordArm64e::new(word_of(&signed, vaddr));
        println!("rebase slot at {vaddr:#x} (target {target:#x}):");
        println!(
            "    unauth : target = {:#x} (VM address), auth bit = {}",
            u.rebase_target(),
            u.is_auth()
        );
        println!(
            "    signed : runtime offset = {:#x} (target − base), PAC = \
             key {}, diversity {:#x}, addrDiv {}",
            s.auth_rebase_offset(),
            s.auth_key(),
            s.auth_diversity(),
            s.auth_addr_div()
        );
    }

    let vaddr = TEXT_VM + 0x200;
    let u = ChainWordArm64e::new(word_of(&unauth, vaddr));
    let s = ChainWordArm64e::new(word_of(&signed, vaddr));
    println!("bind slot at {vaddr:#x} (import _printf, addend 0x20):");
    println!(
        "    unauth : ordinal = {}, inline addend = {} (the M2 split)",
        u.bind_ordinal(),
        u.bind_addend()
    );
    println!(
        "    signed : ordinal = {}, PAC = key {}, diversity {:#x}, \
         table addend = {} (the word has no addend field)",
        s.bind_ordinal(),
        s.auth_key(),
        s.auth_diversity(),
        signed.imports[s.bind_ordinal() as usize].addend
    );
}

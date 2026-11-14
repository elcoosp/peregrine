//! M32 — the UUID suppression (`-no_uuid`): the flag the driver
//! surface accepted as a no-op since M1 becomes the real decision on
//! [`pgr_core::layout::LinkConfig`] — the output's `LC_UUID` command
//! drops (no uuid field for the emit two-pass derivation to patch,
//! `sizeofcmds` 24 bytes narrower). The default (`true`) keeps every
//! pre-M32 link byte-identical — the derived-UUID command rides every
//! segmented image, its field zeroed in the header bytes until the
//! emit patches it after hashing. There is no output-kind conflict
//! (every segmented output can suppress; the relocatable object's
//! header carries no `LC_UUID` command at all), and the emit patch
//! paths consult the plan offset's absent sentinel (`0` — the
//! convention every `__LINKEDIT` offset field shares) instead of
//! carrying a second copy of the decision.
//!
//! Gate matrix:
//! * the default — the command rides exactly as pre-M32 (the field
//!   zeroed in the header bytes, `uuid_at` naming it);
//! * the suppression — the command drops, the field drops
//!   (`sizeofcmds` 24 bytes narrower, `uuid_at` naming the absent
//!   sentinel);
//! * the header-only scope — the `__LINKEDIT` payload plan does not
//!   move (the suppression is a header-assembly decision);
//! * the determinism — the suppressed link is stable (the
//!   double-link gate);
//! * the classic path — the suppression is a header-assembly
//!   decision, not a fixup-level one (the classic opcode stream plans
//!   the same shape).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};

/// A single-object corpus (`_main` exported).
fn corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (i, sym) in ["_main", "_helper"].iter().enumerate() {
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

/// Links the corpus and returns the layout plan.
fn plan(tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::layout::Layout {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(&corpus(), &[], &cfg).expect("the corpus links").layout
}

/// True when the header carries `LC_UUID`.
fn carries_uuid(image: &[u8]) -> bool {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if matches!(cmd.kind, LoadCommandKind::Uuid) {
            return true;
        }
    }
    false
}

// ---- the default and the suppression --------------------------------------------

#[test]
fn the_default_carries_the_derived_uuid_slot() {
    assert!(
        LinkConfig::default().uuid,
        "the default derives the UUID (the knob suppresses)"
    );
    let layout = plan(|_| {});
    assert!(
        carries_uuid(&layout.header_bytes),
        "the default plans the pre-M32 command"
    );
    assert_ne!(
        layout.linkedit.uuid_at, 0,
        "the plan names the uuid field inside the header bytes"
    );
    let at = usize::try_from(layout.linkedit.uuid_at).expect("the offset fits");
    assert!(
        layout.header_bytes[at..at + 16].iter().all(|&b| b == 0),
        "the field is zeroed in the header bytes; the emit patches it after hashing"
    );
}

#[test]
fn the_suppression_drops_the_command_and_the_field() {
    let layout = plan(|c| c.uuid = false);
    assert!(
        !carries_uuid(&layout.header_bytes),
        "the suppression drops the command"
    );
    assert_eq!(
        layout.linkedit.uuid_at, 0,
        "the plan names the absent sentinel — every __LINKEDIT offset field's shape for absence"
    );
}

#[test]
fn the_suppression_is_exactly_one_command_narrower() {
    let carrying = plan(|_| {});
    let suppressed = plan(|c| c.uuid = false);
    let carrying_header = MachHeader64::parse(&carrying.header_bytes).expect("parses");
    let suppressed_header = MachHeader64::parse(&suppressed.header_bytes).expect("parses");
    assert_eq!(
        carrying_header.ncmds - suppressed_header.ncmds,
        1,
        "the suppression drops exactly one command"
    );
    assert_eq!(
        usize::try_from(carrying_header.sizeofcmds - suppressed_header.sizeofcmds).unwrap(),
        24,
        "the suppression drops exactly the 24-byte LC_UUID command"
    );
    assert_eq!(
        carrying.header_bytes.len() - suppressed.header_bytes.len(),
        24,
        "the header bytes shrink by the command"
    );
}

// ---- the header-only scope --------------------------------------------------------

#[test]
fn the_linkedit_plan_does_not_move() {
    // The suppression is a header-assembly decision: the `__LINKEDIT`
    // payload plan (symtab, strtab, trie, function starts) does not
    // move — only the header's command bytes shrink.
    let carrying = plan(|_| {});
    let suppressed = plan(|c| c.uuid = false);
    assert_eq!(
        carrying.linkedit.sym_off, suppressed.linkedit.sym_off,
        "the symtab offset does not move"
    );
    assert_eq!(
        carrying.linkedit.str_off, suppressed.linkedit.str_off,
        "the string-table offset does not move"
    );
    assert_eq!(
        carrying.linkedit.trie_off, suppressed.linkedit.trie_off,
        "the export-trie offset does not move"
    );
    assert_eq!(
        carrying.segments.len(),
        suppressed.segments.len(),
        "the segment plan is untouched"
    );
}

// ---- the determinism and the classic path ---------------------------------------

#[test]
fn the_suppressed_link_is_deterministic() {
    let a = plan(|c| c.uuid = false).header_bytes;
    let b = plan(|c| c.uuid = false).header_bytes;
    assert_eq!(a, b, "the double link is stable");
}

#[test]
fn the_classic_path_carries_the_decision() {
    // The suppression is a header-assembly decision — the classic
    // opcode path (`-no_fixup_chains`) plans the same shape.
    let cfg = LinkConfig {
        fixup_chains: false,
        uuid: false,
        ..LinkConfig::default()
    };
    let layout = link(&corpus(), &[], &cfg).expect("the corpus links").layout;
    assert!(
        !carries_uuid(&layout.header_bytes),
        "the classic path suppresses too"
    );
}

// The output-kind scope stays wide: every segmented output carries
// `LC_UUID` pre-M32, so every segmented output can suppress — there
// is no refusal matrix to gate. The relocatable surface keeps its
// scope: `-r` stops after Pass 2 and its object header carries no
// `LC_UUID` command, so the knob has no relocatable decision to name.
#[test]
fn every_output_kind_carries_the_decision() {
    for filetype in [OutputType::Execute, OutputType::Dylib, OutputType::Bundle] {
        let cfg = LinkConfig {
            filetype,
            uuid: false,
            ..LinkConfig::default()
        };
        let layout = link(&corpus(), &[], &cfg).expect("the corpus links").layout;
        assert!(
            !carries_uuid(&layout.header_bytes),
            "the suppression rides the {filetype:?} output"
        );
        assert_eq!(
            layout.linkedit.uuid_at, 0,
            "the plan names the absent sentinel"
        );
    }
}

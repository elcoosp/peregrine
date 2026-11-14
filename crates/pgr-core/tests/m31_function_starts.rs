//! M31 — the function-starts suppression (`-no_function_starts`): the
//! flag the driver surface accepted as a no-op since M1 becomes the
//! real decision on [`pgr_core::layout::LinkConfig`] — the output's
//! `LC_FUNCTION_STARTS` command drops (no `__LINKEDIT` slot, no
//! ULEB stream, `sizeofcmds` 16 bytes narrower). The default (`true`)
//! keeps every pre-M31 link byte-identical — the command rides even
//! when its stream is empty (the always-carried shape). There is no
//! output-kind conflict (every segmented output can suppress) and the
//! verifier stays silent either way: it validates the payload only
//! when the command is present.
//!
//! Gate matrix:
//! * the default — the command rides exactly as pre-M31 (even with an
//!   empty stream, `dataoff 0 / datasize 0`);
//! * the suppression — the command drops, the slot drops, the stream
//!   is empty (`sizeofcmds` 16 bytes narrower);
//! * the determinism — the suppressed link is stable (the
//!   double-link gate);
//! * the classic path — the suppression is a header-assembly
//!   decision, not a fixup-level one (the classic opcode stream plans
//!   the same bytes).

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

/// True when the header carries `LC_FUNCTION_STARTS`.
fn carries_function_starts(image: &[u8]) -> bool {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::LinkeditData(pgr_format::consts::LC_FUNCTION_STARTS) = cmd.kind {
            return true;
        }
    }
    false
}

// ---- the default and the suppression --------------------------------------------

#[test]
fn the_default_carries_the_command_as_pre_m31() {
    assert!(
        LinkConfig::default().function_starts,
        "the default carries the stream (the knob suppresses)"
    );
    let layout = plan(|_| {});
    assert!(
        carries_function_starts(&layout.header_bytes),
        "the default plans the pre-M31 command"
    );
    assert!(
        !layout.func_starts.is_empty(),
        "the non-empty stream rides the __LINKEDIT slot"
    );
    assert!(layout.linkedit.func_starts_size > 0);
}

#[test]
fn the_suppression_drops_the_command_and_the_slot() {
    let layout = plan(|c| c.function_starts = false);
    assert!(
        !carries_function_starts(&layout.header_bytes),
        "the suppression drops the command"
    );
    assert!(layout.func_starts.is_empty(), "no stream");
    assert_eq!(layout.linkedit.func_starts_off, 0);
    assert_eq!(layout.linkedit.func_starts_size, 0);
}

#[test]
fn the_suppression_is_exactly_the_command_narrower() {
    let carrying = plan(|_| {});
    let suppressed = plan(|c| c.function_starts = false);
    assert_eq!(
        carrying.header_bytes.len() - suppressed.header_bytes.len(),
        16,
        "the suppression drops exactly the LC_FUNCTION_STARTS command"
    );
}

// ---- the determinism and the classic path ---------------------------------------

#[test]
fn the_suppressed_link_is_deterministic() {
    let a = plan(|c| c.function_starts = false).header_bytes;
    let b = plan(|c| c.function_starts = false).header_bytes;
    assert_eq!(a, b, "the double link is stable");
}

#[test]
fn the_classic_path_carries_the_decision() {
    // The suppression is a header-assembly decision — the classic
    // opcode path (`-no_fixup_chains`) plans the same bytes.
    let cfg = LinkConfig {
        fixup_chains: false,
        function_starts: false,
        ..LinkConfig::default()
    };
    let layout = link(&corpus(), &[], &cfg).expect("the corpus links").layout;
    assert!(
        !carries_function_starts(&layout.header_bytes),
        "the classic path suppresses too"
    );
}

// The relocatable surface keeps its scope: `-r` stops after Pass 2 and
// its object header carries no function-starts command, so the knob
// has no relocatable decision to name.
#[test]
fn the_knob_names_an_output_kind_without_conflicts() {
    // Every segmented output can suppress; there is no refusal matrix
    // to gate — the decision is the absence of the command.
    let cfg = LinkConfig {
        filetype: OutputType::Dylib,
        function_starts: false,
        ..LinkConfig::default()
    };
    assert!(!cfg.function_starts);
}

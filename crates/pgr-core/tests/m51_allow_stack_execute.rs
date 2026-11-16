//! M51 — the stack-execution decision (`-allow_stack_execute`): the
//! executable header's `MH_ALLOW_STACK_EXECUTION` flag stops being
//! unreachable and becomes a named decision on
//! [`pgr_core::layout::LinkConfig`] — ld64's `-allow_stack_execute`
//! ("Marks executable so that all stacks in the task will be given
//! stack execution privilege", the pthread stacks included). The
//! default keeps the pre-M51 bytes: the bit rides no image, the same
//! word every milestone before planned.
//!
//! Gate matrix:
//! * the default — no image carries `MH_ALLOW_STACK_EXECUTION` (the
//!   pre-M51 shape), and the flag word rides every output kind it
//!   always did;
//! * the knob — `-allow_stack_execute` sets exactly that bit: the
//!   header flags differ from the default link by that bit alone
//!   (nothing else in the plan moves — the flag is one bit in one
//!   word);
//! * the refusals — a named `-allow_stack_execute` on a dylib, a
//!   bundle or the relocatable output is a layout error:
//!   `MH_ALLOW_STACK_EXECUTION` is an executable-only bit (the driver
//!   surface refuses earlier; the layout re-checks so no library
//!   caller can plan the shape either);
//! * the lock — double-link determinism holds across the decision, and
//!   the classic opcode path (no chained fixups) plans the same flag
//!   word (the bit is loader-level, not fixup-level).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// A single-object corpus (`_main` exported) linkable as any kind.
fn corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    for (i, sym) in ["_main", "_lib_fn"].iter().enumerate() {
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

/// Links the corpus with a config tweak and returns the header bytes.
fn link_header(tweak: impl FnOnce(&mut LinkConfig)) -> Vec<u8> {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(&corpus(), &[], &cfg)
        .expect("the corpus links")
        .layout
        .header_bytes
}

/// The header's flags word (byte 24..28 of the 32-byte header).
fn flags(header: &[u8]) -> u32 {
    u32::from_le_bytes(header[24..28].try_into().expect("flags word"))
}

#[test]
fn the_default_executable_does_not_carry_mh_allow_stack_execution() {
    let header = link_header(|_| {});
    assert_eq!(
        flags(&header) & pgr_format::consts::MH_ALLOW_STACK_EXECUTION,
        0,
        "the pre-M51 shape: no default image opts into an executable stack"
    );
}

#[test]
fn allow_stack_execute_sets_exactly_the_stack_execution_bit() {
    let default = link_header(|_| {});
    let knobbed = link_header(|c| c.allow_stack_execute = true);
    assert_eq!(
        flags(&knobbed) & pgr_format::consts::MH_ALLOW_STACK_EXECUTION,
        pgr_format::consts::MH_ALLOW_STACK_EXECUTION,
        "the named decision sets MH_ALLOW_STACK_EXECUTION"
    );
    // The bit is the whole diff: the flag does not move any other byte
    // of the header (the command stream, the segment layout, the entry
    // — all untouched).
    let stack_exec = pgr_format::consts::MH_ALLOW_STACK_EXECUTION;
    let mut expect = default.clone();
    let word = u32::from_le_bytes(expect[24..28].try_into().expect("flags"));
    expect[24..28].copy_from_slice(&(word | stack_exec).to_le_bytes());
    assert_eq!(
        knobbed, expect,
        "MH_ALLOW_STACK_EXECUTION is the only byte that moves"
    );
}

#[test]
fn non_executable_outputs_refuse_the_knob() {
    for (kind, label) in [
        (OutputType::Dylib, "dylib"),
        (OutputType::Bundle, "bundle"),
        (OutputType::Relocatable, "relocatable"),
    ] {
        let cfg = LinkConfig {
            allow_stack_execute: true,
            filetype: kind,
            ..LinkConfig::default()
        };
        let err = link(&corpus(), &[], &cfg).expect_err("the shape refuses");
        assert!(
            err.to_string().contains(label),
            "the refusal names the output kind ({label}): {err}"
        );
    }
}

#[test]
fn the_decision_links_deterministically_and_on_the_classic_path() {
    // Double-link determinism across the decision.
    let a = link_header(|c| c.allow_stack_execute = true);
    let b = link_header(|c| c.allow_stack_execute = true);
    assert_eq!(a, b, "the double link is stable");
    // The classic opcode path (no chained fixups) plans the same flag
    // word: the bit is loader-level, not fixup-level.
    let classic = link_header(|c| {
        c.allow_stack_execute = true;
        c.fixup_chains = false;
    });
    assert_eq!(
        flags(&classic) & pgr_format::consts::MH_ALLOW_STACK_EXECUTION,
        pgr_format::consts::MH_ALLOW_STACK_EXECUTION,
        "the classic path carries the named decision too"
    );
}

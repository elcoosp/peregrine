//! M98 — the dylib terminator released: `-term <symbol>` — the sibling
//! decision M48's `-init` left empty is the Pass-3 identity decision the
//! header assembly reads: the resolved terminator's image-space vaddr
//! rides `term_address` in the SAME `LC_ROUTINES_64` the initializer
//! composes into (one command, two fields — `-init` + `-term` never plan
//! a duplicate; the legacy `init_module` slot at byte 16 carries the
//! terminator, a fixed-point layout having no module table to index).
//! The default (`None`) keeps every pre-M98 link byte-identical — the
//! command rides exactly when either half names a symbol — and the knob
//! is a dylib decision like `-init`: an executable, a bundle and the
//! relocatable output refuse it, the layout's re-check and
//! `link_reloc` backing the driver surface's earlier refusal.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// lib.o: `_my_init` (the initializer body), `_my_term` (the terminator
/// body) and `_api` (the exported surface), all `ret` bodies in one
/// `__text`.
fn lib_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("lib.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![
            0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6,
        ], // ret; ret; ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_my_init".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_my_term".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_api".into(),
        section_index: text,
        value: 8,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn lib_inputs() -> Vec<LinkInput> {
    vec![LinkInput {
        name: "lib.o".into(),
        bytes: lib_object(),
    }]
}

fn dylib_cfg(init: Option<&str>, term: Option<&str>) -> LinkConfig {
    LinkConfig {
        ident: "lib".into(),
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/lib.dylib".into()),
        init_symbol: init.map(String::from),
        term_symbol: term.map(String::from),
        ..LinkConfig::default()
    }
}

/// The expected address: the named symbol rides the `__text` section
/// start + its own value (the fixture defines it inside one section).
fn expected_addr(layout: &pgr_core::layout::Layout, value: u64) -> u64 {
    layout
        .sections
        .iter()
        .find(|s| s.name == "__text")
        .expect("the __text section plans")
        .vm_addr
        + value
}

/// Walks the header's load commands; returns `(count, init_address,
/// term_address)` of the `LC_ROUTINES_64` family (the 64-bit shape; the
/// count is the duplicate gate — `-init` + `-term` compose one command).
fn routines_fields(header: &[u8]) -> (usize, u64, u64) {
    let hdr = pgr_format::MachHeader64::parse(header).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        header,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut count = 0usize;
    let mut init = 0u64;
    let mut term = 0u64;
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if let pgr_format::LoadCommandKind::Routines = cmd.kind {
            count += 1;
            let size =
                u32::from_le_bytes(cmd.bytes[4..8].try_into().expect("cmdsize rides byte 4"));
            assert_eq!(
                size, 72,
                "LC_ROUTINES rides the 72-byte routines_command_64"
            );
            init = u64::from_le_bytes(
                cmd.bytes[8..16]
                    .try_into()
                    .expect("init_address rides byte 8"),
            );
            term = u64::from_le_bytes(
                cmd.bytes[16..24]
                    .try_into()
                    .expect("term_address rides byte 16 (the legacy init_module slot)"),
            );
        }
    }
    (count, init, term)
}

#[test]
fn the_default_dylib_still_carries_no_routines_command() {
    // The pre-M98 shape holds: without either half of the seam no
    // LC_ROUTINES rides — byte for byte the M48 default.
    let layout = link(&lib_inputs(), &[], &dylib_cfg(None, None))
        .expect("the default dylib plans")
        .layout;
    assert!(
        routines_fields(&layout.header_bytes).0 == 0,
        "the default plans no LC_ROUTINES"
    );
}

#[test]
fn term_names_the_terminator_in_lc_routines() {
    // The named decision: LC_ROUTINES_64 rides the identity block with
    // the resolved terminator's address in `term_address`, the
    // initializer slot riding zero (`-init` did not ride).
    let layout = link(&lib_inputs(), &[], &dylib_cfg(None, Some("_my_term")))
        .expect("the terminated dylib plans")
        .layout;
    let (count, init, term) = routines_fields(&layout.header_bytes);
    assert_eq!(count, 1, "one command carries the terminator");
    assert_eq!(init, 0, "the initializer slot rides zero without -init");
    assert_eq!(
        term,
        expected_addr(&layout, 4),
        "term_address names the resolved terminator"
    );
}

#[test]
fn init_and_term_compose_into_one_command() {
    // The compose gate: both halves ride the SAME LC_ROUTINES_64 —
    // never a duplicate command (dyld reads one routines command, the
    // two fields beside each other).
    let layout = link(
        &lib_inputs(),
        &[],
        &dylib_cfg(Some("_my_init"), Some("_my_term")),
    )
    .expect("the composed dylib plans")
    .layout;
    let (count, init, term) = routines_fields(&layout.header_bytes);
    assert_eq!(count, 1, "-init + -term never plan a duplicate command");
    assert_eq!(
        init,
        expected_addr(&layout, 0),
        "init_address names the resolved initializer"
    );
    assert_eq!(
        term,
        expected_addr(&layout, 4),
        "term_address names the resolved terminator"
    );
}

#[test]
fn term_refuses_on_executables_bundles_and_relocatable() {
    // The M48 shape one field over: the terminator is a dylib decision
    // (an executable terminates through its runtime, a bundle dlopens
    // without a dylib terminator, and the relocatable output carries no
    // load commands at all) — the re-checks back the driver surface.
    for (kind, note) in [
        (OutputType::Execute, "executable"),
        (OutputType::Bundle, "bundle"),
    ] {
        let cfg = LinkConfig {
            ident: "not-a-dylib".into(),
            filetype: kind,
            term_symbol: Some("_my_term".into()),
            ..LinkConfig::default()
        };
        let err =
            link(&lib_inputs(), &[], &cfg).expect_err("the non-dylib output refuses the knob");
        let message = err.to_string();
        assert!(
            message.contains("-term"),
            "the {note} refusal names the knob: {message}"
        );
        assert!(
            message.contains("dylib"),
            "the {note} refusal names the fix: {message}"
        );
    }
    let cfg = LinkConfig {
        ident: "reloc".into(),
        filetype: OutputType::Relocatable,
        term_symbol: Some("_my_term".into()),
        ..LinkConfig::default()
    };
    let err = link_reloc(&lib_inputs(), &[], &cfg, Parallelism::Auto)
        .expect_err("the relocatable output refuses the knob");
    assert!(
        err.to_string().contains("-term"),
        "the relocatable refusal names the knob: {err}"
    );
}

#[test]
fn an_unresolved_term_symbol_refuses_the_link() {
    // The name must resolve like the initializer's: a typo refuses with
    // the entry seam's Symbol error shape — never a silently wrong
    // command.
    let cfg = dylib_cfg(None, Some("_not_defined_here"));
    let err = link(&lib_inputs(), &[], &cfg).expect_err("the unresolved terminator refuses");
    let message = err.to_string();
    assert!(
        message.contains("_not_defined_here"),
        "the refusal names the symbol: {message}"
    );
}

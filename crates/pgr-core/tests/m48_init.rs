//! M48 — the dylib initializer released: `-init <symbol>` — ld64's
//! flag ("Specifies the name of an initializer to be called by dyld
//! when the image is loaded") is the Pass-3 identity decision the
//! header assembly reads: the resolved initializer's address rides
//! `LC_ROUTINES` (`routines_command_64`, 72 bytes — the shape dyld's
//! `hasInitializer` walk reads first). The default (`None`) keeps
//! every pre-M48 link byte-identical — no command rides — and the
//! knob is a dylib decision (ld64: "-init can only be used with
//! -dynamiclib"): an executable, a bundle and the relocatable output
//! refuse it, the layout's re-check and `link_reloc` backing the
//! driver surface's earlier refusal.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// lib.o: `_my_init` (the initializer body) and `_api` (the exported
/// surface), both `ret` bodies in one `__text`.
fn lib_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("lib.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6], // ret; ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_my_init".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_api".into(),
        section_index: text,
        value: 4,
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

fn dylib_cfg(init: Option<&str>) -> LinkConfig {
    LinkConfig {
        ident: "lib".into(),
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/lib.dylib".into()),
        init_symbol: init.map(String::from),
        ..LinkConfig::default()
    }
}

/// The expected initializer address: `_my_init` rides the `__text`
/// section start (the fixture defines it at value 0), so the output
/// symbol value is the section's own `vm_addr`.
fn expected_init_addr(layout: &pgr_core::layout::Layout) -> u64 {
    layout
        .sections
        .iter()
        .find(|s| s.name == "__text")
        .expect("the __text section plans")
        .vm_addr
}

#[test]
fn the_default_dylib_carries_no_routines_command() {
    // Pre-M48 shape: without the knob no LC_ROUTINES rides — the
    // header command set stays exactly the pre-M48 one, byte for byte.
    let layout = link(&lib_inputs(), &[], &dylib_cfg(None))
        .expect("the default dylib plans")
        .layout;
    assert!(
        !header_has_routines(&layout.header_bytes),
        "the default plans no LC_ROUTINES"
    );
}

/// Walks a header's load commands; true when an `LC_ROUTINES` rides.
fn header_has_routines(header: &[u8]) -> bool {
    let hdr = pgr_format::MachHeader64::parse(header).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        header,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if matches!(cmd.kind, pgr_format::LoadCommandKind::Routines) {
            return true;
        }
    }
    false
}

/// Reads the first `LC_ROUTINES` command's `(cmdsize, init_address)`.
fn routines_fields(header: &[u8]) -> (u32, u64) {
    let hdr = pgr_format::MachHeader64::parse(header).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        header,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if let pgr_format::LoadCommandKind::Routines = cmd.kind {
            let size =
                u32::from_le_bytes(cmd.bytes[4..8].try_into().expect("cmdsize rides byte 4"));
            let addr = u64::from_le_bytes(
                cmd.bytes[8..16]
                    .try_into()
                    .expect("init_address rides byte 8"),
            );
            return (size, addr);
        }
    }
    panic!("no LC_ROUTINES in the header")
}

#[test]
fn init_names_the_initializer_in_lc_routines() {
    // The named decision: LC_ROUTINES rides the identity block with the
    // resolved initializer's address (dyld's hasInitializer reads the
    // command first, before the __mod_init_func sections).
    let layout = link(&lib_inputs(), &[], &dylib_cfg(Some("_my_init")))
        .expect("the initialized dylib plans")
        .layout;
    let (size, addr) = routines_fields(&layout.header_bytes);
    assert_eq!(
        size, 72,
        "LC_ROUTINES rides the 72-byte routines_command_64"
    );
    assert_eq!(
        addr,
        expected_init_addr(&layout),
        "init_address names the resolved initializer"
    );
}

#[test]
fn init_refuses_on_executables_bundles_and_relocatable() {
    // ld64: "-init can only be used with -dynamiclib". An executable's
    // initializer surface is LC_MAIN (its entry), a bundle dlopens
    // without a dylib initializer, and the relocatable output carries
    // no load commands at all — the re-checks back the driver surface.
    for (kind, note) in [
        (OutputType::Execute, "executable"),
        (OutputType::Bundle, "bundle"),
    ] {
        let cfg = LinkConfig {
            ident: "not-a-dylib".into(),
            filetype: kind,
            init_symbol: Some("_my_init".into()),
            ..LinkConfig::default()
        };
        let err =
            link(&lib_inputs(), &[], &cfg).expect_err("the non-dylib output refuses the knob");
        let message = err.to_string();
        assert!(
            message.contains("-init"),
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
        init_symbol: Some("_my_init".into()),
        ..LinkConfig::default()
    };
    let err = link_reloc(&lib_inputs(), &[], &cfg, Parallelism::Auto)
        .expect_err("the relocatable output refuses the knob");
    assert!(
        err.to_string().contains("-init"),
        "the relocatable refusal names the knob: {err}"
    );
}

#[test]
fn an_unresolved_init_symbol_refuses_the_link() {
    // ld64 adds the init function to the initial undefineds: the name
    // must resolve. A typo refuses with the entry seam's Symbol error
    // shape — never a silently wrong command.
    let cfg = dylib_cfg(Some("_not_defined_here"));
    let err = link(&lib_inputs(), &[], &cfg).expect_err("the unresolved initializer refuses");
    let message = err.to_string();
    assert!(
        message.contains("_not_defined_here"),
        "the refusal names the symbol: {message}"
    );
}

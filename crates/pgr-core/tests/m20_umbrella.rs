//! M20 — the dylib umbrella region (`pgr_core::umbrella`): the
//! `-sub_umbrella <name>` / `-sub_library <name>` decisions stop being
//! the `LATER_FLAGS` backlog and become validated members of
//! [`pgr_core::layout::LinkConfig`] — the `LC_SUB_UMBRELLA` /
//! `LC_SUB_LIBRARY` commands an umbrella dylib carries beside its
//! `LC_ID_DYLIB` (ld64's identity block: the region names who may load
//! the umbrella *by name* through its members).
//!
//! Gate matrix:
//! * the seam — a member validates (non-empty, NUL-free) with the fix
//!   in the refusal, duplicates refuse (one decision per name), the
//!   command sizes are the 12-byte-fixed `lc_str` shape, and the table
//!   keeps flag order;
//! * layout — a named umbrella dylib carries `LC_SUB_UMBRELLA` then
//!   `LC_SUB_LIBRARY` right after its `LC_ID_DYLIB` and before the
//!   first load command (the ld64-canonical adjacency), each with the
//!   name at the `lc_str` offset, and the region walk is exact (ncmds and
//!   sizeofcmds agree — no sizing drift);
//! * the refusals — a member on an executable, a bundle or the
//!   relocatable output is a layout error (the driver surface refuses
//!   earlier; the layout re-check so no caller can plan the shape);
//! * the lock — the default (empty) table plans what the pre-seam
//!   layout planned: no sub commands, and a double link stays
//!   byte-identical (TDD §4.3);
//! * the classic path — `-no_fixup_chains` opcodes carry the region the
//!   same way (the commands are kind-level, not fixup-level).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::umbrella::{Umbrella, UmbrellaKind, UmbrellaMember};
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

/// Links the corpus with a config tweak and returns the layout.
fn link_layout(tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::Layout {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(&corpus(), &[], &cfg).expect("the corpus links").layout
}

fn align8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

/// Walks a header block (`32 + sizeofcmds` bytes) and returns the
/// classified `(opcode, kind, name)` rows of every command, reading
/// each command's `lc_str` name at the given offset when it carries one.
fn header_rows(header_bytes: &[u8]) -> Vec<(u32, pgr_format::LoadCommandKind, Option<String>)> {
    let ncmds = u32::from_le_bytes(header_bytes[16..20].try_into().expect("ncmds"));
    let sizeofcmds = u32::from_le_bytes(header_bytes[20..24].try_into().expect("sizeofcmds"));
    let mut it = pgr_format::LoadCommandIter::new(
        header_bytes,
        pgr_format::MachHeader64::SIZE,
        ncmds,
        sizeofcmds,
    )
    .expect("the load-command region walks");
    let mut rows = Vec::new();
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        let name = (|| {
            // The lc_str offset field rides byte 8 in every command
            // family here; its *value* is what differs (24 for the
            // dylib-shaped commands, 12 for the region commands).
            let carries_name = matches!(
                cmd.kind,
                pgr_format::LoadCommandKind::LoadDylib
                    | pgr_format::LoadCommandKind::ReexportDylib
                    | pgr_format::LoadCommandKind::IdDylib
                    | pgr_format::LoadCommandKind::Rpath
                    | pgr_format::LoadCommandKind::SubUmbrella
                    | pgr_format::LoadCommandKind::SubLibrary
            );
            if !carries_name {
                return None;
            }
            let off = u32::from_le_bytes(cmd.bytes[8..12].try_into().expect("lc_str")) as usize;
            let start = off.min(cmd.bytes.len());
            let tail = &cmd.bytes[start..];
            let end = tail.iter().position(|&b| b == 0)?;
            Some(String::from_utf8_lossy(&tail[..end]).into_owned())
        })();
        rows.push((cmd.hdr().0, cmd.kind, name));
    }
    rows
}

// ---- the seam ----------------------------------------------------------------

#[test]
fn a_member_validates_and_keeps_flag_order() {
    let mut t = Umbrella::new();
    t.push(
        UmbrellaMember::from_flag(UmbrellaKind::SubUmbrella, "libsub.dylib").expect("validates"),
    )
    .expect("first push lands");
    t.push(
        UmbrellaMember::from_flag(UmbrellaKind::SubLibrary, "liblegacy.dylib").expect("validates"),
    )
    .expect("second push lands");
    let names: Vec<(&str, &str)> = t.iter().map(|m| (m.kind().as_str(), m.name())).collect();
    assert_eq!(
        names,
        [
            ("sub-umbrella", "libsub.dylib"),
            ("sub-library", "liblegacy.dylib")
        ],
        "the table keeps flag order"
    );
    assert_eq!(t.count(), 2);
    assert!(!t.is_empty());
}

#[test]
fn refusals_name_the_fix() {
    // An empty name is a typo, not a member.
    let err = UmbrellaMember::from_flag(UmbrellaKind::SubUmbrella, "").expect_err("empty refuses");
    assert!(err.to_string().contains("non-empty"), "{err}");
    // The lc_str cannot carry an interior NUL.
    let err = UmbrellaMember::from_flag(UmbrellaKind::SubLibrary, "lib\0x.dylib")
        .expect_err("NUL refuses");
    assert!(err.to_string().contains("NUL"), "{err}");
}

#[test]
fn duplicates_refuse_across_kinds() {
    let mut t = Umbrella::new();
    t.push(
        UmbrellaMember::from_flag(UmbrellaKind::SubUmbrella, "libdup.dylib").expect("validates"),
    )
    .expect("first lands");
    // The same name as a sub-umbrella again: one decision per name.
    let err = t
        .push(
            UmbrellaMember::from_flag(UmbrellaKind::SubUmbrella, "libdup.dylib")
                .expect("validates"),
        )
        .expect_err("duplicate refuses");
    assert!(err.to_string().contains("libdup.dylib"), "{err}");
    // The same name as a sub-library: still the same region decision.
    let err = t
        .push(
            UmbrellaMember::from_flag(UmbrellaKind::SubLibrary, "libdup.dylib").expect("validates"),
        )
        .expect_err("cross-kind duplicate refuses");
    assert!(err.to_string().contains("libdup.dylib"), "{err}");
}

#[test]
fn command_sizes_are_the_lc_str_shape() {
    // The 12-byte-fixed command: cmd + cmdsize + lc_str offset, name
    // inline, 8-byte aligned — the LC_RPATH shape.
    assert_eq!(
        UmbrellaMember::from_flag(UmbrellaKind::SubUmbrella, "a")
            .expect("validates")
            .cmd_size(),
        16
    );
    assert_eq!(
        UmbrellaMember::from_flag(UmbrellaKind::SubLibrary, "liblegacy_umbrella.dylib")
            .expect("validates")
            .cmd_size(),
        align8(12 + "liblegacy_umbrella.dylib".len() + 1)
    );
    // The opcodes are the vendored constants (cross-checked against the
    // `object` crate in pgr-format's own suite).
    assert_eq!(
        UmbrellaKind::SubUmbrella.opcode(),
        pgr_format::consts::LC_SUB_UMBRELLA
    );
    assert_eq!(
        UmbrellaKind::SubLibrary.opcode(),
        pgr_format::consts::LC_SUB_LIBRARY
    );
}

// ---- layout ------------------------------------------------------------------

/// The umbrella dylib the gates link: two members, one of each kind.
fn umbrella_dylib_cfg() -> LinkConfig {
    let mut t = Umbrella::new();
    t.push(
        UmbrellaMember::from_flag(UmbrellaKind::SubUmbrella, "libsub.dylib").expect("validates"),
    )
    .expect("lands");
    t.push(
        UmbrellaMember::from_flag(UmbrellaKind::SubLibrary, "liblegacy.dylib").expect("validates"),
    )
    .expect("lands");
    LinkConfig {
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libumbrella.dylib".into()),
        umbrella: t,
        ..LinkConfig::default()
    }
}

#[test]
fn an_umbrella_dylib_carries_the_region_after_its_identity() {
    let layout = link_layout(|c| *c = umbrella_dylib_cfg());
    let rows = header_rows(&layout.header_bytes);
    let id_at = rows
        .iter()
        .position(|(_, k, _)| *k == pgr_format::LoadCommandKind::IdDylib)
        .expect("a dylib carries LC_ID_DYLIB");
    let sub_at = rows
        .iter()
        .position(|(_, k, _)| *k == pgr_format::LoadCommandKind::SubUmbrella)
        .expect("LC_SUB_UMBRELLA emitted");
    let lib_at = rows
        .iter()
        .position(|(_, k, _)| *k == pgr_format::LoadCommandKind::SubLibrary)
        .expect("LC_SUB_LIBRARY emitted");
    let first_load = rows
        .iter()
        .position(|(_, k, _)| *k == pgr_format::LoadCommandKind::LoadDylib)
        .unwrap_or(rows.len());
    assert!(
        id_at < sub_at && sub_at < lib_at && lib_at < first_load,
        "the region rides the identity block: id {id_at}, sub {sub_at}, lib {lib_at}, first load {first_load}"
    );
    assert_eq!(rows[sub_at].2.as_deref(), Some("libsub.dylib"));
    assert_eq!(rows[lib_at].2.as_deref(), Some("liblegacy.dylib"));
    // The region walk is exact: LoadCommandIter already refuses trailing
    // bytes, so reaching here means ncmds and sizeofcmds agree.
}

#[test]
fn the_refusals_name_the_kind_that_cannot_carry_it() {
    for (kind, label) in [
        (OutputType::Execute, "executable"),
        (OutputType::Bundle, "bundle"),
        (OutputType::Relocatable, "relocatable"),
    ] {
        let mut cfg = umbrella_dylib_cfg();
        cfg.filetype = kind;
        cfg.install_name = None;
        let err = link(&corpus(), &[], &cfg).expect_err("the shape refuses");
        assert!(
            err.to_string().contains(label),
            "the refusal names the output kind ({label}): {err}"
        );
    }
}

// ---- the lock ----------------------------------------------------------------

#[test]
fn the_default_links_byte_identical_and_command_free() {
    // Double-link determinism with the empty table.
    let a = link_layout(|_| {});
    let b = link_layout(|_| {});
    assert_eq!(a.header_bytes, b.header_bytes, "the double link is stable");
    // And the empty table emits no sub commands (the pre-M20 shape).
    let rows = header_rows(&a.header_bytes);
    assert!(
        rows.iter().all(|(_, k, _)| !matches!(
            k,
            pgr_format::LoadCommandKind::SubUmbrella | pgr_format::LoadCommandKind::SubLibrary
        )),
        "the default carries no region commands"
    );
}

#[test]
fn the_classic_path_carries_the_region_too() {
    let mut cfg = umbrella_dylib_cfg();
    cfg.fixup_chains = false;
    let layout = link(&corpus(), &[], &cfg)
        .expect("the classic dylib links")
        .layout;
    let rows = header_rows(&layout.header_bytes);
    assert!(
        rows.iter()
            .any(|(_, k, _)| *k == pgr_format::LoadCommandKind::SubUmbrella),
        "the classic opcode path still names the region"
    );
}

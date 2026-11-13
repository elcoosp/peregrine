//! M21 — the dylib client seam (`pgr_core::sub_client`): the
//! `-sub_client <name>` decisions stop being an unnameable identity
//! block and become a validated table on [`pgr_core::layout::LinkConfig`]
//! — the `LC_SUB_CLIENT` commands an identity-block dylib carries after
//! its `LC_SUB_UMBRELLA`/`LC_SUB_LIBRARY` region (the clients dyld
//! allows to link the dylib when its linkage is restricted: each entry
//! names a requesting image by its own name).
//!
//! Gate matrix:
//! * the seam — a client name validates (non-empty, NUL-free) with the
//!   fix in the refusal, duplicates refuse (one decision per name),
//!   the command size is the 12-byte-fixed `lc_str` shape, and the
//!   table keeps flag order;
//! * layout — a named client rides the identity block right after the
//!   umbrella members (the `LC_ID_DYLIB` adjacency the M20 region
//!   pinned) and before the first load command, each with the name at
//!   the `lc_str` offset, and the region walk is exact (ncmds and
//!   sizeofcmds agree — no sizing drift);
//! * the refusals — a client off a dylib (an executable, a bundle or
//!   the relocatable output) is a layout error (the driver surface
//!   refuses earlier; the layout re-check so no library caller can
//!   plan the shape either);
//! * the lock — the default (empty) table plans what the pre-seam
//!   layout planned: no client commands, and a double link stays
//!   byte-identical (TDD §4.3);
//! * the classic path — `-no_fixup_chains` opcodes carry the clients
//!   the same way (the commands are kind-level, not fixup-level).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::sub_client::{SubClient, SubClientEntry};
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
            let carries_name = matches!(
                cmd.kind,
                pgr_format::LoadCommandKind::LoadDylib
                    | pgr_format::LoadCommandKind::ReexportDylib
                    | pgr_format::LoadCommandKind::IdDylib
                    | pgr_format::LoadCommandKind::Rpath
                    | pgr_format::LoadCommandKind::SubUmbrella
                    | pgr_format::LoadCommandKind::SubLibrary
                    | pgr_format::LoadCommandKind::SubClient
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
fn a_client_name_validates_and_keeps_flag_order() {
    let mut t = SubClient::new();
    t.push(SubClientEntry::from_flag("client.app").expect("validates"))
        .expect("first push lands");
    t.push(SubClientEntry::from_flag("/usr/bin/tool").expect("validates"))
        .expect("second push lands");
    let names: Vec<&str> = t
        .iter()
        .map(pgr_core::sub_client::SubClientEntry::name)
        .collect();
    assert_eq!(
        names,
        ["client.app", "/usr/bin/tool"],
        "the table keeps flag order"
    );
    assert_eq!(t.count(), 2);
    assert!(!t.is_empty());
}

#[test]
fn refusals_name_the_fix() {
    // An empty name is the absence of a client, not a decision.
    let err = SubClientEntry::from_flag("").expect_err("empty refuses");
    assert!(err.to_string().contains("non-empty"), "{err}");
    // The lc_str cannot carry an interior NUL.
    let err = SubClientEntry::from_flag("client\0app").expect_err("NUL refuses");
    assert!(err.to_string().contains("NUL"), "{err}");
}

#[test]
fn duplicate_clients_refuse() {
    let mut t = SubClient::new();
    t.push(SubClientEntry::from_flag("client.app").expect("validates"))
        .expect("first lands");
    let err = t
        .push(SubClientEntry::from_flag("client.app").expect("validates"))
        .expect_err("duplicate refuses");
    assert!(err.to_string().contains("client.app"), "{err}");
    assert_eq!(t.count(), 1, "the refusal left the table untouched");
}

#[test]
fn command_sizes_are_the_lc_str_shape() {
    // The 12-byte-fixed command: cmd + cmdsize + lc_str offset, name
    // inline, 8-byte aligned — the LC_RPATH shape.
    assert_eq!(
        SubClientEntry::from_flag("a")
            .expect("validates")
            .cmd_size(),
        16
    );
    assert_eq!(
        SubClientEntry::from_flag("com.example.client.app")
            .expect("validates")
            .cmd_size(),
        align8(12 + "com.example.client.app".len() + 1)
    );
    // The opcode is the vendored constant (cross-checked against the
    // `object` crate in pgr-format's own suite): the sub-command block
    // runs SUB_FRAMEWORK 0x12, SUB_UMBRELLA 0x13, SUB_CLIENT 0x14,
    // SUB_LIBRARY 0x15.
    assert_eq!(pgr_format::consts::LC_SUB_CLIENT, 0x14);
}

// ---- layout ------------------------------------------------------------------

/// The client-restricted dylib the gates link: two umbrella members and
/// two named clients — the adjacency pins clients after the region.
fn restricted_dylib_cfg() -> LinkConfig {
    let mut region = Umbrella::new();
    region
        .push(
            UmbrellaMember::from_flag(UmbrellaKind::SubUmbrella, "libsub.dylib")
                .expect("validates"),
        )
        .expect("lands");
    region
        .push(
            UmbrellaMember::from_flag(UmbrellaKind::SubLibrary, "liblegacy.dylib")
                .expect("validates"),
        )
        .expect("lands");
    let mut clients = SubClient::new();
    clients
        .push(SubClientEntry::from_flag("client.app").expect("validates"))
        .expect("lands");
    clients
        .push(SubClientEntry::from_flag("/usr/bin/tool").expect("validates"))
        .expect("lands");
    LinkConfig {
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libumbrella.dylib".into()),
        umbrella: region,
        sub_clients: clients,
        ..LinkConfig::default()
    }
}

#[test]
fn a_restricted_dylib_carries_the_clients_after_its_region() {
    let layout = link_layout(|c| *c = restricted_dylib_cfg());
    let rows = header_rows(&layout.header_bytes);
    let id_at = rows
        .iter()
        .position(|(_, k, _)| *k == pgr_format::LoadCommandKind::IdDylib)
        .expect("a dylib carries LC_ID_DYLIB");
    let sub_at = rows
        .iter()
        .position(|(_, k, _)| *k == pgr_format::LoadCommandKind::SubUmbrella)
        .expect("the M20 region emitted");
    let client_at = rows
        .iter()
        .position(|(_, k, _)| *k == pgr_format::LoadCommandKind::SubClient)
        .expect("LC_SUB_CLIENT emitted");
    let first_load = rows
        .iter()
        .position(|(_, k, _)| *k == pgr_format::LoadCommandKind::LoadDylib)
        .unwrap_or(rows.len());
    assert!(
        id_at < sub_at && sub_at < client_at && client_at < first_load,
        "the clients ride the identity block after the region: id {id_at}, sub {sub_at}, client {client_at}, first load {first_load}"
    );
    assert_eq!(rows[client_at].2.as_deref(), Some("client.app"));
    // Both client commands carry their names in flag order.
    let client_names: Vec<&str> = rows
        .iter()
        .filter(|(_, k, _)| *k == pgr_format::LoadCommandKind::SubClient)
        .filter_map(|(_, _, n)| n.as_deref())
        .collect();
    assert_eq!(client_names, ["client.app", "/usr/bin/tool"]);
    // The region walk is exact: LoadCommandIter already refuses trailing
    // bytes, so reaching here means ncmds and sizeofcmds agree.
}

#[test]
fn the_refusals_name_the_kind_that_cannot_carry_them() {
    for (kind, label) in [
        (OutputType::Execute, "executable"),
        (OutputType::Bundle, "bundle"),
        (OutputType::Relocatable, "relocatable"),
    ] {
        let mut cfg = restricted_dylib_cfg();
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
fn the_default_links_byte_identical_and_client_free() {
    // Double-link determinism with the empty table.
    let a = link_layout(|_| {});
    let b = link_layout(|_| {});
    assert_eq!(a.header_bytes, b.header_bytes, "the double link is stable");
    // And the empty table emits no client commands (the pre-M21 shape).
    let rows = header_rows(&a.header_bytes);
    assert!(
        rows.iter()
            .all(|(_, k, _)| *k != pgr_format::LoadCommandKind::SubClient),
        "the default carries no client commands"
    );
}

#[test]
fn the_classic_path_carries_the_clients_too() {
    let mut cfg = restricted_dylib_cfg();
    cfg.fixup_chains = false;
    let layout = link(&corpus(), &[], &cfg)
        .expect("the classic dylib links")
        .layout;
    let rows = header_rows(&layout.header_bytes);
    assert!(
        rows.iter()
            .any(|(_, k, _)| *k == pgr_format::LoadCommandKind::SubClient),
        "the classic opcode path still names the clients"
    );
}

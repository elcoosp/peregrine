//! M26 — the loader-path seam (`pgr_core::dylinker`): the
//! `LC_LOAD_DYLINKER` string stops being the layout's hard-coded
//! `/usr/lib/dyld` and becomes a validated decision on
//! [`pgr_core::layout::LinkConfig`] — the `-dylinker <path>` flag ld64
//! names the dynamic loader with. Dyld starts whatever the command
//! names, so the decision is *validated, not defaulted*: a non-empty,
//! NUL-free, **absolute** path (the kernel resolves the loader path
//! from the process root at exec time — a relative name is a shape the
//! loader can never consume). The default (`None`) keeps the
//! pre-M26 bytes: `/usr/lib/dyld`, spelled out byte-for-byte.
//!
//! Gate matrix:
//! * the seam — a path validates with the fix in the refusal, the
//!   command is the 12-byte-fixed `lc_str` shape (the `LC_RPATH`
//!   grammar the environment commands ride too), and one decision per
//!   link (an `Option`, not a list);
//! * layout — a named path rides `LC_LOAD_DYLINKER` before `LC_MAIN`
//!   (the §8.2 loader-configuration order: what the loader is, then
//!   where the entry lives), the region walk is exact (ncmds and
//!   sizeofcmds agree — no sizing drift when the path length moves),
//!   and the default is the hard-coded string byte-for-byte;
//! * the refusals — a named loader on a dylib, a bundle or the
//!   relocatable output is a layout error: only the main executable
//!   carries `LC_LOAD_DYLINKER` (the driver surface refuses earlier;
//!   the layout re-checks so no library caller can plan the shape
//!   either);
//! * the lock — `None` plans what the pre-seam layout planned, and the
//!   default spelled out (`/usr/lib/dyld`) is byte-identical to `None`
//!   (the knob names a *different* loader, never a re-spelling of the
//!   default);
//! * the classic path — `-no_fixup_chains` opcodes carry the named
//!   loader the same way (the command is loader-level, not
//!   fixup-level).

use pgr_core::dylinker::Dylinker;
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
                    | pgr_format::LoadCommandKind::DyldEnvironment
                    | pgr_format::LoadCommandKind::LoadDylinker
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
fn a_loader_path_validates_and_names_itself() {
    let d = Dylinker::from_flag("/usr/local/bin/mydyld").expect("an absolute path validates");
    assert_eq!(d.path(), "/usr/local/bin/mydyld");
    // The command size is the 12-byte-fixed `lc_str` shape: cmd +
    // cmdsize + lc_str offset, the path inline with its NUL, 8-byte
    // aligned — the LC_RPATH grammar (dyld reads this command through
    // the dylinker_command struct).
    assert_eq!(d.cmd_size(), align8(12 + "/usr/local/bin/mydyld".len() + 1));
    // The default spelling stays legal to name explicitly (the lock's
    // byte-identity row exercises it end to end).
    assert_eq!(
        Dylinker::from_flag("/usr/lib/dyld")
            .expect("validates")
            .cmd_size(),
        align8(12 + "/usr/lib/dyld".len() + 1)
    );
    // The opcode is the vendored constant (cross-checked against the
    // `object` crate in pgr-format's own suite).
    assert_eq!(pgr_format::consts::LC_LOAD_DYLINKER, 0xe);
}

#[test]
fn refusals_name_the_fix() {
    // An empty name names no loader — the default IS the absence of
    // the knob, so an empty `-dylinker` is a typo, not a decision.
    let err = Dylinker::from_flag("").expect_err("the empty path refuses");
    assert!(err.to_string().contains("empty"), "{err}");
    // The lc_str cannot carry an interior NUL: the C string would
    // silently truncate to a different loader.
    let err = Dylinker::from_flag("/usr/bin/dy\0ld").expect_err("NUL refuses");
    assert!(err.to_string().contains("NUL"), "{err}");
    // The kernel resolves the loader path from the process root at
    // exec time — a relative name is a shape the loader can never
    // consume (exec would refuse before dyld ever runs).
    let err = Dylinker::from_flag("bin/dyld").expect_err("a relative path refuses");
    assert!(
        err.to_string().contains("absolute") && err.to_string().contains("bin/dyld"),
        "{err}"
    );
}

// ---- layout ------------------------------------------------------------------

/// The custom-loader executable the gates link.
fn custom_loader_cfg() -> LinkConfig {
    LinkConfig {
        dylinker: Some(Dylinker::from_flag("/usr/local/bin/mydyld").expect("validates")),
        ..LinkConfig::default()
    }
}

#[test]
fn a_named_loader_rides_the_loader_configuration_adjacency() {
    let layout = link_layout(|c| *c = custom_loader_cfg());
    let rows = header_rows(&layout.header_bytes);
    let main_at = rows
        .iter()
        .position(|(_, k, _)| *k == pgr_format::LoadCommandKind::Main)
        .expect("an executable carries LC_MAIN");
    let loader_at = rows
        .iter()
        .position(|(_, k, _)| *k == pgr_format::LoadCommandKind::LoadDylinker)
        .expect("LC_LOAD_DYLINKER emitted");
    let symtab_at = rows
        .iter()
        .position(|(_, k, _)| *k == pgr_format::LoadCommandKind::Symtab)
        .expect("LC_SYMTAB emitted");
    assert!(
        loader_at < main_at && main_at < symtab_at,
        "the loader command precedes the entry command (the §8.2 adjacency: \
         what the loader is, then where the entry lives): \
         loader {loader_at}, main {main_at}, symtab {symtab_at}"
    );
    // The command carries the named path — exactly once, at the
    // lc_str offset (a longer path moves the size, never the shape).
    let named: Vec<&str> = rows
        .iter()
        .filter(|(_, k, _)| *k == pgr_format::LoadCommandKind::LoadDylinker)
        .filter_map(|(_, _, n)| n.as_deref())
        .collect();
    assert_eq!(named, ["/usr/local/bin/mydyld"], "the named loader lands");
    // The region walk is exact: LoadCommandIter already refuses
    // trailing bytes, so reaching here means ncmds and sizeofcmds
    // agree with the longer command (no sizing drift).
}

#[test]
fn the_refusals_name_the_kind_that_cannot_carry_one() {
    for (kind, label) in [
        (OutputType::Dylib, "dylib"),
        (OutputType::Bundle, "bundle"),
        (OutputType::Relocatable, "relocatable"),
    ] {
        let mut cfg = custom_loader_cfg();
        cfg.filetype = kind;
        let err = link(&corpus(), &[], &cfg).expect_err("the shape refuses");
        assert!(
            err.to_string().contains(label),
            "the refusal names the output kind ({label}): {err}"
        );
    }
}

// ---- the lock ----------------------------------------------------------------

#[test]
fn the_default_links_byte_identical_and_the_default_spelling_agrees() {
    // Double-link determinism with the unset knob.
    let a = link_layout(|_| {});
    let b = link_layout(|_| {});
    assert_eq!(a.header_bytes, b.header_bytes, "the double link is stable");
    // The default carries the hard-coded string (the pre-M26 shape).
    let rows = header_rows(&a.header_bytes);
    let default: Vec<&str> = rows
        .iter()
        .filter(|(_, k, _)| *k == pgr_format::LoadCommandKind::LoadDylinker)
        .filter_map(|(_, _, n)| n.as_deref())
        .collect();
    assert_eq!(
        default,
        ["/usr/lib/dyld"],
        "the default names the loader it always named"
    );
    // The lock: naming the default explicitly is byte-identical to not
    // naming it — the knob names a different loader, never a
    // re-spelling of the default.
    let explicit = link_layout(|c| {
        c.dylinker = Some(Dylinker::from_flag("/usr/lib/dyld").expect("validates"));
    });
    assert_eq!(
        a.header_bytes, explicit.header_bytes,
        "/usr/lib/dyld spelled out plans the pre-seam bytes"
    );
}

#[test]
fn the_classic_path_carries_the_named_loader_too() {
    // `-no_fixup_chains` opcodes are fixup-level; the loader command is
    // loader-level — both paths plan the named string.
    let mut cfg = custom_loader_cfg();
    cfg.fixup_chains = false;
    let layout = link(&corpus(), &[], &cfg)
        .expect("the classic-path corpus links")
        .layout;
    let rows = header_rows(&layout.header_bytes);
    let named: Vec<&str> = rows
        .iter()
        .filter(|(_, k, _)| *k == pgr_format::LoadCommandKind::LoadDylinker)
        .filter_map(|(_, _, n)| n.as_deref())
        .collect();
    assert_eq!(
        named,
        ["/usr/local/bin/mydyld"],
        "the classic path names the loader too"
    );
}

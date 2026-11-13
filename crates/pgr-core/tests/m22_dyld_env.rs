//! M22 — the dyld-environment seam (`pgr_core::dyld_env`): the
//! `-dyld_env DYLD_<var>=<value>` decisions stop being unnameable and
//! become a validated table on [`pgr_core::layout::LinkConfig`] — the
//! `LC_DYLD_ENVIRONMENT` commands an executable carries so dyld starts
//! the image with the named variables set (the loader-configuration
//! command dyld reads from the main executable only).
//!
//! Gate matrix:
//! * the seam — a pair validates (`DYLD_`-prefixed variable, one `=`
//!   separator, NUL-free) with the fix in the refusal, a repeated
//!   variable refuses (one decision per variable), the command size is
//!   the 12-byte-fixed `lc_str` shape (the `LC_RPATH` grammar), and the
//!   table keeps flag order;
//! * layout — a named pair rides the loader-configuration adjacency
//!   right after `LC_MAIN` and before `LC_SYMTAB`, each with the pair
//!   at the `lc_str` offset, and the region walk is exact (ncmds and
//!   sizeofcmds agree — no sizing drift);
//! * the refusals — an environment command off an executable (a dylib,
//!   a bundle or the relocatable output) is a layout error: dyld reads
//!   the command from the main executable only (the driver surface
//!   refuses earlier; the layout re-check so no library caller can plan
//!   the shape either);
//! * the lock — the default (empty) table plans what the pre-seam
//!   layout planned: no environment commands, and a double link stays
//!   byte-identical (TDD §4.3);
//! * the classic path — `-no_fixup_chains` opcodes carry the pairs the
//!   same way (the commands are loader-level, not fixup-level).

use pgr_core::dyld_env::{DyldEnv, DyldEnvEntry};
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
fn an_env_pair_validates_and_keeps_flag_order() {
    let mut t = DyldEnv::new();
    t.push(DyldEnvEntry::from_flag("DYLD_PRINT_LIBRARIES=1").expect("validates"))
        .expect("first push lands");
    t.push(DyldEnvEntry::from_flag("DYLD_PRINT_RPATHS=1").expect("validates"))
        .expect("second push lands");
    let pairs: Vec<&str> = t.iter().map(DyldEnvEntry::pair).collect();
    assert_eq!(
        pairs,
        ["DYLD_PRINT_LIBRARIES=1", "DYLD_PRINT_RPATHS=1"],
        "the table keeps flag order"
    );
    assert_eq!(t.count(), 2);
    assert!(!t.is_empty());
    // The split is re-derivable: the variable rides the first `=`.
    let e = DyldEnvEntry::from_flag("DYLD_PRINT_PATHS=a=b").expect("validates");
    assert_eq!(e.var(), "DYLD_PRINT_PATHS");
    assert_eq!(e.value(), "a=b");
}

#[test]
fn refusals_name_the_fix() {
    // No `=` is not a pair — the grammar names itself.
    let err = DyldEnvEntry::from_flag("DYLD_PRINT_LIBRARIES").expect_err("no = refuses");
    assert!(err.to_string().contains("DYLD_"), "{err}");
    // dyld honors `DYLD_`-prefixed variables from this command only —
    // anything else would be a silently dropped knob.
    let err = DyldEnvEntry::from_flag("PATH=/bin").expect_err("the prefix refuses");
    assert!(err.to_string().contains("DYLD_"), "{err}");
    // `DYLD_` alone names no variable.
    let err = DyldEnvEntry::from_flag("DYLD_=x").expect_err("an empty variable refuses");
    assert!(err.to_string().contains("DYLD_"), "{err}");
    // The lc_str cannot carry an interior NUL.
    let err = DyldEnvEntry::from_flag("DYLD_A=a\0b").expect_err("NUL refuses");
    assert!(err.to_string().contains("NUL"), "{err}");
}

#[test]
fn duplicate_variables_refuse() {
    let mut t = DyldEnv::new();
    t.push(DyldEnvEntry::from_flag("DYLD_PRINT_LIBRARIES=1").expect("validates"))
        .expect("first lands");
    let err = t
        .push(DyldEnvEntry::from_flag("DYLD_PRINT_LIBRARIES=0").expect("validates"))
        .expect_err("duplicate refuses");
    assert!(err.to_string().contains("DYLD_PRINT_LIBRARIES"), "{err}");
    assert_eq!(t.count(), 1, "the refusal left the table untouched");
}

#[test]
fn command_sizes_are_the_lc_str_shape() {
    // The 12-byte-fixed command: cmd + cmdsize + lc_str offset, the
    // pair inline with its NUL, 8-byte aligned — the LC_RPATH shape
    // (dyld reads this command through the dylinker_command struct).
    assert_eq!(
        DyldEnvEntry::from_flag("DYLD_A=1")
            .expect("validates")
            .cmd_size(),
        24
    );
    assert_eq!(
        DyldEnvEntry::from_flag("DYLD_PRINT_LIBRARIES=1")
            .expect("validates")
            .cmd_size(),
        align8(12 + "DYLD_PRINT_LIBRARIES=1".len() + 1)
    );
    // The opcode is the vendored constant (cross-checked against the
    // `object` crate in pgr-format's own suite).
    assert_eq!(pgr_format::consts::LC_DYLD_ENVIRONMENT, 0x27);
}

// ---- layout ------------------------------------------------------------------

/// The environment-configured executable the gates link: two named
/// variables in flag order.
fn env_exec_cfg() -> LinkConfig {
    let mut env = DyldEnv::new();
    env.push(DyldEnvEntry::from_flag("DYLD_PRINT_LIBRARIES=1").expect("validates"))
        .expect("lands");
    env.push(DyldEnvEntry::from_flag("DYLD_PRINT_RPATHS=1").expect("validates"))
        .expect("lands");
    LinkConfig {
        dyld_envs: env,
        ..LinkConfig::default()
    }
}

#[test]
fn a_configured_executable_carries_the_commands_after_lc_main() {
    let layout = link_layout(|c| *c = env_exec_cfg());
    let rows = header_rows(&layout.header_bytes);
    let main_at = rows
        .iter()
        .position(|(_, k, _)| *k == pgr_format::LoadCommandKind::Main)
        .expect("an executable carries LC_MAIN");
    let env_at = rows
        .iter()
        .position(|(_, k, _)| *k == pgr_format::LoadCommandKind::DyldEnvironment)
        .expect("LC_DYLD_ENVIRONMENT emitted");
    let symtab_at = rows
        .iter()
        .position(|(_, k, _)| *k == pgr_format::LoadCommandKind::Symtab)
        .expect("LC_SYMTAB emitted");
    assert!(
        main_at < env_at && env_at < symtab_at,
        "the environment commands ride the loader-configuration adjacency \
         after LC_MAIN: main {main_at}, env {env_at}, symtab {symtab_at}"
    );
    // Both commands carry their pairs in flag order.
    let pairs: Vec<&str> = rows
        .iter()
        .filter(|(_, k, _)| *k == pgr_format::LoadCommandKind::DyldEnvironment)
        .filter_map(|(_, _, n)| n.as_deref())
        .collect();
    assert_eq!(
        pairs,
        ["DYLD_PRINT_LIBRARIES=1", "DYLD_PRINT_RPATHS=1"],
        "the pairs land in flag order"
    );
    // The region walk is exact: LoadCommandIter already refuses trailing
    // bytes, so reaching here means ncmds and sizeofcmds agree.
}

#[test]
fn the_refusals_name_the_kind_that_cannot_carry_them() {
    for (kind, label) in [
        (OutputType::Dylib, "dylib"),
        (OutputType::Bundle, "bundle"),
        (OutputType::Relocatable, "relocatable"),
    ] {
        let mut cfg = env_exec_cfg();
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
fn the_default_links_byte_identical_and_env_free() {
    // Double-link determinism with the empty table.
    let a = link_layout(|_| {});
    let b = link_layout(|_| {});
    assert_eq!(a.header_bytes, b.header_bytes, "the double link is stable");
    // And the empty table emits no environment commands (the pre-M22 shape).
    let rows = header_rows(&a.header_bytes);
    assert!(
        rows.iter()
            .all(|(_, k, _)| *k != pgr_format::LoadCommandKind::DyldEnvironment),
        "the default carries no environment commands"
    );
}

#[test]
fn the_classic_path_carries_the_envs_too() {
    let mut cfg = env_exec_cfg();
    cfg.fixup_chains = false;
    let layout = link(&corpus(), &[], &cfg)
        .expect("the classic executable links")
        .layout;
    let rows = header_rows(&layout.header_bytes);
    assert!(
        rows.iter()
            .any(|(_, k, _)| *k == pgr_format::LoadCommandKind::DyldEnvironment),
        "the classic opcode path still exports the variables"
    );
}

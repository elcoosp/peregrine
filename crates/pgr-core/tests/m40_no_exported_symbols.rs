//! M40 — the export-trie suppression (`-no_exported_symbols`): the last
//! always-carried `__LINKEDIT` command the surface could not name —
//! `LC_DYLD_EXPORTS_TRIE`, hard-wired into the header assembly since
//! M2 — drops on the named decision. ld64's flag saves the export-trie
//! build and its `__LINKEDIT` slot on an image nothing binds against
//! through it (a main executable exports for `dlsym`/debuggers only;
//! its dylib partners bind *into* their own tries, never the exe's).
//!
//! Gate matrix:
//! * the lock — the default (`true`) plans the pre-M40 bytes exactly
//!   (the same header bytes, the same trie chunk);
//! * the suppression — the command drops (`ncmds` −1, `sizeofcmds`
//!   −16), the `__LINKEDIT` trie chunk empties (`trie_off == 0`, the
//!   absent-sentinel convention every `__LINKEDIT` offset field
//!   shares), the plan's trie bytes ride empty, and the image still
//!   sizes/signs (the symtab, the function starts and the signature
//!   keep their slots);
//! * the classic path — `-no_fixup_chains` plans the same suppression
//!   (the trie command is the export surface, not a fixups artifact);
//! * the refusals — a dylib refuses (its trie *is* the two-level
//!   contract its clients bind through), a bundle refuses (the
//!   dlopen/`dlsym` surface), the relocatable output refuses (no
//!   `__LINKEDIT` commands at all), and a link carrying re-export
//!   dylibs refuses (the REEXPORT nodes ride the trie — dropping the
//!   trie silently breaks the re-export contract);
//! * the neighbors — the suppression composes with `-no_uuid` and
//!   `-no_function_starts` (the whole always-carried family names
//!   itself off in one link).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, LinkResult, Parallelism, link, link_reloc};
use pgr_core::resolve::Dylib;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// `_main` (RET) with a second defined external (`_f`) — the trie
/// carries both, the suppression drops the command.
fn corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2), // ret; ret
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_f".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    vec![LinkInput {
        name: b.name().to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

fn suppressed(tweak: impl FnOnce(&mut LinkConfig)) -> LinkConfig {
    let mut cfg = LinkConfig {
        exported_symbols: false,
        ..LinkConfig::default()
    };
    tweak(&mut cfg);
    cfg
}

fn link_cfg(cfg: &LinkConfig) -> LinkResult {
    link(&corpus(), &[], cfg).expect("the link plans")
}

/// Whether the image's header carries `LC_DYLD_EXPORTS_TRIE`.
fn carries_trie_command(res: &LinkResult) -> bool {
    let bytes = &res.layout.header_bytes;
    let header = pgr_format::MachHeader64::parse(bytes).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind
            == pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_EXPORTS_TRIE)
        {
            return true;
        }
    }
    false
}

// ---- the lock -----------------------------------------------------------------

#[test]
fn the_default_plans_the_pre_m40_bytes() {
    let plain = link_cfg(&LinkConfig::default());
    let kept = link_cfg(&LinkConfig {
        exported_symbols: true,
        ..LinkConfig::default()
    });
    assert_eq!(
        plain.layout.header_bytes, kept.layout.header_bytes,
        "the default *is* the kept trie — the same header bytes"
    );
    assert_eq!(plain.layout.trie, kept.layout.trie);
    assert_eq!(
        plain.layout.linkedit.trie_size,
        kept.layout.linkedit.trie_size
    );
    assert!(
        plain.layout.linkedit.trie_size > 0,
        "the trie rides by default"
    );
}

// ---- the suppression ----------------------------------------------------------

#[test]
fn the_suppression_drops_the_command_and_the_chunk() {
    let full = link_cfg(&LinkConfig::default());
    let bare = link_cfg(&suppressed(|_| {}));

    assert!(
        !carries_trie_command(&bare),
        "LC_DYLD_EXPORTS_TRIE drops on the named decision"
    );
    assert!(
        carries_trie_command(&full),
        "the default carries the command (the pre-M40 shape)"
    );
    assert_eq!(
        bare.layout.header_bytes.len() + 16,
        full.layout.header_bytes.len(),
        "sizeofcmds is 16 bytes narrower (one linkedit-data command)"
    );
    assert_eq!(
        bare.layout.trie,
        Vec::new(),
        "the trie bytes ride empty — the build never runs"
    );
    assert_eq!(
        bare.layout.linkedit.trie_off, 0,
        "the absent-sentinel convention (the __LINKEDIT offset field)"
    );
    assert_eq!(bare.layout.linkedit.trie_size, 0);
    // The neighbors keep their slots: the symtab and function starts
    // still ride, and the file shrinks past the command slot (the
    // ad-hoc signature's blob tail re-sizes with the LINKEDIT it
    // covers, so the exact delta rides the page-hash boundary).
    assert!(
        bare.layout.linkedit.sym_size > 0,
        "the symtab is not the trie's neighbor-victim"
    );
    assert!(full.layout.file_size - bare.layout.file_size >= 16);
}

#[test]
fn the_classic_path_suppresses_too() {
    let bare = link_cfg(&suppressed(|cfg| {
        cfg.fixup_chains = false;
    }));
    assert!(
        !carries_trie_command(&bare),
        "the export surface is not a fixups artifact — the classic path drops it too"
    );
    assert_eq!(bare.layout.trie, Vec::new());
}

#[test]
fn the_suppression_composes_with_the_suppression_family() {
    let bare = link_cfg(&suppressed(|cfg| {
        cfg.uuid = false;
        cfg.function_starts = false;
    }));
    assert!(
        !carries_trie_command(&bare),
        "the trie drops beside its family"
    );
    // 16 (the trie) + 24 (LC_UUID) + 16 (LC_FUNCTION_STARTS) narrower.
    assert_eq!(
        bare.layout.header_bytes.len() + 56,
        link_cfg(&LinkConfig::default()).layout.header_bytes.len(),
        "the whole always-carried family names itself off in one link"
    );
}

// ---- the refusals ---------------------------------------------------------------

fn f_dylib(reexport: bool) -> Dylib {
    Dylib {
        install_name: "@rpath/libf.dylib".to_string(),
        current_version: 0,
        compatibility_version: 0,
        exports: vec![b"_f".to_vec()],
        weak: false,
        lazy: false,
        reexport,
    }
}

#[test]
fn a_dylib_refuses_the_knob() {
    let err = link(
        &corpus(),
        &[],
        &suppressed(|cfg| {
            cfg.filetype = OutputType::Dylib;
            cfg.install_name = Some("@rpath/libout.dylib".into());
        }),
    )
    .expect_err("a dylib's trie IS the two-level contract");
    let msg = err.to_string();
    assert!(msg.contains("dylib"), "{msg}");
    assert!(
        msg.contains("-no_exported_symbols"),
        "{msg} — the fix names the flag"
    );
}

#[test]
fn a_bundle_refuses_the_knob() {
    let err = link(
        &corpus(),
        &[],
        &suppressed(|cfg| {
            cfg.filetype = OutputType::Bundle;
        }),
    )
    .expect_err("a bundle's dlopen/dlsym surface rides the trie");
    let msg = err.to_string();
    assert!(msg.contains("bundle"), "{msg}");
}

#[test]
fn the_relocatable_output_refuses_the_knob() {
    let err = link_reloc(&corpus(), &[], &suppressed(|_| {}), Parallelism::Auto)
        .expect_err("the -r output carries no __LINKEDIT commands");
    let msg = err.to_string();
    assert!(msg.contains("-no_exported_symbols"), "{msg}");
}

#[test]
fn a_reexport_dylib_refuses_the_knob() {
    let err = link(
        &corpus(),
        &[],
        &suppressed(|cfg| {
            cfg.dylibs = vec![f_dylib(true)];
        }),
    )
    .expect_err("REEXPORT nodes ride the trie — the contract cannot survive the drop");
    let msg = err.to_string();
    assert!(
        msg.contains("re-export") || msg.contains("reexport") || msg.contains("REEXPORT"),
        "{msg}"
    );
}

// ---- the neighbors ---------------------------------------------------------------

#[test]
fn the_plain_export_surface_is_untouched() {
    // The re-export *dylib load itself* (without the suppression) keeps
    // its REEXPORT trie nodes — the refusal is the suppression's, not
    // the re-export carriage's.
    let res = link(
        &corpus(),
        &[],
        &LinkConfig {
            dylibs: vec![f_dylib(true)],
            ..LinkConfig::default()
        },
    )
    .expect("the re-export carriage rides on");
    let exports = pgr_format::trie::exports(&res.layout.trie).expect("the trie walks");
    assert!(
        exports.iter().any(|e| e.name == b"_f"),
        "the re-export node rides the trie"
    );
}

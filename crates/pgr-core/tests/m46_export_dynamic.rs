//! M46 — the export-dynamic roots released: `-export_dynamic` — ld64's
//! liveness rule, *"Preserves all global symbols in main executables
//! during dead stripping"* (the `ld` man page) — is the Pass-2/5
//! decision the dead-strip root set reads: every global definition
//! (an `N_SECT` def or a common) roots the mark phase, so a
//! plugin-style main executable keeps its unreferenced entry points
//! (`dlsym` is a runtime contract the static fixpoint cannot see). The
//! default (`false`) keeps every pre-M46 link byte-identical; the knob
//! is an executable decision — a dylib's and a bundle's strip already
//! roots every definition, and the relocatable output strips nothing
//! (its symbol table is the input's, verbatim) — so all three refuse
//! the knob with the fix.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// hello.o: `_main` calls `_live` (BL) and returns; `_dead_hook` is a
/// global definition nothing references (the `dlsym` shape). The
/// fixture's symtab groups defs before undefineds, so the reloc's
/// `r_symbolnum` names the *final* index (`_main` 0, `_dead_hook` 1
/// when present, `_live` last).
fn plugin_main(dead: bool) -> Vec<u8> {
    // _main: bl _live; ret. _dead_hook: ret — defined, exported, never
    // referenced.
    let mut text: Vec<u8> = [0x9400_0000u32, 0xD65F_03C0u32]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    if dead {
        // _dead_hook: ret — defined, exported, never referenced.
        text.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
    }
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let main_idx = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    let _ = main_idx;
    if dead {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_dead_hook".into(),
            section_index: sect,
            value: 8,
            weak: false,
        });
    }
    let live_idx = b.add_symbol(ObjectSymbol::Undefined {
        name: "_live".into(),
        weak_ref: false,
    });
    b.section_mut(sect)
        .relocs
        .push(ObjectReloc::branch26(u32::try_from(live_idx).unwrap()).at(0));
    b.build().expect("the fixture object builds")
}

/// greet.o: `_live` body + `_main` (the reference's target).
fn greet() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![
            0x91, 0x00, 0x00, 0x00, // add x0, x0, #0 (placeholder imm12)
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_live".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Links the corpus with the named decisions and returns the layout.
fn link_image(cfg: &LinkConfig, dead: bool) -> pgr_core::layout::Layout {
    link(
        &[
            LinkInput {
                name: "hello.o".into(),
                bytes: plugin_main(dead),
            },
            LinkInput {
                name: "greet.o".into(),
                bytes: greet(),
            },
        ],
        &[],
        cfg,
    )
    .expect("the link plans")
    .layout
}

/// The image's exported symbol names (the export trie's terminal names).
fn exported_names(layout: &pgr_core::layout::Layout) -> Vec<Vec<u8>> {
    pgr_format::trie::exports(&layout.trie)
        .expect("the trie walks")
        .into_iter()
        .map(|exp| exp.name)
        .collect()
}

#[test]
fn the_default_strips_the_dead_global() {
    // Pre-M46 shape: with `-dead_strip` alone, `_dead_hook` is a global
    // definition nothing references — the mark phase never reaches it,
    // the symtab row and the trie node drop with the body.
    let cfg = LinkConfig {
        ident: "hello".into(),
        dead_strip: true,
        ..LinkConfig::default()
    };
    let layout = link_image(&cfg, true);
    assert!(
        !exported_names(&layout).iter().any(|n| n == b"_dead_hook"),
        "the unreferenced global strips by default"
    );
}

#[test]
fn export_dynamic_roots_every_global_definition() {
    // The named decision: `_dead_hook` ships — the definition is a
    // root, the symtab row and the trie node ride it (the `dlsym`
    // surface the static fixpoint cannot see).
    let cfg = LinkConfig {
        ident: "hello".into(),
        dead_strip: true,
        export_dynamic: true,
        ..LinkConfig::default()
    };
    let layout = link_image(&cfg, true);
    assert!(
        exported_names(&layout).iter().any(|n| n == b"_dead_hook"),
        "the unreferenced global ships under -export_dynamic"
    );
    // The body really shipped: the __text section grew past the
    // two-instruction _main/_live pair.
    let text = layout
        .sections
        .iter()
        .find(|s| s.name == "__text")
        .expect("the __text section plans");
    assert!(text.size >= 12, "the kept body rides __text: {}", text.size);
}

#[test]
fn the_default_without_the_knob_is_byte_identical() {
    // The M46 lock: a corpus with no dead globals plans the same bytes
    // under either decision — the widened root set roots nothing new.
    let plain = LinkConfig {
        ident: "hello".into(),
        dead_strip: true,
        ..LinkConfig::default()
    };
    let widened = LinkConfig {
        ident: "hello".into(),
        dead_strip: true,
        export_dynamic: true,
        ..LinkConfig::default()
    };
    let a = link_image(&plain, false);
    let b = link_image(&widened, false);
    assert_eq!(a.file_size, b.file_size, "the file size holds");
    assert_eq!(
        a.segments.len(),
        b.segments.len(),
        "the segment shape holds"
    );
    for (sa, sb) in a.segments.iter().zip(b.segments.iter()) {
        assert_eq!(sa.vmaddr, sb.vmaddr, "{} holds its address", sa.name);
        assert_eq!(sa.vmsize, sb.vmsize, "{} holds its size", sa.name);
        assert_eq!(sa.fileoff, sb.fileoff, "{} holds its offset", sa.name);
    }
}

#[test]
fn export_dynamic_refuses_on_the_relocatable_output() {
    // The relocatable output strips nothing (its symbol table is the
    // input's, verbatim) — the knob has nothing to root. The re-check
    // backs the driver surface's earlier refusal: no library caller
    // can plan the shape either.
    let cfg = LinkConfig {
        ident: "hello".into(),
        filetype: OutputType::Relocatable,
        dead_strip: true,
        export_dynamic: true,
        ..LinkConfig::default()
    };
    let err = link_reloc(
        &[LinkInput {
            name: "hello.o".into(),
            bytes: plugin_main(true),
        }],
        &[],
        &cfg,
        Parallelism::Auto,
    )
    .expect_err("the relocatable output refuses the knob");
    assert!(
        err.to_string().contains("-export_dynamic"),
        "the refusal names the knob: {err}"
    );
}

#[test]
fn export_dynamic_refuses_on_dylibs_and_bundles() {
    // A dylib's and a bundle's strip already roots every definition
    // (the export surface is the contract) — the knob is vacuous there,
    // and a vacuous named decision refuses with the fix, never a
    // silently dropped one.
    for kind in [OutputType::Dylib, OutputType::Bundle] {
        let cfg = LinkConfig {
            ident: "lib".into(),
            filetype: kind,
            install_name: Some("@rpath/lib.dylib".into()),
            dead_strip: true,
            export_dynamic: true,
            ..LinkConfig::default()
        };
        let err = link(
            &[
                LinkInput {
                    name: "hello.o".into(),
                    bytes: plugin_main(true),
                },
                LinkInput {
                    name: "greet.o".into(),
                    bytes: greet(),
                },
            ],
            &[],
            &cfg,
        )
        .expect_err("the non-executable output refuses the knob");
        assert!(
            err.to_string().contains("-export_dynamic"),
            "the refusal names the knob: {err}"
        );
    }
}

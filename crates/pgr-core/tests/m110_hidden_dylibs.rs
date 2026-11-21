//! M110 — the hidden-dylib mark (`-hidden_library` / `-hidden_framework`
//! / `-hidden-l`): ld64's "hidden" loads, the other half of the
//! load-command contract. The dylib is parsed and its exports enter the
//! resolve arena (the same scan path as `-weak_library`/`-lazy_library`),
//! but the header assembly drops its load command: no `LC_LOAD_DYLIB`, no
//! `LC_LOAD_WEAK_DYLIB`. The two-level ordinal space does not name it (a
//! hidden dylib takes no ordinal; the emitted command list stays
//! contiguous onto the ordinals), and the chained-fixups import table
//! does not name it. A weak reference resolved against a hidden export
//! rides the flat-lookup slot (the M103 dynamic-lookup shape); a strong
//! one refuses the link with the fix (dyld cannot bind it without the
//! load command). The re-export obligation refuses the hidden mark (its
//! trie nodes name a provider dyld must load), and the relocatable output
//! refuses the knob (the object carries no load commands).
//!
//! Gate matrix:
//! * the command drop — a hidden dylib rides no load command (the
//!   `ncmds`/`sizeofcmds` arithmetic follows);
//! * the ordinal space — the visible dylibs' ordinals stay contiguous
//!   onto the emitted command list (a hidden survivor between two
//!   visible ones shifts nothing);
//! * the weak ride — a weak reference to a hidden export binds flat
//!   (`BIND_SPECIAL_DYLIB_FLAT_LOOKUP` + the weak bit), the image
//!   verifies strict;
//! * the strong refusal — a strong reference to a hidden export
//!   refuses with the hidden dylib named;
//! * the import table — the hidden exports never enter it (no import
//!   row, no ordinal);
//! * the composition — hidden beside a visible dylib; hidden + needed
//!   under `-dead_strip_dylibs` (the visible ordinals compact onto the
//!   kept command order);
//! * the re-export refusal — the obligation outranks the mark;
//! * the relocatable refusal — `link_reloc` refuses the mark.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_core::resolve::Dylib;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// An object whose `__data` carries one rebase-style bind slot per named
/// undefined (`_main` over a two-function `__text`).
fn caller(name: &str, refs: &[(&str, bool)]) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: if name == "a.o" {
            "_main".into()
        } else {
            format!("_{name}_fn")
        },
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 8 * refs.len()],
        vec![],
    ));
    for (i, (r, weak)) in refs.iter().enumerate() {
        let undef = b.add_symbol(ObjectSymbol::Undefined {
            name: (*r).into(),
            weak_ref: *weak,
        });
        let slot = b.sym_index(undef);
        b.section_mut(data)
            .relocs
            .push(ObjectReloc::unsigned(slot).at((i * 8) as u32));
    }
    b.build().expect("the fixture object builds")
}

fn dylib(install_name: &str, exports: &[&str]) -> Dylib {
    Dylib {
        install_name: install_name.to_string(),
        current_version: 0,
        compatibility_version: 0,
        exports: exports.iter().map(|e| e.as_bytes().to_vec()).collect(),
        weak: false,
        lazy: false,
        upward: false,
        reexport: false,
        needed: false,
        hidden: false,
    }
}

fn corpus(bytes: Vec<u8>) -> Vec<LinkInput> {
    vec![LinkInput {
        name: "a.o".to_string(),
        bytes,
    }]
}

/// Links the corpus under `tweak`; returns the full Pass 1–3 result.
fn plan(
    bytes: Vec<u8>,
    dylibs: Vec<Dylib>,
    tweak: impl FnOnce(&mut LinkConfig),
) -> pgr_core::link::LinkResult {
    let mut cfg = LinkConfig {
        dylibs,
        ..LinkConfig::default()
    };
    tweak(&mut cfg);
    link(&corpus(bytes), &[], &cfg).expect("the corpus links")
}

/// The header's dylib commands: `(opcode, install name)` in command order.
fn dylib_commands(image: &[u8]) -> Vec<(u32, String)> {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut out = Vec::new();
    while let Ok(Some(cmd)) = it.next_command() {
        if matches!(
            cmd.kind,
            pgr_format::LoadCommandKind::LoadDylib | pgr_format::LoadCommandKind::ReexportDylib
        ) {
            let opcode = u32::from_le_bytes(cmd.bytes[0..4].try_into().expect("the opcode"));
            let name = pgr_format::DylibCommand::parse(cmd.bytes)
                .ok()
                .and_then(|c| c.name(cmd.bytes).ok())
                .map(|n| {
                    String::from_utf8_lossy(n)
                        .trim_end_matches('\0')
                        .to_string()
                });
            if let Some(name) = name {
                out.push((opcode, name));
            }
        }
    }
    out
}

/// The fixup plan's import table: `(lib ordinal, name, weak)` rows, in
/// first-use order — the two-level contract the header's commands and
/// the ordinals must agree on.
fn imports(result: &pgr_core::link::LinkResult) -> Vec<(u16, String, bool)> {
    result
        .layout
        .fixups
        .imports
        .iter()
        .map(|imp| {
            let name = result
                .layout
                .fixups
                .import_names
                .get(imp.name_offset as usize..)
                .and_then(|rest| rest.split(|&b| b == 0).next())
                .unwrap_or(&[]);
            (
                imp.lib_ordinal,
                String::from_utf8_lossy(name).to_string(),
                imp.weak_import,
            )
        })
        .collect()
}

// ---- the gate matrix ---------------------------------------------------------

#[test]
fn the_hidden_dylib_rides_no_load_command() {
    // The mark's own contract: the dylib's exports resolve but no
    // `LC_LOAD_DYLIB` (nor any other dylib command) rides — the ncmds/
    // sizeofcmds arithmetic follows the emitted list.
    let bytes = caller("a.o", &[("_visible", false), ("_hidden_fn", true)]);
    let visible = dylib("@rpath/libvisible.dylib", &["_visible"]);
    let mut hidden = dylib("@rpath/libhidden.dylib", &["_hidden_fn"]);
    hidden.hidden = true;
    let result = plan(bytes, vec![visible, hidden], |_c| {});
    let cmds = dylib_commands(&result.layout.header_bytes);
    assert_eq!(
        cmds,
        vec![(
            pgr_format::consts::LC_LOAD_DYLIB,
            "@rpath/libvisible.dylib".to_string()
        )],
        "the hidden dylib rides no load command: {cmds:?}"
    );
}

#[test]
fn the_visible_ordinals_stay_contiguous_past_a_hidden_slot() {
    // The two-level ordinal space does not name the hidden dylib: the
    // second visible dylib's bind names ordinal 2 (its emitted command
    // position), never the list slot 3 a hidden survivor would have
    // shifted it to.
    let bytes = caller("a.o", &[("_second", false)]);
    let first = dylib("@rpath/libfirst.dylib", &["_first"]);
    let mut hidden = dylib("@rpath/libhidden.dylib", &["_hidden_fn"]);
    hidden.hidden = true;
    let second = dylib("@rpath/libsecond.dylib", &["_second"]);
    let result = plan(bytes, vec![first, hidden, second], |_c| {});
    let cmds = dylib_commands(&result.layout.header_bytes);
    let names: Vec<&str> = cmds.iter().map(|(_, n)| n.as_str()).collect();
    assert_eq!(
        names,
        vec!["@rpath/libfirst.dylib", "@rpath/libsecond.dylib"],
        "the hidden dylib rides no command; the visible order is unchanged"
    );
    let imps = imports(&result);
    assert_eq!(
        imps,
        vec![(2u16, "_second".to_string(), false)],
        "the bind names ordinal 2 — the hidden dylib's list slot shifted nothing"
    );
}

#[test]
fn the_weak_reference_to_a_hidden_export_rides_the_flat_lookup_slot() {
    // The M103 shape one seam over: a weak reference resolved against a
    // hidden dylib's export rides `BIND_SPECIAL_DYLIB_FLAT_LOOKUP` with
    // the weak bit (dyld looks the name up at runtime); the image
    // verifies strict.
    let bytes = caller("a.o", &[("_hidden_fn", true)]);
    let mut hidden = dylib("@rpath/libhidden.dylib", &["_hidden_fn"]);
    hidden.hidden = true;
    let result = plan(bytes, vec![hidden], |_c| {});
    let imps = imports(&result);
    assert_eq!(
        imps.len(),
        1,
        "one import row — the hidden dylib named nothing: {imps:?}"
    );
    assert_eq!(
        imps[0].0,
        pgr_format::consts::BIND_SPECIAL_DYLIB_FLAT_LOOKUP,
        "the weak bind rides the flat-lookup slot (no two-level ordinal exists): {imps:?}"
    );
    assert_eq!(imps[0].1, "_hidden_fn", "the name is the hidden export");
}

#[test]
fn the_strong_reference_to_a_hidden_export_refuses_with_the_fix() {
    // dyld cannot bind a strong reference without the load command the
    // mark drops: the default `-undefined error` policy refuses with
    // the hidden dylib named and the surface fix spoken.
    let bytes = caller("a.o", &[("_hidden_fn", false)]);
    let mut hidden = dylib("@rpath/libhidden.dylib", &["_hidden_fn"]);
    hidden.hidden = true;
    let cfg = LinkConfig {
        dylibs: vec![hidden],
        ..LinkConfig::default()
    };
    let err = link(&corpus(bytes), &[], &cfg).expect_err("the strong bind refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("hidden dylib"),
        "the refusal names its lane: {msg}"
    );
    assert!(
        msg.contains("@rpath/libhidden.dylib"),
        "the refusal names the provider: {msg}"
    );
    assert!(
        msg.contains("-hidden_library"),
        "the refusal names the fix: {msg}"
    );
}

#[test]
fn the_hidden_export_never_enters_the_two_level_map() {
    // A name both dylibs export: the hidden one takes no ordinal, the
    // visible one serves the bind (the first non-hidden dylib in
    // command order wins — the pre-M110 rule over the visible list).
    let bytes = caller("a.o", &[("_both", false)]);
    let mut hidden = dylib("@rpath/libhidden.dylib", &["_both"]);
    hidden.hidden = true;
    let visible = dylib("@rpath/libvisible.dylib", &["_both"]);
    let result = plan(bytes, vec![hidden, visible], |_c| {});
    let imps = imports(&result);
    assert_eq!(
        imps,
        vec![(1u16, "_both".to_string(), false)],
        "the visible dylib (ordinal 1) serves the bind; the hidden one takes no ordinal"
    );
}

#[test]
fn the_drop_compacts_the_visible_ordinals_onto_the_kept_order() {
    // Under `-dead_strip_dylibs` a hidden dylib always drops (no
    // command, and dyld's flat lookup cannot reach an image the
    // process never loaded); the visible survivors' ordinals compact
    // onto the kept command order — a hidden needed mark beside them
    // shifts nothing.
    let bytes = caller("a.o", &[("_used", false), ("_after", false)]);
    let used = dylib("@rpath/libused.dylib", &["_used"]);
    let mut hidden_needed = dylib("@rpath/libhidden.dylib", &["_hidden_fn"]);
    hidden_needed.hidden = true;
    hidden_needed.needed = true;
    let mut after = dylib("@rpath/libafter.dylib", &["_after"]);
    after.needed = true;
    let result = plan(bytes, vec![used, hidden_needed, after], |c| {
        c.dead_strip_dylibs = true;
    });
    let cmds = dylib_commands(&result.layout.header_bytes);
    let names: Vec<&str> = cmds.iter().map(|(_, n)| n.as_str()).collect();
    assert_eq!(
        names,
        vec!["@rpath/libused.dylib", "@rpath/libafter.dylib"],
        "the hidden survivor rides no command; the visible kept order is intact"
    );
}

#[test]
fn the_reexport_obligation_refuses_the_hidden_mark() {
    // A re-export's trie nodes name a provider dyld must load through
    // the command the hidden mark drops — the two marks contradict and
    // the layout refuses (the M45 kind-obligation rule one mark over).
    let bytes = caller("a.o", &[]);
    let mut hidden_reexport = dylib("@rpath/librexp.dylib", &["_rexp"]);
    hidden_reexport.hidden = true;
    hidden_reexport.reexport = true;
    let cfg = LinkConfig {
        dylibs: vec![hidden_reexport],
        ..LinkConfig::default()
    };
    let err = link(&corpus(bytes), &[], &cfg).expect_err("the composition refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("re-export") && msg.contains("hidden"),
        "the refusal names both marks: {msg}"
    );
}

#[test]
fn the_relocatable_output_refuses_the_hidden_mark() {
    // The mark drops a load command; the relocatable output carries
    // none (its symtab is the input's, verbatim — the M42/M106 refusal
    // shape).
    let bytes = caller("a.o", &[]);
    let mut hidden = dylib("@rpath/libhidden.dylib", &["_hidden_fn"]);
    hidden.hidden = true;
    let cfg = LinkConfig {
        dylibs: vec![hidden],
        filetype: OutputType::Relocatable,
        ..LinkConfig::default()
    };
    let err = link_reloc(&corpus(bytes), &[], &cfg, Parallelism::default())
        .expect_err("the relocatable output refuses the mark");
    assert!(
        err.to_string().contains("-hidden"),
        "the refusal names the knob: {err}"
    );
}

#[test]
fn the_pre_m110_shape_is_byte_identical_without_the_mark() {
    // The default (no hidden marks) plans the identical bytes: the
    // ordinal rule changed from "list position" to "visible position" —
    // without hidden dylibs the two agree bit-for-bit.
    let bytes = caller("a.o", &[("_second", false)]);
    let first = dylib("@rpath/libfirst.dylib", &["_first"]);
    let second = dylib("@rpath/libsecond.dylib", &["_second"]);
    let result = plan(bytes, vec![first, second], |_c| {});
    let imps = imports(&result);
    assert_eq!(
        imps,
        vec![(2u16, "_second".to_string(), false)],
        "the plain two-ordinal shape is unchanged (M2 contract)"
    );
}

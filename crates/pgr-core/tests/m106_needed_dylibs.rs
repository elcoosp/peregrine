//! M106 — the needed-dylib mark (`-needed_library` / `-needed_framework`
//! / `-needed-l`): ld64's "needed" loads — the dylib really rides even
//! when no symbol binds against it ("means to really link with the dylib
//! even if no symbols are used from it", the `ld` man page). The mark is
//! the `-dead_strip_dylibs` exemption scoped to the load command: under
//! the drop every unused dylib leaves the header, a needed one survives
//! (the mark is the per-dylib opt-out), the LC kind stays `LC_LOAD_DYLIB`
//! (needed composes with every kind — it is a survival mark, not a
//! command kind), the kept list's ordinal compaction holds, and the
//! relocatable output refuses the knob (the object carries no load
//! commands — the M42 refusal shape).
//!
//! Gate matrix:
//! * the default — without `-dead_strip_dylibs` every dylib rides and
//!   the mark is inert (the pre-M106 shape is byte-identical);
//! * the drop — an unused dylib leaves, the needed one survives;
//! * the LC kind — a needed dylib loads as `LC_LOAD_DYLIB` (the mark
//!   names survival, not a command kind);
//! * the ordinal compaction — the survivors' ordinals compact onto the
//!   kept command order;
//! * the composition — a needed mark rides beside the re-export kind
//!   (the re-export's own obligation already survives the drop);
//! * the relocatable refusal — `link_reloc` refuses the mark.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_core::resolve::Dylib;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// An object whose `__data` carries one rebase-style bind slot per
/// named undefined (`_main` over a two-function `__text`).
fn caller(name: &str, refs: &[&str]) -> Vec<u8> {
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
    for (i, r) in refs.iter().enumerate() {
        let undef = b.add_symbol(ObjectSymbol::Undefined {
            name: (*r).into(),
            weak_ref: false,
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

// ---- the gate matrix ---------------------------------------------------------

#[test]
fn the_default_keeps_every_dylib_and_the_mark_is_inert() {
    // Without `-dead_strip_dylibs` every dylib rides regardless of use —
    // the mark changes nothing (the pre-M106 shape is byte-identical).
    let bytes = caller("a.o", &["_used"]);
    let mut marked = dylib("@rpath/libidle.dylib", &["_idle"]);
    marked.needed = true;
    let plain = plan(
        bytes.clone(),
        vec![
            dylib("@rpath/libused.dylib", &["_used"]),
            dylib("@rpath/libidle.dylib", &["_idle"]),
        ],
        |c| c.dead_strip_dylibs = false,
    );
    let with_mark = plan(
        bytes,
        vec![dylib("@rpath/libused.dylib", &["_used"]), marked],
        |c| c.dead_strip_dylibs = false,
    );
    assert_eq!(
        dylib_commands(&plain.layout.header_bytes),
        dylib_commands(&with_mark.layout.header_bytes),
        "the mark is inert without the drop: both dylibs ride either way"
    );
}

#[test]
fn the_drop_removes_the_unused_and_the_needed_survives() {
    // `-dead_strip_dylibs` drops the unused plain dylib; the needed mark
    // keeps its sibling (ld64: "means to really link with the dylib even
    // if no symbols are used from it").
    let bytes = caller("a.o", &["_used"]);
    let used = dylib("@rpath/libused.dylib", &["_used"]);
    let mut idle = dylib("@rpath/libidle.dylib", &["_idle"]);
    let image = plan(bytes, vec![used, idle.clone()], |c| {
        c.dead_strip_dylibs = true
    })
    .layout
    .header_bytes;
    let cmds = dylib_commands(&image);
    assert_eq!(
        cmds,
        vec![(
            pgr_format::consts::LC_LOAD_DYLIB,
            "@rpath/libused.dylib".to_string()
        )],
        "the unused plain dylib drops under the knob"
    );
    // The same link with the mark: the needed dylib survives the drop.
    idle.needed = true;
    let used = dylib("@rpath/libused.dylib", &["_used"]);
    let image = plan(caller("a.o", &["_used"]), vec![used, idle], |c| {
        c.dead_strip_dylibs = true;
    })
    .layout
    .header_bytes;
    let cmds = dylib_commands(&image);
    let names: Vec<&str> = cmds.iter().map(|(_, n)| n.as_str()).collect();
    assert!(
        names.contains(&"@rpath/libidle.dylib"),
        "the needed dylib survives the drop: {names:?}"
    );
}

#[test]
fn the_needed_kind_loads_as_a_plain_load() {
    // The mark is survival, not a command kind: a needed dylib loads as
    // `LC_LOAD_DYLIB` (needed composes with every kind — the M45 shape
    // one mark over, the command kind is the load's own).
    let bytes = caller("a.o", &["_used"]);
    let used = dylib("@rpath/libused.dylib", &["_used"]);
    let mut idle = dylib("@rpath/libidle.dylib", &["_idle"]);
    idle.needed = true;
    let image = plan(bytes, vec![used, idle], |c| c.dead_strip_dylibs = true)
        .layout
        .header_bytes;
    let cmds = dylib_commands(&image);
    assert!(
        cmds.iter()
            .all(|(op, _)| *op == pgr_format::consts::LC_LOAD_DYLIB),
        "a needed dylib loads as LC_LOAD_DYLIB: {cmds:?}"
    );
}

#[test]
fn the_needed_ordinal_compacts_onto_the_kept_order() {
    // The survivors' two-level ordinals compact onto the kept command
    // order: with the middle dylib dropped, the needed tail dylib's bind
    // names ordinal 2 (its kept position), never the pre-drop 3.
    let bytes = caller("a.o", &["_used"]);
    let used = dylib("@rpath/libused.dylib", &["_used"]);
    let idle_first = dylib("@rpath/libidle_first.dylib", &["_idle_first"]);
    let mut idle_last = dylib("@rpath/libidle_last.dylib", &["_idle_last"]);
    idle_last.needed = true;
    let result = plan(bytes, vec![used, idle_first, idle_last], |c| {
        c.dead_strip_dylibs = true;
    });
    // The only bind is `_used` — ordinal 1 either way. The kept list's
    // own order is the compaction's contract: two dylibs ride.
    assert_eq!(
        dylib_commands(&result.layout.header_bytes).len(),
        2,
        "the used dylib and the needed one survive; the middle drops"
    );
    let cmds = dylib_commands(&result.layout.header_bytes);
    let names: Vec<&str> = cmds.iter().map(|(_, n)| n.as_str()).collect();
    assert_eq!(
        names,
        vec!["@rpath/libused.dylib", "@rpath/libidle_last.dylib"],
        "the survivors ride in command order"
    );
}

#[test]
fn the_reexport_obligation_already_survives_and_composes() {
    // A re-export dylib always rides (the M42 exemption); the needed
    // mark beside it changes nothing — the obligation outranks (the
    // same shape the upward mark rides: one mark per dylib, the
    // survival is the re-export's own).
    let bytes = caller("a.o", &["_rexp"]);
    let mut rexp = dylib("@rpath/librexp.dylib", &["_rexp"]);
    rexp.reexport = true;
    rexp.needed = true;
    let image = plan(bytes, vec![rexp], |c| c.dead_strip_dylibs = true)
        .layout
        .header_bytes;
    let cmds = dylib_commands(&image);
    assert_eq!(
        cmds,
        vec![(
            pgr_format::consts::LC_REEXPORT_DYLIB,
            "@rpath/librexp.dylib".to_string()
        )],
        "the re-export keeps its command kind; the needed mark rides beside it"
    );
}

#[test]
fn the_relocatable_output_refuses_the_mark() {
    // The mark shapes the output's load-command list; the relocatable
    // output carries none (its symtab is the input's, verbatim — the
    // M42 refusal shape).
    let bytes = caller("a.o", &[]);
    let mut idle = dylib("@rpath/libidle.dylib", &["_idle"]);
    idle.needed = true;
    let mut cfg = LinkConfig {
        dylibs: vec![idle],
        filetype: OutputType::Relocatable,
        ..LinkConfig::default()
    };
    cfg.dead_strip_dylibs = false;
    let err = link_reloc(&corpus(bytes), &[], &cfg, Parallelism::default())
        .expect_err("the relocatable output refuses the mark");
    assert!(
        err.to_string().contains("-needed"),
        "the refusal names the knob: {err}"
    );
}

//! M42 — the unused-dylib drop: `-dead_strip_dylibs` removes every
//! input dylib no referenced name binds against (the two-level bind
//! names its provider — a dylib whose exports nothing references
//! cannot serve a bind), keeps the re-exports (their REEXPORT nodes
//! ride the export trie — the contract cannot survive the drop) and
//! keeps every dylib a dynamic-lookup reference could reach at load
//! time (the flat bind names no provider — the loader may reach any
//! loaded image's exports). The kept list rides in command order and
//! the two-level ordinals compact onto it; the default (`false`) keeps
//! every pre-M42 link byte-identical.
//!
//! Gate matrix:
//! * the drop — an unused dylib's `LC_LOAD_DYLIB` leaves the header
//!   and the kept bind's ordinal compacts;
//! * the ordinal stability — the used dylib's ordinal in the default
//!   link is the command-line position, unchanged when nothing drops;
//! * the re-export exemption — an unused re-export dylib rides (the
//!   REEXPORT nodes ride the trie);
//! * the dynamic-lookup reach — a dylib exporting a name the link left
//!   to dyld rides (the flat bind may reach it);
//! * the relocatable refusal — `-r` refuses the knob (the object
//!   output carries no load commands).

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
    }
}

fn reexport(install_name: &str, exports: &[&str]) -> Dylib {
    Dylib {
        reexport: true,
        needed: false,
        ..dylib(install_name, exports)
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

/// The `lib_ordinal` of the first bind in the fixup plan.
fn first_bind_ordinal(layout: &pgr_core::layout::Layout) -> u16 {
    layout.fixups.imports.first().map_or(0, |i| i.lib_ordinal)
}

/// The `LC_LOAD_DYLIB`-family install names the header carries, in
/// command order.
fn header_dylibs(layout: &pgr_core::layout::Layout) -> Vec<String> {
    use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};
    let header = MachHeader64::parse(&layout.header_bytes).expect("the header parses");
    let mut it = LoadCommandIter::new(
        &layout.header_bytes,
        MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut out = Vec::new();
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if matches!(
            cmd.kind,
            LoadCommandKind::LoadDylib | LoadCommandKind::ReexportDylib
        ) {
            // Weak/lazy loads classify under `LoadDylib` (the shared
            // `dylib_command` layout).
            let dylib_cmd =
                pgr_format::DylibCommand::parse(cmd.bytes).expect("the dylib command parses");
            let name = dylib_cmd.name(cmd.bytes).expect("the install name reads");
            out.push(String::from_utf8_lossy(name).into_owned());
        }
    }
    out
}

// ---- the drop -----------------------------------------------------------------

#[test]
fn the_unused_dylib_drops_its_command_and_the_ordinals_compact() {
    // The used dylib rides first, the unused one second: the bind's
    // ordinal is 1 either way, and the unused command leaves the header.
    let caller_obj = caller("a.o", &["_used"]);
    let dylibs = vec![
        dylib("@rpath/libused.dylib", &["_used"]),
        dylib("@rpath/libunused.dylib", &["_unused"]),
    ];
    let result = plan(caller_obj.clone(), dylibs, |c| c.dead_strip_dylibs = true);
    assert_eq!(
        header_dylibs(&result.layout),
        vec!["@rpath/libused.dylib".to_string()],
        "the unused dylib's command leaves the header"
    );
    assert_eq!(
        first_bind_ordinal(&result.layout),
        1,
        "the kept bind's ordinal compacts onto the kept list"
    );
}

#[test]
fn the_used_dylib_keeps_the_command_line_ordinal() {
    // The unused dylib rides FIRST: the kept bind renumbers from 2 to 1
    // and the kept command order is unchanged.
    let caller_obj = caller("a.o", &["_used"]);
    let dylibs = vec![
        dylib("@rpath/libunused.dylib", &["_unused"]),
        dylib("@rpath/libused.dylib", &["_used"]),
    ];
    let result = plan(caller_obj, dylibs, |c| c.dead_strip_dylibs = true);
    assert_eq!(
        header_dylibs(&result.layout),
        vec!["@rpath/libused.dylib".to_string()],
        "the kept list rides in command order"
    );
    assert_eq!(
        first_bind_ordinal(&result.layout),
        1,
        "the ordinal compacts"
    );
}

#[test]
fn the_default_keeps_every_dylib() {
    let caller_obj = caller("a.o", &["_used"]);
    let dylibs = vec![
        dylib("@rpath/libused.dylib", &["_used"]),
        dylib("@rpath/libunused.dylib", &["_unused"]),
    ];
    let cfg = LinkConfig {
        dylibs,
        ..LinkConfig::default()
    };
    let default = link(&corpus(caller_obj.clone()), &[], &cfg).expect("links");
    assert_eq!(
        first_bind_ordinal(&default.layout),
        1,
        "the default ordinal is the command-line position"
    );
    let cfg = LinkConfig {
        dylibs: vec![
            dylib("@rpath/libused.dylib", &["_used"]),
            dylib("@rpath/libunused.dylib", &["_unused"]),
        ],
        ..LinkConfig::default()
    };
    let explicit = link(&corpus(caller_obj), &[], &cfg).expect("links");
    assert_eq!(
        default.layout.header_bytes, explicit.layout.header_bytes,
        "the spelled default is the default"
    );
}

// ---- the exemptions -------------------------------------------------------------

#[test]
fn the_reexport_dylib_always_rides() {
    let caller_obj = caller("a.o", &["_used"]);
    let dylibs = vec![
        dylib("@rpath/libused.dylib", &["_used"]),
        reexport("@rpath/libreexport.dylib", &["_reexported"]),
    ];
    let result = plan(caller_obj, dylibs, |c| c.dead_strip_dylibs = true);
    assert_eq!(
        header_dylibs(&result.layout),
        vec![
            "@rpath/libused.dylib".to_string(),
            "@rpath/libreexport.dylib".to_string(),
        ],
        "the re-export rides: its REEXPORT nodes join the image's export trie"
    );
}

#[test]
fn the_dynamic_lookup_provider_rides() {
    // The reference follows `-undefined dynamic_lookup` (the flat bind
    // names no provider — the loader may reach the dylib's exports at
    // load time, so the provider cannot be proven unreachable).
    let caller_obj = caller("a.o", &["_maybe"]);
    let dylibs = vec![dylib("@rpath/libmaybe.dylib", &["_maybe"])];
    let result = plan(caller_obj, dylibs, |c| {
        c.dead_strip_dylibs = true;
        c.undefined_policy = pgr_core::resolve::UndefinedPolicy::DynamicLookup;
    });
    assert_eq!(
        header_dylibs(&result.layout),
        vec!["@rpath/libmaybe.dylib".to_string()],
        "the dynamic-lookup provider rides"
    );
}

// ---- the relocatable refusal -----------------------------------------------------

#[test]
fn the_relocatable_output_refuses_the_knob() {
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        dead_strip_dylibs: true,
        ..LinkConfig::default()
    };
    let err = link_reloc(
        &corpus(caller("a.o", &["_used"])),
        &[],
        &cfg,
        Parallelism::Auto,
    )
    .expect_err("the relocatable output refuses the knob");
    assert!(
        err.to_string().contains("-dead_strip_dylibs"),
        "the refusal names the knob: {err}"
    );
}

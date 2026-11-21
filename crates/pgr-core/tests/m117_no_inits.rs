//! M117 — the `-no_inits` decision: ld64's init/term section
//! suppression — the `__mod_init_func`, `__mod_term_func` and
//! `__init_offsets` sections drop from the output entirely, overriding
//! the M16 transform (no synthetic `__init_offsets` piece) and the M52
//! dead-strip roots (the sections never place, roots or not). The
//! `LC_ROUTINES_64` command (M48 `-init` / M98 `-term`) drops from the
//! header — no init/term machinery remains. The default keeps every
//! pre-knob link byte-identical; corpora without init/term sections
//! link byte-identical under either face.
//!
//! Gate matrix:
//! * the default keeps the pointer sections (the pre-M117 shape);
//! * `-no_inits` drops `__mod_init_func` and `__mod_term_func` —
//!   no bucket, no placed bytes;
//! * the M16 transform override — `-init_offsets` beside `-no_inits`
//!   plans no synthetic `__init_offsets` section either;
//! * `LC_ROUTINES_64` drops from the dylib header beside `-no_inits`;
//! * the M52 roots override — under `-dead_strip` the dropped sections
//!   never place (roots or not), the image carries no init/term shape;
//! * the byte-identity lock — a corpus without init/term sections
//!   links byte-identical under either face;
//! * the relocatable refusal — the object's sections are the input's,
//!   verbatim (the layout re-check and `link_reloc` back the driver
//!   surface).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_cached, link_reloc};
use pgr_core::propagate::section_digests;
use pgr_core::resolve_reuse::ResolveReuseSeed;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{S_MOD_INIT_FUNC_POINTERS, S_MOD_TERM_FUNC_POINTERS};

/// One object: `_main` (the first), one `_fn` body, one initializer and
/// one terminator body, and one 8-byte pointer slot in each of the
/// `__mod_init_func` / `__mod_term_func` sections targeting them.
fn init_corpus(name: &str, with_main: bool) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(4),
        vec![],
    ));
    if with_main {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
    }
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_{name}_init"),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_{name}_term"),
        section_index: text,
        value: 8,
        weak: false,
    });
    let init_builder = b.add_symbol(ObjectSymbol::Defined {
        name: format!("_{name}_init_ptr"),
        section_index: text,
        value: 4,
        weak: false,
    });
    let init_sym = b.sym_index(init_builder);
    let term_builder = b.add_symbol(ObjectSymbol::Defined {
        name: format!("_{name}_term_ptr"),
        section_index: text,
        value: 8,
        weak: false,
    });
    let term_sym = b.sym_index(term_builder);
    let modinit = b.add_section(ObjectSection::data(
        "__mod_init_func",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(init_sym).at(0)],
    ));
    b.section_mut(modinit).flags = S_MOD_INIT_FUNC_POINTERS;
    let modterm = b.add_section(ObjectSection::data(
        "__mod_term_func",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(term_sym).at(0)],
    ));
    b.section_mut(modterm).flags = S_MOD_TERM_FUNC_POINTERS;
    b
}

fn inputs(builders: &[ObjectBuilder]) -> Vec<LinkInput> {
    builders
        .iter()
        .map(|b| LinkInput {
            name: b.name().into(),
            bytes: b.build().expect("the fixture object builds"),
        })
        .collect()
}

fn cfg(tweak: impl FnOnce(&mut LinkConfig)) -> LinkConfig {
    let mut c = LinkConfig::default();
    tweak(&mut c);
    c
}

fn placed_sections(layout: &pgr_core::Layout) -> Vec<String> {
    layout
        .sections
        .iter()
        .map(|s| format!("{},{}", s.seg_name, s.name))
        .collect()
}

/// Walks the header's load commands; the `LC_ROUTINES_64` count.
fn routines_count(header: &[u8]) -> usize {
    let hdr = pgr_format::MachHeader64::parse(header).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        header,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut count = 0usize;
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if matches!(cmd.kind, pgr_format::LoadCommandKind::Routines) {
            count += 1;
        }
    }
    count
}

// ---- the gate matrix ---------------------------------------------------------

#[test]
fn the_default_keeps_the_init_and_term_sections() {
    // The pre-M117 shape: the pointer sections bucket and place —
    // byte for byte the house default.
    let builders = vec![init_corpus("a.o", true)];
    let layout = link(&inputs(&builders), &[], &cfg(|_| ()))
        .expect("the default link plans")
        .layout;
    let names = placed_sections(&layout);
    assert!(
        names.iter().any(|n| n.contains("__mod_init_func")),
        "the default keeps the initializer pointers: {names:?}"
    );
    assert!(
        names.iter().any(|n| n.contains("__mod_term_func")),
        "the default keeps the terminator pointers: {names:?}"
    );
}

#[test]
fn no_inits_drops_the_init_and_term_sections() {
    // `-no_inits`: no bucket, no placed bytes — the init/term machinery
    // leaves the output entirely (the M52 roots never fire on sections
    // that never place).
    let builders = vec![init_corpus("a.o", true)];
    let layout = link(&inputs(&builders), &[], &cfg(|c| c.no_inits = true))
        .expect("the suppressed link plans")
        .layout;
    let names = placed_sections(&layout);
    assert!(
        !names.iter().any(|n| n.contains("__mod_init_func")),
        "the suppressed link carries no initializer pointers: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.contains("__mod_term_func")),
        "the suppressed link carries no terminator pointers: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.contains("__init_offsets")),
        "no synthetic offsets section rides either: {names:?}"
    );
}

#[test]
fn no_inits_overrides_the_init_offsets_transform() {
    // `-init_offsets` beside `-no_inits`: the M16 transform's synthetic
    // `__TEXT,__init_offsets` section never plans — the suppression
    // overrides the transform (no init machinery remains under either
    // form).
    let builders = vec![init_corpus("a.o", true)];
    let transformed = link(
        &inputs(&builders),
        &[],
        &cfg(|c| {
            c.init_offsets = pgr_core::init_offsets::InitOffsets::Offsets;
        }),
    )
    .expect("the transformed link plans")
    .layout;
    assert!(
        placed_sections(&transformed)
            .iter()
            .any(|n| n.contains("__TEXT,__init_offsets")),
        "the transform alone plans the synthetic offsets section"
    );
    let suppressed = link(
        &inputs(&builders),
        &[],
        &cfg(|c| {
            c.init_offsets = pgr_core::init_offsets::InitOffsets::Offsets;
            c.no_inits = true;
        }),
    )
    .expect("the suppressed transform link plans")
    .layout;
    let names = placed_sections(&suppressed);
    assert!(
        !names.iter().any(|n| n.contains("__init_offsets")),
        "the suppression overrides the transform: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.contains("__mod_init_func")),
        "no pointer section rides either: {names:?}"
    );
}

#[test]
fn no_inits_drops_lc_routines_from_the_header() {
    // The M48/M98 command rides only while init machinery remains —
    // beside `-no_inits` the command drops from the dylib header (no
    // initializer or terminator survives the suppression).
    let builders = vec![init_corpus("a.o", true)];
    let dylib = |no_inits: bool| {
        cfg(move |c| {
            c.filetype = OutputType::Dylib;
            c.ident = "lib".into();
            c.install_name = Some("@rpath/lib.dylib".into());
            c.init_symbol = Some("_a.o_init".into());
            c.term_symbol = Some("_a.o_term".into());
            c.no_inits = no_inits;
        })
    };
    let carried = link(&inputs(&builders), &[], &dylib(false)).expect("the dylib plans");
    assert_eq!(
        routines_count(&carried.layout.header_bytes),
        1,
        "the default dylib carries LC_ROUTINES_64"
    );
    let suppressed = link(&inputs(&builders), &[], &dylib(true)).expect("the dylib plans");
    assert_eq!(
        routines_count(&suppressed.layout.header_bytes),
        0,
        "-no_inits drops the command from the header"
    );
}

#[test]
fn no_inits_composes_with_dead_strip() {
    // The M52 roots override: under `-dead_strip` the init sections are
    // roots, but beside `-no_inits` the sections never place — the
    // roots have nothing to keep, the image carries no init/term shape
    // and still links (the strip's other roots hold the live set).
    let builders = vec![init_corpus("a.o", true)];
    let layout = link(
        &inputs(&builders),
        &[],
        &cfg(|c| {
            c.dead_strip = true;
            c.no_dead_strip_inits_and_terms = true;
            c.no_inits = true;
        }),
    )
    .expect("the stripped suppressed link plans")
    .layout;
    let names = placed_sections(&layout);
    assert!(
        !names.iter().any(|n| n.contains("__mod_init_func"))
            && !names.iter().any(|n| n.contains("__mod_term_func")),
        "the roots never keep a section the suppression dropped: {names:?}"
    );
    assert!(
        names.iter().any(|n| n.contains("__text")),
        "the rest of the image still places: {names:?}"
    );
}

#[test]
fn a_corpus_without_init_sections_links_byte_identical_under_either_face() {
    // The byte-identity lock: no init/term machinery, nothing to drop —
    // the decision never moves a byte (every pre-knob link included).
    let mut b = ObjectBuilder::new("plain.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let builders = vec![b];
    let default = link(&inputs(&builders), &[], &cfg(|_| ())).expect("the plain link plans");
    let suppressed =
        link(&inputs(&builders), &[], &cfg(|c| c.no_inits = true)).expect("the plain link plans");
    assert_eq!(
        default.layout.header_bytes, suppressed.layout.header_bytes,
        "a corpus without init sections links byte-identical"
    );
}

#[test]
fn the_ladder_replay_rides_the_decision() {
    // The M81 pattern: the decision is config, not a product — the
    // resolve-reuse relink re-plans the same init-free shape the cold
    // walk plans (the layout reads the config, both lanes reach it).
    let builders = vec![init_corpus("a.o", true)];
    let ins = inputs(&builders);
    let recording = link_cached(
        &ins,
        &[],
        &cfg(|c| {
            c.record_resolution = true;
            c.no_inits = true;
        }),
        Parallelism::Serial,
        None,
    )
    .expect("the recording link runs");
    let snapshot = recording
        .resolve_snapshot
        .clone()
        .expect("a recording link captures the snapshot");
    let replayed = link_cached(
        &ins,
        &[],
        &cfg(|c| {
            c.resolve_reuse = Some(ResolveReuseSeed {
                snapshot,
                digests: section_digests(&recording.objects),
            });
            c.no_inits = true;
        }),
        Parallelism::Serial,
        None,
    )
    .expect("the seeded relink runs");
    assert_eq!(
        placed_sections(&recording.layout),
        placed_sections(&replayed.layout),
        "the replay plans the same init-free shape (the M81 parity)"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob_in_link_reloc() {
    // The object's sections are the input's, verbatim — there is no
    // init classification to apply (the M104/M105 pattern; the layout
    // re-check backs this in `layout`).
    let builders = vec![init_corpus("a.o", true)];
    let cfg = cfg(|c| {
        c.filetype = OutputType::Relocatable;
        c.no_inits = true;
    });
    let err = link_reloc(&inputs(&builders), &[], &cfg, Parallelism::Serial)
        .expect_err("the relocatable output refuses the knob");
    let text = err.to_string();
    assert!(
        text.contains("-no_inits") && text.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {text}"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob_in_layout() {
    // The layout's own re-check: no library caller plans the shape
    // either (the M104/M105 refusal shape).
    let builders = vec![init_corpus("a.o", true)];
    let cfg = cfg(|c| {
        c.filetype = OutputType::Relocatable;
        c.no_inits = true;
    });
    let err = link(&inputs(&builders), &[], &cfg).expect_err("the layout re-check refuses");
    let text = err.to_string();
    assert!(
        text.contains("-no_inits") && text.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {text}"
    );
}

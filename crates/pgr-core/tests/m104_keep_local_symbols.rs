//! M104 — the symtab-shaping decision (`-keep_local_symbols` / `-x`):
//! the other half of the local-symbol contract (M33 named the
//! filter-hidden shape). The output symtab's plain local-symbol
//! subrange — the rows without `N_EXT` set (`N_SECT & ~N_EXT`, the
//! section-defined statics, plus the name-only locals that ride
//! absolute) — rides by default (ld64's own default:
//! `kLocalSymbolsAll` — the man page's "usually they are stripped when
//! the final linked output is produced" is the *final-output* face the
//! `-x` flag names), and the `-x` face drops exactly that subrange.
//! `-keep_local_symbols` names the keep explicitly — the default's
//! mirror, so every pre-knob link is byte-identical (the last flag
//! wins at the parse).
//!
//! Gate matrix:
//! * the default — the plain locals ride (the symtab's locals subrange
//!   carries the section-defined static and the name-only local), and
//!   the named keep plans the pre-knob bytes exactly (the lock);
//! * the drop — `-x` drops the plain local rows: the symtab shrinks by
//!   one 16-byte row per local, the string table shrinks with the
//!   names, the file shrinks, and the extdefs/undefineds/subrange
//!   math all follow (`iextdefsym` starts at the (possibly empty)
//!   locals subrange's end);
//! * the hidden rows — the M3/M33 filter-hidden shapes
//!   (`N_SECT | N_PEXT`, the conversion product) are the export
//!   machinery's product, never input locals: they ride either way
//!   (the M33 default conversion survives `-x` with it);
//! * the stream — the function-starts stream still covers the local
//!   functions: ld64's `-x` strips the symtab rows, never the start
//!   addresses (the source chain carries the dropped rows);
//! * the refusals — the relocatable output's symtab is the input's,
//!   verbatim: the drop face refuses there (the image path's
//!   relocatable shape and [`pgr_core::link::link_reloc`] back the
//!   driver refusal, the M102/M39 pattern); the keep face is the
//!   default's mirror and never refuses;
//! * the verifier — the symtab contract never refuses on the rows:
//!   local symbols are a dyld-consumed surface, both faces verify
//!   strict (the driver's end-to-end gate reads the faces — the
//!   `-no_adhoc` carve-out pattern);
//! * the lock — double-link determinism holds across the decision.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// A corpus: `_main` exported, `_local_fn` a section-defined local
/// (the static-function shape — it feeds the function-starts stream),
/// and `local_abs` a name-only local (the absolute-riding shape).
fn corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::LocalDefined {
        name: "_local_fn".into(),
        section_index: text,
        value: 8,
    });
    b.add_symbol(ObjectSymbol::Local("local_abs".into()));
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// A corpus with a private external (`N_PEXT`) — the M33 conversion
/// product rides the locals range by default.
fn pext_corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("pext.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::DefinedPrivate {
        name: "_pext_fn".into(),
        section_index: text,
        value: 4,
    });
    vec![LinkInput {
        name: "pext.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

fn plan(inputs: &[LinkInput], tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::layout::Layout {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(inputs, &[], &cfg).expect("the corpus links").layout
}

/// The output symtab row for `name` (`str_offsets` runs parallel to
/// `symbols`, so the row index reads its own `n_strx`).
fn row_of(
    layout: &pgr_core::layout::Layout,
    name: &[u8],
) -> Option<pgr_core::layout::OutputSymbol> {
    for (i, s) in layout.symbols.iter().enumerate() {
        let off = usize::try_from(layout.str_offsets[i]).expect("offset");
        let end = layout.strtab[off..]
            .iter()
            .position(|&b| b == 0)
            .expect("NUL");
        if &layout.strtab[off..off + end] == name {
            return Some(s.clone());
        }
    }
    None
}

// ---- the default and the keep --------------------------------------------------

#[test]
fn the_default_keeps_the_plain_locals() {
    assert!(
        LinkConfig::default().keep_local_symbols,
        "the pre-M104 shape: the default keeps the local-symbol subrange \
         (ld64's own default, kLocalSymbolsAll)"
    );
    let layout = plan(&corpus(), |_| {});
    let sect = row_of(&layout, b"_local_fn").expect("the static rides");
    assert!(
        sect.n_type == pgr_format::consts::N_SECT && !sect.external,
        "the section-defined local rides N_SECT without N_EXT: {:#x}",
        sect.n_type
    );
    let abs = row_of(&layout, b"local_abs").expect("the name-only local rides");
    assert!(
        abs.n_type == pgr_format::consts::N_ABS && !abs.external,
        "the name-only local rides absolute: {:#x}",
        abs.n_type
    );
    let locals = layout.symbols.iter().filter(|s| !s.external).count();
    assert_eq!(
        locals, 2,
        "the locals subrange carries exactly the two plain locals"
    );
}

#[test]
fn the_named_keep_plans_the_pre_knob_bytes_exactly() {
    let default = plan(&corpus(), |_| {});
    let kept = plan(&corpus(), |c| c.keep_local_symbols = true);
    assert_eq!(
        default.header_bytes, kept.header_bytes,
        "-keep_local_symbols is the default's mirror: the same header"
    );
    assert_eq!(
        default.symbols, kept.symbols,
        "the same symtab rows ride either way"
    );
    assert_eq!(default.file_size, kept.file_size, "the same file size");
}

// ---- the drop ------------------------------------------------------------------

#[test]
fn the_x_face_drops_the_plain_local_rows() {
    let kept = plan(&corpus(), |_| {});
    let dropped = plan(&corpus(), |c| c.keep_local_symbols = false);
    assert!(
        row_of(&dropped, b"_local_fn").is_none(),
        "the section-defined local drops"
    );
    assert!(
        row_of(&dropped, b"local_abs").is_none(),
        "the name-only local drops"
    );
    assert!(
        row_of(&dropped, b"_main").is_some(),
        "the extdefs survive the drop"
    );
    let locals = dropped.symbols.iter().filter(|s| !s.external).count();
    assert_eq!(locals, 0, "the plain locals subrange empties");
    assert_eq!(
        kept.linkedit.sym_size - dropped.linkedit.sym_size,
        32,
        "two 16-byte rows leave the symtab"
    );
    assert!(
        dropped.strtab.len() < kept.strtab.len(),
        "the dropped names leave the string table"
    );
    assert!(
        dropped.file_size < kept.file_size,
        "the file shrinks with the subrange"
    );
}

#[test]
fn the_subrange_math_follows_the_drop() {
    // The dysymtab subranges count the shaped rows: under the drop the
    // locals range is empty, so the extdef range starts at index 0 and
    // the undefined range follows it — the dysymtab emit reads the
    // counts, never a constant.
    let dropped = plan(&corpus(), |c| c.keep_local_symbols = false);
    let n_locals = dropped.symbols.iter().filter(|s| !s.external).count();
    let n_defs = dropped
        .symbols
        .iter()
        .filter(|s| {
            s.external && s.n_type & pgr_format::consts::N_TYPE != pgr_format::consts::N_UNDF
        })
        .count();
    let n_undef = dropped
        .symbols
        .iter()
        .filter(|s| {
            s.external && s.n_type & pgr_format::consts::N_TYPE == pgr_format::consts::N_UNDF
        })
        .count();
    assert_eq!(n_locals, 0, "the locals subrange is empty");
    // Two extdefs: `_main` plus the image's own `__mh_execute_header`
    // row (the executable's exported header symbol).
    assert_eq!(
        n_defs, 2,
        "_main and __mh_execute_header ride the extdef range"
    );
    assert_eq!(n_undef, 0, "the corpus carries no undefineds");
    assert_eq!(
        dropped.symbols.len(),
        n_locals + n_defs + n_undef,
        "the shaped symtab is exactly the three subranges"
    );
}

// ---- the hidden rows -----------------------------------------------------------

#[test]
fn the_filter_hidden_rows_ride_the_drop() {
    // M33's default conversion is the filter-hidden shape: a private
    // extern converts into the locals range. The conversion product is
    // the export machinery's, never an input local — `-x` drops the
    // plain locals around it, never the row itself.
    let dropped = plan(&pext_corpus(), |c| c.keep_local_symbols = false);
    let row = row_of(&dropped, b"_pext_fn").expect("the converted row rides the drop");
    assert!(
        row.n_type == pgr_format::consts::N_SECT | pgr_format::consts::N_PEXT && !row.external,
        "the M33 shape survives -x: N_SECT | N_PEXT, a local — {:#x}",
        row.n_type
    );
    let locals = dropped.symbols.iter().filter(|s| !s.external).count();
    assert_eq!(
        locals, 1,
        "the locals subrange carries exactly the filter-hidden row"
    );
    // The plain locals the pext corpus carries none of — the drop and
    // the conversion compose without ordering surprises.
    assert!(
        row_of(&dropped, b"_main").is_some(),
        "the extdef survives beside the hidden row"
    );
}

// ---- the stream ----------------------------------------------------------------

#[test]
fn the_function_starts_stream_still_covers_the_locals() {
    // The static `_local_fn` feeds the stream by default; under `-x`
    // the symtab row drops but the start address rides (ld64 strips
    // the symtab rows, never the start addresses).
    let kept = plan(&corpus(), |_| {});
    let dropped = plan(&corpus(), |c| c.keep_local_symbols = false);
    assert_eq!(
        kept.func_starts, dropped.func_starts,
        "the stream is the decision's neighbor, never its product"
    );
    assert!(
        !kept.func_starts.is_empty(),
        "the corpus's locals make the stream non-trivial"
    );
}

// ---- the refusals --------------------------------------------------------------

#[test]
fn the_relocatable_shape_refuses_the_drop_face() {
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        keep_local_symbols: false,
        ..LinkConfig::default()
    };
    let err = link(&corpus(), &[], &cfg).expect_err("the relocatable shape refuses -x");
    let message = err.to_string();
    assert!(
        message.contains("-x"),
        "the refusal names the drop face: {message}"
    );
    assert!(
        message.contains("verbatim"),
        "the refusal names the contract (the object's symtab is the input's): {message}"
    );
}

#[test]
fn the_relocatable_path_refuses_the_drop_face() {
    let cfg = LinkConfig {
        keep_local_symbols: false,
        ..LinkConfig::default()
    };
    let err =
        link_reloc(&corpus(), &[], &cfg, Parallelism::Auto).expect_err("the -r path refuses -x");
    assert!(
        err.to_string().contains("-x"),
        "the relocatable re-check names the drop face: {err}",
    );
}

#[test]
fn the_keep_face_never_refuses_the_relocatable_path() {
    // The keep face is the default's mirror: the object's symtab is the
    // input's verbatim, and the input symtab always carried its locals.
    let cfg = LinkConfig {
        keep_local_symbols: true,
        ..LinkConfig::default()
    };
    link_reloc(&corpus(), &[], &cfg, Parallelism::Auto)
        .expect("the named keep rides the relocatable path like the default");
}

// ---- the lock ------------------------------------------------------------------

#[test]
fn double_link_is_byte_identical_across_the_decision() {
    let a = plan(&corpus(), |c| c.keep_local_symbols = false);
    let b = plan(&corpus(), |c| c.keep_local_symbols = false);
    assert_eq!(
        a.header_bytes, b.header_bytes,
        "the drop face is deterministic"
    );
    assert_eq!(a.file_size, b.file_size, "the drop face plans one shape");
}

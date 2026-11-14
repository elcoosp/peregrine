//! M30 — the data-in-code carriage: the `LC_DATA_IN_CODE` metadata the
//! design doc's `__LINKEDIT` order names (TDD §8.2 "function starts →
//! data-in-code → symtab") and the verifier already gates, but Pass 1
//! silently dropped — an entry-carrying object linked into an image
//! that lost the debugger-facing data ranges. M30 carries the input
//! payload through the atom map onto the output `__LINKEDIT`: every
//! entry translates from its input `__text` offset to the output
//! `__TEXT`-segment-relative offset (dead-stripped functions drop
//! their entries, ICF-folded ones dedup onto the canonical copy), the
//! command lands right after `LC_FUNCTION_STARTS`, and
//! `-no_data_in_code` (the driver surface's accepted no-op since M1)
//! becomes the suppression decision.
//!
//! Gate matrix:
//! * the carriage — an entry-carrying corpus links into an image whose
//!   payload decodes to the translated, sorted entries; the header
//!   command matches the plan's `__LINKEDIT` slot;
//! * the translation — an entry rides the same atom map the symbols
//!   do, so its output offset tracks its function's placement (the
//!   `__TEXT`-segment-relative base is the header region the first
//!   section sits behind);
//! * the drops — a dead-stripped function's entry is gone;
//! * the dedup — ICF-folded duplicates land once, on the canonical
//!   copy;
//! * the suppression — the named decision drops the command and the
//!   `__LINKEDIT` slot (16 bytes narrower `sizeofcmds`);
//! * the default — an entry-free corpus plans the pre-M30 bytes (no
//!   command, no slot) and the double link stays byte-identical;
//! * the refusals — parse-side validation refuses with the typed
//!   error: an entry beyond the input `__text`, entries without a
//!   `__text` to annotate (the malformed-payload refusal rides the
//!   format reader's unit gate — the core parse path calls it and
//!   maps the failure onto `LinkError::Parse`);
//! * the cache — the POI cache's parsed-object image carries the
//!   entries (the codec revision bumps, stale entries self-heal).

use pgr_core::cache::{decode_poi, encode_poi};
use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{DataInCodeEntry, LoadCommandIter, LoadCommandKind, MachHeader64};

/// One `__text` of `n` RET functions, symbols at every function start
/// (`_main` for the first when `entry` — only one input may own it).
fn ret_corpus(name: &str, n_fns: usize, entry: bool) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_fns),
        vec![],
    ));
    let stem = name.trim_end_matches(".o");
    for f in 0..n_fns {
        b.add_symbol(ObjectSymbol::Defined {
            name: if f == 0 && entry {
                "_main".into()
            } else {
                format!("_{stem}_fn_{f}")
            },
            section_index: text,
            value: (f * 4) as u64,
            weak: false,
        });
    }
    b
}

/// An `n`-function object carrying one data-in-code entry per function
/// (offset = the function's `__text`-relative start).
fn obj_with_dice(name: &str, n_fns: usize, entry: bool) -> Vec<u8> {
    let b = ret_corpus(name, n_fns, entry).set_data_in_code(
        (0..n_fns)
            .map(|f| DataInCodeEntry {
                offset: (f * 4) as u32,
                length: 4,
                kind: 1,
            })
            .collect(),
    );
    b.build().expect("the fixture object builds")
}

/// A single-object corpus (`_main` exported) from raw bytes.
fn corpus(bytes: Vec<u8>) -> Vec<LinkInput> {
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes,
    }]
}

/// Links the corpus and returns the layout plan.
fn plan(tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::layout::Layout {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(&corpus(obj_with_dice("main.o", 3, true)), &[], &cfg)
        .expect("the corpus links")
        .layout
}

/// The `LC_DATA_IN_CODE` command's `(dataoff, datasize)` fields, when
/// the header carries one (the entry bytes live in the file's
/// `__LINKEDIT` slot, not the header — decode them from the plan's
/// stream).
fn dice_command_fields(image: &[u8]) -> Option<(u32, u32)> {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::LinkeditData(pgr_format::consts::LC_DATA_IN_CODE) = cmd.kind {
            let lc = pgr_format::LinkeditDataCommand::parse(cmd.bytes).expect("the command parses");
            return Some((lc.dataoff, lc.datasize));
        }
    }
    None
}

/// Decodes the plan's encoded data-in-code stream.
fn dice_entries(stream: &[u8]) -> Vec<DataInCodeEntry> {
    pgr_format::read_data_in_code(stream).expect("the plan stream decodes")
}

/// The `__TEXT` segment's vmaddr (entries are segment-relative).
fn text_vmaddr(layout: &pgr_core::layout::Layout) -> u64 {
    layout
        .segments
        .iter()
        .find(|s| s.name == "__TEXT")
        .expect("the text segment exists")
        .vmaddr
}

/// The `__text` section's segment-relative base (the header region the
/// first section sits behind) — the translation floor every entry adds.
fn text_base(layout: &pgr_core::layout::Layout) -> u64 {
    let text = layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__text")
        .expect("the text section exists");
    text.vm_addr - text_vmaddr(layout)
}

fn entry_at(offset: u32) -> DataInCodeEntry {
    DataInCodeEntry {
        offset,
        length: 4,
        kind: 1,
    }
}

// ---- the carriage --------------------------------------------------------------

#[test]
fn the_input_metadata_carries_through_the_output() {
    let layout = plan(|_| {});
    let (dataoff, datasize) =
        dice_command_fields(&layout.header_bytes).expect("the command is present");
    assert_eq!(
        u64::from(dataoff),
        layout.linkedit.data_in_code_off,
        "the command names the plan's slot"
    );
    assert_eq!(
        usize::try_from(datasize).unwrap(),
        layout.linkedit.data_in_code_size,
        "the command names the plan's size"
    );
    let base = u32::try_from(text_base(&layout)).expect("the base fits u32");
    let decoded = dice_entries(&layout.data_in_code);
    assert_eq!(
        decoded,
        vec![entry_at(base), entry_at(base + 4), entry_at(base + 8)],
        "the payload decodes to the translated entries (each rides its \
         function's placement behind the header region)"
    );
    assert_eq!(
        layout.data_in_code.len(),
        decoded.len() * 8,
        "the plan carries the encoded stream"
    );
    // Every entry lies inside `__TEXT` (the verifier's contract).
    let text_vmsize = layout.text_vmsize;
    for e in &decoded {
        assert!(
            u64::from(e.offset) + u64::from(e.length) <= text_vmsize,
            "entry {e:?} within __TEXT ({text_vmsize:#x})"
        );
    }
}

#[test]
fn the_entries_translate_through_the_atom_map() {
    // A two-object corpus: the second object's __text lands behind the
    // first one's, so its entries must ride the same atom map the
    // symbols do.
    let inputs = vec![
        LinkInput {
            name: "a.o".to_string(),
            bytes: obj_with_dice("a.o", 3, true),
        },
        LinkInput {
            name: "b.o".to_string(),
            bytes: obj_with_dice("b.o", 3, false),
        },
    ];
    let layout = link(&inputs, &[], &LinkConfig::default())
        .expect("the corpus links")
        .layout;
    let es = dice_entries(&layout.data_in_code);
    assert_eq!(es.len(), 6, "both objects' entries ride");
    // Sorted by output offset (the LINKEDIT stream contract).
    let mut sorted: Vec<u32> = es.iter().map(|e| e.offset).collect();
    sorted.sort_unstable();
    assert_eq!(
        es.iter().map(|e| e.offset).collect::<Vec<_>>(),
        sorted,
        "the stream is offset-sorted"
    );
    // The first entry sits at the first object's function 0 placement;
    // the stream covers both objects' __text spans (a's 12 bytes, then
    // b's 12, so b's last function sits at base + 20).
    let base = u32::try_from(text_base(&layout)).expect("the base fits u32");
    assert_eq!(
        es[0].offset, base,
        "object a's entry 0 tracks its placement"
    );
    assert_eq!(
        es.last().expect("the last entry").offset,
        base + 20,
        "object b's last entry rides its __text placement behind a's"
    );
}

// ---- the drops and the dedup ---------------------------------------------------

#[test]
fn the_dead_strip_drops_the_unreferenced_entries() {
    let layout = plan(|c| {
        c.dead_strip = true;
    });
    let entries = dice_entries(&layout.data_in_code);
    let base = u32::try_from(text_base(&layout)).expect("the base fits u32");
    assert_eq!(
        entries,
        vec![entry_at(base)],
        "only the entry-rooted function (_main) survives"
    );
}

#[test]
fn the_fold_drops_the_folded_away_entries() {
    // Two identical single-function objects: `-icf=all` folds the
    // second object's `__text` bytes out of the image (the same
    // section-granular fold the M6 gates ride; the exported twins are
    // address-taken, so the safe level refuses them) — an entry
    // annotating bytes the output no longer carries drops, and the
    // canonical copy carries the one surviving row.
    let inputs = vec![
        LinkInput {
            name: "a.o".to_string(),
            bytes: obj_with_dice("a.o", 1, true),
        },
        LinkInput {
            name: "b.o".to_string(),
            bytes: obj_with_dice("b.o", 1, false),
        },
    ];
    let cfg = LinkConfig {
        icf: pgr_core::icf::IcfMode::All,
        ..LinkConfig::default()
    };
    let layout = link(&inputs, &[], &cfg).expect("the corpus links").layout;
    let entries = dice_entries(&layout.data_in_code);
    let base = u32::try_from(text_base(&layout)).expect("the base fits u32");
    assert_eq!(
        entries,
        vec![entry_at(base)],
        "the folded twin's entry drops; the canonical copy carries one row"
    );
}

// ---- the suppression and the default -------------------------------------------

#[test]
fn the_suppression_drops_the_command() {
    let layout = plan(|c| c.data_in_code = false);
    assert!(
        dice_command_fields(&layout.header_bytes).is_none(),
        "the suppression drops the command"
    );
    assert!(layout.data_in_code.is_empty(), "no stream, no slot");
    assert_eq!(layout.linkedit.data_in_code_off, 0);
    assert_eq!(layout.linkedit.data_in_code_size, 0);
}

#[test]
fn the_default_plans_the_pre_m30_bytes() {
    assert!(
        LinkConfig::default().data_in_code,
        "the default carries the metadata (the knob suppresses)"
    );
    // An entry-free corpus: no command, no slot — the pre-M30 bytes.
    let b = ret_corpus("main.o", 3, true);
    let layout = link(&corpus(b.build().unwrap()), &[], &LinkConfig::default())
        .expect("the corpus links")
        .layout;
    assert!(dice_command_fields(&layout.header_bytes).is_none());
    assert_eq!(layout.data_in_code, Vec::new());
    // And the carriage links deterministically (the double-link gate).
    let a = link(
        &corpus(obj_with_dice("main.o", 3, true)),
        &[],
        &LinkConfig::default(),
    )
    .expect("links")
    .layout
    .header_bytes;
    let doubled = link(
        &corpus(obj_with_dice("main.o", 3, true)),
        &[],
        &LinkConfig::default(),
    )
    .expect("links")
    .layout
    .header_bytes;
    assert_eq!(a, doubled, "the double link is stable");
}

#[test]
fn the_suppressed_and_entry_free_sizes_match_the_pre_m30_header() {
    // The suppression shrinks `sizeofcmds` by exactly the command's 16
    // bytes against the carrying link; an entry-free default plans the
    // same `sizeofcmds` as the suppressed one.
    let carrying = plan(|_| {});
    let suppressed = plan(|c| c.data_in_code = false);
    assert_eq!(
        carrying.header_bytes.len() - suppressed.header_bytes.len(),
        16,
        "the suppression drops exactly the LC_DATA_IN_CODE command"
    );
}

// ---- the refusals --------------------------------------------------------------

#[test]
fn the_parse_refuses_the_broken_shapes() {
    // An entry beyond the object's `__text`: the parser refuses (the
    // stream would annotate bytes the object does not carry).
    let b = ret_corpus("main.o", 1, true).set_data_in_code(vec![DataInCodeEntry {
        offset: 64,
        length: 4,
        kind: 1,
    }]);
    let err = pgr_core::InputObject::parse(
        pgr_core::ids::FileId(0),
        "main.o",
        b.build().expect("the fixture object builds"),
    )
    .expect_err("the beyond-text entry refuses");
    assert!(err.to_string().contains("data-in-code"), "{err}");

    // Entries without a `__text` to annotate: the parser refuses.
    let mut b = ObjectBuilder::new("loose.o");
    b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
    let b = b.set_data_in_code(vec![DataInCodeEntry {
        offset: 0,
        length: 4,
        kind: 1,
    }]);
    let err = pgr_core::InputObject::parse(
        pgr_core::ids::FileId(0),
        "loose.o",
        b.build().expect("the fixture object builds"),
    )
    .expect_err("the text-less entries refuse");
    assert!(err.to_string().contains("data-in-code"), "{err}");
}

// ---- the cache -----------------------------------------------------------------

#[test]
fn the_cached_parse_carries_the_metadata() {
    let bytes = obj_with_dice("main.o", 3, true);
    let obj = pgr_core::InputObject::parse(pgr_core::ids::FileId(0), "main.o", bytes.clone())
        .expect("the object parses");
    assert_eq!(obj.data_in_code.len(), 3, "the parse carries the entries");
    let poi = encode_poi(&obj, true);
    let round =
        decode_poi(&poi, pgr_core::ids::FileId(0), "main.o", true).expect("the POI image decodes");
    assert_eq!(
        round.data_in_code, obj.data_in_code,
        "the cache codec keeps the entries"
    );
}

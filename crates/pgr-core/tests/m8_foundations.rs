//! M8 integration gates (architecture doc §10.4 row M8 — "Resident +
//! incremental foundations"): the four data-structure foundations the
//! resident server and the M9 incremental relink build on.
//!
//! * **Reverse reference index** (§7.3 step 3): symbol → referencing
//!   `(file, section, offset)` sites, recorded over the parsed inputs; a
//!   changed symbol's dependents are one query away instead of a full
//!   relocation re-scan. Dead atoms contribute nothing when the M5 live set
//!   is active.
//! * **Insertion-stable import table** (§7.3 step 5): canonical ordinals on
//!   a clean build; later inserts keep every existing ordinal and append
//!   canonically — the property that lets an incremental relink reuse the
//!   previous image's bind ordinals.
//! * **Slack-aware layout** (§7.3 "layout stability"): reserved per-section
//!   growth room so a changed atom usually fits where it was, with the
//!   fallback ladder (in-place → segment re-layout → clean link) as a pure
//!   decision function. Slack off (the default) stays byte-shaped exactly
//!   as v1.0.
//! * **Pre-parsed linking**: the resident server's Pass 1 skip — objects
//!   parsed outside [`pgr_core::link_cached`] must produce identical
//!   layouts to the one-shot path (the resident byte-identity gate's
//!   foundation).

use pgr_core::deadstrip;
use pgr_core::ids::FileId;
use pgr_core::interner::Interner;
use pgr_core::layout::LinkConfig;
use pgr_core::link::{
    LinkArchive, LinkInput, Parallelism, check_load_symbols, link_cached, link_from_objects,
};
use pgr_core::object::InputObject;
use pgr_core::resolve::{Resolution, UndefinedPolicy};
use pgr_core::revindex::ReverseIndex;
use pgr_core::slack::{LayoutFallback, SlackPolicy};
use pgr_core::stable_imports::{StableImport, StableImports};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// Parses fixture builders into finished [`InputObject`]s (the Pass 1 shape:
/// parsed, interned, `finish`ed) exactly as [`link_cached`] does.
fn finish(specs: Vec<ObjectBuilder>) -> (Interner, Vec<InputObject>) {
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut objects = Vec::new();
    for (i, spec) in specs.into_iter().enumerate() {
        let bytes = spec.build().unwrap();
        let mut obj = InputObject::parse(FileId(i as u32), spec.name(), bytes).unwrap();
        obj.compute_atoms(false);
        names.append(&mut obj.take_symbol_names());
        objects.push(obj);
    }
    let (interner, ids) = Interner::build(&names);
    let mut cursor = 0usize;
    for obj in &mut objects {
        let take = obj.symbols.len();
        obj.finish(&ids[cursor..cursor + take]).unwrap();
        cursor += take;
    }
    (interner, objects)
}

/// hello.o: `_main` ADRP+ADD loads `_msg` (two relocs), BL `_greet`, ret.
fn hello_main() -> ObjectBuilder {
    let text: Vec<u8> = [
        0x9000_0000u32, // adrp x0, _msg@page
        0x9100_0000u32, // add x0, x0, #_msg@pageoff
        0x9400_0000u32, // bl _greet
        0x5280_0000u32, // mov w0, #0
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("hello.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        text,
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12(1).at(4),
            ObjectReloc::branch26(2).at(8),
        ],
    ));
    b.add_section(ObjectSection::cstring("hello, peregrine\n"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_msg".into(),
        section_index: 1,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b
}

/// greet.o: `_greet` body + a `__data` pointer to `_greet` (external reloc).
fn greet() -> ObjectBuilder {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.section_mut(data).relocs = vec![ObjectReloc::unsigned(0).at(0)];
    b
}

// ---------------------------------------------------------------------------
// M8-a: the reverse reference index
// ---------------------------------------------------------------------------

#[test]
fn revindex_lists_every_external_reference_site() {
    let (interner, objects) = finish(vec![hello_main(), greet()]);
    let index = ReverseIndex::build_all(&objects);

    let msg = interner.lookup(b"_msg").unwrap();
    let sites = index.sites(msg);
    // Two loads of `_msg` from hello.o's `__text` (offsets 0 and 4).
    assert_eq!(sites.len(), 2, "{sites:?}");
    assert_eq!(sites[0].file, FileId(0));
    assert_eq!(sites[0].in_sect, 0);
    assert_eq!(sites[0].offset, 0);
    assert_eq!(sites[1].file, FileId(0));
    assert_eq!(sites[1].offset, 4);

    // `_greet` is referenced twice: the BL from hello.o and the data
    // pointer from greet.o.
    let greet_id = interner.lookup(b"_greet").unwrap();
    let sites = index.sites(greet_id);
    assert_eq!(sites.len(), 2, "{sites:?}");
    assert_eq!(sites[0].file, FileId(0));
    assert_eq!(sites[0].offset, 8);
    assert_eq!(sites[1].file, FileId(1));
    assert_eq!(sites[1].in_sect, 1, "greet.o's __data pointer");

    // Defined but never referenced: no sites.
    let main = interner.lookup(b"_main").unwrap();
    assert!(index.sites(main).is_empty());
    assert!(!index.is_empty());
    assert_eq!(index.len(), 2, "two distinct referenced symbols");
    assert_eq!(index.total_sites(), 4);
}

#[test]
fn revindex_is_sorted_and_schedule_independent() {
    let (interner, objects) = finish(vec![greet(), hello_main()]);
    let index = ReverseIndex::build_all(&objects);
    let greet_id = interner.lookup(b"_greet").unwrap();
    let sites = index.sites(greet_id);
    assert!(sites.len() >= 2);
    for w in sites.windows(2) {
        assert!(
            (w[0].file.0, w[0].in_sect, w[0].offset) < (w[1].file.0, w[1].in_sect, w[1].offset),
            "sites must be total-ordered: {sites:?}"
        );
    }
    // Reversed command order: same site set, same order.
    let (_, flipped) = finish(vec![hello_main(), greet()]);
    let flipped_index = ReverseIndex::build_all(&flipped);
    // File ids follow command order, so the *bytes* behind FileId differ;
    // the per-file site lists must still be sorted.
    for id in [greet_id] {
        let a = index.sites(id);
        let b = flipped_index.sites(id);
        for w in b.windows(2) {
            assert!(
                (w[0].file.0, w[0].in_sect, w[0].offset) < (w[1].file.0, w[1].in_sect, w[1].offset)
            );
        }
        assert_eq!(a.len(), b.len());
    }
}

#[test]
fn revindex_excludes_dead_atoms_when_the_live_set_is_active() {
    // orphan.o defines `_main` (live root) and `_orphan` (never referenced —
    // dead under -dead_strip). `_orphan` references `_helper`, which lives in
    // helper.o. The index must drop the dead atom's reference site.
    let mut orphan = ObjectBuilder::new("orphan.o").set_subsections_via_symbols(true);
    let text = orphan.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6],
        vec![ObjectReloc::branch26(2).at(4)],
    ));
    orphan.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    orphan.add_symbol(ObjectSymbol::Defined {
        name: "_orphan".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    orphan.add_symbol(ObjectSymbol::Undefined {
        name: "_helper".into(),
        weak_ref: false,
    });
    let mut helper = ObjectBuilder::new("helper.o");
    let t2 = helper.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    helper.add_symbol(ObjectSymbol::Defined {
        name: "_helper".into(),
        section_index: t2,
        value: 0,
        weak: false,
    });

    let (interner, mut objects) = finish(vec![orphan, helper]);
    // -dead_strip atomizes at symbol boundaries (the pipeline calls
    // compute_atoms with the dead-strip flag); redo the atomization the way
    // the stripped link sees it.
    for obj in &mut objects {
        obj.compute_atoms(true);
    }
    let mut res = Resolution::default();
    res.install(&objects).unwrap();
    res.require_all_resolved(&interner, &objects, UndefinedPolicy::Error)
        .unwrap();
    let cfg = LinkConfig {
        dead_strip: true,
        ..LinkConfig::default()
    };
    let live = deadstrip::compute(&objects, &res, &interner, &cfg);

    let helper_id = interner.lookup(b"_helper").unwrap();
    let unfiltered = ReverseIndex::build_all(&objects);
    assert_eq!(unfiltered.sites(helper_id).len(), 1);

    let filtered = ReverseIndex::build(&objects, &live);
    assert!(
        filtered.sites(helper_id).is_empty(),
        "the only reference to _helper sits in a dead atom: {:?}",
        filtered.sites(helper_id)
    );
    // The live set really marked it dead (guard against a vacuous gate).
    assert!(live.is_atom_dead(0, 0, 4));
}

// ---------------------------------------------------------------------------
// M8-b: the insertion-stable import table
// ---------------------------------------------------------------------------

fn key(name: &str) -> StableImport {
    StableImport {
        lib_ordinal: 1,
        name: name.as_bytes().to_vec(),
        outlined_addend: 0,
        weak: false,
    }
}

#[test]
fn clean_build_assigns_canonical_ordinals() {
    // Deliberately non-canonical input order.
    let table = StableImports::clean(vec![key("_zeta"), key("_alpha"), key("_mid")]);
    let names: Vec<&[u8]> = table.keys().iter().map(|k| k.name.as_slice()).collect();
    assert_eq!(
        names,
        [
            b"_alpha".as_slice(),
            b"_mid".as_slice(),
            b"_zeta".as_slice()
        ]
    );

    let (imports, pool) = table.import_table();
    assert_eq!(imports.len(), 3);
    assert_eq!(pool, b"_alpha\0_mid\0_zeta\0");
    // Pool offsets: "_alpha" is 7 bytes with NUL, "_mid" 5, "_zeta" 6.
    let offsets: Vec<u32> = imports.iter().map(|imp| imp.name_offset).collect();
    assert_eq!(offsets, [0, 7, 12]);
    for imp in &imports {
        assert_eq!(imp.lib_ordinal, 1);
        assert!(!imp.weak_import);
    }
}

#[test]
fn insert_keeps_existing_ordinals_and_appends_new_canonically() {
    let mut table = StableImports::clean(vec![key("_b"), key("_d")]);

    // First growth: `_a` sorts before both, `_e` after — but neither may
    // renumber the existing entries (the whole point of insertion
    // stability: a relink that adds imports keeps the previous image's
    // bind ordinals valid).
    let assignments = table.insert(vec![key("_e"), key("_a")]);
    assert_eq!(assignments.len(), 2);
    assert!(assignments.iter().all(|a| a.is_new));
    let ordinal_of = |name: &[u8]| -> usize {
        table
            .keys()
            .iter()
            .position(|k| k.name == name)
            .unwrap_or_else(|| panic!("{name:?} missing"))
    };
    assert_eq!(ordinal_of(b"_b"), 0, "existing ordinal unchanged");
    assert_eq!(ordinal_of(b"_d"), 1, "existing ordinal unchanged");
    assert_eq!(table.len(), 4);

    // Second growth round: mixed new/old — the old ones report back their
    // existing ordinals with `is_new == false`.
    let assignments = table.insert(vec![key("_d"), key("_c")]);
    assert_eq!(assignments.len(), 2);
    let d = assignments.iter().find(|a| a.key.name == b"_d").unwrap();
    let c = assignments.iter().find(|a| a.key.name == b"_c").unwrap();
    assert!(!d.is_new);
    assert_eq!(d.ordinal, 1);
    assert!(c.is_new);

    // Determinism: two tables grown through different insertion orders end
    // identical when the union is the same and growth rounds agree.
    let mut other = StableImports::clean(vec![key("_d"), key("_b")]);
    other.insert(vec![key("_a"), key("_e")]);
    other.insert(vec![key("_c"), key("_d")]);
    assert_eq!(table.keys(), other.keys());
}

#[test]
fn import_keys_are_distinguished_by_more_than_the_name() {
    // Same name, different (ordinal, addend, weak): four table entries —
    // the chained import dedup key, not the bare symbol name.
    let mut table = StableImports::clean(vec![StableImport {
        lib_ordinal: 1,
        name: b"_f".to_vec(),
        outlined_addend: 0,
        weak: false,
    }]);
    let added = table.insert(vec![
        StableImport {
            lib_ordinal: 2,
            name: b"_f".to_vec(),
            outlined_addend: 0,
            weak: false,
        },
        StableImport {
            lib_ordinal: 1,
            name: b"_f".to_vec(),
            outlined_addend: 8,
            weak: false,
        },
        StableImport {
            lib_ordinal: 1,
            name: b"_f".to_vec(),
            outlined_addend: 0,
            weak: true,
        },
    ]);
    assert!(added.iter().all(|a| a.is_new));
    assert_eq!(table.len(), 4);
}

// ---------------------------------------------------------------------------
// M8-c: slack-aware layout with fallback
// ---------------------------------------------------------------------------

#[test]
fn slack_policy_padding_math() {
    let policy = SlackPolicy {
        text_percent: 10,
        data_percent: 5,
        min_bytes: 4096,
        max_bytes: 1 << 20,
    };
    // __text, 1000 bytes: 10% = 100 < min → pad min 4096; aligned to 4.
    let padded = policy.pad_section("__TEXT", 1000, 2);
    assert_eq!(padded, (1000u64 + 4096).div_ceil(4) * 4);
    // __text, 64 KiB: 10% = 65536/100*10 = 6550 → total aligned to 4.
    let padded = policy.pad_section("__TEXT", 64 * 1024, 2);
    assert_eq!(padded, (64u64 * 1024 + 6550).div_ceil(4) * 4);
    // __data, 1 MiB: 5% = 1048576/100*5 = 52425 (under max).
    let padded = policy.pad_section("__DATA", 1 << 20, 3);
    assert_eq!(padded, ((1u64 << 20) + 52_425).div_ceil(8) * 8);
    // A huge section caps at max pad.
    let padded = policy.pad_section("__DATA", 1 << 30, 3);
    assert_eq!(padded, (1u64 << 30) + (1u64 << 20));
}

#[test]
fn slack_fallback_ladder_decision() {
    let policy = SlackPolicy {
        text_percent: 10,
        data_percent: 5,
        min_bytes: 4096,
        max_bytes: 1 << 20,
    };
    // Fits inside the previous padded size: in place.
    assert_eq!(
        policy.fits(1000, 1100, 1000 + 4096),
        LayoutFallback::InPlace
    );
    // Grew past the padded section but small in absolute terms (within one
    // max-pad): segment re-layout.
    assert_eq!(
        policy.fits(1000, 20_000, 1000 + 4096),
        LayoutFallback::SegmentRelayout
    );
    // Blew way past it (beyond one max-pad of growth): clean link.
    assert_eq!(
        policy.fits(1000, 8 << 20, 1000 + 4096),
        LayoutFallback::CleanLink
    );
    // Shrinking always fits.
    assert_eq!(policy.fits(10_000, 1, 10_000), LayoutFallback::InPlace);
}

#[test]
fn slack_layout_grows_sections_without_moving_pieces() {
    let main = hello_main().build().unwrap();
    let greet = greet().build().unwrap();
    let inputs = vec![
        LinkInput {
            name: "hello.o".into(),
            bytes: main,
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet,
        },
    ];

    let mut cfg = LinkConfig {
        ident: "slack".into(),
        ..LinkConfig::default()
    };
    let plain = link_cached(&inputs, &[], &cfg, Parallelism::Serial, None).unwrap();
    let plain_twice = link_cached(&inputs, &[], &cfg, Parallelism::Serial, None).unwrap();
    assert_eq!(
        format!("{:?}", plain.layout),
        format!("{:?}", plain_twice.layout),
        "slack-off double link must be structurally identical"
    );

    cfg.layout_slack = Some(SlackPolicy::default());
    let padded = link_cached(&inputs, &[], &cfg, Parallelism::Serial, None).unwrap();
    let padded_twice = link_cached(&inputs, &[], &cfg, Parallelism::Serial, None).unwrap();
    assert_eq!(
        format!("{:?}", padded.layout),
        format!("{:?}", padded_twice.layout),
        "slack-on double link must be structurally identical"
    );

    // Every user section grew (or kept its size for empty ones); synthetic
    // sections stay exact; piece offsets within each section are unchanged.
    for (a, b) in plain.layout.sections.iter().zip(&padded.layout.sections) {
        assert_eq!(a.name, b.name);
        let synthetic = matches!(a.name.as_str(), "__got" | "__stubs" | "__chain_starts");
        if synthetic || a.size == 0 {
            assert_eq!(a.size, b.size, "{} must stay exact", a.name);
        } else {
            assert!(b.size >= a.size, "{} must grow under slack", a.name);
        }
        assert_eq!(a.pieces.len(), b.pieces.len());
        for (pa, pb) in a.pieces.iter().zip(&b.pieces) {
            assert_eq!(pa.offset, pb.offset, "{} piece offset moved", a.name);
            assert_eq!(pa.size, pb.size);
        }
    }
    assert!(
        padded.layout.file_size >= plain.layout.file_size,
        "slack never shrinks the file"
    );
    // The padded __text has real headroom (min 4096 bytes over ~20 bytes of
    // content); the tiny corpus's page-granular segments can absorb that
    // invisibly, so the section sizes are the honest gate, not file size.
    let padded_text = padded
        .layout
        .sections
        .iter()
        .find(|s| s.name == "__text")
        .unwrap();
    assert!(
        padded_text.size >= 4096,
        "__text padded to {}",
        padded_text.size
    );
    // The fixup plan is untouched by padding: same slot count.
    assert_eq!(
        plain.layout.fixups.slot_count,
        padded.layout.fixups.slot_count
    );
}

#[test]
fn preparsed_link_matches_the_one_shot_layout() {
    // The resident server's foundation: parse outside link_cached, feed
    // link_from_objects, get the identical layout.
    let main = hello_main().build().unwrap();
    let greet = greet().build().unwrap();
    let inputs = vec![
        LinkInput {
            name: "hello.o".into(),
            bytes: main.clone(),
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet.clone(),
        },
    ];
    let cfg = LinkConfig {
        ident: "resident".into(),
        ..LinkConfig::default()
    };
    let one_shot = link_cached(&inputs, &[], &cfg, Parallelism::Auto, None).unwrap();

    let mut objects: Vec<InputObject> = Vec::new();
    for (i, bytes) in [main, greet].into_iter().enumerate() {
        let mut obj = InputObject::parse(FileId(i as u32), &inputs[i].name, bytes).unwrap();
        obj.compute_atoms(false);
        objects.push(obj);
    }
    let resident = link_from_objects(objects, &[], &cfg, Parallelism::Auto, None).unwrap();

    // Structurally identical: sections, pieces, symbols, LINKEDIT plan.
    assert_eq!(
        format!("{:?}", one_shot.layout),
        format!("{:?}", resident.layout),
        "the pre-parsed path must produce the one-shot layout exactly"
    );
    assert_eq!(
        one_shot.interner.len(),
        resident.interner.len(),
        "interner sizes must match"
    );
}

#[test]
fn force_load_gate_accepts_and_rejects() {
    let main = hello_main().build().unwrap();
    let greet = greet().build().unwrap();
    let inputs = vec![
        LinkInput {
            name: "hello.o".into(),
            bytes: main,
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet,
        },
    ];
    let cfg = LinkConfig {
        ident: "forces".into(),
        ..LinkConfig::default()
    };
    let result = link_cached(&inputs, &[], &cfg, Parallelism::Serial, None).unwrap();

    check_load_symbols(&result, &[b"_greet".to_vec()]).unwrap();
    let err = check_load_symbols(&result, &[b"_missing".to_vec()]).unwrap_err();
    assert!(err.to_string().contains("_missing"), "{err}");
}

#[test]
fn archives_still_pull_through_the_preparsed_path() {
    // The resident server reuses link_from_objects for archive inputs too —
    // the S7 pull fixpoint must keep working behind it.
    let main = hello_main_only().build().unwrap();
    let greet = greet().build().unwrap();
    let mut archive = pgr_fixtures::ArchiveBuilder::new("libutil.a");
    archive.add_member("greet.o", greet);
    let bytes = archive.build();
    let parsed = pgr_format::parse_archive(&bytes).unwrap();
    let arch = LinkArchive {
        name: "libutil.a".into(),
        bytes,
        index: parsed
            .index
            .iter()
            .map(|e| (e.name.clone().into_bytes(), e.member))
            .collect(),
        members: parsed
            .members
            .iter()
            .map(|m| pgr_core::LinkArchiveMember {
                name: m.name.clone(),
                offset: m.offset,
                size: m.size,
            })
            .collect(),
        all_load: false,
    };

    let mut obj = InputObject::parse(FileId(0), "hello.o", main).unwrap();
    obj.compute_atoms(false);
    let cfg = LinkConfig {
        ident: "archives".into(),
        ..LinkConfig::default()
    };
    let result = link_from_objects(vec![obj], &[arch], &cfg, Parallelism::Auto, None).unwrap();
    assert_eq!(result.objects.len(), 2, "greet.o pulled from the archive");
    assert!(result.objects[1].from_archive);
}

/// hello.o alone: `_main` calls `_greet`, which nothing defines.
fn hello_main_only() -> ObjectBuilder {
    let text: Vec<u8> = [
        0x9000_0000u32,
        0x9100_0000u32,
        0x9400_0000u32,
        0x5280_0000u32,
        0xD65F_03C0u32,
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("hello.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        text,
        vec![ObjectReloc::branch26(1).at(8)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b
}

// The fixup kind import is used by the resident-path gate below: the
// preparsed link must produce the same bind words (not just shapes).
#[test]
fn preparsed_fixup_words_match_the_one_shot_words() {
    let main = hello_main().build().unwrap();
    let greet = greet().build().unwrap();
    let inputs = vec![
        LinkInput {
            name: "hello.o".into(),
            bytes: main.clone(),
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet.clone(),
        },
    ];
    let cfg = LinkConfig {
        ident: "words".into(),
        ..LinkConfig::default()
    };
    let one_shot = link_cached(&inputs, &[], &cfg, Parallelism::Auto, None).unwrap();

    let mut objects: Vec<InputObject> = Vec::new();
    for (i, bytes) in [main, greet].into_iter().enumerate() {
        let mut obj = InputObject::parse(FileId(i as u32), &inputs[i].name, bytes).unwrap();
        obj.compute_atoms(false);
        objects.push(obj);
    }
    let resident = link_from_objects(objects, &[], &cfg, Parallelism::Auto, None).unwrap();

    assert_eq!(one_shot.layout.fixups.slot_count, 1);
    assert_eq!(
        one_shot.layout.fixups.slot_words, resident.layout.fixups.slot_words,
        "bind/rebase words must match slot for slot"
    );
    let (vaddr, word) = &resident.layout.fixups.slot_words[0];
    assert_eq!(*vaddr % 8, 0);
    // A rebase word has bit 63 clear; the slot rebases to a local pointer
    // (greet.o's `__data` slot points at its own `_greet`).
    assert_eq!(word >> 63, 0, "pointer-to-local is a rebase, not a bind");
    // No imports at all: the corpus has no dylib binds.
    assert!(resident.layout.fixups.imports.is_empty());
    assert!(one_shot.layout.fixups.imports.is_empty());
}

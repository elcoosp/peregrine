//! M9 tier-2b gates — the per-symbol change-propagation planner
//! (architecture doc §7.3 step 3; roadmap row M9 GA "the reverse-index
//! tier"). The planner is the §7.3 decision core: seeds = changed input
//! sections (record digest diff), dependents = the reverse index's
//! referencing sites, prediction = the union's placed output ranges. The
//! patch planner's propagation gate leans on it; these tests pin the
//! scope decisions the gate inherits.

use pgr_core::layout::{Layout, LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link_cached};
use pgr_core::propagate::{PropagationScope, SectionDigest, predict, section_digests};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// hello.o: `_main` (ADR P+ADD loads `_msg`, BL `_greet`, ret) — the same
/// shape the emit-tier suite links, so the two suites' corpora agree.
fn hello(text_bytes: usize, body_flip: bool) -> ObjectBuilder {
    let mut words: Vec<u32> = vec![
        0x9000_0000, // adrp x0, _msg@page
        0x9100_0000, // add x0, x0, #_msg@pageoff
        0x9400_0000, // bl _greet
        0x5280_0000, // mov w0, #0 (flipped: #1)
        0xD65F_03C0, // ret
    ];
    if body_flip {
        words[3] = 0x5280_0020;
    }
    words.resize(text_bytes / 4, 0xD503_201F);
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
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
    b.add_section(ObjectSection::cstring(if body_flip {
        "merci, peregrine\n"
    } else {
        "hello, peregrine\n"
    }));
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

/// greet.o: `_greet` defined at `value` inside `__text`, `__data` pointing
/// at itself (an in-file section-relative reference).
fn greet(value: u64) -> ObjectBuilder {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0x1F, 0x20, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6], // nop; ret
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value,
        weak: false,
    });
    b.section_mut(data).relocs = vec![ObjectReloc::unsigned(0).at(0)];
    b
}

fn inputs(hello: &ObjectBuilder, greet: &ObjectBuilder) -> Vec<LinkInput> {
    vec![
        LinkInput {
            name: "hello.o".into(),
            bytes: hello.build().unwrap(),
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet.build().unwrap(),
        },
    ]
}

fn link(inputs: &[LinkInput]) -> (Layout, Vec<pgr_core::object::InputObject>) {
    let cfg = LinkConfig {
        ident: "m9-propagate".into(),
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let result = link_cached(inputs, &[], &cfg, Parallelism::Auto, None).unwrap();
    (result.layout, result.objects)
}

/// The output file range a `(file, section)` pair occupies, from the
/// layout's placed pieces (the predicate the gate checks tiles against).
fn placed_range(layout: &Layout, file: u32, in_sect: usize) -> Option<(u64, u64)> {
    let mut lo = u64::MAX;
    let mut hi = 0u64;
    for sect in &layout.sections {
        for piece in &sect.pieces {
            if piece.file.0 == file && piece.in_sect == in_sect {
                lo = lo.min(sect.file_off + piece.offset);
                hi = hi.max(sect.file_off + piece.offset + piece.size);
            }
        }
    }
    (lo < hi).then_some((lo, hi))
}

fn covers(scope: &PropagationScope, layout: &Layout, file: u32, in_sect: usize) -> bool {
    let Some((lo, hi)) = placed_range(layout, file, in_sect) else {
        return false;
    };
    scope.ranges.iter().any(|r| r.start <= lo && hi <= r.end)
}

#[test]
fn section_digests_are_deterministic_and_content_sensitive() {
    let old = inputs(&hello(64, false), &greet(0));
    let old_again = inputs(&hello(64, false), &greet(0));
    let new = inputs(&hello(64, true), &greet(0));

    let d1 = section_digests(&link(&old).1);
    let d2 = section_digests(&link(&old_again).1);
    let d3 = section_digests(&link(&new).1);

    assert_eq!(d1, d2, "digests are a pure function of the parse");
    assert_ne!(d1, d3, "a body edit changes the parse's digests");
    // The digest list is keyed `(file, section)` in parse order.
    let keys: Vec<(u32, usize)> = d1.iter().map(|d| (d.file, d.in_sect)).collect();
    assert_eq!(keys, vec![(0, 0), (0, 1), (1, 0), (1, 1)]);

    let changed: Vec<(u32, usize)> = d1
        .iter()
        .zip(&d3)
        .filter(|(a, b)| a.sha != b.sha)
        .map(|(a, _)| (a.file, a.in_sect))
        .collect();
    assert_eq!(
        changed,
        vec![(0, 0), (0, 1)],
        "only hello.o's edited sections change (SectionDigest is content-scoped)"
    );
}

#[test]
fn predict_without_seeds_predicts_nothing() {
    let objects = link(&inputs(&hello(64, false), &greet(0))).1;
    let prev = section_digests(&objects);
    let layout = link(&inputs(&hello(64, false), &greet(0))).0;

    let scope = predict(&prev, &objects, &layout);
    assert!(scope.seeds.is_empty(), "an identical parse has no seeds");
    assert!(
        scope.ranges.is_empty(),
        "no seeds means no predicted output ranges"
    );
}

#[test]
fn predict_scopes_a_definition_change_to_its_dependents() {
    // greet.o's `_greet` moves one instruction down (same section size —
    // the skeleton holds): hello.o's `BL _greet` retargets. The scope must
    // cover greet.o's edited text (the seed's own placement) *and*
    // hello.o's referencing text (the reverse index's dependent).
    let old = link(&inputs(&hello(64, false), &greet(0)));
    let new = link(&inputs(&hello(64, false), &greet(4)));

    let prev = section_digests(&old.1);
    let scope = predict(&prev, &new.1, &new.0);

    assert_eq!(scope.seeds, vec![(1, 0)], "only greet.o's __text changed");
    assert!(
        covers(&scope, &new.0, 1, 0),
        "the seed's own placement is predicted"
    );
    assert!(
        covers(&scope, &new.0, 0, 0),
        "the dependent (hello.o's BL site) is predicted"
    );
    // hello.o's `__cstring` did not change and references nothing — it is
    // neither a seed nor a dependent (greet.o's `__data` *is* one: its
    // pointer references the moved `_greet`).
    assert!(
        !covers(&scope, &new.0, 0, 1),
        "an unrelated section stays outside the scope"
    );
}

#[test]
fn predict_scopes_a_symbol_free_section_to_itself() {
    // hello.o's `__cstring` changes (a literal edit): its only symbol
    // (`_msg`) is referenced nowhere, so the scope is exactly the
    // section's own placement — dependents add nothing.
    let old = link(&inputs(&hello(64, false), &greet(0)));
    let new = link(&inputs(&hello(64, true), &greet(0)));

    let prev = section_digests(&old.1);
    let scope = predict(&prev, &new.1, &new.0);

    assert!(scope.seeds.contains(&(0, 1)), "the cstring edit is a seed");
    assert!(
        covers(&scope, &new.0, 0, 1),
        "the literal's own placement is predicted"
    );
    // The seed's *containing output section* rides along (a seed piece
    // growing inside slack shifts its siblings — here hello's `__text`
    // edit covers the merged output `__text`, greet's piece included);
    // greet.o's `__data` sits in another output section entirely.
    assert!(
        !covers(&scope, &new.0, 1, 1),
        "an output section no seed touches stays outside the scope"
    );
}

#[test]
fn predict_walks_every_reference_site_of_a_changed_definition() {
    // The scope's reverse index deliberately skips liveness filtering
    // (the `build_all` over-approximation): *every* referencing site of a
    // changed definition predicts, because a stale prediction is a false
    // fallback (safe) while a missed dependent is a stale byte (not).
    // hello.o gains a second, unreferenced-from-entry `BL _greet` site in
    // its own section; when `_greet` moves, both sites predict.
    let mut wide_hello = hello(64, false);
    wide_hello.add_section(ObjectSection::text(
        "__extra",
        vec![0x94, 0x00, 0x00, 0x00], // bl _greet
        vec![ObjectReloc::branch26(2).at(0)],
    ));
    let old = link(&inputs(&wide_hello, &greet(0)));
    let new = link(&inputs(&wide_hello, &greet(4)));

    let prev = section_digests(&old.1);
    let scope = predict(&prev, &new.1, &new.0);

    assert!(
        covers(&scope, &new.0, 1, 0),
        "the seed's own placement is predicted"
    );
    assert!(
        covers(&scope, &new.0, 0, 0),
        "the entry site (hello.o's `__text` BL) is predicted"
    );
    assert!(
        covers(&scope, &new.0, 0, 2),
        "the second site (hello.o's `__extra` BL) is predicted"
    );
}

#[test]
fn digest_codec_is_lossless_and_keyed() {
    // SectionDigest travels through the record as a pointer-free blob;
    // pin its shape here (the record codec's own roundtrip is the emit
    // suite's gate).
    let objects = link(&inputs(&hello(64, false), &greet(0))).1;
    let digests = section_digests(&objects);
    let first: &SectionDigest = &digests[0];
    assert_eq!((first.file, first.in_sect), (0, 0));
    assert_eq!(first.sha.len(), 32, "SHA-256");
}

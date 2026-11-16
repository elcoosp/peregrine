//! M47 — the branch-island suppression released: `-no_branch_islands` —
//! ld64's knob (`fAllowBranchIslands`, on by default) is the Pass-3
//! decision the M6 veneer fixed point reads: the layout no longer plans
//! a veneer for an out-of-range `B`/`BL`, and a branch the ±128 MiB
//! `imm26` window cannot reach refuses the link with the site named
//! (ld64 reports the same condition when islands are disabled). The
//! default (`true`) keeps every pre-M47 link byte-identical — the
//! veneer set is a pure function of the placed addresses either way —
//! and an in-range corpus plans identical bytes under both decisions.

use pgr_core::layout::{LinkConfig, SynthKind};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

const MIB: usize = 1 << 20;

/// a.o: 64 MiB `__text`, `_main` at 0 branch-rel'ing to `_far`
/// (forward overflow site), `_far` undefined here.
fn obj_a() -> Vec<u8> {
    let mut b = ObjectBuilder::new("a.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0u8; 64 * MIB],
        vec![ObjectReloc::branch26(1).at(0)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_far".into(),
        weak_ref: false,
    });
    b.build().expect("the fixture object builds")
}

/// b.o: 66 MiB `__text` with `_b` (pure distance between the sites).
fn obj_b() -> Vec<u8> {
    let mut b = ObjectBuilder::new("b.o");
    let text = b.add_section(ObjectSection::text("__text", vec![0u8; 66 * MIB], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_b".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// c.o: 2 MiB `__text` with `_far` defined at 0 and a branch back to
/// `_main` (backward overflow site).
fn obj_c() -> Vec<u8> {
    let mut b = ObjectBuilder::new("c.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0u8; 2 * MIB],
        vec![ObjectReloc::branch26(1).at(0)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_far".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_main".into(),
        weak_ref: false,
    });
    b.build().expect("the fixture object builds")
}

/// The M6 giant-text corpus: site→target distances land at ~130 MiB
/// both ways — beyond ±128 MiB, fixable with one veneer per site.
fn giant_inputs() -> Vec<LinkInput> {
    vec![
        LinkInput {
            name: "a.o".into(),
            bytes: obj_a(),
        },
        LinkInput {
            name: "b.o".into(),
            bytes: obj_b(),
        },
        LinkInput {
            name: "c.o".into(),
            bytes: obj_c(),
        },
    ]
}

/// The veneer pieces the layout planned (one per out-of-range site).
fn veneer_count(layout: &pgr_core::layout::Layout) -> usize {
    layout
        .sections
        .iter()
        .flat_map(|s| &s.pieces)
        .filter(|p| {
            matches!(
                &p.synth,
                Some(s) if matches!(s.kind, SynthKind::Veneer { .. })
            )
        })
        .count()
}

#[test]
fn the_default_plans_the_veneers() {
    // Pre-M47 shape: the M6 fixed point inserts one veneer per
    // overflowing site — the default keeps it byte for byte.
    let cfg = LinkConfig {
        ident: "m47-islands".into(),
        ..LinkConfig::default()
    };
    let layout = link(&giant_inputs(), &[], &cfg)
        .expect("the giant-text link plans with the veneer default")
        .layout;
    assert_eq!(
        veneer_count(&layout),
        2,
        "one veneer per out-of-range site under the default"
    );
}

#[test]
fn no_branch_islands_refuses_the_overflow() {
    // The named suppression: the fixed point refuses to plan a veneer,
    // and the out-of-range branch it cannot encode is the typed refusal
    // — ld64's "branch out of range" with islands disabled, the house
    // verdict naming the site and the fix.
    let cfg = LinkConfig {
        ident: "m47-no-islands".into(),
        branch_islands: false,
        ..LinkConfig::default()
    };
    let err = link(&giant_inputs(), &[], &cfg)
        .expect_err("the suppressed link refuses the out-of-range branch");
    let message = err.to_string();
    assert!(
        message.contains("-no_branch_islands"),
        "the refusal names the knob: {message}"
    );
    assert!(
        message.contains("branch"),
        "the refusal names the out-of-range condition: {message}"
    );
}

#[test]
fn the_in_range_corpus_plans_identical_bytes_under_both_decisions() {
    // The M47 lock: an in-range corpus plans the same bytes under
    // either decision — the fixed point inserts no veneers either way,
    // so the suppression is a no-op where it has nothing to refuse.
    let small = |name: &str, defs: &[(&str, bool)]| {
        let mut b = ObjectBuilder::new(name);
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6], // ret; ret
            vec![],
        ));
        let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
        for (i, (n, def)) in defs.iter().enumerate() {
            if *def {
                b.add_symbol(ObjectSymbol::Defined {
                    name: (*n).into(),
                    section_index: if i == 0 { text } else { data },
                    value: 0,
                    weak: false,
                });
            }
        }
        b.build().expect("the fixture object builds")
    };
    let inputs = vec![
        LinkInput {
            name: "m.o".into(),
            bytes: small("m.o", &[("_main", true), ("_far", false)]),
        },
        LinkInput {
            name: "f.o".into(),
            bytes: small("f.o", &[("_far", true)]),
        },
    ];
    let islands = LinkConfig {
        ident: "m47-parity".into(),
        ..LinkConfig::default()
    };
    let suppressed = LinkConfig {
        ident: "m47-parity".into(),
        branch_islands: false,
        ..LinkConfig::default()
    };
    let a = link(&inputs, &[], &islands)
        .expect("the in-range islands link plans")
        .layout;
    let b = link(&inputs, &[], &suppressed)
        .expect("the in-range suppressed link plans")
        .layout;
    assert_eq!(a.file_size, b.file_size, "the file size holds");
    assert_eq!(veneer_count(&a), 0, "no veneers under the default");
    assert_eq!(veneer_count(&b), 0, "no veneers under the suppression");
    for (sa, sb) in a.segments.iter().zip(b.segments.iter()) {
        assert_eq!(sa.vmaddr, sb.vmaddr, "{} holds its address", sa.name);
        assert_eq!(sa.vmsize, sb.vmsize, "{} holds its size", sa.name);
        assert_eq!(sa.fileoff, sb.fileoff, "{} holds its offset", sa.name);
    }
}

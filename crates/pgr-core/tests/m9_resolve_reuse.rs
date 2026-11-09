//! M9 tier-2c gates — the incremental resolve over the propagation index
//! (architecture doc §7.3 step 3; roadmap row M9 GA "the incremental
//! resolve over the propagation index"). The tier-2b planner scopes
//! *bytes*; this rung reuses the Pass-2 *decisions*: recorded winners for
//! every name the seed sections cannot touch, a full precedence replay for
//! the names they can, and the full resolve whenever the reuse shape
//! (input file list, dylib export set) moves. The gate is equality: the
//! reused resolution must be indistinguishable from the full one, or the
//! plan refuses.

use pgr_core::ids::FileId;
use pgr_core::interner::Interner;
use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism, link_cached};
use pgr_core::object::InputObject;
use pgr_core::propagate::{SectionDigest, section_digests};
use pgr_core::resolve::{Dylib, Resolution, ResolutionSnapshot, UndefinedPolicy};
use pgr_core::resolve_reuse::{ResolveReuseSeed, ReuseFallback, install_reused, plan_reuse};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// Parses the builders in command-line order and interns every symbol name
/// plus every dylib export (the same Pass 1 + interning batch
/// `link_cached` runs: object names first, dylib exports after).
fn parse(builders: &[ObjectBuilder], dylibs: &[Dylib]) -> (Interner, Vec<InputObject>) {
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut objects = Vec::new();
    for (i, spec) in builders.iter().enumerate() {
        let bytes = spec.build().unwrap();
        let mut obj = InputObject::parse(FileId(i as u32), spec.name(), bytes).unwrap();
        names.append(&mut obj.take_symbol_names());
        objects.push(obj);
    }
    for dylib in dylibs {
        names.extend(dylib.exports.iter().cloned());
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

/// The full Pass 2 (the reference the reuse path must reproduce).
fn full_resolve(
    objects: &[InputObject],
    interner: &Interner,
    dylibs: &[Dylib],
) -> Result<Resolution, pgr_core::LinkError> {
    let mut res = Resolution::default();
    res.install(objects)?;
    if !dylibs.is_empty() {
        let export_ids: Vec<pgr_core::ids::StringId> = dylibs
            .iter()
            .flat_map(|d| d.exports.iter())
            .filter_map(|name| interner.lookup(name))
            .collect();
        res.install_dylibs(dylibs, &export_ids);
    }
    res.require_all_resolved(interner, objects, UndefinedPolicy::Error)?;
    Ok(res)
}

/// The reused Pass 2: plan the reuse from the recorded state, then install
/// it. Panics with the fallback when the shape moved (tests that expect a
/// fallback assert on `plan_reuse` directly instead).
fn reused_resolve(
    recorded: &ResolutionSnapshot,
    prev: &[SectionDigest],
    objects: &[InputObject],
    interner: &Interner,
    dylibs: &[Dylib],
) -> Result<Resolution, pgr_core::LinkError> {
    let plan = plan_reuse(recorded, prev, interner, objects, dylibs)
        .map_err(|f| panic!("unexpected reuse fallback: {f}"))?;
    install_reused(
        &plan,
        recorded,
        interner,
        objects,
        dylibs,
        UndefinedPolicy::Error,
    )
}

/// Captures the baseline state a relink reuses: the Pass-2 snapshot and
/// the parse's section-digest table (the record's v3 payload).
fn baseline(
    builders: &[ObjectBuilder],
    dylibs: &[Dylib],
) -> (ResolutionSnapshot, Vec<SectionDigest>) {
    let (interner, objects) = parse(builders, dylibs);
    let res = full_resolve(&objects, &interner, dylibs).unwrap();
    let snapshot = ResolutionSnapshot::capture(&objects, &interner, &res, dylibs);
    (snapshot, section_digests(&objects))
}

/// a.o: `_main` (nop; ret) plus `_msg` over the `__cstring`; optional body
/// flip and a weak/strong `_main`.
fn alpha(body_flip: bool, main_weak: bool) -> ObjectBuilder {
    let text: Vec<u8> = if body_flip {
        vec![0x1F, 0x20, 0x03, 0xD5, 0x00, 0x00, 0x00, 0x00] // nop; .word 0
    } else {
        vec![0x1F, 0x20, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6] // nop; ret
    };
    let mut b = ObjectBuilder::new("alpha.o");
    let sect = b.add_section(ObjectSection::text("__text", text, vec![]));
    b.add_section(ObjectSection::cstring(if body_flip {
        "merci, peregrine\n"
    } else {
        "alpha string\n"
    }));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: main_weak,
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

/// b.o: `_greet` defined at `value`, optionally weak, plus a `_dup` in
/// `__data` for the rank-flip gate.
fn beta(value: u64, weak: bool, dup_weak: bool) -> ObjectBuilder {
    let mut b = ObjectBuilder::new("beta.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value,
        weak,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_dup".into(),
        section_index: data,
        value: 0,
        weak: dup_weak,
    });
    b
}

/// c.o: `_dup` defined (the second candidate the rank-flip gate flips to).
fn gamma(dup_weak: bool) -> ObjectBuilder {
    let mut b = ObjectBuilder::new("gamma.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0x1F, 0x20, 0x03, 0xD5], // nop
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_dup".into(),
        section_index: text,
        value: 0,
        weak: dup_weak,
    });
    b
}

fn lib_system(exports: &[&[u8]]) -> Dylib {
    Dylib {
        install_name: "/usr/lib/libSystem.B.dylib".into(),
        current_version: 0,
        compatibility_version: 0,
        exports: exports.iter().map(|e| e.to_vec()).collect(),
        weak: false,
        reexport: false,
    }
}

#[test]
fn unchanged_relink_reuses_every_winner_and_matches_the_full_resolve() {
    let specs = vec![alpha(false, false), beta(0, false, false)];
    let (snapshot, prev) = baseline(&specs, &[]);

    let (interner, objects) = parse(&specs, &[]);
    let full = full_resolve(&objects, &interner, &[]).unwrap();
    let reused = reused_resolve(&snapshot, &prev, &objects, &interner, &[]).unwrap();

    assert!(
        full.equivalent(&reused),
        "unchanged relink must reproduce the full resolve"
    );
    let plan = plan_reuse(&snapshot, &prev, &interner, &objects, &[]).unwrap();
    assert!(plan.seeds.is_empty(), "an unchanged parse seeds nothing");
    assert!(
        plan.redecide.is_empty(),
        "an unchanged parse re-decides nothing"
    );
    assert_eq!(
        plan.reused, 4,
        "_main, _msg, _greet and _dup all ride the record"
    );
}

#[test]
fn body_edit_redecides_only_the_seeded_sections_names_and_matches_full() {
    let baseline_specs = vec![alpha(false, false), beta(0, false, false)];
    let (snapshot, prev) = baseline(&baseline_specs, &[]);

    let relink_specs = vec![alpha(true, false), beta(0, false, false)];
    let (interner, objects) = parse(&relink_specs, &[]);
    let full = full_resolve(&objects, &interner, &[]).unwrap();
    let reused = reused_resolve(&snapshot, &prev, &objects, &interner, &[]).unwrap();

    assert!(
        full.equivalent(&reused),
        "a body edit must land on the full resolve's decisions"
    );

    let plan = plan_reuse(&snapshot, &prev, &interner, &objects, &[]).unwrap();
    assert_eq!(
        plan.seeds,
        vec![(0u32, 0usize), (0, 1)],
        "both of alpha.o's sections move (body bytes + cstring)"
    );
    assert_eq!(
        plan.redecide,
        vec![b"_main".to_vec(), b"_msg".to_vec()],
        "only the names alpha.o defines are re-decided"
    );
    assert_eq!(plan.reused, 2, "_greet and _dup ride the record");
}

#[test]
fn rank_flip_retargets_the_winner_and_matches_the_full_resolve() {
    // Baseline: gamma.o's `_dup` is weak, beta.o's is strong — beta wins.
    let baseline_specs = vec![alpha(false, false), beta(0, false, false), gamma(true)];
    let (snapshot, prev) = baseline(&baseline_specs, &[]);
    {
        let (interner, objects) = parse(&baseline_specs, &[]);
        let res = full_resolve(&objects, &interner, &[]).unwrap();
        let dup = interner.lookup(b"_dup").unwrap();
        assert_eq!(
            res.def(dup).map(|d| d.file.0),
            Some(1u32),
            "the strong definition wins the baseline"
        );
    }

    // Relink: beta.o's `_dup` drops to weak — the winner keeps its file
    // (beta.o installs first, file order) but flips rank Strong → Weak, an
    // edit only beta.o's digest sees.
    let relink_specs = vec![alpha(false, false), beta(0, false, true), gamma(true)];
    let (interner, objects) = parse(&relink_specs, &[]);
    let full = full_resolve(&objects, &interner, &[]).unwrap();
    let reused = reused_resolve(&snapshot, &prev, &objects, &interner, &[]).unwrap();

    assert!(
        full.equivalent(&reused),
        "the rank flip must retarget the reused winner too"
    );
    let dup = interner.lookup(b"_dup").unwrap();
    let flipped = reused.def(dup).expect("_dup still resolves");
    assert_eq!(
        flipped.file.0, 1u32,
        "beta.o installs first and keeps the tie"
    );
    assert_eq!(
        flipped.rank,
        pgr_core::resolve::Rank::WeakDef,
        "the rank flip propagated"
    );
}

#[test]
fn duplicate_strong_introduced_lands_the_full_resolve_error() {
    let baseline_specs = vec![alpha(false, false), beta(0, false, false)];
    let (snapshot, prev) = baseline(&baseline_specs, &[]);

    // The relink plants a second strong `_main` in beta.o — the collision
    // sits inside the seeded set, so the replay must reach the same
    // duplicate error the full walk reaches.
    let mut relink = beta(0, false, false);
    let text = relink.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    relink.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let relink_specs = vec![alpha(false, false), relink];
    let (interner, objects) = parse(&relink_specs, &[]);

    let full = full_resolve(&objects, &interner, &[]);
    let reused = reused_resolve(&snapshot, &prev, &objects, &interner, &[]);
    match (full, reused) {
        (Err(pgr_core::LinkError::Symbol { .. }), Err(pgr_core::LinkError::Symbol { .. })) => {}
        _ => panic!("both paths must reject the duplicate strong definition"),
    }
}

#[test]
fn changed_input_file_list_falls_back_to_the_full_resolve() {
    let baseline_specs = vec![alpha(false, false), beta(0, false, false)];
    let (snapshot, prev) = baseline(&baseline_specs, &[]);

    let relink_specs = vec![alpha(false, false), beta(0, false, false), gamma(true)];
    let (interner, objects) = parse(&relink_specs, &[]);
    let fallback = plan_reuse(&snapshot, &prev, &interner, &objects, &[]).unwrap_err();
    assert!(
        matches!(fallback, ReuseFallback::FileListChanged),
        "a third input moves the file identity the snapshot vouches for"
    );

    // The ladder's bottom rung: the full resolve is always available.
    let full = full_resolve(&objects, &interner, &[]).unwrap();
    let again = full_resolve(&objects, &interner, &[]).unwrap();
    assert!(
        full.equivalent(&again),
        "the full resolve is its own reference"
    );
}

#[test]
fn changed_dylib_export_set_falls_back_to_the_full_resolve() {
    let dylibs = vec![lib_system(&[b"_greet".as_slice()])];
    let baseline_specs = vec![alpha(false, false)];
    let (snapshot, prev) = baseline(&baseline_specs, &dylibs);

    let grown = vec![lib_system(&[b"_greet".as_slice(), b"_strlen".as_slice()])];
    let (interner, objects) = parse(&baseline_specs, &grown);
    let fallback = plan_reuse(&snapshot, &prev, &interner, &objects, &grown).unwrap_err();
    assert!(
        matches!(fallback, ReuseFallback::DylibSetChanged),
        "an export-set change moves the two-level ordinal map"
    );
}

#[test]
fn randomized_edit_walk_keeps_the_reused_resolution_equal_to_the_full_one() {
    // xorshift64* (the M9 GA randomized-edit gate's generator): body flips,
    // value nudges and weak toggles — every shape the digest table sees —
    // must keep the reused decisions equal to the full resolve.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };

    let mut specs = vec![alpha(false, false), beta(0, false, false)];
    let (mut snapshot, mut prev) = baseline(&specs, &[]);
    for step in 0..30usize {
        let dice = next() % 4;
        match dice {
            0 => specs[0] = alpha(next() % 2 == 0, false),
            1 => specs[1] = beta(next() % 16, false, false),
            2 => specs[1] = beta(0, next() % 2 == 0, false),
            _ => {}
        }
        let (interner, objects) = parse(&specs, &[]);
        let full = full_resolve(&objects, &interner, &[]).unwrap();
        let reused = reused_resolve(&snapshot, &prev, &objects, &interner, &[]).unwrap();
        assert!(
            full.equivalent(&reused),
            "step {step} (dice {dice}): reused resolution diverged from the full resolve"
        );
        snapshot = ResolutionSnapshot::capture(&objects, &interner, &full, &[]);
        prev = section_digests(&objects);
    }
}

/// The pipeline-level gate (M9 GA rung, the record-side wiring): the same
/// reuse decision core, consumed through `link_cached`'s config exactly the
/// way the driver's relink hands it over. `cfg_of` builds the link config
/// with the record-side capture flag and the optional recorded seed.
fn cfg_of(seed: Option<ResolveReuseSeed>) -> LinkConfig {
    LinkConfig {
        ident: "m9-resolve-reuse-pipeline".into(),
        record_resolution: true,
        resolve_reuse: seed,
        ..LinkConfig::default()
    }
}

/// Builds `LinkInput`s from the builders (the Pass-0 shape: raw bytes +
/// command-line names).
fn inputs_of(specs: &[ObjectBuilder]) -> Vec<LinkInput> {
    specs
        .iter()
        .map(|b| LinkInput {
            name: b.name().into(),
            bytes: b.build().unwrap(),
        })
        .collect()
}

#[test]
fn pipeline_resolve_reuse_lands_the_full_resolves_snapshot() {
    // Link 1: the recording full link — its snapshot is what the v5 record
    // section carries to the next relink.
    let specs = vec![alpha(false, false), beta(0, false, false)];
    let first = link_cached(
        &inputs_of(&specs),
        &[],
        &cfg_of(None),
        Parallelism::Serial,
        None,
    )
    .unwrap();
    let snapshot1 = first
        .resolve_snapshot
        .clone()
        .expect("a recording link captures the Pass-2 snapshot");
    let digests1 = section_digests(&first.objects);

    // Link 2: the seeded relink — Pass 2 plans through the recorded
    // decisions instead of re-deciding every external.
    let relink_specs = vec![alpha(true, false), beta(0, false, false)];
    let seeded = link_cached(
        &inputs_of(&relink_specs),
        &[],
        &cfg_of(Some(ResolveReuseSeed {
            snapshot: snapshot1,
            digests: digests1,
        })),
        Parallelism::Serial,
        None,
    )
    .unwrap();

    // Link 3: the same relink resolved in full — the reference state.
    let full = link_cached(
        &inputs_of(&relink_specs),
        &[],
        &cfg_of(None),
        Parallelism::Serial,
        None,
    )
    .unwrap();

    assert_eq!(
        seeded.resolve_snapshot, full.resolve_snapshot,
        "the reused Pass 2 must capture exactly the full resolve's state"
    );
}

#[test]
fn pipeline_resolve_reuse_falls_back_transparently_when_the_shape_moves() {
    // The baseline records two files; the relink adds a third — the shape
    // guard refuses, and the link must land exactly where the full resolve
    // lands (the ladder's bottom rung, through the same config seam).
    let specs = vec![alpha(false, false), beta(0, false, false)];
    let first = link_cached(
        &inputs_of(&specs),
        &[],
        &cfg_of(None),
        Parallelism::Serial,
        None,
    )
    .unwrap();
    let seed = ResolveReuseSeed {
        snapshot: first.resolve_snapshot.expect("recording link captures"),
        digests: section_digests(&first.objects),
    };

    let grown = vec![alpha(false, false), beta(0, false, false), gamma(true)];
    let seeded = link_cached(
        &inputs_of(&grown),
        &[],
        &cfg_of(Some(seed)),
        Parallelism::Serial,
        None,
    )
    .unwrap();
    let full = link_cached(
        &inputs_of(&grown),
        &[],
        &cfg_of(None),
        Parallelism::Serial,
        None,
    )
    .unwrap();

    assert_eq!(
        seeded.resolve_snapshot, full.resolve_snapshot,
        "the refused reuse must be indistinguishable from the full resolve"
    );
}

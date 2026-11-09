//! Pass-2 resolve benchmark (M9 tier-2c): the full `Resolution::install`
//! walk against the propagation-index reuse path (`plan_reuse` +
//! `install_reused`) on a corpus where one input file changed, plus the
//! M9 GA record-side wiring's end-to-end pair (`resolve_pipeline`): the
//! full Passes 1b–3 pipeline with and without the recorded seed.
//!
//! The reuse path's work is the shape guard, the seed-file replay and the
//! recorded-winner copy (the digest diff itself is plan-side, computed
//! once per relink beside the byte planner's diff, and hoisted out of the
//! loop here); the full path re-classifies and re-decides every external
//! symbol of every input. Recorded on the dev sandbox (10 samples): the
//! reuse path breaks even past ~32 inputs and wins by ~21% at 64 files ×
//! 49 externals, while at 16 files its plan-read machinery still costs
//! ~20% over the full walk — the decision core pays off where the
//! `BTreeMap` get/decision work dominates, and the record-side wiring (v5)
//! stacks the parse-walk saving on top. The corpus keeps the edit in file
//! 0, the shape the incremental relink serves.

use criterion::{BenchmarkId, Criterion, Throughput};
use pgr_core::ids::FileId;
use pgr_core::interner::Interner;
use pgr_core::layout::LinkConfig;
use pgr_core::link::Parallelism;
use pgr_core::link::link_from_objects;
use pgr_core::object::InputObject;
use pgr_core::propagate::section_digests;
use pgr_core::resolve::{Resolution, ResolutionSnapshot, UndefinedPolicy};
use pgr_core::resolve_reuse::{ResolveReuseSeed, install_reused, plan_reuse};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// Symbols per input file: half defined externs, a quarter undefined
/// cross-references into the next file, one shared common, the rest local
/// (uninterned weight for the parse, invisible to Pass 2).
const SYMS_PER_FILE: usize = 64;

/// Builds one corpus object: `__text` (body seeded by `flip`) plus a
/// `__cstring`, `SYMS_PER_FILE` symbols in declaration order.
fn corpus_object(i: usize, files: usize, flip: bool) -> ObjectBuilder {
    let mut text: Vec<u8> = Vec::with_capacity(256);
    for w_i in 0..64u32 {
        let w = w_i;
        let word: u32 = if flip && i == 0 {
            0xD503_201F ^ w
        } else {
            0xD503_201F ^ w.wrapping_mul(0x9E37_79B9)
        };
        text.extend_from_slice(&word.to_le_bytes());
    }
    let mut b = ObjectBuilder::new(format!("o{i:04}.o").as_str());
    let sect = b.add_section(ObjectSection::text("__text", text, vec![]));
    b.add_section(ObjectSection::cstring("bench string\n"));
    for j in 0..SYMS_PER_FILE / 2 {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_o{i:04}_s{j:03}"),
            section_index: sect,
            value: (j * 8) as u64,
            weak: false,
        });
    }
    for j in 0..SYMS_PER_FILE / 4 {
        b.add_symbol(ObjectSymbol::Undefined {
            name: format!("_o{:04}_s{:03}", (i + 1) % files, j),
            weak_ref: false,
        });
    }
    b.add_symbol(ObjectSymbol::Common {
        name: "_shared_common".into(),
        size: 32,
        align_log2: 4,
    });
    b
}

/// Parses a corpus the way Pass 1 + interning does (names drained into the
/// interner batch, ids assigned back in table order).
fn parse(builders: &[ObjectBuilder]) -> (Interner, Vec<InputObject>) {
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut objects = Vec::new();
    for (i, spec) in builders.iter().enumerate() {
        let bytes = spec.build().unwrap();
        let mut obj = InputObject::parse(FileId(i as u32), spec.name(), bytes).unwrap();
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

/// Parses a corpus for the pipeline benches: parsed + atomized objects,
/// ready for `link_from_objects` (which interns and finishes them itself —
/// the same state `parse_inputs` hands the pipeline).
fn parse_pipeline(builders: &[ObjectBuilder]) -> Vec<InputObject> {
    builders
        .iter()
        .enumerate()
        .map(|(i, spec)| {
            let bytes = spec.build().unwrap();
            let mut obj = InputObject::parse(FileId(i as u32), spec.name(), bytes).unwrap();
            obj.compute_atoms(false);
            obj
        })
        .collect()
}

/// The pipeline bench's config: an executable whose entry is a defined
/// corpus symbol, with the record-side capture always on (the record cost
/// is part of the rung's own path).
fn pipeline_cfg(seed: Option<ResolveReuseSeed>) -> LinkConfig {
    LinkConfig {
        ident: "bench-resolve-pipeline".into(),
        entry_symbol: "_o0000_s000".into(),
        record_resolution: true,
        resolve_reuse: seed,
        ..LinkConfig::default()
    }
}

/// The M9 GA rung end to end (the record-side wiring): the full Passes
/// 1b–3 pipeline over the same relink corpus with and without the recorded
/// seed — the delta is exactly what the v5 record section buys the
/// relink's Pass 2 (decision reuse + the parse-walk saving), measured
/// through the same `link_from_objects` seam the driver hands its config to.
fn bench_pipeline(c: &mut Criterion) {
    let files = 64usize;
    let baseline: Vec<ObjectBuilder> = (0..files).map(|i| corpus_object(i, files, false)).collect();
    let relink: Vec<ObjectBuilder> = (0..files).map(|i| corpus_object(i, files, true)).collect();

    // The recorded state: a full, capturing link of the baseline corpus —
    // the snapshot the v5 record section carries plus the digest table the
    // seeds diff against.
    let recorded = link_from_objects(
        parse_pipeline(&baseline),
        &[],
        &pipeline_cfg(None),
        Parallelism::Serial,
        None,
    )
    .unwrap();
    let seed = ResolveReuseSeed {
        snapshot: recorded.resolve_snapshot.expect("the capture ran"),
        digests: section_digests(&recorded.objects),
    };

    let relink_objects = parse_pipeline(&relink);
    let externals: usize = relink_objects
        .iter()
        .map(|o| o.symbols.iter().filter(|s| s.external && !s.stab).count())
        .sum();

    // Both configs build once (the driver shapes the seed once per
    // relink); the timed unit is the pipeline, not the seed clone.
    let full_cfg = pipeline_cfg(None);
    let reuse_cfg = pipeline_cfg(Some(seed));

    let mut group = c.benchmark_group("resolve_pipeline");
    group.throughput(Throughput::Elements(externals as u64));

    group.bench_with_input(
        BenchmarkId::new("full_resolve", format!("{files} files")),
        &(),
        |b, ()| {
            b.iter(|| {
                link_from_objects(
                    relink_objects.clone(),
                    &[],
                    &full_cfg,
                    Parallelism::Serial,
                    None,
                )
                .unwrap()
            });
        },
    );

    group.bench_with_input(
        BenchmarkId::new("reused_resolve", format!("{files} files")),
        &(),
        |b, ()| {
            b.iter(|| {
                link_from_objects(
                    relink_objects.clone(),
                    &[],
                    &reuse_cfg,
                    Parallelism::Serial,
                    None,
                )
                .unwrap()
            });
        },
    );
    group.finish();
}

fn bench_resolve(c: &mut Criterion) {
    for files in [16usize, 64] {
        let baseline: Vec<ObjectBuilder> =
            (0..files).map(|i| corpus_object(i, files, false)).collect();
        let relink: Vec<ObjectBuilder> =
            (0..files).map(|i| corpus_object(i, files, true)).collect();

        let (interner, objects) = parse(&baseline);
        let mut res = Resolution::default();
        res.install(&objects).unwrap();
        res.require_all_resolved(&interner, &objects, UndefinedPolicy::Error)
            .unwrap();
        let snapshot = ResolutionSnapshot::capture(&objects, &interner, &res, &[]);
        let prev = section_digests(&objects);

        let (relink_interner, relink_objects) = parse(&relink);

        // The reuse plan (shape guard + digest diff) is computed once per
        // relink — the same place the byte planner diffs its digests — so
        // it hoists out of the timed loop; the timed unit is the resolver.
        let plan = plan_reuse(&snapshot, &prev, &relink_interner, &relink_objects, &[]).unwrap();

        let externals: usize = relink_objects
            .iter()
            .map(|o| o.symbols.iter().filter(|s| s.external && !s.stab).count())
            .sum();

        let mut group = c.benchmark_group("resolve_pass2");
        group.throughput(Throughput::Elements(externals as u64));

        group.bench_with_input(
            BenchmarkId::new("full_install", format!("{files} files")),
            &(),
            |b, ()| {
                b.iter(|| {
                    let mut r = Resolution::default();
                    r.install(&relink_objects).unwrap();
                    r.require_all_resolved(
                        &relink_interner,
                        &relink_objects,
                        UndefinedPolicy::Error,
                    )
                    .unwrap();
                    r
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("reused_install", format!("{files} files")),
            &(),
            |b, ()| {
                b.iter(|| {
                    install_reused(
                        &plan,
                        &snapshot,
                        &relink_interner,
                        &relink_objects,
                        &[],
                        UndefinedPolicy::Error,
                    )
                    .unwrap()
                });
            },
        );
        group.finish();
    }
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_resolve(&mut criterion);
    bench_pipeline(&mut criterion);
    criterion.final_summary();
}

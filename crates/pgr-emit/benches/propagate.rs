//! M9 tier-2b bench: the change-propagation planner's cost inside the
//! relink planner (§7.3 step 3, the reverse-index tier). The planner's
//! added work over the tier-1 span diff is the reverse-index build, the
//! digest diff and the dependent-closure walk — measured here against the
//! planner's own baseline so the propagation gate's overhead is a number,
//! not a claim. Corpus shape mirrors the driver's import-churn bench:
//! wide `__text` blobs, cross-object `BL`/pointer reference sites, a
//! one-section body edit as the seed.

use criterion::{Criterion, Throughput};
use pgr_core::layout::{Layout, LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link_cached};
use pgr_core::propagate::{predict, section_digests};
use pgr_emit::incremental::{LinkRecord, plan_patch};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// One object: a wide `__text` with cross-object `BL` sites, a `__data`
/// blob with pointer slots, `symbols` defined externals. Objects reference
/// their predecessor's exports (seed 1 is the root and defines `_main`),
/// so a one-object edit propagates across the whole corpus.
fn bench_object(seed: u64, symbols: usize, text_kib: usize, flip: bool) -> ObjectBuilder {
    let mut text = vec![0x2Au8; text_kib * 1024];
    if flip && seed == 1 {
        text[0] ^= 0xFF; // the one-section edit (the planner's seed)
    }
    let mut b = ObjectBuilder::new(&format!("bench_{seed}.o"));
    let text_idx = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let data_idx = b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; symbols * 8],
        Vec::new(),
    ));
    for i in 0..symbols {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_bench_fn_{seed}_{i}"),
            section_index: text_idx,
            value: (i * 8 % (text_kib * 1024)) as u64,
            weak: false,
        });
    }
    let ref_seed = if seed == 1 { seed } else { seed - 1 };
    for i in 0..symbols {
        let r = b.add_symbol(ObjectSymbol::Undefined {
            name: format!("_bench_fn_{ref_seed}_{i}"),
            weak_ref: false,
        });
        let t = b.sym_index(r);
        b.section_mut(text_idx)
            .relocs
            .push(ObjectReloc::branch26(t).at(((i * 8) % (text_kib * 1024)) as u32));
        b.section_mut(data_idx)
            .relocs
            .push(ObjectReloc::unsigned(t).at((i * 8) as u32));
    }
    if seed == 1 {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text_idx,
            value: 0,
            weak: false,
        });
    }
    b
}

fn corpus(objects: usize, symbols: usize, text_kib: usize, flip: bool) -> Vec<LinkInput> {
    (1..=objects as u64)
        .map(|seed| LinkInput {
            name: format!("bench_{seed}.o"),
            bytes: bench_object(seed, symbols, text_kib, flip).build().unwrap(),
        })
        .collect()
}

fn link(inputs: &[LinkInput]) -> (Layout, Vec<pgr_core::object::InputObject>) {
    let cfg = LinkConfig {
        ident: "pgr-propagate-bench".into(),
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let result = link_cached(inputs, &[], &cfg, Parallelism::Auto, None).unwrap();
    (result.layout, result.objects)
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();

    // 8 objects × 256 externals × 16 KiB text: enough reference sites for
    // the closure walk to do real work on the 2-core sandbox rig.
    let (objects, symbols, text_kib) = (8, 256, 16);
    let old = corpus(objects, symbols, text_kib, false);
    let new = corpus(objects, symbols, text_kib, true);

    let (layout1, objects1) = link(&old);
    let image1 = pgr_emit::build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1, None).unwrap();
    let (layout2, objects2) = link(&new);
    let digests = section_digests(&objects1);

    let mut group = criterion.benchmark_group("pgr-emit/propagate");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));
    group.throughput(Throughput::Bytes(image1.len() as u64));
    group.bench_function("propagation_scope", |b| {
        b.iter(|| {
            let scope = predict(&digests, &objects2, &layout2);
            std::hint::black_box(scope.seeds.len());
        });
    });
    group.bench_function("plan_patch_with_gate", |b| {
        b.iter(|| {
            let decision = plan_patch(&record, &layout2, &objects2, None).unwrap();
            std::hint::black_box(match decision {
                pgr_emit::incremental::PatchDecision::InPlace(p) => p.dirty_tiles.len(),
                pgr_emit::incremental::PatchDecision::Fallback(_) => 0,
            });
        });
    });
    group.finish();

    criterion.final_summary();
}

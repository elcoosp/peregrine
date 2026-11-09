//! Pass 4 emit benchmark (M4 perf gate, architecture doc §10.3 row M4):
//! the fused tile emit against the pre-fusion reference emit over the *same*
//! layout, on corpora shaped so every sub-pass does honest work — wide
//! multi-tile `__text` blobs (copy runs), branch/page/pointer relocations
//! (patches), pointer slots (chain words) and a signed image (page hashes).
//!
//! The M1/M2/M3 numbers in `docs/BENCHMARKS.md` were recorded with the
//! reference body (`build_image`); the M4 records the fused body next to it
//! so the fusion's claim is measured, not argued.

use criterion::{Criterion, Throughput};
use pgr_core::layout::LinkConfig;
use pgr_core::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// One wide object: a multi-tile text blob with branch relocs, a data blob
/// with pointer slots (rebases), cross-object symbol references.
fn bench_object(seed: u64, symbols: usize, text_kib: usize) -> ObjectBuilder {
    let text = vec![0x2Au8; text_kib * 1024];
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

fn corpus(objects: usize, symbols: usize, text_kib: usize) -> (Vec<LinkInput>, usize) {
    let mut inputs = Vec::with_capacity(objects);
    let mut total = 0usize;
    for seed in 1..=objects as u64 {
        let bytes = bench_object(seed, symbols, text_kib).build().unwrap();
        total += bytes.len();
        inputs.push(LinkInput {
            name: format!("bench_{seed}.o"),
            bytes,
        });
    }
    (inputs, total)
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();

    let (inputs, total) = corpus(16, 512, 32);
    let cfg = LinkConfig {
        ident: "pgr-emit-bench".into(),
        ..LinkConfig::default()
    };
    let result = link(&inputs, &[], &cfg).unwrap();

    // The gate precondition, asserted once at bench setup: fused == reference.
    let reference = pgr_emit::build_image(&result.layout, &result.objects).unwrap();
    let fused = pgr_emit::build_image_fused(&result.layout, &result.objects).unwrap();
    assert_eq!(
        reference, fused,
        "fused emit must match the reference bytes"
    );

    let mut group = criterion.benchmark_group("pgr-emit/emit");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));
    group.throughput(Throughput::Bytes(reference.len() as u64));
    group.bench_function("reference_pass4", |b| {
        b.iter(|| {
            let image = pgr_emit::build_image(&result.layout, &result.objects).unwrap();
            std::hint::black_box(image.len());
        });
    });
    group.bench_function("fused_tile_pass4", |b| {
        b.iter(|| {
            let image = pgr_emit::build_image_fused(&result.layout, &result.objects).unwrap();
            std::hint::black_box(image.len());
        });
    });
    group.finish();
    let _ = total;

    // The §7.2 output-residency rung's transport price (wire v5): the
    // changed-tile diff and the client-side replay over an 8 MiB image —
    // the CPU cost the rung adds per relink against the megabytes it
    // keeps off the wire. The one-tile edit is the warm-loop shape (the
    // fusion benches' corpus); the untouched scan is the pure gate.
    let image_8mib: Vec<u8> = (0..8 * 1024 * 1024usize)
        .map(|i| (i * 31 % 251) as u8)
        .collect();
    let mut edited = image_8mib.clone();
    edited[3 * 16 * 1024 + 7] ^= 0xff;
    let stream = pgr_emit::incremental::diff_tiles(&image_8mib, &edited);
    assert_eq!(stream.tiles.len(), 1, "the one-tile edit shapes one tile");

    let mut tiles_group = criterion.benchmark_group("pgr-emit/wire-tiles");
    tiles_group.sample_size(20);
    tiles_group.measurement_time(core::time::Duration::from_secs(4));
    tiles_group.throughput(Throughput::Bytes(image_8mib.len() as u64));
    tiles_group.bench_function("diff_one_tile_edit_8mib", |b| {
        b.iter(|| {
            let s = pgr_emit::incremental::diff_tiles(&image_8mib, &edited);
            std::hint::black_box(s.wire_bytes());
        });
    });
    tiles_group.bench_function("replay_one_tile_edit_8mib", |b| {
        b.iter(|| {
            let out = pgr_emit::incremental::apply_tiles(&image_8mib, &stream);
            std::hint::black_box(out.len());
        });
    });
    tiles_group.bench_function("diff_untouched_8mib", |b| {
        b.iter(|| {
            let s = pgr_emit::incremental::diff_tiles(&image_8mib, &image_8mib);
            std::hint::black_box(s.tiles.len());
        });
    });
    tiles_group.finish();

    criterion.final_summary();
}

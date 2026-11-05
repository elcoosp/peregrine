//! End-to-end link benchmark (M1 perf gate, TDD §12 M1 row): the whole
//! Pass 0–5 pipeline over a deterministic corpus of relocatable objects.
//!
//! The M1 shape is single-threaded ("passes 0–5 minimal"); these numbers are
//! the baseline the M4 parallel machinery must beat (TDD §10.3). Every
//! iteration exercises parse → intern → resolve → layout → emit — the same
//! bytes come out every time (determinism policy §4.3).

use criterion::{Criterion, Throughput};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// One synthetic input object: a text blob with branch relocs, a data
/// section with pointer slots (rebases), and a slice of the corpus-wide
/// symbol space (each object references its seed neighbor's symbols).
fn bench_object(seed: u64, symbols: usize, text_kib: usize) -> ObjectBuilder {
    let text = vec![0u8; text_kib * 1024];
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
    // References point at the previous object's symbols (object 1
    // self-references so the corpus never has an unresolved name).
    let ref_seed = if seed == 1 { seed } else { seed - 1 };
    for i in 0..symbols {
        b.add_symbol(ObjectSymbol::Undefined {
            name: format!("_bench_fn_{ref_seed}_{i}"),
            weak_ref: false,
        });
    }
    for i in 0..symbols {
        b.section_mut(text_idx)
            .relocs
            .push(ObjectReloc::branch26(i as u32).at(((i * 8) % (text_kib * 1024)) as u32));
        b.section_mut(data_idx)
            .relocs
            .push(ObjectReloc::unsigned(symbols as u32 + i as u32).at((i * 8) as u32));
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

/// Builds the corpus (deterministic; identical bytes every run).
fn bench_corpus(objects: usize, symbols: usize, text_kib: usize) -> (Vec<Vec<u8>>, usize) {
    let mut out = Vec::with_capacity(objects);
    let mut total = 0usize;
    for seed in 1..=objects as u64 {
        let bytes = bench_object(seed, symbols, text_kib).build().unwrap();
        total += bytes.len();
        out.push(bytes);
    }
    (out, total)
}

fn bench_link(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_link");
    std::fs::create_dir_all(&dir).unwrap();

    let small = bench_corpus(4, 256, 8);
    let large = bench_corpus(32, 2_048, 32);

    let mut group = c.benchmark_group("pgr-driver/link");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));

    for (name, corpus) in [("small_4_objects", &small), ("large_32_objects", &large)] {
        let files: &Vec<Vec<u8>> = &corpus.0;
        let total: usize = corpus.1;
        let mut opts = pgr_driver::opts::Options::default();
        for (i, bytes) in files.iter().enumerate() {
            let p = dir.join(format!("{name}_obj_{i}.o"));
            std::fs::write(&p, bytes).unwrap();
            opts.inputs.push(p.display().to_string());
        }
        opts.config.ident = (*name).into();
        opts.config.entry_symbol = "_main".into();
        group.throughput(Throughput::Bytes(total as u64));
        group.bench_function((*name).to_string(), |b| {
            b.iter(|| {
                let image = pgr_driver::link_to_bytes(&opts).unwrap();
                std::hint::black_box(image.len());
            })
        });
    }

    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_link(&mut criterion);
    criterion.final_summary();
}

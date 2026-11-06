//! End-to-end link benchmark (M1 perf gate, TDD §12 M1 row; M2 adds the
//! dylib-linked bind path): the whole Pass 0–5 pipeline over a deterministic
//! corpus of relocatable objects.
//!
//! The pipeline is single-threaded until the M4 pass parallelism lands; these
//! numbers are the baseline M4 must beat (TDD §10.3). Every iteration
//! exercises parse → intern → resolve → layout → emit — the same bytes come
//! out every time (determinism policy §4.3). The `*_dylib` variants link one
//! `.tbd` stub whose export covers every unresolved reference, so the GOT/
//! stub synthesis, import-table build and bind chains run on every iteration.

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

/// A `.tbd` stub exporting every symbol the corpus's object 1 leaves
/// unresolved from a dylib (exercises binds + GOT/stub synthesis).
fn bench_dylib_tbd() -> Vec<u8> {
    let exports: Vec<String> = (0..256).map(|i| format!("_bench_dylib_fn_{i}")).collect();
    let mut doc = String::from(
        "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: /usr/lib/libBench.dylib\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ ",
    );
    doc.push_str(&exports.join(", "));
    doc.push_str(" ]\n...\n");
    doc.into_bytes()
}

/// An object that branches through the dylib (stubs + GOT) on every call.
/// Undefined references cover the stub's 256-symbol export window; the
/// branch relocs use `sym_index` (symtab table order: defs before undefs).
fn bench_dylib_caller(seed: u64, calls: usize, text_kib: usize) -> ObjectBuilder {
    let text = vec![0u8; text_kib * 1024];
    let mut b = ObjectBuilder::new(&format!("bench_dylib_{seed}.o"));
    let text_idx = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let mut undef_idx = Vec::with_capacity(calls);
    for i in 0..calls {
        undef_idx.push(b.add_symbol(ObjectSymbol::Undefined {
            name: format!("_bench_dylib_fn_{}", i % 256),
            weak_ref: false,
        }));
    }
    if seed == 1 {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text_idx,
            value: 0,
            weak: false,
        });
    }
    for (i, idx) in undef_idx.iter().enumerate() {
        let table_idx = b.sym_index(*idx);
        b.section_mut(text_idx)
            .relocs
            .push(ObjectReloc::branch26(table_idx).at(((i * 8) % (text_kib * 1024)) as u32));
    }
    b
}

fn bench_link_dylib(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_link_dylib");
    std::fs::create_dir_all(&dir).unwrap();

    let tbd_path = dir.join("libBench.tbd");
    std::fs::write(&tbd_path, bench_dylib_tbd()).unwrap();

    let mut group = c.benchmark_group("pgr-driver/link_dylib");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));

    for (name, objects, calls) in [
        ("small_4_objects_dylib", 4usize, 256usize),
        ("large_32_objects_dylib", 32, 2_048),
    ] {
        let mut opts = pgr_driver::opts::Options::default();
        let mut total = 0usize;
        for seed in 1..=objects {
            let bytes = bench_dylib_caller(seed as u64, calls, 32).build().unwrap();
            total += bytes.len();
            let p = dir.join(format!("{name}_obj_{seed}.o"));
            std::fs::write(&p, bytes).unwrap();
            opts.inputs.push(p.display().to_string());
        }
        total += tbd_path.metadata().unwrap().len() as usize;
        opts.inputs.push(tbd_path.display().to_string());
        opts.config.ident = (*name).into();
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

/// M3: the same dylib-bound corpus emitted as `-dylib` and `-bundle`
/// outputs — exercises the 0 image base (no `__PAGEZERO`), `LC_ID_DYLIB`
/// absence/presence, and the full export trie over every defined external.
fn bench_link_outputs(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_link_outputs");
    std::fs::create_dir_all(&dir).unwrap();

    let mut group = c.benchmark_group("pgr-driver/link_outputs");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));

    let corpus = bench_corpus(8, 1_024, 16);
    for (kind, label) in [
        (pgr_core::layout::OutputType::Dylib, "dylib_8_objects"),
        (pgr_core::layout::OutputType::Bundle, "bundle_8_objects"),
    ] {
        let mut opts = pgr_driver::opts::Options::default();
        let mut total = 0usize;
        for (i, bytes) in corpus.0.iter().enumerate() {
            let p = dir.join(format!("{label}_obj_{i}.o"));
            std::fs::write(&p, bytes).unwrap();
            opts.inputs.push(p.display().to_string());
            total += bytes.len();
        }
        opts.config.ident = label.into();
        opts.config.filetype = kind;
        opts.config.install_name = Some("@rpath/libbench.dylib".into());
        group.throughput(Throughput::Bytes(total as u64));
        group.bench_function(label.to_string(), |b| {
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
    bench_link_dylib(&mut criterion);
    bench_link_outputs(&mut criterion);
    criterion.final_summary();
}

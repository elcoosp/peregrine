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

use core::fmt::Write as _;

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
        // M4: the fused pipeline (default) next to the pre-fusion reference
        // — the architecture doc §10.3 M4 perf gate measures the delta.
        group.bench_function((*name).to_string(), |b| {
            b.iter(|| {
                let image = pgr_driver::link_to_bytes(&opts).unwrap();
                std::hint::black_box(image.len());
            });
        });
        group.bench_function(format!("{name}_reference"), |b| {
            b.iter(|| {
                let image = pgr_driver::link_reference_bytes(&opts).unwrap();
                std::hint::black_box(image.len());
            });
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
            });
        });
        group.bench_function(format!("{name}_reference"), |b| {
            b.iter(|| {
                let image = pgr_driver::link_reference_bytes(&opts).unwrap();
                std::hint::black_box(image.len());
            });
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
            });
        });
        group.bench_function(format!("{label}_reference"), |b| {
            b.iter(|| {
                let image = pgr_driver::link_reference_bytes(&opts).unwrap();
                std::hint::black_box(image.len());
            });
        });
    }
    group.finish();
}

/// M5/S7 archive-liveness corpus: one member per seed, each defining its
/// own symbols and referencing the previous member (so a member is only
/// pulled transitively). `referenced` members are referenced from `main`;
/// the rest stay un-pulled under the lazy (default) archive strategy.
fn bench_archive_corpus(members: usize, symbols: usize, text_kib: usize) -> Vec<u8> {
    let mut arch = pgr_fixtures::ArchiveBuilder::new("libbench_archive.a");
    for seed in 1..=members as u64 {
        let obj = bench_object(seed, symbols, text_kib).set_subsections_via_symbols(true);
        arch.add_member(&format!("m{seed}.o"), obj.build().unwrap());
    }
    arch.build()
}

/// M5/S7: the archive-heavy link. The lazy (default) path parses only the
/// members the pull fixpoint selects; `-all_load` is the eager baseline the
/// S7 decision rule compares against (adopt lazy if ≥ 20% faster).
fn bench_link_archive(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_link_archive");
    std::fs::create_dir_all(&dir).unwrap();

    // 64 members × 32 KiB: ~2 MiB archive, 8 referenced transitively.
    let archive = bench_archive_corpus(64, 256, 32);
    let archive_len = archive.len();
    let archive_path = dir.join("libbench_archive.a");
    std::fs::write(&archive_path, archive).unwrap();

    // main.o references member 1's symbols (transitive pull of the chain).
    let mut main = ObjectBuilder::new("main.o");
    let text = main.add_section(ObjectSection::text(
        "__text",
        vec![0u8; 4 * 1024],
        (0..256)
            .map(|i| ObjectReloc::branch26(i).at(i * 8 % (4 * 1024)))
            .collect(),
    ));
    main.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    for i in 0..256 {
        main.add_symbol(ObjectSymbol::Undefined {
            name: format!("_bench_fn_1_{i}"),
            weak_ref: false,
        });
    }
    let main_path = dir.join("main.o");
    std::fs::write(&main_path, main.build().unwrap()).unwrap();

    let mut group = c.benchmark_group("pgr-driver/link_archive");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));

    for (name, all_load) in [("archive_64_lazy", false), ("archive_64_all_load", true)] {
        let opts = pgr_driver::opts::Options {
            inputs: vec![
                main_path.display().to_string(),
                archive_path.display().to_string(),
            ],
            all_load,
            config: pgr_core::layout::LinkConfig {
                ident: name.into(),
                ..pgr_core::layout::LinkConfig::default()
            },
            ..pgr_driver::opts::Options::default()
        };
        group.throughput(Throughput::Bytes(archive_len as u64 + 4 * 1024));
        group.bench_function(name.to_string(), |b| {
            b.iter(|| {
                let image = pgr_driver::link_to_bytes(&opts).unwrap();
                std::hint::black_box(image.len());
            });
        });
    }
    group.finish();
}

/// M5/D12 dead-strip gate corpus: 32 subsections objects where half the
/// symbols are referenced and half are dead weight (each object defines its
/// symbols twice — a live half and an unreferenced half).
fn bench_strip_object(seed: u64, symbols: usize, text_kib: usize) -> ObjectBuilder {
    let mut b = bench_object(seed, symbols, text_kib).set_subsections_via_symbols(true);
    // Dead weight: a second symbol set nothing references, spread over the
    // same __text (the atomizer splits at the boundaries; dead-strip drops
    // the atoms).
    let text_kib = text_kib as u64;
    for i in 0..symbols {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_bench_dead_{seed}_{i}"),
            section_index: 0,
            value: ((i * 8) as u64 % (text_kib * 1024 - 8)) + 4,
            weak: false,
        });
    }
    b
}

fn bench_link_dead_strip(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_link_strip");
    std::fs::create_dir_all(&dir).unwrap();

    let mut group = c.benchmark_group("pgr-driver/link_dead_strip");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));

    let (files, total): (Vec<Vec<u8>>, usize) = {
        let mut files = Vec::new();
        let mut total = 0;
        for seed in 1..=32u64 {
            let bytes = bench_strip_object(seed, 2_048, 32).build().unwrap();
            total += bytes.len();
            files.push(bytes);
        }
        (files, total)
    };

    for (name, dead_strip) in [
        ("large_32_objects_off", false),
        ("large_32_objects_on", true),
    ] {
        let mut opts = pgr_driver::opts::Options::default();
        for (i, bytes) in files.iter().enumerate() {
            let p = dir.join(format!("strip_{i}.o"));
            std::fs::write(&p, bytes).unwrap();
            opts.inputs.push(p.display().to_string());
        }
        opts.config.dead_strip = dead_strip;
        opts.config.ident = name.into();
        group.throughput(Throughput::Bytes(total as u64));
        group.bench_function(name.to_string(), |b| {
            b.iter(|| {
                let image = pgr_driver::link_to_bytes(&opts).unwrap();
                std::hint::black_box(image.len());
            });
        });
    }
    group.finish();
}

/// M5/D4 cstring-merge corpus: objects whose `__cstring` sections carry a
/// shared pool (duplicated across every object) plus a private tail — the
/// merged link places the shared pool once.
fn bench_cstring_object(seed: u64, strings: usize) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(&format!("cstr_{seed}.o"));
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    if seed == 1 {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
    }
    let mut data = String::new();
    // The shared pool: identical in every object (dedup collapses these).
    for i in 0..strings / 2 {
        let _ = writeln!(data, "shared literal {i} the same everywhere");
    }
    // The private tail: unique per object.
    for i in 0..strings / 2 {
        let _ = writeln!(data, "private literal {seed}_{i}");
    }
    b.add_section(ObjectSection::cstring(&data));
    b
}

fn bench_link_cstring(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_link_cstring");
    std::fs::create_dir_all(&dir).unwrap();

    let mut group = c.benchmark_group("pgr-driver/link_cstring");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));

    let (files, total): (Vec<Vec<u8>>, usize) = {
        let mut files = Vec::new();
        let mut total = 0;
        for seed in 1..=16u64 {
            let bytes = bench_cstring_object(seed, 1_024).build().unwrap();
            total += bytes.len();
            files.push(bytes);
        }
        (files, total)
    };
    let mut opts = pgr_driver::opts::Options::default();
    for (i, bytes) in files.iter().enumerate() {
        let p = dir.join(format!("cstr_{i}.o"));
        std::fs::write(&p, bytes).unwrap();
        opts.inputs.push(p.display().to_string());
    }
    opts.config.ident = "cstring_merge".into();
    group.throughput(Throughput::Bytes(total as u64));
    group.bench_function("cstring_16_objects", |b| {
        b.iter(|| {
            let image = pgr_driver::link_to_bytes(&opts).unwrap();
            std::hint::black_box(image.len());
        });
    });
    group.finish();
}

/// M6 ICF corpus: every object defines `functions` identical bodies (all
/// fold to one canonical copy under `-icf`); the off/on pair measures the
/// fold's wall-time cost (the §10.3 M6 gate: ICF adds ≤ 25%) and the
/// fold's effectiveness (bytes removed).
fn bench_icf_object(seed: u64, functions: usize) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(&format!("icf_{seed}.o")).set_subsections_via_symbols(true);
    // One body, split into `functions` identical atoms via symbol bounds.
    let body: Vec<u8> = [
        0x20u8, 0x00, 0x00, 0x8B, // add x0, x1, x0
        0x00, 0x00, 0x00, 0x8B, // add x0, x0, x0
        0xC0, 0x03, 0x5F, 0xD6, // ret
    ]
    .to_vec();
    let text = b.add_section(ObjectSection::text(
        "__text",
        body.repeat(functions),
        Vec::new(),
    ));
    for i in 0..functions {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_icf_fn_{seed}_{i}"),
            section_index: text,
            value: (i * 12) as u64,
            weak: false,
        });
    }
    if seed == 1 {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
    }
    b
}

fn bench_link_icf(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_link_icf");
    std::fs::create_dir_all(&dir).unwrap();

    let mut group = c.benchmark_group("pgr-driver/link_icf");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));

    let (files, total): (Vec<Vec<u8>>, usize) = {
        let mut files = Vec::new();
        let mut total = 0;
        for seed in 1..=32u64 {
            let bytes = bench_icf_object(seed, 512).build().unwrap();
            total += bytes.len();
            files.push(bytes);
        }
        (files, total)
    };

    for (name, icf) in [
        ("large_32x512_off", pgr_core::icf::IcfMode::None),
        ("large_32x512_safe", pgr_core::icf::IcfMode::Safe),
    ] {
        let mut opts = pgr_driver::opts::Options::default();
        for (i, bytes) in files.iter().enumerate() {
            let p = dir.join(format!("icf_{i}.o"));
            std::fs::write(&p, bytes).unwrap();
            opts.inputs.push(p.display().to_string());
        }
        opts.config.icf = icf;
        opts.config.ident = name.into();
        group.throughput(Throughput::Bytes(total as u64));
        group.bench_function(name.to_string(), |b| {
            b.iter(|| {
                let image = pgr_driver::link_to_bytes(&opts).unwrap();
                std::hint::black_box(image.len());
            });
        });
    }
    group.finish();
}

/// M6 Stage A: the POI cache. The cold variant parses (and populates); the
/// warm variant hits the cache for every input — the relink-speedup gate.
fn bench_link_cache(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_link_cache");
    std::fs::create_dir_all(&dir).unwrap();

    let mut group = c.benchmark_group("pgr-driver/link_cache");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));

    // Parse-heavy shape: many symbols per byte of text (a relink loop's
    // Pass 1 cost is the symtab/reloc decode the POI cache removes; the
    // emit cost stays small so the saving is visible in the wall time).
    let (files, total) = bench_corpus(16, 4_096, 4);
    let mut opts = pgr_driver::opts::Options::default();
    for (i, bytes) in files.iter().enumerate() {
        let p = dir.join(format!("cache_{i}.o"));
        std::fs::write(&p, bytes).unwrap();
        opts.inputs.push(p.display().to_string());
    }
    opts.config.ident = "cache_bench".into();
    let cache_dir = dir.join("cache");
    opts.cache_dir = Some(cache_dir.display().to_string());
    group.throughput(Throughput::Bytes(total as u64));

    // Cold: a fresh cache directory per iteration (parse + store + link).
    group.bench_function("medium_16_objects_cold", |b| {
        b.iter_batched(
            || {
                let fresh = dir.join(format!("cold-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&fresh);
                let mut o = opts.clone();
                o.cache_dir = Some(fresh.display().to_string());
                o
            },
            |o| {
                let image = pgr_driver::link_to_bytes(&o).unwrap();
                std::hint::black_box(image.len());
            },
            criterion::BatchSize::LargeInput,
        );
    });
    // Warm: populate once, then every iteration is a full cache hit.
    let _ = pgr_driver::link_to_bytes(&opts).unwrap();
    group.bench_function("medium_16_objects_warm", |b| {
        b.iter(|| {
            let image = pgr_driver::link_to_bytes(&opts).unwrap();
            std::hint::black_box(image.len());
        });
    });
    group.finish();
}

/// M6 frozen-`.tbd`: text YAML parse vs the frozen export-set decode —
/// the "`.tbd` startup cost < 1 ms" gate.
fn bench_tbd_frozen(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_tbd_frozen");
    std::fs::create_dir_all(&dir).unwrap();

    let mut group = c.benchmark_group("pgr-driver/tbd");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));

    let tbd = bench_dylib_tbd();
    let mut opts = pgr_driver::opts::Options::default();
    let cache_dir = dir.join("cache");
    opts.cache_dir = Some(cache_dir.display().to_string());
    let cache = pgr_core::PoiCache::open(&cache_dir).unwrap();
    let _ = pgr_driver::tbd_to_dylib_cached("libBench.tbd", &tbd, false, Some(&cache)).unwrap();

    group.bench_function("libbench_text_parse", |b| {
        b.iter(|| {
            let d = pgr_driver::tbd_to_dylib("libBench.tbd", &tbd, false).unwrap();
            std::hint::black_box(d.exports.len());
        });
    });
    group.bench_function("libbench_frozen_load", |b| {
        b.iter(|| {
            let d =
                pgr_driver::tbd_to_dylib_cached("libBench.tbd", &tbd, false, Some(&cache)).unwrap();
            std::hint::black_box(d.exports.len());
        });
    });
    group.finish();
}

/// M7 LRU bound: the per-store cost of enforcing a size bound (scan + evict)
/// vs the unbounded path — the bound must be noise on the link wall.
fn bench_cache_evict(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_cache_evict");
    std::fs::create_dir_all(&dir).unwrap();

    // 4 objects x 1,024 symbols: enough parse work for the POI entries to
    // be realistic (a few KiB each).
    let corpus = bench_corpus(4, 1_024, 8);
    let files: &Vec<Vec<u8>> = &corpus.0;
    let total: usize = corpus.1;
    let mut base = pgr_driver::opts::Options::default();
    for (i, bytes) in files.iter().enumerate() {
        let p = dir.join(format!("evict_obj_{i}.o"));
        std::fs::write(&p, bytes).unwrap();
        base.inputs.push(p.display().to_string());
    }
    base.config.ident = "cache_evict_bench".into();

    let mut group = c.benchmark_group("pgr-driver/cache_evict");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));
    group.throughput(Throughput::Bytes(total as u64));

    for (name, cache_max) in [("bounded_64kib", Some(64 * 1024u64)), ("unbounded", None)] {
        let fresh = dir.join(format!("evict-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fresh);
        let mut opts = base.clone();
        opts.cache_dir = Some(fresh.display().to_string());
        opts.cache_max = cache_max;
        group.bench_function(name.to_string(), |b| {
            b.iter(|| {
                let image = pgr_driver::link_to_bytes(&opts).unwrap();
                std::hint::black_box(image.len());
            });
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
    bench_link_archive(&mut criterion);
    bench_link_dead_strip(&mut criterion);
    bench_link_cstring(&mut criterion);
    bench_link_icf(&mut criterion);
    bench_link_cache(&mut criterion);
    bench_tbd_frozen(&mut criterion);
    bench_cache_evict(&mut criterion);
    criterion.final_summary();
}

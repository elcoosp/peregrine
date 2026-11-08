//! Parser-throughput benchmark (M0 perf gate, TDD §10.3 M0 row):
//! "Parser throughput benchmarked (GB/s) and recorded as the baseline for
//! Pass 1".
//!
//! The unit is `pgr_format::summarize` over a deterministic corpus of
//! arm64-apple-darwin executables built by `pgr-fixtures`: header walk, all
//! load commands, all sections, the full symbol table, every relocation
//! entry and a complete chained-fixups chain walk — the structural work
//! Pass 1 will replace with parallel parsing.

use criterion::{Criterion, Throughput};
use pgr_fixtures::{
    ImageBuilder, ImportsFormat, ObjectBuilder, ObjectSection, ObjectSymbol, SectionSpec,
    SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};

/// One synthetic object in the corpus.
fn bench_image(seed: u64, symbols: usize, relocs: usize, text_kib: usize) -> Vec<u8> {
    let mut b = ImageBuilder::executable("peregrine-bench");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(seed, text_kib * 1024),
            relocs: (0..relocs)
                .map(|i| pgr_fixtures::RelocSpec {
                    offset: (i * 4 % (text_kib * 1024)) as u32,
                    symbolnum: (i % symbols) as u32,
                    pcrel: i % 2 == 0,
                    length_log2: 2,
                    extern_: true,
                    rtype: if i % 4 == 0 {
                        pgr_format::consts::ARM64_RELOC_BRANCH26
                    } else {
                        pgr_format::consts::ARM64_RELOC_PAGE21
                    },
                })
                .collect(),
        }],
    });
    b.add_segment(SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    });
    b.add_dylib("/usr/lib/libSystem.B.dylib");
    let mut got: Vec<SlotKind> = Vec::new();
    for i in 0..symbols / 8 {
        let idx = b.add_symbol(SymbolSpec::Undefined {
            name: format!("_bench_symbol_{i}_{seed}"),
            lib_ordinal: 1,
            weak: false,
        });
        got.push(SlotKind::Bind {
            sym_index: idx,
            addend: 0,
        });
        if i % 3 == 0 {
            got.push(SlotKind::Rebase {
                target: (i as u64) * 8,
            });
        }
    }
    b.set_got(got);
    b.set_imports_format(ImportsFormat::Addend64);
    b.set_keep_relocs(true);
    b.build().expect("bench corpus image must build").bytes
}

fn bench_parse(c: &mut Criterion) {
    // Small: one image at "hello-plus" scale.
    let single = bench_image(0x51, 512, 1_024, 16);
    // Large: a 24-image corpus at debug-build scale (heavy symtab + relocs).
    let corpus: Vec<Vec<u8>> = (0u64..24)
        .map(|i| bench_image(0x1000 + i, 4_096, 8_192, 64))
        .collect();
    let corpus_total: u64 = corpus.iter().map(|v| v.len() as u64).sum();

    let mut group = c.benchmark_group("pgr-format/summarize");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));

    group.throughput(Throughput::Bytes(single.len() as u64));
    group.bench_function("single_image", |b| {
        b.iter(|| {
            let s = pgr_format::summarize(std::hint::black_box(&single)).unwrap();
            std::hint::black_box((s.symbols, s.relocations, s.fixup_slots));
        });
    });

    group.throughput(Throughput::Bytes(corpus_total));
    group.bench_function("corpus_24_images", |b| {
        b.iter(|| {
            for img in std::hint::black_box(&corpus) {
                let s = pgr_format::summarize(std::hint::black_box(img)).unwrap();
                std::hint::black_box((s.symbols, s.relocations, s.fixup_slots));
            }
        });
    });

    group.finish();
}

/// Builds a deterministic archive of `members` object files (each a small
/// synthetic `MH_OBJECT`) with a name-sorted ranlib table — the M5 archive
/// parse baseline (S7: the Pass 0 cost of the lazy-pull index).
fn bench_archive(members: usize) -> Vec<u8> {
    let mut arch = pgr_fixtures::ArchiveBuilder::new("libbench.a");
    for seed in 0..members {
        let mut b = ObjectBuilder::new(&format!("m{seed}.o"));
        let text = b.add_section(ObjectSection::text(
            "__text",
            [0xC0u8, 0x03, 0x5F, 0xD6].repeat(64),
            Vec::new(),
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_bench_archive_fn_{seed}"),
            section_index: text,
            value: 0,
            weak: false,
        });
        for i in 0..32 {
            b.add_symbol(ObjectSymbol::Undefined {
                name: format!("_bench_archive_undef_{seed}_{i}"),
                weak_ref: false,
            });
        }
        arch.add_member(&format!("m{seed}.o"), b.build().unwrap());
    }
    arch.build()
}

fn bench_archive_parse(c: &mut Criterion) {
    let archive = bench_archive(64);
    let total = archive.len() as u64;

    let mut group = c.benchmark_group("pgr-format/parse_archive");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));
    group.throughput(Throughput::Bytes(total));
    group.bench_function("archive_64_members", |b| {
        b.iter(|| {
            let a = pgr_format::parse_archive(std::hint::black_box(&archive)).unwrap();
            std::hint::black_box((a.members.len(), a.index.len()));
        });
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_parse(&mut criterion);
    bench_archive_parse(&mut criterion);
    criterion.final_summary();
}

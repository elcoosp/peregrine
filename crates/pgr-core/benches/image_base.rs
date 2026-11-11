//! The dylib/bundle image-base bench (M19): the link cost across the
//! `-image_base` decisions — the M3 zero default, a 512 KiB base and a
//! 2 GiB base over the same corpus (64 objects, 256 binds, one rebase
//! table) linked as a dylib. The base is address arithmetic on the emit
//! plan (every vmaddr is `fileoff + base`), so the honest expectation
//! is parity — the bench pins "the released surface never regresses
//! into the link's hot path" (the same shape gate the pagezero bench
//! rides).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::image_base::ImageBase;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries it), plus a `__data` rebase table so the fixup planner, the
/// trie and the symtab all ride the base.
fn corpus() -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let n_fns = if i == 0 { 2 } else { 4 };
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_fns),
                vec![],
            ));
            let mut first_fn = 0usize;
            for f in 0..n_fns {
                let idx = b.add_symbol(ObjectSymbol::Defined {
                    name: if i == 0 && f == 0 {
                        "_main".into()
                    } else {
                        format!("_fn_{i:03}_{f}")
                    },
                    section_index: text,
                    value: (f * 4) as u64,
                    weak: false,
                });
                if f == 0 {
                    first_fn = idx;
                }
            }
            let data = b.add_section(ObjectSection::data(
                "__data",
                vec![0u8; REBASES_PER_OBJECT * 8],
                vec![],
            ));
            let target = b.sym_index(first_fn);
            for r in 0..REBASES_PER_OBJECT {
                b.section_mut(data)
                    .relocs
                    .push(ObjectReloc::unsigned(target).at((r * 8) as u32));
            }
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_image_base(c: &mut Criterion) {
    let mut group = c.benchmark_group("image_base");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, base) in [
        ("default_0", None),
        ("custom_512kib", Some(0x8_0000u64)),
        ("custom_2gib", Some(0x8000_0000u64)),
    ] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &base,
            |b, base| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Dylib,
                        install_name: Some("@rpath/libbench.dylib".into()),
                        image_base: base
                            .map(ImageBase::from_override)
                            .transpose()
                            .expect("the bench base validates"),
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(result.layout.image_base);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_image_base(&mut criterion);
    criterion.final_summary();
}

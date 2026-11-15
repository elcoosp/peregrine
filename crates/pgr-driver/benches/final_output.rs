//! The final-output bench (M44): the dylib link across the
//! `-final_output` decision — the `-o`-path install-name default beside
//! the named universal path over the same corpus. The identity default
//! is one string fill before Pass 0 (the M44 seam the driver's dylib
//! defaults read), so the honest expectation is parity — the bench pins
//! "the knob never regresses the link's hot path" (the same shape gate
//! the M30–M43 benches ride).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::OutputType;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 16;
const SYMBOLS_PER_OBJECT: usize = 64;

/// One input object: a `__text` blob with branch relocs, a `__data`
/// section with pointer slots, and a slice of the corpus-wide symbol
/// space (each object references its seed neighbor — object 0
/// self-references so the dylib never has an unresolved name).
fn bench_object(seed: usize) -> Vec<u8> {
    let text = vec![0u8; 2048];
    let mut b = ObjectBuilder::new(&format!("bench_{seed:03}.o"));
    let text_idx = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let data_idx = b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; SYMBOLS_PER_OBJECT * 8],
        Vec::new(),
    ));
    for i in 0..SYMBOLS_PER_OBJECT {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_bench_fn_{seed:03}_{i}"),
            section_index: text_idx,
            value: (i * 8 % 2048) as u64,
            weak: false,
        });
    }
    let ref_seed = if seed == 0 { seed } else { seed - 1 };
    for i in 0..SYMBOLS_PER_OBJECT {
        let undef = b.add_symbol(ObjectSymbol::Undefined {
            name: format!("_bench_fn_{ref_seed:03}_{i}"),
            weak_ref: false,
        });
        b.section_mut(text_idx)
            .relocs
            .push(ObjectReloc::branch26(undef as u32).at(((i * 8) % 2048) as u32));
        b.section_mut(data_idx)
            .relocs
            .push(ObjectReloc::unsigned(undef as u32).at((i * 8) as u32));
    }
    b.build().expect("the bench object builds")
}

fn bench_final_output(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_final_output");
    std::fs::create_dir_all(&dir).unwrap();
    let mut inputs = Vec::with_capacity(OBJECTS);
    for seed in 0..OBJECTS {
        let p = dir.join(format!("bench_{seed:03}.o"));
        std::fs::write(&p, bench_object(seed)).unwrap();
        inputs.push(p.display().to_string());
    }

    let mut group = c.benchmark_group("final_output");
    let corpus_bytes: u64 = inputs
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    group.throughput(Throughput::Bytes(corpus_bytes));
    for (name, final_output) in [
        ("output_path_default", None),
        ("universal_named", Some("/usr/local/lib/libuniversal.dylib")),
    ] {
        let opts = pgr_driver::opts::Options {
            output: dir.join("libbench.dylib").display().to_string(),
            inputs: inputs.clone(),
            config: pgr_core::layout::LinkConfig {
                filetype: OutputType::Dylib,
                ident: "bench".into(),
                ..pgr_core::layout::LinkConfig::default()
            },
            final_output: final_output.map(std::string::ToString::to_string),
            ..pgr_driver::opts::Options::default()
        };
        group.bench_with_input(
            BenchmarkId::new("dylib_16_objects", name),
            &opts,
            |b, opts| {
                b.iter(|| {
                    let image = pgr_driver::link_to_bytes(opts).expect("the dylib links");
                    black_box(image.len());
                });
            },
        );
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_final_output(&mut criterion);
    criterion.final_summary();
}

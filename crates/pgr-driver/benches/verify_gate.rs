//! The verify-gate bench (M73): the link's own gate over a linked dylib
//! — the strict verifier's pass on the produced bytes (the signature
//! recompute included, the gate's honest price), the corrupted twin
//! beside it (the refusal path walks the same checks and renders the
//! same issue list), and the `-no_adhoc` carve-out's filter price on a
//! refused-signature image. The gate rides before the write on the cold
//! link, so the honest expectation is "one verifier pass beside the
//! write" — the same shape gate the verifier's own `checks` bench pins;
//! this bench pins the driver-side composition (parse → filter →
//! summary) never regresses it.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::OutputType;
use pgr_driver::verify_gate;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 16;
const SYMBOLS_PER_OBJECT: usize = 64;

/// One input object: the final-output bench's shape (a `__text` blob, a
/// `__data` section with pointer slots, branch+pointer relocs threading
/// the corpus — object 0 self-references so the dylib never has an
/// unresolved name).
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

/// Links the corpus once (the gate's subject).
fn linked_image(dir: &std::path::Path) -> Vec<u8> {
    let mut inputs = Vec::with_capacity(OBJECTS);
    for seed in 0..OBJECTS {
        let p = dir.join(format!("pgr_bench_verify_{seed:03}.o"));
        std::fs::write(&p, bench_object(seed)).unwrap();
        inputs.push(p.display().to_string());
    }
    let opts = pgr_driver::opts::Options {
        output: dir.join("libbench_verify.dylib").display().to_string(),
        inputs,
        config: pgr_core::layout::LinkConfig {
            filetype: OutputType::Dylib,
            ident: "bench".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        ..pgr_driver::opts::Options::default()
    };
    pgr_driver::link_to_bytes(&opts).expect("the dylib links")
}

fn bench_verify_gate(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_verify_gate");
    std::fs::create_dir_all(&dir).unwrap();
    let image = linked_image(&dir);

    let mut group = c.benchmark_group("verify_gate");
    group.throughput(Throughput::Bytes(image.len() as u64));
    group.bench_function(BenchmarkId::new("dylib_16_objects", "clean"), |b| {
        b.iter(|| {
            let gate = verify_gate(black_box(&image), true);
            black_box(gate.summary.ok);
        });
    });
    // The corrupted twin: one byte flipped mid-image — the gate walks
    // the same checks and names the finding (the refusal path's price).
    let mut corrupted = image.clone();
    let mid = image.len() / 2 + 0x4000;
    corrupted[mid] ^= 0xff;
    group.bench_function(BenchmarkId::new("dylib_16_objects", "corrupted"), |b| {
        b.iter(|| {
            let gate = verify_gate(black_box(&corrupted), true);
            black_box(!gate.summary.ok);
        });
    });
    // The `-no_adhoc` image: the same pass, the signature absence excused
    // by the carve-out — the filter's price is one retain over the issues.
    group.bench_function(BenchmarkId::new("dylib_16_objects", "no_adhoc"), |b| {
        b.iter(|| {
            let gate = verify_gate(black_box(&corrupted), false);
            black_box(gate.summary.errors);
        });
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_verify_gate(&mut criterion);
    criterion.final_summary();
}

//! The M10 platform-matrix benchmark (roadmap §10.4 row M10): the same
//! deterministic corpus linked for every `-platform_version` platform.
//!
//! The rung's perf gate is that platform plumbing costs the pipeline
//! nothing — the per-platform chained-fixups floor only selects the fixup
//! *encoding* (`LC_DYLD_CHAINED_FIXUPS` at/above the platform's floor,
//! the classic `LC_DYLD_INFO_ONLY` opcode streams below it), so the five
//! links should sit inside each other's noise. Recorded numbers stop at
//! the dev-sandbox baseline (docs/BENCHMARKS.md's convention).

use criterion::{BenchmarkId, Criterion, Throughput};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// main.o: a `_main` body plus a `__data` pointer to it — one chained
/// rebase slot, so the fixup planner runs on every platform.
fn main_with_rebase_slot() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.section_mut(data).relocs = vec![ObjectReloc::unsigned(0).at(0)];
    b.build().unwrap()
}

/// The per-platform `(name, platform, minos, sdk)` matrix: every linked
/// platform at its chained-fixups floor (the encoding boundary itself).
fn platform_matrix() -> Vec<(&'static str, u32, u32, u32)> {
    use pgr_format::consts::{
        PLATFORM_IOS, PLATFORM_MACOS, PLATFORM_TVOS, PLATFORM_VISIONOS, PLATFORM_WATCHOS,
    };
    vec![
        ("macos", PLATFORM_MACOS, 0x000C_0000, 0x000E_0000),
        ("ios", PLATFORM_IOS, 0x000F_0000, 0x0011_0000),
        ("tvos", PLATFORM_TVOS, 0x000F_0000, 0x0011_0000),
        ("watchos", PLATFORM_WATCHOS, 0x0008_0000, 0x000A_0000),
        ("visionos", PLATFORM_VISIONOS, 0x0001_0000, 0x0001_0000),
    ]
}

/// The rung's benchmark group: one link per platform over the same corpus.
fn bench_platform_matrix(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_platform");
    std::fs::create_dir_all(&dir).unwrap();
    let main = dir.join("main.o");
    let bytes = main_with_rebase_slot();
    std::fs::write(&main, bytes).unwrap();

    let mut group = c.benchmark_group("pgr-driver/platform_matrix");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));

    for (name, platform, minos, sdk) in platform_matrix() {
        let mut opts = pgr_driver::opts::Options::default();
        opts.inputs.push(main.display().to_string());
        opts.config.ident = format!("bench-platform-{name}");
        opts.config.platform = platform;
        opts.config.minos = minos;
        opts.config.sdk = sdk;
        group.throughput(Throughput::Bytes(16));
        group.bench_function(BenchmarkId::new("link", name), |b| {
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
    bench_platform_matrix(&mut criterion);
    criterion.final_summary();
}

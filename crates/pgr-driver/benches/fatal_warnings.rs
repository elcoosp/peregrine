//! The fatal-warnings bench (M109): the driver's run cost across the
//! `-fatal_warnings` faces over the same warning-producing corpus (the
//! `-undefined warning` advisory face prints the unresolved list). The
//! decision is the exit's, never the image's — the honest expectation is
//! parity (the tally is a counter incremented as the faces print), so
//! the bench pins "the escalation never regresses the link" (the same
//! shape gate the M108 multiply-defined bench rides one lane over).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::ffi::OsString;
use std::hint::black_box;
use std::path::PathBuf;

use pgr_driver::opts;

const OBJECTS: usize = 32;

/// One object: `_main` on the first, every object referencing the
/// undefined `_hole_<i>` — the advisory face's warning product.
fn corpus(dir: &std::path::Path) -> Vec<PathBuf> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
                vec![],
            ));
            if i == 0 {
                b.add_symbol(ObjectSymbol::Defined {
                    name: "_main".into(),
                    section_index: text,
                    value: 0,
                    weak: false,
                });
            }
            let undef = b.add_symbol(ObjectSymbol::Undefined {
                name: format!("_hole_{i:03}"),
                weak_ref: false,
            });
            let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
            let slot = b.sym_index(undef);
            b.section_mut(data)
                .relocs
                .push(ObjectReloc::unsigned(slot).at(0));
            let path = dir.join(format!("obj_{i:03}.o"));
            std::fs::write(&path, b.build().expect("the bench object builds")).unwrap();
            path
        })
        .collect()
}

fn bench_fatal_warnings(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_fatal_warnings");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let inputs = corpus(&dir);
    let mut group = c.benchmark_group("fatal_warnings");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, flag) in [
        ("advisory_default", None),
        ("fatal", Some("-fatal_warnings")),
    ] {
        group.bench_with_input(
            BenchmarkId::new("run_32_objects", name),
            &flag,
            |b, flag| {
                b.iter(|| {
                    let out = dir.join("out");
                    let mut argv: Vec<String> = vec![
                        "-o".into(),
                        out.display().to_string(),
                        "-undefined".into(),
                        "warning".into(),
                    ];
                    if let Some(f) = flag {
                        argv.push((*f).to_string());
                    }
                    argv.extend(inputs.iter().map(|p| p.display().to_string()));
                    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
                    let o = opts::parse(&argv).expect("the bench argv parses");
                    // The advisory face exits Ok (the warnings print); the
                    // fatal face errs (the tally elevated). The bench prices
                    // the run's whole shape either way — the escalation never
                    // regresses the link.
                    black_box(pgr_driver::run(&o).err().map(|e| e.to_string()));
                    let _ = std::fs::remove_file(&out);
                });
            },
        );
    }
    group.finish();
    let _ = std::fs::remove_dir_all(&dir);
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_fatal_warnings(&mut criterion);
    criterion.final_summary();
}

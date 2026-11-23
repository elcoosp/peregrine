//! The loaded-object inventory bench (M134): the driver's run cost across
//! the `-whatsloaded` faces over the same clean 32-object corpus — the
//! default's silent run beside the named inventory's run (one stderr line
//! per loaded object, the walk's own order). The face is a measurement,
//! never a layout product — the honest expectation is parity (the bytes
//! never move; the delta is the stderr writes), so the bench pins "the
//! inventory never regresses the link" (the same shape gate the M109/M133
//! driver benches ride, one face over).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::ffi::OsString;
use std::hint::black_box;
use std::path::PathBuf;

use pgr_driver::opts;

const OBJECTS: usize = 32;

/// One object: `_main` on the first, every other object carrying its own
/// unique entry symbol (a second `_main` would refuse the link — the
/// M108 default).
fn corpus(dir: &std::path::Path) -> Vec<PathBuf> {
    use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
                vec![],
            ));
            b.add_symbol(ObjectSymbol::Defined {
                name: if i == 0 {
                    "_main".into()
                } else {
                    format!("_entry_{i:03}")
                },
                section_index: text,
                value: 0,
                weak: false,
            });
            let path = dir.join(format!("obj_{i:03}.o"));
            std::fs::write(&path, b.build().expect("the bench object builds")).unwrap();
            path
        })
        .collect()
}

fn bench_whats_loaded(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_whats_loaded");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let inputs = corpus(&dir);
    let mut group = c.benchmark_group("whats_loaded");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, flag) in [
        ("silent_default", None),
        ("inventory", Some("-whatsloaded")),
    ] {
        group.bench_with_input(
            BenchmarkId::new("run_32_objects", name),
            &flag,
            |b, flag| {
                b.iter(|| {
                    let out = dir.join("out");
                    let mut argv: Vec<String> = vec!["-o".into(), out.display().to_string()];
                    if let Some(f) = flag {
                        argv.push((*f).to_string());
                    }
                    argv.extend(inputs.iter().map(|p| p.display().to_string()));
                    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
                    let o = opts::parse(&argv).expect("the bench argv parses");
                    // Both faces exit Ok (the inventory prints or not, the
                    // link is unchanged either way). The bench prices the
                    // run's whole shape — the inventory never regresses
                    // the link.
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
    bench_whats_loaded(&mut criterion);
    criterion.final_summary();
}

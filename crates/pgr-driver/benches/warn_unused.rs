//! The unused-dylib advisory bench (M136): the driver's run cost across
//! the `-warn_unused_dylibs` faces over the same corpus — the silent
//! default beside the named advisory (one stderr line per riding-but-
//! unbound dylib). The face is a measurement over the M42 predicate
//! read-side, never a layout product — the honest expectation is parity
//! (the bytes never move; the delta is the stderr writes), so the bench
//! pins "the advisory never regresses the link" (the same shape gate the
//! M109/M116/M121 benches ride).
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

/// A stub `.tbd` exporting nothing the corpus binds — one unbound rider
/// the advisory names.
fn stub_library(dir: &std::path::Path) -> PathBuf {
    let tbd = "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: \
        @rpath/libunused.dylib\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\n\
        exports:\n  - targets: [ arm64-macos ]\n    symbols: [_noone_uses_this]\n...\n";
    let path = dir.join("libunused.tbd");
    std::fs::write(&path, tbd).unwrap();
    path
}

fn bench_warn_unused(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_warn_unused");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let inputs = corpus(&dir);
    let lib = stub_library(&dir);
    let mut group = c.benchmark_group("warn_unused_dylibs");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, flag) in [
        ("silent_default", None),
        ("advisory", Some("-warn_unused_dylibs")),
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
                        lib.display().to_string(),
                    ];
                    if let Some(f) = flag {
                        argv.push((*f).to_string());
                    }
                    argv.extend(inputs.iter().map(|p| p.display().to_string()));
                    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
                    let o = opts::parse(&argv).expect("the bench argv parses");
                    // Both faces exit Ok (the advisory prints or not, the
                    // link is unchanged either way). The bench prices the
                    // run's whole shape — the advisory never regresses the
                    // link.
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
    bench_warn_unused(&mut criterion);
    criterion.final_summary();
}

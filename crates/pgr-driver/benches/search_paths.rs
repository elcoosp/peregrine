//! The library-search-order bench (M135): the driver's run cost across
//! the `-search_paths_first`/`-search_dylibs_first` faces over the same
//! split corpus — the per-directory default beside the dylibs-first
//! rounds. The decision is Pass 0's own (it names which files the link
//! consumes; the pipeline rides the picked bytes either way), so the
//! honest expectation is parity — the bench pins "the named order never
//! regresses the link" (the same shape gate the M109/M133/M134 driver
//! benches ride, one face over).
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

/// dir one's archive (`libgreet.a`) and dir two's dylib
/// (`libgreet.dylib`), both exporting `_greet` — the split that makes
/// the two search orders honest work (each walks a candidate list over
/// both directories).
fn split_libraries(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    use pgr_fixtures::{
        ArchiveBuilder, ImageBuilder, ObjectBuilder, ObjectSection, ObjectSymbol, SectionSpec,
        SegmentSpec, SymbolSpec, filler,
    };
    use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
    let dir_a = dir.join("search_a");
    let dir_b = dir.join("search_dylib");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    let mut member = ObjectBuilder::new("greet.o");
    let text = member.add_section(ObjectSection::text(
        "__text",
        [0x90u8, 0x02, 0x00, 0x94].repeat(2),
        vec![],
    ));
    member.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let mut archive = ArchiveBuilder::new("libgreet.a");
    archive.add_member("greet.o", member.build().expect("the bench object builds"));
    std::fs::write(dir_a.join("libgreet.a"), archive.build()).unwrap();

    let mut b = ImageBuilder::dylib("@rpath/libgreet.dylib", "pgr-bench-dylib");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0x7070, 64),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_greet".into(),
        section_index: 0,
    });
    std::fs::write(
        dir_b.join("libgreet.dylib"),
        b.build().expect("the bench dylib builds").bytes,
    )
    .unwrap();
    (dir_a, dir_b)
}

fn bench_search_paths(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_search_paths");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let inputs = corpus(&dir);
    let (dir_a, dir_b) = split_libraries(&dir);
    let mut group = c.benchmark_group("search_paths");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, flag) in [
        ("paths_first_default", None),
        ("paths_first_named", Some("-search_paths_first")),
        ("dylibs_first", Some("-search_dylibs_first")),
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
                        "-L".into(),
                        dir_a.display().to_string(),
                        "-L".into(),
                        dir_b.display().to_string(),
                        "-lgreet".into(),
                    ];
                    if let Some(f) = flag {
                        argv.push((*f).to_string());
                    }
                    argv.extend(inputs.iter().map(|p| p.display().to_string()));
                    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
                    let o = opts::parse(&argv).expect("the bench argv parses");
                    // Every face exits Ok (the search picks a library, the
                    // link is the same shape either way). The bench prices
                    // the run's whole shape — the named order never
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
    bench_search_paths(&mut criterion);
    criterion.final_summary();
}

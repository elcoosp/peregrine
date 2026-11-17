//! The provenance bench (M56): the `-why_export` query's price — the
//! M8-a reverse index's once-per-link build over the parsed arena, and
//! the query's own read against a built index (O(log n) + a slice walk
//! over the sites).
//!
//! The seam consumes data the pipeline already computed (the M54
//! convention: the query re-derives nothing), so the shape gate is the
//! index's own determinism — one site record per
//! `(file, section, offset)`, site count independent of corpus growth
//! beyond the corpus's own edges — and the honest expectation is that
//! the build rides the reference count, not the symbol count.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{Parallelism, link_from_objects};
use pgr_core::object::InputObject;
use pgr_core::provenance::explain_export;
use pgr_core::revindex::ReverseIndex;

/// Objects in the corpus (the resolve bench's shape, 64 files).
const OBJECTS: usize = 64;
/// External targets each file references (the next file's exports).
const REFS_PER_OBJECT: usize = 4;

/// Builds the Pass-1 arena: 64 objects, each defining four functions
/// and referencing the next file's exports through eight-byte data
/// pointers (one relocation per reference — the edges the index
/// records).
fn arena() -> Vec<InputObject> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(4),
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
            for f in 0..4 {
                b.add_symbol(ObjectSymbol::Defined {
                    name: format!("_fn_{i:03}_{f}"),
                    section_index: text,
                    value: (f * 4) as u64,
                    weak: false,
                });
            }
            let next = (i + 1) % OBJECTS;
            let mut targets = Vec::new();
            for f in 0..REFS_PER_OBJECT {
                let idx = b.add_symbol(ObjectSymbol::Undefined {
                    name: format!("_fn_{next:03}_{f}"),
                    weak_ref: false,
                });
                targets.push(idx as u32);
            }
            let data = b.add_section(ObjectSection::data(
                "__data",
                vec![0u8; REFS_PER_OBJECT * 8],
                targets
                    .iter()
                    .enumerate()
                    .map(|(r, sym)| ObjectReloc::unsigned(*sym).at((r * 8) as u32))
                    .collect(),
            ));
            let _ = data;
            let mut obj = InputObject::parse(
                pgr_core::ids::FileId(i as u32),
                &format!("obj_{i:03}.o"),
                b.build().expect("the bench object builds"),
            )
            .expect("the bench object parses");
            obj.compute_atoms(true);
            obj
        })
        .collect()
}

/// The linked corpus (the arena plus its winners).
fn linked() -> pgr_core::LinkResult {
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    link_from_objects(arena(), &[], &cfg, Parallelism::Serial, None).expect("the corpus links")
}

fn bench_provenance(c: &mut Criterion) {
    let mut group = c.benchmark_group("provenance");
    let result = linked();
    let queried = "_fn_001_0";
    // The shape gate, asserted once outside the timed loop: the queried
    // export carries exactly the corpus's own edges (each file
    // references the next file's four exports once — one referencer,
    // one site record per (file, section, offset)).
    let index = ReverseIndex::build_all(&result.objects);
    let answer = explain_export(
        &index,
        &result.objects,
        &result.resolution,
        &result.interner,
        queried,
    )
    .expect("the queried export resolves");
    assert_eq!(answer.sites.len(), 1, "one site record per reference edge");
    assert_eq!(
        answer
            .sites
            .iter()
            .map(|s| s.file.as_str())
            .collect::<Vec<_>>(),
        vec!["obj_000.o"],
        "the referencer is named"
    );

    group.throughput(Throughput::Elements(OBJECTS as u64));
    for files in [16usize, OBJECTS] {
        group.bench_with_input(
            BenchmarkId::new("index_build", files),
            &files,
            |b, &files| {
                let objs = &result.objects[..files];
                b.iter(|| {
                    let index = ReverseIndex::build_all(black_box(objs));
                    black_box(index.total_sites());
                });
            },
        );
    }
    group.bench_with_input(BenchmarkId::new("query", OBJECTS), &(), |b, &()| {
        b.iter(|| {
            let answer = explain_export(
                black_box(&index),
                black_box(&result.objects),
                black_box(&result.resolution),
                black_box(&result.interner),
                black_box(queried),
            )
            .expect("the queried export resolves");
            black_box(answer.sites.len());
        });
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_provenance(&mut criterion);
    criterion.final_summary();
}

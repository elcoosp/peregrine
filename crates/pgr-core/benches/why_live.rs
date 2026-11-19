//! The why-live bench (M92): the `-why_live` query's price — the mark
//! phase's why-record (one store per newly-marked atom, riding the M5
//! mark's own walk, never a second pass) and the query's own walk
//! (one hop per keeper: O(chain depth) over the recorded grid, the
//! name containment a binary search over the arena's atom tables).
//!
//! The chain corpus is the resolve bench's shape turned into a call
//! chain: 64 objects, each defining one function and calling the next
//! object's export through a `branch26` — under `-dead_strip` the
//! entry roots the whole chain, so the deep query walks 63 recorded
//! hops and the shallow query one, and one unreferenced body answers
//! `Dead` off the same grid's miss. The shape gate, asserted once
//! outside the timed loop: the record rides exactly when the strip
//! ran, and the deep chain's hop count is the corpus's own depth.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{Parallelism, link_from_objects};
use pgr_core::object::InputObject;
use pgr_core::why_live::{LiveVerdict, explain_live};

/// Objects in the chain corpus (the resolve bench's shape, 64 files),
/// the unreferenced body riding after them.
const OBJECTS: usize = 64;

/// Builds the Pass-1 arena: object 0 defines `_main` and calls the
/// next file's export; every later chain object defines `_fn_iii` and
/// calls its successor through a `branch26` (the call edges the strip
/// follows — the live chain is the whole corpus, and the recorded
/// parent chain is the corpus's own depth). `dead.o` defines `_dead`
/// and references nothing — the strip drops it, the verdict's honest
/// half rides the same grid.
fn arena() -> Vec<InputObject> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    let mut objects: Vec<InputObject> = (0..OBJECTS)
        .map(|i| {
            let name = format!("obj{i:03}.o");
            let mut b = ObjectBuilder::new(&name).set_subsections_via_symbols(true);
            b.add_section(ObjectSection::text(
                "__text",
                [0x9400_0000u32.to_le_bytes(), 0xD65F_03C0u32.to_le_bytes()].concat(),
                Vec::new(),
            ));
            let def_name = if i == 0 {
                "_main".to_string()
            } else {
                format!("_fn_{i:03}")
            };
            b.add_symbol(ObjectSymbol::Defined {
                name: def_name,
                section_index: 0,
                value: 0,
                weak: false,
            });
            let callee = if i + 1 < OBJECTS {
                format!("_fn_{:03}", i + 1)
            } else {
                "_main".to_string()
            };
            let _ = b.add_symbol(ObjectSymbol::Undefined {
                name: callee,
                weak_ref: false,
            });
            // The branch's target is the symtab's second entry (the
            // grouped table: the defined symbol first, the undefined
            // second).
            b.section_mut(0).relocs.push(ObjectReloc::branch26(1).at(0));
            let mut obj = InputObject::parse(
                pgr_core::ids::FileId(i as u32),
                &name,
                b.build().expect("the bench object builds"),
            )
            .expect("the bench object parses");
            obj.compute_atoms(true);
            obj
        })
        .collect();
    let mut b = ObjectBuilder::new("dead.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_dead".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let mut dead = InputObject::parse(
        pgr_core::ids::FileId(OBJECTS as u32),
        "dead.o",
        b.build().expect("the bench object builds"),
    )
    .expect("the bench object parses");
    dead.compute_atoms(true);
    objects.push(dead);
    objects
}

/// Links the chain corpus with `-dead_strip` (the query's premise —
/// the record rides the mark).
fn linked() -> pgr_core::LinkResult {
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        dead_strip: true,
        ..LinkConfig::default()
    };
    link_from_objects(arena(), &[], &cfg, Parallelism::Serial, None).expect("the corpus links")
}

fn bench_why_live(c: &mut Criterion) {
    let mut group = c.benchmark_group("why_live");
    let result = linked();
    let live = result
        .liveness
        .as_ref()
        .expect("the strip ran: the record rides");
    // The shape gate, asserted once outside the timed loop: the deep
    // query walks the corpus's own depth (63 keepers from the last
    // chain body back to the entry), the shallow query one, and the
    // unreferenced body answers `Dead` off the same grid.
    let deep = explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_fn_063",
    )
    .expect("the name stays live");
    let LiveVerdict::Live { chain, .. } = &deep.verdict else {
        panic!("the chained body stays live");
    };
    assert_eq!(chain.len(), OBJECTS - 1, "the corpus's own depth");
    let shallow = explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_fn_001",
    )
    .expect("the name stays live");
    let dropped = explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_dead",
    )
    .expect("the name resolves");
    assert!(matches!(dropped.verdict, LiveVerdict::Dead));

    group.throughput(Throughput::Elements(OBJECTS as u64));
    group.bench_function(BenchmarkId::new("query", "deep"), |b| {
        b.iter(|| {
            let answer = explain_live(
                black_box(live),
                black_box(&result.objects),
                black_box(&result.resolution),
                black_box(&result.interner),
                "_fn_063",
            )
            .expect("the name stays live");
            black_box(answer.render().len());
        });
    });
    group.bench_function(BenchmarkId::new("query", "shallow"), |b| {
        b.iter(|| {
            let answer = explain_live(
                black_box(live),
                black_box(&result.objects),
                black_box(&result.resolution),
                black_box(&result.interner),
                "_fn_001",
            )
            .expect("the name stays live");
            black_box(answer.render().len());
        });
    });
    group.bench_function(BenchmarkId::new("verdict", "dead"), |b| {
        b.iter(|| {
            let answer = explain_live(
                black_box(live),
                black_box(&result.objects),
                black_box(&result.resolution),
                black_box(&result.interner),
                "_dead",
            )
            .expect("the name resolves");
            assert!(matches!(answer.verdict, LiveVerdict::Dead));
        });
    });
    group.bench_function(BenchmarkId::new("render", "json"), |b| {
        b.iter(|| {
            black_box(shallow.render_json());
            black_box(deep.render_json());
        });
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_why_live(&mut criterion);
    criterion.final_summary();
}

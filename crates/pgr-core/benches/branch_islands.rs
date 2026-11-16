//! The branch-islands bench (M47): the link cost across the
//! `-no_branch_islands` decision — the islands-by-default beside the
//! suppressed fixed point over the same in-range corpus (64 objects,
//! every branch inside the ±128 MiB `imm26` window). The decision rides
//! the M6 veneer scan — one comparison per out-of-range candidate, and
//! an in-range corpus plans none either way — so the honest expectation
//! is parity (the shape-parity gate: the same bytes under both
//! decisions); the overflow lane (veneers planned) is priced by the
//! giant-text corpus in the M6 tests, and its suppressed twin errors by
//! design — the refusal is the decision's observable.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 64;

/// One object: a `ret` body and one exported symbol; object 0 carries
/// `_main`. No cross-object binds — the corpus measures the fixed
/// point's scan decision, not the bind walk (the knob reads the placed
/// `Branch26` patches, of which an in-range corpus plans none).
fn object(i: usize) -> Vec<u8> {
    let mut b = ObjectBuilder::new(&format!("obj{i:02}.o"));
    let sect = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        Vec::new(),
    ));
    if i == 0 {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
    }
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_fn_{i:02}"),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.build().expect("the bench object builds")
}

fn link_with(branch_islands: bool) -> usize {
    let cfg = LinkConfig {
        entry_symbol: "_main".into(),
        branch_islands,
        ..LinkConfig::default()
    };
    let inputs: Vec<LinkInput> = (0..OBJECTS)
        .map(|i| LinkInput {
            name: format!("obj{i:02}.o"),
            bytes: object(i),
        })
        .collect();
    link(black_box(&inputs), &[], &cfg)
        .expect("the corpus links")
        .layout
        .file_size as usize
}

fn bench_branch_islands(c: &mut Criterion) {
    // The smoke gate first: the two decisions plan the same bytes on an
    // in-range corpus (the bench would otherwise measure a difference
    // the shape-parity gate forbids).
    let islands = link_with(true);
    let suppressed = link_with(false);
    assert_eq!(
        islands, suppressed,
        "the in-range corpus plans identical bytes: {islands} vs {suppressed}"
    );
    let mut group = c.benchmark_group("branch_islands");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, branch_islands) in [("islands_default", true), ("no_islands_inrange", false)] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &branch_islands,
            |b, bi| {
                b.iter(|| {
                    let size = link_with(*bi);
                    black_box(size);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_branch_islands(&mut criterion);
    criterion.final_summary();
}

//! The export-dynamic bench (M46): the link cost across the
//! `-export_dynamic` decision — the entry-root default beside the
//! widened root set over the same corpus (64 objects whose exports
//! nothing references). The decision rides the dead-strip root set —
//! one extra root per global definition, widening the mark phase's
//! starting set; the honest expectation is parity-or-under for the
//! default (the shape-parity gate) and a small strip-side delta when
//! the roots widen (the kept bodies ride the layout).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 64;
/// Dead-but-global functions per object (defined, exported, never
/// referenced — the `dlsym` surface the decision preserves).
const DEAD_GLOBALS: usize = 4;

/// One object: `_fn_XXX` calls the next object's export (one bind), and
/// carries `DEAD_GLOBALS` unreferenced global bodies.
fn object(i: usize) -> Vec<u8> {
    // _fn_XXX: bl _fn_YYY (the next object's export); ret. Each
    // _dead_XXX: ret — a global definition nothing references.
    let mut text: Vec<u8> = [
        0x9400_0000u32, // bl _fn_next
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    for _ in 0..DEAD_GLOBALS {
        text.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // ret
    }
    let mut b = ObjectBuilder::new(&format!("obj{i:02}.o")).set_subsections_via_symbols(true);
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    // Only the first object carries the entry; every object defines the
    // export the previous object's body binds against (same address as
    // the first body).
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
    for d in 0..DEAD_GLOBALS {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_dead_{i:02}_{d}"),
            section_index: sect,
            value: u64::try_from(8 + 4 * d).unwrap(),
            weak: false,
        });
    }
    // No cross-object binds: every body is a `ret` (the corpus measures
    // the root-widening decision, not the bind walk — the default lane
    // keeps only the entry, the widened lane keeps every exported body).
    b.build().expect("the bench object builds")
}

fn link_with(export_dynamic: bool) -> usize {
    let cfg = LinkConfig {
        entry_symbol: "_main".into(),
        dead_strip: true,
        export_dynamic,
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

fn bench_export_dynamic(c: &mut Criterion) {
    // The smoke gate first: the widened roots really keep the dead
    // bodies (the bench would otherwise measure nothing).
    let kept = link_with(true);
    let stripped = link_with(false);
    assert!(
        kept > stripped,
        "the widened roots keep the dead globals: {kept} vs {stripped}"
    );
    let mut group = c.benchmark_group("export_dynamic");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, export_dynamic) in [("entry_roots", false), ("all_globals", true)] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &export_dynamic,
            |b, ed| {
                b.iter(|| {
                    let size = link_with(*ed);
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
    bench_export_dynamic(&mut criterion);
    criterion.final_summary();
}

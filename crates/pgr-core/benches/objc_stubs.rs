//! The ObjC-stubs synthesis bench (M130/M135-addendum): the link cost
//! over an `_objc_msgSend$<sel>` callsite corpus — the synthesis lane
//! the M130 design record named, priced once the code landed: the
//! selector classification, the `__objc_stubs` synthesis, the
//! `__objc_methname` dedup and the rebinds ride the corpus's per-selector
//! breadth (the distinct selectors are the stub count; the repeated
//! callsites dedup onto one stub). The honest expectation is a link
//! proportional to the distinct selectors — the bench pins "the
//! synthesis never regresses the callsite-free corpus" beside it (the
//! same shape gate the M43 objc bench rides).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 64;
const SELECTORS_PER_OBJECT: usize = 8;
const DISTINCT_SELECTORS: usize = 32;

/// One object: `_main` on the first, `_objc_msgSend$<sel>` undefineds
/// through `__data` bind slots (the callsite pseudo-symbols the
/// classifier recognizes).
fn callsite_object(idx: usize) -> Vec<u8> {
    let mut b = ObjectBuilder::new(&format!("obj_{idx:03}.o"));
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    if idx == 0 {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
    }
    let data = b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 8 * SELECTORS_PER_OBJECT],
        vec![],
    ));
    for k in 0..SELECTORS_PER_OBJECT {
        let sel = (idx * SELECTORS_PER_OBJECT + k) % DISTINCT_SELECTORS;
        let undef = b.add_symbol(ObjectSymbol::Undefined {
            name: format!("_objc_msgSend$_method_{sel:03}"),
            weak_ref: false,
        });
        let slot = b.sym_index(undef);
        b.section_mut(data)
            .relocs
            .push(ObjectReloc::unsigned(slot as u32).at((k * 8) as u32));
    }
    b.build().expect("the bench object builds")
}

fn corpus(referencing: bool) -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| LinkInput {
            name: format!("obj_{i:03}.o"),
            bytes: if referencing {
                callsite_object(i)
            } else {
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
                b.build().expect("the bench object builds")
            },
        })
        .collect()
}

fn bench_objc_stubs(c: &mut Criterion) {
    let mut group = c.benchmark_group("objc_stubs");
    for (name, referencing) in [("no_callsites", false), ("synthesis_32_selectors", true)] {
        let inputs = corpus(referencing);
        group.throughput(Throughput::Elements(OBJECTS as u64));
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &inputs,
            |b, i| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        entry_symbol: "_main".into(),
                        undefined_policy: pgr_core::resolve::UndefinedPolicy::DynamicLookup,
                        ..LinkConfig::default()
                    };
                    black_box(link(i, &[], &cfg).expect("the corpus links"));
                });
            },
        );
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_objc_stubs(&mut criterion);
    criterion.final_summary();
}

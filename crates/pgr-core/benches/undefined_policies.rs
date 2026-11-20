//! The undefined-policies bench (M103): the link cost across the
//! `-undefined` policies — `error` (the escalation lane; over this
//! corpus it is the refusal face, the walk's own price), the
//! `dynamic_lookup` shape, and the two new M103 faces (`warning`,
//! `suppress`) — over a corpus whose every object carries one
//! unresolved external (64 objects, one `GOT`-bound hole each). The
//! three non-escalating policies plan identical bind words (the
//! flat-lookup slot `dynamic_lookup` always encoded), so the honest
//! expectation is parity across them — the bench pins "the policy is
//! the exit's, never the image's": the recorded unresolved walk and
//! the bind words ride the same plan whatever the exit face prints.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::UndefinedPolicy;

const OBJECTS: usize = 64;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry) plus one unresolved external per object bound
/// through a GOT-form pointer pair (`page21` + `pageoff12`) — the
/// reference no input and no dylib resolves, the walk's policy subject.
fn corpus() -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let n_fns = if i == 0 { 2 } else { 4 };
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_fns * 4),
                vec![],
            ));
            for f in 0..n_fns {
                b.add_symbol(ObjectSymbol::Defined {
                    name: if i == 0 && f == 0 {
                        "_main".into()
                    } else {
                        format!("_fn_{i:03}_{f}")
                    },
                    section_index: text,
                    value: (f * 16) as u64,
                    weak: false,
                });
            }
            // The unresolved external: one hole per object, referenced
            // from the entry object's `__text` through the GOT-form
            // pair (the bind planner's flat-lookup slot subject).
            let hole = b.add_symbol(ObjectSymbol::Undefined {
                name: format!("_hole_{i:03}"),
                weak_ref: false,
            });
            b.section_mut(text)
                .relocs
                .push(ObjectReloc::got_page21(hole as u32).at(4));
            b.section_mut(text)
                .relocs
                .push(ObjectReloc::got_pageoff12(hole as u32).at(8));
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_undefined_policies(c: &mut Criterion) {
    let mut group = c.benchmark_group("undefined_policies");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, policy) in [
        ("error", UndefinedPolicy::Error),
        ("dynamic_lookup", UndefinedPolicy::DynamicLookup),
        ("warning", UndefinedPolicy::Warning),
        ("suppress", UndefinedPolicy::Suppress),
    ] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &policy,
            |b, &policy| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        undefined_policy: policy,
                        ..LinkConfig::default()
                    };
                    // The `error` face is the refusal over this corpus —
                    // the walk's escalation price is the honest subject;
                    // the other three link (the flat-lookup binds).
                    match link(black_box(&inputs), &[], &cfg) {
                        Ok(result) => black_box(result.layout.header_bytes.len()),
                        Err(_) => black_box(0usize),
                    }
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_undefined_policies(&mut criterion);
    criterion.final_summary();
}

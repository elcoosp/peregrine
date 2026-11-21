//! The commons-policy bench (M107): the link cost across the
//! `-commons <policy>` faces — the default (the tentative rides as a
//! local definition, the house rank order) beside the three named
//! faces over the same corpus (64 objects, one tentative each, a dylib
//! exporting every colliding name). The decision is one Pass-2 walk
//! over the common winners, so the honest expectation is parity — the
//! bench pins "the policy never regresses the resolve's hot path" (the
//! same shape gate the M103 undefined-policies bench rides, one policy
//! alphabet over).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::{CommonsPolicy, Dylib};

const OBJECTS: usize = 64;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries it), a tentative definition each (the `N_UNDF | N_EXT`
/// shape the policy decides about), and one bind slot against the same
/// name — the dylib exports every one, so every face walks the same
/// decision.
fn corpus() -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
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
                    format!("_fn_{i:03}")
                },
                section_index: text,
                value: 0,
                weak: false,
            });
            b.add_symbol(ObjectSymbol::Common {
                name: format!("_common_{i:03}"),
                size: 32,
                align_log2: 3,
            });
            let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
            let undef = b.add_symbol(ObjectSymbol::Undefined {
                name: format!("_common_{i:03}"),
                weak_ref: false,
            });
            let slot = b.sym_index(undef);
            b.section_mut(data)
                .relocs
                .push(ObjectReloc::unsigned(slot).at(0));
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

/// The one input dylib: it exports every tentative's name — the
/// conflict surface every policy face reads.
fn dylibs() -> Vec<Dylib> {
    vec![Dylib {
        install_name: "@rpath/libconflict.dylib".into(),
        current_version: 0,
        compatibility_version: 0,
        exports: (0..OBJECTS)
            .map(|i| format!("_common_{i:03}"))
            .map(String::into_bytes)
            .collect(),
        weak: false,
        lazy: false,
        upward: false,
        reexport: false,
        needed: false,
    }]
}

fn bench_commons_policy(c: &mut Criterion) {
    let inputs = corpus();
    let dylibs = dylibs();
    let mut group = c.benchmark_group("commons_policy");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for policy in [
        CommonsPolicy::UseDylibs,
        CommonsPolicy::SearchDylibs,
        CommonsPolicy::UseExtern,
        CommonsPolicy::Error,
    ] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", policy.flag_word()),
            &policy,
            |b, &policy| {
                b.iter(|| {
                    // The error face refuses the conflicted corpus — the
                    // bench prices the walk to the refusal (the face's
                    // own product), never a fabricated success.
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        dylibs: dylibs.clone(),
                        commons: policy,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg);
                    black_box(result.err().map(|e| e.to_string()));
                });
            },
        );
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_commons_policy(&mut criterion);
    criterion.final_summary();
}

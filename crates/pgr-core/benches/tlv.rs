//! The TLV bench (M37): the link cost across the thread-local carriage —
//! the TLV-free corpus beside the carried corpus (one `__thread`
//! variable per object: `__thread_data` initializer, `__thread_vars`
//! descriptor, descriptor-load relocations) over the same corpus shape
//! the M21–M36 parity benches share. The carriage is two sections and
//! a header flag per variable (no synthetic pieces, no new
//! `__LINKEDIT` payload), so the honest expectation is parity-or-under
//! — the bench pins "the carriage never regresses the link's hot path"
//! (the same shape gate the M30–M36 benches ride).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::UndefinedPolicy;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 64;
const FNS_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries it), one RET function per slot — `tlv` adds the
/// `__thread` variable shape (descriptor + initializer + descriptor
/// loads) to every object.
fn corpus(tlv: bool) -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                // RET + the descriptor-load pair (real ADRP/LDR words the
                // TLVP patches ride) + a RET tail.
                vec![
                    0xC0, 0x03, 0x5F, 0xD6, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x40, 0xF9, 0xC0,
                    0x03, 0x5F, 0xD6,
                ],
                vec![],
            ));
            for f in 0..FNS_PER_OBJECT {
                b.add_symbol(ObjectSymbol::Defined {
                    name: if i == 0 && f == 0 {
                        "_main".into()
                    } else {
                        format!("_fn_{i:03}_{f}")
                    },
                    section_index: text,
                    value: (f * 4) as u64,
                    weak: false,
                });
            }
            if tlv {
                let data = b.add_section(ObjectSection::thread_data(
                    (i as u64).to_le_bytes().to_vec(),
                ));
                let vars = b.add_section(ObjectSection::thread_vars(vec![0u8; 16], Vec::new()));
                let addr = b.add_symbol(ObjectSymbol::Undefined {
                    name: "_tlv_get_addr".into(),
                    weak_ref: false,
                });
                let x = b.add_symbol(ObjectSymbol::Defined {
                    name: format!("_tlv_{i:03}"),
                    section_index: vars,
                    value: 0,
                    weak: false,
                });
                let sx = b.sym_index(x);
                let s = b.section_mut(text);
                s.relocs = vec![
                    ObjectReloc::tlvp_page21(sx).at(4),
                    ObjectReloc::tlvp_pageoff12(sx).at(8),
                ];
                let s_addr = b.sym_index(addr);
                let s = b.section_mut(vars);
                s.relocs = vec![
                    ObjectReloc::unsigned(s_addr).at(0),
                    ObjectReloc::unsigned_sect(data as u32).at(8),
                ];
            }
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_tlv(c: &mut Criterion) {
    let mut group = c.benchmark_group("tlv");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, tlv) in [("no_tlv", false), ("tlv_carried", true)] {
        let inputs = corpus(tlv);
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &tlv,
            |b, &_tlv| {
                b.iter(|| {
                    // The dynamic-lookup policy is the bench corpus's
                    // `_tlv_get_addr` resolution (no dylib fixture in
                    // the hot path — the bind cost is the import entry).
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        flat_namespace: true,
                        undefined_policy: UndefinedPolicy::DynamicLookup,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(&result.layout);
                });
            },
        );
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_tlv(&mut criterion);
    criterion.final_summary();
}

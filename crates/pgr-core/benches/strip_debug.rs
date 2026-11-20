//! The debug-section suppression bench (M105): the link cost across the
//! `-S` decisions — the debug-carrying default (the pre-M105 shape:
//! the `S_ATTR_DEBUG`/`__debug_*` shapes bucket as load-time bytes) and
//! the stripped face (`-S`: the debug pieces drop, the symtab's debug
//! entries drop with them, and the `LC_FUNCTION_STARTS` /
//! `LC_DATA_IN_CODE` commands drop) over the same corpus (64 objects,
//! every one carrying a `__TEXT,__debug_info` `S_ATTR_DEBUG` section
//! with a local in it, a `__DWARF` segment section, 256 rebase slots,
//! function-starts and data-in-code inputs). The strip only moves the
//! classification's Debug class, so the honest expectation is a narrow
//! win on the stripped face — the bench pins "the released surface
//! never regresses into the link's hot path".
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), a `__TEXT,__debug_info` `S_ATTR_DEBUG` section
/// carrying a local (the shape the segment-name rule misses — the
/// default buckets it, `-S` drops it), a `__DWARF,__debug_info` section
/// (the always-swept shape), a `__data` rebase table, and data-in-code
/// entries so the two suppressed commands both ride by default.
fn corpus() -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let n_fns = if i == 0 { 2 } else { 4 };
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_fns),
                vec![],
            ));
            let mut first_fn = 0usize;
            for f in 0..n_fns {
                let idx = b.add_symbol(ObjectSymbol::Defined {
                    name: if i == 0 && f == 0 {
                        "_main".into()
                    } else {
                        format!("_fn_{i:03}_{f}")
                    },
                    section_index: text,
                    value: (f * 4) as u64,
                    weak: false,
                });
                if f == 0 {
                    first_fn = idx;
                }
            }
            let debug_sect = b.add_section(ObjectSection {
                name: "__debug_info".into(),
                segment: "__TEXT".into(),
                align_log2: 0,
                flags: pgr_format::consts::S_ATTR_DEBUG,
                data: vec![0xAAu8; 16],
                relocs: vec![],
            });
            b.add_symbol(ObjectSymbol::LocalDefined {
                name: format!("_dbg_{i:03}"),
                section_index: debug_sect,
                value: 0,
            });
            let _dwarf = b.add_section(ObjectSection {
                name: "__debug_info".into(),
                segment: "__DWARF".into(),
                align_log2: 0,
                flags: pgr_format::consts::S_REGULAR,
                data: vec![0xBBu8; 8],
                relocs: vec![],
            });
            let data = b.add_section(ObjectSection::data(
                "__data",
                vec![0u8; REBASES_PER_OBJECT * 8],
                vec![],
            ));
            let target = b.sym_index(first_fn);
            for r in 0..REBASES_PER_OBJECT {
                b.section_mut(data)
                    .relocs
                    .push(ObjectReloc::unsigned(target).at((r * 8) as u32));
            }
            let b = b.set_data_in_code(
                (0..n_fns)
                    .map(|f| pgr_format::DataInCodeEntry {
                        offset: (f * 4) as u32,
                        length: 4,
                        kind: 1,
                    })
                    .collect(),
            );
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_strip_debug(c: &mut Criterion) {
    let mut group = c.benchmark_group("strip_debug");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for name in ["debug_carrying_default", "s_stripped"] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &name,
            |b, name| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        strip_debug: *name == "s_stripped",
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(result.layout.file_size);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_strip_debug(&mut criterion);
    criterion.final_summary();
}

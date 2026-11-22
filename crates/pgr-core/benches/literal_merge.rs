//! M131 — the literal-merge throughput bench: the D4 dedup's own price
//! over a generated 4-byte-literal corpus (32 objects × 16 literals, half
//! the values shared across objects so the merge finds real duplicates
//! without collapsing to one), beside the `-no_deduplicate` verbatim
//! pass-through. The bench measures a real cost (the layout's per-bucket
//! hash-bin find-or-insert over the fixed-width literal atoms, the remap
//! onto the canonical copies, the dead-strip-ready atomization), not a
//! byte-parity assertion — the byte-identity lock is the
//! `m131_literal_merge` gate. The 8/16-byte literals ride the same
//! width-agnostic path (the cstring machinery the M131 completion widens);
//! the 4-byte corpus is the representative face. Run:
//! `cargo bench -p pgr-core --bench literal_merge`.

use criterion::{BenchmarkId, Criterion, Throughput};
use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkArchive, LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::S_4BYTE_LITERALS;
use std::hint::black_box;

/// Builds the literal corpus: `objects_n` objects each carrying a
/// `__literal4` section of `literals_n` 4-byte values. Even-indexed values
/// are shared across objects (a fixed pool the dedup collapses); odd-indexed
/// values are object-unique (the dedup keeps them). Returns the inputs and
/// the total input literal bytes (the throughput denominator).
fn literal_corpus(objects_n: usize, literals_n: usize) -> (Vec<LinkInput>, u64) {
    let width = 4u64;
    let mut inputs = Vec::with_capacity(objects_n);
    let mut total_input_bytes = 0u64;
    for o in 0..objects_n {
        let name = format!("obj{o:02}.o");
        let mut b = ObjectBuilder::new(&name).set_subsections_via_symbols(true);
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0u8, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_main{o:02}"),
            section_index: text,
            value: 0,
            weak: false,
        });
        let mut data = Vec::with_capacity(literals_n * 4);
        for f in 0..literals_n {
            // Even f → a fixed shared pool (dedup collapses the cross-object
            // duplicates); odd f → an object-unique value (the dedup keeps
            // one copy per object). Half-and-half so the merge does real
            // work without collapsing the section to a single value.
            let v: u32 = if f % 2 == 0 {
                0x0102_0304u32.wrapping_add(f as u32)
            } else {
                0xAA00_0000u32 | ((o as u32) << 8) | (f as u32)
            };
            data.extend_from_slice(&v.to_le_bytes());
        }
        total_input_bytes += literals_n as u64 * width;
        b.add_section(ObjectSection {
            name: "__literal4".into(),
            segment: "__TEXT".into(),
            align_log2: 2,
            flags: S_4BYTE_LITERALS,
            data,
            relocs: Vec::new(),
        });
        inputs.push(LinkInput {
            name: format!("obj{o:02}.o"),
            bytes: b.build().expect("the bench object builds"),
        });
    }
    (inputs, total_input_bytes)
}

/// The placed `__TEXT,__literal4` section's size (bytes) — the merged
/// pool's footprint, the size-reduction signal beside the throughput
/// (the dedup path's size sits below the no-dedup path's).
fn deduped_literal_size(layout: &pgr_core::layout::Layout) -> u64 {
    layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__literal4")
        .map_or(0, |s| s.size)
}

/// The literal-merge throughput group: the dedup path beside the
/// `-no_deduplicate` verbatim pass-through, both over the same corpus.
fn bench_literal_merge(c: &mut Criterion) {
    let objects_n = 32usize;
    let literals_n = 16usize;
    let (inputs, total_input_bytes) = literal_corpus(objects_n, literals_n);
    let dedup_cfg = LinkConfig {
        entry_symbol: "_main00".into(),
        ..LinkConfig::default()
    };
    let no_dedup_cfg = LinkConfig {
        entry_symbol: "_main00".into(),
        deduplicate: false,
        ..LinkConfig::default()
    };
    let mut group = c.benchmark_group("literal_merge");
    group.throughput(Throughput::Bytes(total_input_bytes));
    group.bench_with_input(BenchmarkId::new("layout", "dedup"), &dedup_cfg, |b, cfg| {
        b.iter(|| {
            let archives: [LinkArchive; 0] = [];
            let result = link(black_box(&inputs), &archives, cfg).expect("the dedup link plans");
            black_box(deduped_literal_size(&result.layout));
        });
    });
    group.bench_with_input(
        BenchmarkId::new("layout", "no_dedup"),
        &no_dedup_cfg,
        |b, cfg| {
            b.iter(|| {
                let archives: [LinkArchive; 0] = [];
                let result =
                    link(black_box(&inputs), &archives, cfg).expect("the no_dedup link plans");
                black_box(deduped_literal_size(&result.layout));
            });
        },
    );
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_literal_merge(&mut criterion);
    criterion.final_summary();
}

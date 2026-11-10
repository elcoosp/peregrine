//! The export-filter bench (M14): the match cost the visibility
//! closure pays per link — exact entries (the M3 form) against `*`
//! globs over the same name universe. The walk is allocation-free with
//! single-star backtracking, so the cost rides the pattern/name pair
//! count, not allocations.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as the filter's own
//! shape gate — the exact form is the M3 baseline the widened matcher
//! must stay beside, not a win to claim.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::export_filter::{SymbolMatcher, SymbolPattern};

/// The symbol universe: `10_240` realistic C-ish names (the trie-side
/// cost a 100-object link pays at Pass 3).
fn universe() -> Vec<Vec<u8>> {
    (0..10_240)
        .map(|i| {
            if i % 4 == 0 {
                format!("_sdk_api_{i:05}")
            } else if i % 4 == 1 {
                format!("_sdk_helper_{i:05}")
            } else if i % 4 == 2 {
                format!("_internal_state_{i:05}")
            } else {
                format!("_util_seed_{i:05}")
            }
            .into_bytes()
        })
        .collect()
}

/// The per-family lists: four entries each, so every family pays the
/// same per-name scan and the only variable is the matcher itself
/// (memcmp vs the backtracking walk).
fn patterns(kind: &str) -> Vec<SymbolPattern> {
    match kind {
        "exact" => [
            "_sdk_api_00000",
            "_sdk_helper_00001",
            "_internal_state_00002",
            "_util_seed_00003",
        ]
        .iter()
        .map(|p| SymbolPattern::parse(p.as_bytes()).unwrap())
        .collect(),
        "one_star" => [
            "_sdk_api_*",
            "_sdk_helper_*",
            "_internal_state_*",
            "_util_seed_*",
        ]
        .iter()
        .map(|p| SymbolPattern::parse(p.as_bytes()).unwrap())
        .collect(),
        "two_star" => ["_*_api_*", "_*_helper_*", "_*state*", "_*_seed_*"]
            .iter()
            .map(|p| SymbolPattern::parse(p.as_bytes()).unwrap())
            .collect(),
        _ => unreachable!("bench kind"),
    }
}

fn bench_filter(c: &mut Criterion) {
    let mut group = c.benchmark_group("export_filter");
    let names = universe();
    group.throughput(Throughput::Elements(names.len() as u64));
    for kind in ["exact", "one_star", "two_star"] {
        let pats = patterns(kind);
        group.bench_with_input(
            BenchmarkId::new("match_10k_names", kind),
            &pats,
            |b, pats| {
                b.iter(|| {
                    let mut hits = 0usize;
                    for name in &names {
                        if pats.matches(black_box(name)) {
                            hits += 1;
                        }
                    }
                    black_box(hits);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_filter(&mut criterion);
    criterion.final_summary();
}

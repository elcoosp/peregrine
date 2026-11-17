//! The dependency-record bench (M60): the record's own price — the
//! eager-sorted insert, the render (the version row plus one
//! NUL-terminated row per entry) and the strict reader's decode — over
//! records sized like real build-system links (a 512-file `-filelist`
//! corpus is the large end; a hello-world link is the small one). The
//! record rides the driver's Pass 0 (one row per read file), never the
//! pipeline: a shape gate on the sidecar's O(rows) cost, not a link-cost
//! knob.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::dep_info::DependencyRecord;

const ROWS: usize = 512;

/// A `ROWS`-row record: every third row a probed miss (a real `-l`
/// search over a deep `-L` list probes many candidates), the rest
/// inputs, the output last to ride.
fn record(rows: usize) -> DependencyRecord {
    let mut r = DependencyRecord::new("pgr (Peregrine) 0.22.0").expect("the version validates");
    for i in 0..rows {
        if i % 3 == 0 {
            r.record_not_found(&format!("sdk/usr/lib/liblib{i}.tbd"))
                .expect("the path validates");
        } else {
            r.record_input(&format!("build/obj/module_{i:04}.o"))
                .expect("the path validates");
        }
    }
    r.record_output("build/bin/app")
        .expect("the path validates");
    r
}

fn bench_dep_info(c: &mut Criterion) {
    let mut group = c.benchmark_group("dep_info");
    for rows in [8, 64, ROWS] {
        let r = record(rows);
        let bytes = r.render();
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(BenchmarkId::new("render", rows), &r, |b, r| {
            b.iter(|| black_box(r).render());
        });
        group.bench_with_input(BenchmarkId::new("parse", rows), &bytes, |b, bytes| {
            b.iter(|| DependencyRecord::parse(black_box(bytes)).expect("parses"));
        });
    }
    // The insert path itself (the `partition_point` insert): a fresh
    // record filled row by row, as Pass 0 fills it.
    group.bench_function("record_512", |b| {
        b.iter(|| black_box(record(ROWS)));
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_dep_info(&mut criterion);
    criterion.final_summary();
}

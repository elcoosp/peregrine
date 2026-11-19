//! The M69 SARIF interchange's price: the render face over fixed reports
//! (the 8-issue triage shape and the 64-issue worst case a build gate's
//! `--strict --json` pipeline might ship to Code Scanning). The document
//! is one deterministic line — the bench pins the O(issues) render price
//! beside the M13 JSON writer's. The M95 container group joins the face:
//! `render_universal` over 2- and 4-slice verdicts beside one slice's
//! single-image render.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion};
use pgr_verify::{Code, Issue, Report, sarif};

/// The issues a fixed report carries (half errors, half warnings, two
/// anchored — the shapes the SARIF writer branches on).
fn fixed_report(issues: usize) -> Report {
    let rows: Vec<Issue> = (0..issues)
        .map(|i| {
            let code = Code::ALL[i % Code::ALL.len()];
            let offset = if i % 2 == 0 {
                Some(u64::try_from(i * 4096).unwrap_or(u64::MAX))
            } else {
                None
            };
            if i % 3 == 0 {
                Issue::error(
                    code,
                    format!("the check family reported finding {i} (\"quoted\")"),
                    offset,
                )
            } else {
                Issue::warning(
                    code,
                    format!("the check family flagged finding {i}"),
                    offset,
                )
            }
        })
        .collect();
    Report {
        issues: rows,
        stats: pgr_verify::Stats::default(),
    }
}

/// The single-image render's groups: the 8-issue triage shape and the
/// 64-issue worst case, beside the M13 JSON writer's (the O(issues)
/// faces' relative price).
fn bench_sarif(c: &mut Criterion) {
    let mut group = c.benchmark_group("sarif");
    for issues in [8usize, 64] {
        let report = fixed_report(issues);
        group.bench_with_input(BenchmarkId::new("render", issues), &report, |b, report| {
            b.iter(|| {
                let doc = sarif::render(black_box(report), "app.bin");
                black_box(doc.len());
            });
        });
    }
    group.bench_function("render_64_issues_json_face", |b| {
        let report = fixed_report(64);
        b.iter(|| {
            black_box(pgr_verify::to_json(black_box(&report)).len());
        });
    });
    group.finish();
}

/// The M95 container face's price: `render_universal` over fixed 2- and
/// 4-slice verdicts (the SDK-fat-dylib shapes), beside the single-image
/// render of one slice's report — the container doc is the runs' union
/// table plus one results stream per slice, linear in the slices.
fn bench_sarif_universal(c: &mut Criterion) {
    let mut group = c.benchmark_group("sarif_universal");
    for slices in [2usize, 4] {
        let report = pgr_verify::UniversalReport {
            slices: (0..slices)
                .map(|_| pgr_verify::SliceVerdict {
                    arch: pgr_format::universal::FatArch {
                        cputype: pgr_format::consts::CPU_TYPE_ARM64,
                        cpusubtype: 0,
                        offset: 0,
                        size: 0,
                        align_log2: 12,
                    },
                    report: fixed_report(8),
                })
                .collect(),
        };
        group.bench_with_input(BenchmarkId::new("render", slices), &report, |b, report| {
            b.iter(|| {
                let doc = sarif::render_universal(black_box(report), "fat.bin");
                black_box(doc.len());
            });
        });
    }
    group.bench_function("render_one_slice_image_face", |b| {
        let report = fixed_report(8);
        b.iter(|| {
            black_box(sarif::render(black_box(&report), "slice.bin").len());
        });
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_sarif(&mut criterion);
    bench_sarif_universal(&mut criterion);
    criterion.final_summary();
}

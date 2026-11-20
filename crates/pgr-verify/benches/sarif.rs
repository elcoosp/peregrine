//! The M69 SARIF interchange's price: the render face over fixed reports
//! (the 8-issue triage shape and the 64-issue worst case a build gate's
//! `--strict --json` pipeline might ship to Code Scanning). The document
//! is one deterministic line — the bench pins the O(issues) render price
//! beside the M13 JSON writer's. The M95 container group joins the face:
//! `render_universal` over 2- and 4-slice verdicts beside one slice's
//! single-image render.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion};
use pgr_format::consts::CPU_TYPE_ARM64;
use pgr_format::universal::FatArch;
use pgr_verify::{
    BaselineDelta, Code, Issue, OffsetIdentity, Report, SliceVerdict, UniversalReport, sarif,
};

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

/// The M97 baseline face's price: the whole-verdict document with the
/// delta stated on every result — the state consumption pass (the same
/// deliberate O(issues × introduced) shape the delta itself runs) beside
/// the plain render, over the 8-issue triage shape (half introduced, one
/// resolved), and the container's stated face over a 2-slice verdict.
fn bench_sarif_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("sarif_baseline");
    let report = fixed_report(8);
    // The baseline side: two of the report's findings survive (matched by
    // their keys), two are fresh, one cleared finding rides absent — the
    // gate shapes the writer actually branches on.
    let prev_report = fixed_report(8);
    let mut prev_issues = prev_report.issues;
    prev_issues.truncate(2);
    prev_issues.push(Issue::error(
        Code::LinkeditPayload,
        "the cleared finding",
        Some(0x9000),
    ));
    let delta = BaselineDelta::between(&prev_issues, &report.issues, &OffsetIdentity);
    group.bench_function("render_with_baseline_8", |b| {
        b.iter(|| {
            let doc = sarif::render_with_baseline(
                black_box(&report),
                black_box(&delta),
                &OffsetIdentity,
                "app.bin",
            );
            black_box(doc.len());
        });
    });
    group.bench_function("render_plain_8_for_scale", |b| {
        b.iter(|| {
            black_box(sarif::render(black_box(&report), "app.bin").len());
        });
    });
    let fat_arch = FatArch {
        cputype: CPU_TYPE_ARM64,
        cpusubtype: 0,
        offset: 0x1000,
        size: 0x4000,
        align_log2: 12,
    };
    let universal = UniversalReport {
        slices: (0..2)
            .map(|_| SliceVerdict {
                arch: fat_arch,
                report: fixed_report(8),
            })
            .collect(),
    };
    // The container baseline document: one labeled line per slice, the
    // pairing's own prerequisite (the same shape the CLI records).
    let document: String = universal
        .slices
        .iter()
        .enumerate()
        .map(|(i, verdict)| {
            pgr_verify::to_json_with_file(
                &pgr_verify::slice_label("fat.bin", i, &verdict.arch),
                &verdict.report,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let baseline =
        pgr_verify::parse_container_baseline(&document).expect("the writer's own output parses");
    group.bench_function("render_universal_with_baseline_2", |b| {
        b.iter(|| {
            let doc = sarif::render_universal_with_baseline(
                black_box(&universal),
                black_box(&baseline),
                &OffsetIdentity,
                "fat.bin",
            )
            .expect("the pairing agrees");
            black_box(doc.len());
        });
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_sarif(&mut criterion);
    bench_sarif_universal(&mut criterion);
    bench_sarif_baseline(&mut criterion);
    criterion.final_summary();
}

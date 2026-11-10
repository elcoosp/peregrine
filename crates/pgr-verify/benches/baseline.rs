//! The M13 baseline-gate bench: the delta's per-policy cost beside the
//! report JSON's write and read, over synthetic reports shaped like a
//! real relink's (hundreds of anchored findings).
//!
//! The point is the *shape* of the gate, not a claim about absolute
//! costs: the delta must stay cheap against a verify pass (the M12
//! whole-image pass costs ~20 µs on the small fixture), or the build
//! system pays more for the gate than for the check. The O(prev × next)
//! match is deliberate — report issue counts are hundreds at the
//! extreme — and the bench pins that honesty: if the counts ever grow
//! past the linear scan's comfort zone, the shape changes here first.
//! Numbers live in docs/BENCHMARKS.md (M13 section).

use criterion::{BenchmarkId, Criterion, Throughput};
use pgr_verify::{
    BaselineDelta, Code, CodeIdentity, Issue, OffsetIdentity, Options, Report, Severity,
    parse_report_json, to_json, verify,
};

/// A synthetic report with `n` findings spread across the issue codes
/// (anchored — every issue carries an offset, the common real shape).
fn synthetic_report(n: usize) -> Report {
    let codes = Code::ALL;
    let mut report = Report {
        stats: pgr_verify::Stats {
            segments: 4,
            sections: 12,
            symbols: n as u32,
            fixup_slots: n as u64,
            hash_pages: 8,
        },
        issues: Vec::new(),
    };
    for i in 0..n {
        report.issues.push(Issue {
            severity: if i % 4 == 0 {
                Severity::Warning
            } else {
                Severity::Error
            },
            code: codes[i % codes.len()],
            message: format!("synthetic finding {i}: the anchored site drifted"),
            offset: Some((i * 0x40) as u64),
        });
    }
    report
}

/// The next report: the same findings with every tenth one's offset
/// shifted (a small layout move) and ten fresh findings appended.
fn shifted_report(prev: &Report) -> Report {
    let mut next = prev.clone();
    for (i, issue) in next.issues.iter_mut().enumerate() {
        if i % 10 == 0 {
            issue.offset = issue.offset.map(|o| o + 0x10);
        }
    }
    for i in 0..10 {
        next.issues.push(Issue::error(
            Code::Suspicious,
            format!("fresh finding {i}"),
            Some(0xF0_0000 + i as u64 * 8),
        ));
    }
    next
}

fn bench_baseline(c: &mut Criterion) {
    let sizes = [64usize, 256, 512];
    for n in sizes {
        let prev = synthetic_report(n);
        let next = shifted_report(&prev);
        let prev_issues: Vec<Issue> = prev.issues.clone();
        let next_issues: Vec<Issue> = next.issues.clone();
        let json = to_json(&prev);

        let mut group = c.benchmark_group("baseline_gate");
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(
            BenchmarkId::new("delta_offset", n),
            &(prev_issues.clone(), next_issues.clone()),
            |b, (prev, next)| {
                b.iter(|| BaselineDelta::between(prev, next, &OffsetIdentity));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("delta_code", n),
            &(prev_issues.clone(), next_issues.clone()),
            |b, (prev, next)| {
                b.iter(|| BaselineDelta::between(prev, next, &CodeIdentity));
            },
        );
        group.bench_function(BenchmarkId::new("to_json", n), |b| {
            b.iter(|| to_json(&prev));
        });
        group.bench_function(BenchmarkId::new("parse_json", n), |b| {
            b.iter(|| parse_report_json(&json).expect("the writer's own output parses"));
        });
        group.finish();
    }
}

/// One real verify pass on the M12 fixture shape, for scale: the delta
/// gate is only worth its cost while it stays well under this.
fn bench_verify_for_scale(c: &mut Criterion) {
    use pgr_fixtures::{
        ImageBuilder, ImportsFormat, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
    };
    use pgr_format::consts::{
        S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
    };
    let mut b = ImageBuilder::executable("baseline-bench");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xA5A5, 96),
            relocs: Vec::new(),
        }],
    });
    b.add_segment(SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    });
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![SlotKind::Bind {
        sym_index: sym,
        addend: 0,
    }]);
    b.set_entry(0x40);
    b.set_imports_format(ImportsFormat::Plain);
    let bytes = b.build().expect("the fixture builds").bytes;
    let opts = Options::default();
    c.bench_function("baseline_gate/verify_for_scale", |b| {
        b.iter(|| verify(&bytes, &opts));
    });
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_baseline(&mut criterion);
    bench_verify_for_scale(&mut criterion);
    criterion.final_summary();
}

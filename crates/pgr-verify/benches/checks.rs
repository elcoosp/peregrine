//! The M12 selective-surface bench: the whole-image `verify` pass beside
//! each single check family, over one at-floor chained-fixup executable
//! (the rung-3 fixture shape: one `LC_LOAD_DYLIB`, a `__got` bind +
//! rebase slot, an entry point, `LC_BUILD_VERSION` at the macOS floor).
//!
//! The point is the *shape* of the selection surface, not a claim about
//! absolute costs: the gap between `full` and a single family is what a
//! build system buys when it runs `--checks segments` on every relink
//! and the full pass only at hand-off. The signature family dominates
//! the full pass (it recomputes every 4 KiB page hash), so rotation
//! catches a regression in the cheap families too. Numbers live in
//! docs/BENCHMARKS.md (M12 section).
//!
//! The M67 groups join the extension surface: the consumer-side policy
//! check riding beside the full pass and alone — the shape a build
//! system buys when a project policy verifies beside the families on
//! every relink (docs/BENCHMARKS.md, M67 section).

use criterion::{BenchmarkId, Criterion};
use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler};
use pgr_format::consts::{
    MH_ALLOW_STACK_EXECUTION, MH_EXECUTE, PLATFORM_MACOS, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR,
    VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{
    Check, CheckContext, CheckSet, Code, CustomCheck, Issue, Options, verify, verify_with_checks,
    verify_with_extra_checks,
};

fn strict() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A chained-fixup executable born at the macOS chained-fixups floor —
/// the same shape the rung-3 floor-gate bench pins.
fn chained_exec() -> Vec<u8> {
    let mut b = ImageBuilder::executable("checks-bench");
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
    b.set_got(vec![
        SlotKind::Bind {
            sym_index: sym,
            addend: 0,
        },
        SlotKind::Rebase { target: 0x40 },
    ]);
    b.set_entry(0x40);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    b.build().expect("the checks-bench fixture builds").bytes
}

/// The selection surface: full pass first, then each family alone.
fn bench_checks(c: &mut Criterion) {
    let bytes = chained_exec();
    let opts = strict();
    let mut group = c.benchmark_group("verify_checks");
    group.bench_function("full", |b| b.iter(|| verify(&bytes, &opts)));
    for check in Check::ALL {
        let set = CheckSet::empty().with(check);
        group.bench_with_input(
            BenchmarkId::new("single", check.as_str()),
            &set,
            |b, set| {
                b.iter(|| verify_with_checks(&bytes, &opts, set));
            },
        );
    }
    group.finish();
}

/// The M67 consumer-side policy check: executable-only, under its own
/// custom code (it fires nowhere on the fixture — the group prices the
/// ride, not a finding).
struct BenchPolicyCheck;

impl CustomCheck for BenchPolicyCheck {
    fn name(&self) -> &'static str {
        "bench_policy"
    }
    fn summary(&self) -> &'static str {
        "the M67 extension shape: one executable-only policy unit"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::Custom("bench_policy")]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        if ctx.parsed.header.filetype == MH_EXECUTE
            && ctx.parsed.header.flags & MH_ALLOW_STACK_EXECUTION != 0
        {
            ctx.report.issues.push(Issue::error(
                Code::Custom("bench_policy"),
                "the stack-exec bit rode — the fix is dropping the flag",
                None,
            ));
        }
    }
}

/// The M67 extension surface: the policy check beside the full pass and
/// alone (beside the parse pre-pass).
fn bench_extra_checks(c: &mut Criterion) {
    let bytes = chained_exec();
    let opts = strict();
    let check = BenchPolicyCheck;
    let extra: [&dyn CustomCheck; 1] = [&check];
    let mut group = c.benchmark_group("verify_extra");
    group.bench_function("full+policy", |b| {
        b.iter(|| verify_with_extra_checks(&bytes, &opts, &CheckSet::all(), &extra));
    });
    group.bench_function("policy-only", |b| {
        b.iter(|| verify_with_extra_checks(&bytes, &opts, &CheckSet::empty(), &extra));
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_checks(&mut criterion);
    bench_extra_checks(&mut criterion);
    criterion.final_summary();
}

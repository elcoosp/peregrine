//! The M132 terminator-surface bench: the new family's price over one
//! at-floor executable wearing each terminator shape the gate walks —
//! the honest `__mod_term_func` pointer section (whole 8-byte slots) and
//! the same section with a hand-broken stride (the finding path: the walk
//! reads the section header, prices the stride and reports) — beside the
//! whole-image pass over the honest image (for scale: the family is a
//! per-section stride read over a two-segment image, the price a build
//! gate adds when it prices the terminator contract alone).
//!
//! The point is the shape of the family's cost, not a claim about
//! absolute numbers: the walk is one section-header read per section the
//! image carries, so the bench catches a regression that turns the walk
//! into something super-linear. Numbers live in docs/BENCHMARKS.md (M132
//! section).

use criterion::Criterion;
use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_format::consts::{
    PLATFORM_MACOS, S_ATTR_PURE_INSTRUCTIONS, S_MOD_TERM_FUNC_POINTERS, S_REGULAR, VM_PROT_EXECUTE,
    VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{Check, CheckSet, Options, verify, verify_with_checks};

fn strict() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// The macOS chained-fixups floor (12.0.0), the at-floor deployment
/// target the family's honest shapes ride.
const MINOS_AT_FLOOR: u32 = 0x000C_0000;
/// Slot count the honest shape carries (the walk's steady state).
const SLOTS: u32 = 64;

/// One at-floor executable: 64 KiB of `__text` inside the executable
/// `__TEXT`, the named terminator surface, the deployment target pinned
/// at the floor.
fn exec_with(mod_term: Option<Vec<u8>>) -> Vec<u8> {
    let mut b = ImageBuilder::executable("mod-term-bench");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0x94A1, 64 * 1024),
            relocs: Vec::new(),
        }],
    });
    if let Some(bytes) = mod_term {
        b.add_segment(SegmentSpec {
            name: "__DATA_CONST".into(),
            maxprot: VM_PROT_READ | VM_PROT_WRITE,
            initprot: VM_PROT_READ | VM_PROT_WRITE,
            sections: vec![SectionSpec {
                name: "__mod_term_func".into(),
                align_log2: 3,
                flags: S_MOD_TERM_FUNC_POINTERS,
                data: bytes,
                relocs: Vec::new(),
            }],
        });
    }
    b.set_build_version(PLATFORM_MACOS, MINOS_AT_FLOOR, 0x000E_0000);
    b.set_entry(0);
    b.build().expect("the bench fixture builds").bytes
}

/// The honest classic pointer form: 64 whole 8-byte slots.
fn honest_mod_term() -> Vec<u8> {
    vec![0u8; SLOTS as usize * 8]
}

/// The broken pointer form: the honest slots plus four trailing bytes
/// (off the 8-byte stride — the finding path).
fn broken_mod_term() -> Vec<u8> {
    let mut out = honest_mod_term();
    out.extend_from_slice(&[0u8; 4]);
    out
}

fn bench_mod_term(c: &mut Criterion) {
    let opts = strict();
    let honest = exec_with(Some(honest_mod_term()));
    let broken = exec_with(Some(broken_mod_term()));
    let set = CheckSet::empty().with(Check::ModTerm);
    let mut group = c.benchmark_group("verify_mod_term");
    group.bench_function("honest", |b| {
        b.iter(|| verify_with_checks(&honest, &opts, &set));
    });
    group.bench_function("broken_stride", |b| {
        b.iter(|| verify_with_checks(&broken, &opts, &set));
    });
    group.bench_function("full", |b| b.iter(|| verify(&honest, &opts)));
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_mod_term(&mut criterion);
    criterion.final_summary();
}

//! The M94 initializer-surface bench: the new family's price over one
//! at-floor executable wearing each initializer shape the gate walks —
//! the honest `__init_offsets` u32-offset section, the honest classic
//! `__mod_init_func` pointer section, and the same offsets section with
//! a hand-broken entry (the finding path: the walk pays the segment
//! search and the issue) — beside the whole-image pass over the honest
//! image (for scale: the family is a per-section stride read plus a
//! per-entry segment lookup, the price a build gate adds when it prices
//! the initializer contract alone).
//!
//! The point is the shape of the family's cost, not a claim about
//! absolute numbers: entries are O(1) segment lookups over a four-
//! segment image, so the bench catches a regression that turns the walk
//! into something super-linear. Numbers live in docs/BENCHMARKS.md (M94
//! section).

use criterion::Criterion;
use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_format::consts::{
    PLATFORM_MACOS, S_ATTR_PURE_INSTRUCTIONS, S_INIT_FUNC_OFFSETS, S_MOD_INIT_FUNC_POINTERS,
    S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
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
/// Entry count the honest shapes carry (the walk's steady state).
const ENTRIES: u32 = 64;

/// One at-floor executable: 64 KiB of `__text` inside the executable
/// `__TEXT`, the named initializer surface, the deployment target
/// pinned at the floor.
fn exec_with(offsets: Option<Vec<u8>>, mod_init: Option<Vec<u8>>) -> Vec<u8> {
    let mut b = ImageBuilder::executable("init-offsets-bench");
    let mut text_sects = vec![SectionSpec {
        name: "__text".into(),
        align_log2: 2,
        flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
        data: filler(0x94A1, 64 * 1024),
        relocs: Vec::new(),
    }];
    if let Some(bytes) = offsets {
        text_sects.push(SectionSpec {
            name: "__init_offsets".into(),
            align_log2: 2,
            flags: S_INIT_FUNC_OFFSETS,
            data: bytes,
            relocs: Vec::new(),
        });
    }
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: text_sects,
    });
    if let Some(bytes) = mod_init {
        b.add_segment(SegmentSpec {
            name: "__DATA_CONST".into(),
            maxprot: VM_PROT_READ | VM_PROT_WRITE,
            initprot: VM_PROT_READ | VM_PROT_WRITE,
            sections: vec![SectionSpec {
                name: "__mod_init_func".into(),
                align_log2: 3,
                flags: S_MOD_INIT_FUNC_POINTERS,
                data: bytes,
                relocs: Vec::new(),
            }],
        });
    }
    b.set_build_version(PLATFORM_MACOS, MINOS_AT_FLOOR, 0x000E_0000);
    b.set_entry(0);
    b.build().expect("the bench fixture builds").bytes
}

/// The honest u32-offset section: every entry names the load address
/// itself (the `__TEXT` vmaddr, inside the executable segment the
/// target check's pass arm accepts), the 4-byte stride whole.
fn honest_offsets() -> Vec<u8> {
    let mut out = Vec::with_capacity(ENTRIES as usize * 4);
    for _ in 0..ENTRIES {
        out.extend_from_slice(&0u32.to_le_bytes());
    }
    out
}

/// The broken offsets section: the honest entries plus one entry
/// outside every segment (the finding path).
fn broken_offsets() -> Vec<u8> {
    let mut out = honest_offsets();
    out.extend_from_slice(&0x7fff_f000u32.to_le_bytes());
    out
}

/// The honest classic pointer form: 64 whole 8-byte slots.
fn honest_mod_init() -> Vec<u8> {
    vec![0u8; ENTRIES as usize * 8]
}

fn bench_init_offsets(c: &mut Criterion) {
    let opts = strict();
    let honest = exec_with(Some(honest_offsets()), None);
    let broken = exec_with(Some(broken_offsets()), None);
    let pointers = exec_with(None, Some(honest_mod_init()));
    let set = CheckSet::empty().with(Check::InitOffsets);
    let mut group = c.benchmark_group("verify_init_offsets");
    group.bench_function("honest", |b| {
        b.iter(|| verify_with_checks(&honest, &opts, &set));
    });
    group.bench_function("broken_entry", |b| {
        b.iter(|| verify_with_checks(&broken, &opts, &set));
    });
    group.bench_function("pointer_form", |b| {
        b.iter(|| verify_with_checks(&pointers, &opts, &set));
    });
    group.bench_function("full", |b| b.iter(|| verify(&honest, &opts)));
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_init_offsets(&mut criterion);
    criterion.final_summary();
}

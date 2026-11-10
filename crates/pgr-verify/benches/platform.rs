//! The verifier's floor-gate bench (M10 rung 3, slice 2): `verify()`
//! over two chained-fixup executables born at their build versions —
//! one below its platform's chained-fixups floor (the `fixups_floor`
//! gate fires), one at the floor (clean). The gate itself is a floor
//! compare on the `LC_BUILD_VERSION` payload — cheap by construction —
//! so the bench pins the whole verify pass on both shapes and rotation
//! catches a regression in either; no numbers are claimed in
//! docs/BENCHMARKS.md for it yet. The core `platform` bench (rung 3,
//! slice 1) pins the consumer seam's own decision cost.

use criterion::{BenchmarkId, Criterion};
use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler};
use pgr_format::consts::{
    PLATFORM_IOS, PLATFORM_MACOS, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{Options, verify};

fn strict() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A chained-fixup executable born at `(platform, minos, sdk)` — the
/// same shape the rung-3 floor-gate tests pin (one `LC_LOAD_DYLIB`, a
/// `__got` bind slot, so `LC_DYLD_CHAINED_FIXUPS` is present).
fn chained_exec(platform: u32, minos: u32, sdk: u32) -> Vec<u8> {
    let mut b = ImageBuilder::executable("floor-bench");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: pgr_format::consts::S_REGULAR | pgr_format::consts::S_ATTR_PURE_INSTRUCTIONS,
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
    b.set_build_version(platform, minos, sdk);
    b.build().expect("the floor-bench fixture builds").bytes
}

fn bench_floor(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_platform_floor");
    let below = chained_exec(PLATFORM_IOS, 0x000E_0000, 0x0010_0000);
    let at = chained_exec(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    group.bench_with_input(BenchmarkId::new("verify", "below_floor"), &below, |b, bytes| {
        b.iter(|| verify(bytes, &strict()));
    });
    group.bench_with_input(BenchmarkId::new("verify", "at_floor"), &at, |b, bytes| {
        b.iter(|| verify(bytes, &strict()));
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_floor(&mut criterion);
    criterion.final_summary();
}

//! The verifier's arm64e bench (M10 rung 4, slice 1): `verify()` over
//! three executables — two born in the `DYLD_CHAINED_PTR_ARM64E` family
//! through the builder's pointer-format knob (an auth-rebase chain and an
//! auth-bind chain) and one 64_OFFSET control — so rotation pins the
//! strict pass on the new word family and keeps an honest same-shape
//! baseline next to it. No numbers are claimed in docs/BENCHMARKS.md yet
//! (the bench lands with the slice; the next gate run fills the section
//! the way the rung-3 floor bench was filled).

use criterion::{BenchmarkId, Criterion};
use pgr_fixtures::{
    ImageBuilder, PointerFormatKind, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    PLATFORM_MACOS, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
    VM_PROT_WRITE,
};
use pgr_verify::{Options, verify};

fn strict() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A chained-fixup executable born in `pf`'s word family: one rebase slot
/// (auth under arm64e) plus one bind slot, so `LC_DYLD_CHAINED_FIXUPS` is
/// present and the walk covers both shapes.
fn chained_exec(pf: PointerFormatKind) -> Vec<u8> {
    let mut b = ImageBuilder::executable("arm64e-bench");
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
    let slots = match pf {
        PointerFormatKind::Arm64e => vec![
            SlotKind::AuthRebase {
                offset: 0x40,
                diversity: 0x1234,
                addr_div: true,
                key: 2,
            },
            SlotKind::AuthBind {
                sym_index: sym,
                diversity: 0x4321,
                addr_div: false,
                key: 0,
            },
        ],
        PointerFormatKind::Offset64 => vec![
            SlotKind::Bind {
                sym_index: sym,
                addend: 0,
            },
            SlotKind::Rebase { target: 0x40 },
        ],
    };
    b.set_got(slots);
    b.set_entry(0x40);
    b.set_pointer_format(pf);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    b.build().expect("the arm64e-bench fixture builds").bytes
}

fn bench_arm64e(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_arm64e");
    let auth = chained_exec(PointerFormatKind::Arm64e);
    let control = chained_exec(PointerFormatKind::Offset64);
    group.bench_with_input(BenchmarkId::new("verify", "arm64e_auth"), &auth, |b, bytes| {
        b.iter(|| verify(bytes, &strict()));
    });
    group.bench_with_input(
        BenchmarkId::new("verify", "offset64_control"),
        &control,
        |b, bytes| {
            b.iter(|| verify(bytes, &strict()));
        },
    );
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_arm64e(&mut criterion);
    criterion.final_summary();
}

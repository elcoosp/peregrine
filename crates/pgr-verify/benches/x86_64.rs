//! The verifier's `x86_64` bench (M10 rung 5, slice 1): `verify()` over
//! two executables — one born in the `DYLD_CHAINED_PTR_64` family through
//! the builder's pointer-format knob (a VM-address rebase and a bind,
//! packed at the family's 4 KiB page) and one `64_OFFSET` control — so
//! rotation pins the strict pass on the second word family and keeps an
//! honest same-shape baseline next to it. No numbers are claimed in
//! docs/BENCHMARKS.md yet (the bench lands with the slice; the next gate
//! run fills the section the way the rung-3 floor bench was filled).

use criterion::{BenchmarkId, Criterion};
use pgr_fixtures::{
    CpuKind, ImageBuilder, PointerFormatKind, SectionSpec, SegmentSpec, SlotKind, SymbolSpec,
    filler,
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

/// A chained-fixup executable born in the CPU family and pointer format
/// the pair names: one rebase slot plus one bind slot, so
/// `LC_DYLD_CHAINED_FIXUPS` is present and the walk covers both shapes.
fn chained_exec(cpu: CpuKind, pf: PointerFormatKind, ident: &str) -> Vec<u8> {
    let mut b = ImageBuilder::executable(ident);
    b.set_cputype(cpu);
    b.set_pointer_format(pf);
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
        SlotKind::Rebase { target: 0x40 },
        SlotKind::Bind {
            sym_index: sym,
            addend: 0,
        },
    ]);
    b.set_entry(0x40);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    b.build().expect("the bench fixture builds").bytes
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_x86_64");
    group.throughput(criterion::Throughput::Bytes(
        chained_exec(CpuKind::X86_64, PointerFormatKind::Format64, "x86e-size").len() as u64,
    ));
    let x86e = chained_exec(CpuKind::X86_64, PointerFormatKind::Format64, "x86e-bench");
    let offset64 = chained_exec(
        CpuKind::Arm64,
        PointerFormatKind::Offset64,
        "offset64-bench",
    );
    group.bench_with_input(
        BenchmarkId::new("verify", "x86e_format64"),
        &x86e,
        |b, bytes| {
            b.iter(|| verify(bytes, &strict()));
        },
    );
    group.bench_with_input(
        BenchmarkId::new("verify", "offset64_control"),
        &offset64,
        |b, bytes| {
            b.iter(|| verify(bytes, &strict()));
        },
    );
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_verify(&mut criterion);
    criterion.final_summary();
}

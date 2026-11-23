//! The `x86_64` input surface's parity bench (M10 rung 5, slice 3): the
//! same pointer-shaped corpus — `__data` rebase slots and one
//! GOT-indirect `_printf` bind — built twice, once as arm64-typed
//! objects (the arm64 alphabet's `UNSIGNED`/GOT-load forms) and once as
//! x86_64-typed objects (`X86_64_RELOC_UNSIGNED`/`GOT_LOAD`), linked
//! under their own families through the full Passes 1–3 plan. The two
//! alphabets' decoders differ in shape but price the same per-slot work
//! (the pair decode is one `match` arm, the patch planning one
//! displacement compose), so the honest expectation is parity — one
//! family branch, the shape gate the rung-4/5 word-family benches
//! pinned, on the input side.
//!
//! Baseline note (docs/BENCHMARKS.md): the numbers are recorded honestly
//! as a *shape-parity* gate — the sandbox baselines below the rung have
//! not been re-measured on dedicated hardware; this bench exists so the
//! next perf pass measures both input alphabets against the same corpus.

use criterion::{BenchmarkId, Criterion, Throughput};
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{CpuKind, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// The dylib the GOT bind resolves against (the tests' helper shape).
fn dylib() -> pgr_core::resolve::Dylib {
    pgr_core::resolve::Dylib {
        install_name: "/usr/lib/libSystem.B.dylib".into(),
        current_version: 0,
        compatibility_version: 0,
        exports: vec![b"_printf".to_vec()],
        weak: false,
        lazy: false,
        upward: false,
        reexport: false,
        needed: false,
        hidden: false,
    }
}

/// One pointer-shaped object family-typed: `n` `__data` rebase slots
/// against `_main` and one GOT-indirect `_printf` call in `__text` (the
/// slice-2 record's call shape — no stub lane in either family's
/// corpus).
fn corpus(n: usize, cpu: CpuKind) -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("bench_main.o").set_cputype(cpu);
    let text: Vec<u8> = match cpu {
        CpuKind::Arm64 => [
            0x9000_0000u32, // adrp x0, _printf@GOTPAGE
            0xF940_0000u32, // ldr x0, [x0, _printf@GOTPAGEOFF]
            0xD65F_03C0u32, // ret
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect(),
        CpuKind::X86_64 => [
            &[0x48u8, 0x8B, 0x05, 0xFC, 0xFF, 0xFF, 0xFF][..], // movq _printf@GOTPCREL(%rip)
            &[0xC3],                                           // ret
        ]
        .concat(),
    };
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; n * 8], vec![]));
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    let printf_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_printf".into(),
        weak_ref: false,
    });
    let main = b.sym_index(main_sym);
    let printf = b.sym_index(printf_sym);
    match cpu {
        CpuKind::Arm64 => {
            b.section_mut(sect).relocs = vec![
                ObjectReloc::got_page21(printf).at(0),
                ObjectReloc::got_pageoff12(printf).at(4),
            ];
            for i in 0..n {
                let r = ObjectReloc::unsigned(main).at((i * 8) as u32);
                b.section_mut(data).relocs.push(r);
            }
        }
        CpuKind::X86_64 => {
            b.section_mut(sect)
                .relocs
                .push(ObjectReloc::x86_got_load(printf).at(3));
            for i in 0..n {
                let r = ObjectReloc::x86_unsigned(main).at((i * 8) as u32);
                b.section_mut(data).relocs.push(r);
            }
        }
    }
    vec![LinkInput {
        name: "bench_main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// Links one corpus under its own family (the Passes 1–3 plan the bench
/// prices — the input decode, the scan, the layout's patch planning).
fn plan(corpus: &[LinkInput], cpu: pgr_core::cpu::CpuFamily) -> pgr_core::link::LinkResult {
    link(
        corpus,
        &[],
        &LinkConfig {
            cpu,
            filetype: OutputType::Execute,
            dylibs: vec![dylib()],
            ..LinkConfig::default()
        },
    )
    .expect("the bench corpus plans")
}

/// Measures both input alphabets over the 10³/10⁴ slot corpora (the
/// parity gate beside the rung-5 word-family bench).
fn bench_x86_64_inputs(c: &mut Criterion) {
    let mut group = c.benchmark_group("x86_64_inputs");
    for n in [1_000usize, 10_000] {
        group.throughput(Throughput::Elements(n as u64));
        for (name, kind, cpu) in [
            (
                "arm64_control",
                CpuKind::Arm64,
                pgr_core::cpu::CpuFamily::Arm64,
            ),
            ("x86_64", CpuKind::X86_64, pgr_core::cpu::CpuFamily::X86_64),
        ] {
            let corpus = corpus(n, kind);
            group.bench_with_input(
                BenchmarkId::new(name, n),
                &corpus,
                |b, corpus: &Vec<LinkInput>| {
                    b.iter(|| plan(corpus, cpu));
                },
            );
        }
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_x86_64_inputs(&mut criterion);
    criterion.final_summary();
}

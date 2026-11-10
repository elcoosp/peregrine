//! Chained-fixup planner benchmark across the two word families (M10
//! rung 4, slice 2) and the authenticated policy (slice 3): the same
//! slot corpus planned as `DYLD_CHAINED_PTR_64_OFFSET` (the M2 default),
//! `DYLD_CHAINED_PTR_ARM64E` (the rung-4 producer family), and the same
//! family with every slot signed (`FixupAuth` policies — the auth words
//! cost one extra encoder branch and the auth bind's addend rides the
//! import entry). The corpus mirrors a mixed rebase/bind GOT-and-data
//! surface at 16 KiB-page scale.
//!
//! Baseline note (docs/BENCHMARKS.md): the numbers are recorded honestly
//! as a *shape-parity* gate — the sandbox baselines below the rung have
//! not been re-measured on dedicated hardware; this bench exists so the
//! next perf pass measures both families (and the auth policy) against
//! the same corpus.

use criterion::{BenchmarkId, Criterion, Throughput};
use pgr_core::fixups::{
    FixupAuth, FixupKind, FixupPointerFormat, FixupSlot, plan_fixups_with_auth,
    plan_fixups_with_format,
};
use pgr_core::interner::Interner;

/// One segment shaped like the layout's `__TEXT`/`__DATA` pair: the file
/// mirrors the vm layout under the constant-delta contract.
const IMAGE_BASE: u64 = 0x1_0000_0000;
const TEXT_VM: u64 = IMAGE_BASE + 0x4000;
const SEG_SIZE: u64 = 8 * 1024 * 1024;
const PAGE: u64 = pgr_format::consts::PAGE_SIZE_16K;

/// A deterministic mixed corpus: 3/4 rebases (pointer slots over the
/// segment) and 1/4 binds against 64 distinct imports — the GOT-heavy
/// shape the fixtures' dylib-call corpus uses.
fn corpus(n: usize) -> (Interner, Vec<FixupSlot>) {
    let names: Vec<Vec<u8>> = (0..64)
        .map(|i| format!("_bench_import_{i:02}").into_bytes())
        .collect();
    let (interner, ids) = Interner::build(&names);
    let slots: Vec<FixupSlot> = (0..n)
        .map(|i| {
            let vaddr = TEXT_VM + (i as u64) * 8;
            if i % 4 == 0 {
                FixupSlot {
                    vaddr,
                    kind: FixupKind::Bind {
                        lib_ordinal: 1,
                        name: ids[i % ids.len()],
                        addend: (i % 300) as i64,
                        weak: false,
                    },
                }
            } else {
                FixupSlot {
                    vaddr,
                    kind: FixupKind::Rebase {
                        target_vaddr: TEXT_VM + ((i * 64) % (SEG_SIZE as usize)) as u64,
                    },
                }
            }
        })
        .collect();
    (interner, slots)
}

/// Measures both word families — and the same family with every slot
/// signed — over the 10³/10⁴/10⁵ slot corpora.
fn bench_arm64e(c: &mut Criterion) {
    let mut group = c.benchmark_group("plan_fixups_word_family");
    for n in [1_000usize, 10_000, 100_000] {
        let (interner, slots) = corpus(n);
        group.throughput(Throughput::Elements(n as u64));
        for (name, format) in [
            ("offset64", FixupPointerFormat::Offset64),
            ("arm64e", FixupPointerFormat::Arm64e),
        ] {
            group.bench_with_input(
                BenchmarkId::new(name, n),
                &slots,
                |b, s: &Vec<FixupSlot>| {
                    b.iter(|| {
                        plan_fixups_with_format(
                            s.clone(),
                            &[(TEXT_VM, SEG_SIZE, 0x4000)],
                            IMAGE_BASE,
                            PAGE,
                            &interner,
                            None,
                            format,
                        )
                    });
                },
            );
        }
        // The authenticated half (slice 3): the same corpus, every slot
        // signed (rebase and bind alike — the auth bind's addend moves
        // to the import entry, so the table build runs its split too).
        let policies: Vec<FixupAuth> = (0..n)
            .map(|i| FixupAuth {
                vaddr: TEXT_VM + (i as u64) * 8,
                key: (i % 4) as u8,
                diversity: (i % 0xFFFF) as u16,
                addr_div: i % 2 == 0,
            })
            .collect();
        group.bench_with_input(
            BenchmarkId::new("arm64e_auth", n),
            &slots,
            |b, s: &Vec<FixupSlot>| {
                b.iter(|| {
                    plan_fixups_with_auth(
                        s.clone(),
                        &[(TEXT_VM, SEG_SIZE, 0x4000)],
                        IMAGE_BASE,
                        PAGE,
                        &interner,
                        None,
                        FixupPointerFormat::Arm64e,
                        &policies,
                    )
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_arm64e(&mut criterion);
    criterion.final_summary();
}

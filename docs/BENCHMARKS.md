# Peregrine Benchmarks — M0/M1/M2 Baselines

Status: **M0, M1 and M2 gates recorded** (TDD §10.3 parser gate + TDD §12 M1
end-to-end link baseline + architecture doc §10.3 M2 dynamic-link baseline).

These numbers are **dev-sandbox baselines**, not Apple Silicon results. They
exist to (a) prove the benchmark harness works end-to-end from day one and
(b) give Pass 1 (M1) a regression anchor. Nothing here is a product claim —
the perf doc's Phase P0 replaces every one of these numbers with measured
Apple Silicon baselines.

## Harness

* Framework: Criterion (macro-free entry point so the workspace `missing_docs`
  gate stays intact).
* Unit: `pgr_format::summarize` — the structural parse: header walk, all load
  commands, all sections, the full symbol table, every relocation entry, and
  a complete chained-fixups chain walk.
* Corpus: deterministic arm64 executables built by `pgr-fixtures` (no I/O,
  no clocks; identical bytes every run).
* Reproduce with:

```sh
cargo bench -p pgr-format
```

The M1 link baseline (new) uses the same harness rules: the unit is the full
Pass 0–5 pipeline (`pgr_driver::link_to_bytes`) over deterministic
relocatable-object corpora; the corpus carries real relocations (BRANCH26,
ADDEND+PAGE21/PAGEOFF12 pairs, UNSIGNED pointer slots → chained rebases),
cross-object symbol resolution and common symbols, so resolution and layout
do honest work.

```sh
cargo bench -p pgr-driver
```

## Recorded baseline (M0, commit at v0.1.0)

| Bench | Input | Median | Throughput |
|---|---|---|---|
| `pgr-format/summarize/single_image` | ~48 KiB exec (512 syms, 1 Ki relocs, ~85 got slots) | ~0.96 µs | **~53 GiB/s** |
| `pgr-format/summarize/corpus_24_images` | ~7.6 MiB corpus (24 execs, 4 096 syms + 8 192 relocs each) | ~181 µs | **~25.7 GiB/s** |

## Recorded baseline (M1, static hello-world pipeline)

| Bench | Input | Median | Notes |
|---|---|---|---|
| `pgr-driver/link/small_4_objects` | 4 objects, 256 defs + 256 refs each, 8 KiB text | **~2.3 ms** (M1) / ~3.4 ms (M2) | full Pass 0–5, single-threaded |
| `pgr-driver/link/large_32_objects` | 32 objects, 2 048 defs + 2 048 refs each, 32 KiB text (~1.6 MiB inputs) | **~170 ms** (M1) / ~289 ms (M2) | ~9.5 MB/s of input; resolution graph spans all 32 objects |

The M2 deltas are the cost of the dynamic-link surface added on the same
corpora: `__mh_execute_header` + full export-trie build, undefined-symbol
symtab entries, the indirect symbol table, and the two extra `__got`
bucket passes — all single-threaded, all due to become tile-local in M4.

## Recorded baseline (M2, dynamic executables via `.tbd`)

| Bench | Input | Median | Throughput | Notes |
|---|---|---|---|---|
| `pgr-driver/link_dylib/small_4_objects_dylib` | 4 callers × 256 branch-through-stub relocs + one 256-export `.tbd` | **~2.0 ms** | ~88 MiB/s | full bind path: stub/GOT synthesis, first-use import table, bind chains |
| `pgr-driver/link_dylib/large_32_objects_dylib` | 32 callers × 2 048 dylib calls (~1 MiB text) + `.tbd` | **~42 ms** | ~88 MiB/s | 65 536 chained bind slots (GOT + stubs) per link |

How to read the M1 numbers:

1. They are the **starting line** for M4 ("the speed pass"), not a target.
   The M1 pipeline is deliberately single-threaded; the M4 gate (≥5× median
   vs `ld64.lld` at 16 threads, parallel efficiency ≥ 70%) is measured
   against this exact corpus shape.
2. The large corpus is resolution-heavy (4 096 external references per
   object, cross-object definition graph), which exercises Pass 2's
   name-table and Pass 3's piece placement, not just byte copying.
3. The M0 parser baseline (~25–53 GiB/s metadata walk) remains the Pass 1
   anchor: M1's per-file parse starts far below it because it now *decodes*
   symbols, relocs and pairs rather than only counting them.

Machine context (honest caveat): 2-core Intel Xeon (KVM guest), warm cache;
the corpus is L2/L3-resident, so these are *metadata-walk* rates, not DRAM
streaming rates. `summarize` touches the metadata tables (symtab, relocs,
fixup slots), not section payload bytes — the real Pass 1 parser will touch
every input byte and therefore start well below these numbers.

## How to read this

1. The baselines are the **starting line**, not a target. M4's parallel parse
   (LPT-scheduled per file, hash-binned interning) is gated on beating these
   per-thread rates at the same corpora, then on parallel efficiency.
2. Per-pass budgets from the perf doc (§9.3) will be enforced in CI as they
   land: `--time` JSON, single-threaded fraction ≤ 15% (except flush),
   parallel efficiency ≥ 70% on Passes 1/3/4.
3. Nightly wall-clock benchmarks against ld-prime / `ld64.lld` / mold-macho
   require the Apple Silicon rigs from Phase P0 (perf doc §9.1) — the CI
   skeleton for that ships with this milestone, the hardware baselines do
   not exist yet.

## M2 perf gate status (architecture doc §10.3 row M2)

The M2 performance gate — "Pass 2 and Pass 3 meet the parallel-efficiency
budget on the 100 MB corpus" — requires the Phase P0 Apple Silicon rig
(perf doc §9.1: parallel efficiency ≥ 70% for Passes 1/3/4 at 8 P-cores,
single-threaded fraction ≤ 15% except flush). This milestone ships the
**harness and the baseline** (`link_dylib` corpora above); the gate itself
stays open until the rig exists, exactly like the M0/M1 numbers.

The bind path is already shaped for M4's tile emit: the import table is
assigned in first-use order over address-sorted slots (spike S6 result —
`ld64.lld` verified), so chain encoding never mutates the table and the
per-page fixup lists (perf doc §4.3) can bucket by destination page without
re-sorting.

## Known follow-ups

* Add a bench for the *byte-touching* parse (section data copied/summed) so
  the parser baseline is memory-bound, not metadata-bound.
* Parameterize the corpus generator (symbols/relocs/got slots) behind CLI
  flags of a small `xtask` so nightly runs can sweep corpus shapes.
* Import-table canonical order (D7) can replace first-use order when the
  M4 tile scheduler needs it — the planner isolates that decision (see
  `pgr-core/src/fixups.rs` module docs).

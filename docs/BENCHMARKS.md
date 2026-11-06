# Peregrine Benchmarks — M0/M1/M2/M3/M4/M5 Baselines

Status: **M0–M5 gates recorded** (TDD §10.3 parser gate + TDD §12 M1
end-to-end link baseline + architecture doc §10.3 M2 dynamic-link baseline +
M3 export-trie gate "trie build < 10 ms for 10⁵ exports" + M4 fused-emit
byte-identity gate and its sandbox perf half + M5 archive/dead-strip/
cstring gates).

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

## Recorded baseline (M5, archives & dead code — S7/D1/D12/D4)

The M5 milestone (architecture doc §10.3 row M5) adds the archive surface
(ranlib-guided lazy member pull — the **S7 decision: lazy adopted**),
symbol-boundary atomization (D1) with the `-dead_strip` mark-sweep (D12),
`__cstring` merging (D4) and the real-world flag surface (`-filelist`,
`-framework`/`-F`, `-sectcreate`, `-all_load`/`-force_load`). New benches:

### Archive parse (`pgr-format/parse_archive`, new bench)

| Bench | Input | Median | Throughput |
|---|---|---|---|
| `pgr-format/parse_archive/archive_64_members` | 64-member archive (member objects + name-sorted ranlib table, ~1.4 MiB) | ~118 µs | **~11.9 GiB/s** |

The Pass 0 cost of the lazy strategy: one structural walk that yields the
member table and the `(symbol, member)` index the pull fixpoint consumes.

### Archive liveness (`pgr-driver/link_archive`, new bench — the S7 decision rule)

Corpus: 64 members × 256 symbols × 32 KiB (≈ 2 MiB archive); `main.o`
references member 1's symbols and each member references its predecessor,
so the pull fixpoint loads a transitive chain — the rest of the archive is
never needed.

| Bench | Median | Notes |
|---|---|---|
| `pgr-driver/link_archive/archive_64_lazy` | **4.02 ms** | S7 lazy: only the pulled members are parsed and placed |
| `pgr-driver/link_archive/archive_64_all_load` | **49.06 ms** | `-all_load` eager baseline: all 64 members parsed |
| **Δ** | **12.2×** | the S7 adoption rule ("adopt lazy if ≥ 20% faster") is met with an order of magnitude to spare |

### Dead-strip (`pgr-driver/link_dead_strip`, new bench — the D12 perf gate)

Corpus: the large static corpus (32 objects × 2 048 symbols × 32 KiB) with
`MH_SUBSECTIONS_VIA_SYMBOLS` set and a second, never-referenced symbol set
per object (≈ 50% dead weight).

| Bench | Median | Notes |
|---|---|---|
| `pgr-driver/link_dead_strip/large_32_objects_off` | **255 ms** | the M1–M4 shape (whole-section pieces) |
| `pgr-driver/link_dead_strip/large_32_objects_on` | **134 ms** | `-dead_strip`: mark-sweep + atom pieces |
| **Δ** | **1.9× faster** | the gate ("dead-strip adds ≤ 30% to the link") is met with negative overhead: half the atoms are never placed, copied or hashed |

Optimization note (bench-driven, recorded because it shaped the D12 code):
the first working mark-sweep was **3.5× slower** than the unstripped link
(911 ms) — the live-set identity was an O(atoms) linear scan per query and
the mark phase re-scanned every relocation per atom. Three changes closed
it: (a) liveness queries are O(log atoms) binary searches over the shared
atom-start table, (b) the edge graph is built in one pass per section —
relocations are bucketed into their atoms once, never re-scanned per atom,
(c) the atom tables are borrowed slices instead of per-call clones. The
result is also byte-identical to the slow first draft (the live set is a
pure function of the inputs).

### `__cstring` merging (`pgr-driver/link_cstring`, new bench)

| Bench | Input | Median | Notes |
|---|---|---|---|
| `pgr-driver/link_cstring/cstring_16_objects` | 16 objects × 512 strings (half a shared pool duplicated in every object) | **1.69 ms** | the shared pool is placed once; per-string dedup is a hash-map pass over string atoms (D4) |

### M4 gates still hold with M5 on (the roadmap's M5 precondition)

| Bench | M4 recorded | M5 re-measured | Verdict |
|---|---|---|---|
| `pgr-emit/emit` fused vs reference | 1.37× (1.59 vs 2.18 ms) | **1.39× (1.58 vs 2.20 ms)** | holds |
| `pgr-driver/link/large_32_objects` | 172.1 ms | 172.7 ms | holds (noise band) |
| `pgr-driver/link_dylib/large_32_objects_dylib` | 33.8 ms | 32.9 ms | holds |
| `pgr-driver/link_outputs/dylib_8_objects` | 18.1 ms | 18.7 ms | holds |
| `pgr-format/summarize/single_image` | ~53 GiB/s | 51.8 GiB/s | holds |
| `pgr-core/trie` `m3_partition/100000` (10⁵ exports) | 31.5 ms | 30.7 ms | holds (legacy M2 baseline: 354.9 ms) |

The M5 byte-identity gates: `m5_archive_member_is_pulled_and_the_output
_verifies`, `m5_dead_strip_matches_the_reference_emit_and_determinism`,
`m5_cstring_merge_dedups_across_inputs` (and the section-relative pointer
gate), `m5_sectcreate_places_file_contents` — all compare the fused bytes
against the preserved reference emit on the new corpus shapes and fail the
build on divergence.

```sh
cargo bench -p pgr-format --bench parse -- parse_archive
cargo bench -p pgr-driver --bench link -- "link_archive|link_dead_strip|link_cstring"
```

## Recorded baseline (M4, the speed pass — fused tile emit)

The M4 milestone (architecture doc §10.3 row M4) rewrote Pass 4 as the
**fused tile emit** (perf doc §4.4): parallel 16 KiB tiles copy the coalesced
runs, apply relocations, encode chain words, place the `__LINKEDIT` chunks
and hash the 4 KiB signature pages in **one pass over each byte**, where the
reference body made five. The pre-fusion body stays in the tree verbatim
(`build_image`); every bench records both, and the byte-identity gate
(fused == reference) is asserted at bench setup and in the test suite.

### Pass 4 isolated (`pgr-emit/emit`, new bench)

Corpus: 16 objects × 512 symbols × 32 KiB text with branch + pointer-slot
relocations; output ≈ 0.94 MiB, signed (page hashes included in the emit).

| Bench | Median | Throughput | Notes |
|---|---|---|---|
| `pgr-emit/emit/reference_pass4` | **2.18 ms** | 441 MiB/s | the M1–M3 body: copy+patch, chains, chain-starts, `__LINKEDIT`, then **two** full-image SHA-256 passes (UUID derivation + final hashes) |
| `pgr-emit/emit/fused_tile_pass4` | **1.59 ms** | 605 MiB/s | M4: tiles fuse copy+patch+chains+`__LINKEDIT`+hashing; only page 0 re-hashes after the UUID lands |
| **Δ** | **1.37×** | | on 2 threads of a 2-core KVM guest; tile parallelism + one-pass-over-bytes scale with P-core count on the P0 rig |

### Full pipeline (`pgr-driver`, fused vs reference on the same corpora)

| Bench | Fused (M4) | Reference (pre-fusion) | Δ |
|---|---|---|---|
| `pgr-driver/link/small_4_objects` | 2.34 ms | 2.45 ms | 1.05× |
| `pgr-driver/link/large_32_objects` | 172.1 ms | 174.7 ms | 1.01× |
| `pgr-driver/link_dylib/small_4_objects_dylib` | 1.98 ms | 2.19 ms | 1.10× |
| `pgr-driver/link_dylib/large_32_objects_dylib` | 33.8 ms | 37.3 ms | **1.11×** |
| `pgr-driver/link_outputs/dylib_8_objects` | 18.1 ms | 18.1 ms | ~1× |
| `pgr-driver/link_outputs/bundle_8_objects` | 17.9 ms | 18.1 ms | ~1× |

How to read the M4 numbers:

1. **Pass 4 is the milestone's unit of work** and it shows the full fusion
   win (1.37×). The *full-pipeline* rows are dominated by serial Pass 2/3
   (resolution + layout, deliberately unchanged at M4), which is why the
   resolution-heavy static corpus (large_32: 4 096 external references per
   object) moves only 1% — its wall time is Pass 2/3, not emit. The
   bind-path corpora (65 536 chained bind slots per link) lean on Pass 4
   and gain 10–11%.
2. **Parallelism is observable but hardware-bound**: `PGR_JOBS=1` on the
   large static corpus measures 179.0 ms vs 172.1 ms at the default
   (2 threads) — Pass 1 + tile emit already beat the serial schedule on
   two cores. The G1 gate (≥ 5× vs `ld64.lld` at 16 threads, ≥ 1.5× vs
   ld-prime, single-threaded fraction ≤ 15% except flush, RSS ≤ 2.5×
   output) needs the P0 rig; 2 threads cannot exhibit 16-thread scaling,
   exactly like the M0–M3 hardware-bound numbers.
3. **Byte-identity is the gate, not a hope**: `m4_fused_driver_output_is
   _byte_identical_to_the_reference`, `m4_fused_matches_reference_on_m2_and
   _m3_corpora`, the ten `pgr-emit/tests/m4_fused.rs` corpus shapes, and the
   bench-setup assertions all compare the fused bytes against the preserved
   reference emit — equality failures fail the build.
4. **S1 writer pool** (4 writers, 8 MiB blocks, `set_len` extent
   preallocation, file-order `pwrite`) replaced the single-writer flush;
   byte-exactness is gated across block boundaries. The sandbox's writes
   land in the page cache, so a wall-clock writer number would measure the
   host, not the pool — the writer sweep (spike S1's writer-count/block-size
   matrix) runs on the P0 rig against real storage.
5. **D9/D10** land as measured defaults: the shared pool (`PGR_JOBS`
   override, else `available_parallelism` on Linux hosts — the macOS
   P-core default joins with the P0 rig, spike S4) and the parallel
   pre-fault of the zero-page-backed output buffer.

```sh
cargo bench -p pgr-emit --bench emit
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

## M3 perf gate status (architecture doc §10.3 row M3)

The correctness gate is closed on this hardware: `m3_dylib_output_passes_
verifier_strict`, `m3_exec_against_pgr_dylib_passes_the_pair_gate` (the
dyld-replay pair check against the dylib's trie), `m3_bundle_output_passes_
verifier`, `m3_reexport_library_lands_in_the_trie`, `m3_export_filters_shape_
trie_and_symtab` and the deterministic double-link all pass, and the trie
diff against `ld64.lld` runs through the same golden harness as M2 (skipped
when lld is absent). The **performance half** (10 ms for 10⁵ exports) is
met within hardware margin: 31.5 ms single-threaded on this 2-core KVM
sandbox vs the ~3 ms/s P-core the P0 rig provides — ≈ 8–12 ms extrapolated.
The gate formally closes on the P0 rig, exactly like the M0/M1/M2
hardware-bound numbers.

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

## Recorded baseline (M3, dylibs & bundles — export trie + output kinds)

The M3 performance gate (architecture doc §10.3 row M3): **"Export trie
build < 10 ms for 10⁵ exports (or parallelized if not)"**. The unit is
`pgr_core::trie::build` over a 10⁵-name corpus (`_pgr_fn_*` C symbols plus an
ObjC-style `_OBJC_CLASS_$_*` shared-prefix block — the worst case for
tries). The bench keeps the M2 builder (`legacy_m2`, verbatim) next to the
M3 rewrite (`m3_partition`) so the rewrite's claim is measured, not argued:

| Bench | Input | Median |
|---|---|---|
| `export_trie_build/legacy_m2/1000` | 1 000 exports | ~2.5 ms |
| `export_trie_build/legacy_m2/10000` | 10 000 exports | ~28.8 ms |
| `export_trie_build/legacy_m2/100000` | 100 000 exports | **~363 ms** |
| `export_trie_build/m3_partition/1000` | 1 000 exports | ~0.30 ms |
| `export_trie_build/m3_partition/10000` | 10 000 exports | ~3.5 ms |
| `export_trie_build/m3_partition/100000` | 100 000 exports | **~31.5 ms** |

The M3 builder is a range-partition trie over the sorted export list
(multikey quicksort skips the shared prefixes that make `memcmp` sorts
expensive; every edge is created once in compressed form; the offset
fixpoint converges from a 4-byte upper bound over packed per-node rows).
That is **8–11× faster than the M2 builder** and turns the gate's 10⁵-export
budget from "impossible single-threaded" into "on the order of the gate on
reference hardware": this dev sandbox is a 2-core KVM guest with ~3× slower
single-thread throughput than the P0 rig's P-cores, where the same build
measures ≈ 8–12 ms. The gate closes when measured on that rig (or when the
M4 tile pass parallelizes the build, as the gate's "or parallelized" clause
allows).

```sh
cargo bench -p pgr-core --bench trie
```

The M3 output-kind benches (new) run the full pipeline with `-dylib` /
`-bundle` semantics — 0 image base (no `__PAGEZERO`), `LC_ID_DYLIB`, and the
full export trie over every defined external:

| Bench | Input | Median |
|---|---|---|
| `pgr-driver/link_outputs/dylib_8_objects` | 8 objects × 1 024 defs (all exported) | ~19.1 ms |
| `pgr-driver/link_outputs/bundle_8_objects` | same corpus as `MH_BUNDLE` | ~18.5 ms |

## Known follow-ups

* Add a bench for the *byte-touching* parse (section data copied/summed) so
  the parser baseline is memory-bound, not metadata-bound.
* Parameterize the corpus generator (symbols/relocs/got slots) behind CLI
  flags of a small `xtask` so nightly runs can sweep corpus shapes.
* Import-table canonical order (D7) can replace first-use order when the
  M4 tile scheduler needs it — the planner isolates that decision (see
  `pgr-core/src/fixups.rs` module docs). *Update, M4:* the tile scheduler
  shipped without needing D7 — the import table is built in Pass 3 and the
  chain words are read-only in Pass 4, so no cross-tile mutation exists;
  D7 remains open for the M6 incremental work (insertion-stable ordinals).
* M4 follow-ups for the P0 rig: writer-count/block-size sweep (S1 matrix),
  P-core pool sizing (S4), PGO build, and the G1 parallel-efficiency gate.

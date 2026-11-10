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
## Recorded baseline (M6, scale & ecosystem — ICF/veneers/legacy fixups/Stage A caches)

The M6 milestone (architecture doc §10.3 row M6) lands the in-tree scope:
branch veneers + the verifier branch-range checker, the `LC_DYLD_INFO_ONLY`
legacy fallback, `-icf=safe|all` (color refinement), the Stage A POI +
frozen-`.tbd` caches, and LTO/ObjC/Swift pass-through gates. New benches
(`cargo bench -p pgr-driver`):

### ICF (`pgr-driver/link_icf`, the "ICF ≤ 25% added wall" gate)

Corpus: 32 objects × 512 identical 12-byte functions (16,384 atoms, all
foldable; `MH_SUBSECTIONS_VIA_SYMBOLS` splitting; ~0.8 MiB of inputs).

| Bench | Median | Notes |
|---|---|---|
| `link_icf/large_32x512_off` | **17.29 ms** | fold-off (the M5 pipeline shape) |
| `link_icf/large_32x512_safe` | **19.37 ms** | `-icf=safe`: full fold (16,383 atoms folded, ~192 KiB of duplicate text removed) |
| **Δ** | **+12.0%** | the ≤ 25% gate holds; the refinement's byte hashing runs on the shared pool |

### Stage A POI cache (`pgr-driver/link_cache`, the §7.1 relink gate)

Corpus: 16 objects × 4,096 symbols × 4 KiB text (parse-heavy: ~64K symbols,
128K relocations; ~1.6 MiB of inputs). Cold = fresh cache directory per
iteration (parse + store + link); warm = every input is a cache hit.

| Bench | Median | Notes |
|---|---|---|
| `link_cache/medium_16_objects_cold` | **177.8 ms** | Pass 1 parse + store |
| `link_cache/medium_16_objects_warm` | **172.8 ms** | Pass 1 replaced by the POI decode |
| **Δ** | **−2.8%** | the corpus is Pass 2/3-bound (64K-symbol resolution dominates); the POI cache removes Pass 1 exactly, which bounds the wall gain on this shape. The §10.3 "relink ≥ 2× ld-prime" gate compares against ld-prime on the P0 rig |

Honesty note (§7.1's own framing): the POI cache is a Pass 0/1 elimination.
Where the wall is dominated by resolution/layout (this corpus), the gain is
bounded by Pass 1's share; Stage B/C (resident state, incremental relink)
address the rest.

### Frozen `.tbd` (`pgr-driver/tbd`, the "`.tbd` startup cost < 1 ms" gate)

Unit: parse-or-decode of one 256-export stub (`libBench.tbd`).

| Bench | Median | Notes |
|---|---|---|
| `tbd/libbench_text_parse` | **35.8 µs** | the M2 YAML text path |
| `tbd/libbench_frozen_load` | **19.9 µs** | the M6 frozen export-set decode (1.8×; both far below the 1 ms gate) |

### M4/M5 gates re-measured with M6 in the pipeline

The veneer scan (a per-iteration `Branch26` patch walk), the `FixupLc`
command-size dispatch and the fold-empty fast path are all active in every
link now:

| Bench | M5 record | M6 re-measure | Gate |
|---|---|---|---|
| `pgr-driver/link/large_32_objects` | 174–176 ms | **175.7 ms** | holds |
| `pgr-driver/link_dead_strip/large_32_objects_off` | 255 ms | **259.0 ms** | holds |
| `pgr-driver/link_dead_strip/large_32_objects_on` | 134 ms | **136.0 ms** | 1.90× vs off |

### Not benched (with reasons)

* **Veneer insertion** — the triggering corpus is a >128 MiB text (~4 s of
  SHA-256 per iteration); the feature is correctness-gated instead (the
  branch-range checker + determinism tests) and its steady-state cost is
  the per-iteration overflow scan already covered by the re-measured gates.
* **Legacy `LC_DYLD_INFO_ONLY` streams** — stream encoding is O(slots)
  with ULEB writes; at M6 scale the chained/classic split costs nothing
  measurable (the slot list is built once either way). The verifier's
  stream walk is gated for correctness, not speed.

## Recorded baseline (M7 — production; versioned cache, build-system surface)

The M7 milestone (architecture doc §10.3 row M7, in-tree scope) versions the
cache format, adds the build-system driver surface (response files,
`-syslibroot`, LRU-bounded caches) and the compatibility suite. New bench
(`pgr-driver/cache_evict`) plus the full re-measure of every prior gate with
M7 in the pipeline (`cargo bench`, default sampling, 2-core KVM sandbox):

### LRU-bounded cache (`pgr-driver/cache_evict`, new bench)

The size bound's cost lives only on the store path (scan + evict after each
POI store); warm hits never store, so the steady-state relink is untouched.

| Bench | Median | Notes |
|---|---|---|
| `cache_evict/unbounded` | **9.12 ms** | the M6 warm-cache path (4 objects × 1 024 symbols) |
| `cache_evict/bounded_64kib` | **9.73 ms** | every store scans and evicts (cap binds) |
| **Δ** | **+6.7% on cold stores** | warm links (all hits) measure identical to unbounded — no stores, no scans; the M7 format's `touch` recency mark is two syscalls per hit |

### Versioned cache format (v2) gates re-measured

| Bench | M6 (v1) record | M7 (v2) | Verdict |
|---|---|---|---|
| `pgr-driver/link_cache/medium_16_objects_cold` | 177.8 ms | 186.4 ms (quick-sampling run) | holds within the sandbox noise band |
| `pgr-driver/link_cache/medium_16_objects_warm` | 172.8 ms | **173.7 ms** | holds — the two-revision key, marker check and recency touch cost nothing measurable |
| `pgr-driver/tbd/libbench_text_parse` | 35.8 µs | 36.2 µs | holds |
| `pgr-driver/tbd/libbench_frozen_load` | 19.9 µs | **19.8 µs** | holds (the v2 frame is 4 bytes larger; ≪ the 1 ms gate) |

### Prior gates re-measured with M7 in the pipeline

| Bench | M4/M5/M6 record | M7 re-measure | Gate |
|---|---|---|---|
| `pgr-driver/link/large_32_objects` | 172–176 ms | **175.6 ms** | holds |
| `pgr-driver/link/small_4_objects` | 2.34 ms | 2.42 ms | holds |
| `pgr-driver/link_dylib/large_32_objects_dylib` | 33.8–37.3 ms | 36.9 ms | holds |
| `pgr-driver/link_outputs/dylib_8_objects` | 18.1–18.7 ms | 18.6 ms | holds |
| `pgr-driver/link_outputs/bundle_8_objects` | 17.9–18.5 ms | 18.4 ms | holds |
| `pgr-driver/link_archive/archive_64_lazy` | 4.02 ms | **3.99 ms** | holds (S7 lazy) |
| `pgr-driver/link_archive/archive_64_all_load` | 49.06 ms | 50.4 ms | holds |
| `pgr-driver/link_dead_strip/large_32_objects_off` | 255–259 ms | 263.6 ms | holds (noise band) |
| `pgr-driver/link_dead_strip/large_32_objects_on` | 134–136 ms | **136.4 ms** | 1.93× vs off (gate: ≤ +30%) |
| `pgr-driver/link_cstring/cstring_16_objects` | 1.69 ms (M5 record) | 1.94 ms | **no regression**: the M6 baseline re-measured on the same box today is 1.88 ms — the delta is environmental drift, not M7 code |
| `pgr-driver/link_icf/large_32x512_off` | 17.29 ms | **16.47 ms** | holds |
| `pgr-driver/link_icf/large_32x512_safe` | 19.37 ms | 18.92 ms | +14.8% vs off (gate: ≤ 25%) |
| `pgr-emit/emit` fused vs reference | 1.37× (1.59 vs 2.18 ms) | **1.38× (1.59 vs 2.17 ms)** | holds |
| `pgr-format/summarize/single_image` | ~53 GiB/s | 52.7 GiB/s | holds |
| `pgr-format/summarize/corpus_24_images` | ~25.7 GiB/s | 24.7 GiB/s | holds |
| `pgr-format/parse_archive/archive_64_members` | 11.9 GiB/s | **12.2 GiB/s** | holds (the M5 row's "~118 µs" was a unit slip: the corpus is ~118 KiB, i.e. ~9.9 µs at that rate — corrected here) |
| `pgr-core/trie m3_partition/100000` (10⁵ exports) | 31.5 ms | **27.9 ms** | holds (legacy M2 baseline today: 349.6 ms) |

### Fuzzing at scale (the M7 row's "fuzzers clean" gate)

Short local libFuzzer sessions (61 s each, ASan, 2-core sandbox) over the
four parser targets plus the two new ones — all clean after the fixes below:

| Target | Execs (61 s) | Result |
|---|---|---|
| `dyld_info_streams` (new) | 1 860 070 | clean |
| `cache_entries` (new) | 6 302 019 | clean after the `HEADER_LEN + len` overflow fix |
| `verify_image` | 143 230 | clean after the hostile-header arithmetic battery (structural/dyld_info/pair/chain_starts/branch_range) |
| `link_object` | 319 230 | clean after the stale `link()` signature fix and the 8 GiB `nreloc` pre-allocation bound |

Each crash class carries a deterministic regression test in the tree; the
M7 row's "fuzzers clean for 30 CPU-days" formally closes on the P0 rig.

## Recorded baseline (M8 — resident + incremental foundations)

The M8 milestone (architecture doc §10.4 row M8) ships the resident-server
foundations: `pgrd` (§7.2) with the in-memory POI session, the reverse
reference index, the insertion-stable import table, slack-aware layout and
the reused emit buffer. New bench (`pgr-driver/resident`) plus the M8
correctness gates (`m8_foundations.rs`, `m8_resident.rs`, `pgrd_binary.rs`).
Recorded on the same 2-core KVM dev sandbox (`cargo bench`, default
sampling).

### Resident warm relink (`pgr-driver/resident`, new bench)

Corpus: 64 objects × 2 048 symbols × 2 KiB text (the parse-heavy shape —
the symbol tables dominate the input bytes). The resident iterations run
the exact user path (`pgr -resident` → prepare → hash → negotiate → POI
decode → link → fused emit → wire); the daemon reports **64/64 POI hits**
from the second iteration on and reuses its emit buffer.

| Bench | Median | Throughput | Notes |
|---|---|---|---|
| `resident/one_shot_64_objects` | **224.3 ms** | 37.8 MiB/s | the full pipeline (v1.0 path) |
| `resident/resident_warm_64_objects` | **260.3 ms** | 32.6 MiB/s | POI hits 64/64, no input re-transfer, buffer reuse active |

**Honest verdict: a wash-to-slight-loss on this sandbox corpus, recorded
as-is.** The phase breakdown (release-mode probe):

| Phase | Cost |
|---|---|
| client Pass 0 (`prepare_link`) | 4.2 ms |
| client manifest build (hash + stage bytes) | ~8 ms (parallelized SHA-256) |
| daemon session link (POI decode + Passes 2–5 + wire) | ~248 ms |

The finding replays the M6 cache-bench physics one level up: this corpus —
like the M6 POI-cache corpus — is **Pass 2/3-bound** (interning, resolution,
layout, symtab/trie dominate), and the POI *decode* on this sandbox measures
comparable to a fresh parse, so the skipped Pass 1 does not cover the
manifest + wire overhead. What the numbers do not show (hardware-gated,
like every Apple-Silicon row in this doc): the §10.4 M8 performance gate
("resident relink ≥ 5× ld-prime") is decided on the P0 rig, and the
*bytes-over-the-wire* and *page-fault* savings this design exists for are
bounded by the fixture sizes here (8 MiB inputs, 6 MiB images). What the
bench *does* prove functionally: the session skip is real (hit counters),
the output is byte-identical to the one-shot link on every iteration
(gated in `m8_resident.rs`), and the emit buffer survives across links
(`scratch` capacity gate in the session tests).

### The M8 correctness gates (all green)

* `m8_foundations.rs` (13): reverse-index site lists (live + dead-filtered,
  total-ordered), insertion-stable import ordinals across growth rounds,
  slack padding math + fallback ladder, slack-off structural identity with
  v1.0, pre-parsed-link layout equality, archive pull through
  `link_from_objects`, the shared `-u` gate.
* `m8_resident.rs` (7): resident-vs-one-shot byte identity (executable,
  dylib and archive corpora, cold and warm), POI-hit counters across the
  wire, one-shot fallback transparency, daemon restart, 4-way concurrent
  clients, `-u` error parity through the fallback.
* `pgrd_binary.rs` (4): the real `pgrd` process — strict-verifier-clean
  resident output, SIGKILL-restart identity, link-error survival,
  idle-exit (§7.2).

```sh
cargo bench -p pgr-driver --bench resident
```

### The M9 GA fusion rung (`pgr-driver/resident-fusion`, new bench)

The fusion wire rung routes the `-resident -incremental` relink through
the daemon's §7.3 ladder (protocol v3: record in, refreshed record +
patch outcome out). Same 64-object parse-heavy corpus; every timed
iteration is a real edit (object 1 alternates between the pristine and a
byte-distinct variant, one dirty tile + re-sign each time), served by the
daemon's warm session and patched in memory.

| Bench | Median | Notes |
|---|---|---|
| `resident/one_shot_64_objects` | **235.3 ms** | the full pipeline (reference) |
| `resident/resident_warm_64_objects` | **272.1 ms** | POI hits 64/64, no input re-transfer |
| `resident-fusion/fusion_relink_64_objects` | **535.0 ms** | the §7.3 ladder in the session: relink pipeline (warm POIs) + plan + in-memory patch + re-sign + the renewed record |

**Honest verdict: the ladder costs ~2× the warm resident link on this
sandbox corpus, recorded as-is.** The delta pays for what the rung *is*:
the relink re-runs Passes 2–3 (this corpus's dominant share, warm POIs
only skip Pass 1 — the M8 verdict's physics again), plans the patch,
applies it in memory and re-signs, and the previous output's bytes cross
the wire once per changed output state (each patch changes the content
hash, so the session's blob cache misses). What the rung buys and the
bench proves functionally: the fusion cycle is correct end to end
(byte-identical to the one-shot incremental cycle — gated in
`m9_resident_fusion.rs`), the incremental state survives daemon
fallbacks (the daemon's full link renews the record — the regression
gate), and the relink's parse half rides the session. The
bytes-written win ("patch ~1% of the image") lands where the patch path
already proved it — the file-bound engine, P0-rig rows in the M9
section above.

### The §7.2 output-residency rung (`pgr-emit/wire-tiles` + re-recorded `pgr-driver/resident-fusion`)

Wire v5 closes the deferral the fusion rung recorded: the session now
*holds* every served image as resident output state (a content-addressed
blob under the session's existing ceiling and LRU), so the warm cycle's
previous output stops re-crossing the wire, and a patched relink's reply
is the **changed-tile stream** (`pgr_emit::incremental::TilePatch`:
`diff_tiles` on the daemon, `apply_tiles` + a content-hash gate on the
client) instead of the whole image. What crosses per warm relink:

| step | before (wire v3/v4) | after (wire v5) |
|---|---|---|
| previous output | uploaded once per changed output state | **0 bytes** (resident; re-uploaded only after a ceiling eviction) |
| patched relink reply | the full patched image | **the changed tiles only** — e.g. 37.9 KiB of an 87 KiB corpus image (2 of 6 tiles, page 0 + the edit + the re-sign tail), ≈16.4 KiB of 8 MiB for a one-tile edit |
| untouched relink reply | the full image, rewritten | **0 bytes**, nothing rewritten |

The rung's CPU price is a memcmp-speed scan (which doubles as the wire's
replay gate — the stream carries the patched image's SHA-256) plus a
tile-splice replay. Recorded (2-core KVM sandbox, criterion median,
20 samples, default sampling):

| bench | time | throughput | what it runs |
|---|---|---|---|
| `wire-tiles/diff_one_tile_edit_8mib` | **5.64 ms** | 1.39 GiB/s | the daemon-side tile diff (scan + SHA-256) |
| `wire-tiles/replay_one_tile_edit_8mib` | **0.75 ms** | 10.4 GiB/s | the client-side replay |
| `wire-tiles/diff_untouched_8mib` | **5.25 ms** | 1.52 GiB/s | the pure scan, zero tiles |

| (re-recorded on the rung) | time | what the step runs |
|---|---|---|
| `resident-fusion/fusion_relink_64_objects` | **529.6 ms** | the ladder + the tile stream (upload and download gone; the bench asserts the transport) |
| `resident-fusion-audited/fusion_relink_audited_64_objects` | **610.6 ms** | the ladder + the tile stream + the audit |

Honest verdict: on loopback unix sockets the wall clock is a **wash**
(529.6 ms vs the 502.5–535.0 ms band the group recorded across runs —
the relink is pipeline-bound, not socket-bound, and the 5.6 ms scan is
~1% of it). The win is the wire and the memory bus: megabytes that used
to cross per changed output state are now the changed tiles (~0.2–1% of
the image), and the machine-hosted `pgrd` shape (a daemon on another
host, a socketpair through a supervisor) is where the saved crossings
become wall clock. The CPU price is paid on every relink; the byte
saving is paid back on the first warm cycle.

### The audited fusion rung (`pgr-driver/resident-fusion-audited`, new bench)

Wire v4 serves `-incremental-verify` inside the session: the audited warm
relink runs the ladder **plus** the audit (byte-identity against the
reference emit — a second full fused emit of the same plan — and the
strict verifier's page-hash recompute). The group pairs with the
unaudited fusion group above on the same corpus and edit alternation:

| (2-core KVM sandbox, criterion median, 20 samples) | time | what the step runs |
|---|---|---|
| `resident-fusion/fusion_relink_64_objects` | **502.5 ms** | the ladder: warm pipeline + plan + in-memory patch + re-sign |
| `resident-fusion-audited/fusion_relink_audited_64_objects` | **597.4 ms** | the ladder **+ the audit**: the reference emit + the strict pass |

Honest verdict: the audit costs **+19% per audited relink** on this
corpus (94.8 ms — the reference emit over warm POIs plus the verifier's
chain walk and page-hash recompute). That is the rung's price for
never shipping an unaudited patch, paid only when `-incremental-verify`
is on; the driver's `-resident -incremental` cycles without the flag are
unchanged. The bench also caught the first real audit finding on the way
in: the symbol-heavy bench corpus overflowed the verifier's
function-starts delta accumulator — `build_func_starts` had emitted
absolute offsets into a **delta** stream since M0 (small corpora masked
it; 131 K function starts did not). Fixed with a regression gate in
`m9_resident_fusion.rs`.

## Recorded baseline (M9 — in-place incremental relink, tier 1)

The M9 milestone (architecture doc §10.4 row M9, §7.3 Stage C tier 1)
ships the incremental relink engine: the versioned link record
(`pgr-emit::incremental::LinkRecord`), the span-diff patch planner, the
clone-and-patch output path with the merged-hash CodeDirectory rebuild,
slack anchors, and the driver loop (`-incremental`,
`-incremental-verify`). New bench (`pgr-driver/incremental`) plus the M9
gates (`pgr-core/tests/m9_foundations.rs`, `pgr-emit/tests/incremental.rs`,
`m9_incremental.rs`). Recorded on the same 2-core KVM dev sandbox
(`cargo bench`, default sampling).

### Edit–relink loop (`pgr-driver/incremental`, new bench)

Corpus: 32 objects × 256 KiB text — the *write-heavy* shape (the output
pages dominate; the image is 8.53 MiB / 521 tiles of 16 KiB). The timed
edit flips eight words of one function mid-corpus (same size — the frozen
skeleton is the tier-1 contract). Every timed incremental iteration is a
real edit→patch cycle (the input alternates between the pristine and
edited object variants).

| Bench | Median | Throughput | Notes |
|---|---|---|---|
| `full_relink_8mib` | **16.4 ms** | 496 MiB/s | the complete pipeline + fused emit + write (v1.1 path) |
| `incremental_relink_8mib` | **17.6 ms** | 461 MiB/s | record → plan → clone-and-patch → re-sign |
| `untouched_relink_8mib` | **13.3 ms** | 610 MiB/s | identical inputs: plan says *untouched*, the output is left alone |

**Bytes written (the §7.3 gate "bytes written ∝ change size"): the mean
patch is 105 536 bytes per edited relink — 1.2% of the image.** Of that,
72.7 KiB is the rebuilt CodeDirectory (the signature's page-hash table is
contractually whole), the rest is the two dirty tiles (the edited content
tile + the UUID page). Max dirty tiles across 20 iterations: 2 of 521.

**Honest verdict: wall-time parity-to-slight-loss on this sandbox,
bytes-written win by 80×, recorded as-is.** Three physical reasons, each
bounded by the sandbox rather than the design:

1. **The clone degrades to a full copy.** On APFS, `std::fs::copy`
   resolves to `fclonefileat` — an instant copy-on-write clone, which is
   the §7.3 output path's foundation. This sandbox's ext4 has no reflink,
   so the clone reads and writes all 8.53 MiB — roughly the full link's
   own write cost, before any patch. Spike S8 (clone + dirty-page
   `pwrite` vs full write on APFS) is exactly the measurement this bench
   cannot make.
2. **The span digests are SHA-256 over the input bytes.** The planner
   hashes every copy-run tile piece and `__LINKEDIT` chunk once per
   relink (~8.6 MiB here) — comparable to the full emit's own page
   hashing. A faster non-crypto change-detection digest is a tuning knob,
   deliberately not pulled at tier 1 (a hash collision would mean reused
   stale bytes; the signature catches it at load, but the engine holds
   itself to the no-collision standard).
3. **The corpus is compute-bound.** Like the M6/M8 corpora, Passes 2–3
   dominate the pipeline share; the tier-1 engine deliberately re-runs
   them (per-symbol change propagation over the M8 reverse index is the
   M9 GA ladder).

What the bench *does* prove functionally: the dirty-tile set tracks the
change (2 tiles for a one-function edit, 0 for an unchanged relink), the
patched output is byte-identical to the full fused emit of the same plan
(gated in `pgr-emit/tests/incremental.rs` and `m9_incremental.rs`, and
re-proven per link under `-incremental-verify`), and the untouched path
costs 19% less than the full relink even before the clone question
arises. The §10.4 M9 hardware gate — "< 100 ms for a one-function edit at
1 GiB output; ≥ 10× vs ld-prime relink" — is decided on the P0 rig, where
the 1.2%-of-image patch bytes and the COW clone are the whole story.

### The M9 correctness gates (all green)

* `pgr-core/tests/m9_foundations.rs` (4): anchored relinks keep every
  section's reserved size, overflow falls to the natural pad through the
  §7.3 ladder, anchors are pure deterministic layout inputs, and the empty
  anchor list reproduces M8-c exactly.
* `pgr-emit/tests/incremental.rs` (9) + unit tests (16): the byte-identity
  contract (body edit, growth within slack, dylib image-base, no-slack
  and unsigned corpora), the no-op relink, symbol-count and
  overflow-ladder fallbacks, the integrity gate's honest sampling (caught:
  page 0, last page, resize; pinned: unsampled-page tampering is the
  signature's job), and the record codec's roundtrip + corruption
  tolerance (flip, truncate, append, foreign magic, arbitrary garbage —
  never a panic).
* `m9_incremental.rs` (11): the driver loop end to end — first link
  records, edited relink patches in place and verifies strict, no-op
  relink reports untouched, deleted/corrupt record and deleted output
  fall back, skeleton moves fall back *and* recover incrementally on the
  next link, `-incremental-verify` audits, `-no_incremental` stays full,
  link errors propagate, and the option surface parses.

```sh
cargo bench -p pgr-driver --bench incremental
```

## Recorded baseline (M9 tier 2b — the change-propagation planner)

The tier-2b milestone (architecture doc §7.3 step 3, roadmap row M9 GA)
ships the per-symbol change-propagation planner: the record grows the
parse's section-digest table (content + symbol records, v3), and the
relink planner gains the **propagation gate** — every changed content
span must sit inside `pgr_core::propagate::predict`'s scope (the seeds'
own output-section extents plus the reverse-index closure of their
dependents) or the relink falls back to the full link instead of
patching bytes nobody predicted. New bench (`pgr-emit/propagate`)
measures the gate's added cost over the planner's tier-1 baseline; the
corpus is the §10.4-shaped one — 8 objects × 256 cross-object reference
sites × 16 KiB `__text` (~274 KB image), one body edit as the seed.

| `pgr-emit/propagate` (2-core KVM sandbox, criterion median) | time | throughput |
|---|---|---|
| `propagation_scope` — digest diff + reverse-index build + closure walk | **572.9 µs** | 456.0 MiB/s |
| `plan_patch_with_gate` — full planner end to end (span table + diff + gate) | **1.1088 ms** | 235.6 MiB/s |

Reading: the propagation gate's whole added work (digest diff, reverse
index build, dependent closure) is ~52% of the planner's wall on this
corpus — the planner's span table extraction (TileCtx build) dominates.
The scope walk visits 2 048 reference sites and lands a one-section seed
with its dependents; on real edit shapes (one changed section, a handful
of dependents) the gate's cost is the reverse-index build, which the
resident session (M8) can amortize across links. The GA tier (incremental
resolve over the same index) is what turns this from a *gate* into a
*speedup* — recorded here so the baseline exists when it lands.

```sh
cargo bench -p pgr-emit --bench propagate
```

## Recorded baseline (M9 tier 2 — the segment-relayout patch tier)

The tier-2 milestone (architecture doc §7.3 "layout stability", roadmap
row M9 GA) executes the fallback ladder's middle rung: a skeleton shift
that the ladder classifies as `SegmentRelayout` — a section overflowing
its slack anchor within the policy's max pad, or the `__LINKEDIT` chunk
stream outgrowing its signature-boundary reservation — is admitted as a
relayout patch plan instead of falling to the full link. The record grows
the output-section content digest table (v4: SHA-256 per output section
over its copy-run bytes, a placement-invariant concatenation), which is
what lets the propagation gate exempt a *byte-identical* move (the
section's derived bytes — relocations, chain words — re-emit from the plan
and re-prove under the byte-identity contract) while genuine content churn
inside the moved suffix still answers to the propagation scope.

The bench (`pgr-driver/incremental::segment_relayout_relink_8mib`) climbs
a monotone ladder — eight +64 KiB growth steps of object 1, each beyond
the current anchor and each within the ladder's bound, then one reset
link back to pristine. The ladder shape is not cosmetic: the anchored
skeleton holds any size a section has already carried, so an alternating
grown↔pristine cycle degenerates to tier 1 after the first round trip;
only climbing growth re-triggers the tier. The recorded mean is therefore
the honest 8 tier-2 : 1 tier-1 mix, and the accounting pass prints the
per-step split.

| `pgr-driver/incremental` (container sandbox, ext4 — no reflink, the clone degrades to a full copy) | time |
|---|---|
| `full_relink_8mib` | **17.4 ms** |
| `incremental_relink_8mib` (tier 1, one-function edit) | 32.2 ms |
| `incremental_add_import_8mib` (tier 1, anchored ordinals) | 22.4 ms |
| `segment_relayout_relink_8mib` (8 tier-2 : 1 tier-1 mix) | **34.2 ms** |
| `untouched_relink_8mib` | 12.8 ms |

Bytes written (the §7.3 gate, accounting pass, 8.53 → 9.37 MiB image over
the ladder): each +64 KiB growth step patches **1.2 MiB (69–70 of 573
tiles, ~13% of the image)** — exactly the moved suffix (the re-padded
section's tail, the shifted downstream sections, the grown `__LINKEDIT`
chunks, the relocated `CodeDirectory` and the UUID page) — where the full
relink writes every byte. The wall-clock verdict is the same honest wash
the tier-1 bench recorded: ext4 has no reflink, so the clone is a full
copy and the patch path cannot win wall time on this filesystem; the
tier-2 mean lands within noise of the tier-1 mean and the APFS verdict is
decided on the P0 rig, where clonefile is instant and the 13%-of-image
patch is the whole story.

Regression discipline: the record-time content-digest hash (parallel over
sections) adds no measurable full-link cost (full relink 17.4 ms vs the
pre-tier-2 17.4 ms measured back-to-back), and the tier-1 relink carries
only the copy-or-rehash digest table (a pure-copy experiment measured
32.0 ms vs 32.2 ms with hashing — noise). The bench file also gained two
correctness fixes: the bytes-written accounting loop indexed input 0 (the
extern-provider dylib) instead of the alternated object — replacing the
dylib would have failed the link if the loop had ever run — and the
import-churn warm-up asserted a full link on a state whose parity the
previous bench's timed loop had already consumed (the assert could never
pass; a reset now precedes the group).

```sh
cargo bench -p pgr-driver --bench incremental
```

## Recorded baseline (M9 GA hardening — the shrink rung + the randomized edit gate)

The GA hardening milestone (architecture doc §10.4 row M9; risk register
P4) adds two pieces to the relink ladder. The **shrink rung**: the
tier-2 trigger's mirror — an unsigned relink (`-no_adhoc`) has no
signature boundary to anchor the `__LINKEDIT` tail, so a
symtab/string-pool shrink moves the chunk-stream end down and the image
shrinks with it; the planner now admits that shape (frozen content
skeleton, clone truncated, moved chunk tail re-emitted) instead of
falling back to the full link. The **randomized edit gate**: the seeded
xorshift64* edit walk ships at two levels — the engine API walk in
`pgr-emit/tests/incremental.rs` (5 edits/sequence: body growth, import
add, retarget, oversized growth, symtab churn, no-op) and the
end-to-end driver walk in `pgr-driver/tests/m9_randomized.rs` (the real
`-incremental -incremental-verify` loop over files, record sidecar and
fallback ladder in the mix, unsigned corpus so symtab churn exercises
the shrink rung's side). `PGR_RANDOMIZED_STEPS` sizes both walks; the
CI subsets (80 engine steps, 24 driver steps) and the roadmap's 10⁴-step
GA profile (2000 sequences × 5 steps) use the same deterministic seed,
so a failure reproduces exactly.

The 10⁴-step GA profile was run on the dev sandbox (release, engine-level
walk): **10 000 steps in 11.4 s, every step byte-identical to the full
fused emit or an honest fallback that re-records, with the
in-place/fallback/symtab-grow/symtab-shrink dimensions all exercised**.
The 10⁴-step *driver*-level profile and the hardware verdicts belong to
the P0 rig (each driver step re-runs the pipeline over an ~8 MiB image;
the sandbox profile is recorded here as evidence, not as the GA bar).

| `pgr-driver/incremental_shrink` (container sandbox, ext4 — no reflink) | time |
|---|---|
| `linkedit_shrink_relink_8mib` (alternating shrink : regrow mix) | **23.4 ms** |

Bytes written (the §7.3 gate, accounting pass): the shrink direction
patches **56 624 bytes of an 8.46 MiB image (4 of 568 tiles, ~0.67%)**
while the image shrinks 9 319 592 → 9 297 200 bytes — the moved
`__LINKEDIT` chunks and the truncated tail, where the fallback full link
would have re-emitted and re-written every byte; the regrow direction
patches 79 016 bytes through the LINKEDIT-overflow trigger. Reading the
23.4 ms mean honestly: the shrink corpus is **unsigned** (no page-hash
table, no CodeDirectory rebuild) and ext4's clone is a full copy, so the
wall clock is not comparable with the signed tier-1/tier-2 groups above —
the bytes-written gate is the sandbox verdict, the APFS wall-clock
verdict is decided on the P0 rig.

```sh
cargo bench -p pgr-driver --bench incremental -- linkedit_shrink
PGR_RANDOMIZED_STEPS=2000 cargo test -p pgr-emit --release --test incremental -- randomized
```

## Recorded baseline (M9 GA — the resolve's record-side wiring, record v5)

The record-side wiring rung (architecture doc §7.3 step 3) ships the
tier-2c decision core's delivery path: the link record grows the
**resolution snapshot section (v5)** — the candidate stream plus the
winner matrix keyed by digest-vouched `(file, symbol)` positions — and
the relink's Pass 2 plans through the recorded decisions
(`pgr_core::resolve_reuse`) instead of re-deciding every external,
refusing to the full resolve whenever the reuse shape (file list, dylib
export surface) moves. The relink's refreshed record re-captures the
fresh Pass-2 state, so the chain stays self-describing across cycles.

Two bench groups land in `pgr-core/benches/resolve`:

| (2-core KVM sandbox, criterion median, 10 samples) | time |
|---|---|
| `resolve_pass2/full_install` — 64 files × 49 externals | **347.7 µs** |
| `resolve_pass2/reused_install` — same corpus, one edited file | **282.8 µs** (−19%) |
| `resolve_pipeline/full_resolve` — full Passes 1b–3, 64 files | **2.94 ms** |
| `resolve_pipeline/reused_resolve` — same relink through the v5 seed | **2.99 ms** (wash) |

Reading the pair honestly: the resolver-level win matches the tier-2c
gate (~19% of Pass 2 at 64 files; the decision core breaks even past
~32 inputs and stays ~13% slower at 16), but Pass 2 is a small slice of
Passes 1b–3 on this corpus, so the *pipeline-level* effect is a wash
here — the same shape the M8 warm-relink bench recorded. The reuse win
scales with symbol count (the copy is O(reused winners), the replay
O(seeds)) while parse/layout stay put, so the payoff arrives where the
roadmap aims it: input-heavy relinks on the P0 rig, stacked on the POI
cache and the resident session. The record side's own cost (the v5
capture + encode) rides the recording link's budget and is bounded by
the parse walk it mirrors.

```sh
cargo bench -p pgr-core --bench resolve
```

## Recorded baseline (M10 rung 1 — the `-r` relocatable object emit)

The relocatable rung ships `pgr_emit::build_object_image`: Passes 1–2
stop short of the segment layout and the emit assembles the `MH_OBJECT`
the pipeline itself consumes as an input — sections merged at their
declared alignments, the symbol table grouped (locals, winner-backed
globals, open undefineds) with its `LC_DYSYMTAB` subranges, and every
relocation entry preserved and re-pointed at the output symbol table
(`ADDEND`/`SUBTRACTOR` leaders re-emitted in decode order, site bytes
verbatim). The corpus is the emit bench's own shape (16 objects × 512
symbols × 32 KiB `__text`, branch + pointer relocs cross-referencing
neighbors), so the two rungs' numbers read side by side:

| (2-core KVM sandbox, criterion median, 20 samples) | time | throughput |
|---|---|---|
| `pgr-emit/object/build_object_image/16x512sym-32kib` | **6.57 ms** | ~1.6 GiB/s input |
| `pgr-emit/emit/fused_tile_pass4` (same corpus) | 1.50 ms | 631 MiB/s |
| `pgr-emit/emit/reference_pass4` (same corpus) | 2.14 ms | 442 MiB/s |

Reading the ratio honestly: the object emit costs ~4× the fused image
pass on the same bytes. It earns its shape, not a speed crown — the
fused pass tiles `par_chunks_mut` across the pool and only *applies*
pre-resolved patches, while the object emit rebuilds the symbol table
(winner walk + strtab freeze), re-encodes every relocation entry against
the output symtab and runs the section merge deterministically
single-threaded (objects have no 16 KiB tile regime to parallelize
across; the §4.3 determinism walk is the point). The rung's win is the
output *class*: an input the next link consumes, skipping Pass 3, the
fixup packer, the signature rebuild and the image write entirely. The
two-step gate (link `-r`, then link the object) is byte-identical across
double runs; per-file reloc-table costs scale with the entry count the
input carries, not the image size.

```sh
cargo bench -p pgr-emit --bench object
```

## Recorded baseline (M10 rung 2 — the platform plumbing rung)

The platform rung ships the five-platform `-platform_version` surface
with a per-platform chained-fixups floor (`pgr_core::layout::
chained_fixups_min_minos`: macOS 12.0, iOS 15.0, tvOS 15.0, watchOS 8.0,
visionOS 1.0). The perf gate is a *wash by design*: the floor only
selects the fixup **encoding** (chained payload at/above the floor, the
classic `LC_DYLD_INFO_ONLY` opcode streams below it), so the same corpus
linked for each platform at its floor must sit inside the noise. The
`pgr-driver/platform_matrix/link/<platform>` bench links one
rebase-slot corpus per platform (20 samples, 2-core KVM sandbox,
criterion median):

| platform | floor | median | throughput |
|---|---|---|---|
| `macos` 12.0.0 | chained | **84.6 µs** | 184.8 KiB/s |
| `ios` 15.0.0 | chained | 84.1 µs | 185.8 KiB/s |
| `tvos` 15.0.0 | chained | 83.0 µs | 188.3 KiB/s |
| `watchos` 8.0.0 | chained | 82.5 µs | 189.4 KiB/s |
| `visionos` 1.0.0 | chained | 84.4 µs | 185.1 KiB/s |

The five medians span ~2.5% — the platform word is a config field the
pipeline already carried (`LinkConfig::platform` existed since M1; the
rung wires the driver flag, the floor table and the verifier gate around
it), and the encoding decision is one integer comparison in Pass 3. No
hardware gate changes: the arm64 targets keep their M4/M8/M9 profiles,
and the floor table's fallback is byte-tested per platform
(`m10_platform::*`).

```sh
cargo bench -p pgr-driver --bench platform
```

## Recorded baseline (M10 rung 3 — the encoding seam)

Rung 3 makes the fixup-encoding decision a *consumer seam* — slice 1
named it in the library (`pgr_core::platform::FixupEncoding::for_target`),
slice 2 crosses the surface (`pgr --print-fixup-encoding` /
`pgr_driver::fixup_encoding_report`, the verifier's `fixups_floor`
gate, the canonical table beside the `PLATFORM_*` constants). Two
bench pins ride along:

- `pgr-core/platform_floor/for_target/<platform>` (slice 1): the
  consumer seam's own decision cost — a floor compare plus its tracing
  event, benched across the five linked platforms at a fixed deployment
  word. Cheap by construction; the bench exists so rotation catches a
  shape regression on a seam every before-the-link consumer pays.
- `pgr-verify/verify_platform_floor/verify/<below_floor|at_floor>`
  (slice 2, the crate's first bench): the strict verify pass over two
  chained-fixup executables *born* at their build versions through the
  builder's platform knob — one below its platform's floor (the gate
  fires), one at the floor (clean).

**No numbers are recorded for either bench yet** (the rung-3 benches
landed with this milestone; the next gate run fills this section the
way the rung-2 table above was filled — criterion medians on the
2-core KVM dev sandbox). The honest expectation mirrors rung 2: the
gate itself is one integer comparison, so the two verify shapes should
sit inside each other's noise, and any divergence is the finding.

```sh
cargo bench -p pgr-core --bench platform
cargo bench -p pgr-verify --bench platform
```

## Recorded baseline (M10 rung 4, slice 1 — the arm64e read side)

Rung 4 opens the arm64e word family on the read side: the builder's
pointer-format knob emits `DYLD_CHAINED_PTR_ARM64E` chains and the
verifier walks them under the same closure contract (8-byte strides,
VM-address unauth rebase targets, 32-bit auth runtime offsets). The
bench pin (`pgr-verify/verify_arm64e/verify/<arm64e_auth|offset64_control>`)
holds the strict pass on an auth-chained executable next to an honest
same-shape 64_OFFSET control, so rotation catches a regression in
either family and the two stay comparable by construction.

**No numbers are recorded yet** (the bench lands with this slice; the
next gate run fills this section the way the rung-3 section above was
filled — criterion medians on the 2-core KVM dev sandbox). The honest
expectation: the arm64e shape sits inside the control's noise band —
the walk does the same work per slot with a wider stride — and any
divergence is the finding.

```sh
cargo bench -p pgr-verify --bench arm64e
```

## Recorded baseline (M10 rung 4, slice 2 — the arm64e producer)

Slice 2 ships the write side: Pass 3 plans either word family
(`pgr_core::fixups::plan_fixups_with_format`), and the planner bench
(`pgr-core/plan_fixups_word_family/<offset64|arm64e>/<1k|10k|100k>`) holds
the same mixed rebase/bind slot corpus through both encoders — the shape
parity the producer's contract wants visible (the family changes the
encoding, never the fixups, so the two curves should track).

**No numbers are recorded yet** (the bench lands with this slice; the
next gate run fills this section like the slice-1 section above). The
honest expectation: arm64e sits inside the 64_OFFSET noise band — the
per-slot work is the same packer with a wider stride and one extra
encoder branch — and any divergence is the finding.

```sh
cargo bench -p pgr-core --bench arm64e
```

## Recorded baseline (M10 rung 4, slice 3 — the authenticated producer)

Slice 3 closes the family's named target: the same planner takes an
authentication policy (`pgr_core::fixups::plan_fixups_with_auth`) and
the bench grows the matching variant
(`pgr-core/plan_fixups_word_family/arm64e_auth/<1k|10k|100k>`) — the
same mixed rebase/bind corpus as the slice-2 rows with every slot
signed, so the auth curve reads directly against both family curves.
The auth rebase swaps the target shape (32-bit runtime offset instead
of the VM address) and the auth bind moves its whole addend into the
import entry, so the table build runs its split too.

**No numbers are recorded yet** (the variant lands with this slice; the
next gate run fills this section like the slice-2 section above). The
honest expectation: `arm64e_auth` sits inside the `arm64e` noise band —
the packer, the payload and the mirror are the same work, one encoder
branch per word — and any divergence is the finding.

```sh
cargo bench -p pgr-core --bench arm64e
```

## Recorded baseline (M10 rung 4, slice 4 — the pair gate walks the family)

Slice 4 makes the verifier's M3 pair gate family-blind and the bench
grows the matching group (`pgr-verify/verify_arm64e/pair_replay/
<arm64e_auth|offset64_control>`) — the M3 two-level bind replay over an
arm64e executable + dylib pair (one authenticated `__got` bind) and a
64_OFFSET control pair born through the same builder knobs, so the
family-blind walk keeps an honest same-shape baseline next to it.

**No numbers are recorded yet** (the group lands with this slice; the
next gate run fills this section like the slice-1 section above). The
honest expectation: `pair_replay/arm64e_auth` sits inside the
`offset64_control` noise band — the replay is the same chain walk with
a different word reader and a doubled stride unit, a handful of slots
per pair — and any divergence is the finding.

```sh
cargo bench -p pgr-verify --bench arm64e
```

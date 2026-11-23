# Peregrine Benchmarks — Recorded Baselines

**Status: M0–M71 surfaces recorded on the dev sandbox** (M47–M52 as shape-parity gates — initial runs noted inline). These numbers exist to (a) prove the
harness works end-to-end from day one and (b) give each pass a regression anchor.

> [!WARNING]
> **Nothing here is a product claim.** Every figure is a 2-core KVM dev-sandbox baseline, not an
> Apple Silicon result. The perf doc's Phase P0 replaces them with measured hardware baselines;
> the G1/G2/G3 gates and every `ld-prime`/`ld64.lld` comparison stay **open until the rig exists**.
> Correctness is never traded for speed: every benchmark link is also run through `pgr-verify`,
> and the byte-identity gates fail the build on divergence.

<p>
  <a href="#results-at-a-glance">Results</a> • <a href="#gate-scoreboard">Gates</a> • <a href="#conditions--harness">Setup</a> • <a href="#pipeline-baselines">Pipeline</a> • <a href="#the-edit-loop--stages-abc">Edit loop</a> • <a href="#consumer-surfaces-m11m14">Surfaces</a> • <a href="#knob-parity-m10m46">Parity</a> • <a href="#pending-measurements">Pending</a> • <a href="#findings--corrections">Findings</a>
</p>

---

## Results at a glance

**Wins (sandbox-recorded):**

| Lever                             | Result                                                                                   | Gate it answers                                                         |
| --------------------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| S7 lazy archive pull              | **12.2×** vs `-all_load` (4.02 vs 49.06 ms)                                              | "adopt lazy if ≥ 20 % faster" — met with an order of magnitude to spare |
| D12 `-dead_strip`                 | **1.9× faster** than unstripped (134 vs 255 ms)                                          | "adds ≤ 30 %" — met with _negative_ overhead                            |
| M4 fused tile emit (Pass 4)       | **1.37×** (1.59 vs 2.18 ms), one pass over each byte                                     | byte-identity vs the preserved reference emit                           |
| M3 export trie, 10⁵ exports       | **363 → 31.5 ms** (8–11× across sizes)                                                   | "< 10 ms or parallelized" — rig-bound, ≈ 8–12 ms extrapolated           |
| M6 ICF `-icf=safe`                | **+12.0 %** wall, ~192 KiB duplicate text removed                                        | "≤ 25 % added wall"                                                     |
| M6 frozen `.tbd`                  | **19.9 µs** (1.8× vs text parse)                                                         | "< 1 ms startup" — both paths far below                                 |
| M9 incremental, one-function edit | **1.2 % of the image written** (105 536 B of 8.53 MiB; 2 of 521 tiles)                   | "bytes written ∝ change size" (~80× fewer bytes)                        |
| M9 segment relayout               | **~13 %** written per +64 KiB growth step                                                | the ladder's middle rung patches, not falls back                        |
| M9 shrink rung                    | **0.67 %** written (4 of 568 tiles)                                                      | unsigned `__LINKEDIT` shrink patches through                            |
| Wire v5 tile streams              | changed tiles only (~0.2–1 % of the image); untouched relink ships **0 bytes**           | the last full-image wire crossing, gone                                 |
| Randomized edit gate              | **10 000 steps in 11.4 s**, every step byte-identical or an honest re-recording fallback | the 10⁴ GA profile (engine level)                                       |
| M9 resolve reuse                  | **−19 %** of Pass 2 at 64 files × 49 externals                                           | break-even past ~32 inputs                                              |

**Honest washes & prices (recorded as-is, each sandbox-bound):**

| Shape                          | Recorded                                    | Why the wall clock doesn't move _here_                                                   |
| ------------------------------ | ------------------------------------------- | ---------------------------------------------------------------------------------------- |
| M6 POI cache, warm             | −2.8 %                                      | corpus is Pass 2/3-bound; the cache removes Pass 1 exactly                               |
| M8 resident warm relink        | wash-to-slight-loss (260 vs 224 ms)         | same physics + manifest/wire overhead; POI decode ≈ fresh parse on this box              |
| M9 tier-1 wall time            | parity-to-slight-loss                       | **ext4 has no reflink** — the clone degrades to a full copy (S8 is the APFS measurement) |
| Wire v5 on loopback            | wash (529.6 ms, inside the 502–535 ms band) | pipeline-bound, not socket-bound; the win is bytes, paid back on remote-hosted `pgrd`    |
| Audited fusion                 | **+19 %** per audited relink                | the price of never shipping an unaudited patch; only with `-incremental-verify`          |
| Fusion ladder vs warm resident | ~2×                                         | the ladder re-runs Passes 2–3 (this corpus's dominant share) + plan + patch + re-sign    |
| M9 resolve, pipeline level     | wash (2.99 vs 2.94 ms)                      | Pass 2 is a small slice of Passes 1b–3 on this corpus                                    |

## Gate scoreboard

| Gate (perf doc)           | Target                                       | Sandbox evidence                                      | Status                            |
| ------------------------- | -------------------------------------------- | ----------------------------------------------------- | --------------------------------- |
| S7 archive strategy       | lazy ≥ 20 % faster                           | 12.2×                                                 | ✅ closed                         |
| D12 dead-strip cost       | ≤ +30 %                                      | −47 % (1.9× faster)                                   | ✅ closed                         |
| M4 fused byte-identity    | fused == reference                           | tests + bench-setup asserts, ten corpus shapes        | ✅ closed                         |
| M3 trie, 10⁵ exports      | < 10 ms (or parallelized)                    | 31.5 → 27.9 ms; ≈ 8–12 ms extrapolated to P-cores     | 🔶 rig-bound                      |
| M6 ICF cost               | ≤ +25 %                                      | +12.0 % (M7 re-measure: +14.8 %)                      | ✅ closed                         |
| M6 `.tbd` startup         | < 1 ms                                       | 19.9 µs frozen / 35.8 µs text                         | ✅ closed                         |
| M7 fuzzers clean          | 30 CPU-days                                  | 61 s sessions clean after fixes (ledger below)        | 🔶 rig-bound                      |
| M9 bytes ∝ change         | patch ≪ image                                | 1.2 % / ~13 % / 0.67 % across the ladder              | ✅ closed (sandbox)               |
| M9 randomized edits       | 10⁴ sequences                                | engine-level 10⁴ steps green in 11.4 s                | 🔶 driver-level + hardware on rig |
| M2/M4 parallel efficiency | ≥ 70 % @ 8 P-cores, serial ≤ 15 %            | 2 threads cannot exhibit it                           | 🔶 rig-bound                      |
| G1/G2 clean link          | ≥ 5×/8× vs `ld64.lld`, ≥ 1.5×/3× vs ld-prime | no hardware baselines exist yet                       | 🔶 rig-bound                      |
| M6/M8 relink              | ≥ 2×/5× vs ld-prime                          | washes recorded honestly above                        | 🔶 rig-bound                      |
| G3 incremental            | **< 100 ms @ 1 GiB**, ≥ 10× vs ld-prime      | bytes-written half proven; APFS clone unmeasured (S8) | 🔶 rig-bound                      |

## Conditions & harness

- **Machine**: 2-core Intel Xeon (KVM guest), warm cache; corpora are L2/L3-resident. Inter-run
  spread on this box is up to ±20 % — deltas below that are noise, and the tables say so.
- **Filesystem**: ext4, **no reflink** — every clone-and-patch wall time carries that caveat.
- **Framework**: Criterion (macro-free entry points; the workspace `missing_docs` gate stays intact).
  Medians; default sampling unless a row states 10/20 samples.
- **Corpora**: deterministic arm64 images/objects from `pgr-fixtures` — no I/O, no clocks,
  identical bytes every run. The link corpora carry real relocations (BRANCH26, ADDEND+PAGE21/
  PAGEOFF12, UNSIGNED pointer slots), cross-object resolution and commons, so Passes 2–3 do honest work.
- **Units**: `pgr_format::summarize` (structural parse: headers, load commands, sections, full
  symtab, every reloc, complete chain walk) and `pgr_driver::link_to_bytes` (full Pass 0–5).
- **Caveat on parser rates**: `summarize` walks _metadata tables_, not section payload — these are
  metadata-walk rates, not DRAM streaming. The byte-touching parse starts well below them.

<details><summary><b>Run the benches (every recorded command)</b></summary>

```sh
# format
cargo bench -p pgr-format                                  # summarize
cargo bench -p pgr-format --bench parse -- parse_archive
cargo bench -p pgr-format --bench universal
# driver: pipeline + surfaces
cargo bench -p pgr-driver                                  # link, link_dylib, link_outputs, …
cargo bench -p pgr-driver --bench link -- "link_archive|link_dead_strip|link_cstring"
cargo bench -p pgr-driver --bench resident
cargo bench -p pgr-driver --bench incremental
cargo bench -p pgr-driver --bench incremental -- linkedit_shrink
cargo bench -p pgr-driver --bench platform
# emit
cargo bench -p pgr-emit --bench emit
cargo bench -p pgr-emit --bench object
cargo bench -p pgr-emit --bench propagate
cargo bench -p pgr-emit --bench record_summary
# core: trie + the knob-parity family
cargo bench -p pgr-core --bench trie
cargo bench -p pgr-core --bench order
cargo bench -p pgr-core --bench map
cargo bench -p pgr-core --bench resolve
cargo bench -p pgr-core --bench platform
cargo bench -p pgr-core --bench arm64e
cargo bench -p pgr-core --bench filter
cargo bench -p pgr-core --bench dylibs
cargo bench -p pgr-core --bench pagezero
cargo bench -p pgr-core --bench init_offsets
cargo bench -p pgr-core --bench segprot
cargo bench -p pgr-core --bench stack_size
cargo bench -p pgr-core --bench image_base
cargo bench -p pgr-core --bench umbrella
cargo bench -p pgr-core --bench sub_client
cargo bench -p pgr-core --bench dyld_env
cargo bench -p pgr-core --bench alias
cargo bench -p pgr-core --bench bundle_loader
cargo bench -p pgr-core --bench dylinker
cargo bench -p pgr-core --bench pie
cargo bench -p pgr-core --bench sect_align
cargo bench -p pgr-core --bench header_pad
cargo bench -p pgr-core --bench data_in_code
cargo bench -p pgr-core --bench func_starts
cargo bench -p pgr-core --bench uuid
cargo bench -p pgr-core --bench keep_pext
cargo bench -p pgr-core --bench unwind
cargo bench -p pgr-core --bench unwind_compressed
cargo bench -p pgr-core --bench no_compact_unwind
cargo bench -p pgr-core --bench tlv
cargo bench -p pgr-core --bench headerpad_max
cargo bench -p pgr-core --bench make_undefined
cargo bench -p pgr-core --bench exported_symbols
cargo bench -p pgr-core --bench no_deduplicate
cargo bench -p pgr-core --bench dead_strip_dylibs
cargo bench -p pgr-core --bench objc
cargo bench -p pgr-core --bench upward
cargo bench -p pgr-core --bench export_dynamic
cargo bench -p pgr-core --bench branch_islands
cargo bench -p pgr-core --bench dylib_init
cargo bench -p pgr-core --bench dylib_term
cargo bench -p pgr-core --bench named_uuid
cargo bench -p pgr-core --bench objc_pre2
cargo bench -p pgr-core --bench no_weak_imports
cargo bench -p pgr-core --bench stack_exec
cargo bench -p pgr-core --bench rename_sections
cargo bench -p pgr-core --bench dead_strip_inits
cargo bench -p pgr-core --bench observer
cargo bench -p pgr-core --bench time_report
cargo bench -p pgr-core --bench trace
cargo bench -p pgr-core --bench provenance
cargo bench -p pgr-core --bench why_load
cargo bench -p pgr-core --bench why_live
cargo bench -p pgr-core --bench dep_info
cargo bench -p pgr-driver --bench final_output
cargo bench -p pgr-driver --bench verify_gate
# daemon: the served tails' codec price
cargo bench -p pgr-daemon --bench wire_time
cargo bench -p pgr-daemon --bench wire_trace
cargo bench -p pgr-daemon --bench wire_verify
cargo bench -p pgr-daemon --bench wire_provenance
cargo bench -p pgr-daemon --bench wire_map
cargo bench -p pgr-daemon --bench wire_order
cargo bench -p pgr-daemon --bench wire_liveness
# verify
cargo bench -p pgr-verify --bench platform
cargo bench -p pgr-verify --bench arm64e
cargo bench -p pgr-verify --bench checks
cargo bench -p pgr-verify --bench baseline
cargo bench -p pgr-verify --bench sarif
cargo bench -p pgr-verify --bench universal
cargo bench -p pgr-verify --bench universal_checks
cargo bench -p pgr-verify --bench init_offsets
# the randomized edit gate (CI subsets: 80 engine / 24 driver steps)
PGR_RANDOMIZED_STEPS=2000 cargo test -p pgr-emit --release --test incremental -- randomized
```

</details>

## Pipeline baselines

### Parser (M0, v0.1.0)

| Bench                        | Input                                               | Median   | Throughput      |
| ---------------------------- | --------------------------------------------------- | -------- | --------------- |
| `summarize/single_image`     | ~48 KiB exec (512 syms, 1 Ki relocs, ~85 GOT slots) | ~0.96 µs | **~53 GiB/s**   |
| `summarize/corpus_24_images` | ~7.6 MiB (24 execs, 4 096 syms + 8 192 relocs each) | ~181 µs  | **~25.7 GiB/s** |

### Static links (M1)

| Bench                   | Input                                                 | Median                          | Notes                                 |
| ----------------------- | ----------------------------------------------------- | ------------------------------- | ------------------------------------- |
| `link/small_4_objects`  | 4 objects, 256 defs + 256 refs each, 8 KiB text       | **~2.3 ms** (M1) / ~3.4 ms (M2) | full Pass 0–5, single-threaded at M1  |
| `link/large_32_objects` | 32 objects, 2 048 defs + 2 048 refs each, 32 KiB text | **~170 ms** (M1) / ~289 ms (M2) | resolution graph spans all 32 objects |

The M2 delta is the dynamic-link surface on the same corpora: `__mh_execute_header` + full trie,
undefined symtab entries, the indirect symbol table, two extra `__got` bucket passes — all of it
tile-local by M4. These are the **starting line** for the speed pass, not a target.

### Dynamic links (M2, `.tbd` bind path)

| Bench                               | Input                                           | Median      | Throughput                           |
| ----------------------------------- | ----------------------------------------------- | ----------- | ------------------------------------ |
| `link_dylib/small_4_objects_dylib`  | 4 callers × 256 stub relocs + 256-export `.tbd` | **~2.0 ms** | ~88 MiB/s                            |
| `link_dylib/large_32_objects_dylib` | 32 callers × 2 048 dylib calls + `.tbd`         | **~42 ms**  | ~88 MiB/s; 65 536 chained bind slots |

The bind path was shaped for M4 from the start: import ordinals in first-use order over
address-sorted slots (spike S6, `ld64.lld`-verified), so chain encoding never mutates the table
and per-page fixup lists bucket without re-sorting. The parallel-efficiency gate is rig-bound.

### Export trie (M3)

`pgr_core::trie::build` over 10⁵ names (`_pgr_fn_*` + an ObjC-style shared-prefix block — the
worst case for tries). The M2 builder stays in-tree verbatim (`legacy_m2`) so the rewrite's
claim is measured, not argued:

| Exports | `legacy_m2` | `m3_partition` |
| ------- | ----------- | -------------- |
| 1 000   | ~2.5 ms     | ~0.30 ms       |
| 10 000  | ~28.8 ms    | ~3.5 ms        |
| 100 000 | **~363 ms** | **~31.5 ms**   |

Range-partition trie over the sorted list: multikey quicksort skips shared prefixes, every edge
created once in compressed form, offset fixpoint from a 4-byte upper bound. **8–11× faster**;
the < 10 ms gate closes on the P0 rig (≈ 8–12 ms extrapolated) or via the gate's
"or parallelized" clause.

### Fused tile emit (M4)

Pass 4 rewritten as parallel 16 KiB tiles: copy coalesced runs → apply relocs → encode chains →
place `__LINKEDIT` → hash 4 KiB pages, **one pass over each byte** where the reference made five.
The pre-fusion body stays in-tree (`build_image`); fused == reference is asserted at bench setup
and in the suite.

**Pass 4 isolated** (16 objects × 512 syms × 32 KiB, ~0.94 MiB signed output):

| Bench                                                                                    | Median      | Throughput                                   |
| ---------------------------------------------------------------------------------------- | ----------- | -------------------------------------------- |
| `emit/reference_pass4` (copy+patch, chains, LINKEDIT, **two** full-image SHA-256 passes) | 2.18 ms     | 441 MiB/s                                    |
| `emit/fused_tile_pass4` (only page 0 re-hashes after the UUID lands)                     | **1.59 ms** | 605 MiB/s                                    |
| **Δ**                                                                                    | **1.37×**   | on 2 threads; scales with P-cores on the rig |

**Full pipeline, fused vs reference:**

| Bench                               | Fused    | Reference | Δ         |
| ----------------------------------- | -------- | --------- | --------- |
| `link/small_4_objects`              | 2.34 ms  | 2.45 ms   | 1.05×     |
| `link/large_32_objects`             | 172.1 ms | 174.7 ms  | 1.01×     |
| `link_dylib/small_4_objects_dylib`  | 1.98 ms  | 2.19 ms   | 1.10×     |
| `link_dylib/large_32_objects_dylib` | 33.8 ms  | 37.3 ms   | **1.11×** |
| `link_outputs/dylib_8_objects`      | 18.1 ms  | 18.1 ms   | ~1×       |
| `link_outputs/bundle_8_objects`     | 17.9 ms  | 18.1 ms   | ~1×       |

How to read M4:

1. **Pass 4 is the unit of work** and shows the full win. The resolution-heavy static corpus
   (4 096 external refs/object) is Pass 2/3-bound — deliberately unchanged at M4 — so it moves
   1 %; the bind-path corpora lean on Pass 4 and gain 10–11 %.
2. **Parallelism is observable but hardware-bound**: `PGR_JOBS=1` measures 179.0 ms vs 172.1 ms
   at 2 threads. G1's 16-thread scaling needs the rig.
3. **S1 writer pool** (4 writers, 8 MiB blocks, `set_len` preallocation, file-order `pwrite`)
   replaced the single writer; byte-exactness gated across block boundaries. Sandbox writes land
   in the page cache, so the writer sweep runs on real storage on the rig.
4. **D9/D10** landed as measured defaults: shared pool (`PGR_JOBS`, else `available_parallelism`
   on Linux; the macOS P-core default joins with S4) + parallel pre-fault of the zero-page-backed
   output buffer.

### Output kinds (M3 dylibs/bundles · M10 `-r` objects)

| Bench                                               | Input                                                                   | Median                         |
| --------------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------ |
| `link_outputs/dylib_8_objects`                      | 8 objects × 1 024 defs, all exported (0 base, `LC_ID_DYLIB`, full trie) | ~19.1 ms                       |
| `link_outputs/bundle_8_objects`                     | same corpus as `MH_BUNDLE`                                              | ~18.5 ms                       |
| `object/build_object_image/16x512sym-32kib` (M10)   | the emit bench's own corpus as `MH_OBJECT`                              | **6.57 ms** (~1.6 GiB/s input) |
| `emit/fused_tile_pass4` (same corpus, that session) | —                                                                       | 1.50 ms                        |
| `emit/reference_pass4` (same corpus, that session)  | —                                                                       | 2.14 ms                        |

The object emit costs ~4× the fused image pass **and earns its shape, not a speed crown**: it
rebuilds the symtab (winner walk + strtab freeze), re-encodes every relocation against the output
symtab, and merges sections deterministically single-threaded — objects have no 16 KiB tile
regime. The win is the output _class_: the next link consumes it, skipping Pass 3, the fixup
packer, the signature and the image write. Two-step self-consumption is byte-identical across
double runs.

## Size & ecosystem (M5–M6)

### Archive parse (`parse_archive`)

| Bench                              | Input                                               | Median      | Throughput             |
| ---------------------------------- | --------------------------------------------------- | ----------- | ---------------------- |
| `parse_archive/archive_64_members` | 64 members + name-sorted ranlib table, **~118 KiB** | **~9.9 µs** | ~11.9 GiB/s (M7: 12.2) |

_The original M5 row said "~1.4 MiB / ~118 µs" — a unit slip, corrected in the M7 re-measure; see
[Findings](#findings--corrections)._ One structural walk yields the member table and the
`(symbol, member)` index the pull fixpoint consumes.

### Archive liveness (the S7 decision)

64 members × 256 syms × 32 KiB (~2 MiB); `main.o` → member 1 → predecessor chain, so the pull
fixpoint loads a transitive chain and the rest is never needed.

| Bench                              | Median                   |
| ---------------------------------- | ------------------------ |
| `link_archive/archive_64_lazy`     | **4.02 ms**              |
| `link_archive/archive_64_all_load` | 49.06 ms                 |
| **Δ**                              | **12.2×** — lazy adopted |

### Dead-strip (the D12 gate)

32 objects × 2 048 syms × 32 KiB, `MH_SUBSECTIONS_VIA_SYMBOLS`, ~50 % never-referenced weight.

| Bench                                  | Median                                                          |
| -------------------------------------- | --------------------------------------------------------------- |
| `link_dead_strip/large_32_objects_off` | 255 ms                                                          |
| `link_dead_strip/large_32_objects_on`  | **134 ms**                                                      |
| **Δ**                                  | **1.9× faster** — half the atoms never placed, copied or hashed |

> **Bench-driven optimization, recorded because it shaped the code**: the first working
> mark-sweep was **3.5× slower** than the unstripped link (911 ms) — O(atoms) liveness scans and
> per-atom relocation re-scans. Three fixes closed it: O(log atoms) binary searches over the
> shared atom-start table, one-pass-per-section edge bucketing, borrowed slices instead of
> per-call clones. The result is byte-identical to the slow first draft — the live set is a pure
> function of the inputs.

### `__cstring` merging (D4) & ICF (M6)

| Bench                             | Input                                                        | Median                 | Notes                                              |
| --------------------------------- | ------------------------------------------------------------ | ---------------------- | -------------------------------------------------- |
| `link_cstring/cstring_16_objects` | 16 × 512 strings, shared pool duplicated per object          | **1.69 ms**            | pool placed once; hash-map dedup over string atoms |
| `link_icf/large_32x512_off`       | 32 × 512 identical 12-byte functions (16 384 foldable atoms) | 17.29 ms               | fold-off                                           |
| `link_icf/large_32x512_safe`      | same, `-icf=safe`                                            | **19.37 ms (+12.0 %)** | 16 383 folded, ~192 KiB removed; ≤ 25 % gate holds |

**Not benched, with reasons**: veneer insertion (triggering corpus > 128 MiB text ≈ 4 s of SHA-256
per iteration — correctness-gated instead, steady-state cost covered by the re-measured gates);
legacy `LC_DYLD_INFO_ONLY` streams (O(slots) ULEB writes, nothing measurable at M6 scale — the
verifier's walk is gated for correctness, not speed).

## The edit loop — Stages A→C

The perf doc's §7 thesis: the order-of-magnitude wins come from _not doing the work_. Each stage
is independently shippable and byte-identity-gated against the one-shot link.

### Stage A — caches (M6 POI + frozen `.tbd`, M7 v2 + LRU)

Parse-heavy corpus: 16 objects × 4 096 syms × 4 KiB (~64 K symbols, 128 K relocs).

| Bench                               | Median                              | Notes                                             |
| ----------------------------------- | ----------------------------------- | ------------------------------------------------- |
| `link_cache/medium_16_objects_cold` | 177.8 ms                            | parse + store                                     |
| `link_cache/medium_16_objects_warm` | **172.8 ms (−2.8 %)**               | Pass 1 replaced by POI decode                     |
| `tbd/libbench_text_parse`           | 35.8 µs                             | M2 YAML path                                      |
| `tbd/libbench_frozen_load`          | **19.9 µs**                         | frozen export set (1.8×; ≪ 1 ms gate)             |
| `cache_evict/unbounded`             | 9.12 ms                             | M6 warm path (4 × 1 024 syms)                     |
| `cache_evict/bounded_64kib`         | 9.73 ms (**+6.7 % on cold stores**) | every store scans + evicts; warm hits never store |

**Honesty note (§7.1's own framing)**: the POI cache is a Pass 0/1 elimination — where the wall
is resolution/layout-bound, the gain is bounded by Pass 1's share. Stages B/C address the rest.
The v2 format's two-revision key, marker check and recency touch cost nothing measurable
(ledger below).

### Stage B — resident session (M8)

64 objects × 2 048 syms × 2 KiB (parse-heavy). Resident iterations run the exact user path
(`pgr -resident` → prepare → hash → negotiate → POI decode → link → fused emit → wire);
**64/64 POI hits** from iteration two, emit buffer reused.

| Bench                               | Median       | Throughput |
| ----------------------------------- | ------------ | ---------- |
| `resident/one_shot_64_objects`      | 224.3 ms     | 37.8 MiB/s |
| `resident/resident_warm_64_objects` | **260.3 ms** | 32.6 MiB/s |

Phase breakdown (release probe): client Pass 0 = 4.2 ms · manifest build ≈ 8 ms (parallel
SHA-256) · session link ≈ 248 ms. **Verdict: wash-to-slight-loss, recorded as-is** — the corpus
is Pass 2/3-bound and POI decode ≈ fresh parse here, so skipped Pass 1 doesn't cover manifest +
wire. What it proves functionally: the skip is real (hit counters), output byte-identical every
iteration, buffer survives across links. The ≥ 5× gate and the page-fault/wire savings are
rig-bound.

#### The arm64e family on the resident lane (M82)

The same parse-heavy corpus with `-fixup_chains_format arm64e` named
(`cargo bench -p pgr-driver --bench resident`): the family byte has ridden
the wire config since v6, so the family costs nothing at the wire — the
group pins the plan-side price beside the lane's own shape (the M8 verdict
above governs the warm-vs-cold wash here too).

| Bench                                            | Median (dev sandbox) |
| ------------------------------------------------ | -------------------- |
| `resident-arm64e/one_shot_arm64e_64_objects`     | 226.8 ms             |
| `resident-arm64e/resident_warm_arm64e_64_objects` | **279.9 ms**         |

Initial dev-sandbox run (this host only; the recording-pass convention above governs the
comparable table): one-shot 226.8 ms beside warm 279.9 ms — the same wash-to-slight-loss shape
the Offset64 pair records, inside its span at this profile. The bench pins the shape (the
family's plan cost rides the group's warm/cold pair), the hardware gates own the comparable
numbers.

#### The relocatable shape on the resident lane (M83)

The same parse-heavy corpus under `-r`
(`cargo bench -p pgr-driver --bench resident`): the session's walk runs
the object path over the raw blobs (Passes 1–2, no POI interning — the
object path re-parses) and `build_object_image` assembles the `MH_OBJECT`
the reply carries. The group prices the object shape's session cost
beside the one-shot's; the manifest/wire share rides with it, the same
shape the M8 groups record for images.

| Bench                                          | Median (dev sandbox) |
| ---------------------------------------------- | -------------------- |
| `resident-reloc/one_shot_reloc_64_objects`     | 225.6 ms             |
| `resident-reloc/resident_warm_reloc_64_objects` | **166.4 ms**         |

Initial dev-sandbox run (this host only; the recording-pass convention above governs the
comparable table): one-shot 225.6 ms beside warm 166.4 ms — warm under parity (the skipped
blob re-transfer covers the session's manifest/negotiation share at this profile; the object
path re-parses either lane). The bench pins the shape, the hardware gates own the comparable
numbers.

### Stage C — incremental relink (M9, all tiers)

The ladder, with the bytes-written gate as the sandbox verdict (wall times are ext4-bound;
APFS decides them on the rig):

| Tier                            | Trigger                                                                | Bytes patched                                                                        | Sandbox wall                                                |
| ------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------- |
| **1 — engine**                  | same-size edit within the frozen skeleton                              | **105 536 B = 1.2 %** of 8.53 MiB (2/521 tiles; 72.7 KiB is the whole CodeDirectory) | 17.6 ms vs 16.4 full                                        |
| **2b — propagation gate**       | every changed span inside `propagate::predict`'s scope, else fall back | gate cost: 572.9 µs scope walk; 1.1088 ms full planner                               | ~52 % of planner wall                                       |
| **2 — segment relayout**        | slack overflow within bound / `__LINKEDIT` outgrowth                   | **1.2 MiB ≈ 13 %** per +64 KiB step (69–70/573 tiles — exactly the moved suffix)     | 34.2 ms (8 tier-2 : 1 tier-1 mix)                           |
| **GA — shrink rung**            | unsigned symtab/strtab shrink, clone truncated                         | **56 624 B = 0.67 %** (4/568 tiles); regrow 79 016 B                                 | 23.4 ms (unsigned corpus — not comparable to signed groups) |
| **2c + wiring — resolve reuse** | record v5 snapshot, shape-guarded, seed-scoped replay                  | −19 % of Pass 2 at 64 files                                                          | pipeline-level wash (2.99 vs 2.94 ms)                       |

**Tier 1** (32 objects × 256 KiB text, 8.53 MiB image; the edit flips eight words mid-corpus):

| Bench                                 | Median              | Throughput                                         |
| ------------------------------------- | ------------------- | -------------------------------------------------- |
| `incremental/full_relink_8mib`        | 16.4 ms             | 496 MiB/s                                          |
| `incremental/incremental_relink_8mib` | 17.6 ms             | 461 MiB/s                                          |
| `incremental/untouched_relink_8mib`   | **13.3 ms (−19 %)** | 610 MiB/s — plan says untouched, output left alone |

Three physical reasons for the wall-time parity, each sandbox-bound: **(1)** ext4 has no reflink,
so the clone reads+writes all 8.53 MiB (S8 is exactly this measurement on APFS); **(2)** span
digests are SHA-256 over ~8.6 MiB per relink — a faster non-crypto digest is a deliberate
non-knob at tier 1 (no-collision standard); **(3)** the corpus is Pass 2/3-bound and tier 1
re-runs them by design.

**Tier 2** (monotone ladder: eight +64 KiB growth steps then a reset — the anchored skeleton
holds any size already carried, so only _climbing_ growth re-triggers the tier; the recorded
mean is the honest 8:1 mix):

| Bench (that session)                              | Median      |
| ------------------------------------------------- | ----------- |
| `full_relink_8mib`                                | 17.4 ms     |
| `incremental_relink_8mib` (tier 1)                | 32.2 ms     |
| `incremental_add_import_8mib` (anchored ordinals) | 22.4 ms     |
| `segment_relayout_relink_8mib`                    | **34.2 ms** |
| `untouched_relink_8mib`                           | 12.8 ms     |

Record v4's per-section content digests exempt byte-identical moves from the propagation gate;
the digest hash adds no measurable full-link cost (17.4 vs 17.4 back-to-back; copy-vs-rehash
32.0 vs 32.2 ms — noise).

**M84/M85 read faces on the warm ladder** (initial dev-sandbox run, this host only — the
recording-pass convention above governs the comparable table; the queried/record-bearing
medians sit inside the plain relink's noise band, so the honest verdict is a wash: the
answers' index walk and the sidecar's render are invisible beside an 8.5 MiB tier-1 relink):

| Bench (this host)                                | Median      | Throughput  |
| ------------------------------------------------ | ----------- | ----------- |
| `incremental_relink_8mib` (tier 1)               | 36.6 ms     | 222 MiB/s   |
| `incremental_provenance_relink_8mib` (M84)       | 33.3 ms     | 244 MiB/s — wash |
| `incremental_dep_info_relink_8mib` (M85)         | 32.5 ms     | 250 MiB/s — wash |
| `untouched_relink_8mib`                          | 19.4 ms     | —           |

**M86/M87 map faces on the warm ladders** (initial dev-sandbox run, this host only — the
recording-pass convention above governs the comparable table; the map-bearing medians sit
inside the plain lanes' noise band, so the honest verdict is a wash on both tiers: the
document's render and write are invisible beside an 8.5 MiB tier-1 relink, and the served
fusion document's render/encode is invisible beside a 596 ms session ladder. The served
document is byte-identical to the in-process render either way — the parity gates in
`m87_fusion_map.rs` and the session's `map_reference` carry that contract):

| Bench (this host)                                     | Median      | Throughput  |
| ----------------------------------------------------- | ----------- | ----------- |
| `incremental_relink_8mib` (tier 1)                    | 35.5 ms     | 240 MiB/s   |
| `incremental_map_relink_8mib` (M86)                   | 35.3 ms     | 241 MiB/s — wash |
| `untouched_relink_8mib`                               | 18.8 ms     | —           |
| `resident-fusion/fusion_relink_64_objects`            | 596.6 ms    | —           |
| `resident-fusion/fusion_map_relink_64_objects` (M87)  | 583.9 ms    | — wash      |
| `resident-fusion/fusion_provenance_relink_64_objects` (M88) | see note | — expected wash |
| `resident-fusion/fusion_dep_info_relink_64_objects` (M89)   | see note | — expected wash |

**M88/M89 served faces on the fusion ladder** — the query-bearing and record-bearing relink
groups joined `resident-fusion` beside the map group (M87) and the plain relink: the session's
replay walk renders the answers and the client's Pass 0 records the read set, so the honest
expectation is the same wash the M84–M87 faces recorded (a per-relink reverse-index build and
query, a per-relink sidecar render and write, beside a 596 ms session ladder). This host's
medians belong to the perf-rig run (the recording-pass convention above governs the comparable
table; the dev sandbox built the groups but the release-ladder recording outruns its disk —
the compile gate is `cargo test --benches`, green).

**Randomized edit gate**: seeded xorshift64* walk (body growth, import add, retarget, oversized
growth, symtab churn, no-op), engine-level and real `-incremental -incremental-verify` driver
loop. **10 000 engine steps in 11.4 s, every step byte-identical or an honest re-recording
fallback.** CI runs sized subsets (80 engine / 24 driver); the driver-level 10⁴ profile and
hardware verdicts belong to the rig. Same seed everywhere — failures reproduce exactly.

**Resolve reuse** (record v5; 64 files × 49 externals, 10 samples):

| Bench                                            | Median               |
| ------------------------------------------------ | -------------------- |
| `resolve_pass2/full_install`                     | 347.7 µs             |
| `resolve_pass2/reused_install` (one edited file) | **282.8 µs (−19 %)** |
| `resolve_pipeline/full_resolve` (Passes 1b–3)    | 2.94 ms              |
| `resolve_pipeline/reused_resolve`                | 2.99 ms (wash)       |

The win scales with symbol count (copy O(reused winners), replay O(seeds)); break-even past
~32 inputs, ~13 % slower at 16. The payoff arrives where the roadmap aims it: input-heavy
relinks on the rig, stacked on POI + residency.

### Fusion on the wire (v3 → v4 → v5)

The ladder runs _inside_ the resident session. Same 64-object corpus; every timed iteration is
a real edit (one dirty tile + re-sign), served warm and patched in memory:

| Bench                                                     | Median       | What runs                                                       |
| --------------------------------------------------------- | ------------ | --------------------------------------------------------------- |
| `resident/one_shot_64_objects` (that session)             | 235.3 ms     | reference                                                       |
| `resident/resident_warm_64_objects` (that session)        | 272.1 ms     | POI hits 64/64                                                  |
| `resident-fusion/fusion_relink_64_objects` (v3 record)    | 535.0 ms     | ladder: warm pipeline + plan + patch + re-sign + renewed record |
| `resident-fusion/fusion_relink_64_objects` (v5 re-record) | **529.6 ms** | ladder + tile stream; transport asserted                        |
| `resident-fusion-audited/…` (v4, that session)            | 597.4 ms     | ladder **+ audit** (reference emit + strict pass)               |
| `resident-fusion-audited/…` (v5 re-record)                | 610.6 ms     | ladder + tile stream + audit                                    |

**The audit costs +19 %** (94.8 ms) — paid only under `-incremental-verify`; plain cycles
unchanged. The ladder's ~2× over warm resident is the Pass 2/3 physics again, recorded as-is.

**Wire v5 — what crosses per warm relink:**

| Step            | before (v3/v4)                    | after (v5)                                                                                               |
| --------------- | --------------------------------- | -------------------------------------------------------------------------------------------------------- |
| previous output | uploaded per changed output state | **0 bytes** (resident; re-upload only after ceiling eviction)                                            |
| patched reply   | the full image                    | **changed tiles only** — 37.9 KiB of an 87 KiB image (2/6 tiles); ≈16.4 KiB of 8 MiB for a one-tile edit |
| untouched reply | full image, rewritten             | **0 bytes**, nothing rewritten                                                                           |

| `wire-tiles` (20 samples)                               | Median      | Throughput |
| ------------------------------------------------------- | ----------- | ---------- |
| `diff_one_tile_edit_8mib` (daemon: scan + SHA-256)      | 5.64 ms     | 1.39 GiB/s |
| `replay_one_tile_edit_8mib` (client splice + hash gate) | **0.75 ms** | 10.4 GiB/s |
| `diff_untouched_8mib` (pure scan)                       | 5.25 ms     | 1.52 GiB/s |

**Verdict: loopback wall clock is a wash** (529.6 ms inside the 502–535 ms band — the relink is
pipeline-bound; the 5.6 ms scan is ~1 %). The win is the wire and the memory bus, paid back on
the first warm cycle of a machine-hosted `pgrd`. The client hash-verifies its replay before the
atomic write; the daemon still never touches the filesystem.

## Consumer surfaces (M11–M14)

A gate or query must cost far less than the work it summarizes.

**Order file & link map (M11)** — 12 objects × 256 atoms, 3 072 pieces:

| Bench                                         | Median  | Reading                                                                                                                                                                      |
| --------------------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `order_file/layout/no_order`                  | 2.51 ms | 12 whole-section pieces                                                                                                                                                      |
| `order_file/layout/ranked` (1 536 ranked)     | 5.41 ms | pays the **atom split** (3 072 pieces — same cost `-dead_strip` pays) + rank pass + stable sort; shape-parity, not like-for-like. Rank pass is linear (one hash probe/piece) |
| `link_map/build_render/3072` (incl. the link) | 3.03 ms | map's own share ≈ delta vs the 2.51 ms plain link; reporting never touches the hot path                                                                                      |

**Selective verification (M12)** — one at-floor chained fixture:

| Selection   | Median      |     | Selection                                     | Median       |
| ----------- | ----------- | --- | --------------------------------------------- | ------------ |
| `full`      | 20.6 µs     |     | `fixups`                                      | 0.48 µs      |
| `signature` | **20.1 µs** |     | `chain_starts` / `branch_range` / `dyld_info` | 0.34 µs each |
| `structure` | 0.34 µs     |     | `segments`                                    | 0.56 µs      |
| `symbols`   | 0.32 µs     |     | `linkedit`                                    | 0.53 µs      |

The signature family _is_ the pass on this fixture (SHA-256 recompute: 20.1 of 20.6 µs).
`--checks segments,fixups` per relink ≈ 1 µs; the recompute waits for the hand-off gate. Family
domains are test-gated (`single_check_never_reports_foreign_codes`).

**Baseline gate & record inspector (M13):**

| Bench                                 | Median         |     | Bench                       | Median               |
| ------------------------------------- | -------------- | --- | --------------------------- | -------------------- |
| `delta_offset/64` / `delta_code/64`   | 1.94 / 1.56 µs |     | `to_json/512`               | 152.8 µs             |
| `delta_offset/256` / `delta_code/256` | 20.2 / 13.6 µs |     | `parse_json/512`            | 252.6 µs             |
| `delta_offset/512` / `delta_code/512` | 68.4 / 47.0 µs |     | `verify_for_scale`          | 20.6 µs              |
| `record_summary/record_and_encode`    | ~125 µs        |     | `read_record` / `of_render` | **11.1 µs / 1.5 µs** |

The delta is the cheap half (O(prev×next) is deliberate at these counts); JSON walks every
message's bytes; the gate's total is dominated by the verify it gates — the point. Reading a
record costs ~a tenth of making one.

The M96 container group rides the same bench (`container_baseline`, 8-issue slice reports):
`parse/2` **9.5 µs** / `parse/4` **18.5 µs** (the document read — one labeled report line per
declared slice, linear in the slices, each line a full M13 report parse), `between_slices/2`
**275 ns** / `between_slices/4` **510 ns** (the window agreement plus one per-slice delta —
linear in the slices, ~34 ns a slice beside the `one_slice_delta_for_scale` **476 ns** single
8→18-issue pair the same slice shape costs unbundled). The gate is a document read and a
linear walk — never a second verify pass.

**Export-filter matcher (M14)** — 10 240 names, four-entry lists, same scan length per family:

| Bench                      | Median   | Per name       |
| -------------------------- | -------- | -------------- |
| `match_10k_names/exact`    | 54.9 µs  | ≈5.4 ns        |
| `match_10k_names/one_star` | 171.2 µs | ≈16.7 ns (~3×) |
| `match_10k_names/two_star` | 430.2 µs | ≈42.0 ns (~8×) |

Nanoseconds per name against a millisecond-scale Pass 3 — off the hot path by three orders of
magnitude. Hundreds of globs over hundreds of thousands of names is the shape that would need
a prefix index; this bench is where that decision lives.

## Knob parity (M10–M53) · reporting & interchange seams (M54–M62, M67–M71)

**Shared reading for every row below**: parity within the sandbox's run-to-run spread (up to
±20 %; criterion change-detection non-significant where a p-value is shown). Each released knob
moves field writes, header commands or address arithmetic the passes already carried — and
every default keeps pre-knob links **byte-identical**. These benches are parity gates, not wins.

| Knob (milestone)                     | Bench                             | Default                          | Named decisions                                                                | Δ                                                                             |
| ------------------------------------ | --------------------------------- | -------------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| Dylib kind (M14)                     | `dylib_surface/link_256_binds`    | `load` 501.7 µs                  | `weak` 502.0 · `lazy` 501.7 µs                                                 | parity — one header opcode                                                    |
| `-pagezero_size` (M15)               | `pagezero/link_64_objects`        | 4 GiB: 794.7 µs                  | 1 GiB: 818.6 (+2.2 %, p=0.36) · 16 MiB: 841.2 µs (+4.5 %, p=0.62)              | parity                                                                        |
| `-init_offsets` (M16)                | `init_offsets/link_*_32_objects`  | chained 453.4 · classic 426.5 µs | chained **382.5 (−15.6 %)** · classic **387.3 µs (−9.2 %)**                    | _cheaper_ — 128 rebase words leave the payload, pointer sections never bucket |
| `-segprot` (M17)                     | `segprot/link_64_objects`         | house 822.9 µs                   | `__DATA_CONST` rw/r 797.7 (−2.9 %) · `__TEXT` rwx/rx 844.5 µs (+0.1 %, p=0.98) | parity — two u32 fields/segment                                               |
| `-stack_size` (M18)                  | `stack_size/link_64_objects`      | zero 793.4 µs                    | 16 MiB 803.8 (+1.3 %) · 1 GiB 800.2 µs (+0.9 %)                                | parity — one field in the 24-byte `LC_MAIN`                                   |
| `-image_base` (M19)                  | `image_base/link_64_objects`      | zero 838.1 µs                    | 512 KiB 852.3 (+1.7 %) · 2 GiB 860.5 µs (+2.7 %)                               | parity — the one constant-delta base                                          |
| `-sub_umbrella`/`-sub_library` (M20) | `umbrella/link_64_objects`        | empty 827.1 µs                   | 8 members 821.0 (−0.7 %) · 64: 843.6 µs (+2.0 %, p=0.79)                       | parity                                                                        |
| `-sub_client` (M21)                  | `sub_client/link_64_objects`      | empty 805.8 µs                   | 8: 822.2 (+2.0 %) · 64: 835.3 µs (+3.6 %, p=0.77)                              | parity                                                                        |
| `-dyld_env` (M22)                    | `dyld_env/link_64_objects`        | empty 602.2 µs                   | 8: 599.6 (−0.4 %) · 64: 645.8 µs (+7.2 %, p=0.86)                              | parity — spread swallows per-command cost                                     |
| `-alias` (M24)                       | `alias/link_64_objects`           | empty 876.3 µs                   | 8: 893.4 (+2.0 %) · 64: 930.9 µs (+6.2 %)                                      | near-parity — symtab rows + trie terminals                                    |
| `-bundle_loader` (M25)               | `bundle_loader/bundle_64_objects` | dyn-lookup 751.1 µs              | 64-export loader 772.0 µs (+2.8 %)                                             | parity — `0xFF` binds of the same plan cost                                   |

The M26–M29 rows ride the same gate shape and ship with their benches (`dylinker`,
`pie`, `sect_align`, `header_pad` — commands in the inventory above): each decision is
one string swap in an existing command, one bit in one header word, one packing-loop
alignment raise, and one reservation floor whose default plans the pre-knob bytes. Their
medians land in this table with the next recording pass on the dev sandbox (the same
convention the hardware gates carry: numbers only from the rig that measured the rest —
a dev-sandbox re-measure under a different host would not be comparable). The M30–M31 rows ride the same shape (`data_in_code`, `func_starts` — commands in the inventory above): the carriage is one Pass-1 decode, one containment check and 8 `__LINKEDIT` bytes per entry, and the suppression is one dropped command — parity is the honest expectation, the bench pins it. Their medians land in this table with the next recording pass. The M32–M33 rows (`uuid`, `keep_pext` — commands in the inventory above) ride the same shape: the suppression/keep is one dropped command or one symtab-range split over the same corpus — parity is the honest expectation, the bench pins it. The M34 row (`unwind` — command in the inventory above) rides the same shape (the carriage is one Pass-1 decode, one containment check and one regular-page row per entry — parity against the entry-free corpus is the honest expectation) plus the synthesis seam's own groups (`synthesize/1024|4096|4097`: the O(n log n) sort + one pass over the table, the 4097 row pinning the two-page split); their medians land in this table with the next recording pass. The M35 row (`unwind_compressed` — command in the inventory above) rides the same shape over the compressed families: the carried corpus's rows all qualify and ride 4-byte compressed entries through the common encodings array (parity against the entry-free corpus is the honest expectation — the rows only halve, the pipeline is the same), and the synthesis groups pin the compressed families beside the all-regular fallback (`synthesize/compressible_1024|compressible_4096|compressible_4097` — the two-page split at 4097 — beside `synthesize/beyond_24bit_4097`, the pre-M35 all-regular shape over the same row count). Initial dev-sandbox shape-parity run (this host only; the recording-pass convention above governs the comparable table): link 64 objects 572/651 µs (entry-free/carried — the carried link inside the run-to-run span of the entry-free one), synthesize medians 8.6 µs (1024, ~118 Melem/s), 34.7 µs (4096 and 4097 — the page split is free), 38.0 µs (beyond-24-bit fallback); the density at scale — 4096 rows over one encoding plan 16,452 section bytes compressed against 32,828 all-regular (50.1 %, `plan_shape`-verified). The M36 row (`no_compact_unwind` — command in the inventory above) rides the same shape: the suppression is one dropped synthetic section over the same carried corpus, so parity-or-under is the honest expectation — the initial dev-sandbox run pins it (median 466.0 µs carried beside 444.8 µs suppressed; the dropped carriage is the difference). The M37 row (`tlv` — command in the inventory above) rides the same shape across the thread-local carriage: the TLV-free corpus beside the carried corpus (one `__thread` variable per object — descriptor, initializer, zero-fill, the descriptor-load pair), so parity-or-under is the honest expectation (the carriage is two sections and a header flag per variable — no synthetic pieces, no new `__LINKEDIT` payload). Initial dev-sandbox shape-parity run (this host only; the recording-pass convention above governs the comparable table): link 64 objects 687.5 µs TLV-free beside 998.8 µs carried — the delta is the second and third `__DATA` section per object plus the two descriptor-load patch sites; the bench pins the shape, the hardware gates own the comparable numbers. The M38 row (`headerpad_max` — command in the inventory above) rides the same shape across the install-name auto-floor: the natural-region corpus beside the auto-floored corpus (two dylibs of different install-name lengths), so parity-or-under is the honest expectation (the floor is one integer max in the packing loop's `__TEXT` cursor — the growth is computed once from the install names). Initial dev-sandbox shape-parity run (this host only; the recording-pass convention above governs the comparable table): link 64 objects 610.2 µs natural beside 615.2 µs auto-floored — inside the run-to-run span (the floor is the one integer max; the two extra aligned bytes ride the `__TEXT` reservation). The M39 row (`make_undefined` — command in the inventory above) rides the same shape across the make-undefined marks: the empty table beside the 8- and 64-mark tables over the same 64-object corpus (256 rebase slots) — the empty table is the shape-parity gate (an empty table plans the pre-M39 bytes verbatim), the populated tables price the mark's semantic consequence, not the mark itself (a mark is one skipped install — no symtab row, no trie node — while the stripped definitions' rebase slots turn into dynamic-lookup binds, so the import table and symtab grow by the marked names). Initial dev-sandbox run (this host only): link 64 objects 850.3 µs (empty table), 907.3 µs (8 marks — inside the run-to-run span, p = 0.41) beside 1.033 ms (64 marks — the 64 extra dynamic-lookup binds ride the import table and the symtab, the same price the equivalent all-undefined corpus pays without `-U`); the bench pins the shape, the hardware gates own the comparable numbers. The M40 row (`exported_symbols` — command in the inventory above) rides the same shape across the export-trie suppression: the default trie beside the suppressed surface over the same 64-object corpus (256 rebase slots, 256 exported externals), so parity-or-under is the honest expectation (the suppression skips the trie walk and its `__LINKEDIT` slot — one dropped command, no payload). Initial dev-sandbox shape-parity run (this host only; the recording-pass convention above governs the comparable table): link 64 objects 865.6 µs default beside 784.6 µs suppressed — the skipped trie walk is the difference; the bench pins the shape, the hardware gates own the comparable numbers. The M41 row (`no_deduplicate` — command in the inventory above) rides the same shape across the dedup toggle: the merged pool beside the verbatim pass-through over the same 64-object corpus (four `__cstring` literals per object, half shared across every object), so parity-or-under is the honest expectation (the toggle removes plan work — no dedup map, no remap entries — and adds copy bytes: the verbatim pool carries every input literal). Initial dev-sandbox shape-parity run (this host only; the recording-pass convention above governs the comparable table): link 64 objects median 779.1 µs merged beside 534.1 µs verbatim (criterion `--quick` medians) — the toggle is under parity (the dropped dedup map and remap walk are the difference); the bench pins the shape, the hardware gates own the comparable numbers. The M42 row (`dead_strip_dylibs` — command in the inventory above) rides the same shape across the unused-dylib drop: the every-dylib-carried corpus beside the dropped corpus over the same 64-object corpus (one bind per object against the used dylib, the unused dylib exporting a parallel set nothing references), so parity-or-under is the honest expectation (the drop is one skipped walk and one dropped command). Initial dev-sandbox shape-parity run (this host only; the recording-pass convention above governs the comparable table): link 64 objects median 734.1 µs carried beside 764.7 µs dropped (criterion `--quick` medians) — the drop pays its resolve-side walk over the references and the two-level map compaction beside the dropped command's savings, inside the run-to-run span at this profile; the bench pins the shape, the hardware gates own the comparable numbers. The M43 row (`objc` — command in the inventory above) rides the same shape across the ObjC archive pull: the reference-driven pull beside the metadata pull beside `-all_load` over the same 64-object corpus with a half-ObjC archive (32 class-implementing members, 32 plain members, one referenced provider), so the honest expectation is a ladder — the pull costs one prefix walk over the ranlib index every link already parses plus the members it admits, and `-all_load` parses everything. Initial dev-sandbox shape-parity run (this host only; the recording-pass convention above governs the comparable table): link 64 objects median 412.1 µs reference-driven beside 529.9 µs pulled and 607.9 µs all-loaded (criterion medians) — the ladder lands exactly in shape; the bench pins the ladder, the hardware gates own the comparable numbers. The M44 row (`final_output` — command in the inventory above) rides the same shape across the dylib-identity default: the `-o`-path install-name default beside the named universal path over the same 16-object dylib corpus, so parity is the honest expectation (the identity default is one string fill before Pass 0). Initial dev-sandbox shape-parity run (this host only; the recording-pass convention above governs the comparable table): dylib 16 objects median 2.712 ms default beside 2.729 ms named (criterion medians, +0.6 % — inside the run-to-run span); the bench pins the shape, the hardware gates own the comparable numbers. The M47 row (`branch_islands` — command in the inventory above) rides the same shape across the branch-island suppression: the islands-by-default fixed point beside the suppressed scan over the same in-range 64-object corpus (every branch inside the ±128 MiB `imm26` window), so parity is the honest expectation — the decision is one comparison per out-of-range candidate and an in-range corpus plans none either way (the overflow lane's typed refusal is the decision's observable, priced by the giant-text corpus in the M6 tests); the bench pins the shape, the hardware gates own the comparable numbers. The M48 row (`dylib_init` — command in the inventory above) rides the same shape across the dylib initializer: the no-command default beside the named `LC_ROUTINES_64` over the same 64-object dylib corpus, so parity is the honest expectation for the default (the shape-parity gate — the decision is one 72-byte identity-block command and one interner lookup; the command rides inside the reserved header region, so the file size holds and the fixed 72-byte header-block delta is what the smoke gate pins — nothing else in the plan moves); the bench pins the shape, the hardware gates own the comparable numbers. The M98 row (`dylib_term` — command in the inventory above) rides the same shape across the dylib terminator: the no-command default beside the named terminator over the same 64-object dylib corpus, so parity is the honest expectation for the default (the shape-parity gate — the decision is one 72-byte identity-block command shared with M48's `-init` and one interner lookup; the command rides inside the reserved header region, so the file size holds and the fixed 72-byte header-block delta is what the smoke gate pins — nothing else in the plan moves). Initial dev-sandbox shape-parity run (this host only; the recording-pass convention above governs the comparable table): link 64 objects median 440.3 µs default beside 420.9 µs named (criterion `--measurement-time 1` medians) — inside the run-to-run span; the bench pins the shape, the hardware gates own the comparable numbers. The M99 row (`named_uuid` — command in the inventory above) rides the same shape across the named-UUID decision: the content-derived default beside the named value over the same 64-object corpus the M32 bench shares, so parity is the honest expectation — the decision is an emit-side identity write (the plan never moves; the smoke gate pins the two layouts' header blocks byte-identical), the named lane dropping the derivation for the config's own 16 bytes. Initial dev-sandbox shape-parity run (this host only; the recording-pass convention above governs the comparable table): link 64 objects median 845.2 µs derived beside 830.1 µs named (criterion `--measurement-time 1` medians, p = 0.74) — inside the run-to-run span; the bench pins the shape, the hardware gates own the comparable numbers. The M49 row (`objc_pre2` — command in the inventory above) rides the M43 corpus shape with the metadata half split into the two families (16 modern `_OBJC_CLASS_$_` members, 16 GCC-era `.objc_class_name_` members, 32 plain), so the honest expectation is the M43 ladder unchanged — the widened classifier walks the same ranlib table the default link already parses and the pull admits both families. Initial dev-sandbox shape-parity run (this host only; the recording-pass convention above governs the comparable table): link 64 objects median 570.4 µs reference-driven beside 746.2 µs pulled and 846.7 µs all-loaded (criterion `--quick` medians) — the ladder lands exactly in shape; the bench pins the ladder, the hardware gates own the comparable numbers. The M50 row (`no_weak_imports` — command in the inventory above) rides the same shape across the weak-import refusal: the runtime-lookup fallthrough default beside the named refusal over the same 64-object corpus whose every weak reference resolves against the weak-loaded dylib — a resolved weak bind is not a runtime lookup, so parity and byte-identical output are the honest expectation (the smoke gate pins the byte identity). Initial dev-sandbox shape-parity run (this host only): link 64 objects median 610.7 µs default beside 592.5 µs named (criterion `--quick` medians) — inside the run-to-run span; the bench pins the shape, the hardware gates own the comparable numbers. The M51 row (`stack_exec` — command in the inventory above) rides the same shape across the stack-execution decision: the bitless default beside the named flag word over the same 64-object corpus (256 rebase slots), so parity is the honest expectation — the decision is one bit in one header word (the M27 PIE bench's shape, one flag word over). Initial dev-sandbox shape-parity run (this host only): link 64 objects median 813.2 µs bitless beside 806.8 µs stack-exec (criterion `--quick` medians) — inside the run-to-run span; the bench pins the shape, the hardware gates own the comparable numbers. The M52 row (`dead_strip_inits` — command in the inventory above) rides the same shape across the dead-strip init/term roots: the term-strip default beside the rooted term sections over the same 64-object corpus with one unreferenced `__mod_term_func` entry each, so the honest expectation is a small kept-bytes delta on the rooted lane (a root keeps a body the strip would drop — the term routine's atom and its symtab row ride the layout) beside parity in plan cost. Initial dev-sandbox shape run (this host only): link 64 objects median 441.6 µs term-strip beside 696.3 µs rooted (criterion `--quick` medians) — the delta is the kept terminator bodies (one unreferenced function per object rides the layout instead of stripping); the bench pins the shape, the hardware gates own the comparable numbers. The M53 row (`rename_sections` — command in the inventory above) rides the same shape across the section renames: the empty map beside the renamed `__mydata` pairs over the same 64-object corpus (one `__DATA,__data` and one `__DATA,__mydata` section per object), so near-parity is the honest expectation — a rename is one map lookup per classified section (the first match wins, the flag-order walk), and the renamed sections group into buckets the packer plans the same way. Initial dev-sandbox shape-parity run (this host only; the recording-pass convention above governs the comparable table): link 64 objects median 626.5 µs unnamed beside 647.9 µs renamed (criterion `--quick` medians) — near parity, the map lookup rides the classification the link already pays; the bench pins the shape, the hardware gates own the comparable numbers. The M45 row (`upward` — command in the inventory above) rides the same shape across the load-command kinds: the plain-load corpus beside the upward-mark corpus over the same 256-bind corpus (16 dylibs × 16 exports), so parity is the honest expectation (the kind is one header opcode per dylib — binds, the import table and the trie do not read it); the bench pins the shape, the hardware gates own the comparable numbers. The M46 row (`export_dynamic` — command in the inventory above) rides the same shape across the dead-strip root widening: the entry-root default beside the widened all-globals root set over the same 64-object corpus (four dead globals per object), so parity-or-under is the honest expectation for the default (the shape-parity gate — the roots stay the entry, the `-u` marks, the aliases and the sections' own attributes) and a small strip-side delta rides the widened lane (the kept bodies land in the layout); the bench pins the shape, the hardware gates own the comparable numbers.

**Platform word (M10 rung 2)** — one rebase-slot corpus per platform at its floor (20 samples);
the encoding decision is one integer compare in Pass 3:

| Platform     | Floor   | Median  |
| ------------ | ------- | ------- |
| macOS 12.0   | chained | 84.6 µs |
| iOS 15.0     | chained | 84.1 µs |
| tvOS 15.0    | chained | 83.0 µs |
| watchOS 8.0  | chained | 82.5 µs |
| visionOS 1.0 | chained | 84.4 µs |

~2.5 % span — a wash by design; the floor selects the _encoding_, never the fixups
(`m10_platform::*` byte-tests the fallback per platform). _M23's framework re-export rides the
M3 `LC_REEXPORT_DYLIB` path; no separate bench recorded._

**The reporting seams (M54–M62, M67) ride the same gate shape — "reporting never regresses into the
link's hot path", recorded honestly:**

- `observer` (`cargo bench -p pgr-core --bench observer`): the pipeline's cost with and without a
  subscribed observer over the 64-object corpus — the seam emits one event per phase (seven per
  segmented link, a handful of structs), so the honest expectation is near-parity across the
  `unobserved` / `tracing_bridge` / `recording` variants; the unobserved link's shape is the gate.
- `link_map_json` (rides `cargo bench -p pgr-core --bench map`): the M55 JSON interchange beside
  the text render over the same 12×256-symbol corpus — `write` (the compact render, escape rules
  included) and `write_read` (the strict reader's round trip), the cost pinned to the symbol count
  the map carries.
- `provenance` (`cargo bench -p pgr-core --bench provenance`, M56): the `-why_export` query's
  price over the resolve bench's corpus — `index_build` (the M8-a reverse index's once-per-link
  build: 3.3 µs at 16 objects, 16.0 µs at 64, ~19.2/4.0 Melem/s) and `query` (one answer against
  the built index: 234 ns at 64 objects — O(log n) plus a slice walk). The shape gate asserts the
  queried export carries exactly the corpus's own edges, named.
- `why_load` (`cargo bench -p pgr-core --bench why_load`, M57): the S7 pull with the load record
  riding — `pull` (the full reference-driven pull over a 16- and a 64-member archive, one row per
  admitted member) and `render` (the text and JSON renders, 17.6 µs at 64 members). The shape gate
  asserts the report carries exactly the pulled members, each decision a `Reference` seed.
- `time_report` (`cargo bench -p pgr-core --bench time_report`, M58): the per-pass report's own
  price — `link_64_objects/unobserved` vs `collector` (the M54 seam's near-parity gate: one push
  per phase, seven per segmented link, regardless of the corpus size) beside the faces' render
  price over a fixed eight-row report (`render_8_rows`, `render_json_8_rows` — O(rows), the rows
  are the pipeline's own count).
- `wire_time` (`cargo bench -p pgr-daemon --bench wire_time`, M59): the served report's wire-tail
  codec price over a served-shape report (the warm pipeline's six rows, the ladder's note, the
  total band) — `encode_report/6_rows` and `decode_report/6_rows`; the tail rides an IMAGE reply
  that carries pages, so the honest expectation is noise beside the transfer.
- `trace` (`cargo bench -p pgr-core --bench trace`, M61): the timeline's own price —
  `link_64_objects/unobserved` vs `collector` (the M54 seam's near-parity gate, shared with
  the m54/m58 benches: one push per phase, seven per segmented link, regardless of the
  corpus size) beside the faces' price over a fixed eight-row report (`render_8_rows`,
  `parse_8_rows` — O(rows), the rows are the pipeline's own count). M63 rides the same
  bench: the `collector` variant's parse now reports one task record per input (the M63
  seam's honest price — one channel send per input beside the per-phase pushes), and the
  task rows' faces join as `render_8_rows_64_tasks`/`parse_8_rows_64_tasks` (the 64-object
  link's report shape — seven phase rows, 64 worker-lane task rows, one note). M65 rides
  the same bench: the §7.3 ladder's rung rows join as
  `render_12_rows_relink`/`parse_12_rows_relink` (the edited relink's report shape — the
  pipeline's rows, the four rungs, both notes; the ladder's events are four pushes beside
  the pipeline's own, so the honest expectation stays near-parity).
- `wire_trace` (`cargo bench -p pgr-daemon --bench wire_trace`, M62): the served timeline's
  wire-tail codec price over a served-shape document (the warm pipeline's six phase rows,
  the ladder's note instant) — `encode_trace/6_rows` and `decode_trace/6_rows` (one length
  prefix, one string push; the JSON rides verbatim). The tail rides an IMAGE reply that
  carries pages, so the honest expectation is noise beside the transfer.
- `wire_verify` (`cargo bench -p pgr-daemon --bench wire_verify`, M72): the served verdict's
  wire-tail codec price over served-shape reports — `encode_report/clean` (the stats ride, no
  issues) **102.2 ns**, `decode_report/clean` (the strict reader restores the report)
  **386.8 ns**, `encode_report/refused` (a handful of issues ride the document) **946.6 ns**,
  `decode_report/refused` **1.76 µs**, `encode_absent` (the unasked byte) **281 ps** (dev-sandbox
  medians). The tail rides an IMAGE reply that carries pages, so the honest expectation is noise
  beside the transfer; the document rides the M13 interchange form verbatim — the codec's own
  price is the M13 writer and the strict reader, never a re-shape.
- `wire_provenance` (`cargo bench -p pgr-daemon --bench wire_provenance`, M79): the served
  answers' wire-tail codec price over served-shape renders — `encode/one_query` (the name and
  the render, two length prefixes) **30.3 ns**, `decode/one_query` (the verbatim strings
  restore) **156.3 ns**, `encode/eight_queries` (the repeatable flag's real shape)
  **163.9 ns**, `decode/eight_queries` **821.4 ns**, `encode_absent` (the unasked byte)
  **281 ps** (dev-sandbox medians). The tail rides an IMAGE reply that carries pages, so the
  honest expectation is noise beside the transfer; the renders ride verbatim — the codec's
  own price is two length-prefixed string pushes and their reads, never a re-shape.
- `wire_liveness` (`cargo bench -p pgr-daemon --bench wire_liveness`, M93): the liveness
  ask's wire price — the request side `request_encode/eight_queries` (the C-symbol names)
  **222.4 ns**, `request_decode/eight_queries` **445.5 ns**; the reply side
  `encode/one_query` (the verdict line, the keeper row, the root decision) **33.6 ns**,
  `decode/one_query` (the verbatim strings restore) **173.7 ns**, `encode/eight_queries`
  (the repeatable flag's real shape) **195.0 ns**, `decode/eight_queries` **900.1 ns**
  (dev-sandbox medians). The chains ride the provenance tail beside an IMAGE reply that
  carries pages, so the honest expectation is noise beside the transfer; the renders ride
  verbatim — the codec's own price is count-prefixed length-prefixed string pushes and
  their reads, never a re-shape.
- `wire_map` (`cargo bench -p pgr-daemon --bench wire_map`, M80): the served link map's
  wire-tail codec price over served-shape documents — `encode/small` (the hello shape's
  render, one length prefix) **17.0 ns**, `decode/small` (the verbatim document restores)
  **105.7 ns**, `encode/large_64_sections` (the build-system scale's render) **71.7 ns**,
  `decode/large_64_sections` **2.09 µs**, `encode_absent` (the unasked byte) **280 ps**
  (dev-sandbox medians). The tail rides an IMAGE reply that carries pages, so the honest
  expectation is noise beside the transfer; the document rides verbatim — the codec's own
  price is one length-prefixed string push and its read, never a re-shape.
- `wire_order` (`cargo bench -p pgr-daemon --bench wire_order`, M81): the rank table's
  config-tail price over the request body at the build-system scales — `encode/no_table`
  (the pre-M81 shape) **186 ns**, `decode/no_table` **268 ns**, `encode/8_entries` (the
  repeatable flag's real shape) **323 ns**, `decode/8_entries` **1.72 µs**,
  `encode/64_entries` **938 ns**, `decode/64_entries` **17.8 µs** (dev-sandbox medians).
  The tail rides a body that carries the inputs' manifest, so the honest expectation is
  noise beside the transfer; the table's own price is the count-prefixed entry pushes and
  the constructor's rebuild (the duplicate walk one pass over the entries).
- `dep_info` (`cargo bench -p pgr-core --bench dep_info`, M60): the dependency record's own price
  over records sized like real build-system links (8, 64 and 512 rows) — `render` (the version
  row plus one NUL-terminated row per entry) and `parse` (the strict reader's decode), linear in
  the rows the link read, beside `record_512` (the `partition_point` insert path Pass 0 fills the
  record with, one memmove per row). The record rides Pass 0, never the pipeline — a shape gate
  on the sidecar's cost, not a link-cost knob.
- `checks`' extension groups (`cargo bench -p pgr-verify --bench checks`, M67): the
  consumer-side policy check riding the selection surface — `verify_extra/full+policy` beside
  `verify_checks/full` (the extension is one `&dyn` call after the families, not a re-verify:
  initial dev-sandbox run 21.05 µs beside 20.90 µs, inside the run-to-run span — parity is the
  honest expectation) and `verify_extra/policy-only` beside the parse pre-pass (342 ns — the
  extension alone prices the unit's own read; the group pins the shape, the hardware gates own
  the comparable numbers).
- `sarif` (`cargo bench -p pgr-verify --bench sarif`, M69): the render face over the fixed
  triage shapes — `render/8` (the 8-issue report) **4.17 µs** and `render/64` (the 64-issue worst
  case) **19.6 µs**, beside the M13 JSON writer's `to_json/64` at **18.2 µs** — the O(issues)
  price the document's shape promises, the rule table riding one pass over the report's distinct
  codes. (The M69 surface predates this recording pass; the row joins with M70/M71's.)
- `universal` (`cargo bench -p pgr-format --bench universal`, M70): the read seam's own price over
  `FAT_MAGIC` containers — `universal-decode` (header + slice table + window bounds) **28.2 ns**
  (2 slices), **38.7 ns** (5) and **53.2 ns** (9); `universal-select` (decode + the arm64 cputype
  match) **20.0 ns**, **33.0 ns** and **49.7 ns** — linear in the table rows, the window a
  subslice and never a copy (the throughput column prices the container bytes; the work is the
  table).
- `universal` (`cargo bench -p pgr-verify --bench universal`, M71): the container face beside the
  single-image pass it wraps — `single_image` **10.5 µs**, `verify/1` **10.5 µs** (the container
  adds nothing per byte), `verify/2` **21.2 µs**, `verify/4` **42.4 µs** — one strict pass per
  declared slice plus the table-row/header agreement check, linear in the slices.
- `universal_checks` (`cargo bench -p pgr-verify --bench universal_checks`, M74): the selected
  container face beside the full pass it wraps (the M12 selector surface composed over the M71
  face) — `full/2` **21.0 µs**, `signature/2` **20.1 µs**, `full/4` **42.0 µs**, `signature/4`
  **40.2 µs** (dev-sandbox medians) — the signature-only lane under the full pass, both linear
  in the slices: the page-hash recompute dominates either lane, and the selection's saving is
  the skipped segment/fixup walks (the honest expectation the M12 `checks` bench pins, composed
  over the slices).

## Pending measurements

Benches landed with their milestones; the next gate run fills the numbers (criterion medians,
same sandbox). Expectations are stated so any divergence is a finding:

| Bench                                                                          | Pins                                                              | Honest expectation                                                  |
| ------------------------------------------------------------------------------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| `pgr-core/platform_floor/for_target/*` (M10 r3)                                | the consumer seam's decision cost (floor compare + tracing event) | cheap by construction; rotation catches shape regressions           |
| `pgr-verify/verify_platform_floor/verify/<below\|at_floor>` (M10 r3)           | strict pass, images _born_ at their build versions                | the two shapes inside each other's noise                            |
| `pgr-verify/verify_arm64e/verify/<arm64e_auth\|offset64_control>` (r4 s1)      | the read walk, both families                                      | arm64e inside the control's band — same work per slot, wider stride |
| `pgr-core/plan_fixups_word_family/<offset64\|arm64e>/<1k\|10k\|100k>` (r4 s2)  | both encoders, same slot corpus                                   | curves track — one extra encoder branch                             |
| `…/arm64e_auth/<1k\|10k\|100k>` (r4 s3)                                        | every slot signed (PAC triple; auth-bind addend split)            | inside the `arm64e` band                                            |
| `pgr-verify/verify_arm64e/pair_replay/<arm64e_auth\|offset64_control>` (r4 s4) | the family-blind M3 pair gate                                     | inside the control's band — different word reader, doubled stride   |
| `pgr-verify/verify_x86_64/verify/<x86e_format64\|offset64_control>` (r5 s1)   | the strict pass over the 64 family at 4 KiB pages                  | parity — one branch for the VM-address target translation           |
| `pgr-core/x86_64/<format64\|offset64>/<n>` (r5 s2)                    | the planner over the same slot corpus, the two 4-byte-stride families | parity — only the rebase composition differs                        |
| `pgr-format/summarize_family/<offset64_control\|arm64e>` (r4 s1, the format half) | the family-aware summary walk, both families over the same slot corpus | parity — one extra word-reader branch                               |

## Findings & corrections

The bench suite earning its keep — every item carries a regression gate in-tree:

| Finding                                                                                                                               | Where                                                                               | Resolution                                                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| **Unit slip**: archive-parse row said ~1.4 MiB / ~118 µs                                                                              | M5 record                                                                           | corpus is ~118 KiB → ~9.9 µs at 12.2 GiB/s; corrected in the M7 ledger                      |
| **`build_func_starts` emitted absolute offsets into a delta stream since M0**                                                         | caught by the audited-fusion bench (131 K function starts; small corpora masked it) | fixed; regression gate in `m9_resident_fusion.rs`                                           |
| Dead-strip first draft 3.5× slower (911 ms)                                                                                           | M5 bench                                                                            | binary-search liveness + one-pass edge bucketing + borrowed slices → 134 ms, byte-identical |
| `cstring` 1.69 → 1.94 ms at M7                                                                                                        | environmental drift                                                                 | same-box re-measure of the M6 baseline: 1.88 ms — not M7 code                               |
| Accounting loop indexed input 0 (the dylib) instead of the alternated object; import-churn warm-up asserted an already-consumed state | tier-2 bench file                                                                   | both fixed (reset precedes the group)                                                       |
| `cache_entries` `HEADER_LEN + len` overflow; hostile-header arithmetic; stale `link()` signature; 8 GiB `nreloc` pre-allocation       | M7 fuzz sessions                                                                    | fixed; deterministic regression tests per crash class                                       |

<details><summary><b>Regression ledger — every prior gate re-measured as milestones landed</b></summary>

**M4 gates under M5:**

| Bench                               | M4                   | M5                   | Verdict                           |
| ----------------------------------- | -------------------- | -------------------- | --------------------------------- |
| `emit` fused vs reference           | 1.37× (1.59/2.18 ms) | 1.39× (1.58/2.20 ms) | holds                             |
| `link/large_32_objects`             | 172.1 ms             | 172.7 ms             | holds                             |
| `link_dylib/large_32_objects_dylib` | 33.8 ms              | 32.9 ms              | holds                             |
| `link_outputs/dylib_8_objects`      | 18.1 ms              | 18.7 ms              | holds                             |
| `summarize/single_image`            | ~53 GiB/s            | 51.8 GiB/s           | holds                             |
| `trie m3_partition/100000`          | 31.5 ms              | 30.7 ms              | holds (legacy that day: 354.9 ms) |

**M5 gates under M6** (veneer scan, `FixupLc` dispatch, fold-empty fast path all active):

| Bench                   | M5         | M6       | Verdict      |
| ----------------------- | ---------- | -------- | ------------ |
| `link/large_32_objects` | 174–176 ms | 175.7 ms | holds        |
| `link_dead_strip/…_off` | 255 ms     | 259.0 ms | holds        |
| `link_dead_strip/…_on`  | 134 ms     | 136.0 ms | 1.90× vs off |

**Everything under M7** (v2 cache, response files, `-syslibroot`, LRU):

| Bench                                               | Prior record             | M7                        | Verdict                                |
| --------------------------------------------------- | ------------------------ | ------------------------- | -------------------------------------- |
| `link_cache/…_cold`                                 | 177.8 ms                 | 186.4 ms (quick-sampling) | noise band                             |
| `link_cache/…_warm`                                 | 172.8 ms                 | 173.7 ms                  | holds — v2 key/marker/touch free       |
| `tbd/…_text_parse` / `…_frozen_load`                | 35.8 / 19.9 µs           | 36.2 / **19.8 µs**        | holds (v2 frame +4 B)                  |
| `link/large_32_objects`                             | 172–176 ms               | 175.6 ms                  | holds                                  |
| `link/small_4_objects`                              | 2.34 ms                  | 2.42 ms                   | holds                                  |
| `link_dylib/large_32_objects_dylib`                 | 33.8–37.3 ms             | 36.9 ms                   | holds                                  |
| `link_outputs/dylib_8_objects` / `bundle_8_objects` | 18.1–18.7 / 17.9–18.5 ms | 18.6 / 18.4 ms            | holds                                  |
| `link_archive/…_lazy` / `…_all_load`                | 4.02 / 49.06 ms          | 3.99 / 50.4 ms            | holds                                  |
| `link_dead_strip/…_off` / `…_on`                    | 255–259 / 134–136 ms     | 263.6 / 136.4 ms          | 1.93× vs off                           |
| `link_cstring/cstring_16_objects`                   | 1.69 ms                  | 1.94 ms                   | drift, not code (same-box M6: 1.88 ms) |
| `link_icf/…_off` / `…_safe`                         | 17.29 / 19.37 ms         | 16.47 / 18.92 ms          | +14.8 % (≤ 25 %)                       |
| `emit` fused vs reference                           | 1.37×                    | 1.38× (1.59/2.17 ms)      | holds                                  |
| `summarize/single_image` / `corpus_24_images`       | ~53 / ~25.7 GiB/s        | 52.7 / 24.7 GiB/s         | holds                                  |
| `parse_archive/archive_64_members`                  | 11.9 GiB/s               | 12.2 GiB/s                | holds (unit slip corrected)            |
| `trie m3_partition/100000`                          | 31.5 ms                  | **27.9 ms**               | holds (legacy that day: 349.6 ms)      |

**M7 fuzz sessions** (61 s each, ASan, libFuzzer — all clean after the fixes above):

| Target                    | Execs     |
| ------------------------- | --------- |
| `dyld_info_streams` (new) | 1 860 070 |
| `cache_entries` (new)     | 6 302 019 |
| `verify_image`            | 143 230   |
| `link_object`             | 319 230   |

The "30 CPU-days clean" gate formally closes on the rig.

</details>

<details><summary><b>Correctness-gate inventory behind the numbers</b></summary>

- `verify_gate` (`cargo bench -p pgr-driver --bench verify_gate`, M73): the link's own gate
  over a linked dylib — `dylib_16_objects/clean` **496.9 µs** (the strict pass on the produced
  bytes, the signature recompute included), `corrupted` **471.3 µs** (the refusal path walks the
  same checks and renders the same issue list), `no_adhoc` **470.3 µs** (the `-no_adhoc`
  carve-out's filter — one retain over the issues), `served_face` **~3.4 ns** (M76 — the
  resident lane's served face: the session's verdict arrives as a report, shaping the gate face
  from it is O(issues), never the image walk; one verifier pass per resident link, not two),
  `selected_segments` **~4.3 µs** (M77 — the narrowed lane beside the full pass: the M12
  selector skips every family the selection did not name, the signature recompute included)
  (dev-sandbox medians). The gate rides before the write on the cold link, so the honest
  expectation is one verifier pass beside the write — the same shape the verifier's own
  `checks` bench pins, composed at the driver.

- **M4**: `m4_fused_driver_output_is_byte_identical_to_the_reference`, `m4_fused_matches_reference_on_m2_and_m3_corpora`, ten `pgr-emit/tests/m4_fused.rs` corpus shapes, bench-setup assertions.
- **M5**: `m5_archive_member_is_pulled_and_the_output_verifies`, `m5_dead_strip_matches_the_reference_emit_and_determinism`, `m5_cstring_merge_dedups_across_inputs` (+ section-relative pointer gate), `m5_sectcreate_places_file_contents`.
- **M8**: `m8_foundations.rs` (13 — reverse-index site lists, insertion-stable ordinals across growth, slack math + ladder, slack-off identity, pre-parsed layout equality, archive pull, shared `-u` gate); `m8_resident.rs` (7 — byte identity exe/dylib/archive cold+warm, hit counters, fallback transparency, restart, 4-way concurrency, `-u` parity); `pgrd_binary.rs` (4 — real process: strict-clean output, SIGKILL-restart identity, error survival, idle-exit).
- **M9**: `m9_foundations.rs` (4 — anchors, overflow ladder, purity, empty-list == M8-c); `pgr-emit/tests/incremental.rs` (9 + 16 unit — byte identity across body/growth/dylib/no-slack/unsigned, no-op, fallbacks, integrity sampling, codec corruption tolerance); `m9_incremental.rs` (11 — the driver loop end to end); `m9_resident_fusion.rs` (cycle survives daemon fallback, one-shot parity, stand-downs, the served audit, the func-starts regression).
- **M12**: `check_selection::single_check_never_reports_foreign_codes`.

</details>

## How to read these numbers

1. **Starting lines, not targets.** Each pass's gate is beating its own baseline on the same
   corpora, then parallel efficiency — then the hardware comparisons.
2. **Budgets land in CI as they ship**: `--time` JSON, serial fraction ≤ 15 % (except flush),
   parallel efficiency ≥ 70 % on Passes 1/3/4.
3. **Nightly wall-clock vs ld-prime / `ld64.lld` / mold-macho needs the P0 rigs** (perf doc §9.1).
   The CI skeleton ships; the hardware baselines do not exist yet.

**Known follow-ups**: a byte-touching parse bench (memory-bound, not metadata-bound) ·
parameterized corpus generator behind an `xtask` for nightly shape sweeps · D7 canonical import
order remains optional (M4 shipped without needing it; M8's insertion-stable ordinals cover the
incremental requirement) · rig-bound: S1 writer matrix, S4 P-core sizing, PGO, the G1 gate.


## The order-surface groups (M90/M91)

The `order` bench carries the `-sectorder` rungs beside the M11 `order_file` groups (`cargo bench -p pgr-core --bench order`): `sectorder_compose/2|8` — the composition's own price (building the one rank table from N parsed sources, the cross-source duplicate walk plus the merged maps, over 128-entry sources at the per-subsystem file scale); `sectorder_link/layout/composed` — the composed table's link, the ranked shape the M11 `ranked` group gates (the compose is paid once per link, before Pass 3); `sectorder_cstring/layout/{no_order,ranked}` — the M91 cstring rank pass beside the plain D4 merge over 32 objects × 16 literals (the lookup is one linear probe per piece over the small rank vector, the sort the same stable pass the symbol ranks ride). All dev-sandbox numbers; the hardware gates own the comparable numbers.

## The verifier's registry rungs (M94/M95)

- `init_offsets` (`cargo bench -p pgr-verify --bench init_offsets`, M94): the initializer-surface
  family's price over one at-floor executable — `honest` (the 64-entry `__init_offsets`
  u32-offset section, every target mapped) **447 ns**, `broken_entry` (the finding path: one
  target no segment maps) **646 ns**, `pointer_form` (the classic `__mod_init_func` stride
  read) **338 ns**, beside the whole-image pass over the honest image **50.7 µs** — the
  family is ~0.9 % of the pass, a per-section stride read plus a per-entry segment lookup
  (dev-sandbox medians, 2-core KVM rig; the hardware gates own the comparable numbers).
- `mod_term` (`cargo bench -p pgr-verify --bench mod_term`, M132): the terminator-surface
  family's price over one at-floor executable — `honest` (the 64-slot `__mod_term_func`
  pointer section, whole stride) **281 ns**, `broken_stride` (the finding path: four trailing
  bytes off the 8-byte stride) **393 ns**, beside the whole-image pass over the honest image
  **59.9 µs** — the family is ~0.5 % of the pass, a per-section stride read (the
  pointer-form-only shape, lighter than the M94 offsets-form target walk — no per-entry
  segment lookup) (dev-sandbox `--quick` medians, 2-core KVM rig; the hardware gates own
  the comparable numbers).
- `sarif_universal` (the `sarif` bench's M95 group, `cargo bench -p pgr-verify --bench sarif`):
  the container face's render price — `render/2` (two-slice verdict) **6.8 µs**,
  `render/4` (four-slice verdict) **13.0 µs**, beside one slice's single-image render of
  the same 8-issue report **3.6 µs** — linear in the slices, the union rule table paid once
  per run's document (dev-sandbox medians).
- `container_baseline` (the `baseline` bench's M96 group, `cargo bench -p pgr-verify --bench
  baseline`): the container baseline's read and pairing price — `parse/2` **9.5 µs**,
  `parse/4` **18.5 µs** (the document read, linear in the slices), `between_slices/2`
  **275 ns**, `between_slices/4` **510 ns** (the window agreement plus one per-slice delta),
  beside `one_slice_delta_for_scale` **476 ns** (the same slice's delta unbundled) — the
  container gate is a linear walk over slice deltas, never a second pass (dev-sandbox medians).
- `sarif_baseline` (the `sarif` bench's M97 group, `cargo bench -p pgr-verify --bench sarif`):
  the stated face's price — `render_with_baseline_8` **4.29 µs** beside the plain render
  **3.63 µs** (the state consumption pass plus the `absent` tail, ~18 % over the whole-verdict
  document, both O(issues)) and `render_universal_with_baseline/2` **7.63 µs** beside the
  M95 plain container render's 6.8 µs — the M96 pairing rides inside, the window agreement
  plus per-slice states (dev-sandbox medians).

## The identity rungs (M98/M99)

- `dylib_term` (`cargo bench -p pgr-core --bench dylib_term`, M98): the link across the
  `-term <symbol>` decision over the 64-object dylib corpus — `no_term_default` **440.3 µs**
  beside `term_named` **420.9 µs** (dev-sandbox medians, `--measurement-time 1`; inside the
  run-to-run span) — the shape-parity gate, the decision one 72-byte identity-block command
  shared with M48's `-init` and one interner lookup (the smoke gate pins the fixed 72-byte
  header delta; the file size holds). The `dylib_term_link` example walks the default, the
  named terminator, the composed command and the refusals.
- `named_uuid` (`cargo bench -p pgr-core --bench named_uuid`, M99): the link across the
  `-uuid <uuid>` decision over the M32 corpus — `derived_default` **845.2 µs** beside
  `named_value` **830.1 µs** (dev-sandbox medians, `--measurement-time 1`, p = 0.74; inside
  the run-to-run span) — the shape-parity gate, the decision an emit-side identity write
  (the smoke gate pins the two layouts' header blocks byte-identical). The
  `named_uuid_link` example walks the derived default, the content-independent name, the
  uppercase form and the three refusals.

## The composition round (M100/M101)

- `exported_symbol` (`cargo bench -p pgr-core --bench exported_symbol`, M100): the link across the
  composed filter table over the 64-object rebase corpus — `no_filter_default` **959.7 µs** beside
  `only_64_exact` **976.5 µs** (p = 0.72) and `hide_64_exact` **1.010 ms** (p = 0.62) (dev-sandbox
  medians, `--measurement-time 1`; inside the run-to-run span) — the shape-parity gate, the composed
  table feeding the unchanged M14 visibility closure (one matcher walk per planned export name; the
  smoke gates pin the gated surfaces: the only-list halves the trie's terminal count, the hide-list
  keeps the symtab rows and shrinks the trie). The `exported_symbol_link` example walks the default,
  the singular face, the flag+list compose, the glob form and the parse refusals.
- `alias_list` (`cargo bench -p pgr-core --bench alias_list`, M101): the link across the alias table
  the file form composes over the alias bench's corpus — `no_aliases_default` **924.8 µs** beside
  `composed_8` **983.4 µs** and `composed_64` **1.058 ms** (dev-sandbox medians,
  `--measurement-time 1`; the growth is the composed rows' own symtab/trie/strtab cost, the same
  per-pair price the M24 flag form's bench pinned) — the shape-parity gate, the composed table
  riding the same `AliasTable` seam the flags pushed. The `alias_list_link` example walks the file
  form, the flag+file compose and the three refusals.

## The flag-word and policy round (M102/M103)

- `bind_at_load` (`cargo bench -p pgr-core --bench bind_at_load`, M102): the link across the
  `-bind_at_load` decisions over the 64-object rebase corpus — `bitless_default` **930.2 µs**
  beside `bind_at_load` **876.2 µs** (p = 0.15; dev-sandbox medians, `--measurement-time 2`;
  inside the run-to-run span) — the shape-parity gate, the decision one bit in one header word
  (the M51 stack-execution bench's shape, one flag word over). The `bind_at_load_link` example
  walks the default, the named face and the refusal.
- `undefined_policies` (`cargo bench -p pgr-core --bench undefined_policies`, M103): the link
  across the `-undefined` policies over the 64-object corpus whose every object carries one
  unresolved external bound through a GOT-form pointer pair — `error` **252.6 µs** (the
  escalation face: the walk refuses, the price is the walk's own), `dynamic_lookup` **863.9 µs**
  beside `warning` **954.0 µs** (p = 0.15) and `suppress` **970.6 µs** (p = 0.51) (dev-sandbox
  medians, `--measurement-time 2`; inside the run-to-run span) — the three non-escalating faces
  plan byte-identical outputs (the flat-lookup binds ride whatever the exit prints; the policy is
  the exit's, never the image's). The `undefined_warning_link` and `undefined_suppress_link`
  examples walk the two faces beside the M2 defaults.

## The symtab-shaping and debug-suppression round (M104/M105)

- `keep_local_symbols` (`cargo bench -p pgr-core --bench keep_local_symbols`, M104): the link
  across the `-keep_local_symbols`/`-x` decisions over the 64-object corpus whose every object
  carries two section-defined statics and two name-only locals beside its externals —
  `kept_default` **1.0548 ms** beside `x_dropped` **1.0234 ms** (dev-sandbox medians,
  `--measurement-time 1` — the sandbox's bounded run; inside the run-to-run span) — the shape
  gate, the drop moving the symtab builder's subrange and the strtab's tail, never the
  function-starts stream. The `keep_local_symbols_link` example walks the default, the drop,
  the named keep and the refusal.
- `strip_debug` (`cargo bench -p pgr-core --bench strip_debug`, M105): the link across the
  `-S` decisions over the 64-object corpus whose every object carries a `__TEXT,__debug_info`
  `S_ATTR_DEBUG` section with a local in it, a `__DWARF` segment section, and data-in-code
  inputs — `debug_carrying_default` **1.0564 ms** beside `s_stripped` **1.0010 ms**
  (dev-sandbox medians, `--measurement-time 1` — the sandbox's bounded run; inside the
  run-to-run span) — the shape gate, the strip moving the classification's Debug class, the
  symtab's debug entries and the two metadata commands, never the `__unwind_info` synthesis.
  The `strip_debug_link` example walks the carried default, the stripped face and the refusal.


### M106 — the needed-dylib mark

- `needed_dylibs` (`cargo bench -p pgr-core --bench needed_dylibs`): the link across the needed mark under `-dead_strip_dylibs` — `unmarked_drop` (the unused dylib drops) beside `needed_survives` (the mark keeps it) over the 64-object corpus. Shape-parity gate: the mark is one bool in the survival check. Recorded on the dev sandbox: `unmarked_drop` ≈ 806 µs, `needed_survives` ≈ 786 µs (p = 0.49, parity within noise).

### M107 — the commons resolution policy

- `commons_policy` (`cargo bench -p pgr-core --bench commons_policy`): the link across the four `-commons` faces over the 64-object corpus (a tentative each, a dylib exporting every colliding name). Shape-parity gate: the decision is one Pass-2 walk over the common winners. Recorded on the dev sandbox (bounded `--measurement-time 1`): the four faces land within noise of each other (the default face the reference).

### M108 — the multiply-defined resolution policy

- `multiply_defined` (`cargo bench -p pgr-core --bench multiply_defined`): the link across the four `-multiply_defined` faces over the 64-object corpus (every name defined by exactly two objects). Shape-parity gate: the decision is one tie-check at the install site plus one derive walk over the winners. Recorded on the dev sandbox (bounded `--measurement-time 1`): the four faces land within noise of each other (the default face the reference — it prices the walk to the refusal).

### M109 — the warnings-as-errors exit policy

- `fatal_warnings` (`cargo bench -p pgr-driver --bench fatal_warnings`): the driver run across the exit faces (the advisory default beside the `-fatal_warnings` escalation) over the same warning-producing 32-object corpus. Shape-parity gate: the tally is a counter the faces increment as they print; the escalation never regresses the link. Recorded on the dev sandbox (bounded `--measurement-time 1`): the two faces land within noise of each other (the advisory face the reference).

### M110 — the hidden-dylib mark

- `hidden_library` (`cargo bench -p pgr-core --bench hidden_library`): the link across the two faces over the 64-object corpus (the dylib rides visibly — `LC_LOAD_DYLIB` — or hidden, its load command dropped and its exports riding the resolve arena). Recorded on the dev sandbox (bounded `--measurement-time 1`): the two faces land within noise of each other (the mark is one bool in the arena install and the command-drop arithmetic — the shape-parity gate).

### M111 — the read-only-relocations policy

- `read_only_relocs` (`cargo bench -p pgr-core --bench read_only_relocs`): the link across the three `-read_only_relocs` faces over the 64-object corpus (a read-only-target slot per object: the `error` face prices the refusal walk, the `warning`/`suppress` faces price the identical image plus the advisory derivation). Recorded on the dev sandbox (bounded `--measurement-time 1`): the warning and suppress faces land within noise of each other and of the un-knobbed link (the policy is the exit's, never the bytes').

### M112 — the link-statistics report

- `print_statistics` (`cargo bench -p pgr-core --bench print_statistics`): the seam's near-parity — the stats collector rides the M54 observation seam (two count updates per phase event, seven per segmented link, regardless of the corpus size) beside the unobserved link over the observer bench's 64-object corpus, plus the render's O(rows) price. Recorded on the dev sandbox (bounded `--measurement-time 1`): the two faces land within noise of each other (the unobserved face the reference — the shape-parity gate).

### M113 — the reference trace

- `trace_refs` (`cargo bench -p pgr-core --bench trace_refs`): the seam's near-parity — the refs collector rides the M54 observation seam's `on_reference` face (one event per reference the resolve visits, 64 per link over this corpus) beside the unobserved link. Recorded on the dev sandbox (bounded `--measurement-time 1`): the two faces land within noise of each other (the unobserved face the reference — the shape-parity gate).

### M114 — the UUID source

The `random_uuid` bench: a shape-parity gate over the corpus the M32/M99 uuid benches share (64 objects, 4 rebases each) — the carried faces' plans byte-identical (the source is the emit's identity write, never the plan's), the suppressed face exactly one 24-byte command narrower; recorded on the dev sandbox (the knob-parity convention).

### M115 — the ObjC category-merging decision

The `no_objc_category_merging` bench: a shape-parity gate over a 32-object category-bearing corpus — the merged plan drops the registration section, the disabled plan keeps it, the unmergeable corpus links byte-identical under either face; recorded on the dev sandbox.

### M116 — the common-symbol advisory decision

The `warn_commons` bench: a shape-parity gate over a 32-object commons-bearing corpus (half resolved against a linked dylib export under `-commons use_extern`, half landing as the local definition) — the advisory face never moves the bytes (the header parity under the default commons policy and `use_extern` alike), and the landing entries derive on the on face only; recorded on the dev sandbox (bounded `--measurement-time 1`).

### M117 — the init/term section suppression decision

The `no_inits` bench: a shape-parity gate over a 32-object init-bearing corpus (each object carrying one initializer and one terminator pointer section) — the carrying corpus keeps its sections by default and drops them under the suppression, and a corpus without init/term sections links byte-identical under either face; recorded on the dev sandbox (bounded `--measurement-time 1`).

### M118 — the dtrace DOF section processing decision

The `dtrace` bench: a shape-parity gate over a 32-object dtrace-bearing corpus (each object carrying one `__dtrace_dof` (`S_DTRACE_DOF`) section whose head carries the `DOF` identification magic) — the carrying corpus keeps its section under the default and under the decision (the classification recognizes the payload, never drops it; the emit validates the `DOF` header at emit), the payload rides under `-S` too (distinct from the debug class), and a corpus without a `__dtrace_dof` section links byte-identical under either face; recorded on the dev sandbox (bounded `--measurement-time 1`).

### M119 — the dylib module-policy decision

The `module_policy` bench: a shape-parity gate over a 32-object dylib corpus (each object carrying one defined `_fn_N`) — the default `-multi_module` plans no `LC_DYSYMTAB` module table (`nmodtab = 0`, the legacy zero-module table peregrine always carried, every pre-knob link byte-identical), and `-single_module` dylib emits one 56-byte `DylibModule64` entry whose subranges mirror the `LC_DYSYMTAB`'s locals/extdefs (the whole image as one module); recorded on the dev sandbox (bounded `--measurement-time 1`).

### M120 — the executable-override decision

The `executable` bench: a shape-parity gate over a 32-object executable corpus (each object carrying one defined `_fn_N`, the first carrying `_main`) — the default `Execute` filetype carries the executable shape (`MH_EXECUTE`, `__PAGEZERO` first, `LC_MAIN`, no `LC_ID_DYLIB`), and the explicit `-executable` override forces `OutputType::Execute` (the same shape — the decision never moves the bytes, every pre-knob link byte-identical); recorded on the dev sandbox (bounded `--measurement-time 1`).

### M121 — the duplicate-symbol advisory decision

The `warn_duplicate` bench: a shape-parity gate over a 32-object corpus whose second half redefines the first half's symbols (the duplicate strong-strong collisions the advisory tallies) — under the `warning` policy the first definition wins; `-warn_duplicate` tallies the collisions (one per pair) without changing the resolution policy, and the bytes never move under either face (the advisory is a measurement, never a layout product); recorded on the dev sandbox (bounded `--measurement-time 1`).

### M122 — the PIE positive-form decision

The `pie` bench: a shape-parity gate over a 64-object executable corpus — the default carries `MH_PIE` (every executable already does), and `-pie` names the same bit explicitly (last-wins a preceding `-no_pie`); the bytes never move (the bit is the default's own — `-pie` is the explicit-decision mirror, never a layout product); recorded on the dev sandbox (bounded `--measurement-time 1`).

### M123 — the weak-reference-mismatches decision

The `weak_reference_mismatches` bench: a shape-parity gate over a 32-object corpus whose references mix weak and strong against the same name — under `error` the mix refuses, under `weak`/`non-weak` the mismatch is recorded and the link exits 0; the bytes never move under either advisory face (the advisory is a Pass-2 walk, never a layout product); recorded on the dev sandbox (bounded `--measurement-time 1`).

### M124 — the first-segment-base decision

The `seg1addr` bench: a shape-parity gate over a 64-object executable corpus — the default 4 GiB constant-delta floor and a named 1 GiB `-seg1addr` override; the base is one resolver read at the head of the segment planner (the constant-delta contract `vmaddr = fileoff + base` holds either way), so the link cost never regresses when the floor shifts (the shifted vmaddrs are the only diff, every byte the planner does not touch is identical); recorded on the dev sandbox (bounded `--measurement-time 1`).

### M125 — the CPU-subtype-override decision

The `force_cpusubtype_all` bench: a shape-parity gate over a 64-object executable corpus — the default cpusubtype word and a named `-force_cpusubtype_ALL` override; the word is `CPU_SUBTYPE_ARM64_ALL` either way (the default already carries it — the knob is byte-identity, the M122 `-pie` pattern over the cpusubtype word), so the two images are byte-identical and the link cost never regresses when the decision is named; recorded on the dev sandbox (bounded `--measurement-time 1`).

### M126 — the output's atomization bit decision

The `subsections_via_symbols` bench: a shape-parity gate over a 64-object executable corpus — the default flags word (no `MH_SUBSECTIONS_VIA_SYMBOLS` bit) and a named `-allow_subsections_via_symbols` override (the bit OR'd into the `mach_header_64.flags` word); the bit is the producer's own atomization decision (the dead-strip and ICF passes already read the bit from input objects since M5 — the output decision names whether the *producer* marks its own image atomizable, never a layout product), so the two images differ only in the single flags word and the link cost never regresses when the decision is named (the named `false` face is byte-identical to the default — byte-identity, the M122 `-pie` pattern over the flags word); recorded on the dev sandbox (bounded `--measurement-time 1`).

### M127 — the interpose-all dylib mark decision

The `interposable` bench: a shape-parity gate over a 64-object dylib corpus with no weak-defined exports — the default flags word (no `MH_WEAK_DEFINES | MH_BINDS_TO_WEAK` bits) and a named `-interposable` override (both bits OR'd into the `mach_header_64.flags` word); the bits are the producer's own interpose-all decision (they ride the weak-define presence the M2 trie already priced — a dylib with no weak defines never carried the bits, so the named `false` face is byte-identical to the default — byte-identity, the M122 `-pie` pattern over the flags word), so the two images differ only in the single flags word and the link cost never regresses when the decision is named; recorded on the dev sandbox (bounded `--measurement-time 1`).

### M128 — the app-extension-safe mark decision

The `application_extension` bench: a shape-parity gate over a 64-object executable corpus — the default flags word (no `MH_APP_EXTENSION_SAFE` bit) and a named `-application_extension` override (the bit OR'd into the `mach_header_64.flags` word); the bit is the producer's own app-extension-safe decision (the App Store sandbox compatibility contract the system enforces on a `.appex`'s loaded images — never a layout product), so the two images differ only in the single flags word and the link cost never regresses when the decision is named (the named `false` face is byte-identical to the default — byte-identity, the M122 `-pie` pattern over the flags word); recorded on the dev sandbox (bounded `--measurement-time 1`).

### M129 — the debug-map stabs decision

The `debug_map` bench: the symtab-build throughput (ns) and the output symtab bytes over a generated stab-carrying corpus (`128x2048` and `256x2048` — 128/256 objects × 2048 stab-anchored symbols with the full `N_SO`/`N_OSO`/`N_FUN`/`N_GSYM`/`N_STSYM`/`N_LSYM`/`N_BNSYM`/`N_ENSYM` set), the bench measuring a real cost (the symtab builder's walk over the stab-carrying corpus, the stab re-addressing onto placed live atoms), not a byte-parity assertion — the byte-identity lock is the `m129_debug_map` gate; recorded on the dev sandbox (bounded `--measurement-time 1`).

### M130 — the ObjC-stubs synthesis decision

The `objc_stubs` bench (the M130 design record's named follow-up, shipped additively once the synthesis landed): the link cost over a generated `_objc_msgSend$<sel>` callsite corpus (64 objects × 8 callsites over 32 distinct selectors, the repeats deduping onto one stub per selector) beside the callsite-free corpus — `link_64_objects/synthesis_32_selectors` beside `link_64_objects/no_callsites`, the delta the synthesis's own price (the selector classification, the stub emission, the `__objc_methname` dedup). Recorded on the dev sandbox; the hardware gates own the comparable numbers.


### M131 — the mergeable literal-pool decision

The `literal_merge` bench (this block records the rung the M131 Cargo.toml comment already named — the block was the one doc the milestone's ceremony skipped): the D4 dedup's own price over a generated 4-byte-literal corpus (32 objects × 16 literals, half the values shared across objects so the merge finds real duplicates without collapsing to one), beside the `-no_deduplicate` verbatim pass-through — `layout/dedup` **1.08 ms** vs `layout/no_dedup` **414 µs** over the same 32-object corpus. The bench measures a real cost (the layout's per-bucket hash-bin find-or-insert over the fixed-width literal atoms, the remap onto the canonical copies, the dead-strip-ready atomization), not a byte-parity assertion — the byte-identity lock is the `m131_literal_merge` gate. The 8/16-byte literals ride the same width-agnostic path (the cstring machinery the M131 completion widens); the 4-byte corpus is the representative face. Recorded on the dev sandbox (bounded `--quick` medians, 2-core KVM rig; the hardware gates own the comparable numbers).

### M133 — the warning-suppression face

The `warn_suppress` bench: the driver's run cost across the `-w` faces over the same warning-producing 32-object corpus (every object referencing an undefined `_hole_<i>`, the `-undefined warning` advisory face's product) — `run_32_objects/advisory_default` **1.38 ms** vs `run_32_objects/suppressed` **833 µs**. The decision is the print face's, never the image's — the link cost never regresses when the suppression is named; the recorded delta is the default lane's 32 `pgr: warning:` stderr writes (terminal I/O on the dev rig), not pipeline work — the honest expectation is pipeline parity, the suppression silences the lines and never moves the tally the M109 escalation reads. Recorded on the dev sandbox (bounded `--quick` medians, 2-core KVM rig; the hardware gates own the comparable numbers).

### M134 — the loaded-object inventory face

The `whats_loaded` bench: the driver's run cost across the `-whatsloaded` faces over the same clean 32-object corpus (each object carrying its own entry symbol — a second `_main` would refuse the link) — `run_32_objects/silent_default` **581 µs** vs `run_32_objects/inventory` **710 µs**. The face is a measurement over data the link already had, never a layout product — the link cost never regresses when the inventory is named; the recorded delta is the named lane's 32 stderr lines (terminal I/O on the dev rig), the image byte-identical either way (the `whatsloaded` gate pins the byte-identity against the un-named decision's image). Recorded on the dev sandbox (bounded `--quick` medians, 2-core KVM rig; the hardware gates own the comparable numbers).

### M135 — the library-search-order face

The `search_paths` bench: the driver's run cost across the `-search_paths_first`/`-search_dylibs_first` faces over the same split corpus (dir one's `libgreet.a` beside dir two's `libgreet.dylib`, both exporting `_greet`, so each face's walk probes a real candidate list over both directories) — `run_32_objects/paths_first_default` **~615 µs**, `run_32_objects/paths_first_named` and `run_32_objects/dylibs_first` within noise (p > 0.05, bounded `--measurement-time 1` medians). The decision is Pass 0's own — it names which files the link consumes and the pipeline rides the picked bytes either way — so the honest expectation is parity, and the split corpus makes each walk honest work rather than a first-directory hit (the shape gate the M109/M133/M134 driver benches ride, one face over). Recorded on the dev sandbox; the hardware gates own the comparable numbers.

### M136 — the unused-dylib advisory face

The `warn_unused` bench: the driver's run cost across the `-warn_unused_dylibs` faces over the same 32-object corpus with one unbound-rider stub — `run_32_objects/silent_default` beside `run_32_objects/advisory`, the honest expectation is parity (the face reads the M42 predicate read-side and never moves the bytes; the delta is the one stderr line). Recorded on the dev sandbox; the hardware gates own the comparable numbers.

### M10 rung 5, slice 1 — the x86_64 read side

The `verify_x86_64` bench: the whole-image strict pass over a `DYLD_CHAINED_PTR_64` chained executable born at the family's 4 KiB page (one VM-address rebase plus one bind) beside the `64_OFFSET` control — `verify_x86_64/verify/<x86e_format64|offset64_control>`, the honest expectation parity (the walk strides both families in 4-byte units; the format-2 face adds one branch for the VM-address target translation). No numbers claimed yet — the bench lands with the slice and the next gate run fills the row the way the rung-3 floor bench was filled.


### M10 rung 5, slice 2 — the x86_64 producer half

The `x86_64` bench: the fixup planner over the same slot corpus in both
4-byte-stride families — `DYLD_CHAINED_PTR_64_OFFSET` (the M2 default,
image-offset rebases) beside `DYLD_CHAINED_PTR_64` (the x86_64 family,
VM-address rebases) — `x86_64/<format64|offset64>/<1k|10k|100k>`, the
honest expectation parity (the families share the word layout, the packer
and the import table; only the rebase encoder's composition differs, one
branch — the same shape gate the rung-4 family bench pinned one family
over). No numbers claimed yet — the bench lands with the slice and the
next gate run fills the row the way the rung-3 floor bench was filled.

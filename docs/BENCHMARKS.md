# Peregrine Benchmarks — Recorded Baselines

**Status: M0–M29 surfaces recorded on the dev sandbox.** These numbers exist to (a) prove the
harness works end-to-end from day one and (b) give each pass a regression anchor.

> [!WARNING]
> **Nothing here is a product claim.** Every figure is a 2-core KVM dev-sandbox baseline, not an
> Apple Silicon result. The perf doc's Phase P0 replaces them with measured hardware baselines;
> the G1/G2/G3 gates and every `ld-prime`/`ld64.lld` comparison stay **open until the rig exists**.
> Correctness is never traded for speed: every benchmark link is also run through `pgr-verify`,
> and the byte-identity gates fail the build on divergence.

<p>
  <a href="#results-at-a-glance">Results</a> • <a href="#gate-scoreboard">Gates</a> • <a href="#conditions--harness">Setup</a> • <a href="#pipeline-baselines">Pipeline</a> • <a href="#the-edit-loop--stages-abc">Edit loop</a> • <a href="#consumer-surfaces-m11m14">Surfaces</a> • <a href="#knob-parity-m10m25">Parity</a> • <a href="#pending-measurements">Pending</a> • <a href="#findings--corrections">Findings</a>
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
cargo bench -p pgr-emit --bench wire-tiles
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
# verify
cargo bench -p pgr-verify --bench platform
cargo bench -p pgr-verify --bench arm64e
cargo bench -p pgr-verify --bench checks
cargo bench -p pgr-verify --bench baseline
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

**Export-filter matcher (M14)** — 10 240 names, four-entry lists, same scan length per family:

| Bench                      | Median   | Per name       |
| -------------------------- | -------- | -------------- |
| `match_10k_names/exact`    | 54.9 µs  | ≈5.4 ns        |
| `match_10k_names/one_star` | 171.2 µs | ≈16.7 ns (~3×) |
| `match_10k_names/two_star` | 430.2 µs | ≈42.0 ns (~8×) |

Nanoseconds per name against a millisecond-scale Pass 3 — off the hot path by three orders of
magnitude. Hundreds of globs over hundreds of thousands of names is the shape that would need
a prefix index; this bench is where that decision lives.

## Knob parity (M10–M29)

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
a dev-sandbox re-measure under a different host would not be comparable).

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

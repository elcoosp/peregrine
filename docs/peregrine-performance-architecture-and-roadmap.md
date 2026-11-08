# Peregrine — Performance Architecture & Multi-Year Roadmap

**Companion to the Peregrine TDD (2026-11-05). Goal: the fastest Mach-O linker for arm64-apple-darwin.**

| | |
|---|---|
| **Document type** | Performance architecture + roadmap (supersedes TDD §12 for sequencing; extends TDD §4–§10 for design) |
| **Planning assumption** | ~3 full-time engineers; Month 0 = project start (calendar dates assume Jan 2027). Timelines scale roughly inversely with headcount for Y1, much less so for Y2+ |
| **Status of numbers** | Every figure marked *(hypothesis)* is a back-of-envelope estimate or a number carried over from the TDD / mold paper. None were measured on Apple Silicon by me. Phase P0 exists to replace them with measurements |

---

## 0. Summary

1. **Linking is write-bound once the compute is parallel.** After parsing, resolution and layout are parallelized well (the TDD's design), a large link is limited by (a) memory bandwidth, (b) SHA-256 over every output page, and (c) pushing the output through `pwrite` into the APFS page cache. The estimated floor for a 1 GiB output is a few hundred milliseconds, and most of that is (c). Section 1 shows the budget.
2. **So there are two ways to be "fastest possible", and Peregrine needs both:**
   - *Make the full link run at hardware speed.* Fused tile emit (copy + relocate + chain-encode + hash in one cache-hot pass), de-indirected symbol tables, zero-copy relocations, P-core-aware scheduling, overlap of everything that can overlap. (Years 1–2.)
   - *Don't do the work.* Parsed-object caches, a resident process, and in-place incremental relinking with clone-and-patch output, re-hashing only dirty pages. This is the only route to the 10–100× numbers on edit–relink loops, because it avoids writing bytes at all. (Years 2–3.)
3. **The TDD design is a strong base but has gaps that would hurt both correctness and speed** (Section 3): atoms must be formed from symbol boundaries (`.subsections_via_symbols`), not input sections; compact-unwind synthesis, debug-map stabs and `__cstring`/literal merging are missing; relocations should not be materialized into `Vec<Reloc>`; Pass 0 mapping should be parallel; import ordinals should not depend on fixup address order.
4. **Sequencing change:** the TDD puts "the speed pass" at M4. I recommend performance-shaped data structures and a perf-regression CI from M1, because retrofitting layout, interner and emit structure later is the expensive kind of rewrite. Apple Silicon benchmark hardware is a Month 0 requirement, not a stretch goal (TDD risk R9).
5. **The TDD's "≥5× vs ld-prime" goal is unproven.** I keep it as the Year 2 stretch target but make the commitment staged and baseline-driven (Section 2).

---

## 1. Performance thesis

### 1.1 Where time goes in a link

For a debug-scale link (about 1 GiB output, 10⁶–10⁷ symbols, ~10⁷ relocations, warm page cache), the cost centers are:

| Stage | Nature | Scales with cores? | Estimated wall at 8 P-cores *(hypothesis)* |
|---|---|---|---|
| Map + parse (symtab, load commands, reloc ranges) | cache-miss + page-fault bound; reads maybe 20–30% of input bytes | Yes (per file); skew-limited by the largest object | 40–80 ms |
| Intern + resolve | random access to `owners[]`; one CAS per definition | Yes | 10–30 ms |
| Dead-strip / liveness | pointer chasing over relocation edges | Partly (worklist) | 10–40 ms (only with `-dead_strip`) |
| Layout | prefix scans; tiny serial part | Yes | 5–15 ms |
| Emit: copy + relocate | memory-bandwidth + random loads for symbol addresses | Yes | 50–100 ms |
| Chain encode + LINKEDIT | page-local; sorts of fixups/symbols | Yes | 10–40 ms |
| SHA-256 page hashes | 1 GiB at ~2 GB/s/core with ARM SHA-2 extensions | Yes | ~65 ms *(if the hardware path holds)* |
| `pwrite` into page cache + APFS | kernel copy + extent allocation; 4 writers | Weakly | 100–300 ms; **largest unknown** |

With emit, hash and write overlapped, the floor is write-bound at roughly 0.2–0.5 s for 1 GiB. Everything the linker does *before* the writers saturate is therefore worth optimizing only to the extent it delays the first block reaching the writers and the tail after the last one.

**Consequence.** Past roughly Year 1, raw compute speedups hit diminishing returns. The remaining large wins are structural: do not parse what did not change, do not write what did not change, do not hash what did not change.

### 1.2 The five levers, in priority order

1. **Avoid work** — caches, resident state, incremental output. Largest multiplier, highest complexity.
2. **Overlap work** — emit ‖ hash ‖ write; tail of layout ‖ start of emit; background page pre-fault of the output buffer.
3. **Parallelize with low skew** — LPT scheduling by file size, intra-file splitting for giant objects, P-core-sized pool.
4. **Cut latency per element** — de-indirect symbol lookups, software prefetch, SoA, no allocation in hot loops, no per-reloc decode.
5. **Tune constants** — PGO/LTO build of `pgr`, allocator, block sizes, writer count, `madvise`/QoS knobs. Each worth 5–30%, never a rewrite.

---

## 2. Targets and scorecard

All targets are *(hypothesis)* until Phase P0 produces baselines. They are stated so that every milestone has a falsifiable performance gate.

### 2.1 Metrics

| Metric | Definition |
|---|---|
| **Clean-link wall** | Wall time, warm page cache, output removed first, median of ≥ 10 runs |
| **Relink wall** | Wall time after a one-function change in one object, previous output present |
| **Startup floor** | Wall time to link a hello-world (a few tiny objects + libSystem `.tbd`) |
| **Parallel efficiency** | (thread-seconds at 1 thread) / (N × wall at N threads) per pass, from `--time` |
| **Peak RSS ratio** | Peak RSS / output size |
| **Bytes written** | Bytes actually `pwrite`n per link |

### 2.2 Staged targets

| Gate | Date | Clean-link vs `ld64.lld` | Clean-link vs ld-prime | Relink | Startup floor |
|---|---|---|---|---|---|
| G1 (M4) | Month 10 | ≥ 5× (TDD gate, 100 MB corpus, 16 threads) | ≥ 1.5× on large debug corpus | n/a | ≤ 5 ms |
| G2 (v1.0) | Month 24 | ≥ 8× | ≥ 3× | ≥ 2× (cache-assisted) | ≤ 3 ms |
| G3 (incremental GA) | Month 36 | — | ≥ 3× clean | ≥ 10× (target: < 100 ms for a 1 GiB output) | ≤ 3 ms |
| Stretch | Month 24–36 | — | ≥ 5× clean (TDD goal 3) | ≥ 30× | — |

Notes:
- "Large debug corpus" and "100 MB corpus" are defined in Section 9.
- If P0 shows ld-prime is already within ~1.5× of the speed-of-light floor on a given corpus, the clean-link target for that corpus is retired and effort moves to the relink metric. This is the honest way to handle the possibility that the competition is closer to the floor than assumed.
- Pass-level budgets (enforced in CI, Section 9.3): no single-threaded section above 15% of wall except flush; parallel efficiency ≥ 70% for Passes 1, 3, 4 at 8 P-cores; peak RSS ≤ 2.5× output (TDD §10.5).

---

## 3. Architecture deltas against the TDD

Each row is something I would change or add. "Gap" means a Mach-O feature real-world links need that the TDD does not currently schedule. "Perf" means the TDD design works but leaves speed on the table.

| # | Type | Finding | Why it matters | Proposed change |
|---|---|---|---|---|
| D1 | Gap, critical | The TDD defines `AtomId` as an *input section*. Clang emits one `__text` per object with `.subsections_via_symbols`; real atoms are the symbol-delimited subranges | With section-granular atoms: dead-strip cannot remove an unused function, ICF is useless, `-order_file` cannot order functions, and Pass 3's "10k atoms per group" degenerates to ~1 atom per file | In Pass 1, split every section carrying `MH_SUBSECTIONS_VIA_SYMBOLS` into atoms at symbol boundaries (sort symbol `n_value`s per section, per file, in parallel). Atom = `(file, section, start, size)`; keep `N_ALT_ENTRY` symbols inside their parent atom. Per-section atomization remains for objects without the flag |
| D2 | Gap | No pass synthesizes `__TEXT,__unwind_info` from `__LD,__compact_unwind` (and merges/keeps `__eh_frame`) | C++ exceptions, Rust panics, backtraces fail without it | Add to Pass 3 (sizing) and Pass 4 (emit): per-function compact-unwind entries gathered per atom, sorted by address, two-level index + second-level pages built in parallel by address chunk; personality/LSDA tables deduped |
| D3 | Gap | No debug map. ld64 emits stabs (`N_OSO`, `N_SO`, `N_FUN`, `N_GSYM`, …) into the symbol table so `lldb`/`dsymutil` can find DWARF in the `.o` files | Without it, debug builds are undebuggable on macOS | Emit stabs in the symtab builder, parallel per file with prefix-sum offsets. Provide `-S` (strip debug) as a fast path. Record object mtimes for `N_OSO` |
| D4 | Gap, also perf | No `__cstring` / literal merging (`S_CSTRING_LITERALS`, `S_4BYTE_LITERALS`, `S_8BYTE_LITERALS`, `S_16BYTE_LITERALS`, ObjC method/class-name pools) | ld64 dedups these by default; output size and cache footprint depend on it | Reuse the hash-bin technique from the interner (TDD §6.1) for literal pools: bin by hash, dedup per bin, prefix-sum offsets. Parallel and deterministic. Maps each source string to an output offset via a per-input-section remap |
| D5 | Perf | Pass 1 decodes every relocation into `Vec<Reloc>` | Mach-O `relocation_info` is already 8 bytes and sorted; decoding it doubles memory traffic and allocation | Keep `&[RelocationInfo]` as zero-copy slices into the input mmap. Decode on the fly in the Pass 2 scan and again in Pass 4 apply. Pre-index only what Pass 2 needs (per-atom reloc ranges) |
| D6 | Perf | Pass 0 maps every input serially (TDD target < 10 ms for 1 000 inputs) | `open` + `fstat` + `mmap` is on the order of 5–15 µs each on macOS *(hypothesis)*; 5 000 `-filelist` entries is 25–75 ms serial | Keep Pass 0 serial only for argv and archive/dylib search. Move `open`/`mmap` into the Pass 1 per-file task. Probe `-L`/`-l` search paths in parallel with a stat cache |
| D7 | Perf, determinism | Import ordinals are assigned in first-use order over address-sorted fixups (TDD §7.3) | Creates a global dependency that blocks fusing chain-encode into the tile emit loop, and makes the table unstable under incremental relinks | Assign import ordinals from a canonical order independent of fixup addresses, computed in Pass 3: collect `(lib_ordinal, SymbolId, addend, weak)` tuples per section in parallel, sort + dedup. Candidate order: `(lib_ordinal, name bytes, addend)`. Verify against dyld behavior and ld64 goldens (spike S6); if a first-use order is required for any reason, fall back to it |
| D8 | Perf | Resolution path is three dependent loads: local symbol → `name_ids` → `owners` → `extra` | Random access dominates relocation application at 10⁷ relocs | After Pass 3, materialize a flat per-file table `resolved: Box<[ResolvedSym]>` (final vaddr, GOT slot, flags) written by a sequential, prefetched `par_iter`. Emit then reads one file-local array |
| D9 | Perf | Rayon pool = `available_parallelism` | On Apple Silicon, E-cores join barrier-synchronized passes and create stragglers | Default pool size = P-core count (`hw.perflevel0.logicalcpu`), QoS `USER_INITIATED`; E-cores are used only by the writer/IO side. Make it a measured default (spike S4) |
| D10 | Perf | Output `Vec<u8>` with capacity = file size | A zeroed Rust `Vec` may memset; padding/bss gaps must be zero | Allocate the output as anonymous `mmap` (lazily zero-filled by the kernel, no memset), pre-faulted in parallel just ahead of emit (or kept mapped between links in resident mode) |
| D11 | Perf | Free-at-exit | Dropping arenas and unmapping gigabytes costs tens of ms | After the writers join, `_exit` without teardown. Optional second-process teardown (TDD §2.1.1) stays a fallback |
| D12 | Compat, scheduling | `-dead_strip`, `-order_file`, ICF, thunks are M5 | Xcode release builds and `cargo --release` pass `-dead_strip`; startup-time order files are standard in shipping apps; text > 128 MiB needs thunks | Pull dead-strip and order-file into Year 1 (with D1), ICF and thunks into Year 2 H1 |
| D13 | Compat | Missing from the load-command surface: `LC_RPATH`, `LC_LOAD_DYLINKER`, `LC_SOURCE_VERSION`, `LC_BUILD_VERSION` tool entries, `LC_ID_DYLIB`, `__init_offsets` and `-init_offsets` for newer deployment targets, `-sectcreate`, `-exported_symbols_list`, `-weak_library`/`-reexport_library` | Needed before any real build system will use `pgr` | Track as a compat checklist from M2; each flag has a fixture |
| D14 | Perf | Hashing is a separate step after emit (TDD §9 step 2) | Re-reads the whole output from DRAM after it has left cache | Hash 4 KiB pages inside the fused tile loop (Section 4.4); only the header page and the LINKEDIT tail are hashed late |

---

## 4. Optimized pipeline (v2)

The TDD's six passes stay. What changes is what happens inside them and where the barriers are.

```
 Pass 0   argv, search paths, archive/dylib discovery            (serial, tiny)
   │
 Pass 1   per-file task: open+mmap → parse → ATOMIZE → intern     (parallel, LPT-scheduled)
   │        ├─ cache hit: load Parsed Object Image (zero-copy)    (Y2)
   │        └─ giant objects split across threads
   │
 Pass 2   resolve (CAS) → ordinals → archive liveness → roots     (parallel)
   │        └─ reloc scan: GOT/stub/bind flags, liveness edges     (zero-copy relocs)
   │
 Pass 3   sizes → prefix-scan layout → pack segments → patch       (parallel + tiny serial)
   │        └─ materialize per-file `resolved[]` tables; import table; fixup lists per page
   │
 Pass 4   FUSED TILE EMIT over 16 KiB output pages                (parallel)
   │        copy runs → apply relocs → encode chains → hash 4 KiB pages → queue
   │        + LINKEDIT builders in parallel on other tasks
   │        + header page and signature blob last
   │
 Pass 5   writers (4, E-core friendly) ‖ Pass 4 tail              (overlapped)
```

### 4.1 Pass 1 — parse, atomize, intern

- Scheduling: sort the file list by size descending and hand out via rayon (LPT). Objects above a threshold (default 64 MiB, tunable) are split: symbol table parsed in chunks, atomization per section range, relocation index built per section range. This protects against single-codegen-unit Rust objects and Swift whole-module objects that otherwise serialize the pass.
- Only external symbols (`N_EXT`) enter the interner and the global symbol table. Local symbols stay file-local; their names are only needed for the output symtab and are copied through as byte ranges (no interning, no hashing). `L`/`l` temporaries are dropped.
- Atomization (D1) emits, per section, a sorted atom-boundary array. Atom records are 16 B: `(offset: u32, size: u32, align_log2: u8, flags: u8, first_sym: u32)`; no pointers.
- Hash function for names: a fixed-seed fast hash (`ahash` fixed constants or `rapidhash`/`foldhash`); choose by microbenchmark on real symbol-name distributions (long mangled C++/Swift/Rust names share long prefixes, so hash quality and speed on 40–200 byte inputs matter more than on short keys).
- Bins: `BIN_BITS` sized from `n_threads × 4` so each bin dedup is a short sequential task; sort key is `(hash, len)`, with byte compares only on equal-hash neighbours (TDD §6.1 sketch, but do not include a pointer in the sort key — it adds a cache miss per compare).

### 4.2 Pass 2 — resolve

- Keep the packed-key CAS (TDD §6.2) unchanged. The one improvement: a **pre-filter for singletons**. During Pass 1 phase C the per-bin dedup already knows when a name occurs exactly once among definitions and has no undefined references from elsewhere; mark those so Pass 2 can skip the CAS and set the owner with a plain store. For typical C++ links this removes the majority of CASes.
- The relocation scan (GOT/stub/bind flags, liveness edges) runs over zero-copy reloc slices. Software-prefetch the `owners[]`/`flags[]` entries 8–16 relocations ahead (`core::arch::aarch64::_prefetch` on arm64 hosts; the generic intrinsic path on x86 Linux).
- Liveness / dead-strip: use the "one scoped task per thread + local worklist + steal" pattern from the TDD (wild style) with 32-bit atom ids and a bitmap for the mark set. Mark bits are `AtomicU64` words with `fetch_or` on a bit; check-then-set avoids dirtying cache lines for already-marked atoms.
- Archive handling: parse-everything-eagerly (TDD §4.1) is the default. Add experiment **S7**: use the archive's ranlib table (`__.SYMDEF SORTED`) so liveness can pull members on demand and skip parsing members never referenced. This matters for very large static libraries (Rust `rlib` sets, vendored C++ libs) where most members are unreferenced. Decision rule: adopt if it wins ≥ 20% on the archive-heavy corpus without breaking `-ObjC`, `-force_load`, `-all_load` semantics.

### 4.3 Pass 3 — layout

- Unchanged in structure (two-level prefix scan, 16 KiB segment packing, constant vaddr−fileoff delta).
- **Copy-run coalescing:** while assigning atom offsets, detect consecutive atoms that are adjacent in both input and output and merge them into one `CopyRun { src: Range, dst: u64 }`. Without dead-strip or ordering, a whole input section becomes one run, turning millions of small `memcpy`s into thousands of large ones. With dead-strip, runs break only at dead atoms.
- **Per-page fixup lists:** while scanning relocations for `ARM64_RELOC_UNSIGNED` slots, bucket them by destination 16 KiB output page (counting sort by page index, then sort within a page by offset). Chain packing and chain encoding then become per-page tasks with no global sort.
- **Import table (D7):** built here from canonical tuples (see D7), so chain encoding in Pass 4 needs only a lookup, never a mutation.
- **`resolved[]` tables (D8)** are written here, sequentially per file.
- Header/LINKEDIT fixed point: unchanged. Precompute signature sizing from `sig_off` as the TDD describes. The one re-run trigger (chain multi-start overflow) is rare; assert the rerun count ≤ 1 in CI.

### 4.4 Pass 4 — fused tile emit

The central structural change for raw speed. Instead of "copy everything, then fix up, then encode chains, then hash everything", process the output in **tiles of one 16 KiB page (or a small multiple, e.g. 64 KiB, tuned)** while the bytes are in L1/L2:

```rust
// per tile, executed by a rayon task; tile = one fixup page group
fn emit_tile(t: &Tile, ctx: &EmitCtx, out: &mut [u8]) {
    // 1. copy: CopyRuns intersecting this tile (src mmap -> out), memcpy; zero fill is free (anon mmap)
    for run in ctx.runs_in(t) { out[run.dst_in(t)].copy_from_slice(run.src(ctx)); }
    // 2. relocate: ADRP/ADD/LDR/BR26/SUBTRACTOR/GOT/TLV for atoms in this tile
    for atom in ctx.atoms_in(t) { apply_relocs(atom, &ctx.files[atom.file].resolved, out); }
    // 3. chains: page-local by construction -> encode rebase/bind words, no cross-tile data
    encode_chain_page(&ctx.fixups_for_page(t.page), &ctx.import_table, out);
    // 4. hash: every 4 KiB sub-page of this tile is final unless it is header/LINKEDIT tail
    for sp in t.subpages_final() { ctx.hashes[sp.index] = sha256(&out[sp.range()]); }
    // 5. hand finalized range to the writers
    ctx.output.queue_flush(t.file_range());
}
```

Why this works:
- Chains never cross a page (TDD §7.4), so chain encoding is tile-local. With D7, nothing in step 3 depends on another tile.
- Relocation application reads only the file-local `resolved[]` table and the atom's own slot range.
- Output bytes are touched once while hot, instead of three times (copy, fixup, hash) from DRAM.
- Writers receive finalized pages earlier, so Pass 5 overlaps more of Pass 4.

Tile ordering: schedule tiles from `__TEXT` and `__DATA_CONST` first (largest, no late dependencies); the header page, LINKEDIT chunks, and the signature are produced by dedicated tasks that start as soon as their inputs exist. The header page (load commands) is final only after Pass 3, but its hash is computed last because `LC_CODE_SIGNATURE`/LINKEDIT sizes are in it. Tiles that overlap two output sections (section boundaries inside a page) are processed by the task owning the lower section, with the upper section's slice deferred to a "seam" list processed after both finish.

LINKEDIT builders (symtab, strtab, export trie, function starts, data-in-code, compact-unwind index, debug-map stabs) run as independent parallel tasks, sized in Pass 3 so their file ranges are known. Per-file symtab emission uses prefix sums over per-file symbol counts. Strtab copies name bytes from input mmaps by range.

### 4.5 Pass 5 — writer pool

Keep the TDD / mold-macho design (4 writers, 8 MiB blocks, 16 KiB page-granular, edge pages deferred). Additions to evaluate (spike **S1**):

- Create the output with `ftruncate` to final size and `fcntl(F_PREALLOCATE)` to avoid extent growth during writes (the macOS analogue of Linux `fallocate`).
- Writer count and block size sweep on M-series Pro/Max/Ultra (writers sit in the kernel; more may help on Ultra-class parts).
- `F_NOCACHE` is probably wrong for dev loops (the next step is exec, which wants the file in cache) but measure it for CI/artifact workloads.
- Writer threads are I/O-bound; bias them toward E-cores via a lower QoS so P-cores stay on hashing and relocation work.
- Order of queueing: send blocks in file order when possible, to help the filesystem coalesce.

---

## 5. Hot-path rules (enforced in code review and lint)

1. **No allocation in a `par_iter` body** except into pre-sized per-task arenas.
2. **No pointers in metadata records.** 32-bit ids and offsets only (TDD §6.1).
3. **No per-element hash lookups after Pass 1.** Everything downstream indexes arrays by id.
4. **No locks in Passes 1–4.** The synchronization inventory in TDD §10.2 is the entire allowed set; any addition needs a design note.
5. **One pass over each byte** where possible (tile emit). If a second pass is needed, justify it in a comment with the measured cost.
6. **Struct-of-arrays for anything iterated over more than 10⁵ times**; hot fields separated from cold fields (TDD §6.2).
7. **Every parallel loop has a granularity**: minimum items per task chosen so task overhead < 1% (rayon `with_min_len`), and a maximum so one task is < ~2% of the pass.
8. **Determinism is a performance feature**: nondeterministic output blocks caching and incremental work (Section 7), so a determinism regression is a perf regression.
9. **`unsafe` is allowed only in `pgr-emit` and `pgr-format`**, wrapped in small audited functions with `debug_assert!`s and Miri/ASan CI.

---
## 6. Apple Silicon and macOS platform tuning

| Topic | Decision | Notes |
|---|---|---|
| Core topology | Rayon pool sized to P-cores; writers and background pre-fault on lower QoS | Pass barriers make E-core stragglers costly. Spike S4 compares P-only vs all-cores on base, Pro, Max and Ultra parts |
| 16 KiB pages | Tiles, writer blocks and fixup pages all align to 16 KiB | Already a TDD invariant; here it also sets the unit of parallel work and the unit of dirtiness for incremental mode |
| Page-fault cost | Output buffer is anonymous `mmap`, pre-faulted by a background task as soon as the size is known (end of Pass 3), and by tile tasks just ahead of their writes | 1 GiB is about 65 000 faults at 16 KiB. No explicit superpage API exists for Apple Silicon, so reduce fault cost by overlap and by reusing the buffer in resident mode |
| Input access | Default `mmap` + `madvise(MADV_WILLNEED)` on ranges known to be read (symtab, strtab, reloc tables) | Spike S2 compares against `pread` into per-thread arenas; on macOS this is not obviously a win either way, so it is a measurement, not a belief |
| SHA-256 | `sha2` crate with ARMv8 SHA-2 intrinsics on aarch64 hosts, SHA-NI on x86 Linux hosts; runtime feature detection | Required algorithm for the CodeDirectory page hashes. BLAKE3 is *not* an option for these hashes (mold uses it elsewhere, but the CodeDirectory requires SHA-256/SHA-1). It may be used for internal cache keys |
| Output file | Fresh vnode every time (unlink first), `pwrite` only, never a writable mapping | TDD §2.1.3, risk R1. Keep the CI lint that forbids `MmapMut` in `pgr-emit` |
| Executable replacement | Write to a temp name in the destination directory, then `rename` over the target | A running executable cannot be overwritten in place on macOS (the write is refused), so a new file is the correct path anyway; this also makes failed links atomic |
| Exit | `_exit` after writers join and the signature is closed | D11 |
| Cross-hosting | Linux host: `fallocate`, `MADV_HUGEPAGE` on input mmaps, same writer pool | One output path for both hosts (TDD decision) preserves testability |

---

## 7. Avoiding work: caches, resident mode, incremental relinking

This is where the order-of-magnitude wins live. It is ordered by increasing complexity and by decreasing safety margin; each stage is independently shippable.

### 7.1 Stage A — Compiled caches for stable inputs (Year 2 H1)

Most inputs in a developer loop never change between links: the SDK `.tbd` files, third-party static libraries, vendored dependency archives, dependency `rlib`s.

- **Parsed Object Image (POI):** a flat, mmap-able binary sidecar per input file or archive member containing exactly what Pass 1 would produce: section table, atom boundary arrays, external symbol records with precomputed name hashes, per-atom relocation ranges, and name byte ranges. Loading is a single mmap plus pointer-free validation; Pass 1 becomes near-zero for cached files.
- **Frozen `.tbd` exports:** compile each `.tbd` (and re-export chain) into a sorted or perfect-hash export set with ordinals resolved. Startup for libSystem drops from text parsing to an mmap.
- **Cache key:** `(device, inode, size, mtime_ns, ctime_ns)` plus a content hash on demand (`--cache-verify`). Archive members key on `(archive key, member offset)`. A cache entry also records the `pgr` format version and any parse-affecting flags.
- **Location and safety:** per-user cache directory, content-addressed, size-bounded with LRU eviction, written atomically (write temp, rename). The cache is an optimization only: a corrupt or stale entry must be detected and silently re-parsed. A `--no-cache` flag and a CI job that compares cached vs uncached output byte-for-byte keep it honest.
- **Why before a daemon:** it is stateless between processes, so it is simple to reason about, safe under build-system parallelism, and captures a large share of the benefit.
- **Expected effect *(hypothesis)*:** removes most of Pass 0/1 for the unchanged majority; relink dominated by the changed objects plus Passes 2–5. The Year 2 relink gate (≥ 2× ld-prime) relies only on this stage.

### 7.2 Stage B — Resident link server (Year 3 H1)

An optional per-project daemon (`pgrd`, unix-domain socket, started on demand by `pgr`) that keeps across links:

- the interner and global symbol table for unchanged files;
- parsed state (POIs already in memory, no even-mmap cost);
- the output buffer (already faulted), so the page-fault cost disappears;
- the previous layout, for Stage C.

Constraints: the daemon must be **optional and transparent** (`pgr` falls back to one-shot if it cannot connect), must never change output bytes relative to a clean link in deterministic mode, and must key all state by file identity so concurrent builds are safe. It idles out after a timeout. Memory ceiling is configurable.

### 7.3 Stage C — In-place incremental relink with clone-and-patch output (Year 3)

Goal: relink time proportional to the size of the change, not the size of the binary. Target: < 100 ms for a one-function change in a 1 GiB output *(hypothesis)*.

**Layout stability.** Atom placement reserves slack so a changed atom usually fits where it was:
- per input-section group, leave configurable slack (default ~10% of text, ~5% of data, tuned from real edit histories);
- keep atom order stable (previous order is the tiebreaker);
- when a section overflows its slack, fall back to a full re-layout of that segment, and if that moves anything outside it, to a full clean link. The fallback must always be available and always correct.

**Change propagation.**
1. Detect changed inputs (by key, as in Stage A).
2. Re-parse only those; diff atom sets (added, removed, modified).
3. Re-resolve only affected symbols (changed owners). A **reverse reference index** (symbol → referencing atoms), built during the previous full link, tells which relocations must be reapplied.
4. Patch: rewrite changed atoms; reapply relocations in dependents; fix up chained fixups on touched pages only (chains are page-local, so a page's chain can be rebuilt independently; update that page's `page_start`).
5. Update the import table with an insertion-stable scheme (stable ordinals assigned by canonical order with room for appended entries; this is why D7 matters now).
6. Rebuild LINKEDIT pieces that changed (symtab entries for changed atoms, function starts, unwind index pages) — each is a local edit when slack exists.

**Output path.**
- `clonefile()` the previous output (APFS copy-on-write: instant, no data copied) to a new file → new vnode.
- `pwrite` only the dirty 16 KiB pages into the clone.
- Re-hash only the dirty 4 KiB pages; rebuild the CodeDirectory. To keep the signature's own offset stable, size the signature region with slack so `nblocks` growth does not move it, or accept a LINKEDIT-tail rewrite.
- `rename` over the destination.

**Required spikes before committing:** S1b (a clone + `pwrite`d file passes exec-time signature validation — the TDD's taint concern is about *writable shared mappings*, which this path never creates, but it must be proven on real hardware), S8 (cost of `clonefile` + dirty-page `pwrite` vs full write on APFS at 1 GiB), and S9 (distribution of real edit sizes in large projects to size the slack).

**Determinism policy for incremental mode.** Incremental output is *semantically* equal to a clean link but not necessarily byte-identical (slack and stable ordering change layout). Therefore:
- clean links remain bit-deterministic (TDD §4.3), always;
- incremental mode is explicit opt-in (`--incremental`) for development builds;
- `--incremental-verify` re-links clean and compares semantically with `pgr-verify` (dyld-simulated fixup values, symbol maps, unwind tables). CI runs this on every incremental test.

### 7.4 What not to build

- No attempt at hot-patching a running process (out of scope; interacts badly with code signing and AMFI).
- No distributed/remote link caching until the local caches are mature. Revisit in the horizon (Section 10.5).

---

## 8. Building `pgr` itself for speed

- Release profile: `opt-level=3`, fat LTO, `codegen-units=1`, `panic=abort`, `debug=line-tables-only` for profiling builds.
- PGO (`cargo-pgo` or equivalent) trained on the benchmark corpus; ship the profile in-repo and refresh monthly. Expect 5–15% on parse and relocation loops *(hypothesis)*.
- Post-link layout optimization (BOLT or equivalent) is evaluated in Year 2; low priority and not available for Mach-O in every toolchain — verify before planning around it.
- Target CPU: baseline `apple-m1` for the macOS binary (NEON, crypto extensions); a generic aarch64 + runtime-detected SHA fallback for Linux arm64; x86-64-v3 plus SHA-NI detection for Linux x86.
- Allocator: `mimalloc` (TDD §10.4). Re-measure on macOS in Year 1; the paper's numbers are for Linux.
- Startup: no global constructors, no lazy statics on the hot path, no locale, no logging initialization unless enabled. Startup floor is a tracked metric (Section 2.1).
- Binary size is irrelevant except where it hurts startup (page faults on a cold binary): keep the hot path contiguous and avoid heavy dependencies in `pgr-driver`.

---

## 9. Measurement infrastructure

Nothing in this document is real until it can be measured. This is built in Phase P0 and gates all later work.

### 9.1 Hardware

| Rig | Purpose |
|---|---|
| Apple Silicon, small (e.g. 4P+4E) | Low core-count scaling, laptop-class thermal behavior |
| Apple Silicon, Pro/Max class (8–12 P-cores) | Primary development benchmark |
| Apple Silicon, Ultra class (16–24 P-cores), if obtainable | Scaling, writer-count tuning |
| Linux x86-64 and aarch64 build hosts | Cross-link throughput, CI scale |

Cloud Apple Silicon runners are acceptable for CI but too noisy for fine-grained decisions; keep at least one dedicated machine for the decision-making benchmarks.

### 9.2 Corpus and baselines

| Corpus | Why it is in the set |
|---|---|
| `hello` and a 50-link "many tiny links" script | Startup floor; test-suite style workloads |
| ripgrep (Rust, release and debug) | Rust objects, `rlib` archives, `-dead_strip` |
| mold/LLVM-sized C++ debug build (~1 GiB output) | The headline large-debug benchmark; stabs, unwind, many symbols |
| Chromium-class or Firefox-class debug link, if obtainable | Scaling to 10⁷ symbols |
| Single giant object (unity/LTO-style, ≥ 500 MB) | Skew and intra-file splitting |
| Archive-heavy (hundreds of static libs, most members unused) | S7 archive strategy |
| ObjC/Swift GUI app with many frameworks | `.tbd` chains, ObjC sections, ordinals, `-order_file` |
| Dylib with 10⁵+ exports | Export trie cost |

Baselines to run on every rig: ld-prime (Apple's current `ld`), `ld64.lld`, and mold's Mach-O backend. zld is archived and not a meaningful baseline. Record exact tool versions and flags; commit the harness.

### 9.3 Continuous performance CI

- **Per-PR (noise-resistant):** instruction counts and cache-miss counts on a fixed corpus (`perf stat` or valgrind-class tooling on Linux), plus allocation counts per pass. A PR that regresses any pass's instruction count by > 3% needs an explicit waiver.
- **Nightly (wall-clock, dedicated hardware):** full corpus, 10 runs, median and p95, vs baselines. Results stored and charted.
- **Budgets enforced from `--time` JSON output:** per-pass wall, thread-seconds, parallel efficiency; fail the build if the single-threaded fraction exceeds 15% (except flush) or parallel efficiency drops below 70% on Passes 1/3/4.
- **Determinism:** double-link byte-equality on every PR (TDD §4.3); cached-vs-uncached equality once Stage A lands.
- **Correctness stays first:** performance jobs never gate on unverified output — every benchmark link is also run through `pgr-verify`.

### 9.4 Profiling toolbox

`--time` (per pass table + JSON), `--trace` (Chrome-trace-format timeline per thread, so stragglers and idle gaps are visible), `samply`/Instruments on macOS, `perf` + flamegraph on Linux, and a "thread utilization" chart generated by CI for the headline corpus.

---
## 10. Multi-year roadmap

Principles:
1. **Verifier before linker, benchmark before optimizer** (TDD's verifier-first stance, extended).
2. **Performance-shaped from M1.** The data structures that determine speed (interner, SoA tables, arenas, zero-copy parse, atomization, disjoint-range emit) are built that way the first time. M4 becomes "tune and fuse", not "rewrite".
3. **Every milestone has a correctness gate and a performance gate.** Neither ships without the other.
4. **Compat is a feature stream, not a phase.** Real-world flags and sections are added continuously, each with a fixture.

### 10.1 Overview

| Phase | Months | Theme | Headline deliverable |
|---|---|---|---|
| P0 | 0–2 | Measure and de-risk | Baseline report, spike results, perf-CI skeleton, locked targets |
| Year 1 H1 | 1–8 | Correct images, perf-shaped core | M0–M3: verifier, static, dynamic, dylibs |
| Year 1 H2 | 9–12 | Fast and real-world | M4 speed pass, M5 real-world C/C++/ObjC/Rust links; **v0.5 beta** |
| Year 2 H1 | 13–18 | Scale and ecosystem | M6: ICF, thunks, ObjC stubs, Swift, legacy fixups, **Stage A caches** |
| Year 2 H2 | 19–24 | Production | M7: build-system integration, runtime validation on macOS, hardening; **v1.0** |
| Year 3 H1 | 25–30 | Resident + incremental foundations | M8: resident server, reverse index, slack-aware layout |
| Year 3 H2 | 31–36 | Incremental GA and platform breadth | M9: incremental relink GA; M10: arm64e, x86_64 macOS |
| Year 4+ | 37+ | Horizon | Section 10.5 |

### 10.2 Phase P0 — Measure and de-risk (Months 0–2)

Deliverables:
- Benchmark rigs (Section 9.1) and the corpus (Section 9.2), with a committed harness and baselines for ld-prime, `ld64.lld`, mold-macho.
- Spike results S1–S6 (Section 11), each with a written decision.
- CI skeleton: build, rustfmt/clippy, ASan, `--time` JSON schema, nightly benchmark job (even if it only runs baselines).
- The speed-of-light model (Section 1.1) re-derived from measured numbers.

**Exit gate:** a one-page baseline report. Targets in Section 2.2 are either confirmed or rewritten. If ld-prime is within ~1.5× of the measured floor on the headline corpus, shift the primary headline metric to relink time (Section 7) and treat clean-link speedups as table stakes rather than the product.

### 10.3 Year 1 — Foundations to a usable fast linker

| Milestone | Month | Scope | Correctness gate | Performance gate |
|---|---|---|---|---|
| **M0** Verifier first | 3 | `pgr-format` raw structs and cursor; `pgr-verify` v1 (structural, segment contract, chain-walk simulation, signature recompute); three-opinion cross-check (pgr, `object`, LLVM tools); fuzz targets for the parsers | Verifier is green on lld-produced arm64 goldens that Peregrine did not make | Parser throughput benchmarked (GB/s) and recorded as the baseline for Pass 1 |
| **M1** Static hello, perf-shaped | 4 | Passes 0–5 minimal; direct `.o` inputs; **atomization (D1)**; hash-bin interner; SoA symbol table with CAS owner; zero-copy relocs (D5); anonymous-mmap output (D10); `pwrite` writers; ad-hoc signature; `--time`/`--trace` | Full verifier pass; double-link byte-identical; `llvm-otool -l` diff vs golden clean | Startup floor ≤ 5 ms; no allocation in Pass 1–4 hot loops (counted in CI); perf CI per-PR active |
| **M2** Dynamic executable | 6 | `.tbd` parse (v3/v4); `LC_LOAD_DYLIB` ordinals; two-level resolution; GOT/stub synthesis; chained fixups rebase+bind with **canonical import order (D7)**; minimal export trie; indirect symbols; compat checklist D13 started | Links `printf("hi\n")`; verifier dyld-simulation matches lld values slot-for-slot; `-flat_namespace` works | Pass 2 and Pass 3 meet parallel-efficiency budget on the 100 MB corpus |
| **M3** Dylibs and bundles | 8 | `-dylib`, `-bundle`, install names, full export trie, re-exports, `-exported_symbols_list`, `LC_RPATH` | Dylib + executable pair verifier checks; trie diff vs ld64 golden clean | Export trie build < 10 ms for 10⁵ exports (or parallelized if not) |
| **M4** Speed pass | 10 | **Fused tile emit (4.4)**; copy-run coalescing; `resolved[]` de-indirection (D8); LPT scheduling and giant-object splitting; P-core pool (D9); background pre-fault; fused hashing (D14); writer tuning (S1); PGO build | Byte-identical to pre-fusion output on the full corpus (the refactor must not change bytes) | **G1:** ≥ 5× vs `ld64.lld` on the 100 MB corpus at 16 threads; ≥ 1.5× vs ld-prime on the large debug corpus; single-threaded fraction ≤ 15% except flush; peak RSS ≤ 2.5× output |
| **M5** Real-world links; **v0.5 beta** | 12 | Compact-unwind synthesis (D2); stabs/debug map (D3); `__cstring`/literal merging (D4); `-dead_strip` and `-order_file` (D12); `-filelist`, `-framework`, `-sectcreate`, `-rpath`, remaining D13 flags; archive strategy decision (S7) | ripgrep, a C++ project using exceptions, an ObjC/Cocoa sample, and a Rust app link, verify, and (on macOS hardware) run; lldb shows source lines via the debug map | Perf gates from M4 still hold with the new features on; dead-strip adds ≤ 30% to the link on the large corpus |

Year 1 exit: usable by early adopters as a drop-in for debug builds of C/C++/Rust/ObjC; Linux-hosted cross-linking works; macOS hosts supported as a normal `ld`.

**Critical path:** M0 → M1 → M2 → M4 → M5. M3 can run alongside M4 on a second engineer. The main schedule risks are (a) the verifier taking longer than three months (mitigate by shipping structural checks first and adding the dyld simulation incrementally), and (b) compat surface growth in M5 (mitigate by cutting to a fixed, fixture-backed flag list).

### 10.4 Years 2–3 — Scale, production, and beyond a full link

| Milestone | Month | Scope | Correctness gate | Performance gate |
|---|---|---|---|---|
| **M6** Scale and ecosystem | 18 | ICF (parallel color refinement); branch thunks/veneers for `BR26` overflow (> 128 MiB text); ObjC stubs and selector/class handling; Swift sections and flags; `LC_DYLD_INFO` legacy fallback for older deployment targets; LTO object pass-through; **Stage A caches (7.1): POI + frozen `.tbd`** | ICF preserves determinism; cached vs uncached output byte-identical on full corpus; thunk placement verified by a branch-range checker in `pgr-verify` | Relink ≥ 2× ld-prime with cache warm; ICF ≤ 25% added wall on the large corpus; `.tbd` startup cost < 1 ms |
| **M7** Production; **v1.0** | 24 | `ld`-compatible driver tested through clang `-fuse-ld`, Xcode and `xcodebuild`, cargo, CMake/Ninja; **runtime validation on macOS hardware** (run the produced binaries, `codesign -v`, dyld load, in CI); fuzzing at scale; compatibility suite adapted from ld64/lld test inputs; docs and migration guide; versioned cache format | Compat suite ≥ 98% pass on the agreed list; no known miscompiles; fuzzers clean for 30 CPU-days | **G2:** ≥ 8× vs `ld64.lld`, ≥ 3× vs ld-prime clean; startup ≤ 3 ms; nightly perf stable ±3% |
| **M8** Resident + incremental foundations | 30 | `pgrd` resident server (7.2); persistent interner/symbol state for unchanged files; reverse reference index recorded at full links; slack-aware layout with fallback; insertion-stable import table; clone-based output proven (S1b, S8) | Resident output byte-identical to one-shot in deterministic mode; server crash/restart never corrupts output; concurrent-build safety tests | Resident relink ≥ 5× ld-prime; page-fault cost eliminated (buffer reuse) |
| **M9** Incremental GA | 34 | In-place incremental relink (7.3): change propagation, patch, per-page chain repair, dirty-page rehash, CodeDirectory rebuild, clone-and-patch output; `--incremental` / `--incremental-verify`; fallback to full link on any invariant break. **v1.2.0 ships tier 1** (`pgr-emit::incremental`): the versioned link record, the span-diff patch planner over the frozen skeleton, slack anchors, the clone-and-patch output with the merged-hash CodeDirectory rebuild, the byte-identity contract, and the driver flags; per-symbol change propagation (the reverse-index tier), the segment-relayout patch tier and the 10⁴-sequence randomized gate remain GA scope | `--incremental-verify` equals clean link semantically across 10⁴ randomized edit sequences on the corpus; no stale-signature or stale-fixup failures at runtime on macOS hardware. **Tier-1 shipped gates:** the patched file is byte-identical to the full emit of the same plan (tests + per-link audit); every fallback path lands on the full link; bytes written ∝ change size (1.2% of an 8 MiB image per one-function edit, bench-recorded) | **G3:** relink < 100 ms for a one-function edit at 1 GiB output; ≥ 10× vs ld-prime relink; bytes written ∝ change size |
| **M10** Platform breadth | 36 | arm64e (auth rebase/bind, `DYLD_CHAINED_PTR_ARM64E*`); x86_64 macOS (4 KiB constants, same tree); iOS/tvOS/watchOS/visionOS platform plumbing; `-r` relocatable output | Verifier extended for each target; golden pairs per target | No regression on arm64 targets; each new target meets its own startup and clean-link gates |

Staffing sketch for 3 engineers (adjust to reality):
- **Engineer A — core pipeline:** layout, emit, fused tiles, incremental (Y3).
- **Engineer B — format and compat:** verifier, Mach-O features, flag surface, build-system integration.
- **Engineer C — performance and infrastructure:** benchmark rigs, perf CI, caches, resident server, PGO, platform tuning. This role starts in P0; it is the one most often under-resourced and the one this plan depends on.

### 10.5 Year 4+ horizon (not committed)

- **Parallel debug-symbol packaging.** A real edit–build–run loop on macOS also pays for `dsymutil` after link. A parallel, cache-aware dSYM generator (or an integrated debug-map-to-dSYM stage) may matter more to end users than another 2× in the linker.
- **Distributed or shared caches** of POIs for CI fleets.
- **Better LTO integration** beyond pass-through (ThinLTO coordination, symbol-level parallelism across the LTO boundary).
- **Link-time layout optimization** from profile data (function ordering without hand-maintained order files).
- **Upstreaming** of reusable pieces (`pgr-format`, `pgr-verify`, chained-fixup encoder) to the wider ecosystem.

---

## 11. Spike register (Phase P0 and early Year 1)

| ID | Question | Method | Decision rule | By |
|---|---|---|---|---|
| S1 | Best write strategy on APFS: writer count, block size, `F_PREALLOCATE`, `F_NOCACHE`, QoS | Sweep on three rigs with a synthetic 1 GiB output | Pick per-machine-class defaults; adopt anything ≥ 10% faster than the TDD defaults (4 × 8 MiB) | Month 2 |
| S1b | Does a `clonefile`d file modified with `pwrite` pass exec-time signature validation and run? | Clone a signed binary, patch dirty pages, re-sign page hashes, exec on hardware | Must pass reliably across macOS versions in use, or Stage C's output design changes | Month 2 (blocks M8) |
| S2 | `mmap` + `MADV_WILLNEED` vs `pread` into arenas for input access on macOS | Parse-only benchmark on the corpus, cold and warm cache | Choose the faster per file-size class; keep both behind one trait if they split | Month 2 |
| S3 | SHA-256 throughput per core and end-to-end hashing cost when fused into the tile loop vs a separate pass | Microbench + prototype tile loop | Fuse if ≥ 10% win or neutral with lower memory traffic | Month 3 |
| S4 | P-cores only vs all cores for the compute pool; effect of QoS classes | Pass-level scaling curves on base/Pro/Max/Ultra | Default to the config with the best median and p95 on Pro/Max | Month 3 |
| S5 | Pre-fault strategies for the output buffer | Compare no pre-fault, background fault, per-tile fault-ahead | Keep the strategy that shortens time-to-first-queued-block | Month 4 |
| S6 | Is a canonical import order (D7) acceptable to dyld and tooling? | Build ordering variants, load on hardware, diff against ld64 behavior | Adopt canonical order if dyld/tooling accept it; otherwise keep first-use order and compute it in Pass 3 (still no emit-time dependency) | Month 5 |
| S7 | Archive strategy: eager parse-all vs ranlib-guided lazy members | Archive-heavy corpus | Adopt lazy if ≥ 20% faster and semantics (`-ObjC`, `-force_load`, `-all_load`) fully preserved | Month 11 |
| S8 | Cost of `clonefile` plus dirty-page writes vs full writes at 1 GiB; behavior on non-APFS volumes | Measurements, including fallback paths | Defines whether Stage C's output design is worth it and its fallback behavior | Month 24 |
| S9 | Real edit-size distribution (functions/objects changed per rebuild) in large projects | Instrument build logs of several real projects | Sets slack percentages and the incremental design envelope | Month 24 |
| S10 | Name hash function choice on real symbol-name distributions | Microbench ahash-fixed vs rapidhash vs foldhash on C++/Swift/Rust names | Pick best throughput with acceptable collision behavior | Month 2 |
| S11 | Tile size (16 KiB, 64 KiB, 256 KiB) in the fused loop | Sweep inside the prototype | Choose by throughput and by time-to-first-queued-block | Month 9 |

---

## 12. Performance-specific risk register (adds to TDD §13)

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| P1 | ld-prime is already near the write-bound floor on large links, capping the clean-link speedup | Medium | High (headline claim) | P0 baseline decides the headline metric; relink and cache work (Section 7) is the differentiator regardless |
| P2 | The kernel/APFS write path dominates and cannot be tuned further | Medium | Medium | Reduce bytes written (Stage C), overlap fully, measure per-machine defaults (S1) |
| P3 | Apple Silicon hardware access is limited or noisy | Medium | High | P0 requirement; at least one dedicated machine; cloud runners only for coarse CI |
| P4 | Incremental relink complexity and subtle staleness bugs (stale fixups, stale hashes) | High | High | Staged delivery (cache → resident → in-place), `--incremental-verify`, randomized edit-sequence tests, always-available full-link fallback, opt-in flag until proven |
| P5 | Cache invalidation errors produce wrong output silently | Medium | High | Cached-vs-uncached equality CI, strong keys, versioned format, `--cache-verify`, cache treated as optional |
| P6 | Apple changes dyld, signing or linker conventions (the fate of zld, TDD §2.3) | Medium | High | Small owned format surface; macOS-hardware CI across the current and previous major OS releases; track Apple's open-source dyld and cctools-style sources; golden refresh process |
| P7 | Scope creep from ld64 compat flags drains performance work | High | Medium | Fixed, fixture-backed flag list per milestone; every flag has an owner and a test; "won't support" list published |
| P8 | Parallel efficiency decays as features land (dead-strip, ICF, debug map) | Medium | Medium | Per-pass budgets enforced in CI (Section 9.3); regressions need waivers |
| P9 | `unsafe` in emit introduces memory-safety bugs in a tool that processes hostile inputs | Medium | High | Confined to two crates, audited wrappers, ASan/Miri CI, continuous fuzzing of parsers and the emit path on mutated inputs |
| P10 | Bus factor on the emit/fixup core | Medium | Medium | Design notes per pass; pair on M4; verifier doubles as executable specification |

---

## 13. Decisions I made and questions for you

**Decisions made in this document (override any):**
1. Perf CI and perf-shaped data structures start at M1, not M4.
2. Atoms are symbol-delimited subsections (D1); this is a correctness-critical change to the TDD.
3. Import ordinals use a canonical order independent of fixup addresses, subject to spike S6 (D7).
4. The compute pool defaults to P-cores on Apple Silicon, subject to spike S4.
5. Caches (Year 2) come before the resident server (Year 3), which comes before in-place incremental relinking (Year 3).
6. The TDD's 5× vs ld-prime goal is a stretch target, not a Year 1 commitment.
7. Incremental output need not be byte-identical to a clean link; clean links always are.

**Questions that change the plan:**
1. Team size and whether Apple Silicon hardware (including a Pro/Max-class machine) is available from Month 0.
2. Primary users: developers' debug loops (favours Stage A–C and compat breadth), CI release builds (favours clean-link speed, ICF, dead-strip), or both. This reorders Year 2.
3. Minimum macOS/Xcode versions to support (decides how long the legacy `LC_DYLD_INFO` path and `-init_offsets` handling stay on the critical path).
4. Licensing and whether upstreaming pieces is acceptable; this affects how freely mold-macho behavior can be consulted versus reimplemented clean-room.

**Suggested first 30 days:**
1. Acquire/schedule hardware; assemble the corpus; run ld-prime, `ld64.lld` and mold-macho baselines.
2. Run spikes S1, S1b, S2, S10.
3. Start M0 in parallel: workspace, `pgr-format`, structural verifier against lld goldens.
4. Stand up `--time` JSON and the nightly benchmark job, even if it only measures baselines.
5. Write the atomization (D1) and compact-unwind (D2) design notes before any Pass 1 code, because they shape the core data model.

*Note on sources: the prior-art claims, mold paper figures and quoted behavior of mold-macho come from your TDD; I did not re-verify them against the upstream repositories. Timing estimates and speedup figures here are hypotheses to be replaced by P0 measurements.*

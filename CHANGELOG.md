# Changelog

All notable changes to Peregrine are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adopts [Conventional Commits](https://www.conventionalcommits.org/) for
release automation.
## [0.5.0] - 2026-11-06### Features
- **emit:** M4 fused tile emit (`build_image_fused`) — parallel 16 KiB
  tiles copy coalesced runs, apply relocations, encode chained-fixup
  words, place the `__LINKEDIT` chunks and hash the 4 KiB signature pages
  in one pass (perf doc §4.4, D14); UUID derives from the fused hash
  table, only page 0 re-hashes; parallel pre-fault of the zero-page-backed
  output buffer (D10); the pre-fusion M1–M3 body stays verbatim as the
  reference (`build_image`)
- **core:** M4 Pass 1 — LPT-scheduled parallel parse (longest input first
  on the shared compute pool) with giant-object splitting (inputs ≥ 64 MiB
  or ≥ 2²⁰ symbols decode their symtab in deterministic index chunks) and
  the parallel canonicalizing interner sort; `Parallelism::Serial` keeps
  the M1–M3 reference path (perf doc §4.1)
- **core:** D8 `resolved[]` de-indirection — per-file flat
  `ResolvedFile { syms, sects }` tables written once per layout fixed-point
  iteration; the relocation scan reads the file-local array and the M1–M3
  `addr_of`/`def_addr` map walks leave the hot path
- **core:** copy-run coalescing (perf doc §4.3) — `Layout.runs` merges
  pieces contiguous in input and output into one `memcpy`; coverage and
  disjointness gated
- **core:** shared compute pool (D9) — one process-wide rayon pool sized
  `PGR_JOBS` → `available_parallelism` (the macOS P-core default joins
  with the P0 rig, spike S4)
- **emit:** S1 writer pool — extent preallocation (`set_len`) plus a
  4-writer `pwrite` pool over disjoint 8 MiB blocks; fresh-vnode + fsync +
  atomic-rename contract unchanged
- **driver:** the fused pipeline becomes the default (`link_to_bytes`);
  `link_reference_bytes`/`link_reference_image` expose the pre-fusion
  reference for the M4 byte-identity gate and benches
### Performance
- **bench:** `pgr-emit/emit` gate — fused tile emit 1.59 ms vs reference
  2.18 ms for ~0.94 MiB signed images (1.37×, 605 vs 441 MiB/s) on the
  2-core dev sandbox; full-pipeline benches record fused vs reference on
  all corpora (bind-path links 1.10–1.11×; resolution-heavy static corpus
  is Pass 2/3-bound as before); `PGR_JOBS=1` scaling recorded
### Tests
- **emit:** ten fused-vs-reference byte-identity gates over every M3
  corpus shape (executables, dylibs, bundles, re-exports, export filters,
  flat namespace, `-no_fixup_chains`, `-no_adhoc`, wide multi-tile
  corpora); pooled-writer byte-exactness across 8 MiB block boundaries
- **core:** copy-run coverage/partition gates, parallel-vs-serial layout
  fingerprint equality, `resolved[]` table checks, giant-object chunked
  decode vs serial decode
- **driver:** M4 e2e gates — byte-identity with the reference pipeline,
  strict verifier + bundle/dylib contracts on fused outputs, fused
  double-link determinism

## [0.4.0] - 2026-11-06### Features
- **driver:** M3 CLI — `-dylib`/`-bundle` outputs, `-install_name`,
  `-current_version`/`-compatibility_version`, `-reexport_library`,
  `-exported_symbols_list`/`-unexported_symbols_list`,
  `-mark_dead_strippable_dylib`; Mach-O dylib inputs (`.dylib` scan for
  direct inputs and `-l` search); symbol-list files (one name per line,
  `#` comments)
- **core:** M3 layout — `OutputType` drives the image base (0 for
  dylibs/bundles, no `__PAGEZERO`), the load-command set (no `LC_MAIN`/
  `LC_LOAD_DYLINKER`; `LC_ID_DYLIB` for dylibs) and header flags
  (`MH_NOUNDEFS` iff no undefineds, `MH_PIE` exec-only,
  `MH_NO_REEXPORTED_DYLIBS`, `MH_DEAD_STRIPPABLE_DYLIB`); export filters
  hide externals as `N_PEXT` locals; local definitions shadow re-exports
- **core:** range-partition export-trie builder — multikey quicksort over
  `(name, index)` (deterministic, prefix-skip), compressed edges created
  exactly once, packed-row offset fixpoint from a 4-byte upper bound,
  allocation-free serialization; REEXPORT terminals (ordinal + imported
  name); 8–11× the M2 builder (see BENCHMARKS)
- **verify:** dylib/bundle contract checks (`LC_ID_DYLIB` presence,
  `MH_PIE` sanity, version ordering), REEXPORT trie-node validation with
  re-export-aware exports, and the M3 **pair gate**
  `verify_dylib_pair` — replays the executable's chained binds the way
  dyld does and asserts every two-level bind into the dylib resolves to a
  name its trie exports
- **format:** total export-trie walker (re-export nodes, cycle/offset
  rejection) and `LC_REEXPORT_DYLIB` classification
- **emit:** chain words at `vaddr − image_base`; ad-hoc signature carries
  `execSegFlags = CS_EXECSEG_MAIN_BINARY` only for executables
### Performance
- **bench:** export-trie build gate — 31.5 ms for 10⁵ exports vs 363 ms
  for the legacy M2 builder on the dev sandbox (11.5×); legacy builder
  kept verbatim in the bench as the measured baseline
- **core:** hash-set import dedup and hash-map indirect-symbol lookup
  replace two O(n²) scans
- **bench:** `-dylib`/`-bundle` output-kind link benches
### Tests
- **driver:** M3 e2e gates — strict-verified dylib/bundle outputs, the
  pair gate over a scanned dylib binary, re-export trie shape, export
  filters (`N_PEXT` symtab + trie exclusion), deterministic double-link

<!-- generated by git-cliff -->

## [0.3.0] - 2026-11-05### Continuous Integration
- Parse_tbd fuzz target + got/tbd corpus seeds (ab3d31f)
### Documentation
- M2 README gates + D13 compat checklist; version 0.3.0 (659f4bc)
### Features
- **driver:** M2 dynamic link CLI — tbd inputs, -l/-L, flat namespace (b3c275b)- **verify:** Export-trie walk for LC_DYLD_EXPORTS_TRIE (c8a50fa)- **emit:** Synthetic slot pieces + indirect symbol table chunk (1a1edd1)- **core:** M2 passes 1-3 — GOT/stub synthesis, binds, import table, trie (4732cf2)- **core:** Two-level resolution, dylib rank, GOT-load relocations (3d3fc9a)- **fixtures:** LLVM single-segment object convention, GOT relocations (d3f6e39)- **format:** .tbd v3/v4 stub parser, unsigned bind-word addend codec (585c30d)
### Performance
- **bench:** Dylib-linked bind-path baseline (M2) (34fc15e)
### Tests
- **driver:** M2 e2e gates — printf-from-tbd, flat namespace, lld golden (14fe25c)

<!-- generated by git-cliff -->

## [0.2.0] - 2026-11-05

### Features
- **driver:** M1 static hello-world link pipeline: ld64-compatible option
  surface (`-o -arch -platform_version -e -static -fixup_chains -adhoc
  -headerpad -segalign`), Pass 0 mapping and the Pass 1–5 driver loop
- **core:** Passes 1–3: arm64 relocatable-object parser (pair-resolving
  relocation decode), canonicalizing interner, Mach-O precedence resolution
  (strong > weak > common, coalescing), §8 layout engine (16 KiB congruence,
  constant-delta segments, `__LINKEDIT` chunk order), §7 chained-fixup
  planner (stride-bounded packer, rebase-only payload, `__chain_starts`
  static mirror) and the fully-resolved patch plan
- **emit:** Passes 4–5: single-allocation output buffer, arm64 immediate
  patching (ADRP/imm12/BR26, subtractor writes), chain-word encoding,
  `__LINKEDIT` assembly, two-pass content-derived UUID, ad-hoc SHA-256
  signature, atomic page-granular writer
- **verify:** `__chain_starts` mirror-vs-payload agreement check and the
  canonical segment-order check for executables
- **fixtures:** deterministic arm64 relocatable-object (`MH_OBJECT`)
  builder with clang-convention symtab grouping and relocation tables
- **driver:** end-to-end link benchmark (small/large corpora) recorded as
  the M4 baseline

### Continuous Integration
- Fuzz schedule extended with the `link_object` target (Pass 1 parser +
  Pass 2/3 pipeline) and object seeds in the fuzz corpus

## [0.1.0] - 2026-11-05### Bug Fixes
- **format:** Panic-free casts on misaligned mutated input (a5e3a4f)
### Continuous Integration
- Fmt/clippy/test/doc/bench gates, fuzz schedule, git-cliff release pipeline (c3234fa)
### Features
- **verify:** M0 verifier v1 with chain-walk simulation (408eb90)- **fixtures:** Deterministic Mach-O image builder (eb69c00)- **format:** Zero-copy Mach-O primitives, cursor and codecs (5ccacc8)
### Performance
- **bench:** Parser-throughput baseline (GB/s) (d80515d)
### Refactor
- **fixtures:** Bundle fixup-payload inputs into FixupContext (f583287)

<!-- generated by git-cliff -->

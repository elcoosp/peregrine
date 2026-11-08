# Changelog

All notable changes to Peregrine are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adopts [Conventional Commits](https://www.conventionalcommits.org/) for
release automation.

## [1.2.0] - 2026-11-08

### Features

- **emit:** M9 in-place incremental relink engine (architecture doc §10.4
  row M9, §7.3 Stage C tier 1) — the new `pgr-emit::incremental` module
  records a full link's state (`LinkRecord`: the emit plan's byte-producing
  spans with per-tile-piece SHA-256 digests, the frozen skeleton, the
  signature's final page-hash table) into a versioned, checksum-framed,
  pointer-free sidecar; plans the next relink by diffing the new plan's
  spans against the record (dirty 16 KiB tiles + the §7.3 skeleton gate);
  and patches the output in place — clone the previous image (APFS
  copy-on-write via `fclonefileat` on macOS, `copy_file_range` on Linux),
  `pwrite` only the dirty tiles, rebuild page 0 with the derived `LC_UUID`,
  re-sign from the merged hash table (recorded hashes for clean pages,
  recomputed for dirty ones), rename. **Contract: the patched file is
  byte-identical to the full fused emit of the same plan** — gated in
  tests, auditable per link
- **emit:** the planner's fallback ladder — any skeleton move (section or
  segment placement, signature boundary, file size, identity), output
  change (missing, resized, or failed the sampled integrity gate), or
  record problem (missing, corrupt, foreign format) falls back to the full
  link, which is always available and always correct; when every content
  tile is dirty the planner declines on economics; §7.3 ladder tiers are
  classified through `SlackPolicy::fits` for the diagnostics
- **core:** M9 slack anchors (`LinkConfig::slack_anchor` +
  `SlackPolicy::pad_section_anchored`) — the previous link's reserved
  section sizes are a layout input, so a changed section keeps its on-disk
  place while its content fits (the in-place patch tier's precondition);
  an empty anchor list reproduces M8-c exactly (gated)
- **driver:** `-incremental` / `-no_incremental` / `-incremental-verify` —
  the relink loop over real files with the record sidecar
  (`<output>.pgr-inc`, `PGR_INCREMENTAL_RECORD`), silent fallbacks
  (`PGR_INCREMENTAL_DEBUG=1` prints reasons), and the audit gate
  (byte-identity against the full emit, then a strict `pgr-verify` pass on
  the patched bytes; a divergence never ships). `-incremental` implies
  slack layout for the whole link cycle so the cold full link reserves
  exactly what its record describes
- **daemon:** wire protocol v2 — the config carries the M9 slack anchors
  (a version mismatch stays a hard proto error; clients fall back to the
  one-shot link)

### Tests

- `pgr-core/tests/m9_foundations.rs` (4): anchored relink stability,
  overflow to the natural pad, anchor determinism, M8-c reproduction
- `pgr-emit/tests/incremental.rs` (9) + `pgr-emit::incremental` unit tests
  (16): the byte-identity contract across executables, dylibs, no-slack
  and unsigned corpora; growth within slack patches in place (LINKEDIT
  churn included — the skeleton freezes the segment extent, not the chunk
  offsets); no-op relinks; symbol-count and ladder fallbacks; the
  integrity gate's honest sampling; codec roundtrip and corruption
  tolerance (never a panic)
- `pgr-driver/tests/m9_incremental.rs` (11): the end-to-end loop — record,
  patch, no-op, every fallback path, verifier-clean patched output,
  `-incremental-verify`, option surface, error propagation

### Performance

- `pgr-driver/incremental` bench: full relink 16.4 ms vs incremental
  17.6 ms on the 8.53 MiB sandbox corpus (a wash — ext4 has no reflink, so
  the clone degrades to a full copy; recorded as-is), untouched relink
  13.3 ms, and the §7.3 bytes-written gate met: **1.2% of the image bytes
  per one-function edit** (105 KB: two dirty tiles + the CodeDirectory)

## [1.1.0] - 2026-11-08

### Features

- **daemon:** M8 resident link server — the new `pgr-daemon` crate ships
  `pgrd` (unix-domain socket, idle timeout, `--shutdown`) and the client
  `pgr -resident` uses. The session keeps the Pass 1 product of every
  direct input (POI frames keyed by the Stage A versioned content key),
  the input bytes (content-hash keyed, transferred once), and the fused
  emit buffer (reused across links — the §10.4 M8 "page-fault cost
  eliminated (buffer reuse)" groundwork). Blob negotiation sends only
  bytes the daemon does not hold; `-resident_socket <path>` /
  `PGR_DAEMON_SOCK` pick the socket; `pgr` starts `pgrd` on demand (the
  binary beside it) and **falls back to the one-shot link on any failure**
  (§7.2 "optional and transparent"; `PGR_RESIDENT_DEBUG=1` prints the
  fallback reason)
- **daemon:** M8 correctness gates — resident output byte-identical to the
  one-shot link in deterministic mode (executable/dylib/archive corpora,
  cold and warm, gated end-to-end); daemon SIGKILL/restart never changes a
  byte (the daemon holds no output state; clients write via the Pass 5
  atomic path); concurrent clients serialize with identical results; link
  errors surface through the fallback with the one-shot message text
- **core:** M8 `link_from_objects` — Passes 1b–3 over already-parsed
  direct inputs (the resident path's entry point); the S7 archive pull
  fixpoint, interning, resolution, liveness/ICF and layout run exactly as
  in `link_cached`, and the pre-parsed layout is gated identical;
  `-u` enforcement shared via the new `check_load_symbols` (driver and
  daemon run the same gate)
- **core:** M8-a reverse reference index (`pgr_core::revindex`) — symbol →
  referencing `(file, section, offset)` sites over the parsed inputs,
  recorded at full links (§7.3 step 3); dead-atom references drop when the
  M5 live set is active; sites total-ordered and deduplicated (the index
  is a pure function of the inputs)
- **core:** M8-b insertion-stable import table (`pgr_core::stable_imports`)
  — canonical ordinals on a clean build ((name, ordinal, addend, weak)
  order — address-independent, D7's property made load-bearing); growth
  keeps every existing ordinal and appends new imports canonically (§7.3
  step 5, the M9 relink ordinal-reuse foundation); the table drops
  straight into the `pgr_format` import/name-pool shape
- **core:** M8-c slack-aware layout with fallback (`pgr_core::slack`) —
  `LinkConfig::layout_slack` reserves per-section growth room (10% text /
  5% data, clamped, aligned; synthetic `__got`/`__stubs`/`__chain_starts`
  stay contract-exact) so a changed atom usually fits where it was;
  default off — v1.0 packing is byte-unchanged, and slack padding is a
  pure function of size (deterministic both ways); the §7.3 fallback
  ladder (in-place → segment re-layout → clean link) is a pure decision
  function
- **emit:** `build_image_fused_into` — the fused tile emit into a
  caller-owned buffer (cleared + resized, capacity retained), the reuse
  path the resident session's scratch buffer rides on

### Performance

- **bench:** `pgr-driver/resident` — the warm-relink path recorded
  honestly: one-shot 224.3 ms vs resident-warm 260.3 ms on the
  parse-heavy 64×2048×2 KiB corpus (POI hits 64/64, no input re-transfer,
  buffer reuse). The finding replays M6's: the corpus is Pass 2/3-bound
  and the POI decode measures ≈ a fresh parse on this sandbox, so the
  skipped Pass 1 does not yet cover manifest+wire overhead; the §10.4 M8
  performance gates (≥ 5× ld-prime) stay hardware-gated. Full phase
  breakdown in docs/BENCHMARKS.md
- **bench:** client manifest hashing runs on the shared compute pool (one
  SHA-256 per input, parallelized)

### Tests

- **core:** `m8_foundations.rs` — reverse-index gates (site lists,
  dead-atom filtering under the live set, total order, schedule
  independence), import-table canonical order + ordinal stability across
  growth rounds + key shape (ordinal/addend/weak distinguish), slack
  padding math + fallback ladder + layout gates (pieces never move,
  synthetics exact, deterministic both ways), pre-parsed-layout equality,
  fixup-word equality, archive pull through the preparsed path, shared
  `-u` gate
- **daemon:** protocol round-trips (rich/default configs, version
  mismatch, truncation/trailing-byte rejection, frame bounds), session
  gates (cold-vs-warm byte identity incl. one-shot parity, changed-input
  POI reuse, missing-blob and hash-mismatch refusal, LRU memory ceiling,
  scratch reuse, archive inputs), `pgrd_binary.rs` — strict-verifier-clean
  resident output, SIGKILL restart identity, error survival, idle exit
- **driver:** `m8_resident.rs` — resident-vs-one-shot byte identity over
  executable/dylib/archive corpora (cold + warm), POI-hit counters across
  the wire, fallback transparency (absent daemon), restart transparency,
  4-way concurrent clients, `-u` parity through the fallback
- **emit:** the fused `_into` variant is byte-identical to the allocating
  path (reused by the M4 gates)

## [1.0.0] - 2026-11-07### Features
- **core:** M7 versioned cache format v2 — `CACHE_FORMAT_VERSION = 2` plus a
  parser revision recorded in every POI/frozen-`.tbd` frame *and* bound into
  the cache key (`sha256(bytes ‖ flags ‖ format ‖ parser)` — stale entries
  are unreachable, not merely unread); entries record the parse-affecting
  flag and decode rejects mismatches; the directory carries a
  `PGR_CACHE_FORMAT` marker and self-heals on foreign or legacy content
  (pgr-shaped files reclaimed, foreign files untouched); v1 frames are
  silently missed (determinism-gated cached-vs-uncached equality re-asserted
  on v2)
- **core:** M7 size-bounded caches — oldest-mtime (LRU) eviction with
  recency refresh on hits; the just-stored entry is never evicted; store +
  evict serialized per cache so Pass 1's concurrent stores cannot wipe the
  directory (regression-gated by a 30-iteration parallel-store stress test)
- **driver:** M7 `-cache_max <bytes>` / `PGR_CACHE_MAX` (default 2 GiB,
  0 = unbounded)
- **driver:** M7 build-system surface — `@response-file` expansion (nested,
  depth-bounded; ld64 tokenization with `#` comments, quote grouping and
  backslash escapes; **opportunistic** expansion — a non-existent `@path`
  passes through, keeping `-install_name @rpath/libfoo.dylib` intact)
- **driver:** M7 `-syslibroot <dir>` (repeatable) with the ld64 pairing
  rule: one root searches only prefixed variants of every `-L`/`-F` dir and
  the defaults; two or more roots search the union including the original
  path (`effective_lib_dirs`/`effective_framework_dirs`)
- **driver:** M7 accepted no-ops with fixtures — `-demangle`/`-no_demangle`
  /`-no_deduplicate` (arm64 defaults already match) and
  `-object_path_lto <path>` (value consumed; LTO inputs stay diagnosed)
- **driver:** M7 compatibility suite (`m7_compat.rs`) — the agreed list as
  38 fixture-backed end-to-end cases (load commands, image contracts,
  driver flags & search, M7 surface, determinism, diagnostics), each strict
  verifier-clean, with the roadmap's **≥ 98% pass** gate pinned by its own
  test (currently **38/38 = 100%**)
- **fuzz:** M7 fuzzing at scale — new targets `dyld_info_streams` (classic
  rebase/bind opcode decoders) and `cache_entries` (v2 cache decoders),
  valid framed/streamed seeds in `emit_corpus`, and the six-target nightly
  matrix
- **fixtures:** `emit_link_inputs` example — the deterministic
  hello/greet/tbd inputs the runtime-validation job links
- **docs:** `docs/MIGRATION.md` — the ld64 → pgr migration guide (flag
  mapping, no-ops, cache semantics, determinism contract, exit codes)

### Bug Fixes
- **format:** `parse_imports` bounds `imports_count` by the payload before
  pre-allocation (a mutated/truncated image once drove `count × 16` to
  68 GiB and aborted; typed `Overrun` now; unknown formats rejected up
  front) and `read_u32_slice` bounds its count — M7 fuzzing finds
- **core:** cache unframe uses `checked_add` for the framed length (the
  `cache_entries` fuzzer wrapped `HEADER_LEN + len` on a hostile header);
  object relocation decode caps `with_capacity(nreloc)` by the file's
  bytes (the `link_object` fuzzer drove an 8 GiB allocation)
- **verify:** hostile-header arithmetic overflow battery — `nsections`
  accumulation and segment/branch/chain/pair address computations all
  saturate (`structural`, `dyld_info`, `pair`, `chain_starts`,
  `branch_range`); each crash has a deterministic regression test
- **fuzz:** the `link_object` target links again (the M5 `link()`
  signature change had broken its compile)

### Performance
- **bench:** `pgr-driver/cache_evict` — the LRU bound costs only on cold
  stores: 9.73 ms bounded vs 9.12 ms unbounded (+6.7%) on the 4-object
  parse-heavy corpus; warm (all-hit) links are unchanged — no stores, no
  scans
- **bench:** every M4–M6 gate re-measured with M7 in the pipeline and
  holding: large link 175.6 ms, dead-strip 136.4 ms (1.93× vs off), ICF
  +14.8% (gate ≤ 25%), fused emit 1.38× the reference, warm cache 173.7 ms
  (was 172.8 — the v2 key/marker/touch cost nothing measurable), frozen
  `.tbd` 19.8 µs, trie 10⁵ exports 27.9 ms, archive parse 12.2 GiB/s
  (docs/BENCHMARKS.md records the full table; the M5 row's "~118 µs" unit
  slip is corrected there)

### Tests
- **core:** v2 frame/key/flag gates, marker self-heal (foreign + legacy
  dirs), LRU eviction + recency, hostile framed-length miss, parallel-store
  stress (30 bounded links)
- **driver:** response-file e2e (expansion order-preserving, byte-identical
  to the plain link), syslibroot single-root prefix-only + two-root union,
  `-cache_max` bound e2e, frozen-`.tbd` v2 round-trip, the 38-case compat
  suite
- **format:** bounded imports count / unknown format, hostile framed
  lengths
- **verify:** saturated arithmetic on mutated headers (chain walks, branch
  ranges, segment contracts)

## [0.7.0] - 2026-11-07### Features
- **core:** M6 branch thunks/veneers — out-of-range `B`/`BL` sites (beyond
  the ±128 MiB arm64 reach) get a 3-instruction veneer (`adrp x16/add
  x16/br x16`) inserted into the same output section right after the
  site's piece, inside the layout fixed point; the veneer reaches its
  target through ADRP's ±4 GiB window so no chaining is ever required;
  giant-atom sites (a single atom larger than the branch range) fail with
  ld64-style diagnostics; determinism-gated (double-link layout equality)
- **verify:** M6 branch-range checker — every `B`/`BL` in the executable
  sections is decoded and its target must land back inside `__TEXT`,
  4-byte aligned (`Code::BranchRange`); the architecture doc's "thunk
  placement verified by a branch-range checker in `pgr-verify`" gate
- **format:** M6 classic `LC_DYLD_INFO` opcode streams — rebase/bind
  encoders and decoders (ULEB/SLEB, trailing-flags symbols, special
  ordinals), round-trip and malformed-input gated, never panics
- **core:** M6 `LC_DYLD_INFO_ONLY` legacy fallback — chained fixups are a
  macOS ≥ 12 format (TDD §3.6 invariant 3), so `minos < 12.0.0` and
  `-no_fixup_chains` emit classic rebase/bind streams instead of the
  chained payload (slot bytes stay zero, no `__chain_starts`); the import
  metadata (symtab/indirect construction) is built identically to the
  chained path via the shared `build_import_table`
- **emit:** the classic rebase/bind streams land in `__LINKEDIT` (both
  the reference and fused tile emitters write them identically)
- **verify:** classic dyld-info stream walk — both streams decoded the
  way dyld does; slot bounds/alignment, bind ordinals vs the
  `LC_LOAD_DYLIB` list, special ordinals only in flat images, non-empty
  symbol names (`Code::DyldInfoStreams`)
- **core:** M6 ICF (identical code folding) — `-icf=safe`/`-icf=all`/
  `-no_icf` (ld64 vocabulary, default none); Hopcroft-style color
  refinement over per-atom `(content, ordered relocation fingerprints)`
  signatures with byte hashing on the shared compute pool and
  deterministic first-occurrence class ids; `-icf=safe` never folds
  address-taken atoms, weak definitions never fold, section-relative
  targets never fold (unredirectable); folded aliases keep their symtab
  names at the canonical copy's address and output section; composes with
  `-dead_strip` and the D4 cstring merge
- **core:** M6 Stage A caches (architecture doc §7.1) — the POI (Parsed
  Object Image) cache stores everything Pass 1 produces pre-interning
  (sections with raw relocations, typed symbols, the name pool, D1 atom
  ranges) content-addressed by `sha256(input || flags)`; frozen `.tbd`
  caches the parsed stub; both are checksum-framed (`PGRPOI1`/`PGRFTBD1`),
  atomically written (unique temp + rename — the shared-temp race is
  regression-gated), and corruption/version tolerant (silent re-parse)
- **driver:** M6 flag surface — `-icf=`/`-icf <level>`/`-no_icf`,
  `-cache <dir>` / `PGR_CACHE_DIR` / `-no_cache`; cached vs uncached
  output byte-identical (the §7.1 gate); LTO bitcode inputs (raw
  `BC\xC0\xDE` and `0x0B17C0DE` wrapper) detected up front with a clear
  `-fno-lto` diagnostic instead of a deep Mach-O parse failure
- **core:** M6 Stage A plumbing — `link_cached` threads the POI cache
  through direct inputs and archive members alike (member keys hash the
  member bytes; `from_archive`/archive-name stay call-site properties)
- **fixtures:** `ObjectBuilder::set_subsections_via_symbols` (chained
  form) already exercised by the M5 tests; M6 corpora add ObjC/Swift
  metadata sections (`__objc_classrefs`, `__objc_selrefs`,
  `__swift5_types`) and `-icf` fold corpora

### Performance
- **bench:** `pgr-driver/link_icf` — the "ICF ≤ 25% added wall" gate:
  17.29 ms fold-off vs 19.37 ms `-icf=safe` on the fully-foldable 32×512
  corpus (**+12.0%**, 16,383 atoms folded, ~192 KiB of duplicate text
  removed)
- **bench:** `pgr-driver/link_cache` — Stage A: cold 177.8 ms vs warm
  172.8 ms on the parse-heavy 64K-symbol corpus (−2.8% wall; the corpus
  is Pass 2/3-bound, so the POI cache's Pass 1 elimination is bounded by
  Pass 1's share — recorded honestly with the pass profile)
- **bench:** `pgr-driver/tbd` — the "`.tbd` startup cost < 1 ms" gate:
  frozen export-set decode **19.9 µs** vs 35.8 µs YAML text parse (1.8×,
  both ≪ 1 ms)
- **bench:** M4/M5 gates re-measured with M6 in the pipeline: large link
  175.7 ms (was 174–176), dead-strip 259.0/136.0 ms off/on (1.90×, was
  1.90×) — the veneer scan, fixup-command dispatch and fold-empty fast
  path cost nothing measurable

### Tests
- **core:** veneer insertion on forward/backward overflow (one veneer per
  site, in-range final deltas, double-link determinism, no veneers when
  in range); ICF fold/keep/alias gates (identical fold, distinct targets
  stay, safe vs all address-taken split, dead-strip composition,
  parallel-vs-serial equality); POI round-trip, corruption battery, cache
  key stability, cached-vs-uncached layout equality, consecutive-hit
  equality (the shared-temp store race is regression-gated); frozen-`.tbd`
  round-trip; classic stream planning (slot order, ordinals, specials,
  addends) and segment-bound errors
- **format:** opcode encoders (ULEB/SLEB vs LLVM vectors), rebase/bind
  round-trips, `dyld_info_command` parse gates, truncated-stream battery
- **verify:** branch-range decode battery (B/BL shapes, register-branch
  shapes), in-range pass, out-of-range/misaligned/negative-target errors,
  truncated tails tolerated; classic stream slot/ordinal/name checks
- **driver:** `m6_thunks` (giant-text e2e), `m6_legacy` (minos 11 +
  `-no_fixup_chains` + rebase/bind stream contents + determinism + dylib
  bind names), `m6_icf` (CLI parse, fold e2e with strict verifier,
  `-icf=all` superset), `m6_cache` (byte-identity, corruption re-parse,
  frozen-`.tbd` dylib links, `-no_cache`), `m6_ecosystem` (LTO detection,
  ObjC/Swift pass-through + determinism)

## [0.6.0] - 2026-11-06### Features
- **format:** M5 `!<arch>` archive parser — Apple `__.SYMDEF`/`__.SYMDEF_64`
  and GNU `/` ranlib tables (32/64-bit entries), BSD `#1/<len>` and GNU `//`
  long-name tables, ranlib member-offset resolution (header offset first,
  data-offset fallback); total parser (typed errors, never panics), fuzz-
  and proptest-gated
- **core:** M5/S7 archive liveness — the pull fixpoint walks the ranlib
  index in command order and parses only the members that resolve an
  unresolved name (weak references never pull; `-u` names seed the loop;
  `-all_load`/`-force_load` short-circuit to eager); ranks 3/4
  (`ArchiveStrong`/`ArchiveWeak`) keep direct definitions winning without
  duplicate errors — ld64 semantics; pull order a pure function of the
  inputs (FileIds continue after direct inputs in pull order)
- **core:** D1 atomization — `MH_SUBSECTIONS_VIA_SYMBOLS` sections split at
  symbol boundaries (`N_ALT_ENTRY` merges into the preceding atom;
  `S_CSTRING_LITERALS` sections split at NUL terminators); deterministic
  per-section atom tables, borrowed throughout (no per-call clones)
- **core:** D12 `-dead_strip` — mark-sweep liveness over the D1 atoms
  (roots: entry, `-u` names, all extern defs for dylibs/bundles,
  `__mod_init_func`, `S_ATTR_NO_DEAD_STRIP`); dead atoms leave the layout,
  symtab and trie; edge graph built in one pass per section (relocations
  bucketed into atoms), liveness queries O(log atoms)
- **core:** D4 `__cstring` merging (ld64-default-on) — cross-input dedup of
  `S_CSTRING_LITERALS` via a hash-map pass over string atoms; the first
  live instance is canonical; symbol- and section-relative references remap
  to the single copy through the M5 containment tables; cooperates with
  dead-strip (unreferenced literals strip)
- **driver:** M5 flag surface — `.a` inputs (ranlib pre-parsed, members
  lazy), `.a` in `-l` search after dylib candidates, `-all_load`,
  `-force_load <archive>`, `-u` member pull, `-dead_strip`/
  `-no_dead_strip`, `-filelist <path>[,<dir>]`, `-framework`/`-F` (`.tbd`/
  dylib payloads), `-sectcreate <seg> <sect> <file>` (synthetic
  single-section object); stale M2/M3 force-load message replaced
- **fixtures:** `ArchiveBuilder` (deterministic libtool-style archives,
  name-sorted ranlib table from the member symtabs),
  `set_subsections_via_symbols`/`set_alt_entry`, section-relative reloc
  ctors (`unsigned_sect`, `page21_sect`, `pageoff12_sect`)
### Performance
- **bench:** `pgr-format/parse_archive` — 11.9 GiB/s structural archive
  parse (64 members + ranlib index)
- **bench:** `pgr-driver/link_archive` — S7 decision recorded: lazy pull
  4.02 ms vs `-all_load` 49.06 ms on the 64-member corpus (12.2×; the
  adoption rule was ≥ 20%)
- **bench:** `pgr-driver/link_dead_strip` — 134 ms with `-dead_strip` vs
  255 ms without on the 50%-dead corpus (gate was ≤ 30% overhead; the first
  mark-sweep draft measured 911 ms and was closed by O(log atoms) liveness
  queries + one-pass-per-section edge bucketing + borrowed atom tables)
- **bench:** `pgr-driver/link_cstring` — 1.69 ms for the 16-object shared-
  pool corpus (deduped); M4 gates re-measured and holding (emit 1.39× the
  reference, full-pipeline parity within noise)
### Tests
- **format:** archive round-trips (libtool/GNU/BSD shapes, `__.SYMDEF_64`),
  malformed-input battery, mutation/arbitrary-byte proptests
- **core:** atom-boundary and `N_ALT_ENTRY` gates, dead-strip closure
  (transitive roots, dylib export surface, `__mod_init_func`,
  `S_ATTR_NO_DEAD_STRIP`, `-u` roots), schedule-independence with
  dead-strip on
- **driver:** `m5_archives` (pull/no-pull/order/all_load/force_load/-u/-l/
  weak-ref/collision/determinism), `m5_deadstrip` (strip on/off byte
  checks, byte-identity, `-u` roots, dylib exports, archive transitive
  closure), `m5_cstring` (dedup + symbol remap + dyld-simulated
  section-relative pointer remap + dead-strip cooperation), `m5_flags`
  (filelist/framework/sectcreate/search order)
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

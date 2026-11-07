# Peregrine (`pgr`)

An ultra-fast Mach-O linker for **arm64-apple-darwin**, written in Rust,
cross-linking from Linux — developed verifier-first so correctness gates ship
before the fast paths.

> **Status: M7 production shipped (versioned cache, build-system surface,
> compat suite, fuzzing at scale) — v1.0.0.** Building on M6 (veneers, ICF,
> legacy fixups, Stage A caches), M7 lands the roadmap's production row in
> its in-tree scope: the **versioned cache format v2** (format + parser
> revisions in every frame and key, a directory marker with self-heal,
> oldest-mtime LRU size bounds via `-cache_max`/`PGR_CACHE_MAX`, default
> 2 GiB), the **build-system driver surface** (`@response-file` expansion
> with ld64's opportunistic rule, `-syslibroot` with the ld64 pairing rule,
> accepted no-ops `-demangle`/`-no_demangle`/`-no_deduplicate`/
> `-object_path_lto`), the **compatibility suite** (38 fixture-backed cases
> over the agreed list, gate **≥ 98%** — currently 100%), **fuzzing at
> scale** (two new targets — classic dyld-info opcode streams and the cache
> decoders — which found and closed four real crash/OOM classes; all six
> targets run clean), and the **migration guide**
> ([docs/MIGRATION.md](docs/MIGRATION.md)). Every M4–M6 perf gate re-measured
> and holding (large link 175.6 ms, dead-strip 1.93×, ICF +14.8% ≤ 25%,
> fused emit 1.38×, warm cache 173.7 ms, frozen `.tbd` 19.8 µs; see
> [BENCHMARKS](docs/BENCHMARKS.md)). The hardware-bound halves (G2 ≥ 8× vs
> `ld64.lld`, runtime validation via `codesign`/dyld on produced binaries,
> 30 CPU-days of fuzzing) formally close on the P0 rig; the CI plumbing for
> the macOS runtime-validation job ships with this milestone.

## Workspace layout (TDD §4.1)

| Crate | Role | Threading |
|---|---|---|
| `pgr-driver` | `pgr` CLI (ld64-compatible M5 flag surface: `.tbd` **and `.dylib`** inputs, **`.a` archives**, library/framework search, `-filelist`, `-sectcreate`) + Pass 0 + the M5 driver loop (fused emit default, reference emit kept for the byte-identity gate) | single + pooled Passes 1/4/5 |
| `pgr-format` | raw `#[repr(C)]` Mach-O structs, constants, cursor, chained-fixup & signature codecs, `.tbd` v3/v4 parser, **`!<arch>` parser (BSD/GNU long names, ranlib indexes)**, total export-trie walker | pure |
| `pgr-core` | Passes 1–3: object parser (GOT-load relocs, giant-object chunked symbol decode), interner (parallel canonicalizing sort), two-level resolution, **archive liveness (S7 pull fixpoint, ranks 3/4)**, layout + `__got`/`__stubs` synthesis, **D1 atomization**, **`-dead_strip` mark-sweep (D12)**, **`__cstring` merging (D4)**, import-table planning, range-partition export-trie builder, D8 `resolved[]` tables + copy-run coalescing, shared compute pool (D9) | Pass 1 parallel (LPT), Pass 2/3 single, mark pass single (deterministic) |
| `pgr-emit` | Passes 4–5: **fused tile emit** (16 KiB tiles: copy runs → patches → chain words → `__LINKEDIT` placement → fused 4 KiB page hashing, D14), pre-fault (D10), reference Pass 4 kept verbatim, ad-hoc signature, **4-writer `pwrite` pool** (S1) | Pass 4 parallel (tiles), Pass 5 4 writers |
| `pgr-verify` | read-side verifier + `pgr-verify` CLI (structural, segment contract, dylib/bundle contract, chain-walk simulation over binds/imports, export-trie walk incl. REEXPORT nodes, signature recompute, `__chain_starts` mirror checks, **dylib+executable pair gate**) | single |
| `pgr-fixtures` | deterministic Mach-O image **and relocatable-object** builders (LLVM single-segment object convention — `ld64.lld`-compatible) shared by tests, benches and the fuzz corpus | test-support |

## Engineering gates

* **No lint suppression.** The workspace carries no `#[allow]`/`#[expect]`;
  CI runs `cargo clippy --workspace --all-targets -- -D warnings` on Linux
  and macOS, `cargo fmt --check`, `cargo doc -D warnings` and locked builds.
* **No `unsafe` anywhere at M0–M4** (workspace-wide `unsafe_code = "forbid"`;
  the M4 parallel paths are built from safe primitives — disjoint
  `par_chunks_mut` tiles and `FileExt::write_at` — so no audited opt-in was
  needed yet; `pgr-emit`/`pgr-format` opt-ins still require design notes,
  perf doc §5 rule 9).
* **Parsers never panic.** Typed errors everywhere; the fuzz targets
  (`cargo fuzz run parse_any|parse_tbd|verify_image|link_object`) and the
  proptest mutation suites keep that honest.
* **Deterministic fixtures.** `pgr-fixtures` builds valid arm64 images
  (16 KiB congruence, 4 GiB `__PAGEZERO`, `DYLD_CHAINED_PTR_64_OFFSET`
  chains, ad-hoc SHA-256 signatures, content-derived UUIDs) byte-identically
  on every run.

## Quick start

```sh
cargo build --release --locked
cargo test --workspace --locked          # 350+ tests: units, e2e gate, proptests, cross-checks, byte-identity gates, the M7 compat suite
cargo bench -p pgr-format                # parser GB/s baseline (docs/BENCHMARKS.md)
cargo bench -p pgr-core --bench trie     # export-trie build gate (docs/BENCHMARKS.md)
cargo bench -p pgr-emit --bench emit     # fused-tile vs reference Pass 4 (docs/BENCHMARKS.md)
cargo bench -p pgr-driver                # end-to-end link baseline + M5 archive/dead-strip/cstring groups

# Link a dynamic executable against a .tbd stub (M2):
./target/release/pgr -o hi printf_main.o -l System -L /path/to/stubs \
    -platform_version macos 12.0 14.0
# Flat namespace / dynamic lookup / rpath:
./target/release/pgr -o hi printf_main.o libSystem.tbd \
    -flat_namespace -undefined dynamic_lookup -rpath @executable_path/../lib

# Link a dylib (M3) and build an executable against the dylib binary:
./target/release/pgr -dylib -install_name @rpath/libfoo.dylib \
    -current_version 1.2.0 -compatibility_version 1.0.0 \
    -o libfoo.dylib foo.o libSystem.tbd
./target/release/pgr -o main main.o libfoo.dylib
./target/release/pgr -bundle -o plug.bundle plugin.o libSystem.tbd

# Link against a static archive (M5): members are pulled lazily via the
# ranlib table — only the members the link needs are ever parsed.
./target/release/pgr -o hi main.o -lgreet -L /path/to/libs
# Dead-strip (M5) + cstring merging (default) + a synthetic section:
./target/release/pgr -o hi main.o libutil.a -dead_strip \
    -sectcreate __TEXT __info_plist Info.plist
# Real-world surface (M5): -filelist, -framework/-F, -all_load/-force_load:
./target/release/pgr -o hi -filelist objs.txt,objdir -framework Foundation \
    -F /sdks/MacOSX.sdk/System/Library/Frameworks -platform_version macos 12.0 14.0

# Cross-check the fixup values against ld64.lld (the M2 golden gate):
PGR_LLD64=$(which ld64.lld) cargo test -p pgr-driver --test e2e

# Verify any Mach-O image against the Peregrine contract:
./target/release/pgr-verify hi --strict

# M7 build-system surface: response files (CMake/Ninja/Xcode shape) and
# -syslibroot (the ld64 SDK pairing rule — single root: prefixed-only;
# multiple roots: union + original):
pgr @link.rsp
pgr -o hi main.o -l System -syslibroot /sdks/MacOSX.sdk -platform_version macos 12.0 14.0

# M7 Stage A cache v2 with an LRU size bound (default 2 GiB, 0 = unbounded):
pgr -o app app.o -cache .pgr-cache -cache_max 536870912
PGR_CACHE_DIR=.pgr-cache pgr -o app app.o   # env form; -no_cache forces off

# Run the M5 pipeline single-threaded (determinism/debugging):
PGR_JOBS=1 ./target/release/pgr -o hi printf_main.o -l System -L /path/to/stubs

# Seed + run the fuzzers (nightly):
cargo run -p pgr-fixtures --example emit_corpus -- fuzz/corpus
cargo +nightly fuzz run link_object -- -max_total_time=120
```

## CI/CD

* **CI** (`.github/workflows/ci.yml`): fmt → clippy (`-D warnings`) → locked
  tests → doc gate → bench compile, on Linux x86_64 and macOS aarch64.
* **Fuzz** (`.github/workflows/fuzz.yml`): nightly libFuzzer runs over
  `parse_any`, `parse_tbd`, `verify_image`, `link_object` and the M7
  targets `dyld_info_streams` / `cache_entries`, with a fixture-seeded
  corpus (images, objects, tbd stubs, classic opcode streams, cache
  entries).
* **Runtime validation** (`.github/workflows/runtime.yml`, M7): on macOS
  runners, links a binary/dylib pair, runs the produced binaries, and
  validates them with `codesign -v` + dyld — the hardware half of the M7
  row.
* **Release** (`.github/workflows/release.yml`): pushing a `v*` tag builds
  Linux + macOS binaries, generates the changelog/notes with
  [git-cliff](https://git-cliff.org) from conventional commits and attaches
  signed-checksummed tarballs to a GitHub Release.
* **Dependabot** keeps Actions and Cargo dependencies fresh weekly.

## M0 gate checklist (TDD §10.3)

- [x] `pgr-format`: raw structs and cursor, constants cross-checked against
      `object::macho` (TDD §2.4)
- [x] `pgr-verify` v1: structural, segment contract, chain-walk simulation,
      signature recompute
- [x] Fuzz targets for the parsers (cargo-fuzz + stable proptests)
- [x] Parser throughput benchmarked (GB/s) and recorded
      (`docs/BENCHMARKS.md`) as the baseline for Pass 1
- [x] Verifier green on fixtures Peregrine did not "link" (deterministic
      builder used as the third-party stand-in until lld-produced goldens
      land on macOS hardware)
- [x] Perf-shaped from day one: no-allocation hot loops, zero-copy parse
      surfaces, 16 KiB contract checks, benchmark harness in CI

## M1 gate checklist (TDD §12)

- [x] Passes 0–5 minimal: direct `.o` inputs, `-static` semantics
      (single-threaded M1 shape; the pass structures are M4-parallel-ready)
- [x] `LC_MAIN`, `LC_SYMTAB`, minimal `LC_DYSYMTAB`, `__chain_starts`
- [x] Ad-hoc signature; rebase-only chained fixups for `__DATA` pointers
- [x] `pgr-verify` full pass on every linked image, including the dyld
      chain-walk simulation and the signature hash recompute (e2e gate)
- [x] Deterministic double-link byte-equal (CI-level, every PR — e2e gate)
- [x] Semantic checks vs the fixture spec: rebase targets, subtractor
      results, common allocation, canonical symtab order, cstring content
- [x] Verifier grew with the emitter: `__chain_starts` mirror agreement and
      canonical segment-order checks are now enforced
- [x] Link benchmark recorded (`docs/BENCHMARKS.md`) as the M4 baseline
- [x] `llvm-otool -l` diff vs ld64 goldens — **deferred**: requires
      `ld64.lld`/macOS hardware (CI skeleton exists; the verifier +
      `object`-crate crosscheck is the Linux stand-in, as at M0)

## M5 gate checklist (architecture doc §10.3 row M5 — core engine shipped)

- [x] **Archives (S7)**: `pgr-format::archive` total `!<arch>` parser (Apple
      `__.SYMDEF`/`__.SYMDEF_64`, GNU `/`, BSD `#1/` + GNU `//` long names;
      typed errors, fuzz/proptest-gated) + `pgr-fixtures::ArchiveBuilder`;
      the **S7 decision is taken: lazy adopted** — the pull fixpoint walks
      the ranlib index in command order and parses only needed members
      (12.2× the `-all_load` baseline on the archive-heavy bench, gate was
      ≥ 20%); ranks 3/4 (archive strong/weak) keep direct definitions
      winning without duplicate errors, exactly ld64
- [x] Archive semantics gated: undefined→pull, order-insensitivity,
      weak references never pull, `-all_load`/`-force_load`/`-u` roots,
      `.a` in `-l` search after dylib candidates, double-link determinism,
      byte-identity with the reference emit, strict verifier clean
- [x] **D1 atomization**: `MH_SUBSECTIONS_VIA_SYMBOLS` sections split at
      symbol boundaries (`N_ALT_ENTRY` merges; cstring sections split at
      NULs), deterministic atom tables, parallel-vs-serial equality
- [x] **`-dead_strip` (D12)**: mark-sweep liveness — roots = entry, `-u`
      names, all extern defs for dylibs/bundles, `__mod_init_func`,
      `S_ATTR_NO_DEAD_STRIP`; dead atoms leave layout, symtab and trie;
      `__cstring` strings strip at literal granularity
- [x] **Perf gate**: "dead-strip adds ≤ 30% to the link" — measured
      **1.9× faster** on the 50%-dead corpus (134 ms vs 255 ms); the
      bench-driven optimization trail (3.5× → 1.9×) is recorded in
      docs/BENCHMARKS.md
- [x] **`__cstring` merging (D4)**: cross-input dedup of
      `S_CSTRING_LITERALS` (ld64-default-on), first-live-instance
      canonical, symbol- and section-relative references remap to the
      single copy (dyld-simulation-gated); cooperates with dead-strip
- [x] **Driver flags**: `-filelist <path>[,<dir>]`, `-framework`/`-F`
      (`.tbd`/dylib payloads), `-sectcreate`, `-all_load`, `-force_load`,
      `-dead_strip`/`-no_dead_strip`; `-u` pulls members; usage text
      updated (see docs/COMPAT.md for the fixture list)
- [x] **Correctness gates**: every new corpus shape emits byte-identical
      output through fused and reference emits, passes `pgr-verify
      --strict`, and double-links deterministically (282 workspace tests,
      zero `#[allow]` in the tree)
- [ ] **Deferred with reasons** (the rest of the M5 row): compact-unwind
      synthesis (D2) and the stabs/debug map (D3) gate on macOS hardware
      (C++ exceptions / lldb validation — the in-tree verifier cannot
      replay unwind tables or dwarf); `-order_file` waits for the D1
      ordering pass; `-ObjC` member pull joins M6's ObjC class handling.
      The roadmap's real-project correctness gate (ripgrep, C++, ObjC,
      Rust links *running* on Apple Silicon) formally closes on the P0 rig

## M7 gate checklist (architecture doc §10.3 row M7 — production, in-tree scope)

- [x] **Versioned cache format**: `CACHE_FORMAT_VERSION = 2` + a parser
      revision recorded in every POI/frozen-`.tbd` frame *and* bound into
      the cache key (stale entries are unreachable, not merely unread);
      entries record the parse-affecting flag; the directory carries a
      format marker and self-heals on foreign/legacy content (pgr-owned
      files reclaimed, foreign files untouched); size-bounded with
      oldest-mtime (LRU) eviction, recency touch on hits, and the
      just-stored entry never evicted — `-cache_max <bytes>` /
      `PGR_CACHE_MAX`, default 2 GiB. §7.1's "cached vs uncached
      byte-identical" gate re-asserted on v2
- [x] **ld-compatible driver, build-system surface**: `@response-file`
      expansion (recursive, depth-bounded, ld64 tokenization, opportunistic
      expansion so `@rpath/...` values pass through), `-syslibroot`
      (repeatable, the ld64 pairing rule), accepted no-ops
      `-demangle`/`-no_demangle`/`-no_deduplicate`/`-object_path_lto`;
      every flag fixture-backed (`docs/COMPAT.md` rows)
- [x] **Compatibility suite** (`m7_compat.rs`): the agreed list — 38
      fixture-backed cases spanning load commands, image contracts, driver
      flags & search, M7 surface, determinism and diagnostics — driven
      through the real pipeline and `pgr-verify --strict`; the gate
      `≥ 98% pass on the agreed list` is pinned by its own test and
      currently measures **38/38 (100%)**
- [x] **Fuzzing at scale**: two new targets (`dyld_info_streams`,
      `cache_entries`) with framed valid seeds; the six-target nightly
      matrix updated; short local sessions over all targets surfaced and
      closed four real defect classes (cache frame-length overflow, hostile
      header arithmetic in five verifier sites, a stale fuzz-target
      signature, an 8 GiB `nreloc` pre-allocation) — each with a
      deterministic regression test; the 30-CPU-day gate closes on the P0 rig
- [x] **Docs and migration guide**: `docs/MIGRATION.md` (ld64 → pgr flag
      mapping, no-ops, cache semantics, determinism contract, exit codes),
      README + `docs/COMPAT.md` + `docs/BENCHMARKS.md` updated for M7
- [x] **Bench everything**: the full bench suite re-run with M7 in the
      pipeline — every M4–M6 gate holds; the new `cache_evict` bench shows
      the LRU bound costs only on cold stores (+6.7% there) and nothing on
      warm hits
- [ ] **Deferred with reasons** (the rest of the M7 row): `ld`-compatible
      driver *tested through* clang `-fuse-ld`/Xcode/`xcodebuild`/cargo
      (needs macOS hosts; the flag shapes those tools pass are
      fixture-covered), runtime validation on macOS hardware (run produced
      binaries, `codesign -v`, dyld load — the CI job ships as
      `.github/workflows/runtime.yml` and executes on the P0 rig), the G2
      perf gates (≥ 8× vs `ld64.lld`, ≥ 3× vs ld-prime, startup ≤ 3 ms,
      nightly ±3%), and fuzzing at 30 CPU-days

## M6 gate checklist (architecture doc §10.3 row M6 — scale & ecosystem, in-tree scope)

- [x] **Branch thunks/veneers (BR26 overflow)**: out-of-range `B`/`BL`
      sites (±128 MiB arm64 reach) get a 3-instruction veneer
      (`adrp x16/add x16/br x16`, ±4 GiB ADRP window) inserted into the
      same output section right after the site's piece, inside the layout
      fixed point; determinism-gated (double-link layout equality), and
      giant-atom sites (single atom > 128 MiB) fail with ld64-style
      diagnostics instead of mis-linking
- [x] **Branch-range checker in `pgr-verify`**: every `B`/`BL` in the
      executable sections is decoded; targets must land back inside the
      `__TEXT` span, 4-byte aligned (`Code::BranchRange`) — the M6 gate
      "thunk placement verified by a branch-range checker"
- [x] **`LC_DYLD_INFO` legacy fallback**: chained fixups are a macOS ≥ 12
      format (TDD §3.6 invariant 3), so `minos < 12.0.0` and
      `-no_fixup_chains` emit classic `LC_DYLD_INFO_ONLY` rebase/bind
      opcode streams instead — slot bytes stay zero (dyld writes them),
      no `__chain_starts`; `pgr-format` owns the opcode encoders/decoders
      (round-trip + malformed battery), `pgr-core::dyld_info` plans the
      streams from the same slot list, and the verifier walks both
      streams entry-by-entry (`Code::DyldInfoStreams`)
- [x] **ICF (identical code folding)**: `-icf=safe` / `-icf=all` /
      `-no_icf` (ld64 vocabulary, default `none`); Hopcroft-style color
      refinement over per-atom `(content, ordered relocation
      fingerprints)` signatures, byte hashing on the shared pool,
      deterministic class ids (TDD §4.3); `-icf=safe` never folds
      address-taken atoms, weak defs never fold, section-relative targets
      never fold (unredirectable); folded aliases keep their symtab names
      at the canonical address; composes with `-dead_strip`
- [x] **ICF determinism + perf gates**: identical layouts across
      `Parallelism::Serial`/`Auto` and repeated runs; every ICF output is
      verifier-clean; the wall overhead on the fully-foldable corpus is
      **+12.0%** (gate: ≤ 25%) while removing ~192 KiB of duplicate text
- [x] **Stage A caches (§7.1): POI + frozen `.tbd`**: content-addressed
      (`sha256(input || flags)`), checksum-framed, atomically written,
      corruption- and version-tolerant (silent re-parse); `-cache <dir>`
      / `PGR_CACHE_DIR` / `-no_cache` (opt-in); **cached vs uncached
      output byte-identical** (the roadmap gate), warm links skip Pass 1
      entirely; frozen `.tbd` startup **19.9 µs** vs 35.8 µs text parse
      (gate: < 1 ms)
- [x] **LTO pass-through scope**: LLVM bitcode inputs (raw `BC\xC0\xDE`
      and `0x0B17C0DE` wrapper) are detected up front and diagnosed
      clearly (rebuild with `-fno-lto`) instead of failing deep in the
      Mach-O parser; the full LTO backend joins a later milestone
- [x] **ObjC/Swift section pass-through gates**: `__objc_classrefs` /
      `__objc_selrefs` / `__swift5_types` corpora place, chain-rebase
      their pointers, verify strictly and double-link deterministically
- [ ] **Deferred with reasons** (the rest of the M6 row): ObjC stub
      synthesis and selector/class *semantics* (needs real ObjC corpora
      and the P0 rig to validate against dyld), Swift flags
      (`-swift_version` etc.), LTO object *execution* (LLVM backend
      integration), and the D7 insertion-stable import order (Stage C
      incremental work). The relink-vs-ld-prime gate closes on the P0 rig

## M4 gate checklist (architecture doc §10.3 row M4)

- [x] **Fused tile emit** (perf doc §4.4): parallel 16 KiB tiles copy the
      coalesced runs, apply relocations, encode chain words, place the
      `__LINKEDIT` chunks and hash the 4 KiB signature pages in one pass
      (D14); only the header page (UUID) and the SuperBlob finish late —
      `pgr-emit::tile::build_image_fused`
- [x] **Copy-run coalescing** (§4.3): Pass 3 emits `Layout.runs` — adjacent
      pieces contiguous in input and output merge into one `memcpy` —
      coverage gated in `pgr-core` tests
- [x] **`resolved[]` de-indirection** (D8): per-file flat
      `ResolvedFile { syms, sects }` tables written once per fixed-point
      iteration; the relocation scan reads the file-local array instead of
      global maps (the M1–M3 map walks are gone from the hot path)
- [x] **LPT scheduling + giant-object splitting** (§4.1): Pass 1 parses
      longest-file-first on the shared pool; inputs ≥ 64 MiB or ≥ 2²⁰
      symbols split their symbol decode into deterministic index chunks
      (mechanism gated against the serial decode)
- [x] **P-core pool** (D9): one shared rayon pool per process
      (`pgr_core::pool::compute_pool`), sized `PGR_JOBS` →
      `available_parallelism` on Linux hosts; the macOS P-core default
      (`hw.perflevel0.logicalcpu`) lands with the P0 rig (spike S4)
- [x] **Background pre-fault** (D10): parallel one-byte-per-4-KiB-page read
      pass over the zero-page-backed output buffer before the tile loop
- [x] **Fused hashing** (D14): the SHA-256 page table for the ad-hoc
      signature is produced inside the tile loop; only page 0 re-hashes
      after the UUID lands — identical bytes to the reference two-pass
      derivation (§9), gated
- [x] **Writer tuning** (S1): extent preallocation (`set_len`) + 4-writer
      `pwrite` pool over disjoint 8 MiB blocks, fresh vnode + fsync +
      atomic rename preserved; byte-exactness gated across block boundaries
- [x] **Correctness gate: byte-identity with the pre-fusion output** — the
      reference emit stays in the tree (`pgr-emit::build_image`,
      `pgr_driver::link_reference_bytes`); e2e + integration gates compare
      both paths on executables, dylibs, bundles, re-exports, export
      filters, flat namespace, `-no_fixup_chains`, `-no_adhoc` and wide
      multi-tile corpora; strict verifier + pair gate stay green on the
      fused outputs; double-link determinism holds
- [x] **Perf gate (sandbox half)**: Pass 4 emits **1.37× the reference**
      (2.18 ms → 1.59 ms for ~0.94 MiB images) and bind-path links run
      1.10–1.11× the reference pipeline on the 2-core dev sandbox
      (`docs/BENCHMARKS.md`); the parallel-efficiency half of **G1**
      (≥ 5× vs `ld64.lld` at 16 threads; ≥ 1.5× vs ld-prime; single-
      threaded fraction ≤ 15%) formally closes on the P0 rig — 2 threads
      cannot exhibit 16-thread scaling, exactly like the M0–M3
      hardware-bound numbers
- [ ] **PGO build**: deferred with reason — profile-guided optimization
      needs representative training links on target hardware (P0 rig);
      the CI skeleton carries the release profile (`lto = "fat"`,
      `codegen-units = 1`) until then

## M3 gate checklist (architecture doc §10.3 row M3)

- [x] `-dylib` output: `MH_DYLIB`, `LC_ID_DYLIB` (`-install_name`,
      `-current_version`, `-compatibility_version`; install name defaults to
      the output path), no `LC_MAIN`/`LC_LOAD_DYLINKER`, image base 0 —
      verifier-validated (`pgr-verify` grew `check_dylib_contract`)
- [x] `-bundle` output: `MH_BUNDLE`, no `LC_ID_DYLIB`
- [x] Full export trie: compressed range-partition builder (8–11× the M2
      builder; bench-recorded), weak-definition flags, deterministic bytes
- [x] Re-exports: `-reexport_library` → `LC_REEXPORT_DYLIB` + REEXPORT trie
      nodes (ordinal + imported name); verifier walk validates ordinals and
      strings; local definitions shadow re-exports
- [x] `-exported_symbols_list` / `-unexported_symbols_list` (exact-name
      subset; hidden externals become `N_PEXT` locals and leave the trie)
- [x] `-mark_dead_strippable_dylib` → `MH_DEAD_STRIPPABLE_DYLIB`
- [x] Mach-O dylib inputs: `.dylib` scan (install name + exports from the
      trie, symtab fallback) for direct inputs and `-l` search
- [x] **Correctness gate: dylib + executable pair** —
      `pgr_verify::pair::verify_dylib_pair` verifies both images, replays the
      exec's chained binds like dyld, and asserts every two-level bind into
      the dylib resolves to a name its trie exports (the R4 mitigation);
      `e2e::m3_exec_against_pgr_dylib_passes_the_pair_gate` links the pair
      end-to-end through the scanned dylib binary
- [x] Trie diff vs ld64 goldens runs through the M2 lld harness (skips when
      lld is absent; CI installs it)
- [x] Perf gate: trie build 31.5 ms for 10⁵ exports on the 2-core dev
      sandbox (legacy M2 builder: 363 ms) — ≈ 8–12 ms on P-core-class
      hardware; formally closes on the P0 rig
      (`docs/BENCHMARKS.md`)

## M2 gate checklist (architecture doc §10.3 row M2)

- [x] `.tbd` parse (v3/v4) — `pgr-format::tbd`, total parser, fuzz target
- [x] `LC_LOAD_DYLIB` ordinals + two-level resolution (`(dylib, name)`)
- [x] GOT/stub synthesis (arm64 12-byte stubs, `S_SYMBOL_STUBS` /
      `S_NON_LAZY_SYMBOL_POINTERS`, `reserved1/2` per ld64)
- [x] Chained fixups rebase+bind with import table (`IMPORT_ADDEND`),
      first-use ordinals (spike S6 verified vs `ld64.lld`)
- [x] Minimal export trie (`__mh_execute_header` + defined externs) with a
      full verifier walk (sorted edges, bounds, flag checks)
- [x] Indirect symbols (`LC_DYSYMTAB.indirectsymoff` for `__got`/`__stubs`)
- [x] Compat checklist D13 started (`-l -L -rpath -flat_namespace
      -undefined -u -weak_library -source_version`; `LC_RPATH`,
      `LC_SOURCE_VERSION`, `LC_LOAD_WEAK_DYLIB`) — each with a fixture
      (`docs/COMPAT.md`)
- [x] **Correctness gate: links `printf("hi\n")`** against a libSystem-
      shaped `.tbd`; verifier dyld-simulation slot-for-slot matches
      `ld64.lld` on the same corpus (`e2e::m2_lld_golden_binds_slot_for_slot`)
- [x] `-flat_namespace` works (flat-lookup ordinal `0xFE` in imports and
      `n_desc`, `MH_TWOLEVEL` dropped)
- [x] Bind-path benchmark baseline recorded (`docs/BENCHMARKS.md`); the
      parallel-efficiency half of the gate stays hardware-gated (P0 rig)

## Documentation

* `docs/TDD.md` — technical design document (pipeline, pass specs, data
  structures, chained fixups, layout engine, signing, verifier)
* `docs/peregrine-performance-architecture-and-roadmap.md` — performance
  architecture, deltas against the TDD, multi-year roadmap, spike register
* `docs/BENCHMARKS.md` — recorded M0/M1/M2/M3/M4 baselines and how to read
  them
* `docs/COMPAT.md` — ld64/D13 compatibility checklist with fixture links
* `docs/MIGRATION.md` — migrating from ld64 to `pgr` (flags, cache,
  determinism, exit codes)
* `CHANGELOG.md` — generated by git-cliff

## License

MIT OR Apache-2.0 (see `LICENSE-MIT` / `LICENSE-APACHE`).

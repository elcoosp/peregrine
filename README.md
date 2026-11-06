# Peregrine (`pgr`)

An ultra-fast Mach-O linker for **arm64-apple-darwin**, written in Rust,
cross-linking from Linux — developed verifier-first so correctness gates ship
before the fast paths.

> **Status: M4 ("the speed pass") shipped.** Building on the M3 dylibs and
> bundles, Peregrine's emit pipeline now runs as the **fused tile emit**
> (perf doc §4.4): the output is processed in parallel 16 KiB tiles that copy
> the coalesced runs, apply relocations, encode chained-fixup words, place
> the `__LINKEDIT` chunks and **hash the 4 KiB signature pages in the same
> pass** — one pass over each byte instead of five. Pass 1 parses
> **LPT-scheduled in parallel** with giant-object splitting (§4.1), the
> interner sorts on the shared compute pool (D9), Pass 3 materializes the
> per-file `resolved[]` de-indirection tables (D8) and the **copy-run
> coalescing** (§4.3), and Pass 5 flushes through a **4-writer `pwrite` pool**
> with extent preallocation (S1). The M4 correctness gate is byte-identity
> with the pre-fusion pipeline, which stays in the tree as the reference
> (`pgr-emit::build_image` / `pgr_driver::link_reference_bytes`): every
> corpus shape — executables, dylibs, bundles, re-exports, export filters,
> flat namespace, `-no_fixup_chains`, `-no_adhoc` — emits identical bytes
> through both paths, and the fused output passes the strict verifier and
> the M3 pair gate. Pass 4 measures **1.37× the reference emit** on the
> 2-core dev sandbox (bind-path links 1.10–1.11×; see [BENCHMARKS](
> docs/BENCHMARKS.md) for the recorded numbers and the hardware-gated G1
> half of the gate). M0–M3 foundations are unchanged; archives and
> `-dead_strip` start at M5 (see the
> [roadmap](docs/peregrine-performance-architecture-and-roadmap.md), the
> [TDD](docs/TDD.md) and the [compat checklist](docs/COMPAT.md)).

## Workspace layout (TDD §4.1)

| Crate | Role | Threading |
|---|---|---|
| `pgr-driver` | `pgr` CLI (ld64-compatible M3 flag surface, `.tbd` **and `.dylib`** inputs, library search) + Pass 0 + the M4 driver loop (fused emit default, reference emit kept for the byte-identity gate) | single + pooled Passes 1/4/5 |
| `pgr-format` | raw `#[repr(C)]` Mach-O structs, constants, cursor, chained-fixup & signature codecs, `.tbd` v3/v4 parser, total export-trie walker | pure |
| `pgr-core` | Passes 1–3: object parser (GOT-load relocs, giant-object chunked symbol decode), interner (parallel canonicalizing sort), two-level resolution, layout + `__got`/`__stubs` synthesis, import-table planning, range-partition export-trie builder, D8 `resolved[]` tables + copy-run coalescing, shared compute pool (D9) | Pass 1 parallel (LPT), Pass 2/3 single |
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
cargo test --workspace --locked          # 240+ tests: units, e2e gate, proptests, cross-checks, M4 byte-identity gates
cargo bench -p pgr-format                # parser GB/s baseline (docs/BENCHMARKS.md)
cargo bench -p pgr-core --bench trie     # export-trie build gate (docs/BENCHMARKS.md)
cargo bench -p pgr-emit --bench emit     # fused-tile vs reference Pass 4 (docs/BENCHMARKS.md)
cargo bench -p pgr-driver                # end-to-end link baseline (docs/BENCHMARKS.md)

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

# Cross-check the fixup values against ld64.lld (the M2 golden gate):
PGR_LLD64=$(which ld64.lld) cargo test -p pgr-driver --test e2e

# Verify any Mach-O image against the Peregrine contract:
./target/release/pgr-verify hi --strict

# Run the M4 pipeline single-threaded (determinism/debugging):
PGR_JOBS=1 ./target/release/pgr -o hi printf_main.o -l System -L /path/to/stubs

# Seed + run the fuzzers (nightly):
cargo run -p pgr-fixtures --example emit_corpus -- fuzz/corpus
cargo +nightly fuzz run link_object -- -max_total_time=120
```

## CI/CD

* **CI** (`.github/workflows/ci.yml`): fmt → clippy (`-D warnings`) → locked
  tests → doc gate → bench compile, on Linux x86_64 and macOS aarch64.
* **Fuzz** (`.github/workflows/fuzz.yml`): nightly libFuzzer runs over
  `parse_any`, `parse_tbd` (new at M2), `verify_image` and `link_object`
  with a fixture-seeded corpus (GOT-reloc objects + tbd stubs).
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
* `CHANGELOG.md` — generated by git-cliff

## License

MIT OR Apache-2.0 (see `LICENSE-MIT` / `LICENSE-APACHE`).

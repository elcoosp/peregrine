# Peregrine (`pgr`)

An ultra-fast Mach-O linker for **arm64-apple-darwin**, written in Rust,
cross-linking from Linux — developed verifier-first so correctness gates ship
before the fast paths.

> **Status: M2 ("dynamic executable") shipped.** The repository now links
> dynamic executables against text-based dylib stubs:
> `pgr -o out hello.o libSystem.tbd` produces a valid arm64 MH_EXECUTE with
> `LC_LOAD_DYLIB` ordinals, two-level namespace resolution, synthesized
> `__TEXT,__stubs` + `__DATA_CONST,__got`, chained fixups with a real import
> table (rebase **and** bind), indirect symbols, the minimal export trie
> (`__mh_execute_header` + defined externs), `-flat_namespace`,
> `-undefined dynamic_lookup`, `-rpath`, `-source_version` and weak dylibs —
> all passing the full verifier gate (dyld chain-walk simulation over binds
> + imports, trie walk, signature recompute). The M2 **slot-for-slot golden
> gate** compares our fixup values against `ld64.lld` on the same corpus
> (skips gracefully when lld is absent; CI installs it). M0/M1 foundations
> are unchanged; dylib *outputs* and archives start at M3 (see the
> [roadmap](docs/peregrine-performance-architecture-and-roadmap.md), the
> [TDD](docs/TDD.md) and the [compat checklist](docs/COMPAT.md)).

## Workspace layout (TDD §4.1)

| Crate | Role | Threading |
|---|---|---|
| `pgr-driver` | `pgr` CLI (ld64-compatible M2 surface: M1 flags + `-l -L -rpath -flat_namespace -undefined -u -weak_library -source_version`, `.tbd` inputs, library search) + Pass 0 | single |
| `pgr-format` | raw `#[repr(C)]` Mach-O structs, constants, cursor, chained-fixup & signature codecs, `.tbd` v3/v4 parser | pure |
| `pgr-core` | Passes 1–3: object parser (incl. GOT-load relocs), interner, two-level resolution, layout + `__got`/`__stubs` synthesis, import-table & export-trie planning (single-threaded; M4-parallel-ready shapes) | single (M1/M2) |
| `pgr-emit` | Passes 4–5: output buffer, reloc apply, chain words (rebase + bind), `__LINKEDIT` build (symtab + indirect symbols + trie), ad-hoc signature, atomic writer | single (M1/M2) |
| `pgr-verify` | read-side verifier + `pgr-verify` CLI (structural, segment contract, chain-walk simulation over binds/imports, export-trie walk, signature recompute, `__chain_starts` mirror checks) | single |
| `pgr-fixtures` | deterministic Mach-O image **and relocatable-object** builders (LLVM single-segment object convention — `ld64.lld`-compatible) shared by tests, benches and the fuzz corpus | test-support |

## Engineering gates

* **No lint suppression.** The workspace carries no `#[allow]`/`#[expect]`;
  CI runs `cargo clippy --workspace --all-targets -- -D warnings` on Linux
  and macOS, `cargo fmt --check`, `cargo doc -D warnings` and locked builds.
* **No `unsafe` anywhere at M0/M1** (workspace-wide `unsafe_code = "forbid"`;
  audited opt-ins are deferred to `pgr-emit`/`pgr-format` with design notes,
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
cargo test --workspace --locked          # 140+ tests: units, e2e gate, proptests, cross-checks
cargo bench -p pgr-format                # parser GB/s baseline (docs/BENCHMARKS.md)
cargo bench -p pgr-driver                # end-to-end link baseline (docs/BENCHMARKS.md)

# Link a dynamic executable against a .tbd stub (M2):
./target/release/pgr -o hi printf_main.o -l System -L /path/to/stubs \
    -platform_version macos 12.0 14.0
# Flat namespace / dynamic lookup / rpath:
./target/release/pgr -o hi printf_main.o libSystem.tbd \
    -flat_namespace -undefined dynamic_lookup -rpath @executable_path/../lib

# Cross-check the fixup values against ld64.lld (the M2 golden gate):
PGR_LLD64=$(which ld64.lld) cargo test -p pgr-driver --test e2e

# Verify any Mach-O image against the Peregrine contract:
./target/release/pgr-verify hi --strict

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
* `docs/BENCHMARKS.md` — recorded M0/M1/M2 baselines and how to read them
* `docs/COMPAT.md` — ld64/D13 compatibility checklist with fixture links
* `CHANGELOG.md` — generated by git-cliff

## License

MIT OR Apache-2.0 (see `LICENSE-MIT` / `LICENSE-APACHE`).

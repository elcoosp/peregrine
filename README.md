# Peregrine (`pgr`)

An ultra-fast Mach-O linker for **arm64-apple-darwin**, written in Rust,
cross-linking from Linux — developed verifier-first so correctness gates ship
before the fast paths.

> **Status: M1 ("static hello-world") shipped.** The repository now links:
> `pgr -o out hello.o greet.o` produces a valid arm64-apple-darwin
> MH_EXECUTE with `LC_MAIN`, minimal `LC_DYSYMTAB`, rebase-only chained
> fixups, the `__TEXT,__chain_starts` static mirror and an ad-hoc signature
> — passing the full verifier gate (chain-walk simulation + signature hash
> recompute) and the deterministic double-link contract. M0 foundations
> (format layer, verifier, fixtures, parser-throughput baseline, CI/CD) are
> unchanged. Dynamic linking starts at M2 (see the
> [roadmap](docs/peregrine-performance-architecture-and-roadmap.md) and the
> [TDD](docs/TDD.md)).

## Workspace layout (TDD §4.1)

| Crate | Role | Threading |
|---|---|---|
| `pgr-driver` | `pgr` CLI (ld64-compatible M1 surface: `-o -arch -platform_version -e -static -fixup_chains -adhoc -headerpad -segalign`) + Pass 0 | single |
| `pgr-format` | raw `#[repr(C)]` Mach-O structs, constants, cursor, chained-fixup & signature codecs | pure |
| `pgr-core` | Passes 1–3: object parser, interner, resolution, layout, fixup planning (M1 single-threaded; the pass shapes are M4-parallel-ready) | single (M1) |
| `pgr-emit` | Passes 4–5: output buffer, reloc apply, chain words, `__LINKEDIT` build, ad-hoc signature, atomic writer | single (M1) |
| `pgr-verify` | read-side verifier + `pgr-verify` CLI (structural, segment contract, chain-walk simulation, signature recompute, `__chain_starts` mirror checks) | single |
| `pgr-fixtures` | deterministic Mach-O image **and relocatable-object** builders shared by tests, benches and the fuzz corpus | test-support |

## Engineering gates

* **No lint suppression.** The workspace carries no `#[allow]`/`#[expect]`;
  CI runs `cargo clippy --workspace --all-targets -- -D warnings` on Linux
  and macOS, `cargo fmt --check`, `cargo doc -D warnings` and locked builds.
* **No `unsafe` anywhere at M0/M1** (workspace-wide `unsafe_code = "forbid"`;
  audited opt-ins are deferred to `pgr-emit`/`pgr-format` with design notes,
  perf doc §5 rule 9).
* **Parsers never panic.** Typed errors everywhere; the fuzz targets
  (`cargo fuzz run parse_any|verify_image|link_object`) and the proptest
  mutation suites keep that honest.
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

# Link a static executable (M1: direct .o inputs only):
./target/release/pgr -o hello hello.o greet.o

# Verify any Mach-O image against the Peregrine contract:
./target/release/pgr-verify hello --strict

# Seed + run the fuzzers (nightly):
cargo run -p pgr-fixtures --example emit_corpus -- fuzz/corpus
cargo +nightly fuzz run link_object -- -max_total_time=120
```

## CI/CD

* **CI** (`.github/workflows/ci.yml`): fmt → clippy (`-D warnings`) → locked
  tests → doc gate → bench compile, on Linux x86_64 and macOS aarch64.
* **Fuzz** (`.github/workflows/fuzz.yml`): nightly libFuzzer runs over
  `parse_any`, `verify_image` and (new at M1) `link_object` with a
  fixture-seeded corpus.
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

## Documentation

* `docs/TDD.md` — technical design document (pipeline, pass specs, data
  structures, chained fixups, layout engine, signing, verifier)
* `docs/peregrine-performance-architecture-and-roadmap.md` — performance
  architecture, deltas against the TDD, multi-year roadmap, spike register
* `docs/BENCHMARKS.md` — recorded M0/M1 baselines and how to read them
* `CHANGELOG.md` — generated by git-cliff

## License

MIT OR Apache-2.0 (see `LICENSE-MIT` / `LICENSE-APACHE`).

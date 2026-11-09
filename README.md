<div align="center">
  <img src="https://cdn.jsdelivr.net/gh/elcoosp/peregrine@main/docs/logo.png" alt="Peregrine Logo" width="300"/>
  <p>
    <strong>A deterministic Mach-O linker for Apple arm64, built verifier-first in safe Rust.</strong><br/>
    Peregrine drives a six-pass pipeline — parallel parse, two-level resolution,
    layout, fused tile emit, concurrent flush — over relocatable objects, static
    archives, <code>.tbd</code> stubs and dylibs, and writes chained-fixup
    executables, dylibs and bundles with an ad-hoc code signature. Every output
    is gated by the bundled <code>pgr-verify</code> checker, which replays dyld's
    bind walk and recomputes the signature page hashes before the test suite
    calls a link finished. Built for toolchain and build-system authors, and
    usable from Linux, where the CI matrix links and verifies on every push.
  </p>
  <p>
    <a href="https://github.com/elcoosp/peregrine/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/elcoosp/peregrine/ci.yml?style=flat-square&label=CI" alt="CI status"/></a>
    <a href="https://github.com/elcoosp/peregrine/actions/workflows/fuzz.yml"><img src="https://img.shields.io/github/actions/workflow/status/elcoosp/peregrine/fuzz.yml?style=flat-square&label=fuzz" alt="Fuzz status"/></a>
    <a href="https://github.com/elcoosp/peregrine/blob/main/Cargo.toml"><img src="https://img.shields.io/badge/version-0.5.0-blue?style=flat-square" alt="Version 0.5.0"/></a>
    <a href="https://github.com/elcoosp/peregrine/blob/main/Cargo.toml"><img src="https://img.shields.io/badge/rust-1.85%2B-orange?style=flat-square" alt="MSRV 1.85"/></a>
    <a href="https://github.com/elcoosp/peregrine/blob/main/LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-lightgrey?style=flat-square" alt="Dual license: MIT OR Apache-2.0"/></a>
  </p>
</div>

<p align="center">
  <a href="#quickstart">Quickstart</a> • <a href="#features">Features</a> • <a href="#how-it-works">How it works</a> • <a href="#usage">Usage</a> • <a href="#status">Status</a> • <a href="#learn-more">Learn more</a>
</p>

<img src="https://cdn.jsdelivr.net/gh/elcoosp/peregrine@main/docs/assets/pipeline.png" alt="Peregrine link pipeline: Pass 0 input mapping, Pass 1 parallel parse, Pass 2 resolution, Pass 3 layout and fixup planning, Pass 4 fused tile emit, Pass 5 concurrent flush" width="720"/>

## Quickstart

Prerequisites: Rust 1.85 or newer (stable toolchain, see `rust-toolchain.toml`), on macOS or Linux. The linker produces arm64 macOS binaries from any of these hosts.

```sh
git clone https://github.com/elcoosp/peregrine
cd peregrine
cargo build --release --locked
cargo test --workspace --locked
```

Link a hello-world against the libSystem `.tbd` stub that ships with the macOS SDK:

```sh
clang -arch arm64 -c hello.c -o hello.o      # Apple clang on macOS, or osxcross on Linux
./target/release/pgr -o hello hello.o -l System -L stubs -platform_version macos 12.0 14.0
./target/release/pgr-verify hello --strict
```

`-L stubs` points at a directory of `.tbd` stubs (on macOS: the SDK's `usr/lib`). The driver searches `-L` dirs, then `/usr/lib`; `.tbd` stubs, Mach-O dylibs and static `.a` archives are all accepted library forms.

The same surface scales to real links — static archives with lazy member pull, dead-code stripping, identical code folding, and a relink cache:

```sh
./target/release/pgr -o app main.o -lgreet -L libs \
    -dead_strip -icf=safe -cache .pgr-cache
./target/release/pgr-verify app --strict
```

Every linked image passes `pgr-verify --strict` in the repo's own end-to-end gates — the e2e suite links fixtures, walks the chained fixups, and recomputes signatures before asserting anything else.

## Features

- **ld64-compatible driver surface.** `-dylib`/`-bundle` outputs, two-level namespace, `-weak_library`, `-rpath`, export filters, `-framework`/`-F`, `-filelist`, `-all_load`/`-force_load` and more; every row is tracked with a fixture in [docs/COMPAT.md](docs/COMPAT.md), and unsupported flags fail with actionable errors instead of being silently dropped.
- **Correctness gated by a built-in verifier.** `pgr-verify` re-reads each image: full dyld chain-walk simulation of `LC_DYLD_CHAINED_FIXUPS`, SHA-256 signature page-hash recompute, 16 KiB segment congruence, export-trie walks (including re-export nodes), `B`/`BL` branch-range decoding, and a dylib+executable pair gate. It ships as a CLI (`--strict`, `--json`) and as a library.
- **Size optimizations with recorded evidence.** `-dead_strip` mark-sweep over symbol-boundary atoms; `-icf=safe`/`-icf=all` identical code folding via color refinement; cross-input `__cstring` merging; ranlib-guided lazy archive member pull. Numbers and methods are recorded in [docs/BENCHMARKS.md](docs/BENCHMARKS.md) (e.g. the dead-strip bench link runs 1.9x faster than the unstripped link on a 50%-dead corpus).
- **Deterministic output.** Double links are byte-identical (a CI-level gate), the parallel fused tile emit is byte-identical to the reference emit kept in-tree, and nothing reads hash iteration order — parallel schedules change who computes a result, never the result.
- **Safe, panic-free parsing.** The workspace forbids `unsafe` (`unsafe_code = "forbid"`) and carries no lint suppressions; parsers return typed errors and never panic. Nightly cargo-fuzz targets (`parse_any`, `parse_tbd`, `verify_image`, `link_object`) plus stable proptests keep that honest.
- **Relink caching.** Content-addressed, checksum-framed caches for parsed objects and frozen `.tbd` export sets (`-cache <dir>`, `PGR_CACHE_DIR`, `-no_cache`); cached and uncached outputs are byte-identical, and corruption falls back to a silent re-parse.
- **Resident relinking (M8).** `pgr -resident` routes a link through the optional `pgrd` daemon, which keeps the parsed state of unchanged inputs (POIs), the input bytes and the emit buffer across links: a warm relink transfers manifests only, skips the parse (hit-counted), and reuses its output buffer. Optional and transparent by contract — the daemon is started on demand, idles out, and every failure silently falls back to the one-shot link. Resident output is byte-identical to the one-shot link (a test gate, not a promise): the daemon holds no output state, so a crash or restart can never corrupt an image.
- **In-place incremental relinking (M9).** `pgr -incremental` records the link's emit plan next to the output (`<output>.pgr-inc`) and, on the next link, patches only the changed 16 KiB tiles into a copy-on-write clone of the previous output (`fclonefileat` on APFS), rebuilds page 0 with the fresh `LC_UUID`, and re-signs from the merged page-hash table — recorded hashes for clean pages, recomputed for dirty ones. Slack-anchored layout (the M8-c policy, anchored cross-link) keeps a changed section where it was, and the §7.3 fallback ladder now executes its middle rung: a section that overflows its anchor within the relayout bound holds its base while everything behind it shifts, and the relayout tier patches the moved suffix (clone resized, re-signed at the moved signature boundary) instead of re-running the full link — an outgrown `__LINKEDIT` reservation moves the boundary the same way. Anything else (or any record problem) still falls back to the full link silently. The engine's contract — the patched file is byte-identical to the full fused emit of the same plan — is a test gate, and `-incremental-verify` re-proves it per link plus a strict `pgr-verify` pass. One-function edits patch ~1% of an 8 MiB image's bytes, and a slack-overflowing edit patches ~13% through the relayout tier (docs/BENCHMARKS.md).
- **Current Mach-O coverage.** `DYLD_CHAINED_PTR_64_OFFSET` chained fixups with a classic `LC_DYLD_INFO_ONLY` opcode fallback for pre-12.0 deployment targets, full export tries with re-exports, arm64 GOT/stub synthesis, branch veneers for beyond-±128 MiB calls, ad-hoc signing, `.tbd` v3/v4, and BSD/GNU long-name archives. Mach-O constants are cross-checked against the `object` crate in CI.

## How it works

Peregrine is a six-pass pipeline split across six crates. `pgr-driver` maps inputs (Pass 0) and drives the loop; `pgr-format` provides zero-copy, bounds-checked parsing of Mach-O, archives, `.tbd` stubs, chained fixups and signature blobs; `pgr-core` runs Passes 1–3 (LPT-scheduled parallel parse and interning, two-level symbol resolution with archive liveness, layout with `__got`/`__stubs` synthesis, ICF, dead-strip and fixup planning); `pgr-emit` runs Passes 4–5, where parallel 16 KiB tiles copy runs, apply relocations, encode chain words, place `__LINKEDIT` and hash signature pages in one pass over each byte, then a 4-writer `pwrite` pool flushes the file. `pgr-verify` closes the loop by treating the output as a hostile third-party image and validating it against the contract dyld will enforce at load time. `pgr-daemon` (M8) wraps the same pipeline in a resident server: unchanged inputs keep their parsed state across links, with byte-identity to the one-shot link gated by tests.

| Crate | Role |
|---|---|
| `pgr-driver` | the `pgr` CLI binary: option parsing, input classification, the Pass 0–5 loop |
| `pgr-format` | zero-copy Mach-O primitives: headers, load commands, symtab, relocations, chained fixups, export tries, `.tbd` v3/v4, `!<arch>` archives, signature blobs |
| `pgr-core` | Passes 1–3: interning, two-level resolution, layout, ICF, dead-strip, thunks, dyld-info planning, caches, the M8 reverse reference index / insertion-stable import table / slack policy |
| `pgr-emit` | Passes 4–5: fused tile emit, relocation application, ad-hoc signature, concurrent writer — and the M9 incremental engine (record, plan, clone-and-patch) |
| `pgr-verify` | the read-side verifier: library and `pgr-verify` CLI |
| `pgr-daemon` | the M8 resident link server: the `pgrd` daemon, its wire protocol, the persistent session (POIs + bytes + emit buffer) and the client `pgr -resident` speaks |
| `pgr-fixtures` | deterministic Mach-O object and archive builders shared by tests, benches and the fuzz corpus |

## Usage

Key driver flags (full surface: `pgr --help`):

| Group | Flags |
|---|---|
| Output kind | `-o`, `-static`, `-dylib`, `-bundle`, `-e` |
| Inputs and search | object/`.a`/`.tbd`/`.dylib` paths, `-l`, `-L`, `-filelist path[,dir]`, `-framework`/`-F`, `-all_load`, `-force_load`, `-u` |
| Symbol binding | `-flat_namespace`, `-undefined error\|dynamic_lookup`, `-weak_library`, `-rpath` |
| Dylib metadata | `-install_name`, `-current_version`, `-compatibility_version`, `-reexport_library`, `-exported_symbols_list`, `-unexported_symbols_list` |
| Codegen and size | `-dead_strip`, `-icf=safe\|all\|none`, `-fixup_chains`/`-no_fixup_chains`, `-adhoc`/`-no_adhoc`, `-segalign`, `-headerpad`, `-sectcreate` |
| Caching and jobs | `-cache <dir>`, `-no_cache`, `PGR_CACHE_DIR`, `-cache_max <bytes>`, `PGR_CACHE_MAX`, `PGR_JOBS` |
| Incremental mode (M9) | `-incremental`, `-no_incremental`, `-incremental-verify`, `PGR_INCREMENTAL_RECORD`, `PGR_INCREMENTAL_DEBUG` |
| Resident mode (M8) | `-resident`, `-resident_socket <path>`, `PGR_DAEMON_SOCK`, `PGR_RESIDENT_DEBUG`; the `pgrd` daemon: `--socket`, `--idle-secs`, `--shutdown` |

Environment: `PGR_JOBS` sizes the shared compute pool (default: available parallelism); `PGR_LLD64=/path/to/ld64.lld` enables the golden harness that compares Peregrine's bind semantics slot-for-slot against `ld64.lld` (skipped when lld is absent).

As a library, the crates are path dependencies (not published to crates.io — `publish = false` in each manifest), so reference them by path or git. The verifier is the natural entry point for tooling:

```rust
let report = pgr_verify::verify(&bytes, &pgr_verify::Options::default());
for issue in &report.issues {
    println!("{:?} [{}] {}", issue.severity, issue.code.as_str(), issue.message);
}
```

> [!TIP]
> When auditing a linker's output, start from `pgr-verify <image> --json`: the machine-readable report names every issue with a stable code (`fixups_chain`, `export_trie`, `branch_range`, `signature_hash_mismatch`, ...), so CI jobs can gate on specific violations instead of grepping text.

Compatibility is a tracked checklist rather than a promise: [docs/COMPAT.md](docs/COMPAT.md) lists each ld64 load command, driver flag and semantic behavior with its status, the milestone that shipped it, and its fixture. Flags that arrive in later milestones (`-order_file`, `-ObjC`, TLV, LTO execution) are rejected with a clear message today.

## Status

> [!NOTE]
> Peregrine is a post-1.0 project (v1.2.0) whose milestone stream follows the architecture doc: M6 (ICF, veneers, legacy fixups, Stage A caches) and M7 (versioned caches, build-system surface, the ≥ 98% compatibility suite, fuzzing at scale) shipped the in-tree scope; M8 shipped the resident + incremental foundations — the `pgrd` resident server with its persistent POI session, the reverse reference index, the insertion-stable import table, and slack-aware layout with the §7.3 fallback ladder; M9-v1 ships the in-place incremental relink engine — the versioned link record, the span-diff patch planner, the clone-and-patch output path with the merged-hash CodeDirectory rebuild, slack anchors, `-incremental`/`-incremental-verify`, and the byte-identity contract (tests + per-link audit); M9 tier 2b ships the per-symbol change-propagation planner — the record's section-digest table (content + symbol records) and the relink planner's propagation gate, which scopes every content change through the M8 reverse reference index and falls back when the span diff escapes the scope; M9 tier 2 ships the segment-relayout patch tier — the §7.3 ladder's middle rung executes (a slack overflow within the bound, or an outgrown `__LINKEDIT` reservation, patches the moved suffix through the record's v4 output-section content digests instead of falling back) — and the M9 GA hardening pass ships the ladder's shrink rung (an unsigned relink has no signature boundary to anchor the tail, so a symtab/string-pool shrink now patches through the relayout tier with the clone truncated instead of falling back) plus the seeded randomized edit gate (the engine-level and end-to-end `-incremental-verify` walks; `PGR_RANDOMIZED_STEPS` sizes the walk, 2000 sequences × 5 steps being the roadmap's 10⁴ GA profile for the decision rig). The target is arm64-apple-darwin only — `CPU_TYPE_ARM64`, little-endian, 16 KiB segment congruence — producing `MH_EXECUTE`, `MH_DYLIB` and `MH_BUNDLE` images; chained fixups serve macOS 12.0+ targets, and older deployment targets (or `-no_fixup_chains`) get classic `LC_DYLD_INFO_ONLY` rebase/bind streams. The host side is platform-independent: CI builds and runs the full test suite on Linux x86_64 and macOS aarch64. Performance claims stop at the dev-sandbox baselines in docs/BENCHMARKS.md — the hardware gates against `ld64.lld` on Apple Silicon (including M8's resident-relink gate and M9's §7.3 relink targets) are specified but not yet measured, the M8 warm-relink bench is recorded honestly as a wash on the Pass 2/3-bound sandbox corpus, and the M9 incremental bench records both the bytes-written win (~1% of an 8 MiB image per one-function edit, ~13% per slack-overflowing edit through the segment-relayout tier) and the ext4-clone wash. LTO object execution, compact-unwind synthesis, `-order_file`, TLV, ObjC/Swift semantics beyond section pass-through, M9 tier 2c ships the incremental resolve’s decision core — the snapshot-backed reuse of Pass 2’s winners scoped by the propagation seeds and equality-gated against the full resolve — and the remaining M9 GA items (the resolve’s record-side wiring, resident + incremental fusion) are deferred with reasons in docs/COMPAT.md and the roadmap.

## Learn more

- [docs/COMPAT.md](docs/COMPAT.md) — ld64 compatibility checklist: load commands, driver flags, linking semantics, each with a fixture.
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md) — recorded milestone baselines (parser, link, trie, emit, ICF, caches) and how to read them.
- [docs/TDD.md](docs/TDD.md) — the technical design document: pass specifications, data structures, chained fixups, layout, signing, verifier.
- [docs/peregrine-performance-architecture-and-roadmap.md](docs/peregrine-performance-architecture-and-roadmap.md) — performance architecture and the multi-year roadmap.
- [docs/assets/](docs/assets) — the pipeline, output-map, alignment and fixup-chain diagrams.
- [fuzz/](fuzz) — cargo-fuzz targets and the fixture-seeded corpus.

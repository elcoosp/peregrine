<div align="center">
  <img src="https://cdn.jsdelivr.net/gh/elcoosp/peregrine@main/docs/logo.png" alt="Peregrine Logo" width="300"/>
  <p>
    <strong>A deterministic Mach-O linker for Apple arm64 — verifier-first, in safe Rust.</strong><br/>
    Six parallel passes from <code>.o</code> / <code>.a</code> / <code>.tbd</code> to signed executables,
    dylibs and bundles — every image gated by the bundled <code>pgr-verify</code>, which replays dyld's
    bind walk and recomputes the signature before a link counts as finished. Warm edit loops skip the
    work: caches, a resident daemon, and clone-and-patch relinks that rewrite only changed 16 KiB tiles.
    Links from macOS <em>and</em> Linux; built for toolchain and build-system authors.
  </p>
  <p>
    <a href="https://github.com/elcoosp/peregrine/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/elcoosp/peregrine/ci.yml?style=flat-square&label=CI" alt="CI status"/></a>
    <a href="https://github.com/elcoosp/peregrine/actions/workflows/fuzz.yml"><img src="https://img.shields.io/github/actions/workflow/status/elcoosp/peregrine/fuzz.yml?style=flat-square&label=fuzz" alt="Fuzz status"/></a>
    <a href="https://github.com/elcoosp/peregrine/blob/main/Cargo.toml"><img src="https://img.shields.io/badge/version-0.22.0-blue?style=flat-square" alt="Version 0.22.0"/></a>
    <a href="https://github.com/elcoosp/peregrine/blob/main/Cargo.toml"><img src="https://img.shields.io/badge/rust-1.85%2B-orange?style=flat-square" alt="MSRV 1.85"/></a>
    <a href="https://github.com/elcoosp/peregrine/blob/main/LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-lightgrey?style=flat-square" alt="Dual license: MIT OR Apache-2.0"/></a>
  </p>
</div>

<p align="center">
  <a href="#quickstart">Quickstart</a> • <a href="#how-it-works">Pipeline</a> • <a href="#fast-edit-loops">Edit loops</a> • <a href="#verification--determinism">Verification</a> • <a href="#compatibility">Compatibility</a> • <a href="#performance">Performance</a> • <a href="#status--roadmap">Status</a> • <a href="#learn-more">Learn more</a>
</p>

---

## Highlights

| | |
|---|---|
| 🔍 **Verifier-first** | Every output is re-read as a hostile third-party image: full dyld chain-walk simulation, SHA-256 signature recompute, segment congruence, export tries, branch ranges. CLI **and** library. |
| 🔒 **Deterministic** | Double links are byte-identical (CI gate); the parallel fused emit is byte-identical to the in-tree reference emit; nothing reads hash iteration order. |
| 🦀 **Safe Rust** | `unsafe_code = "forbid"` workspace-wide, zero lint suppressions. Typed errors, no panics, 7 nightly fuzz targets + proptests. |
| ⚡ **Warm edit loops** | Content-addressed caches → resident `pgrd` sessions → in-place incremental relinks: **~1 % of an 8 MiB image's bytes** per one-function edit (bench-recorded). |
| 🧭 **ld64-shaped driver** | Tracked compatibility checklist, one fixture per row. Unsupported flags **refuse with the fix** — never silently dropped. |
| 🖥️ **Cross-host** | Produces arm64 macOS images from macOS or Linux; CI links and verifies on both. |

> [!IMPORTANT]
> **Every fast path is gated, not promised.** Cached, resident and incremental outputs are
> byte-identity-tested against the one-shot link, and every doubt falls back to the full link
> silently. Performance claims stop at recorded dev-sandbox baselines — the Apple Silicon
> hardware gates are specified, not yet measured ([Performance](#performance)).

## Quickstart

Rust **1.85+** (stable, see `rust-toolchain.toml`), on macOS or Linux:

```sh
git clone https://github.com/elcoosp/peregrine
cd peregrine
cargo build --release --locked
cargo test --workspace --locked
```

Link a hello-world against the libSystem `.tbd` stub, then verify it:

```sh
clang -arch arm64 -c hello.c -o hello.o    # Apple clang on macOS, or osxcross on Linux
./target/release/pgr -o hello hello.o -l System -L stubs -platform_version macos 12.0 14.0
./target/release/pgr-verify hello --strict
```

`-L stubs` points at a directory of `.tbd` stubs (on macOS: the SDK's `usr/lib`). The driver
searches `-L` dirs, then `/usr/lib`; `.tbd` stubs, Mach-O dylibs and static `.a` archives are all
accepted library forms. The same surface scales to real links:

```sh
./target/release/pgr -o app main.o -lgreet -L libs \
    -dead_strip -icf=safe -cache .pgr-cache
./target/release/pgr-verify app --strict
```

Every image in the repo's own e2e gates passes `pgr-verify --strict` — the suite links fixtures,
walks the chained fixups and recomputes signatures before asserting anything else.
(`pgr` below means `./target/release/pgr`.)

## How it works

<img src="https://cdn.jsdelivr.net/gh/elcoosp/peregrine@main/docs/assets/pipeline.png" alt="Peregrine link pipeline: Pass 0 input mapping, Pass 1 parallel parse, Pass 2 resolution, Pass 3 layout and fixup planning, Pass 4 fused tile emit, Pass 5 concurrent flush" width="720"/>

| Pass | Work |
|---|---|
| **0** | Input mapping: argv, `-L`/`-l` search, archive & dylib discovery |
| **1** | Parallel parse → atomize at symbol boundaries → intern (LPT-scheduled; cache hits load parsed-object images) |
| **2** | Two-level symbol resolution, archive liveness, dead-strip roots |
| **3** | Layout, `__got`/`__stubs` synthesis, ICF, fixup planning, insertion-stable import table |
| **4** | **Fused 16 KiB tile emit** — copy → relocate → chain-encode → hash in one cache-hot pass over each byte |
| **5** | 4-writer `pwrite` pool overlapped with the emit tail; atomic rename into place |

`pgr-verify` closes the loop against the contract dyld enforces at load time; `pgrd` wraps the
same pipeline in a resident session for warm relinks.

| Crate | Role |
|---|---|
| `pgr-driver` | the `pgr` CLI: option parsing, input classification, the Pass 0–5 loop |
| `pgr-format` | zero-copy, bounds-checked Mach-O primitives: headers, load commands, symtab, relocs, chained fixups (both word families), export tries, `.tbd` v3/v4, archives, signature blobs |
| `pgr-core` | Passes 1–3: interning, resolution, layout, ICF, dead-strip, thunks, fixup planning, caches, reverse reference index, slack policy, the validated image-knob decisions |
| `pgr-emit` | Passes 4–5: fused tile emit, ad-hoc signing, writer pool — plus the incremental engine (record, plan, clone-and-patch) and `-r` object assembly |
| `pgr-verify` | the read-side verifier: library + CLI, selectable checks, JSON reports, baseline diffs |
| `pgr-daemon` | `pgrd`: versioned wire protocol (v22), persistent sessions (POIs + bytes + emit buffer + resident output), the served incremental audit |
| `pgr-fixtures` | deterministic Mach-O object/archive builders shared by tests, benches and the fuzz corpus |

## Fast edit loops

Three lanes, one pipeline — each lane's output is byte-identical to the one-shot link (a test
gate), and each falls back silently on any doubt:

| Lane | Flag | What gets skipped |
|---|---|---|
| **Cached inputs** | `-cache <dir>` | Re-parsing unchanged objects & `.tbd` stubs — content-addressed, checksum-framed parsed-object images and frozen export sets; corruption → silent re-parse |
| **Resident session** | `-resident` | The daemon keeps parsed state, input bytes and the emit buffer across links; a warm relink transfers manifests only. Output residency: replies are changed-tile streams, an untouched relink ships **nothing** |
| **Incremental relink** | `-incremental` | The write itself: only changed 16 KiB tiles are patched into a copy-on-write clone of the previous output (`fclonefileat` on APFS), page 0 rebuilt with a fresh `LC_UUID`, re-signed from the merged page-hash table |

The incremental engine's fallback ladder — every rung lands on a correct image:

| Rung | When | What happens |
|---|---|---|
| **Tile patch** | Changed sections fit their slack anchors | Dirty tiles patched into the clone; clean pages keep recorded hashes |
| **Segment relayout** | Slack overflow within the relayout bound, an outgrown `__LINKEDIT` reservation, or an unsigned shrink | Section holds its base, the moved suffix is patched; clone resized, re-signed at the moved boundary |
| **Full link** | Anything else — record problem, input-list or dylib-export change | Silent fallback, record renewed so the cycle never stalls |

```sh
pgr -o app main.o -lgreet -L libs -incremental -incremental-verify   # patch + per-link audit
pgr -o app main.o -lgreet -L libs -resident -incremental             # the whole cycle, warm
pgr --print-record app.pgr-inc                                       # what the last link recorded
```

- **Change propagation is per-symbol**: the record's section digests + the reverse reference
  index scope every edit; the Pass-2 resolution snapshot (record v5) replays recorded winners
  and re-resolves only seed-touched names — equality-gated against the full resolve.
- **The contract is a gate, not a claim**: the patched file is byte-identical to the full fused
  emit of the same plan (tests + per-link audit), and a seeded randomized-edit suite
  (2000 sequences × 5 steps) walks the ladder end-to-end.
- **The daemon never touches the filesystem** — the client hash-verifies the tile replay and
  writes through the normal atomic-rename path, so a crash or restart can never corrupt an
  image. `-incremental-verify` is served in-session: divergence is healed in memory before it
  ships, and a failing verdict is never written.

## Verification & determinism

`pgr-verify` treats every image — including Peregrine's own — as hostile input:

- Full `LC_DYLD_CHAINED_FIXUPS` chain-walk simulation (both word families: `64_OFFSET` and
  arm64e, including authenticated words) · classic opcode streams below the fixups floor
- SHA-256 signature page-hash recompute · 16 KiB segment congruence · export-trie walks
  including re-export nodes · `B`/`BL` branch-range decoding
- Dylib + executable **pair gate** (family-aware two-level bind replay) · `MH_OBJECT` contract
  for `-r` · per-platform build-version & fixups-floor gates · W^X and protection invariants

Five byte-identity gates run in CI:

| Gate | Contract |
|---|---|
| Double link | byte-identical output |
| Fused tile emit vs reference emit | byte-identical (reference kept in-tree) |
| Cached vs uncached | byte-identical |
| Resident vs one-shot | byte-identical (daemon never writes; client does) |
| Incremental vs full emit | byte-identical (tests + per-link audit + `-incremental-verify`) |

Build-system surfaces — reports are interchange shapes, not print-outs:

```sh
pgr-verify app --strict --json > report.json     # stable issue codes, library writer/reader
pgr-verify app --baseline report.json --fail-on new   # only NEW findings fail the build
pgr-verify app --checks segments,fixups          # fail fast on one contract (--list-checks)
pgr --print-fixup-encoding macos 11.0 14.0       # the encoding decision, before the link
```

As a library (crates are git/path dependencies, `publish = false`):

```rust
let report = pgr_verify::verify(&bytes, &pgr_verify::Options::default());
for issue in &report.issues {
    println!("{:?} [{}] {}", issue.severity, issue.code.as_str(), issue.message);
}
// Interchange: pgr_verify::to_json / parse_report_json (round-trip gated).
// Baselines: BaselineDelta::between under an IssueIdentity policy —
// OffsetIdentity (position-aware) or CodeIdentity (survives layout shifts).
```

> [!TIP]
> Gate CI on `pgr-verify <image> --json`: every issue carries a stable code
> (`fixups_chain`, `export_trie`, `branch_range`, `signature_hash_mismatch`, …), so jobs fail on
> specific violations instead of grepping text.

Safety net: workspace-wide `unsafe_code = "forbid"`, no lint suppressions, parsers that return
typed errors and never panic — kept honest by nightly cargo-fuzz (`parse_any`, `parse_tbd`,
`verify_image`, `link_object`, `link_record`, `dyld_info_streams`, `cache_entries`) plus stable
proptests. Mach-O constants are cross-checked against the `object` crate in CI.

## Compatibility

A tracked checklist, not a promise: [docs/COMPAT.md](docs/COMPAT.md) lists each ld64 load
command, driver flag and semantic behavior with its status, shipping milestone and fixture.
Not-yet-supported surface (`-ObjC`, TLV, LTO execution) is **rejected with a clear message**.

| Group | Flags |
|---|---|
| Output kind | `-o`, `-static`, `-dylib`, `-bundle`, `-r` (relocatable), `-e` |
| Platform | `-platform_version macos\|ios\|tvos\|watchos\|visionos <min> <sdk>` |
| Inputs & search | `.o`/`.a`/`.tbd`/`.dylib`, `-l`, `-L`, `-filelist`, `-framework`/`-F`, `-all_load`, `-force_load`, `-u` |
| Binding | `-flat_namespace`, `-undefined error\|dynamic_lookup`, `-weak_library`/`-weak_framework`, `-lazy_library`/`-lazy_framework`, `-rpath`, `-bundle_loader` (host-bound binds, main-exec ordinal) |
| Exports & identity | `-exported_symbols_list`/`-unexported_symbols_list` (exact or `*` globs), `-alias`, `-install_name`, `-current_version`, `-compatibility_version`, `-reexport_library`/`-reexport_framework`, `-sub_umbrella`/`-sub_library`/`-sub_client` |
| Image layout | `-pagezero_size` (exe), `-image_base` (dylib/bundle), `-segprot <seg> <max> <init>`, `-stack_size`, `-init_offsets`/`-no_init_offsets`, `-segalign`, `-headerpad`, `-sectcreate` |
| Order & report | `-order_file` (ld64-style rank sort), `-map` (rendered from the emit plan — report and bytes cannot disagree) |
| Size | `-dead_strip`, `-icf=safe\|all\|none`, cross-input `__cstring` merging, lazy archive member pull |
| Fixups & signing | `-fixup_chains`/`-no_fixup_chains`, `-fixup_chains_format offset64\|arm64e` (incl. authenticated PAC words), `-adhoc`/`-no_adhoc` |
| Linkedit metadata | `-no_function_starts` (suppress `LC_FUNCTION_STARTS`), `-no_data_in_code` (suppress the carried data-in-code stream) |
| Dyld environment | `-dyld_env DYLD_<var>=<value>` (main executable only) |
| Fast paths | `-cache`/`-no_cache`/`-cache_max`, `-resident`/`-resident_socket`, `-incremental`/`-no_incremental`/`-incremental-verify` |
| Queries | `--print-record`, `--print-fixup-encoding`; `pgr-verify --strict --json --checks --list-checks --baseline --fail-on` |
| Daemon | `pgrd --socket --idle-secs --shutdown` |

Every knob refuses the combinations it cannot serve — `-order_file` × `-resident`, `-map` ×
`-incremental`, `-image_base` on executables, a named chain format below the platform floor —
and each refusal names the fix. Defaults keep every pre-knob link byte-identical.

**Fixups & platforms.** `DYLD_CHAINED_PTR_64_OFFSET` by default; the arm64e family (authenticated
rebases/binds included) via `-fixup_chains_format`. Below the platform floor — or with
`-no_fixup_chains` — classic `LC_DYLD_INFO_ONLY` streams encode the *same* fixups:

| Platform | Chained fixups from |
|---|---|
| macOS | 12.0 |
| iOS / tvOS | 15.0 |
| watchOS | 8.0 |
| visionOS | 1.0 |

One floor table, three readers (layout, verifier, `--print-fixup-encoding`) — the encoding
decision is a typed value (`pgr_core::platform::FixupEncoding`) a build system can read before
Pass 3 runs.

<details><summary><b>Environment variables</b></summary>

| Variable | Effect |
|---|---|
| `PGR_JOBS` | sizes the shared compute pool (default: available parallelism) |
| `PGR_LLD64` | path to `ld64.lld` — enables the golden harness comparing bind semantics slot-for-slot (skipped when absent) |
| `PGR_TRACING` | installs a tracing subscriber in the consumer examples |
| `PGR_CACHE_DIR` / `PGR_CACHE_MAX` | cache location / size ceiling |
| `PGR_INCREMENTAL_RECORD` / `PGR_INCREMENTAL_DEBUG` | record path override / incremental debug output |
| `PGR_DAEMON_SOCK` / `PGR_RESIDENT_DEBUG` | daemon socket / resident debug output |
| `PGR_RANDOMIZED_STEPS` | sizes the seeded randomized-edit gate walk |

</details>

## Performance

The goal is the fastest arm64 macOS linker; the claim waits for the hardware gates. Two
strategies, per the [architecture doc](docs/peregrine-performance-architecture-and-roadmap.md):
run the full link at hardware speed (fused tiles, zero-copy parse, de-indirected resolution,
overlap), and — the bigger multiplier — **don't do the work** (caches, residency, clone-and-patch).

**Recorded evidence — dev sandbox only** ([docs/BENCHMARKS.md](docs/BENCHMARKS.md)):

| Benchmark | Result |
|---|---|
| `-dead_strip`, 50 %-dead corpus | **1.9× faster** than the unstripped link |
| Incremental, one-function edit, 8 MiB image | **~1 % of bytes written** |
| Incremental, slack-overflowing edit (relayout tier) | **~13 % of bytes written** |
| Resident warm relink (sandbox corpus) | a wash — the corpus is Pass 2/3-bound; recorded honestly |
| Clone step on ext4 (Linux host) | a wash — APFS CoW is the fast path; the bytes-written win stands |

> [!WARNING]
> The hardware gates against `ld64.lld` on Apple Silicon — clean-link targets, the resident
> relink gate, and the §7.3 goal of **< 100 ms for a one-function edit at 1 GiB output** — are
> *specified but not yet measured*. Nothing in this README claims otherwise.

## Status & roadmap

**v0.22.0, pre-1.0.** Target: `arm64-apple-darwin` only (`CPU_TYPE_ARM64`, little-endian, 16 KiB
congruence), producing `MH_EXECUTE`, `MH_DYLIB`, `MH_BUNDLE` and `-r` `MH_OBJECT` images. Hosts:
CI builds, links and verifies on Linux x86_64 and macOS aarch64. Crates are consumed by git/path
(`publish = false`).

The milestone stream, per the [architecture doc](docs/peregrine-performance-architecture-and-roadmap.md):

| Milestone | Shipped surface |
|---|---|
| **M0–M5** | Verifier-first foundations: six-pass pipeline, dylibs & bundles, fused tile emit, real-world link surface |
| **M6–M7** | ICF, branch veneers, legacy fixups, Stage-A caches; versioned caches, compat suite, fuzzing at scale |
| **M8** | Resident `pgrd` + incremental foundations: reverse reference index, insertion-stable imports, slack-anchored layout |
| **M9** | Incremental engine → GA: record v5, span-diff planner, clone-and-patch, relayout + shrink rungs, per-symbol propagation, snapshot-backed resolve reuse, randomized-edit gate, daemon fusion (record → served audit → output residency) |
| **M10** | `-r` relocatable output (self-consumption gated); five-platform targeting + per-platform floors; `FixupEncoding` seam & query; arm64e end-to-end (read → producer → auth → pair gate → floor refusals) |
| **M11** | `-order_file` rank seam + `-map` link map, rendered from the plan |
| **M12** | Selectable verifier checks (`--checks`, `--list-checks`, the `ImageCheck` registry) |
| **M13** | Report JSON interchange + baseline gate (`IssueIdentity` policies); `.pgr-inc` record inspector |
| **M14** | Glob export filters; weak/lazy dylib & framework loads |
| **M15–M19** | Image knobs: `-pagezero_size`, `-init_offsets`, `-segprot`, `-stack_size`, `-image_base` |
| **M20–M22** | Dylib identity: `-sub_umbrella`/`-sub_library`, `-sub_client`, `-dyld_env` |
| **M23–M25** | `-reexport_framework`, `-alias` (one body, two names), `-bundle_loader` |
| **M26–M27** | Header assembly: `-dylinker` (the loader path), `-no_pie` (the flag word) |
| **M28–M29** | Packing decisions: `-sectalign` (per-section alignment floors), `-headerpad` (the reserved header region — the advisory no-op promoted) |
| **M30–M31** | Linkedit metadata: data-in-code carriage (the input `LC_DATA_IN_CODE` streams ride the atom map onto the output — the design doc's named slot, no longer dropped), `-no_data_in_code` (the suppression), `-no_function_starts` (the second advisory no-op promoted — the command drops on the named decision) |

Every knob ships the same way: a validated decision in the library, verifier gates for the
shapes it can break, a parity bench, a runnable consumer example, daemon-wire carriage (protocol v22)

**Still on the roadmap:** the Apple Silicon hardware gates · LTO object execution ·
compact-unwind synthesis · TLV · ObjC/Swift semantics beyond section pass-through.

<details><summary><b>Consumer examples (one per milestone surface)</b></summary>

Each ships in its crate's `examples/` with a matching bench — run with
`cargo run -p <crate> --example <name>`:

`relocatable_link` · `platform_matrix` · `platform_floor` · `encoding_query` ·
`arm64e_producer` · `fixup_chains_auth` · `arm64e_pair` · `chain_format_floor` ·
`glob_export_filter` · `lazy_library_link` · `pagezero_link` · `init_offsets_link` ·
`segprot_link` · `stack_size_link` · `icf_link` · `dead_strip_link` · `image_base_link` ·
`umbrella_link` · `sub_client_link` · `dyld_env_link` · `reexport_framework_link` ·
`alias_link` · `bundle_loader_link` · `dylinker_link` · `no_pie_link` ·
`sectalign_link` · `headerpad_link` · `data_in_code_link` · `function_starts_link`

</details>

## Learn more

- [docs/COMPAT.md](docs/COMPAT.md) — the ld64 compatibility checklist: load commands, driver flags, semantics, each with a fixture
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md) — recorded milestone baselines (parser, link, trie, emit, ICF, caches, incremental) and how to read them
- [docs/TDD.md](docs/TDD.md) — the technical design: pass specs, data structures, chained fixups, layout, signing, verifier
- [Performance architecture & roadmap](docs/peregrine-performance-architecture-and-roadmap.md) — the speed thesis, the avoid-work stages, the multi-year plan
- [docs/assets/](docs/assets) — pipeline, output-map, alignment and fixup-chain diagrams
- [fuzz/](fuzz) — cargo-fuzz targets and the fixture-seeded corpus

---

<div align="center">
  <sub>Licensed under MIT OR Apache-2.0 · Verifier-first · Deterministic by CI gate · No <code>unsafe</code>, no silent drops</sub>
</div>

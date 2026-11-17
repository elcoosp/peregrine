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
| `pgr-daemon` | `pgrd`: versioned wire protocol (v42), persistent sessions (POIs + bytes + emit buffer + resident output), the served incremental audit, the served per-pass time report |
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
Not-yet-supported surface (LTO execution) is **rejected with a clear message**.

| Group | Flags |
|---|---|
| Output kind | `-o`, `-static`, `-dylib`, `-bundle`, `-r` (relocatable), `-e` |
| Platform | `-platform_version macos\|ios\|tvos\|watchos\|visionos <min> <sdk>` |
| Inputs & search | `.o`/`.a`/`.tbd`/`.dylib`, `-l`, `-L`, `-filelist`, `-framework`/`-F`, `-all_load`, `-force_load`, `-u` |
| Binding | `-flat_namespace`, `-undefined error\|dynamic_lookup`, `-U <symbol>` (make-undefined: the definition drops, the reference binds per `-undefined`), `-weak_library`/`-weak_framework`, `-lazy_library`/`-lazy_framework`, `-upward_library`/`-upward_framework` (the umbrella-relationship load, `LC_LOAD_UPWARD_DYLIB` — M45), `-rpath`, `-bundle_loader` (host-bound binds, main-exec ordinal), `-no_weak_imports` (a weak import dyld must look up at runtime refuses with the symbol named — a link-time resolution never does; M50) |
| Exports & identity | `-exported_symbols_list`/`-unexported_symbols_list` (exact or `*` globs), `-alias`, `-install_name`, `-current_version`, `-compatibility_version`, `-reexport_library`/`-reexport_framework`, `-sub_umbrella`/`-sub_library`/`-sub_client`, `-init <symbol>` (the dylib's load-time initializer, `LC_ROUTINES_64` — M48) |
| Image layout | `-pagezero_size` (exe), `-image_base` (dylib/bundle), `-segprot <seg> <max> <init>`, `-stack_size`, `-init_offsets`/`-no_init_offsets`, `-segalign`, `-headerpad`, `-sectcreate`, `-no_branch_islands` (refuse the veneers the Pass-3 fixed point plans — M47), `-allow_stack_execute` (the `MH_ALLOW_STACK_EXECUTION` flag word an executable plans with — M51) |
| Order & report | `-order_file` (ld64-style rank sort), `-map` (rendered from the emit plan — report and bytes cannot disagree), `-dependency_info <path>` (ld64's build-system dependency record written beside the link: the linker version, every file the link read, the probed misses, the output — ld64's own binary format; M60) |
| Size | `-dead_strip`, `-export_dynamic` (every global definition roots the strip — the `dlsym` surface, M46), `-icf=safe\|all\|none`, cross-input `__cstring` merging, `-no_deduplicate` (turn the merge off — every input literal rides verbatim), `-dead_strip_dylibs` (drop input dylibs nothing binds against — re-exports and dynamic-lookup providers ride), lazy archive member pull, `-no_dead_strip_inits_and_terms` (the termination routines join the init sections' dead-strip roots — M52) |
| Fixups & signing | `-fixup_chains`/`-no_fixup_chains`, `-fixup_chains_format offset64\|arm64e` (incl. authenticated PAC words), `-adhoc`/`-no_adhoc` |
| Linkedit metadata | `-no_function_starts` (suppress `LC_FUNCTION_STARTS`), `-no_data_in_code` (suppress the carried data-in-code stream), `-no_compact_unwind` (suppress the synthesized `__unwind_info` section — the parse still validates the table), `-no_exported_symbols` (suppress `LC_DYLD_EXPORTS_TRIE` — executables only; a dylib's trie is its two-level contract), `-no_deduplicate` (turn the `__cstring` merge off — every input literal rides verbatim) |
| Dyld environment | `-dyld_env DYLD_<var>=<value>` (main executable only) |
| Fast paths | `-cache`/`-no_cache`/`-cache_max`, `-resident`/`-no_resident`/`-resident_socket`, `-incremental`/`-no_incremental`/`-incremental-verify` |
| Queries | `--print-record`, `--print-fixup-encoding`, `-why_export <symbol>` (repeatable; the definition and every reference site, text or JSON), `-why_load` (why each archive member rode — and each dylib's carriage under `-dead_strip_dylibs`), `--time` / `--time-json` (the per-pass wall report, M58; the resident lane serves its own observed run — wire v40, M59; the in-process incremental ladder rides its rungs since M65 — the fusion lane `-resident -incremental` still refuses), `--trace <path>` (the Chrome-trace timeline, M61/M63/M64; the same lane contract — the ladder's rungs ride the timeline since M65, the fusion lane still refuses); `pgr-verify --strict --json --checks --list-checks --baseline --fail-on` |
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

One floor table, four readers (layout, verifier, `--print-fixup-encoding`, the initializer-offsets decision) — the encoding
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
| **M32–M33** | The last two advisory no-ops promoted: `-no_uuid` (the derived-UUID suppression — the command drops, the emit patch paths consult the plan offset's absent sentinel), `-keep_private_externs` (the private-extern decision — the input `N_PEXT` bit the tree dropped at parse now converts into the locals range by default or stays external and exported under the named keep) |
| **M34** | Compact-unwind synthesis: the input `__LD,__compact_unwind` tables the Pass-1 sweep kept dropping (the `S_ATTR_DEBUG` section the `__LD` skip hid) ride the atom map onto the output `__TEXT,__unwind_info` — the section dyld's unwinder and every backtrace reader walks (header arrays, personality rows in first-use order, the sorted index, regular second-level pages, the LSDA rows); dead-stripped functions drop their rows, ICF-folded duplicates land once on the canonical copy, the personality/LSDA references root their targets under `-dead_strip`; an entry-free corpus plans the pre-M34 bytes (`pgr_core::unwind::synthesize` is the public seam a build system can plan with before any link runs) |
| **M35** | Compact-unwind compressed second-level pages: the density rung past the M34 regular pages — a row rides the compressed family exactly when its offset fits the 24-bit field and its final encoding word sits in the section-level common encodings array (the distinct words in first-use order, capped at the 8-bit index space), consecutive same-family rows share a page, and the compressed page's page-local encodings array rides empty (the two-tier decode libunwind runs answers at tier one); qualifying rows halve the second-level entry width (a 4096-row single-encoding table plans 50 % of the M34 bytes), `pgr_core::unwind::plan_shape`/`synthesized_size_shape` plan the exact shape before any link runs, and the verifier's `unwind` family walks both page families |
| **M36** | The compact-unwind suppression: `-no_compact_unwind` drops the output `__TEXT,__unwind_info` section on the named decision (the pre-M34 bytes exactly, byte-identical to the entry-free link; the file-size delta rides the 16 KiB segment congruence) — the parse still validates the table (the knob is a Pass-3 decision, never a parse blindfold), an incremental knob flip lands on the relayout rung's correct image and the record renews so the cycle never stalls, and the daemon wire v25 carries the decision the resident relink asked for |
| **M37** | Thread-local variables (TLV): the input `S_THREAD_LOCAL_*` sections the pipeline rejected since M5 ride the atom map onto the output `__DATA` segment — the `__thread_vars` descriptors (16-byte thunk/initializer pairs; a section off the stride refuses at parse with the fix), the `__thread_data` initializers, the `__thread_bss` zero-fills (VM-only, their own section — never merged into `__common`); the `ARM64_RELOC_TLVP_LOAD_PAGE21`/`PAGEOFF12` descriptor loads decode and patch ADRP/scaled-LDR-imm12 directly against the descriptor's vaddr (no GOT slot — the descriptor is always a local definition; a descriptor load past this image's definitions refuses with the fix, thread-local variables cannot bind across a dylib boundary); the descriptor slots ride chained fixups (the thunk's bind, the initializer's rebase) and the header declares `MH_HAS_TLV_DESCRIPTORS` exactly when the image carries a thread-local section; the verifier's `tlv` family joins the `--checks` registry (the marker/section parity, the descriptor stride, the descriptors' thread-local data) and the relocatable output round-trips the surface (`-r` keeps the sections and re-encodes the TLVP pair; the object links again) |
| **M38** | The install-name auto-floor: `-headerpad_max_install_names` — the flag the surface carried as a later item since M29 — is the decision the packing loop reads: the reserved header region grows past its natural size by every load-dylib command's room to grow its install name to the longest install name in the image (+1 NUL, 8-byte aligned — `pgr_core::header_pad::install_names_growth` is the public seam a build system can plan with), the space `install_name_tool` needs to rewrite any install name in place; the default (`false`) keeps every pre-M38 link byte-identical, a single-name surface plans zero growth, the floor composes with `-headerpad` (both are minimums — the bigger wins), the relocatable output refuses the knob, and the daemon wire v26 carries the decision |
| **M39** | The make-undefined mark: `-U <symbol>` — the flag the surface carried as a later item since M2 is the Pass-2 decision the definition install reads: the named symbol's definition (`N_SECT` or common) never installs *as it is linked* — the symtab row, the export-trie node and the `__common` slot drop, and the defining atom loses its liveness root (`-dead_strip` drops the body nothing references anymore) — and the stripped references follow the `-undefined` policy like any unresolved name (a dynamic lookup under `-undefined dynamic_lookup`, the vacuous refusal naming the misspelling under the default `error`; a stripped definition may also rebind against the dylib that exports the name); the empty table keeps every pre-M39 link byte-identical, the marks ride the resolve-reuse replay (a relink strips like the full walk, the equality gate holds), the relocatable output refuses the knob (`-r` carries its input symbol table verbatim — the driver refuses at parse time, `link_reloc` re-checks), the daemon wire v27 carries the names, and the `make_undefined` bench plus the `make_undefined_link` consumer example ride along |
| **M40** | The export-trie suppression: `-no_exported_symbols` — the last always-carried `__LINKEDIT` command the surface could not name (`LC_DYLD_EXPORTS_TRIE`, hard-wired since M2) drops on the named decision: no `__LINKEDIT` slot, no trie bytes, `sizeofcmds` 16 bytes narrower (`pgr_core::trie::build` never runs); the default (`true`) keeps every pre-M40 link byte-identical — the command rides even when its trie is empty, the always-carried family shape (M31 function starts, M32 UUID, M36 compact unwind); the knob is an executable decision — a main executable's trie is the `dlsym`/debugger surface (its dylib partners bind *into their own* tries, never the exe's), while a dylib's trie *is* the two-level contract its clients bind through and a bundle's the dlopen surface, so a dylib, a bundle and `-r` refuse the knob with the fix (the layout re-checks so no library caller can plan the shape either), and a link carrying re-export dylibs refuses (the REEXPORT nodes ride the trie); the classic `-no_fixup_chains` path plans the same suppression (the trie is the export surface, not a fixups artifact), the verifier's dylib contract gates the trie-less foreign shape (the export surface is missing — two-level clients cannot bind), and the daemon wire v28 carries the decision; the `exported_symbols` bench plus the `no_exported_symbols_link` consumer example ride along |
| **M41** | The dedup toggle: `-no_deduplicate` — the flag the surface carried as an accepted no-op since M7 is the Pass-3 decision the D4 piece builder reads: identical literals stop merging, every input `S_CSTRING_LITERALS` section rides the output verbatim (one whole-section piece per input, every symbol on its own instance — the pre-D4 shape); the default (`true`) keeps every pre-M41 link byte-identical (the M5/D4 merge and its remap unchanged); the knob is a Pass-3 decision — never a parse blindfold (the parse still splits cstring sections into atoms — liveness and the POI cache are flag-independent), dead-strip still drops dead literals under either decision (the knob widens the merge off, never the strip), and there is no output-kind conflict (the relocatable output never engaged the merge, so `-r` plans the same bytes under both decisions); riding the same seam, the symtab's output-section lookup resolves a definition whose input section merged away *entirely* (every atom a duplicate — no piece of its own remains) through its remapped address instead of the `n_sect 0` row the symtab contract refuses; the daemon wire v29 carries the decision; the `no_deduplicate` bench plus the `no_deduplicate_link` consumer example ride along |
| **M42** | The unused-dylib drop: `-dead_strip_dylibs` — ld64's flag, previously unknown on the surface, is the Pass-2 decision the resolve reads: every input dylib no referenced name binds against *as it is linked* leaves the header (the two-level bind names its provider — a dylib whose exports nothing references cannot serve a bind), and the kept list compacts the two-level ordinals onto it (symtab `n_desc` rows, the chained-fixups import table and the classic opcode binds all read the compacted table); the default (`false`) keeps every pre-M42 link byte-identical — every input dylib rides its `LC_LOAD_DYLIB` command regardless of use, ld64's shape; the re-export dylibs always ride (their `LC_REEXPORT_DYLIB` command is an identity obligation and their REEXPORT nodes join the export trie), and every dylib a dynamic-lookup reference could reach rides (the flat bind names no provider — the loader may reach any loaded image's exports); the relocatable output refuses the knob (the object carries no load commands), `-flat_namespace` refuses it (the flat bind names no provider), and `link_reloc` re-checks so no library caller can plan the shape either; the daemon wire v30 carries the decision; the `dead_strip_dylibs` bench plus the `dead_strip_dylibs_link` consumer example ride along |
| **M43** | The ObjC archive pull: `-ObjC` — the flag the surface carried as a later item since M6 is the Pass-0 liveness decision the archive pull reads: archive members implementing an Objective-C class or category ride the pull without a reference (the modern clang emitter names a class with `_OBJC_CLASS_$_`/`_OBJC_METACLASS_$_` and a category with `_OBJC_CATEGORY_$_` — the ObjC runtime registers the metadata by section address at load time, so no static reference exists to seed the S7 fixpoint; the decision rides the ranlib index every link already parses, a member whose index entry names the metadata family joins the pull in member file order, and its own undefineds continue the fixpoint); the default (`false`) keeps every pre-M43 link byte-identical — the pull stays reference-driven and the unreferenced member stays unparsed; a member defining none of the metadata names is not pulled by the knob (the rule is class-or-category, not `-all_load`); there is no output-kind conflict (the relocatable output consumes pulled members exactly like a segmented one, so `-r` rides the same pull); the daemon wire v31 carries the decision; the `objc` bench plus the `objc_link` consumer example ride along |
| **M44** | The dylib-identity default: `-final_output <path>` — ld64's flag, previously unknown on the surface, supplies the install name a dylib link derives when `-install_name` is absent (the `ld` man page: "Specifies the install name of a dylib if -install_name is not used" — the multi-arch driver names the universal path so every arch slice records it instead of its own `-o` path); an explicit `-install_name` wins (the man-page rule); the default (flag absent) keeps every pre-M44 link byte-identical — the derived install name stays the `-o` path; executables, bundles and the relocatable output refuse the knob with the fix (the identity rides `LC_MAIN`, a bundle dlopens without a region, the object carries no identity commands); the `final_output` bench plus the `final_output_link` consumer example ride along |
| **M45** | The upward-dylib load: `-upward_library <path>` / `-upward_framework <name>` — ld64's umbrella-relationship mark, previously unknown on the surface, is the fourth load-command kind: the opcode `pgr-format` has decoded since M0 (`LC_LOAD_UPWARD_DYLIB`, the weak/upward/lazy family in the load-command reader) but no producer could name rides `pgr_core::resolve::Dylib::upward`; the command participates in the two-level ordinal space exactly like a plain load (dyld's own rule — the verifier's walk and pair gate count it); the mark names the family of a plain load only (a lazy, weak or re-export load keeps its command — the obligations outrank the mark) and the driver's flags name one kind per path; the framework form resolves through the `-F` search after the lazy frameworks (the LC order — and with it the two-level ordinals — is plain, re-export, weak, lazy, then upward; an empty list leaves every pre-M45 link byte-identical); the daemon wire v32 carries the kind (one byte per dylib beside weak/re-export/lazy — the M14 lazy-byte convention); the `upward` bench plus the `upward_library_link` consumer example ride along |
| **M46** | The export-dynamic roots: `-export_dynamic` — ld64's liveness rule, *"Preserves all global symbols in main executables during dead stripping"* (the `ld` man page), is the decision the dead-strip root set reads (`pgr_core::layout::LinkConfig::export_dynamic` → `pgr_core::deadstrip`): every global definition in the image (an `N_SECT` def or a common) roots the mark phase, so a plugin-style main executable keeps its unreferenced entry points (the `dlsym` surface is a runtime contract the static fixpoint cannot see); the default (`false`) keeps every pre-M46 link byte-identical — the roots stay the entry, the `-u` marks, the aliases and the sections' own attributes; the knob is an executable decision — a dylib's and a bundle's strip already roots every definition (the export surface is the contract) and the relocatable output strips nothing (its symbol table is the input's, verbatim), so all three refuse the knob with the fix (the layout's re-check and `link_reloc` back the driver surface's refusal); the daemon wire v33 carries the decision; the `export_dynamic` bench plus the `export_dynamic_link` consumer example ride along |
| **M47** | The branch-island suppression: `-no_branch_islands` — ld64's knob (`fAllowBranchIslands`, on by default) is the Pass-3 decision the M6 veneer fixed point reads (`pgr_core::layout::LinkConfig::branch_islands` → `scan_branch_overflow`): under the named suppression the layout stops planning a veneer for an out-of-range `B`/`BL`, and a branch the ±128 MiB `imm26` window cannot reach refuses the link with the site named (ld64 reports the same condition when islands are disabled); the default (`true`) keeps every pre-M47 link byte-identical — the veneer set stays a pure function of the placed addresses, and an in-range corpus plans identical bytes under both decisions (there is no output-kind conflict: the relocatable output resolves no branches, so `-r` never reads the decision — the M41/M43 inert-for-relocatable shape); the daemon wire v34 carries the decision; the `branch_islands` bench plus the `branch_islands_link` consumer example ride along |
| **M48** | The dylib initializer: `-init <symbol>` — ld64's flag (*"Specifies the name of an initializer to be called by dyld when the image is loaded"*), previously unknown on the surface, is the identity decision the header assembly reads (`pgr_core::layout::LinkConfig::init_symbol`): the resolved initializer's image-space vaddr rides `LC_ROUTINES_64` (the 72-byte `routines_command_64` `pgr-format` classifies beside the 32-bit family — dyld's `hasInitializer` walk reads the command before the `__mod_init_func` sections), the name resolves like the entry seam's (an unresolved one refuses with the `Symbol` error), and the verifier's new routines contract gates the shapes the knob can break (a command off a dylib, the 32-bit opcode in a 64-bit image, an undersized command, a duplicate, an `init_address` naming no executable mapping); the default (`None`) keeps every pre-M48 link byte-identical — no command rides; the knob is a dylib decision (ld64: "-init can only be used with -dynamiclib") — an executable, a bundle and `-r` refuse it with the fix (the layout's re-check and `link_reloc` back the driver surface's refusal); the daemon wire v35 carries the name; the `dylib_init` bench plus the `dylib_init_link` consumer example ride along |
| **M49** | The GCC-era ObjC pull: the ledger M43's module doc drew closes at ld64's own archive matcher — the pull matches ranlib-index entries on the `.objc_c` prefix (the ObjC1/GCC-era C symbols: `.objc_class_name_<Class>` classes, `.objc_category_name_<Class>_<Category>` categories) beside `_OBJC_CLASS_$_` (ld64-609 `archive_file.cpp`), so `pgr_core::objc` widens — `classify_objc_metadata` names the family (`ObjcFamily`: the modern class/metaclass/category forms beside the ObjC1/GCC-era pair), the pull admits both families in member file order, and the exclusions stay named (the protocol list `_OBJC_PROTOCOL_$_` — a protocol is neither a class nor a category, and ld64's matcher reads neither; the pre-2.0 method-symbol form — a method rides its class or category's metadata symbols); the default stays reference-driven (an unreferenced GCC-era member stays unparsed, every pre-M49 link byte-identical); the `objc_pre2` bench plus the `objc_pre2_link` consumer example ride along |
| **M50** | The weak-import refusal: `-no_weak_imports` — ld64's flag is the Pass-2 decision the resolve's undefined walk reads (`pgr_core::layout::LinkConfig::no_weak_imports`): a weak reference (`N_WEAK_REF`) that no input, no dylib and no loader resolves — a bind dyld must look up at runtime — refuses the link with the symbol named, under `-undefined error` (where weak imports used to fall to the lookup silently) and `-undefined dynamic_lookup` alike; the default (`false`) keeps every pre-M50 link byte-identical — the weak reference rides dyld's runtime lookup exactly as it did; a link-time resolution (an input definition or a dylib export, weak-loaded or not) never refuses — the knob prices the runtime lookup, not the weakness; the relocatable output never reads the decision (its undefineds stay open); the daemon wire v36 carries the decision; the `no_weak_imports` bench plus the `no_weak_imports_link` consumer example ride along |
| **M51** | The stack-execution decision: `-allow_stack_execute` — ld64's flag (*"Marks executable so that all stacks in the task will be given stack execution privilege"*, the pthread stacks included) is the header decision the flag-word assembly reads (`pgr_core::layout::LinkConfig::allow_stack_execute`): the named decision ORs `MH_ALLOW_STACK_EXECUTION` into the executable's header flags — the kernel maps the main thread's and every pthread's stack executable; the default (`false`) keeps every pre-M51 link byte-identical — the bit rides no image; the knob is an executable decision (the kernel loads a dylib or a bundle itself, the relocatable output carries no loader semantics), so the non-executable outputs refuse it with the fix — the layout's re-check backs the driver surface's refusal (the M27 `-no_pie` shape, one flag word over); the verifier's structural contract names the broken shape (the bit on a non-executable image — a hostile third-party fixture, the knob cannot plan it); the daemon wire v37 carries the decision; the `stack_exec` bench plus the `allow_stack_execute_link` consumer example ride along |
| **M52** | The dead-strip init/term roots: `-no_dead_strip_inits_and_terms` — ld64's flag (*"The linker never dead strips initialization and termination routines"*) is the Pass-2 decision the dead-strip root set reads (`pgr_core::layout::LinkConfig::no_dead_strip_inits_and_terms` → `pgr_core::deadstrip`): the termination-pointer sections (`S_MOD_TERM_FUNC_POINTERS`) join the initialization-pointer sections' whole-section root treatment, so a term routine nothing references survives `-dead_strip`; the default (`false`) keeps every pre-M52 link byte-identical — the init half has been the house default since M5 (the flag never changes it), and an unreferenced term routine strips exactly as it did; there is no output-kind conflict — without `-dead_strip` the decision never fires and the relocatable output strips nothing (its symbol table is the input's, verbatim — the M41/M43/M47 inert-for-relocatable shape); the daemon wire v38 carries the decision; the `dead_strip_inits` bench plus the `no_dead_strip_inits_link` consumer example ride along |
| **M53** | The section renames: `-rename_section <fromSeg> <fromSect> <toSeg> <toSect>` — ld64's flag (*"Renames section orgSegment/orgSection to newSegment/newSection"*) is the Pass-3 decision the section classification reads (`pgr_core::rename`, `LinkConfig::renames`): the first entry naming an input section's `(segment, name)` pair renames it before grouping — the section groups with its new name and lands in the new segment, the protections following the segment the way ld64's reader-level rename does, and two sections renamed onto one pair coalesce (the grouping is by name); the default (the empty map) keeps every pre-M53 link byte-identical; the decision is validated, not defaulted — every name within the Mach-O 16-byte field width (ld64's own max-16-chars check), a source named once, and a source or target the house synthesizes (`__unwind_info`, `__chain_starts`, `__init_offsets`, the type-merged `__common`) refuses, the zero-fill type rule outranks the map, and a rename outside the M1 bucket trio refuses at layout with the segment named; there is no output-kind conflict — every linked output's sections ride the same buckets and the relocatable output never reads the table (its section table is the input's, verbatim — the M41/M43/M47 inert-for-relocatable shape); the daemon wire v39 carries the map (a count-prefixed table, four names per entry, re-validated on decode); the `rename_sections` bench plus the `rename_sections_link` consumer example ride along |
| **M54** | The link-pipeline observation seam: `pgr_core::observe` — the pass structure Passes 1–3 already name on the tracing span seam (`link_reloc`, `resolve_reuse_plan`/`install`) becomes a typed surface a library consumer subscribes to (`pgr_core::link_observed`, `link_from_objects_observed`, `link_reloc_observed`): each phase's completion arrives in link order (`Parse → ArchivePull → Intern → Resolve → Liveness → Fold → Layout`, the `-r` shape its own run) carrying its own detail — the parse's input count, the pulled members, the interned names, the resolve's reuse split, the fold count, the plan shape — plus its wall time, and the §7.3 ladder's silent-correct rungs (the resolve-reuse fallback) arrive as notes (`LinkNote::ResolveReuseFallback`, the refusal's own wording). The observer is read-only (an observed link plans the identical layout — the parity gate is the seam's own contract) and subscribes to nothing by default; `TracingObserver` bridges every event onto the house tracing convention (inert until a subscriber installs); the `observer` bench pins the shape (one event per phase — seven per segmented link — regardless of corpus size) and the `phase_observer` consumer example rides along |
| **M55** | The link-map JSON interchange: `pgr_core::map` — the build-system-facing report ld64's `-map` serves, already a pure function of the plan (the report and the bytes cannot disagree) — gains the machine face: `LinkMap::render_json` is the deterministic compact interchange (fixed key order, one line, the report-JSON escape rules) and `parse_link_map_json` the strict reader — a rigid schema (unknown or duplicate keys refuse, integer-only numbers, no trailing commas, byte-positioned `MapJsonError`s) with the data model's own structural gate (a section's `seg_name` must name the segment it rode in on). The reader restores the writer's data exactly (the `to_json`/`parse_report_json` round-trip convention, gated), so a build system ships the map to any JSON tooling without a custom parser; the `link_map_json` bench group rides the map bench and the `map_json` consumer example renders both faces (text and JSON) beside each other |
| **M56** | The symbol-reference provenance query (`-why_export <symbol>`): ld64's flag — previously unknown on the surface — is the reporting seam the M8-a reverse reference index always served but no consumer could reach (`pgr_core::provenance`): a query names the definition the Pass-2 resolution installed — the input file and section (direct object or pulled member, the rank and weak mark riding), the dylib export whose two-level bind serves it, or the loader's dynamic lookup — and every reference site the link saw, `(file, section, offset)` in the index's own ascending order, one record per site; `RefExplanation::render` is the diffable text face, `render_json` the deterministic interchange (the M55 escape rules), a vacuous query refuses with the misspelling named (the C-underscore hint the fix). The seam is read-only — the query consumes the link's own Pass-2 product (`LinkResult` carries the resolution since M56) and re-derives nothing, a queried link plans the identical layout — the resident and incremental lanes refuse the flag (the product never crosses the wire, the daemon wire stays v39); the `provenance` bench pins the index build and the query price, and the `why_export_link` consumer example renders both faces beside the vacuous refusal |
| **M57** | The load-provenance report (`-why_load`): ld64's flag (*"Print why each archive member or dylib was loaded"*) is the pull's own record made nameable (`pgr_core::provenance::LoadReport`, carried on the link result): every archive member the S7 fixpoint admitted names its decision — the reference whose round reached it (the seed named), the `-all_load`/`-force_load` eager family, the `-ObjC` metadata pull — beside the member's own symbol surface (its definitions and the undefineds its pull opened, the next fixpoint round's food), in pull order; a member nothing reached rides nowhere (the "why not" half of the question). Under `-dead_strip_dylibs` every input dylib carries its carriage (kept binds, dropped doesn't); without the knob the dylib rows ride empty — every dylib rides because the command line names it. The pull records from data it already had (one entry per pulled member), the report and the bytes cannot disagree, the record never changes the plan (the parity gate), and the same lane contract as `-why_export` holds (the wire stays v39); the `why_load` bench pins the pull-record and render prices, and the `why_load_link` consumer example walks the lazy pull, the eager pull and both faces |
| **M58** | The per-pass time report (`--time` / `--time-json`): the TDD's instrumentation spec (*"`--time` prints a per-pass table"* — parse, intern, resolve, layout, emit) and the roadmap §9.3 budgets ("enforced from `--time` JSON output") name the measurement surface the M54 observation seam serves the raw material for — `pgr_core::time_report` is the consumer that turns the seam's typed `PhaseEvent`s *as data* into the report: `TimeCollector` subscribes to the observed pipeline (`link_observed` / `link_reloc_observed`), `TimeReport::render` is the deterministic text table (phase token, the phase's own shape, the wall time, the permille share — integer math, no float rounding; µs below a millisecond, seconds beyond) and `render_json` the compact interchange line (fixed key order, the M55/M56/M57 escape rules, walls in whole microseconds). The emit band and the total are the caller's measurement; the ladder's silent-correct rungs ride the report as notes — a phase table that hid the resolve-reuse fallback would misread the resolve row's price. The report is a measurement, not a layout product: collecting never moves a byte (the parity gate re-gated through the collector), the `-r` shape reports its own five phases with no fused-emit row, and the fast-path lanes refuse where the observer does not watch; the `time_report` bench pins the collector's near-parity and the faces' O(rows) render price, and the `time_report` consumer example renders both faces beside the library face |
| **M59** | The resident lane's served time report (wire v40): the session observes its own pipeline — a time-asking request (`--time` beside `-resident`) subscribes the same `TimeCollector` to the warm run the §7.3 ladder serves, and the reply's IMAGE tail carries the collected report (`pgr_core::time_report::TimeReport` crossing the wire count-prefixed, phase token + detail kind + µs per row, the notes, the bands): the served table names the phases the session's run actually executed (no `Parse` row — the POIs are resident, the parse was paid when the blobs arrived), the relink's Pass-4 half is the in-memory patch so its emit band rides absent, and an unasked report never crosses (the tail is one byte); a client whose daemon falls back prints the one-shot link's own report — either way the run is observed, and the daemon still never touches the filesystem. The `wire_time` bench pins the tail's encode/decode price, and the `time_report` example plus the driver's resident cycle walk the served face |
| **M60** | The build-system dependency record (`-dependency_info <path>`): ld64's flag — previously unknown on the surface — is the sidecar artifact Xcode's incremental builds read, written beside the link in ld64's own binary format (`pgr_core::dep_info` is the seam, writer and strict reader): the linker-version row leads (`0x00`, the tool's identity string), every file the link read rides the `0x10` input family (objects, archives, resolved `-l`/`-framework` libraries, `-sectcreate` payloads, the symbol-list files, the bundle loader, the order file — ld64's object/dylib/archive/filelist/section/bundle-loader/misc names are one opcode in the field), every probed-but-missing search candidate rides `0x11` (the search's own story, ld64's `checkFileExists` shape), and the output — the `-map` beside it — rides `0x40`; the rows sort by `(opcode, path)` for build reproducibility (ld64's rdar://30750137 sort), two links of one command line write byte-identical records, and the reader restores the writer's data exactly (the round-trip convention, gated) or refuses the broken shapes with the byte position named. The record is the link's read set — never plan-derived — so it rides every lane that actually reads the input files (the resident lane writes it client-side from the request's own list; the daemon never touches the filesystem) and refuses the one that does not (`-incremental`: the relink patches the recorded plan and re-reads no input file — a record naming them would misreport the run); a recording link plans the identical image the plain link does (the parity gate — the sidecar never moves a byte); the `dep_info` bench pins the insert/render/decode prices and the `dependency_info_link` consumer example walks the record beside a real link |
| **M61** | The Chrome-trace timeline (`--trace <path>`): the roadmap §9.4 profiling toolbox ("`--trace` — Chrome-trace-format timeline per thread, so stragglers and idle gaps are visible") names the measurement surface the M54 observation seam serves the raw material for — `pgr_core::trace` is the consumer that turns the seam's typed `PhaseEvent`s *as data* into the timeline: `TraceCollector` subscribes to the observed pipeline (an `ObserverPair` serves the time and trace faces together when both flags ride — one event stream, both faces), `TraceReport::render` is the Trace Event Format's object form (`{"traceEvents":[…]}`, one line, deterministic: the metadata rows lead, the spans and instants ride `ts` order with the arrival order stable on the ties, integer-µs bounds, the M55/M56/M57/M58 escape rules, the detail riding the M58 interchange's own keys) and `parse_trace_json` the strict reader — the round-trip convention, gated, refusals byte-positioned (unknown `ph`, unknown phase or detail token, a float timestamp, a missing or duplicate key, a lane no `thread_name` declared). A span's start is the arrival clock minus the event's own wall (one emit-call behind the clock — saturating, never negative); the collector's lane registry keeps one lane per distinct arrival thread (today's pipeline renders one `pgr link` lane; a worker-span seam rides the same shape with more). The timeline is a measurement, not a layout product: collecting never moves a byte (the parity gate re-gated through the collector), the `-r` shape traces its own five-phase run, and the incremental lane refuses where the observer does not watch; the `trace` bench pins the near-parity and the O(rows) render/parse prices, and the `trace_timeline` consumer example writes the file beside a real link, round-trip gate included |
| **M62** | The resident lane's served timeline (wire v41): the session observes its own pipeline — a trace-asking request (`--trace` beside `-resident`) subscribes the same `TraceCollector` to the warm run the §7.3 ladder serves (paired with the time collector when both flags ride), and the reply's IMAGE tail carries the rendered document verbatim (`pgr_core::trace::TraceReport` crossing the wire as the interchange's own bytes — the strict reader is the document's face, the wire never re-shapes it): the served timeline names the phases the session's run actually executed (no `Parse` row — the POIs are resident, the parse was paid when the blobs arrived), the relink's Pass-4 half is the in-memory patch, and an unasked timeline never crosses (the tail is one byte); the client writes the served document to `--trace`'s path — either lane writes the same face. The `wire_trace` bench pins the tail's encode/decode price, and the flag's resident refusal flips to service |
| **M63** | The parse pool's worker-lane task spans: the M61 module doc named the future seam ("a worker-span seam rides the same shape with more lanes") and the §9.4 toolbox's per-thread goal names the reader — the parse pool's per-input parses (M4's LPT schedule) ride the M54 observation seam as `pgr_core::observe::TaskEvent`s (a new default-no-op `LinkObserver::on_task`, the same inert-until-subscriber convention; a cache hit included — the load is the work the consumer waited on), each carrying the thread that ran it and its own arrival clock (the two facts the phase event cannot: the lane registry's key, and the start the span's µs bounds reconstruct from — a drain-time re-stamp would end every worker's span at the drain); the pool threads report through a channel opened only when a subscriber rides (the parallel closures cannot borrow the caller's observer slot), the serial path reports on its own thread, and the `-r` shape rides the same wire-up. `TraceCollector` keeps the records as `TraceTask` spans on the workers' own lanes, `TraceReport::finish` presents them in the timeline's canonical `ts` order (the drain interleaves the workers — the render's document and the strict reader's restore must agree, the round-trip convention the example's own gate caught), the render writes the task rows beside the phase spans (`ph: "X"`, the phase token, `args: {"kind":"task","name":…}`) and the reader's args union grows the task member. The seam stays read-only (the parity gate re-gated); the `trace` bench's collector variant carries the one-record-per-input price and the 64-task report rides `render_8_rows_64_tasks`/`parse_8_rows_64_tasks`; the `trace_tasks` consumer example walks the worker lanes beside a twelve-object link |
| **M64** | The lane registry's names: the M63 worker lanes made the timeline multi-lane, and every `thread_name` row still carried the one hard-coded `pgr link` label — a viewer could not tell the pipeline's lane from the pool's workers. `TraceReport::lanes` becomes the named registry (`pgr_core::trace::TraceLane { id, name }`): the collector names the pipeline's thread (the first phase/note arrival) `pgr link` and the pool's workers `pgr parse pool N` (1-based, registration order among the workers — a serial-path task on the calling thread is the pipeline lane, not a worker; a feed with no phase or note events names every lane a worker), the render writes each lane's own label and the strict reader restores the labels exactly (the round-trip convention, gated on a multi-lane report; a foreign writer names its lanes its own way — the reader restores the document's labels, the registry's gates stay: one row per lane, ascending, non-empty). The `m64_named_lanes.rs` gate matrix pins the naming, the render/round-trip and the refusals; the `trace_tasks` example prints the lanes with their names |
| **M65** | The relink ladder rides the observation seam (`--time`/`--trace` beside `-incremental`): the §7.3 ladder's engine rungs — the integrity gate (`RelinkGate`, the record's page-hash sample hashed against the previous output), the patch plan (`RelinkPlan`, the total and dirty tiles), the clone-and-patch (`RelinkPatch`, the bytes and tiles actually written) and the `-incremental-verify` audit (`RelinkAudit`, the heal and the blocking-issue count) — join the M54 seam's phase vocabulary beside the pipeline's passes, and the ladder's fallback rungs join [`LinkNote`] (`RelinkFallback` — the full link the ladder handed over to names itself on the report and the timeline, the "silent-correct, not silent-blind" contract; one report per run: a successful ladder prints the rungs it ran, a handover prints the full link's phases with the note leading). The warm pipeline's Passes 1–3 ride the seam through the same `link_observed` entry the one-shot path uses, the timing flags stop refusing `-incremental` (the M58/M61 lane refusals flip to service — the fusion lane `-resident -incremental` still refuses until the session's ladder joins the seam), and wire v42 registers the rung vocabulary in the time-report tail (the decode side restores a captured tail carrying the rungs; the session reports them at the next rung). The observation is read-only (the parity gate: the observed relink patches the full link's bytes); the `trace` bench's relink groups pin the rung rows' render/parse price, and the `relink_timeline` consumer example walks the cycle — record, untouched relink, edit, patched relink — beside the round-trip gate |
| **M66** | The fusion lane's ladder joins the seam (wire v42 in service): the session's ladder reports its rungs beside the warm pipeline it already observed — the integrity gate over the transferred bytes, the plan, the in-memory patch and the audit — so `-resident -incremental --time/--trace` stops refusing and serves both faces (the report's rungs name the run the session actually executed: no `Parse` row, the POIs are resident; the emit band absent, the Pass-4 half is the in-memory patch), the client prints the served table and writes the served timeline verbatim — either lane, one observed run — and an untouched relink's served report ends at the plan (no patch row rides a relink that patched nothing). The vocabulary crossed no new wire: v42 registered the rung tokens at M65; the session reports them now. The `served_timing_session` example walks the ladder face beside the round-trip gate, and the driver's fusion cycle gates it end to end |

Every knob ships the same way: a validated decision in the library, verifier gates for the
shapes it can break, a parity bench, a runnable consumer example, daemon-wire carriage (protocol v42)

**Still on the roadmap:** the Apple Silicon hardware gates · LTO object execution ·
ObjC/Swift semantics beyond section pass-through (the protocol list and the
pre-2.0 method-symbol form stay out — ld64's archive matcher names neither; the
GCC-era class/category C symbols pull under `-ObjC` since M49).

<details><summary><b>Consumer examples (one per milestone surface)</b></summary>

Each ships in its crate's `examples/` — the milestone surfaces carry a matching bench,
the tail of the list is the support examples (the fixture emitters, the daemon session
walks, the library faces); run with `cargo run -p <crate> --example <name>`:

`relocatable_link` · `platform_matrix` · `platform_floor` · `encoding_query` ·
`arm64e_producer` · `fixup_chains_auth` · `arm64e_pair` · `chain_format_floor` ·
`glob_export_filter` · `lazy_library_link` · `pagezero_link` · `init_offsets_link` ·
`segprot_link` · `stack_size_link` · `icf_link` · `dead_strip_link` · `image_base_link` ·
`umbrella_link` · `sub_client_link` · `dyld_env_link` · `reexport_framework_link` ·
`alias_link` · `bundle_loader_link` · `dylinker_link` · `no_pie_link` ·
`sectalign_link` · `headerpad_link` · `data_in_code_link` · `function_starts_link` · `no_uuid_link` · `keep_private_externs_link` · `compact_unwind_link` ·
`compact_unwind_compressed_link` · `no_compact_unwind_link` · `no_deduplicate_link` · `dead_strip_dylibs_link` · `tlv_link` · `headerpad_max_install_names_link` · `make_undefined_link` · `no_exported_symbols_link` · `library_link` · `link_map` · `order_file_link` · `cache_link` · `objc_link` · `final_output_link` ·
`upward_library_link` · `export_dynamic_link` · `arm64e_walk` ·
`branch_islands_link` · `dylib_init_link` · `objc_pre2_link` ·
`no_weak_imports_link` · `allow_stack_execute_link` ·
`no_dead_strip_inits_link` · `rename_sections_link` · `selective_checks` ·
`baseline_gate` · `record_summary` ·
`phase_observer` · `map_json` · `cache_poi` · `why_export_link` · `why_load_link` ·
`time_report` · `phase_timing` · `incremental_resolve` · `record_patch_tiles` ·
`resident_output_tiles` · `fusion_audit_session` · `served_timing_session` · `verify_report` · `dependency_info_link` · `trace_timeline` ·
`trace_tasks` · `relink_timeline` ·
`walk_image` · `emit_corpus` · `emit_link_inputs`

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

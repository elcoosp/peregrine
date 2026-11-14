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
| `pgr-daemon` | `pgrd`: versioned wire protocol (v16), persistent sessions (POIs + bytes + emit buffer + resident output), the served incremental audit |
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
<<<<<<< HEAD
| Double link | byte-identical output |
| Fused tile emit vs reference emit | byte-identical (reference kept in-tree) |
| Cached vs uncached | byte-identical |
| Resident vs one-shot | byte-identical (daemon never writes; client does) |
| Incremental vs full emit | byte-identical (tests + per-link audit + `-incremental-verify`) |
||||||| 5b628c4
| Output kind | `-o`, `-static`, `-dylib`, `-bundle`, `-r` (relocatable, M10), `-e` |
| Platform targeting (M10) | `-platform_version macos\|ios\|tvos\|watchos\|visionos <min> <sdk>` (SDK ≥ deployment target; the per-platform chained-fixups floor picks the fixup encoding) |
| Inputs and search | object/`.a`/`.tbd`/`.dylib` paths, `-l`, `-L`, `-filelist path[,dir]`, `-framework`/`-F`, `-all_load`, `-force_load`, `-u` |
| Symbol binding | `-flat_namespace`, `-undefined error\|dynamic_lookup`, `-weak_library`, `-weak_framework`/`-lazy_framework` (M14), `-lazy_library` (M14), `-rpath` |
| Export filters | `-exported_symbols_list <file>` / `-unexported_symbols_list <file>` — one entry per line, `#` comments; each entry is an exact name or a `*` glob (`_OBJC_CLASS_$_*`; each star matches any, possibly empty, byte run — M14) |
| Dylib metadata | `-install_name`, `-current_version`, `-compatibility_version`, `-reexport_library` |
| Codegen and size | `-dead_strip`, `-icf=safe\|all\|none`, `-fixup_chains`/`-no_fixup_chains`, `-fixup_chains_format offset64\|arm64e` (M10 rung 4: the chain word family; the default stays the M2 encoding), `-adhoc`/`-no_adhoc`, `-segalign`, `-headerpad`, `-sectcreate` |
| Layout control and reporting (M11) | `-order_file <path>` (rank-based subset: `symbol` / `object.o:symbol`), `-map <path>` (the placed image's report) |
| Image base (M15) | `-pagezero_size <n>` (the `__PAGEZERO` vmsize an executable plans with — decimal or `0x`-hex, a non-zero multiple of the 16 KiB arm64 page; the default stays 4 GiB) |
| Initializers (M16) | `-init_offsets` / `-no_init_offsets` (the initializer form an executable plans with: the classic `__mod_init_func` pointer sections by default, or the transform that replaces them with a `__TEXT,__init_offsets` section of u32 offsets from the load address; below the chained-fixups floor and on `-r` the named form refuses) |
| Segment protections (M17) | `-segprot <seg> <max> <init>` (the `maxprot`/`initprot` pair one planned segment loads with — the protections are subsets of `rwx`, the segment one of `__TEXT`, `__DATA_CONST`, `__DATA`, `__LINKEDIT`; the initial mapping never exceeds its ceiling and never starts writable+executable, and on `-r` the knob refuses) |
| Stack reserve (M18) | `-stack_size <n>` (the `LC_MAIN` stacksize an executable plans with — decimal or `0x`-hex, a non-zero multiple of the 16 KiB arm64 page; on a non-executable output the knob refuses) |
| Image base (M19) | `-image_base <n>` (the `__TEXT` vmaddr a dylib or bundle plans with — decimal or `0x`-hex, a non-zero multiple of the 16 KiB arm64 page; the executable's base is `__PAGEZERO`'s job, so the knob refuses there (use `-pagezero_size`) and on `-r`) |
| Umbrella region and clients (M20/M21) | `-sub_umbrella <name>` / `-sub_library <name>` (the umbrella dylib's region members) and `-sub_client <name>` (the identity block's allowed clients) — each name validated (non-empty, NUL-free, once), emitted beside `LC_ID_DYLIB` in flag order; non-dylib outputs refuse the knobs with the fix |
| Dyld environment (M22) | `-dyld_env DYLD_<var>=<value>` (the `LC_DYLD_ENVIRONMENT` commands an executable exports — repeatable, flag order, each pair validated: a `DYLD_`-prefixed non-empty variable, one `=`, NUL-free, one decision per variable; dyld reads the command from the main executable only, so dylibs, bundles and `-r` refuse the knob with the fix) |
| Re-export frameworks (M23) | `-reexport_framework <name>` (the framework form of the M3 re-export: searched through `-F` dirs like `-framework`, loaded as `LC_REEXPORT_DYLIB`, its exports joining the trie as REEXPORT nodes; the LC order is plain, re-export, weak, then lazy) |
| Queries (M13) | `--print-record <path>` (the `.pgr-inc` sidecar's summary: identity, skeleton, span/digest/hash counts; `pgr-verify --baseline <prev.json>` + `--fail-on new\|any` gate a relink on *new* findings only) |
| Caching and jobs | `-cache <dir>`, `-no_cache`, `PGR_CACHE_DIR`, `-cache_max <bytes>`, `PGR_CACHE_MAX`, `PGR_JOBS` |
| Incremental mode (M9) | `-incremental`, `-no_incremental`, `-incremental-verify` (daemon-served under `-resident`), `PGR_INCREMENTAL_RECORD`, `PGR_INCREMENTAL_DEBUG` |
| Resident mode (M8) | `-resident`, `-resident_socket <path>`, `PGR_DAEMON_SOCK`, `PGR_RESIDENT_DEBUG`; the `pgrd` daemon: `--socket`, `--idle-secs`, `--shutdown` |
=======
| Output kind | `-o`, `-static`, `-dylib`, `-bundle`, `-r` (relocatable, M10), `-e` |
| Platform targeting (M10) | `-platform_version macos\|ios\|tvos\|watchos\|visionos <min> <sdk>` (SDK ≥ deployment target; the per-platform chained-fixups floor picks the fixup encoding) |
| Inputs and search | object/`.a`/`.tbd`/`.dylib` paths, `-l`, `-L`, `-filelist path[,dir]`, `-framework`/`-F`, `-all_load`, `-force_load`, `-u` |
| Symbol binding | `-flat_namespace`, `-undefined error\|dynamic_lookup`, `-weak_library`, `-weak_framework`/`-lazy_framework` (M14), `-lazy_library` (M14), `-rpath` |
| Export filters | `-exported_symbols_list <file>` / `-unexported_symbols_list <file>` — one entry per line, `#` comments; each entry is an exact name or a `*` glob (`_OBJC_CLASS_$_*`; each star matches any, possibly empty, byte run — M14) |
| Dylib metadata | `-install_name`, `-current_version`, `-compatibility_version`, `-reexport_library` |
| Codegen and size | `-dead_strip`, `-icf=safe\|all\|none`, `-fixup_chains`/`-no_fixup_chains`, `-fixup_chains_format offset64\|arm64e` (M10 rung 4: the chain word family; the default stays the M2 encoding), `-adhoc`/`-no_adhoc`, `-segalign`, `-headerpad`, `-sectcreate` |
| Layout control and reporting (M11) | `-order_file <path>` (rank-based subset: `symbol` / `object.o:symbol`), `-map <path>` (the placed image's report) |
| Image base (M15) | `-pagezero_size <n>` (the `__PAGEZERO` vmsize an executable plans with — decimal or `0x`-hex, a non-zero multiple of the 16 KiB arm64 page; the default stays 4 GiB) |
| Initializers (M16) | `-init_offsets` / `-no_init_offsets` (the initializer form an executable plans with: the classic `__mod_init_func` pointer sections by default, or the transform that replaces them with a `__TEXT,__init_offsets` section of u32 offsets from the load address; below the chained-fixups floor and on `-r` the named form refuses) |
| Segment protections (M17) | `-segprot <seg> <max> <init>` (the `maxprot`/`initprot` pair one planned segment loads with — the protections are subsets of `rwx`, the segment one of `__TEXT`, `__DATA_CONST`, `__DATA`, `__LINKEDIT`; the initial mapping never exceeds its ceiling and never starts writable+executable, and on `-r` the knob refuses) |
| Stack reserve (M18) | `-stack_size <n>` (the `LC_MAIN` stacksize an executable plans with — decimal or `0x`-hex, a non-zero multiple of the 16 KiB arm64 page; on a non-executable output the knob refuses) |
| Image base (M19) | `-image_base <n>` (the `__TEXT` vmaddr a dylib or bundle plans with — decimal or `0x`-hex, a non-zero multiple of the 16 KiB arm64 page; the executable's base is `__PAGEZERO`'s job, so the knob refuses there (use `-pagezero_size`) and on `-r`) |
| Umbrella region and clients (M20/M21) | `-sub_umbrella <name>` / `-sub_library <name>` (the umbrella dylib's region members) and `-sub_client <name>` (the identity block's allowed clients) — each name validated (non-empty, NUL-free, once), emitted beside `LC_ID_DYLIB` in flag order; non-dylib outputs refuse the knobs with the fix |
| Dyld environment (M22) | `-dyld_env DYLD_<var>=<value>` (the `LC_DYLD_ENVIRONMENT` commands an executable exports — repeatable, flag order, each pair validated: a `DYLD_`-prefixed non-empty variable, one `=`, NUL-free, one decision per variable; dyld reads the command from the main executable only, so dylibs, bundles and `-r` refuse the knob with the fix) |
| Re-export frameworks (M23) | `-reexport_framework <name>` (the framework form of the M3 re-export: searched through `-F` dirs like `-framework`, loaded as `LC_REEXPORT_DYLIB`, its exports joining the trie as REEXPORT nodes; the LC order is plain, re-export, weak, then lazy) |
| Symbol aliases (M24) | `-alias <alias_name> <definition_name>` (repeatable; the additional exported name an image ships beside the definition it names — one body, both names: a defined-external symtab row and an export-trie node at the definition's address, in flag order; the relocatable output refuses the knob with the fix) |
| Bundle loader (M25) | `-bundle_loader <path>` (the host executable a bundle binds its undefined references against — the binds ride the main-executable ordinal `0xFF`, dyld resolving them against the host process at load time; only a bundle binds against a host, everything else refuses the knob with the fix) |
| Queries (M13) | `--print-record <path>` (the `.pgr-inc` sidecar's summary: identity, skeleton, span/digest/hash counts; `pgr-verify --baseline <prev.json>` + `--fail-on new\|any` gate a relink on *new* findings only) |
| Caching and jobs | `-cache <dir>`, `-no_cache`, `PGR_CACHE_DIR`, `-cache_max <bytes>`, `PGR_CACHE_MAX`, `PGR_JOBS` |
| Incremental mode (M9) | `-incremental`, `-no_incremental`, `-incremental-verify` (daemon-served under `-resident`), `PGR_INCREMENTAL_RECORD`, `PGR_INCREMENTAL_DEBUG` |
| Resident mode (M8) | `-resident`, `-resident_socket <path>`, `PGR_DAEMON_SOCK`, `PGR_RESIDENT_DEBUG`; the `pgrd` daemon: `--socket`, `--idle-secs`, `--shutdown` |
>>>>>>> ship-temp-ai

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

<<<<<<< HEAD
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

Every knob ships the same way: a validated decision in the library, verifier gates for the
shapes it can break, a parity bench, a runnable consumer example, daemon-wire carriage
(protocol v16) — and a byte-identical default.

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
`alias_link` · `bundle_loader_link`

</details>
||||||| 5b628c4
> [!NOTE]
> Peregrine is a pre-1.0 project (v0.22.0) whose milestone stream follows the architecture doc: M6 (ICF, veneers, legacy fixups, Stage A caches) and M7 (versioned caches, build-system surface, the ≥ 98% compatibility suite, fuzzing at scale) shipped the in-tree scope; M8 shipped the resident + incremental foundations — the `pgrd` resident server with its persistent POI session, the reverse reference index, the insertion-stable import table, and slack-aware layout with the §7.3 fallback ladder; M9-v1 ships the in-place incremental relink engine — the versioned link record, the span-diff patch planner, the clone-and-patch output path with the merged-hash CodeDirectory rebuild, slack anchors, `-incremental`/`-incremental-verify`, and the byte-identity contract (tests + per-link audit); M9 tier 2b ships the per-symbol change-propagation planner — the record's section-digest table (content + symbol records) and the relink planner's propagation gate, which scopes every content change through the M8 reverse reference index and falls back when the span diff escapes the scope; M9 tier 2 ships the segment-relayout patch tier — the §7.3 ladder's middle rung executes (a slack overflow within the bound, or an outgrown `__LINKEDIT` reservation, patches the moved suffix through the record's v4 output-section content digests instead of falling back) — and the M9 GA hardening pass ships the ladder's shrink rung (an unsigned relink has no signature boundary to anchor the tail, so a symtab/string-pool shrink now patches through the relayout tier with the clone truncated instead of falling back) plus the seeded randomized edit gate (the engine-level and end-to-end `-incremental-verify` walks; `PGR_RANDOMIZED_STEPS` sizes the walk, 2000 sequences × 5 steps being the roadmap's 10⁴ GA profile for the decision rig). The target is arm64-apple-darwin only — `CPU_TYPE_ARM64`, little-endian, 16 KiB segment congruence — producing `MH_EXECUTE`, `MH_DYLIB` and `MH_BUNDLE` images; chained fixups serve macOS 12.0+ targets, and older deployment targets (or `-no_fixup_chains`) get classic `LC_DYLD_INFO_ONLY` rebase/bind streams. The host side is platform-independent: CI builds and runs the full test suite on Linux x86_64 and macOS aarch64. M11 rung 1 ships the `-order_file` rank seam — the parsed order file (`pgr_core::order`), the ordered link's atom-granular pieces and the §8.4 stable rank sort with the advisory for entries that rank nothing — and rung 2 ships the `-map` link-map report (`pgr_core::map`: segments, sections, symbol rows rendered from the plan itself). Performance claims stop at the dev-sandbox baselines in docs/BENCHMARKS.md — the hardware gates against `ld64.lld` on Apple Silicon (including M8's resident-relink gate and M9's §7.3 relink targets) are specified but not yet measured, the M8 warm-relink bench is recorded honestly as a wash on the Pass 2/3-bound sandbox corpus, and the M9 incremental bench records both the bytes-written win (~1% of an 8 MiB image per one-function edit, ~13% per slack-overflowing edit through the segment-relayout tier) and the ext4-clone wash. LTO object execution, compact-unwind synthesis, TLV and ObjC/Swift semantics beyond section pass-through stay on the roadmap; M9 tier 2c ships the incremental resolve’s decision core — the snapshot-backed reuse of Pass 2’s winners scoped by the propagation seeds and equality-gated against the full resolve — and the M9 GA record-side wiring ships the decision core's delivery path (the record's v5 resolution-snapshot section, the relink's Pass 2 planning through the recorded decisions, refusing to the full resolve when the reuse shape moves); the resident fusion wire rung puts both incremental halves on the daemon wire (protocol v3: the previous record in, the refreshed record and patch outcome out) and runs the §7.3 ladder inside the resident session — warm POIs pipeline the relink, the patched bytes cross the wire, the client writes the file, and a daemon-internal fallback renews the record so the cycle survives; the audited fusion rung (wire v4) completes the audit's move: the daemon serves `-incremental-verify` — byte-identity against the reference emit plus the strict verifier, divergence healed in memory, verdict on the wire, nothing written on a failing verdict; the §7.2 output-residency rung (wire v5) closes the last deferred fusion item — the session-resident output buffer: every served image becomes resident output state (content-hash keyed, ceiling-covered), the previous output stops re-crossing the wire, a patched relink's reply is the changed 16 KiB-tile stream (`pgr_emit::incremental::TilePatch`) instead of the image, an untouched relink ships nothing, and the client hash-verifies its replay before the atomic write (the daemon still never touches the filesystem). M10 rung 1 ships the `-r` relocatable output: Passes 1–2 stop short of the segment layout and `pgr_emit::build_object_image` assembles the `MH_OBJECT` the pipeline itself consumes as an input — sections merged at their declared alignments, relocation entries preserved and re-pointed at the output symbol table (`ADDEND`/`SUBTRACTOR` pairs re-emitted in decode order), the symtab grouped locals/winner-backed globals/open undefineds with its `LC_DYSYMTAB` subranges, and undefined externals left open by design; the two-step self-consumption link (`pgr -r a.o b.o -o out.o`, then `pgr out.o -o exe`) is a test gate, the verifier carries the object contract (no fixups/signature on `MH_OBJECT`, every relocation entry bounds-checked), and `pgr-emit`'s `object` bench plus the `relocatable_link` consumer example ride along. M10 rung 2 ships the platform plumbing — `-platform_version` accepts the five linked platforms (`macos`, `ios`, `tvos`, `watchos`, `visionos`; unknown names refuse with the surface in the hint, and an SDK older than the deployment target refuses at parse time), the layout's chained-fixups gate is per-platform (`chained_fixups_min_minos`: macOS 12.0 / iOS 15.0 / tvOS 15.0 / watchOS 8.0 / visionOS 1.0 — below the floor the M6 classic opcode streams encode the same fixups), the verifier's build-version gate checks the *declared* platform (unknown constants are errors, `sdk < minos` is an error, the five platforms verify strict-clean), `pgr_format::PLATFORM_VISIONOS` crosschecks against the vendored headers' `PLATFORM_XROS`, and the `platform_matrix` consumer example plus the `platform` bench ride along. M10 rung 3 makes the encoding decision a consumer seam: slice 1 named it in the library (`pgr_core::platform::FixupEncoding::for_target` reads the same per-platform floor table the layout encodes — one table, two readers — with a tracing event on the decision and the `platform_floor` example rendering the below-floor advisory as miette help text); slice 2 crosses the surface: `pgr --print-fixup-encoding <platform> <min> <sdk>` (and `pgr_driver::fixup_encoding_report`) answers the build system's before-the-link question with the `-platform_version` refusals and a miette advisory on below-floor rows, the verifier's build-version gate reads the same canonical floor table (`pgr_format::consts::chained_fixups_floor` — one table, three readers) and refuses chained fixups below the declared platform's floor with the new `fixups_floor` code, the fixture builder takes its build version as a knob (`ImageBuilder::set_build_version` — no more post-build repatching), and the `encoding_query` consumer example plus the verifier's first bench (`verify_platform_floor`) ride along. M10 rung 4, slice 1 opens the arm64e read side: `pgr_format::fixups::ChainWordArm64e` names the `DYLD_CHAINED_PTR_ARM64E` word family (the two-bit bind/auth discriminator rides bits 62/63, `next` counts 8-byte strides), `pgr_fixtures::PointerFormatKind::Arm64e` builds the shapes (unauth rebases carry VM-address targets, auth words carry the diversity/key PAC triple), and the verifier's dyld chain-walk, `__chain_starts` mirror and slot-count gates accept the format — the Pass-3 producer encoding and the driver surface are the rung's next slice. M10 rung 4, slice 2 ships that producer: `pgr_core::fixups::FixupPointerFormat` names the word family and `plan_fixups_with_format` encodes it (the default `Offset64` stays byte-identical to the M2 planner — the §7.2 lock holds; `Arm64e` swaps the rebase target to a VM address, strides `next` in 8-byte units, and declares pointer format 1 in the payload records and the `__chain_starts` mirror, with the import table and its M9 anchor untouched), the driver surface names it (`-fixup_chains_format offset64|arm64e`, refusing the combinations that cannot carry the family — the classic opcode path, the resident session, `-r` — with the fix in the message), the daemon wire mirrors the family faithfully (v6 tail byte), and the `arm64e_producer` consumer example plus the planner bench ride along. M10 rung 4, slice 3 closes the family's named target — the **authenticated** words: the same Pass-3 planner takes a `pgr_core::fixups::FixupAuth` policy (`plan_fixups_with_auth`), auth rebases carry the 32-bit runtime offset dyld adds to the preferred load address plus the diversity/addrDiv/key PAC triple, auth binds carry the ordinal and move their whole addend into the import entry (the auth bind word has no addend field — the M2 split's one named exception, and the M9 anchor appends the signed key without renumbering), the 64_OFFSET family refuses a policy outright (no auth discriminator to set), an empty policy plans byte-identically to the slice-2 planner, the verifier's dyld walk has read these words since slice 1, and the `fixup_chains_auth` consumer example renders the refusal as miette help text while the `arm64e_auth` bench variant rides the same corpus. M10 rung 4, slice 4 closes the rung's named deferral — the M3 pair gate goes family-blind: the two-level bind replay decodes each segment through its own `pointer_format` (`ChainWord64` under the 64 families, `ChainWordArm64e` under arm64e) and strides by the family's `chain_stride` (4 or 8 bytes), so an arm64e executable binding a name its dylib does not export is refused where slice 3 left it passing silently; the `arm64e_pair` consumer example renders the refusal as miette help text and the pair-replay bench variant rides the same corpus. M10 rung 4, slice 5 makes the family honest below the deployment floor: an explicitly named `-fixup_chains_format` (either spelling) refuses when the `-platform_version` target sits below the platform's chained-fixups floor — the layout would plan the classic opcode streams and the named family would never reach the image (a refusal, never a silently dropped knob) — while the flag-less default keeps the documented silent fallback, the refusal renders its fix as miette help text, the `chain_format_floor` consumer example walks the whole story, and the slice's sweep heals the rung's fixture debt (the auth slots register their imports and ride the indirect symbol table) plus the docs drift the audit found. M12 makes the verifier's checks a selectable surface: `pgr_verify::CheckSet` parses a comma-separated family list (`--checks segments,fixups`), the `pgr_verify::ImageCheck` registry names each family with the issue codes it may report, `pgr_verify::verify_with_checks` drives a subset through the same parse pre-pass and stats contract (the full set is exactly `verify`), and `pgr-verify` gains `--checks`/`--list-checks` — the shape a build system uses to fail fast on one contract without paying the whole pass on every relink. M13 makes the artifacts that gate a build system readable *surfaces*: rung 1 is the report's interchange shape — one JSON writer and one reader in the library (`pgr_verify::to_json`/`parse_report_json`, the CLI's `--json` output now rendered by the same writer), the typed `ReportJsonError` reader refusals, and the baseline gate (`pgr-verify --baseline <prev.json>`, `--fail-on new|any`; `pgr_verify::BaselineDelta::between` classifies introduced/resolved/surviving as a multiset under an `IssueIdentity` policy — `OffsetIdentity` position-aware, `CodeIdentity` shift-surviving), so a relink loop gates on "no *new* findings" instead of "no findings, ever"; rung 2 is the link record's inspector — `pgr_emit::incremental::read_record`/`read_summary` (typed `RecordReadError` frame refusals: size, magic, length, checksum, version, body — the fix in each message) and `pgr --print-record <output>.pgr-inc` rendering the deterministic summary text, with `pgr-emit`'s first consumer example riding along. M14 widens the export filters into the ld64 glob form — `-exported_symbols_list`/`-unexported_symbols_list` entries are named `*` patterns now (`pgr_core::export_filter`: `SymbolPattern` exact-or-glob behind the `SymbolMatcher` seam, the M3 exact form being the all-exact shape of the same contract), the daemon wire re-encodes the lists faithfully (protocol v7: kind byte + source bytes, a glob never flattens across the wire), a malformed line refuses with the fix, a pattern that matched nothing warns like the order-file advisory, and the `glob_export_filter` consumer example plus the `filter` bench ride along. M14 rung 2 releases the weak/lazy dylib family the compat table kept rejecting: `-weak_framework`/`-lazy_framework` search `-F` dirs like `-framework` and `-lazy_library` is a path input — weak loads ride `LC_LOAD_WEAK_DYLIB` with weak binds, lazy loads ride `LC_LAZY_LOAD_DYLIB`, and the lazy command participates in the two-level ordinal space exactly like a plain load (the verifier's dylib walk and pair gate count it; the `dylibs` bench pins the kind as a header-byte cost and the `lazy_library_link` consumer example rides along). M15 releases the image base the layout kept as a constant: `-pagezero_size <n>` names the `__PAGEZERO` vmsize an executable plans with (`pgr_core::pagezero::PageZero` — the validated decision the constant-delta contract, the fixup planner, the export trie and the verifier all read; non-zero, a multiple of the 16 KiB arm64 page, the 4 GiB default staying byte-identical), the verifier's base contract verifies the invariant instead of the constant (a hand-broken pagezero is named, a custom-base image verifies strict), the daemon wire carries the configured base (protocol v8) so a resident relink lays out the base the client named, non-executable outputs refuse the knob, and the `pagezero` bench pins parity across base decisions while the `pagezero_link` consumer example walks both images and renders the misaligned refusal as miette help text. M16 releases the initializer form the pass-through kept fixed: `-init_offsets`/`-no_init_offsets` names the form (`pgr_core::init_offsets` — the validated decision the layout's bucketing, both fixup planners and the daemon wire v9 read; the default keeps the M1-locked `__mod_init_func` pointer sections, every pre-M16 link byte-identical; the transform replaces them with a `__TEXT,__init_offsets` section of u32 offsets from the load address — the shape dyld has walked since the chained-fixups era, no rebases needed — and refuses below the platform's chained-fixups floor, on `-r`, and at a bind-targeted initializer, the fix in each message), the `init_offsets` bench pins the per-decision parity across both fixup paths, and the `init_offsets_link` consumer example walks both images and renders the below-floor refusal as miette help text. M17 releases the segment protections the layout kept as a hard-coded table: `-segprot <seg> <max> <init>` names the `maxprot`/`initprot` pair one planned segment loads with (`pgr_core::segprot` — the validated decision the segment packing and the daemon wire v10 read; the protections are subsets of `rwx`, the segment one of `__TEXT`, `__DATA_CONST`, `__DATA`, `__LINKEDIT`, one decision per segment, the initial mapping never exceeding its ceiling and never starting writable+executable — the arm64 macOS W^X contract — and every unnamed segment keeping the house pair, every pre-M17 link byte-identical), the verifier's protection contract checks the invariants the fixture knob can break (an init beyond its ceiling, a W+X mapping, a protected `__PAGEZERO`), a `-segprot` on `-r` refuses (the relocatable output carries no segments), and the `segprot` bench pins parity across the protection decisions while the `segprot_link` consumer example walks both images and renders the W^X refusal as miette help text. M18 releases the stack reserve the header assembly kept at zero: `-stack_size <n>` names the `LC_MAIN.stacksize` an executable plans with (`pgr_core::stack_size` — the validated decision the header emit and the daemon wire v11 read; non-zero, a multiple of the 16 KiB arm64 page, the zero default — dyld's own main-thread fallback — keeping every pre-M18 link byte-identical), the command is 24 bytes either way so nothing else in the plan moves, the verifier's entry gate checks the page-multiple invariant (a misaligned reserve is named), non-executable outputs refuse the knob (no `LC_MAIN`, no field to land on), and the `stack_size` bench pins parity across the reserve decisions while the `stack_size_link` consumer example walks both images and renders the misaligned refusal as miette help text — and the rung's example sweep fixed the fixups gate the dead-strip story exposed (the gate counted dead atoms' pointer slots, promising a chained-fixups payload the placement could not build: a header-only `__chain_starts` mirror beside no `LC_DYLD_CHAINED_FIXUPS`, the verifier's own contract refusing exactly that shape; the gate counts live slots now), the `icf_link` and `dead_strip_link` consumer examples ride along, and the docs drift the audit found healed (the version badge and the TDD trailer's M16 row). **M19** releases the dylib/bundle preferred load address the M3 contract kept at zero: `-image_base <n>` names the `__TEXT` vmaddr a non-executable image plans with (`pgr_core::image_base` — the validated decision the constant-delta resolver (`pgr_core::pagezero::PageZero::base_for` — one kind table, one reader since M15), both fixup planners (the `64_OFFSET` rebase words and the arm64e targets are offsets from the base), the export trie and the incremental record all read; non-zero, a multiple of the 16 KiB arm64 page, the zero default — the M3 `__TEXT.vmaddr == fileoff` contract — keeping every pre-M19 link byte-identical), the verifier's base contract verifies the invariant instead of the constant (a hand-broken base is named, a named-base dylib verifies strict), an `-image_base` on an executable refuses (the base is `__PAGEZERO`'s job — M15's `-pagezero_size` — one base knob per output kind) and on `-r` too (the relocatable output carries no segments), the daemon wire v12 carries the named base so a resident relink lays out the base the client named, and the `image_base` bench pins parity across the base decisions while the `image_base_link` consumer example walks both images and renders the executable-conflict refusal as miette help text. M20 releases the dylib umbrella region (`pgr_core::umbrella` — `-sub_umbrella`/`-sub_library`: the validated member table an umbrella dylib emits as the `LC_SUB_UMBRELLA`/`LC_SUB_LIBRARY` identity-block commands in flag order, non-dylib outputs refusing the knob with the fix, the daemon wire v13 carrying the members, the verifier gating the broken shapes, the `umbrella` bench pinning parity and the `umbrella_link` consumer example walking the story). M21 releases the dylib client list (`pgr_core::sub_client` — `-sub_client <name>`: the validated client table an identity-block dylib emits as the `LC_SUB_CLIENT` commands right after the M20 region in flag order, non-dylib outputs refusing the knob with the fix, the daemon wire v14 carrying the names, the verifier's identity-block contract gating the broken shapes in the client namespace, the `sub_client` bench pinning parity and the `sub_client_link` consumer example walking the story). M22 releases the dyld environment (`pgr_core::dyld_env` — `-dyld_env DYLD_<var>=<value>`: the validated pair table an executable emits as the `LC_DYLD_ENVIRONMENT` commands right after `LC_MAIN`, the loader-configuration adjacency, in flag order; dyld reads the command from the main executable only, so dylibs, bundles and `-r` refuse the knob with the fix, the daemon wire v15 carrying the pairs, the verifier's environment contract gating the broken shapes, the `dyld_env` bench pinning parity and the `dyld_env_link` consumer example walking the story). M23 releases the framework form of the re-export (`-reexport_framework <name>`: the M3 `-reexport_library` shape resolved through the M5 `-F` framework search — the dylib loads as `LC_REEXPORT_DYLIB`, its exports join the image's export trie as REEXPORT nodes, the LC order is plain, re-export, weak, then lazy, and the `reexport_framework_link` consumer example walks the story).
=======
> [!NOTE]
> Peregrine is a pre-1.0 project (v0.22.0) whose milestone stream follows the architecture doc: M6 (ICF, veneers, legacy fixups, Stage A caches) and M7 (versioned caches, build-system surface, the ≥ 98% compatibility suite, fuzzing at scale) shipped the in-tree scope; M8 shipped the resident + incremental foundations — the `pgrd` resident server with its persistent POI session, the reverse reference index, the insertion-stable import table, and slack-aware layout with the §7.3 fallback ladder; M9-v1 ships the in-place incremental relink engine — the versioned link record, the span-diff patch planner, the clone-and-patch output path with the merged-hash CodeDirectory rebuild, slack anchors, `-incremental`/`-incremental-verify`, and the byte-identity contract (tests + per-link audit); M9 tier 2b ships the per-symbol change-propagation planner — the record's section-digest table (content + symbol records) and the relink planner's propagation gate, which scopes every content change through the M8 reverse reference index and falls back when the span diff escapes the scope; M9 tier 2 ships the segment-relayout patch tier — the §7.3 ladder's middle rung executes (a slack overflow within the bound, or an outgrown `__LINKEDIT` reservation, patches the moved suffix through the record's v4 output-section content digests instead of falling back) — and the M9 GA hardening pass ships the ladder's shrink rung (an unsigned relink has no signature boundary to anchor the tail, so a symtab/string-pool shrink now patches through the relayout tier with the clone truncated instead of falling back) plus the seeded randomized edit gate (the engine-level and end-to-end `-incremental-verify` walks; `PGR_RANDOMIZED_STEPS` sizes the walk, 2000 sequences × 5 steps being the roadmap's 10⁴ GA profile for the decision rig). The target is arm64-apple-darwin only — `CPU_TYPE_ARM64`, little-endian, 16 KiB segment congruence — producing `MH_EXECUTE`, `MH_DYLIB` and `MH_BUNDLE` images; chained fixups serve macOS 12.0+ targets, and older deployment targets (or `-no_fixup_chains`) get classic `LC_DYLD_INFO_ONLY` rebase/bind streams. The host side is platform-independent: CI builds and runs the full test suite on Linux x86_64 and macOS aarch64. M11 rung 1 ships the `-order_file` rank seam — the parsed order file (`pgr_core::order`), the ordered link's atom-granular pieces and the §8.4 stable rank sort with the advisory for entries that rank nothing — and rung 2 ships the `-map` link-map report (`pgr_core::map`: segments, sections, symbol rows rendered from the plan itself). Performance claims stop at the dev-sandbox baselines in docs/BENCHMARKS.md — the hardware gates against `ld64.lld` on Apple Silicon (including M8's resident-relink gate and M9's §7.3 relink targets) are specified but not yet measured, the M8 warm-relink bench is recorded honestly as a wash on the Pass 2/3-bound sandbox corpus, and the M9 incremental bench records both the bytes-written win (~1% of an 8 MiB image per one-function edit, ~13% per slack-overflowing edit through the segment-relayout tier) and the ext4-clone wash. LTO object execution, compact-unwind synthesis, TLV and ObjC/Swift semantics beyond section pass-through stay on the roadmap; M9 tier 2c ships the incremental resolve’s decision core — the snapshot-backed reuse of Pass 2’s winners scoped by the propagation seeds and equality-gated against the full resolve — and the M9 GA record-side wiring ships the decision core's delivery path (the record's v5 resolution-snapshot section, the relink's Pass 2 planning through the recorded decisions, refusing to the full resolve when the reuse shape moves); the resident fusion wire rung puts both incremental halves on the daemon wire (protocol v3: the previous record in, the refreshed record and patch outcome out) and runs the §7.3 ladder inside the resident session — warm POIs pipeline the relink, the patched bytes cross the wire, the client writes the file, and a daemon-internal fallback renews the record so the cycle survives; the audited fusion rung (wire v4) completes the audit's move: the daemon serves `-incremental-verify` — byte-identity against the reference emit plus the strict verifier, divergence healed in memory, verdict on the wire, nothing written on a failing verdict; the §7.2 output-residency rung (wire v5) closes the last deferred fusion item — the session-resident output buffer: every served image becomes resident output state (content-hash keyed, ceiling-covered), the previous output stops re-crossing the wire, a patched relink's reply is the changed 16 KiB-tile stream (`pgr_emit::incremental::TilePatch`) instead of the image, an untouched relink ships nothing, and the client hash-verifies its replay before the atomic write (the daemon still never touches the filesystem). M10 rung 1 ships the `-r` relocatable output: Passes 1–2 stop short of the segment layout and `pgr_emit::build_object_image` assembles the `MH_OBJECT` the pipeline itself consumes as an input — sections merged at their declared alignments, relocation entries preserved and re-pointed at the output symbol table (`ADDEND`/`SUBTRACTOR` pairs re-emitted in decode order), the symtab grouped locals/winner-backed globals/open undefineds with its `LC_DYSYMTAB` subranges, and undefined externals left open by design; the two-step self-consumption link (`pgr -r a.o b.o -o out.o`, then `pgr out.o -o exe`) is a test gate, the verifier carries the object contract (no fixups/signature on `MH_OBJECT`, every relocation entry bounds-checked), and `pgr-emit`'s `object` bench plus the `relocatable_link` consumer example ride along. M10 rung 2 ships the platform plumbing — `-platform_version` accepts the five linked platforms (`macos`, `ios`, `tvos`, `watchos`, `visionos`; unknown names refuse with the surface in the hint, and an SDK older than the deployment target refuses at parse time), the layout's chained-fixups gate is per-platform (`chained_fixups_min_minos`: macOS 12.0 / iOS 15.0 / tvOS 15.0 / watchOS 8.0 / visionOS 1.0 — below the floor the M6 classic opcode streams encode the same fixups), the verifier's build-version gate checks the *declared* platform (unknown constants are errors, `sdk < minos` is an error, the five platforms verify strict-clean), `pgr_format::PLATFORM_VISIONOS` crosschecks against the vendored headers' `PLATFORM_XROS`, and the `platform_matrix` consumer example plus the `platform` bench ride along. M10 rung 3 makes the encoding decision a consumer seam: slice 1 named it in the library (`pgr_core::platform::FixupEncoding::for_target` reads the same per-platform floor table the layout encodes — one table, two readers — with a tracing event on the decision and the `platform_floor` example rendering the below-floor advisory as miette help text); slice 2 crosses the surface: `pgr --print-fixup-encoding <platform> <min> <sdk>` (and `pgr_driver::fixup_encoding_report`) answers the build system's before-the-link question with the `-platform_version` refusals and a miette advisory on below-floor rows, the verifier's build-version gate reads the same canonical floor table (`pgr_format::consts::chained_fixups_floor` — one table, three readers) and refuses chained fixups below the declared platform's floor with the new `fixups_floor` code, the fixture builder takes its build version as a knob (`ImageBuilder::set_build_version` — no more post-build repatching), and the `encoding_query` consumer example plus the verifier's first bench (`verify_platform_floor`) ride along. M10 rung 4, slice 1 opens the arm64e read side: `pgr_format::fixups::ChainWordArm64e` names the `DYLD_CHAINED_PTR_ARM64E` word family (the two-bit bind/auth discriminator rides bits 62/63, `next` counts 8-byte strides), `pgr_fixtures::PointerFormatKind::Arm64e` builds the shapes (unauth rebases carry VM-address targets, auth words carry the diversity/key PAC triple), and the verifier's dyld chain-walk, `__chain_starts` mirror and slot-count gates accept the format — the Pass-3 producer encoding and the driver surface are the rung's next slice. M10 rung 4, slice 2 ships that producer: `pgr_core::fixups::FixupPointerFormat` names the word family and `plan_fixups_with_format` encodes it (the default `Offset64` stays byte-identical to the M2 planner — the §7.2 lock holds; `Arm64e` swaps the rebase target to a VM address, strides `next` in 8-byte units, and declares pointer format 1 in the payload records and the `__chain_starts` mirror, with the import table and its M9 anchor untouched), the driver surface names it (`-fixup_chains_format offset64|arm64e`, refusing the combinations that cannot carry the family — the classic opcode path, the resident session, `-r` — with the fix in the message), the daemon wire mirrors the family faithfully (v6 tail byte), and the `arm64e_producer` consumer example plus the planner bench ride along. M10 rung 4, slice 3 closes the family's named target — the **authenticated** words: the same Pass-3 planner takes a `pgr_core::fixups::FixupAuth` policy (`plan_fixups_with_auth`), auth rebases carry the 32-bit runtime offset dyld adds to the preferred load address plus the diversity/addrDiv/key PAC triple, auth binds carry the ordinal and move their whole addend into the import entry (the auth bind word has no addend field — the M2 split's one named exception, and the M9 anchor appends the signed key without renumbering), the 64_OFFSET family refuses a policy outright (no auth discriminator to set), an empty policy plans byte-identically to the slice-2 planner, the verifier's dyld walk has read these words since slice 1, and the `fixup_chains_auth` consumer example renders the refusal as miette help text while the `arm64e_auth` bench variant rides the same corpus. M10 rung 4, slice 4 closes the rung's named deferral — the M3 pair gate goes family-blind: the two-level bind replay decodes each segment through its own `pointer_format` (`ChainWord64` under the 64 families, `ChainWordArm64e` under arm64e) and strides by the family's `chain_stride` (4 or 8 bytes), so an arm64e executable binding a name its dylib does not export is refused where slice 3 left it passing silently; the `arm64e_pair` consumer example renders the refusal as miette help text and the pair-replay bench variant rides the same corpus. M10 rung 4, slice 5 makes the family honest below the deployment floor: an explicitly named `-fixup_chains_format` (either spelling) refuses when the `-platform_version` target sits below the platform's chained-fixups floor — the layout would plan the classic opcode streams and the named family would never reach the image (a refusal, never a silently dropped knob) — while the flag-less default keeps the documented silent fallback, the refusal renders its fix as miette help text, the `chain_format_floor` consumer example walks the whole story, and the slice's sweep heals the rung's fixture debt (the auth slots register their imports and ride the indirect symbol table) plus the docs drift the audit found. M12 makes the verifier's checks a selectable surface: `pgr_verify::CheckSet` parses a comma-separated family list (`--checks segments,fixups`), the `pgr_verify::ImageCheck` registry names each family with the issue codes it may report, `pgr_verify::verify_with_checks` drives a subset through the same parse pre-pass and stats contract (the full set is exactly `verify`), and `pgr-verify` gains `--checks`/`--list-checks` — the shape a build system uses to fail fast on one contract without paying the whole pass on every relink. M13 makes the artifacts that gate a build system readable *surfaces*: rung 1 is the report's interchange shape — one JSON writer and one reader in the library (`pgr_verify::to_json`/`parse_report_json`, the CLI's `--json` output now rendered by the same writer), the typed `ReportJsonError` reader refusals, and the baseline gate (`pgr-verify --baseline <prev.json>`, `--fail-on new|any`; `pgr_verify::BaselineDelta::between` classifies introduced/resolved/surviving as a multiset under an `IssueIdentity` policy — `OffsetIdentity` position-aware, `CodeIdentity` shift-surviving), so a relink loop gates on "no *new* findings" instead of "no findings, ever"; rung 2 is the link record's inspector — `pgr_emit::incremental::read_record`/`read_summary` (typed `RecordReadError` frame refusals: size, magic, length, checksum, version, body — the fix in each message) and `pgr --print-record <output>.pgr-inc` rendering the deterministic summary text, with `pgr-emit`'s first consumer example riding along. M14 widens the export filters into the ld64 glob form — `-exported_symbols_list`/`-unexported_symbols_list` entries are named `*` patterns now (`pgr_core::export_filter`: `SymbolPattern` exact-or-glob behind the `SymbolMatcher` seam, the M3 exact form being the all-exact shape of the same contract), the daemon wire re-encodes the lists faithfully (protocol v7: kind byte + source bytes, a glob never flattens across the wire), a malformed line refuses with the fix, a pattern that matched nothing warns like the order-file advisory, and the `glob_export_filter` consumer example plus the `filter` bench ride along. M14 rung 2 releases the weak/lazy dylib family the compat table kept rejecting: `-weak_framework`/`-lazy_framework` search `-F` dirs like `-framework` and `-lazy_library` is a path input — weak loads ride `LC_LOAD_WEAK_DYLIB` with weak binds, lazy loads ride `LC_LAZY_LOAD_DYLIB`, and the lazy command participates in the two-level ordinal space exactly like a plain load (the verifier's dylib walk and pair gate count it; the `dylibs` bench pins the kind as a header-byte cost and the `lazy_library_link` consumer example rides along). M15 releases the image base the layout kept as a constant: `-pagezero_size <n>` names the `__PAGEZERO` vmsize an executable plans with (`pgr_core::pagezero::PageZero` — the validated decision the constant-delta contract, the fixup planner, the export trie and the verifier all read; non-zero, a multiple of the 16 KiB arm64 page, the 4 GiB default staying byte-identical), the verifier's base contract verifies the invariant instead of the constant (a hand-broken pagezero is named, a custom-base image verifies strict), the daemon wire carries the configured base (protocol v8) so a resident relink lays out the base the client named, non-executable outputs refuse the knob, and the `pagezero` bench pins parity across base decisions while the `pagezero_link` consumer example walks both images and renders the misaligned refusal as miette help text. M16 releases the initializer form the pass-through kept fixed: `-init_offsets`/`-no_init_offsets` names the form (`pgr_core::init_offsets` — the validated decision the layout's bucketing, both fixup planners and the daemon wire v9 read; the default keeps the M1-locked `__mod_init_func` pointer sections, every pre-M16 link byte-identical; the transform replaces them with a `__TEXT,__init_offsets` section of u32 offsets from the load address — the shape dyld has walked since the chained-fixups era, no rebases needed — and refuses below the platform's chained-fixups floor, on `-r`, and at a bind-targeted initializer, the fix in each message), the `init_offsets` bench pins the per-decision parity across both fixup paths, and the `init_offsets_link` consumer example walks both images and renders the below-floor refusal as miette help text. M17 releases the segment protections the layout kept as a hard-coded table: `-segprot <seg> <max> <init>` names the `maxprot`/`initprot` pair one planned segment loads with (`pgr_core::segprot` — the validated decision the segment packing and the daemon wire v10 read; the protections are subsets of `rwx`, the segment one of `__TEXT`, `__DATA_CONST`, `__DATA`, `__LINKEDIT`, one decision per segment, the initial mapping never exceeding its ceiling and never starting writable+executable — the arm64 macOS W^X contract — and every unnamed segment keeping the house pair, every pre-M17 link byte-identical), the verifier's protection contract checks the invariants the fixture knob can break (an init beyond its ceiling, a W+X mapping, a protected `__PAGEZERO`), a `-segprot` on `-r` refuses (the relocatable output carries no segments), and the `segprot` bench pins parity across the protection decisions while the `segprot_link` consumer example walks both images and renders the W^X refusal as miette help text. M18 releases the stack reserve the header assembly kept at zero: `-stack_size <n>` names the `LC_MAIN.stacksize` an executable plans with (`pgr_core::stack_size` — the validated decision the header emit and the daemon wire v11 read; non-zero, a multiple of the 16 KiB arm64 page, the zero default — dyld's own main-thread fallback — keeping every pre-M18 link byte-identical), the command is 24 bytes either way so nothing else in the plan moves, the verifier's entry gate checks the page-multiple invariant (a misaligned reserve is named), non-executable outputs refuse the knob (no `LC_MAIN`, no field to land on), and the `stack_size` bench pins parity across the reserve decisions while the `stack_size_link` consumer example walks both images and renders the misaligned refusal as miette help text — and the rung's example sweep fixed the fixups gate the dead-strip story exposed (the gate counted dead atoms' pointer slots, promising a chained-fixups payload the placement could not build: a header-only `__chain_starts` mirror beside no `LC_DYLD_CHAINED_FIXUPS`, the verifier's own contract refusing exactly that shape; the gate counts live slots now), the `icf_link` and `dead_strip_link` consumer examples ride along, and the docs drift the audit found healed (the version badge and the TDD trailer's M16 row). **M19** releases the dylib/bundle preferred load address the M3 contract kept at zero: `-image_base <n>` names the `__TEXT` vmaddr a non-executable image plans with (`pgr_core::image_base` — the validated decision the constant-delta resolver (`pgr_core::pagezero::PageZero::base_for` — one kind table, one reader since M15), both fixup planners (the `64_OFFSET` rebase words and the arm64e targets are offsets from the base), the export trie and the incremental record all read; non-zero, a multiple of the 16 KiB arm64 page, the zero default — the M3 `__TEXT.vmaddr == fileoff` contract — keeping every pre-M19 link byte-identical), the verifier's base contract verifies the invariant instead of the constant (a hand-broken base is named, a named-base dylib verifies strict), an `-image_base` on an executable refuses (the base is `__PAGEZERO`'s job — M15's `-pagezero_size` — one base knob per output kind) and on `-r` too (the relocatable output carries no segments), the daemon wire v12 carries the named base so a resident relink lays out the base the client named, and the `image_base` bench pins parity across the base decisions while the `image_base_link` consumer example walks both images and renders the executable-conflict refusal as miette help text. M20 releases the dylib umbrella region (`pgr_core::umbrella` — `-sub_umbrella`/`-sub_library`: the validated member table an umbrella dylib emits as the `LC_SUB_UMBRELLA`/`LC_SUB_LIBRARY` identity-block commands in flag order, non-dylib outputs refusing the knob with the fix, the daemon wire v13 carrying the members, the verifier gating the broken shapes, the `umbrella` bench pinning parity and the `umbrella_link` consumer example walking the story). M21 releases the dylib client list (`pgr_core::sub_client` — `-sub_client <name>`: the validated client table an identity-block dylib emits as the `LC_SUB_CLIENT` commands right after the M20 region in flag order, non-dylib outputs refusing the knob with the fix, the daemon wire v14 carrying the names, the verifier's identity-block contract gating the broken shapes in the client namespace, the `sub_client` bench pinning parity and the `sub_client_link` consumer example walking the story). M22 releases the dyld environment (`pgr_core::dyld_env` — `-dyld_env DYLD_<var>=<value>`: the validated pair table an executable emits as the `LC_DYLD_ENVIRONMENT` commands right after `LC_MAIN`, the loader-configuration adjacency, in flag order; dyld reads the command from the main executable only, so dylibs, bundles and `-r` refuse the knob with the fix, the daemon wire v15 carrying the pairs, the verifier's environment contract gating the broken shapes, the `dyld_env` bench pinning parity and the `dyld_env_link` consumer example walking the story). M23 releases the framework form of the re-export (`-reexport_framework <name>`: the M3 `-reexport_library` shape resolved through the M5 `-F` framework search — the dylib loads as `LC_REEXPORT_DYLIB`, its exports join the image's export trie as REEXPORT nodes, the LC order is plain, re-export, weak, then lazy, and the `reexport_framework_link` consumer example walks the story). M24 releases the symbol aliases (`pgr_core::alias` — `-alias <alias_name> <definition_name>`: the validated pair table an image exports as additional symtab rows and export-trie nodes, each pointing at the same definition as the named symbol so dyld resolves both names to one body; the pairs ride the symtab in flag order, an alias of a name no input defines refuses with the misspelling named, an alias name already carried by the image's symbol surface refuses (one symtab row per external name — the duplicate would silently shadow), an alias keeps its definition alive under `-dead_strip`, the relocatable output refuses the knob (the object surface carries the input symtab verbatim), the daemon wire v16 carrying the pairs, the verifier's symtab contract gating the duplicate external name, the `alias` bench pinning parity and the `alias_link` consumer example walking the story). M25 releases the bundle's host (`pgr_core::bundle_loader` — `-bundle_loader <path>`: the validated export surface a bundle binds its undefined references against, the binds riding the main-executable ordinal `0xFF` in the symtab and the import table with no `LC_LOAD_DYLIB` for the host; the surface is one reader in `pgr_format::loader_export_surface` — the host's trie plus its symtab's defined externals — shared by the driver's scan and the verifier's pair gate; only a bundle binds against a host — executables, dylibs and `-r` refuse the knob with the fix, the daemon wire v16 carrying the surface, the `bundle_loader` bench pinning parity and the `bundle_loader_link` consumer example walking the story).
>>>>>>> ship-temp-ai

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

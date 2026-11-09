# Migrating from `ld64` (Apple ld) to Peregrine (`pgr`)

Peregrine is an ld64-compatible Mach-O linker for arm64-apple-darwin. This
guide maps the flags and behaviors a build system (or a human) uses today to
their Peregrine equivalents, lists what is accepted as a no-op, and explains
the two Peregrine-specific features — the Stage A link cache and the
deterministic output contract — that have no ld64 counterpart.

## Invocation

```sh
# ld64:
ld -o hello hello.o -l System -syslibroot $SDK -e _main -arch arm64

# Peregrine:
pgr -o hello hello.o -l System -syslibroot $SDK -e _main -arch arm64
```

Peregrine accepts the ld64 flag vocabulary on the standard single-dash form
(`-flag value` and `-flagvalue` for libraries). Long link lines (CMake/Ninja
responses, Xcode's `@response` files) work as-is:

```sh
pgr @link.rsp                 # expands in place, recursively (depth-bounded)
```

Response-file rules (identical to ld64's): whitespace-separated tokens, `#`
comments, `"`-grouped tokens with `\` escapes, nested `@file` allowed. A
`@path` token whose file does not exist passes through **literally** — which
is exactly why `-install_name @rpath/libfoo.dylib` keeps working.

## Search paths and SDKs

| ld64 | Peregrine | Notes |
|---|---|---|
| `-L <dir>` | `-L <dir>` | searched for `-l` names; dylib candidates (`.tbd`, `.dylib`) win over archives (`.a`) |
| `-l <name>` / `-l<name>` | same | `lib<name>.tbd`, `<name>.tbd`, `lib<name>.dylib`, `<name>.dylib`, `lib<name>.a`, `<name>.a` |
| `-syslibroot <dir>` | `-syslibroot <dir>` (repeatable) | the ld64 pairing rule: one root → **only** `<root>/<dir>` variants of every search dir (and `/usr/lib`, the default framework dirs) are searched; two or more roots → the union of all prefixed variants **plus** the original path |
| `-F <dir>` / `-framework <n>` | same | `<dir>/<N>.framework/<N>` (+ `.tbd`) |
| `-filelist <path>[,<dir>]` | same | newline-separated paths, `#` comments |
| `-sectcreate <seg> <sect> <file>` | same | file bytes become a synthetic section |

## Output kinds and dylib surface

| ld64 | Peregrine |
|---|---|
| executable (default) | default; `-static` accepted |
| `-dylib` + `-install_name` + `-current_version` / `-compatibility_version` | same; the install name defaults to the output path |
| `-bundle` | same |
| `-r` (relocatable) | same (`MH_OBJECT` output: sections merged, relocation entries preserved and re-pointed at the output symbol table, undefineds stay open — M10) |
| `-reexport_library <path>` | same (`LC_REEXPORT_DYLIB` + trie REEXPORT nodes) |
| `-exported_symbols_list` / `-unexported_symbols_list` | same (exact-name subset; globs are roadmap) |
| `-mark_dead_strippable_dylib` | same |
| `-dead_strip` / `-no_dead_strip` | same (mark-sweep over symbol-boundary atoms) |
| `-icf=safe` / `-icf=all` / `-no_icf` | same (default `none`) |
| `-all_load` / `-force_load <archive>` / `-u <symbol>` | same (archives pull members lazily via ranlib) |

## Accepted no-ops (feature parity by default)

These ld64 flags are accepted with no effect because Peregrine's default
behavior already matches what they request on arm64:

- `-demangle` / `-no_demangle` — symbol names are stored verbatim in the
  symtab (demangling is a consumer-side concern);
- `-no_deduplicate` — cstring/code dedup stays on (the arm64 default; there
  is no off switch yet);
- `-object_path_lto <path>` — the value is consumed; LLVM bitcode inputs are
  diagnosed clearly (rebuild with `-fno-lto`);
- `-no_uuid`, `-no_function_starts`, `-no_data_in_code`,
  `-keep_private_externs`, `-no_adhoc_extensions`;
- `-adhoc` / `-no_adhoc`, `-headerpad`, `-segalign` (0x1000 or 0x4000),
  `-fixup_chains` / `-no_fixup_chains`, `-flat_namespace` /
  `-twolevel_namespace`, `-undefined error|dynamic_lookup`, `-rpath`,
  `-source_version`, `-arch arm64`, `-platform_version <platform> <min> <sdk>`
  with `<platform>` ∈ `macos`, `ios`, `tvos`, `watchos`, `visionos` (M10; the
  SDK must be at least the deployment target).

## Rejected with an actionable message

A linker that silently drops a flag it does not implement is worse than one
that says so. These are rejected with the roadmap entry in the message:
`-dylinker`, `-weak_framework`, `-lazy_framework`, `-lazy_library`,
`-order_file`, `-U`, `-pagezero_size`, `-sub_library`, `-sub_umbrella`.

## Peregrine-specific: the Stage A link cache

Optional, off by default, and **an optimization only** — a corrupt, stale or
foreign entry is detected and silently re-parsed; cached and uncached output
are byte-identical (gated in CI):

```sh
pgr -o app app.o -cache .pgr-cache          # opt in
pgr -o app app.o -cache .pgr-cache -cache_max 536870912   # 512 MiB LRU bound
PGR_CACHE_DIR=.pgr-cache pgr -o app app.o   # environment form
pgr -o app app.o -no_cache                  # force off
```

Entries are content-addressed (`sha256(input || flags)` plus the cache
format version and parser revision) and carry a v2 frame
(`magic | format_version | parser_revision | len | sha256`). A cache
directory written by a different pgr version self-heals on open: stale
pgr-owned files are reclaimed, the marker is rewritten, foreign files are
never touched. The default size bound is 2 GiB (`-cache_max 0` = unbounded);
eviction is oldest-mtime-first with recency refresh on hits, and the
just-stored entry is never evicted.

## Peregrine-specific: determinism

Linking the same inputs twice — in one process or two, single-threaded
(`PGR_JOBS=1`) or parallel, cached or uncached, folded or not — produces
**byte-identical** output. Build systems can treat the output path as
content-addressed. `-icf` and `-dead_strip` are deterministic by
construction (first-occurrence class ids, fixed-point layouts).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | link succeeded |
| 1 | link failure (undefined symbols, malformed input, emit error) |
| 2 | command-line problem (unknown flag, missing value, bad response file) |

## Environment variables

| Variable | Meaning |
|---|---|
| `PGR_CACHE_DIR` | default cache directory (as `-cache`) |
| `PGR_CACHE_MAX` | default cache size bound (as `-cache_max`) |
| `PGR_JOBS` | worker threads for the parallel passes (`1` = serial/deterministic debugging mode) |
| `PGR_LLD64` | path to `ld64.lld` for the golden cross-check tests |
| `PGR_DAEMON_SOCK` | default `pgrd` socket path (as `-resident_socket`) |
| `PGR_RESIDENT_DEBUG` | set to install a tracing subscriber for the resident path |
| `PGR_INCREMENTAL_RECORD` | pin the M9 link-record sidecar path (default `<output>.pgr-inc`) |
| `PGR_INCREMENTAL_DEBUG` | set to install a tracing subscriber for the relink path |
| `PGR_RANDOMIZED_STEPS` | size the M9 GA seeded randomized edit walk |
| `PGR_TRACING` | set in consumer processes to install a tracing subscriber (the library spans stay inert otherwise) |

## Verifying outputs

`pgr-verify` is the read-side contract checker (structural, segment,
dyld-simulation of chained fixups, export-trie walk, signature recompute,
dylib-pair gate). CI runs every linked image through it in strict mode:

```sh
pgr-verify hello --strict
```

## Compatibility suite

`cargo test -p pgr-driver --test m7_compat` runs the agreed-list
compatibility suite (38 fixture-backed cases spanning load commands, image
contracts, driver flags, M7 surface, determinism and diagnostics) and
asserts the roadmap's **≥ 98% pass** gate. The suite prints the per-case
table; every case is strict-verified output of the real driver pipeline.

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
| `-dylib` + `-install_name` + `-current_version` / `-compatibility_version` | same; the install name defaults to the output path (`-final_output <path>` supplies the derived name when `-install_name` is absent — M44) |
| `-bundle` | same |
| `-r` (relocatable) | same (`MH_OBJECT` output: sections merged, relocation entries preserved and re-pointed at the output symbol table, undefineds stay open — M10) |
| `-reexport_library <path>` | same (`LC_REEXPORT_DYLIB` + trie REEXPORT nodes) |
| `-weak_framework <name>` / `-lazy_framework <name>` | same (`LC_LOAD_WEAK_DYLIB` with weak binds / `LC_LAZY_LOAD_DYLIB`; M14) |
| `-lazy_library <path>` | same (`LC_LAZY_LOAD_DYLIB`; the command rides the two-level ordinal space like a plain load — M14) |
| `-upward_library <path>` / `-upward_framework <name>` | same (`LC_LOAD_UPWARD_DYLIB` — the umbrella-relationship load; the command rides the two-level ordinal space like a plain load — M45) |
| `-export_dynamic` | same (every global definition roots the dead-strip mark phase in a main executable — the `dlsym` surface; M46) |
| `-no_branch_islands` | same (the Pass-3 veneer fixed point stops planning branch islands — an out-of-range branch the ±128 MiB `imm26` window cannot reach refuses the link with the site named; M47) |
| `-init <symbol>` | same (the dylib's load-time initializer rides `LC_ROUTINES_64` — the resolved initializer's image-space vaddr; dylibs only, ld64's "-init can only be used with -dynamiclib" — M48) |
| `-ObjC` (GCC-era members) | same (the pull admits the ObjC1/GCC-era `.objc_class_name_`/`.objc_category_name_` index symbols beside the modern `$_` family — ld64's `.objc_c` matcher rule; the protocol list stays out — M49) |
| `-no_weak_imports` | same (a weak import dyld must look up at runtime refuses with the symbol named — a link-time resolution never does; M50) |
| `-allow_stack_execute` | same (the `MH_ALLOW_STACK_EXECUTION` flag word rides the executable's header — every stack in the task, the pthread stacks included, maps executable; executables only — the kernel loads a dylib or a bundle itself; M51) |
| `-no_dead_strip_inits_and_terms` | same (the termination-pointer sections join the init sections' dead-strip roots — a term routine nothing references survives `-dead_strip`; the init half is the default; M52) |
| `-rename_section <fromSeg> <fromSect> <toSeg> <toSect>` | same (the renamed section groups with its new name and lands in the new segment — the protections follow the segment; every name within the Mach-O 16-byte field width, a synthetic source or target refuses, the zero-fill type rule outranks the map, the relocatable output never reads the table; M53) |
| `-exported_symbols_list` / `-unexported_symbols_list` | same (`*` globs supported — each star matches any, possibly empty, byte run; M14) |
| `-mark_dead_strippable_dylib` | same |
| `-dead_strip` / `-no_dead_strip` | same (mark-sweep over symbol-boundary atoms) |
| `-icf=safe` / `-icf=all` / `-no_icf` | same (default `none`) |
| `-all_load` / `-force_load <archive>` / `-u <symbol>` | same (archives pull members lazily via ranlib) |
| `-dead_strip_dylibs` | same (input dylibs nothing binds against leave the header — the kept list compacts the two-level ordinals; re-export dylibs and dynamic-lookup providers always ride; M42) |
| `-fixup_chains` / `-no_fixup_chains` | same (chained `LC_DYLD_CHAINED_FIXUPS` by default; below the deployment floor — or with `-no_fixup_chains` — the classic `LC_DYLD_INFO_ONLY` streams encode the same fixups) |
| `-fixup_chains_format offset64\|arm64e` | same family vocabulary (M10 rung 4; an explicitly named family refuses a target below the platform's chained-fixups floor — raise the target or drop the flag) |
| `-platform_version <platform> <min> <sdk>` | same (`<platform>` ∈ `macos`, `ios`, `tvos`, `watchos`, `visionos`; the SDK must be at least the deployment target) |
| `-flat_namespace` / `-twolevel_namespace`, `-undefined error\|dynamic_lookup` | same |
| `-rpath <path>` | same (`LC_RPATH`) |
| `-source_version <n>` | same (`LC_SOURCE_VERSION`) |
| `-adhoc` / `-no_adhoc` | same (the ad-hoc signature is on by default) |
| `-segalign 0x1000\|0x4000` | same |
| `-pagezero_size <n>` | same (the `__PAGEZERO` vmsize an executable plans with — the constant-delta image base; a non-zero multiple of the 16 KiB arm64 page, the 4 GiB default unchanged; M15) |
| `-arch arm64` | same (arm64-apple-darwin exclusively) |

## Accepted no-ops

These ld64 flags are accepted and ignored (recorded as no-ops rather than
silently dropped):

- `-demangle` / `-no_demangle` — symbol names are stored verbatim in the
  symtab (demangling is a consumer-side concern);
- `-object_path_lto <path>` — the value is consumed; LLVM bitcode inputs are
  diagnosed clearly (rebuild with `-fno-lto`);
- `-no_adhoc_extensions`.

Flags that left this list when they became real decisions: `-no_data_in_code`
(M30, the data-in-code carriage), `-no_function_starts` (M31, the
function-starts suppression), `-no_uuid` (M32, the UUID suppression),
`-keep_private_externs` (M33, the private-extern decision), `-headerpad <n>`
(M29, the header-region floor — the advisory no-op it carried since M1) and
`-no_deduplicate` (M41, the dedup toggle — identical literals stop merging
and every input `__cstring` section rides verbatim; code dedup stays an
opt-in via `-icf`), `-dead_strip_dylibs` (M42, the unused-dylib drop),
`-ObjC` (M43, the ObjC archive pull — members implementing an
Objective-C class or category ride the pull without a reference),
`-final_output` (M44, the dylib-identity default — the install name a
dylib link derives when `-install_name` is absent) and
`-upward_library`/`-upward_framework` (M45, the umbrella-relationship load)
with `-export_dynamic` (M46, the dead-strip root widening — every global
definition roots the mark phase in a main executable), `-no_branch_islands`
(M47, the branch-island suppression — the M6 veneer fixed point stops
planning islands on the named decision) and `-init` (M48, the dylib's
load-time initializer — the resolved initializer's image-space vaddr rides
`LC_ROUTINES_64`, dylibs only per ld64's own validation).

The flags that look like no-ops but actually shape the link (the default
behavior already matches what they request on arm64) are mapped in the
tables above: `-adhoc` / `-no_adhoc`, `-segalign`, `-fixup_chains` /
`-no_fixup_chains`, `-fixup_chains_format`, `-flat_namespace`, `-undefined`,
`-rpath`, `-source_version`, `-arch arm64`, `-platform_version`. The provenance queries (`-why_export <symbol>`, `-why_load`, M56/M57) ride the same driver surface: the definition and reference sites a symbol carries, the decision that admitted each archive member — reports beside the link, every lane serving its own walk's answer (the resident session since M79, the incremental ladder since M84, the fusion ladder since M88). The liveness query (`-why_live <symbol>`, M92) joins them — the mark phase's own record walked from the queried definition back to its root — and serves beside `-resident` since M93 (wire v48 carries the names, the session's own mark record renders the chains; the relocatable output refuses the premise — `-r` carries no strip).

## Peregrine-specific: the per-pass time report

`--time` prints the per-pass wall table after the link — the passes the
pipeline ran (parse through layout), each with its own shape and wall time,
the fused emit band and the pipeline's total; `--time-json` prints the same
measurement as a one-line JSON interchange. It is Peregrine-specific (ld64
has no counterpart): a measurement for build systems and CI budgets, read
off the M54 observation seam, never a layout product — a timed link plans
byte-identical output to an untimed one. The resident lane serves the same
report from the daemon's own observed pipeline (wire v40); the in-process
incremental ladder rides since M65 — the §7.3 rungs (the integrity gate,
the patch plan, the clone-and-patch, the audit) join the seam's vocabulary
and the table names them beside the pipeline's rows; the fusion lane
`-resident -incremental` serves the session's observed ladder since M66
(wire v42 in service — the daemon reports its rungs across the wire).

```sh
pgr -o app main.o -lgreet -L libs --time         # the table beside the link
pgr -o app main.o -lgreet -L libs --time-json    # the interchange line
pgr -o app main.o -lgreet -L libs -incremental --time   # the ladder's rungs
```

## Peregrine-specific: the Chrome-trace timeline

`--trace <path>` writes the link's Chrome Trace Event Format timeline
(the `{"traceEvents":[…]}` object form) after the link — the pipeline's
phase spans on a µs axis, each with its own shape, and the ladder's notes
as instants; the gaps between the spans are the idle stretch the
profiling toolbox reads. It is Peregrine-specific (ld64 has no
counterpart): a measurement off the same M54 observation seam the time
report reads, never a layout product — a traced link plans byte-identical
output to an untraced one. The file opens in `chrome://tracing` or the
Perfetto UI, and `pgr_core::trace::parse_trace_json` is the strict reader
(the round trip is gated). The resident lane serves the same timeline
from the daemon's own observed pipeline (wire v41 — the client writes the
served document verbatim); the in-process incremental ladder rides since
M65 — the §7.3 rungs ride the timeline as spans beside the pipeline's —
and the fusion lane serves the session's observed ladder since M66 (wire
v42 in service).

```sh
pgr -o app main.o -lgreet -L libs --trace t.json   # the timeline beside the link
pgr -o app main.o -lgreet -L libs -resident --trace t.json   # the served timeline
pgr -o app main.o -lgreet -L libs -incremental --trace t.json   # the ladder's rungs
```

## Rejected with an actionable message

A linker that silently drops a flag it does not implement is worse than one
that says so. The list is empty today — every flag that waited here shipped:
(`-order_file` left this list when its rank-based subset shipped at M11,
alongside `-map`; the weak/lazy dylib family — `-weak_framework`,
`-lazy_framework`, `-lazy_library` — left it at M14, `-pagezero_size`
left it at M15, the image base becoming a validated `LinkConfig` decision,
`-sub_umbrella`/`-sub_library` left it at M20 (the umbrella region),
`-U` left it at M39 — the make-undefined mark: `-U _f -undefined
dynamic_lookup` strips `_f`'s definition as it is linked and binds the
reference flat at load time — `-dylinker` left it at M26 (its stale entry
here outlived the release and left with the M43 promotion), and `-ObjC`
left it at M43 — the ObjC archive pull: members implementing an
Objective-C class or category ride the pull without a reference.)

`-sectorder <seg> <sect> <file>` (M90/M91) — ld64's per-section order flag
rides the M11 rank seam: an ordinary section's file appends its entries to
the rank table in flag order, the `__TEXT,__cstring` face ranks the literal
sections by escape-decoded content, and a `__TEXT,__literal*` section is the
warned no-op (the file is never read). It composes with `-order_file` in
command-line order and serves beside `-resident` on the same rank-table
carriage.

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

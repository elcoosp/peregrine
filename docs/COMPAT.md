# ld64 Compatibility Checklist

The ld64 surface Peregrine **implements**, **refuses**, or **will never implement** — tracked
from M2 per the architecture doc (§3, row D13: _"as a compat checklist from M2; each flag has a
fixture"_). Every ✅ row lands with a fixture-backed test; every refusal names its fix.

| Legend             | Meaning                                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------- |
| ✅                 | Supported, fixture-backed                                                                   |
| ✅ (no-op)         | Accepted, deliberately no effect (build-system compat)                                      |
| ✅ (pass-through)  | Carried verbatim, structurally verified                                                     |
| ✅ (diagnose-only) | Detected and refused with a diagnostic                                                      |
| 🔶                 | Staged — see the [incremental tier table](#incremental-relink--shipped-tiers)               |
| ❌                 | Refused with an actionable error, or won't-support — [reasons below](#refused--unsupported) |

<p>
  <a href="#load-commands">Load commands</a> • <a href="#output-kinds">Output kinds</a> • <a href="#driver-flags">Driver flags</a> • <a href="#linking-semantics">Semantics</a> • <a href="#incremental-relink--shipped-tiers">Incremental tiers</a> • <a href="#refused--unsupported">Refusals</a> • <a href="#golden-cross-validation">Golden harness</a>
</p>

---

## Load commands

| Command                                                                                     | Status            | Since  | Fixture / test                                                                         |
| ------------------------------------------------------------------------------------------- | ----------------- | ------ | -------------------------------------------------------------------------------------- |
| `LC_SEGMENT_64` (canonical order; protections via `-segprot`)                               | ✅                | M0     | `pgr-verify` `check_segments`                                                          |
| `LC_MAIN` (entry; stack reserve via `-stack_size`)                                          | ✅                | M0     | `pgr-verify` entry checks                                                              |
| `LC_SYMTAB` / `LC_DYSYMTAB`                                                                 | ✅                | M0/M2  | `e2e::symtab_is_in_ld64_canonical_order`, `m2_links_printf_from_tbd` (indirect ranges) |
| `LC_BUILD_VERSION` (1 tool entry, `TOOL_LD`; five platforms)                                | ✅                | M0/M10 | `misc::check_entry_and_version`, `m10_platform::*` (verify)                            |
| `LC_UUID` (content-derived)                                                                 | ✅                | M0     | `emit::write_signature` two-pass UUID                                                  |
| `LC_LOAD_DYLINKER`                                                                          | ✅                | M0     | `misc::check_entry_and_version` (warning when absent)                                  |
| `LC_SOURCE_VERSION` (`-source_version A.B.C.D.E`)                                           | ✅                | M2     | `e2e::m2_rpath_and_source_version_commands_land`                                       |
| `LC_FUNCTION_STARTS`                                                                        | ✅                | M0     | `misc::check_function_starts`                                                          |
| `LC_DATA_IN_CODE`                                                                           | ✅ (pass-through) | M0     | `misc::check_linkedit_payloads`                                                        |
| `LC_CODE_SIGNATURE` (ad-hoc; arm64 mandatory)                                               | ✅                | M0     | `signature::check_signature`                                                           |
| `LC_DYLD_CHAINED_FIXUPS` (rebase + bind, import table)                                      | ✅                | M0/M2  | `fixups` unit tests, `verify_integration::bind_ordinal_out_of_range_detected`          |
| `LC_DYLD_INFO_ONLY` (classic opcode streams below the platform floor or `-no_fixup_chains`) | ✅                | M6     | `m6_legacy::*`, `dyld_info::check_dyld_info`                                           |
| `LC_DYLD_EXPORTS_TRIE` (exe exports + `__mh_execute_header`)                                | ✅                | M2     | `e2e::m2_links_printf_from_tbd`, `export_trie` walker tests                            |
| `LC_LOAD_DYLIB` (ordinal order, versions from `.tbd`)                                       | ✅                | M2     | `e2e::m2_links_printf_from_tbd`                                                        |
| `LC_LOAD_WEAK_DYLIB` (`-weak_library` / `-weak_framework`)                                  | ✅                | M2     | `opts::tests::m2_flags_shape_the_config`, `Dylib.weak`                                 |
| `LC_LAZY_LOAD_DYLIB` (counts in the two-level ordinal space like a plain load)              | ✅                | M14    | `m14_lazy_dylibs::*`, `pgr_core::resolve::Dylib::lazy`                                 |
| `LC_REEXPORT_DYLIB` + trie REEXPORT nodes                                                   | ✅                | M3     | `e2e::m3_reexport_library_lands_in_the_trie`                                           |
| `LC_ID_DYLIB` (`-install_name`, versions)                                                   | ✅                | M3     | `e2e::m3_dylib_output_passes_verifier_strict`                                          |
| `LC_RPATH` (`-rpath`)                                                                       | ✅                | M2     | `e2e::m2_rpath_and_source_version_commands_land`                                       |
| `LC_SUB_UMBRELLA` / `LC_SUB_LIBRARY` (`-sub_umbrella` / `-sub_library`)                     | ✅                | M20    | `m20_umbrella::*` (verify), `pgr_core::umbrella`                                       |
| `LC_SUB_CLIENT` (`-sub_client`)                                                             | ✅                | M21    | `m21_sub_client::*` (verify), `pgr_core::sub_client`                                   |
| `LC_DYLD_ENVIRONMENT` (`-dyld_env`; right after `LC_MAIN`)                                  | ✅                | M22    | `m22_dyld_env::*` (verify), `pgr_core::dyld_env`                                       |
| `__TEXT,__init_offsets` (section; the `-init_offsets` u32-offset initializer form)          | ✅                | M16    | `pgr_core::init_offsets`, `m16_init_offsets::*`                                        |

_`LC_ENCRYPTION_INFO` is on the [won't-support list](#refused--unsupported)._

## Output kinds

| Kind                                                                   | Status | Since | Fixture / test                                                                                                           |
| ---------------------------------------------------------------------- | ------ | ----- | ------------------------------------------------------------------------------------------------------------------------ |
| `MH_DYLIB` (`-dylib`)                                                  | ✅     | M3    | `e2e::m3_dylib_output_passes_verifier_strict`                                                                            |
| `MH_BUNDLE` (`-bundle`)                                                | ✅     | M3    | `e2e::m3_bundle_output_passes_verifier`                                                                                  |
| `MH_OBJECT` (`-r`; merged sections, preserved relocs, open undefineds) | ✅     | M10   | `m10_relocatable::r_output_relinks_into_an_executable` (two-step self-consumption), `object_emit::*`, `object_relocs::*` |

## Driver flags

<<<<<<< HEAD
Full surface: `pgr --help`. Refusals name the fix; every knob's default keeps pre-knob links
**byte-identical**. Grouped by domain below.

### Output & platform

| Flag                                                                  | Status | Since | Fixture / test                                                                          |
| --------------------------------------------------------------------- | ------ | ----- | --------------------------------------------------------------------------------------- |
| `-o` / `-arch` / `-e` / `-static`                                     | ✅     | M0/M1 | `opts` unit tests                                                                       |
| `-platform_version <macos\|ios\|tvos\|watchos\|visionos> <min> <sdk>` | ✅     | M10   | `opts` tests, `m10_platform::*` · example `platform_matrix`                             |
| `-dylib` / `-bundle`                                                  | ✅     | M3    | `opts::tests::m3_dylib_flags_shape_the_config`, `e2e::m3_bundle_output_passes_verifier` |
| `-r` (relocatable `MH_OBJECT`)                                        | ✅     | M10   | `m10_relocatable::r_output_relinks_into_an_executable`                                  |

- SDK ≥ deployment target, checked at parse time; unknown platforms refuse with the surface in the hint.
- The per-platform chained-fixups floor picks the encoding — one table, three readers (layout, verifier, `--print-fixup-encoding`).

### Inputs & search

| Flag                                                                                                         | Status | Since | Fixture / test                                                                                                                |
| ------------------------------------------------------------------------------------------------------------ | ------ | ----- | ----------------------------------------------------------------------------------------------------------------------------- |
| `.tbd` stubs (v3/v4)                                                                                         | ✅     | M2    | `pgr-format::tbd` tests, `e2e::m2_links_printf_from_tbd`                                                                      |
| Mach-O `.dylib` inputs (install name + trie/symtab export scan)                                              | ✅     | M3    | `pgr_driver::scan_dylib`, `e2e::m3_exec_against_pgr_dylib_passes_the_pair_gate`                                               |
| `.a` archives (ranlib `__.SYMDEF` / `/` / `__.SYMDEF_64`; BSD `#1/` + GNU `//` long names; lazy member pull) | ✅     | M5    | `pgr_format::archive` tests + proptests, `m5_archives::*`                                                                     |
| `-l <name>` / `-l<name>` / `-L <dir>` (searches `-L`, then `/usr/lib`; dylib candidates before `.a`)         | ✅     | M2/M5 | `driver::resolve_lib`, `m5_flags::m5_l_search_prefers_dylibs_over_archives`, `m5_archives::m5_l_search_finds_static_archives` |
| `-filelist <path>[,<dir>]`                                                                                   | ✅     | M5    | `m5_flags::m5_filelist_expands_inputs_in_order`                                                                               |
| `-framework <name>` / `-F <dir>` (`.tbd`/dylib payloads)                                                     | ✅     | M5    | `m5_flags::m5_framework_search_finds_stub_dylibs`                                                                             |
| `-all_load`                                                                                                  | ✅     | M5    | `m5_archives::m5_all_load_pulls_every_member`                                                                                 |
| `-force_load <archive>`                                                                                      | ✅     | M5    | `m5_archives::m5_force_load_pulls_only_the_named_archive`                                                                     |
| `-rpath <path>`                                                                                              | ✅     | M2    | `e2e::m2_rpath_and_source_version_commands_land`                                                                              |
| `-sectcreate <seg> <sect> <file>`                                                                            | ✅     | M5    | `m5_flags::m5_sectcreate_places_file_contents`                                                                                |
| `-syslibroot <dir>` (repeatable)                                                                             | ✅     | M7    | `opts::effective_lib_dirs` tests, `m7_driver::m7_syslibroot_*`                                                                |
| `@<response-file>`                                                                                           | ✅     | M7    | `opts::m7_response_file_*`, `m7_driver::m7_response_file_drives_a_real_link`                                                  |

- **`-syslibroot` pairing rule** (ld64's): 1 root = prefixed-only; ≥ 2 roots = union + original.
- **Response files**: nested, `#` comments, quotes/escapes; expansion is opportunistic — a non-existent `@path` passes through, keeping `-install_name @rpath/...` intact.

### Symbol binding & visibility

| Flag                                                                            | Status | Since  | Fixture / test                                                                                                           |
| ------------------------------------------------------------------------------- | ------ | ------ | ------------------------------------------------------------------------------------------------------------------------ |
| `-flat_namespace` / `-no_flat_namespace` / `-twolevel_namespace`                | ✅     | M2     | `e2e::m2_flat_namespace_binds_dyld_flat`                                                                                 |
| `-undefined error\|dynamic_lookup`                                              | ✅     | M2     | `e2e::m2_undefined_dynamic_lookup_binds_weak_flat`                                                                       |
| `-u <symbol>` (in-image definition required; pulls the defining archive member) | ✅     | M2/M5  | `driver::link_to_image`, `m5_archives::m5_u_symbol_pulls_its_member`                                                     |
| `-weak_library <path>`                                                          | ✅     | M2     | `Dylib.weak` → `LC_LOAD_WEAK_DYLIB`                                                                                      |
| `-weak_framework` / `-lazy_framework` / `-lazy_library` (repeatable)            | ✅     | M14    | `opts::tests::m14_lazy_weak_flags_shape_the_config`, `m14_lazy_dylibs::*` · bench `dylibs` · example `lazy_library_link` |
| `-exported_symbols_list <file>` (exact or `*` globs)                            | ✅     | M3/M14 | `e2e::m3_export_filters_shape_trie_and_symtab`, `m14_export_filter::*`, `pgr_core::export_filter`                        |
| `-unexported_symbols_list <file>` (same matcher; `N_PEXT` semantics)            | ✅     | M3/M14 | `e2e::m3_export_filters_shape_trie_and_symtab`, `m14_export_filter::*`                                                   |
| `-alias <alias> <definition>` (repeatable; one body, two exported names)        | ✅     | M24    | `pgr_core::alias`, `m24_alias::*` · bench `alias` · example `alias_link`                                                 |
| `-bundle_loader <path>` (bundle binds against its host executable)              | ✅     | M25    | `pgr_core::bundle_loader`, `m25_bundle_loader::*` · bench `bundle_loader` · example `bundle_loader_link`                 |

- **Globs**: each `*` matches any, possibly empty, byte run (`_OBJC_CLASS_$_*`); a malformed line refuses with the fix; a pattern that matched nothing warns (the order-file advisory precedent). The M3 exact form is the all-exact shape of the same `SymbolMatcher` seam.
- **Framework forms** search `-F` like `-framework`; weak loads ride `LC_LOAD_WEAK_DYLIB` + weak binds, lazy loads ride `LC_LAZY_LOAD_DYLIB`.
- **`-alias`**: an undefined target refuses with the misspelling named; a name already defined or referenced refuses (one symtab row per external name — a duplicate would silently shadow); the alias keeps its definition alive under `-dead_strip`; `-r` refuses.
- **`-bundle_loader`**: binds ride the main-executable ordinal `0xFF` (`BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE`), no `LC_LOAD_DYLIB` for the host; one export-surface reader (`pgr_format::loader_export_surface`: trie + defined externals) shared by the driver's scan and the verifier's pair gate; only a bundle may name a host.

### Dylib identity & loader metadata

| Flag                                                             | Status | Since | Fixture / test                                                                                     |
| ---------------------------------------------------------------- | ------ | ----- | -------------------------------------------------------------------------------------------------- |
| `-install_name` (dylibs; defaults to the output path)            | ✅     | M3    | `opts::tests::m3_dylib_flags_shape_the_config`                                                     |
| `-current_version` / `-compatibility_version`                    | ✅     | M3    | `opts::tests::m3_dylib_flags_shape_the_config`                                                     |
| `-reexport_library <path>`                                       | ✅     | M3    | `opts::tests::m3_reexport_library_records_the_input`, `e2e::m3_reexport_library_lands_in_the_trie` |
| `-reexport_framework <name>` (the `-F`-searched re-export form)  | ✅     | M23   | `m23_reexport_framework::*` · example `reexport_framework_link`                                    |
| `-sub_umbrella <name>` / `-sub_library <name>` (umbrella region) | ✅     | M20   | `m20_umbrella::*`, `pgr_core::umbrella` · bench `umbrella` · example `umbrella_link`               |
| `-sub_client <name>` (allowed clients)                           | ✅     | M21   | `m21_sub_client::*`, `pgr_core::sub_client` · bench `sub_client` · example `sub_client_link`       |
| `-dyld_env DYLD_<var>=<value>` (repeatable; exe only)            | ✅     | M22   | `m22_dyld_env::*`, `pgr_core::dyld_env` · bench `dyld_env` · example `dyld_env_link`               |
| `-mark_dead_strippable_dylib`                                    | ✅     | M3    | `opts::tests::m3_dylib_flags_shape_the_config`                                                     |
| `-source_version A.B.C.D.E`                                      | ✅     | M2    | `opts::tests::m2_flags_shape_the_config`                                                           |

- **Names**: non-empty, NUL-free, one decision per name, emitted in flag order. `-dyld_env` pairs additionally require a `DYLD_`-prefixed variable and exactly one `=`.
- **Output-kind gates**: umbrella/clients are dylib-only; `-dyld_env` is main-executable-only (dyld reads it from there) — everything else refuses with the fix.
- **Command order**: `LC_ID_DYLIB` → region → clients; dylib loads order plain → re-export → weak → lazy; `LC_DYLD_ENVIRONMENT` sits right after `LC_MAIN`.

### Image layout

| Flag                                                                                         | Status | Since | Fixture / test                                                                                       |
| -------------------------------------------------------------------------------------------- | ------ | ----- | ---------------------------------------------------------------------------------------------------- |
| `-pagezero_size <n>` (exe `__PAGEZERO` vmsize; default 4 GiB)                                | ✅     | M15   | `m15_pagezero::*`, `pgr_core::pagezero` · bench `pagezero` · example `pagezero_link`                 |
| `-image_base <n>` (dylib/bundle `__TEXT` vmaddr; default 0)                                  | ✅     | M19   | `m19_image_base::*`, `pgr_core::image_base` · bench `image_base` · example `image_base_link`         |
| `-segprot <seg> <max> <init>` (per-segment protection pair)                                  | ✅     | M17   | `m17_segprot::*`, `pgr_core::segprot` · bench `segprot` · example `segprot_link`                     |
| `-stack_size <n>` (exe `LC_MAIN` stack reserve; default 0 = dyld's fallback)                 | ✅     | M18   | `m18_stack_size::*`, `pgr_core::stack_size` · bench `stack_size` · example `stack_size_link`         |
| `-init_offsets` / `-no_init_offsets` (initializer form; default = classic `__mod_init_func`) | ✅     | M16   | `m16_init_offsets::*`, `pgr_core::init_offsets` · bench `init_offsets` · example `init_offsets_link` |
| `-headerpad` (advisory) / `-segalign`                                                        | ✅     | M1    | `opts` unit tests                                                                                    |

- **Values**: decimal or `0x`-hex, non-zero multiples of the 16 KiB arm64 page (`-pagezero_size`, `-image_base`, `-stack_size`). Defaults keep every pre-knob link byte-identical.
- **One base knob per output kind**: `-pagezero_size` is executable-only; `-image_base` is dylib/bundle-only (the executable's base is `__PAGEZERO`'s job). Both refuse on `-r`.
- **`-segprot`**: segments `__TEXT` / `__DATA_CONST` / `__DATA` / `__LINKEDIT`, protections subsets of `rwx`, one decision per segment; init never exceeds max, never starts W+X (the arm64 macOS W^X contract). House pairs: `__TEXT` RX/RX, `__DATA_CONST`/`__DATA` RW/RW, `__LINKEDIT` R/R.
- **`-init_offsets`**: the transform emits `__TEXT,__init_offsets` u32 offsets from the load address (no rebases needed); refuses below the platform's chained-fixups floor, on `-r`, and at a bind-targeted initializer.
- **`-stack_size`**: `LC_MAIN` is 24 bytes either way — nothing else in the plan moves; non-executable outputs refuse.
- The verifier checks the **invariants**, not the constants (a hand-broken base/protection is named; a custom-base image verifies strict).

### Size, order & reporting

| Flag                                                                            | Status | Since | Fixture / test                                                                     |
| ------------------------------------------------------------------------------- | ------ | ----- | ---------------------------------------------------------------------------------- |
| `-dead_strip` / `-no_dead_strip` (D12 mark-sweep over D1 symbol-boundary atoms) | ✅     | M5    | `m5_deadstrip::*` (e2e + core)                                                     |
| `-icf=safe\|all` / `-no_icf` (identical code folding, color refinement)         | ✅     | M6    | `pgr-core::icf` tests, `m6_icf::*`                                                 |
| `-order_file <path>` (rank subset: `symbol` / `object.o:symbol`)                | ✅     | M11   | `m11_order_file::*`, `pgr_core::order` · bench `order` · example `order_file_link` |
| `-map <path>` (link map: segments, sections, symbol rows)                       | ✅     | M11   | `pgr_core::map`, `m11_map::*` · bench `map` · example `link_map`                   |

- **Dead-strip roots**: entry, `-u`, dylib exports, `__mod_init_func`, `S_ATTR_NO_DEAD_STRIP`.
- **Order file**: TDD §8.4 stable rank sort — ranked atoms lead, unranked keep canonical order; contract-coupled sections (`__got`/`__stubs`/`__common`/`__cstring`) keep their own order; entries that rank nothing get an advisory. Refuses `-r` / `-resident`.
- **Link map**: rendered from the plan the fused emit writes — report and bytes cannot disagree. Refuses `-r` / `-incremental` / `-resident`.

### Fixups & signing

| Flag                                                                                                          | Status | Since | Fixture / test                                                                                     |
| ------------------------------------------------------------------------------------------------------------- | ------ | ----- | -------------------------------------------------------------------------------------------------- |
| `-fixup_chains` / `-no_fixup_chains`                                                                          | ✅     | M1    | `opts` unit tests                                                                                  |
| `-fixup_chains_format offset64\|arm64e` (chain word family; default = M2 `DYLD_CHAINED_PTR_64_OFFSET`)        | ✅     | M10   | `m10_arm64e::*` (parse + gates + e2e strict), `m10_arm64e_producer::*` · example `arm64e_producer` |
| Authenticated arm64e words — **library seam, no CLI flag** (`plan_fixups_with_auth` + `FixupAuth` PAC triple) | ✅     | M10   | `m10_arm64e_auth::*` · bench `arm64e_auth` · example `fixup_chains_auth`                           |
| `-adhoc` / `-no_adhoc`                                                                                        | ✅     | M1    | `e2e::no_adhoc_omits_the_signature`                                                                |

- **Named-format refusals**: the classic opcode path, `-resident`, `-r`, and below-floor targets all refuse an explicitly named family (the flag-less default keeps the documented silent fallback).
- **Auth words**: rebases carry the 32-bit runtime offset + diversity/addrDiv/key; binds move their whole addend into the import entry (the addend-split's one named exception); a policy under `offset64` refuses outright.

### Build-system integration

| Flag                                                                   | Status     | Since | Fixture / test                                                         |
| ---------------------------------------------------------------------- | ---------- | ----- | ---------------------------------------------------------------------- |
| `-demangle` / `-no_demangle` / `-no_deduplicate`                       | ✅ (no-op) | M7    | `opts::m7_build_system_noop_flags_are_accepted`, `m7_compat::m7_noops` |
| `-object_path_lto <path>` (value consumed; LTO objects stay diagnosed) | ✅ (no-op) | M7    | `opts::m7_build_system_noop_flags_are_accepted`                        |
| Compatibility suite (38-case agreed list, ≥ 98 % gate)                 | ✅         | M7    | `m7_compat::m7_compat_suite_passes_the_agreed_list`                    |

- No-op semantics are deliberate: symtab names stay verbatim; dedup stays on (the arm64 default).

### Fast paths — cache · resident · incremental

| Flag                                                                                                  | Status | Since | Fixture / test                                                                      |
| ----------------------------------------------------------------------------------------------------- | ------ | ----- | ----------------------------------------------------------------------------------- |
| `-cache <dir>` / `PGR_CACHE_DIR` / `-no_cache` (Stage A: POIs + frozen `.tbd`)                        | ✅     | M6    | `pgr-core::cache` tests, `m6_cache::*`                                              |
| `-cache_max <bytes>` / `PGR_CACHE_MAX` (LRU bound; default 2 GiB, 0 = unbounded)                      | ✅     | M7    | `pgr_core::cache` LRU tests, `m7_cache::m7_cache_max_bounds_the_directory`          |
| Versioned cache format v2 (format + parser revisions in frame and key; self-healing directory marker) | ✅     | M7    | `pgr_core::cache::m7_*`, `m7_cache::*`                                              |
| `-resident` / `-resident_socket` / `pgrd` (daemon-optional; one-shot fallback)                        | ✅     | M8    | `m8_resident::*`, `pgrd_binary::*`                                                  |
| `-incremental` / `-no_incremental` / `PGR_INCREMENTAL_RECORD`                                         | ✅     | M9    | `pgr-emit::incremental` tests, `pgr-emit/tests/incremental.rs`, `m9_incremental::*` |
| `-incremental-verify` (per-link audit; daemon-served under `-resident`)                               | ✅     | M9    | `m9_incremental::incremental_verify_audits_the_patched_output`                      |
| Slack-anchored layout (`-incremental` implies slack)                                                  | ✅     | M9    | `pgr-core/tests/m9_foundations.rs`                                                  |
| `--print-record <path>` (the `.pgr-inc` inspector) — _Peregrine surface_                              | ✅     | M13   | `pgr_emit::incremental::read_summary`                                               |
| `--print-fixup-encoding <platform> <min> <sdk>` — _Peregrine surface_                                 | ✅     | M10   | `pgr_driver::fixup_encoding_report`, example `encoding_query`                       |

The incremental engine's shipped tiers, fallback ladder and gate inventory:
**[Incremental relink — shipped tiers](#incremental-relink--shipped-tiers)**.

<details><summary><b>Daemon wire carriage (protocol v16)</b></summary>

Every knob rides the resident wire faithfully — a glob never flattens, a named base never
reverts to the default. Version map:

| Wire | Carries                                                                                                             |
| ---- | ------------------------------------------------------------------------------------------------------------------- |
| v3   | Incremental fusion: previous record + output hash in, refreshed record + patch outcome out                          |
| v4   | The served `-incremental-verify` audit (verdict on the wire; failing verdicts never written)                        |
| v5   | Output residency: content-keyed resident images, `TilePatch` tile-stream replies, empty stream on untouched relinks |
| v6   | The arm64e chain-word family (tail byte)                                                                            |
| v7   | Glob export lists (kind byte + source bytes)                                                                        |
| v8   | `-pagezero_size`                                                                                                    |
| v9   | `-init_offsets`                                                                                                     |
| v10  | `-segprot`                                                                                                          |
| v11  | `-stack_size`                                                                                                       |
| v12  | `-image_base`                                                                                                       |
| v13  | `-sub_umbrella` / `-sub_library`                                                                                    |
| v14  | `-sub_client`                                                                                                       |
| v15  | `-dyld_env`                                                                                                         |
| v16  | `-alias` pairs + the `-bundle_loader` export surface                                                                |

</details>
||||||| 5b628c4
| Flag | Status | Since | Fixture / test |
|---|---|---|---|
| `-o -arch -platform_version -e -static` | ✅ | M0/M1 | `opts` unit tests |
| `-platform_version <macos\|ios\|tvos\|watchos\|visionos> <min> <sdk>` (five platforms; SDK ≥ deployment target; the per-platform chained-fixups floor picks the fixup encoding) | ✅ | M10 | `opts` unit tests + `m10_platform::*` (core/driver/verify), `platform_matrix` example |
| `-fixup_chains` / `-no_fixup_chains` | ✅ | M1 | `opts` unit tests |
| `-fixup_chains_format <offset64\|arm64e>` (chain word family: the rung-4 producer names the encoding; the default stays the M2 `DYLD_CHAINED_PTR_64_OFFSET`) | ✅ | M10 | `m10_arm64e::*` (driver parse/flag gates + e2e verify-strict), `m10_arm64e_producer::*` (core word shapes) |
| Authenticated arm64e chain words (library seam, rung 4 slice 3: `pgr_core::fixups::plan_fixups_with_auth` signs slots with a `FixupAuth` PAC triple — auth rebases carry the 32-bit runtime offset, auth binds move their whole addend to the import table; a policy under `offset64` refuses, no CLI flag this slice) | ✅ | M10 | `m10_arm64e_auth::*` + the `arm64e_auth` bench variant + the `fixup_chains_auth` example |
| `-adhoc` / `-no_adhoc` | ✅ | M1 | `e2e::no_adhoc_omits_the_signature` |
| `-headerpad` (advisory) / `-segalign` | ✅ | M1 | `opts` unit tests |
| `.tbd` inputs (v3/v4) | ✅ | M2 | `pgr-format::tbd` tests, `e2e::m2_links_printf_from_tbd` |
| `-l <name>` / `-l<name>` (searches `-L` dirs, then `/usr/lib`) | ✅ | M2 | `driver::resolve_lib` |
| `-L <dir>` | ✅ | M2 | `driver::resolve_lib` |
| `-rpath <path>` | ✅ | M2 | `e2e::m2_rpath_and_source_version_commands_land` |
| `-flat_namespace` / `-no_flat_namespace` / `-twolevel_namespace` | ✅ | M2 | `e2e::m2_flat_namespace_binds_dyld_flat` |
| `-undefined error\|dynamic_lookup` | ✅ | M2 | `e2e::m2_undefined_dynamic_lookup_binds_weak_flat` |
| `-u <symbol>` (in-image definition required) | ✅ | M2 | `driver::link_to_image` force-load check |
| `-weak_library <path>` | ✅ | M2 | `Dylib.weak` → `LC_LOAD_WEAK_DYLIB` |
| `-source_version A.B.C.D.E` | ✅ | M2 | `opts::tests::m2_flags_shape_the_config` |
| `-dylib` / `-bundle` | ✅ | M3 | `opts::tests::m3_dylib_flags_shape_the_config`, `e2e::m3_bundle_output_passes_verifier` |
| `-install_name` (dylibs; defaults to the output path) | ✅ | M3 | `opts::tests::m3_dylib_flags_shape_the_config` |
| `-current_version` / `-compatibility_version` (dylibs) | ✅ | M3 | `opts::tests::m3_dylib_flags_shape_the_config` |
| `-reexport_library <path>` | ✅ | M3 | `opts::tests::m3_reexport_library_records_the_input`, `e2e::m3_reexport_library_lands_in_the_trie` |
| `-exported_symbols_list <file>` (`*` glob subset: each star matches any, possibly empty, byte run — the ld64 wildcard form; M14) | ✅ | M3/M14 | `e2e::m3_export_filters_shape_trie_and_symtab`, `m14_export_filter::*` (core + driver), `pgr_core::export_filter` |
| `-unexported_symbols_list <file>` (`*` glob subset, same matcher; N_PEXT semantics) | ✅ | M3/M14 | `e2e::m3_export_filters_shape_trie_and_symtab` (N_PEXT semantics), `m14_export_filter::*` |
| `-mark_dead_strippable_dylib` | ✅ | M3 | `opts::tests::m3_dylib_flags_shape_the_config` |
| Mach-O dylib inputs (`.dylib` scan: install name + trie/symtab exports) | ✅ | M3 | `pgr_driver::scan_dylib`, `e2e::m3_exec_against_pgr_dylib_passes_the_pair_gate` |
| `.a` archives (ranlib `__.SYMDEF`/`/`/`__.SYMDEF_64`, BSD `#1/` + GNU `//` long names; lazy member pull) | ✅ | M5 | `pgr_format::archive` tests + proptests, `m5_archives::*` |
| `-l <name>` finds static archives (`.a` after the dylib candidates) | ✅ | M5 | `m5_flags::m5_l_search_prefers_dylibs_over_archives`, `m5_archives::m5_l_search_finds_static_archives` |
| `-all_load` | ✅ | M5 | `m5_archives::m5_all_load_pulls_every_member` |
| `-force_load <archive>` | ✅ | M5 | `m5_archives::m5_force_load_pulls_only_the_named_archive` |
| `-u <symbol>` pulls the archive member defining it | ✅ | M5 | `m5_archives::m5_u_symbol_pulls_its_member` |
| `-dead_strip` / `-no_dead_strip` (D12 mark-sweep over D1 atoms) | ✅ | M5 | `m5_deadstrip::*` (e2e) + `pgr-core/tests/m5_deadstrip.rs` (roots: entry, `-u`, dylib exports, `__mod_init_func`, `S_ATTR_NO_DEAD_STRIP`) |
| `__cstring` merging (D4; ld64-default-on) | ✅ | M5 | `m5_cstring::*` (symbol remap, section-relative pointer remap, dead-strip cooperation) |
| `-filelist <path>[,<dir>]` | ✅ | M5 | `m5_flags::m5_filelist_expands_inputs_in_order` |
| `-framework <name>` / `-F <dir>` (`.tbd`/dylib payloads) | ✅ | M5 | `m5_flags::m5_framework_search_finds_stub_dylibs` |
| `-sectcreate <seg> <sect> <file>` | ✅ | M5 | `m5_flags::m5_sectcreate_places_file_contents` |
| `-weak_framework <name>` / `-lazy_framework <name>` / `-lazy_library <path>` (repeatable; the framework forms search `-F` dirs like `-framework`, the library form is a path input; weak loads ride `LC_LOAD_WEAK_DYLIB` + weak binds, lazy loads ride `LC_LAZY_LOAD_DYLIB` — M14) | ✅ | M14 | `opts::tests::m14_lazy_weak_flags_shape_the_config`, `m14_lazy_dylibs::*` (driver), the `dylibs` bench + the `lazy_library_link` example |
| `-reexport_framework <name>` (the framework form of the M3 re-export: the flag searches `-F` dirs like `-framework` (M5), the resolved dylib loads as `LC_REEXPORT_DYLIB` and its exports join the image's export trie as REEXPORT nodes; the LC order is plain, re-export, weak, then lazy — M23) | ✅ | M23 | `m23_reexport_framework::*` (driver), the `reexport_framework_link` example |
| `-order_file` (rank-based subset: `symbol` / `object.o:symbol`) | ✅ | M11 | `m11_order_file::*` (core + driver), `pgr_core::order` |
| `-pagezero_size <n>` (the `__PAGEZERO` vmsize an executable plans with — the constant-delta base; decimal or `0x`-hex, a non-zero multiple of the 16 KiB arm64 page, the 4 GiB default unchanged; non-executable outputs refuse the knob — M15) | ✅ | M15 | `m15_pagezero::*` (core + driver), `pgr_core::pagezero` |
| `-init_offsets` / `-no_init_offsets` (the initializer form: the classic `__mod_init_func` pointer sections by default — every pre-M16 link byte-identical — or the `__TEXT,__init_offsets` u32-offset transform; below the platform's chained-fixups floor and on `-r` the named form refuses with the fix — M16; the daemon wire v9 carries the form) | ✅ | M16 | `m16_init_offsets::*` (core + driver), `pgr_core::init_offsets` |
| `-segprot <seg> <max> <init>` (the per-segment protection decision: the house pairs (`__TEXT` RX/RX, `__DATA_CONST`/`__DATA` RW/RW, `__LINKEDIT` R/R) by default — every pre-M17 link byte-identical — or the named `rwx` pairs the segment packing reads; unknown segments, twice-named segments, an init beyond its ceiling, a W+X initial mapping and `-r` refuse with the fix — M17; the daemon wire v10 carries the decisions) | ✅ | M17 | `m17_segprot::*` (core + driver), `pgr_core::segprot` |
| `-stack_size <n>` (the `LC_MAIN` stack reserve: the pre-M18 zero by default — dyld's own main-thread fallback — or the named non-zero multiple of the 16 KiB arm64 page; malformed values and non-executable outputs refuse with the fix — M18; the daemon wire v11 carries the reserve) | ✅ | M18 | `m18_stack_size::*` (core + driver), `pgr_core::stack_size` |
| `-image_base <n>` (the dylib/bundle preferred load address: the `__TEXT` vmaddr a non-executable image plans with — the M3 zero by default, every pre-M19 link byte-identical — or the named non-zero multiple of the 16 KiB arm64 page; the executable's base is `__PAGEZERO`'s job and the relocatable output carries no segments, so both refuse the knob with the fix — M19; the daemon wire v12 carries the base) | ✅ | M19 | `m19_image_base::*` (core + driver + verify), `pgr_core::image_base` |
| `-dylinker` (MH_DYLINKER outputs) | ❌ (rejected) | later | `opts::LATER_FLAGS` |
| `-sub_umbrella <name>` / `-sub_library <name>` (the dylib umbrella region: the validated members an umbrella dylib names beside its `LC_ID_DYLIB` — non-empty, NUL-free, one decision per name, flag order; executables, bundles and `-r` refuse the knob with the fix — M20; the daemon wire v13 carries the members) | ✅ | M20 | `m20_umbrella::*` (core + driver + verify), `pgr_core::umbrella`, the `umbrella` bench + the `umbrella_link` example |
| `-sub_client <name>` (the dylib client list: the validated clients an identity-block dylib names after its region — non-empty, NUL-free, one decision per name, flag order; executables, bundles and `-r` refuse the knob with the fix — M21; the daemon wire v14 carries the names) | ✅ | M21 | `m21_sub_client::*` (core + driver + verify), `pgr_core::sub_client`, the `sub_client` bench + the `sub_client_link` example |
| `-dyld_env DYLD_<var>=<value>` (the dyld environment: the validated pairs an executable exports as its `LC_DYLD_ENVIRONMENT` commands — a `DYLD_`-prefixed non-empty variable, one `=`, NUL-free, one decision per variable, flag order; dylibs, bundles and `-r` refuse the knob with the fix — M22; the daemon wire v15 carries the pairs) | ✅ | M22 | `m22_dyld_env::*` (core + driver + verify), `pgr_core::dyld_env`, the `dyld_env` bench + the `dyld_env_link` example |
| `-ObjC` (archive member class pull) | ❌ (rejected, actionable) | M6 (ObjC class/selector handling) | `opts::LATER_FLAGS` |
| `-map <path>` (the link map: segments, sections, symbols) | ✅ | M11 | `pgr_core::map`, `m11_map::*` (core + driver), the `map` bench + the `link_map` example |
=======
| Flag | Status | Since | Fixture / test |
|---|---|---|---|
| `-o -arch -platform_version -e -static` | ✅ | M0/M1 | `opts` unit tests |
| `-platform_version <macos\|ios\|tvos\|watchos\|visionos> <min> <sdk>` (five platforms; SDK ≥ deployment target; the per-platform chained-fixups floor picks the fixup encoding) | ✅ | M10 | `opts` unit tests + `m10_platform::*` (core/driver/verify), `platform_matrix` example |
| `-fixup_chains` / `-no_fixup_chains` | ✅ | M1 | `opts` unit tests |
| `-fixup_chains_format <offset64\|arm64e>` (chain word family: the rung-4 producer names the encoding; the default stays the M2 `DYLD_CHAINED_PTR_64_OFFSET`) | ✅ | M10 | `m10_arm64e::*` (driver parse/flag gates + e2e verify-strict), `m10_arm64e_producer::*` (core word shapes) |
| Authenticated arm64e chain words (library seam, rung 4 slice 3: `pgr_core::fixups::plan_fixups_with_auth` signs slots with a `FixupAuth` PAC triple — auth rebases carry the 32-bit runtime offset, auth binds move their whole addend to the import table; a policy under `offset64` refuses, no CLI flag this slice) | ✅ | M10 | `m10_arm64e_auth::*` + the `arm64e_auth` bench variant + the `fixup_chains_auth` example |
| `-adhoc` / `-no_adhoc` | ✅ | M1 | `e2e::no_adhoc_omits_the_signature` |
| `-headerpad` (advisory) / `-segalign` | ✅ | M1 | `opts` unit tests |
| `.tbd` inputs (v3/v4) | ✅ | M2 | `pgr-format::tbd` tests, `e2e::m2_links_printf_from_tbd` |
| `-l <name>` / `-l<name>` (searches `-L` dirs, then `/usr/lib`) | ✅ | M2 | `driver::resolve_lib` |
| `-L <dir>` | ✅ | M2 | `driver::resolve_lib` |
| `-rpath <path>` | ✅ | M2 | `e2e::m2_rpath_and_source_version_commands_land` |
| `-flat_namespace` / `-no_flat_namespace` / `-twolevel_namespace` | ✅ | M2 | `e2e::m2_flat_namespace_binds_dyld_flat` |
| `-undefined error\|dynamic_lookup` | ✅ | M2 | `e2e::m2_undefined_dynamic_lookup_binds_weak_flat` |
| `-u <symbol>` (in-image definition required) | ✅ | M2 | `driver::link_to_image` force-load check |
| `-weak_library <path>` | ✅ | M2 | `Dylib.weak` → `LC_LOAD_WEAK_DYLIB` |
| `-source_version A.B.C.D.E` | ✅ | M2 | `opts::tests::m2_flags_shape_the_config` |
| `-dylib` / `-bundle` | ✅ | M3 | `opts::tests::m3_dylib_flags_shape_the_config`, `e2e::m3_bundle_output_passes_verifier` |
| `-install_name` (dylibs; defaults to the output path) | ✅ | M3 | `opts::tests::m3_dylib_flags_shape_the_config` |
| `-current_version` / `-compatibility_version` (dylibs) | ✅ | M3 | `opts::tests::m3_dylib_flags_shape_the_config` |
| `-reexport_library <path>` | ✅ | M3 | `opts::tests::m3_reexport_library_records_the_input`, `e2e::m3_reexport_library_lands_in_the_trie` |
| `-exported_symbols_list <file>` (`*` glob subset: each star matches any, possibly empty, byte run — the ld64 wildcard form; M14) | ✅ | M3/M14 | `e2e::m3_export_filters_shape_trie_and_symtab`, `m14_export_filter::*` (core + driver), `pgr_core::export_filter` |
| `-unexported_symbols_list <file>` (`*` glob subset, same matcher; N_PEXT semantics) | ✅ | M3/M14 | `e2e::m3_export_filters_shape_trie_and_symtab` (N_PEXT semantics), `m14_export_filter::*` |
| `-mark_dead_strippable_dylib` | ✅ | M3 | `opts::tests::m3_dylib_flags_shape_the_config` |
| Mach-O dylib inputs (`.dylib` scan: install name + trie/symtab exports) | ✅ | M3 | `pgr_driver::scan_dylib`, `e2e::m3_exec_against_pgr_dylib_passes_the_pair_gate` |
| `.a` archives (ranlib `__.SYMDEF`/`/`/`__.SYMDEF_64`, BSD `#1/` + GNU `//` long names; lazy member pull) | ✅ | M5 | `pgr_format::archive` tests + proptests, `m5_archives::*` |
| `-l <name>` finds static archives (`.a` after the dylib candidates) | ✅ | M5 | `m5_flags::m5_l_search_prefers_dylibs_over_archives`, `m5_archives::m5_l_search_finds_static_archives` |
| `-all_load` | ✅ | M5 | `m5_archives::m5_all_load_pulls_every_member` |
| `-force_load <archive>` | ✅ | M5 | `m5_archives::m5_force_load_pulls_only_the_named_archive` |
| `-u <symbol>` pulls the archive member defining it | ✅ | M5 | `m5_archives::m5_u_symbol_pulls_its_member` |
| `-dead_strip` / `-no_dead_strip` (D12 mark-sweep over D1 atoms) | ✅ | M5 | `m5_deadstrip::*` (e2e) + `pgr-core/tests/m5_deadstrip.rs` (roots: entry, `-u`, dylib exports, `__mod_init_func`, `S_ATTR_NO_DEAD_STRIP`) |
| `__cstring` merging (D4; ld64-default-on) | ✅ | M5 | `m5_cstring::*` (symbol remap, section-relative pointer remap, dead-strip cooperation) |
| `-filelist <path>[,<dir>]` | ✅ | M5 | `m5_flags::m5_filelist_expands_inputs_in_order` |
| `-framework <name>` / `-F <dir>` (`.tbd`/dylib payloads) | ✅ | M5 | `m5_flags::m5_framework_search_finds_stub_dylibs` |
| `-sectcreate <seg> <sect> <file>` | ✅ | M5 | `m5_flags::m5_sectcreate_places_file_contents` |
| `-weak_framework <name>` / `-lazy_framework <name>` / `-lazy_library <path>` (repeatable; the framework forms search `-F` dirs like `-framework`, the library form is a path input; weak loads ride `LC_LOAD_WEAK_DYLIB` + weak binds, lazy loads ride `LC_LAZY_LOAD_DYLIB` — M14) | ✅ | M14 | `opts::tests::m14_lazy_weak_flags_shape_the_config`, `m14_lazy_dylibs::*` (driver), the `dylibs` bench + the `lazy_library_link` example |
| `-reexport_framework <name>` (the framework form of the M3 re-export: the flag searches `-F` dirs like `-framework` (M5), the resolved dylib loads as `LC_REEXPORT_DYLIB` and its exports join the image's export trie as REEXPORT nodes; the LC order is plain, re-export, weak, then lazy — M23) | ✅ | M23 | `m23_reexport_framework::*` (driver), the `reexport_framework_link` example |
| `-order_file` (rank-based subset: `symbol` / `object.o:symbol`) | ✅ | M11 | `m11_order_file::*` (core + driver), `pgr_core::order` |
| `-pagezero_size <n>` (the `__PAGEZERO` vmsize an executable plans with — the constant-delta base; decimal or `0x`-hex, a non-zero multiple of the 16 KiB arm64 page, the 4 GiB default unchanged; non-executable outputs refuse the knob — M15) | ✅ | M15 | `m15_pagezero::*` (core + driver), `pgr_core::pagezero` |
| `-init_offsets` / `-no_init_offsets` (the initializer form: the classic `__mod_init_func` pointer sections by default — every pre-M16 link byte-identical — or the `__TEXT,__init_offsets` u32-offset transform; below the platform's chained-fixups floor and on `-r` the named form refuses with the fix — M16; the daemon wire v9 carries the form) | ✅ | M16 | `m16_init_offsets::*` (core + driver), `pgr_core::init_offsets` |
| `-segprot <seg> <max> <init>` (the per-segment protection decision: the house pairs (`__TEXT` RX/RX, `__DATA_CONST`/`__DATA` RW/RW, `__LINKEDIT` R/R) by default — every pre-M17 link byte-identical — or the named `rwx` pairs the segment packing reads; unknown segments, twice-named segments, an init beyond its ceiling, a W+X initial mapping and `-r` refuse with the fix — M17; the daemon wire v10 carries the decisions) | ✅ | M17 | `m17_segprot::*` (core + driver), `pgr_core::segprot` |
| `-stack_size <n>` (the `LC_MAIN` stack reserve: the pre-M18 zero by default — dyld's own main-thread fallback — or the named non-zero multiple of the 16 KiB arm64 page; malformed values and non-executable outputs refuse with the fix — M18; the daemon wire v11 carries the reserve) | ✅ | M18 | `m18_stack_size::*` (core + driver), `pgr_core::stack_size` |
| `-image_base <n>` (the dylib/bundle preferred load address: the `__TEXT` vmaddr a non-executable image plans with — the M3 zero by default, every pre-M19 link byte-identical — or the named non-zero multiple of the 16 KiB arm64 page; the executable's base is `__PAGEZERO`'s job and the relocatable output carries no segments, so both refuse the knob with the fix — M19; the daemon wire v12 carries the base) | ✅ | M19 | `m19_image_base::*` (core + driver + verify), `pgr_core::image_base` |
| `-dylinker` (MH_DYLINKER outputs) | ❌ (rejected) | later | `opts::LATER_FLAGS` |
| `-sub_umbrella <name>` / `-sub_library <name>` (the dylib umbrella region: the validated members an umbrella dylib names beside its `LC_ID_DYLIB` — non-empty, NUL-free, one decision per name, flag order; executables, bundles and `-r` refuse the knob with the fix — M20; the daemon wire v13 carries the members) | ✅ | M20 | `m20_umbrella::*` (core + driver + verify), `pgr_core::umbrella`, the `umbrella` bench + the `umbrella_link` example |
| `-sub_client <name>` (the dylib client list: the validated clients an identity-block dylib names after its region — non-empty, NUL-free, one decision per name, flag order; executables, bundles and `-r` refuse the knob with the fix — M21; the daemon wire v14 carries the names) | ✅ | M21 | `m21_sub_client::*` (core + driver + verify), `pgr_core::sub_client`, the `sub_client` bench + the `sub_client_link` example |
| `-dyld_env DYLD_<var>=<value>` (the dyld environment: the validated pairs an executable exports as its `LC_DYLD_ENVIRONMENT` commands — a `DYLD_`-prefixed non-empty variable, one `=`, NUL-free, one decision per variable, flag order; dylibs, bundles and `-r` refuse the knob with the fix — M22; the daemon wire v15 carries the pairs) | ✅ | M22 | `m22_dyld_env::*` (core + driver + verify), `pgr_core::dyld_env`, the `dyld_env` bench + the `dyld_env_link` example |
| `-ObjC` (archive member class pull) | ❌ (rejected, actionable) | M6 (ObjC class/selector handling) | `opts::LATER_FLAGS` |
| `-map <path>` (the link map: segments, sections, symbols) | ✅ | M11 | `pgr_core::map`, `m11_map::*` (core + driver), the `map` bench + the `link_map` example |
| `-alias <alias_name> <definition_name>` (the symbol aliases: repeatable, the additional exported names an image ships beside the definitions they name — a defined-external symtab row and an export-trie node at the definition's address per decision, in flag order; an alias of a name no input defines refuses with the misspelling named, an alias name already defined or referenced refuses (one symtab row per external name), an alias keeps its definition alive under `-dead_strip`, the relocatable output refuses the knob — M24; the daemon wire v16 carries the pairs) | ✅ | M24 | `pgr_core::alias` + `m24_alias::*` (core + driver + verify), the `alias` bench + the `alias_link` example |
| `-bundle_loader <path>` (the bundle's host: the `-bundle_loader` executable a bundle binds its undefined references against — the binds ride the main-executable ordinal `0xFF` (`BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE`) in the symtab and the chained-fixups import table, no `LC_LOAD_DYLIB` for the host; the export surface is one reader (`pgr_format::loader_export_surface`: the host's trie plus its symtab's defined externals) shared by the driver's scan and the verifier's pair gate; only a bundle binds against a host — executables, dylibs and the relocatable output refuse the knob — M25; the daemon wire v16 carries the surface) | ✅ | M25 | `pgr_core::bundle_loader` + `m25_bundle_loader::*` (core + driver + verify), the `bundle_loader` bench + the `bundle_loader_link` example |
>>>>>>> ship-temp-ai

## Linking semantics

<<<<<<< HEAD
### Resolution & binding

| Feature                                                               | Status | Since | Notes / fixture                                                |
| --------------------------------------------------------------------- | ------ | ----- | -------------------------------------------------------------- |
| Two-level namespace (`(dylib, name)` resolution)                      | ✅     | M2    | first-exporting `LC_LOAD_DYLIB` wins; ordinals in `n_desc`     |
| Flat namespace (ordinal `0xFE`, no `MH_TWOLEVEL`)                     | ✅     | M2    | `e2e::m2_flat_namespace_binds_dyld_flat`                       |
| Weak imports (`N_WEAK_REF` → weak binds, `MH_BINDS_TO_WEAK`)          | ✅     | M2    | dynamic lookups and weak dylibs                                |
| GOT/stub synthesis (arm64 `adrp x16 / ldr x16 / br x16`)              | ✅     | M2    | `__DATA_CONST,__got` + `__TEXT,__stubs`, indirect symbol table |
| Indirect symbol table                                                 | ✅     | M2    | `INDIRECT_SYMBOL_LOCAL` for unnamed rebases                    |
| Bundle-host binds (ordinal `0xFF`, resolved against the host process) | ✅     | M25   | `pgr_verify::pair::verify_bundle_loader` (family-blind replay) |

### Fixups

| Feature                                                                                                          | Status | Since | Notes / fixture                                                                      |
| ---------------------------------------------------------------------------------------------------------------- | ------ | ----- | ------------------------------------------------------------------------------------ |
| Chained rebase + bind (`DYLD_CHAINED_PTR_64_OFFSET`, `IMPORT_ADDEND`)                                            | ✅     | M0/M2 | import ordinals in first-use order (spike S6: matches `ld64.lld`)                    |
| Addend split (inline `0..=255` vs import-entry `i32`)                                                            | ✅     | M2    | mirrors lld's `ChainedFixupsSection`; the auth-bind exception moves the whole addend |
| arm64e family, end to end (read walk + `__chain_starts` mirror → producer → auth words → family-aware pair gate) | ✅     | M10   | `m10_arm64e::*` · bench `arm64e` · examples `arm64e_walk`, `arm64e_pair`             |

### Exports & symbol surface

| Feature                                                                 | Status | Since  | Notes / fixture                                                                 |
| ----------------------------------------------------------------------- | ------ | ------ | ------------------------------------------------------------------------------- |
| Minimal exe export trie (`__mh_execute_header` + defined externs)       | ✅     | M2     | dyld walk verified by `pgr-verify`                                              |
| Full dylib trie + re-export nodes (`flags & 0x08`)                      | ✅     | M3     | `e2e::m3_reexport_library_lands_in_the_trie`; walker validates ordinals/strings |
| Export filters (`N_PEXT` marking, trie exclusion; glob lists since M14) | ✅     | M3/M14 | `e2e::m3_export_filters_shape_trie_and_symtab`, `m14_export_filter::*`          |
| Symbol aliases (one body, two names; one symtab row per external)       | ✅     | M24    | `pgr_core::alias`, `m24_alias::*`, the verifier's duplicate-external-name gate  |

### Output contracts

| Feature                                                                                                                                             | Status | Since  | Notes / fixture                                                                              |
| --------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ------ | -------------------------------------------------------------------------------------------- |
| Dylib/bundle base contract (default `__TEXT.vmaddr == fileoff`; `-image_base` names the base — the verifier checks the invariant, not the constant) | ✅     | M3/M19 | `pgr-verify::check_dylib_contract`, `m19_image_base::*`                                      |
| Dylib + executable pair gate (two-level binds vs the dylib's trie)                                                                                  | ✅     | M3     | `pgr_verify::pair::verify_dylib_pair`, `e2e::m3_exec_against_pgr_dylib_passes_the_pair_gate` |
| `MH_OBJECT` contract (no fixups/signature; every relocation entry bounds-checked)                                                                   | ✅     | M10    | `check_object_contract`, `object_relocs::*`                                                  |

### Size & ecosystem

| Feature                                                               | Status             | Since | Notes / fixture                                                                        |
| --------------------------------------------------------------------- | ------------------ | ----- | -------------------------------------------------------------------------------------- |
| Branch veneers/thunks for `BR26` overflow (> 128 MiB text)            | ✅                 | M6    | `pgr-core::thunks` tests, `pgr-verify::branch_range`                                   |
| `__cstring` merging (D4; ld64-default-on)                             | ✅                 | M5    | `m5_cstring::*` (symbol remap, section-relative pointer remap, dead-strip cooperation) |
| ObjC `__objc_classrefs`/`__objc_selrefs`, Swift `__swift5_*` sections | ✅ (pass-through)  | M6    | `m6_ecosystem::m6_objc_and_swift_sections_pass_through_and_verify`                     |
| LLVM bitcode (LTO) object detection                                   | ✅ (diagnose-only) | M6    | `m6_ecosystem::m6_lto_bitcode_objects_are_detected_and_diagnosed`                      |

## Incremental relink — shipped tiers

The M9 engine ships as a ladder of independently-gated tiers. **Every tier's contract is the
same**: the patched file is byte-identical to the full fused emit of the same plan, and any
refusal falls back to the full link silently (re-recording, so the cycle never stalls).

| Tier                            | What shipped                                                                                                                                                                                                                                                              | Headline gates                                                                                                                                                          |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **v1 — engine**                 | Versioned link record, span-diff patch planner over the frozen skeleton, slack anchors, clone-and-patch output, merged-hash CodeDirectory rebuild, driver flags                                                                                                           | `pgr-emit/tests/incremental.rs`, `m9_incremental::*`, `m9_foundations.rs`                                                                                               |
| **2b — per-symbol propagation** | Record v3 section-digest table (content + symbol records); the propagation gate scopes every changed span through `pgr_core::propagate::predict` (seeds' extents + reverse-index closure) or falls back                                                                   | `m9_propagate.rs` (6), tier-2b gates (3)                                                                                                                                |
| **2 — segment relayout**        | The ladder's middle rung: a slack overflow within bound holds its base, the moved suffix is patched (clone resized, re-signed at the moved boundary); an outgrown `__LINKEDIT` moves the signature boundary; record v4 digests exempt byte-identical moves                | tier-2 gates (6) · bench `segment_relayout_relink_8mib`                                                                                                                 |
| **GA hardening**                | The shrink rung (unsigned symtab/string-pool shrink: clone truncated, chunk tail re-emitted) + the seeded randomized-edit gate (xorshift64* walk over body/growth/symtab-churn/no-op edits; `PGR_RANDOMIZED_STEPS`; 2000 × 5 = the 10⁴ GA profile, CI runs sized subsets) | `linkedit_shrink_patches_through_segment_relayout`, `randomized_edit_sequences_keep_the_patch_byte_identical`, `m9_randomized.rs` · bench `linkedit_shrink_relink_8mib` |
| **2c — resolve reuse**          | The resolution snapshot (name-grouped candidates + digest-vouched winners), the shape guard (input file list + dylib export surface), seed-scoped precedence replay, equality gate vs the full resolve                                                                    | `m9_resolve_reuse.rs` (9) · bench `resolve.rs` — break-even past ~32 inputs, **−21 % at 64 files × 49 externals** (bench-recorded)                                      |
| **Record-side wiring**          | Record **v5** carries the snapshot (`record_resolution` captures, `resolve_reuse` feeds back, relinks re-capture); Pass 2 plans through recorded decisions; v1–v4 records resolve in full                                                                                 | `record_v5_carries_the_resolution_and_the_relink_renews_it`, `moved_file_list_resolves_in_full_and_still_patches`, v5 codec gates (2)                                   |
| **Resident fusion** (wire v3)   | The record + previous-output hash ride the request; the session runs the ladder in memory over warm POIs; daemon-internal fallbacks renew the record                                                                                                                      | `m9_resident_fusion.rs`, session fusion gates, bytes-twin gates · bench `fusion_relink_64_objects`                                                                      |
| **Audited fusion** (wire v4)    | The session serves `-incremental-verify`: byte-identity + strict verify, divergence healed in memory, verdict on the wire — the client never writes a failing verdict                                                                                                     | the audit-served + audited stand-down gates                                                                                                                             |
| **Output residency** (wire v5)  | Served images become content-keyed resident state; patched relinks reply with the changed 16 KiB-tile stream (`TilePatch`), untouched relinks ship nothing; the client hash-verifies its replay before the atomic write (`TileReplayRefusal` on divergence)               | tile-stream + session residency gates, `resident_output_tiles_close_the_wire_crossing` · benches `resident-fusion`, `wire-tiles`                                        |

🔶 **What remains GA-flagged**: the full 10⁴-sequence profile and the hardware runtime gates
(no stale signatures/fixups on real macOS, the < 100 ms @ 1 GiB relink target) belong to the
P0 benchmark rig — CI runs sized subsets today. The daemon never touches the filesystem in
any tier; residency is state, never a write path.

<details><summary><b>Full gate inventory (every named test/bench)</b></summary>

- **Propagation (2b)**: `pgr-core/tests/m9_propagate.rs` (6); `pgr-emit/tests/incremental.rs` tier-2b gates (3).
- **Relayout (2)**: tier-2 gates (6); bench `pgr-driver/incremental::segment_relayout_relink_8mib`.
- **GA hardening**: `linkedit_shrink_patches_through_segment_relayout`, `randomized_edit_sequences_keep_the_patch_byte_identical`, `m9_incremental::shrinking_edit_patches_through_the_relayout_tier_and_verifies`, `m9_randomized::randomized_edit_walk_survives_the_ladder_end_to_end`; bench `pgr-driver/incremental_shrink::linkedit_shrink_relink_8mib`.
- **Resolve reuse (2c + wiring)**: `pgr-core/tests/m9_resolve_reuse.rs` (9, incl. pipeline-level reuse + refused-fallback), `m9_incremental::record_v5_carries_the_resolution_and_the_relink_renews_it`, `m9_incremental::moved_file_list_resolves_in_full_and_still_patches`, v5 codec gates (2); bench `pgr-core/benches/resolve.rs` (tier-2c pair + `resolve_pipeline` pair).
- **Resident fusion (v3)**: `m9_resident_fusion.rs` (cycle survives a daemon fallback; byte-for-byte parity with the one-shot cycle; stand-down without a daemon); `pgr-daemon` session gates (capture on request, record-bearing relink patching, untouched relink, stale previous output → full link, structural edit → daemon-internal fallback + renewal); `pgr-emit` bytes-twin gates (`output_integrity_matches_the_file_gate`, `apply_patch_bytes_matches_the_file_patch`); bench `pgr-driver/resident-fusion::fusion_relink_64_objects`.
- **Audited fusion (v4)**: the audit served by the daemon; the audited stand-down to the in-process audit.
- **Output residency (v5)**: `pgr-emit/tests/incremental.rs` (`tile_stream_replays_the_patch_losslessly`, `tile_stream_carries_the_replay_hash`); `pgr-daemon` session gates (`served_images_become_resident_output`, `tiles_relink_serves_the_changed_tile_stream`, `untouched_relink_ships_an_empty_tile_stream`, `tiles_not_asked_serves_no_stream`); `pgr-driver/tests/m9_resident_fusion.rs::resident_output_tiles_close_the_wire_crossing`; benches `pgr-driver/resident-fusion` (transport asserted) + `pgr-emit/wire-tiles` (diff/replay price).

</details>

## Refused & unsupported

The published "won't support / not yet" list — every refusal is actionable and names its fix
(or its reason). Flags here fail loudly; none is silently dropped.

| Surface                                 | Status               | Why / plan                                                                 | Where                                                             |
| --------------------------------------- | -------------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `-ObjC` (archive class pull)            | ❌ rejected          | class/selector **sections** pass through (M6); archive member pull not yet | `opts::LATER_FLAGS`                                               |
| `-dylinker` (`MH_DYLINKER` outputs)     | ❌ rejected          | later milestone                                                            | `opts::LATER_FLAGS`                                               |
| TLV (`__thread_vars`, `tlv_bootstrap`)  | ❌ rejected          | reloc types parsed and rejected today                                      | M5                                                                |
| Direct page reloc to an external symbol | ❌ **deliberate**    | ld64/lld both reject or mis-link; the error points at GOT-load relocs      | M2                                                                |
| LTO object **execution**                | ❌ diagnose-only     | bitcode detected + diagnosed (M6); execution on the roadmap                | `m6_ecosystem::m6_lto_bitcode_objects_are_detected_and_diagnosed` |
| `LC_ENCRYPTION_INFO`                    | ❌ **won't support** | iOS App Store path                                                         | —                                                                 |
||||||| 5b628c4
| Feature | Status | Since | Notes |
|---|---|---|---|
| Two-level namespace (`(dylib, name)` resolution) | ✅ | M2 | first-exporting `LC_LOAD_DYLIB` wins; ordinals in `n_desc` |
| GOT/stub synthesis (arm64: `adrp x16 / ldr x16 / br x16`) | ✅ | M2 | `__DATA_CONST,__got` + `__TEXT,__stubs`, indirect symbol table |
| Chained fixups: rebase + bind (`DYLD_CHAINED_PTR_64_OFFSET`, `IMPORT_ADDEND`) | ✅ | M0/M2 | import ordinals in first-use order (spike S6: matches `ld64.lld`) |
| Chained fixups: arm64e read side (`DYLD_CHAINED_PTR_ARM64E` walk + `__chain_starts` mirror gate; the producer encodes the family since rung 4 slice 2) | ✅ | M10 | `m10_arm64e::*` + the `arm64e` bench + the `arm64e_walk` example |
| Addend split (inline 0..=255 vs import-entry `i32`) | ✅ | M2 | mirrors lld's `ChainedFixupsSection` |
| Weak imports (`N_WEAK_REF` → weak binds, `MH_BINDS_TO_WEAK`) | ✅ | M2 | dynamic lookups and weak dylibs |
| `-flat_namespace` (flat-lookup ordinal `0xFE`, no `MH_TWOLEVEL`) | ✅ | M2 | |
| Minimal export trie (`__mh_execute_header` + all defined externs) | ✅ | M2 | dyld walk verified by `pgr-verify` |
| Full export trie for dylibs + re-export nodes (`flags & 0x08`) | ✅ | M3 | `e2e::m3_reexport_library_lands_in_the_trie`; verifier walk validates ordinals/strings |
| Dylib/bundle output contract (`__TEXT.vmaddr == fileoff`, no `LC_MAIN`/dylinker) | ✅ | M3 | `pgr-verify::check_dylib_contract`, `e2e::m3_dylib_output_passes_verifier_strict` |
| Dylib + executable pair gate (two-level binds vs the dylib's trie) | ✅ | M3 | `pgr_verify::pair::verify_dylib_pair`, `e2e::m3_exec_against_pgr_dylib_passes_the_pair_gate` |
| Export filters (`N_PEXT` symtab marking, trie exclusion; M14: the lists match `*` globs — `pgr_core::export_filter`, the exact form is the M3 seam's all-exact shape) | ✅ | M3/M14 | `e2e::m3_export_filters_shape_trie_and_symtab`, `m14_export_filter::*` |
| Indirect symbol table (`__got`/`__stubs` slots) | ✅ | M2 | `INDIRECT_SYMBOL_LOCAL` for unnamed rebases |
| Direct page reloc to an external symbol | ❌ **rejected** (ld64/lld both reject or mis-link) | M2 | error message points at GOT-load relocs |
| `-dead_strip` | ✅ | M5 | D12 |
| ICF (`-icf=safe`/`-icf=all`) | ✅ | M6 | `m6_icf::*`, `pgr-core::icf` tests |
| Branch veneers/thunks for `BR26` overflow (> 128 MiB text) | ✅ | M6 | `pgr-core::thunks` tests, `pgr-verify::branch_range` |
| `-order_file` (rank-based subset; a stable sort by the order file's rank — TDD §8.4) | ✅ | M11 | `m11_order_file::*`, the `order` bench + the `order_file_link` example |
| TLV (`__thread_vars`, `tlv_bootstrap`) | ❌ | M5 | reloc types parsed and rejected today |
| `-icf=safe` / `-icf=all` / `-no_icf` (identical code folding) | ✅ | M6 | `pgr-core::icf` tests, `m6_icf::*` |
| `-syslibroot <dir>` (repeatable; ld64 pairing rule: 1 root = prefixed-only, ≥2 roots = union + original) | ✅ | M7 | `opts::effective_lib_dirs` tests, `m7_driver::m7_syslibroot_*` |
| `@<response-file>` (nested, `#` comments, quotes/escapes; opportunistic expansion — a non-existent `@path` passes through, keeping `-install_name @rpath/...` intact) | ✅ | M7 | `opts::m7_response_file_*`, `m7_driver::m7_response_file_drives_a_real_link` |
| `-demangle` / `-no_demangle` / `-no_deduplicate` (accepted no-ops: symtab names stay verbatim; dedup stays on — the arm64 default) | ✅ (no-op) | M7 | `opts::m7_build_system_noop_flags_are_accepted`, `m7_compat::m7_noops` |
| `-object_path_lto <path>` (accepted; value consumed — LTO objects stay diagnosed per M6) | ✅ (no-op) | M7 | `opts::m7_build_system_noop_flags_are_accepted` |
| `-cache_max <bytes>` / `PGR_CACHE_MAX` (LRU size bound; default 2 GiB, 0 = unbounded) | ✅ | M7 | `pgr_core::cache` LRU tests, `m7_cache::m7_cache_max_bounds_the_directory` |
| Versioned cache format v2 (format+parser revisions in frame and key, directory marker with self-heal) | ✅ | M7 | `pgr_core::cache::m7_*` tests, `m7_cache::*` |
| M7 compatibility suite (38-case agreed list, ≥ 98% gate) | ✅ | M7 | `m7_compat::m7_compat_suite_passes_the_agreed_list` |
| `-cache <dir>` / `PGR_CACHE_DIR` / `-no_cache` (Stage A POI + frozen `.tbd`) | ✅ | M6 | `pgr-core::cache` tests, `m6_cache::*` |
| `-resident` / `-resident_socket` / `pgrd` (M8 resident relink; daemon-optional, one-shot fallback) | ✅ | M8 | `m8_resident::*`, `pgrd_binary::*` |
| `-incremental` / `-no_incremental` / `PGR_INCREMENTAL_RECORD` (M9 in-place relink: record sidecar, span-diff patch plan, clone-and-patch output, merged-hash re-sign; skeleton shifts admit through the segment-relayout tier, everything else falls back to the full link) | ✅ | M9 | `pgr-emit::incremental` tests, `pgr-emit/tests/incremental.rs`, `m9_incremental::*` |
| `-incremental-verify` (M9 audit gate: byte-identity against the full emit + strict verifier pass on the patched bytes) | ✅ | M9 | `m9_incremental::incremental_verify_audits_the_patched_output` |
| Slack-anchored layout (M9 cross-link reservations; `-incremental` implies slack) | ✅ | M9 | `pgr-core/tests/m9_foundations.rs` |
| M9 GA items (incremental resolve over the propagation index, resident + incremental fusion, 10⁴-sequence randomized edit verification) | 🔶 (tiers 2a, 2b, the segment-relayout patch tier, the shrink rung, the randomized edit gate, tier-2c and the resolve's record-side wiring shipped, plus the resident fusion wire rung — the record rides the daemon wire and the ladder runs in the session) | M9 tier 2b: the per-symbol change-propagation planner — the record carries the parse's section-digest table (v3: content + symbol records), and the relink planner's **propagation gate** requires every changed content span to sit inside `pgr_core::propagate::predict`'s scope (seeds' output-section extents + the reverse-index closure of their dependents) or falls back. M9 tier 2: the **segment-relayout patch tier** executes — a section that overflows its anchor within the ladder's bound (`SlackPolicy::fits` says `SegmentRelayout` for every resized section) holds its base while everything behind it shifts, and an outgrown `__LINKEDIT` reservation moves the signature boundary; the record's output-section content digests (v4) exempt byte-identical moved sections from the propagation gate and the patch rewrites the moved suffix (clone resized, merged-hash re-sign at the moved boundary), still byte-identical to the full emit. M9 GA hardening (this milestone): the relayout tier's **shrink rung** — an unsigned relink has no signature boundary to anchor the tail, so a symtab/string-pool shrink moves the image end down; the planner admits the frozen-content shrinking shape (clone truncated, chunk tail re-emitted), any content resize beside a shrinking image stays structural. And the **randomized edit gate** ships: a seeded xorshift64* walk over body/growth/symtab-churn/no-op edits drives the engine API (`pgr-emit`, 5 edits/sequence) and the real `-incremental -incremental-verify` driver loop over files (`m9_randomized.rs`), `PGR_RANDOMIZED_STEPS` sizes the walk (CI subsets; 2000 sequences × 5 steps = the 10⁴ GA profile — run in CI-sized subsets, the profile belongs to the P0 rig like every hardware gate). M9 tier 2c (this milestone) ships the incremental *resolve*'s decision core — the resolution snapshot (the name-grouped candidate stream plus winners keyed by their digest-vouched `(file, symbol)` positions), the shape-guarded reuse plan (input file list + dylib export surface; either moving refuses and the relink resolves in full), the seed-scoped precedence replay, and the equality gate against the full resolve including a randomized edit walk (`pgr-core/tests/m9_resolve_reuse.rs`, bench `pgr-core/benches/resolve.rs`: break-even past ~32 inputs, −21% at 64 files × 49 externals). The **record-side wiring** (this milestone) ships the decision core's delivery path: the record's **v5 section** carries the resolution snapshot (`LinkConfig::record_resolution` captures it on the recording link; `LinkConfig::resolve_reuse` feeds it back on the relink, and the relink's refreshed record re-captures the fresh state), the pipeline's Pass 2 plans through the recorded decisions (`link_cached` → `plan_reuse`/`install_reused`, refusing to the full install when the shape guard or the replay refuses), v1–v4 records decode to `None` and resolve in full. The **resident fusion wire rung** (this milestone) carries the M9 halves across the daemon wire (protocol v3): the request brings the previous record and the previous output's content hash (its bytes ride the `BLOB` exchange), and the reply brings the refreshed record plus the patch outcome; the session serves the §7.3 ladder in memory — integrity gate, the anchored relink config derived from the record, the pipeline warm over its POIs, the patch plan, the in-memory patch (`pgr_emit::incremental::apply_patch_bytes`, the file path's byte-twin) — and any refusal falls back inside the daemon to its clean full link, which captures whenever asked, so the incremental cycle survives daemon fallbacks (the driver's `-resident -incremental` relink runs the daemon path first, stands down to the in-process relink, and `-incremental-verify` keeps the audited relink in-process). The **audited fusion rung** (this milestone, wire v4) completes the audit's move: the request's `audit` flag asks the session to serve `-incremental-verify` on the patched relink — byte-identity against the reference emit (the engine's audit twin, `pgr_emit::incremental::audit`, shared with the driver's in-process gate) plus the strict verifier with the deliberate-unsigned carve-out — a divergence is healed in memory from the reference emit (re-recorded, outcome adjusted), the verdict rides the reply, and the client refuses to write a failing verdict (§7.2 crash-safety unchanged; the audited relink runs warm instead of standing down to a second cold pipeline). The **§7.2 output-residency rung** (this milestone, wire v5) closes the last deferred fusion item — the session-resident output buffer: every served image is stored as resident output state (a content-addressed blob under the same ceiling and LRU as every other blob), so the next cycle's `prev_output` reference finds it and the previous output stops re-crossing the wire; a tiles-asking client (the v5 request flag) receives a patched relink as the changed 16 KiB-tile stream (`pgr_emit::incremental::TilePatch`: `diff_tiles`/`apply_tiles`, the bytes-level twin of the file patch) plus the patched image's content hash, an untouched relink ships an empty stream (nothing is rewritten), and the client hash-verifies its replay before the atomic write — a diverged replay is refused with miette help text (`TileReplayRefusal`) and stands down to the in-process relink. The daemon still never touches the filesystem: residency is state, never a write path (a crash loses the cache, the client re-uploads). | `pgr-core/tests/m9_propagate.rs` (6), `pgr-emit/tests/incremental.rs` tier-2b gates (3) + tier-2 gates (6) + `linkedit_shrink_patches_through_segment_relayout` + `randomized_edit_sequences_keep_the_patch_byte_identical` + v5 codec gates (2), `m9_incremental::shrinking_edit_patches_through_the_relayout_tier_and_verifies`, `m9_incremental::record_v5_carries_the_resolution_and_the_relink_renews_it`, `m9_incremental::moved_file_list_resolves_in_full_and_still_patches`, `m9_randomized::randomized_edit_walk_survives_the_ladder_end_to_end`, `pgr-core/tests/m9_resolve_reuse.rs` (9, incl. the pipeline-level reuse + refused-fallback gates), benches `pgr-driver/incremental::segment_relayout_relink_8mib` + `pgr-driver/incremental_shrink::linkedit_shrink_relink_8mib` + `pgr-core/benches/resolve.rs` (tier-2c pair + `resolve_pipeline` pair) + `pgr-driver/resident-fusion::fusion_relink_64_objects`; the fusion rung's gates: `m9_resident_fusion.rs` (the cycle survives a daemon fallback, byte-for-byte parity with the one-shot cycle, stand-down without a daemon, the audit served by the daemon, the audited stand-down to the in-process audit), `pgr-daemon` session fusion gates (capture on request, record-bearing relink patching, untouched relink, stale previous output → full link, structural edit → daemon-internal fallback + renewal), `pgr-emit` bytes-twin gates (`output_integrity_matches_the_file_gate`, `apply_patch_bytes_matches_the_file_patch`); the residency rung's gates: `pgr-emit/tests/incremental.rs` (`tile_stream_replays_the_patch_losslessly`, `tile_stream_carries_the_replay_hash`), `pgr-daemon` session gates (`served_images_become_resident_output`, `tiles_relink_serves_the_changed_tile_stream`, `untouched_relink_ships_an_empty_tile_stream`, `tiles_not_asked_serves_no_stream`), `pgr-driver/tests/m9_resident_fusion.rs::resident_output_tiles_close_the_wire_crossing` (the tiles cycle end to end: transport on the outcome, byte parity with the one-shot cycle, the untouched relink rewrites nothing), bench `pgr-driver/resident-fusion` (transport asserted) + `pgr-emit/wire-tiles` (the diff/replay price) |
| LLVM bitcode (LTO) object detection + diagnostic | ✅ (diagnose-only) | M6 | `m6_ecosystem::m6_lto_bitcode_objects_are_detected_and_diagnosed` |
| ObjC `__objc_classrefs`/`__objc_selrefs`, Swift `__swift5_*` section pass-through | ✅ (pass-through) | M6 | `m6_ecosystem::m6_objc_and_swift_sections_pass_through_and_verify` |
=======
| Feature | Status | Since | Notes |
|---|---|---|---|
| Two-level namespace (`(dylib, name)` resolution) | ✅ | M2 | first-exporting `LC_LOAD_DYLIB` wins; ordinals in `n_desc` |
| GOT/stub synthesis (arm64: `adrp x16 / ldr x16 / br x16`) | ✅ | M2 | `__DATA_CONST,__got` + `__TEXT,__stubs`, indirect symbol table |
| Chained fixups: rebase + bind (`DYLD_CHAINED_PTR_64_OFFSET`, `IMPORT_ADDEND`) | ✅ | M0/M2 | import ordinals in first-use order (spike S6: matches `ld64.lld`) |
| Chained fixups: arm64e read side (`DYLD_CHAINED_PTR_ARM64E` walk + `__chain_starts` mirror gate; the producer encodes the family since rung 4 slice 2) | ✅ | M10 | `m10_arm64e::*` + the `arm64e` bench + the `arm64e_walk` example |
| Addend split (inline 0..=255 vs import-entry `i32`) | ✅ | M2 | mirrors lld's `ChainedFixupsSection` |
| Weak imports (`N_WEAK_REF` → weak binds, `MH_BINDS_TO_WEAK`) | ✅ | M2 | dynamic lookups and weak dylibs |
| `-flat_namespace` (flat-lookup ordinal `0xFE`, no `MH_TWOLEVEL`) | ✅ | M2 | |
| Minimal export trie (`__mh_execute_header` + all defined externs) | ✅ | M2 | dyld walk verified by `pgr-verify` |
| Full export trie for dylibs + re-export nodes (`flags & 0x08`) | ✅ | M3 | `e2e::m3_reexport_library_lands_in_the_trie`; verifier walk validates ordinals/strings |
| Dylib/bundle output contract (`__TEXT.vmaddr == fileoff`, no `LC_MAIN`/dylinker) | ✅ | M3 | `pgr-verify::check_dylib_contract`, `e2e::m3_dylib_output_passes_verifier_strict` |
| Dylib + executable pair gate (two-level binds vs the dylib's trie) | ✅ | M3 | `pgr_verify::pair::verify_dylib_pair`, `e2e::m3_exec_against_pgr_dylib_passes_the_pair_gate` |
| Export filters (`N_PEXT` symtab marking, trie exclusion; M14: the lists match `*` globs — `pgr_core::export_filter`, the exact form is the M3 seam's all-exact shape) | ✅ | M3/M14 | `e2e::m3_export_filters_shape_trie_and_symtab`, `m14_export_filter::*` |
| Indirect symbol table (`__got`/`__stubs` slots) | ✅ | M2 | `INDIRECT_SYMBOL_LOCAL` for unnamed rebases |
| Direct page reloc to an external symbol | ❌ **rejected** (ld64/lld both reject or mis-link) | M2 | error message points at GOT-load relocs |
| `-dead_strip` | ✅ | M5 | D12 |
| ICF (`-icf=safe`/`-icf=all`) | ✅ | M6 | `m6_icf::*`, `pgr-core::icf` tests |
| Branch veneers/thunks for `BR26` overflow (> 128 MiB text) | ✅ | M6 | `pgr-core::thunks` tests, `pgr-verify::branch_range` |
| `-order_file` (rank-based subset; a stable sort by the order file's rank — TDD §8.4) | ✅ | M11 | `m11_order_file::*`, the `order` bench + the `order_file_link` example |
| TLV (`__thread_vars`, `tlv_bootstrap`) | ❌ | M5 | reloc types parsed and rejected today |
| `-icf=safe` / `-icf=all` / `-no_icf` (identical code folding) | ✅ | M6 | `pgr-core::icf` tests, `m6_icf::*` |
| `-syslibroot <dir>` (repeatable; ld64 pairing rule: 1 root = prefixed-only, ≥2 roots = union + original) | ✅ | M7 | `opts::effective_lib_dirs` tests, `m7_driver::m7_syslibroot_*` |
| `@<response-file>` (nested, `#` comments, quotes/escapes; opportunistic expansion — a non-existent `@path` passes through, keeping `-install_name @rpath/...` intact) | ✅ | M7 | `opts::m7_response_file_*`, `m7_driver::m7_response_file_drives_a_real_link` |
| `-demangle` / `-no_demangle` / `-no_deduplicate` (accepted no-ops: symtab names stay verbatim; dedup stays on — the arm64 default) | ✅ (no-op) | M7 | `opts::m7_build_system_noop_flags_are_accepted`, `m7_compat::m7_noops` |
| `-object_path_lto <path>` (accepted; value consumed — LTO objects stay diagnosed per M6) | ✅ (no-op) | M7 | `opts::m7_build_system_noop_flags_are_accepted` |
| `-cache_max <bytes>` / `PGR_CACHE_MAX` (LRU size bound; default 2 GiB, 0 = unbounded) | ✅ | M7 | `pgr_core::cache` LRU tests, `m7_cache::m7_cache_max_bounds_the_directory` |
| Versioned cache format v2 (format+parser revisions in frame and key, directory marker with self-heal) | ✅ | M7 | `pgr_core::cache::m7_*` tests, `m7_cache::*` |
| M7 compatibility suite (38-case agreed list, ≥ 98% gate) | ✅ | M7 | `m7_compat::m7_compat_suite_passes_the_agreed_list` |
| `-cache <dir>` / `PGR_CACHE_DIR` / `-no_cache` (Stage A POI + frozen `.tbd`) | ✅ | M6 | `pgr-core::cache` tests, `m6_cache::*` |
| `-resident` / `-resident_socket` / `pgrd` (M8 resident relink; daemon-optional, one-shot fallback) | ✅ | M8 | `m8_resident::*`, `pgrd_binary::*` |
| `-incremental` / `-no_incremental` / `PGR_INCREMENTAL_RECORD` (M9 in-place relink: record sidecar, span-diff patch plan, clone-and-patch output, merged-hash re-sign; skeleton shifts admit through the segment-relayout tier, everything else falls back to the full link) | ✅ | M9 | `pgr-emit::incremental` tests, `pgr-emit/tests/incremental.rs`, `m9_incremental::*` |
| `-incremental-verify` (M9 audit gate: byte-identity against the full emit + strict verifier pass on the patched bytes) | ✅ | M9 | `m9_incremental::incremental_verify_audits_the_patched_output` |
| Slack-anchored layout (M9 cross-link reservations; `-incremental` implies slack) | ✅ | M9 | `pgr-core/tests/m9_foundations.rs` |
| M9 GA items (incremental resolve over the propagation index, resident + incremental fusion, 10⁴-sequence randomized edit verification) | 🔶 (tiers 2a, 2b, the segment-relayout patch tier, the shrink rung, the randomized edit gate, tier-2c and the resolve's record-side wiring shipped, plus the resident fusion wire rung — the record rides the daemon wire and the ladder runs in the session) | M9 tier 2b: the per-symbol change-propagation planner — the record carries the parse's section-digest table (v3: content + symbol records), and the relink planner's **propagation gate** requires every changed content span to sit inside `pgr_core::propagate::predict`'s scope (seeds' output-section extents + the reverse-index closure of their dependents) or falls back. M9 tier 2: the **segment-relayout patch tier** executes — a section that overflows its anchor within the ladder's bound (`SlackPolicy::fits` says `SegmentRelayout` for every resized section) holds its base while everything behind it shifts, and an outgrown `__LINKEDIT` reservation moves the signature boundary; the record's output-section content digests (v4) exempt byte-identical moved sections from the propagation gate and the patch rewrites the moved suffix (clone resized, merged-hash re-sign at the moved boundary), still byte-identical to the full emit. M9 GA hardening (this milestone): the relayout tier's **shrink rung** — an unsigned relink has no signature boundary to anchor the tail, so a symtab/string-pool shrink moves the image end down; the planner admits the frozen-content shrinking shape (clone truncated, chunk tail re-emitted), any content resize beside a shrinking image stays structural. And the **randomized edit gate** ships: a seeded xorshift64* walk over body/growth/symtab-churn/no-op edits drives the engine API (`pgr-emit`, 5 edits/sequence) and the real `-incremental -incremental-verify` driver loop over files (`m9_randomized.rs`), `PGR_RANDOMIZED_STEPS` sizes the walk (CI subsets; 2000 sequences × 5 steps = the 10⁴ GA profile — run in CI-sized subsets, the profile belongs to the P0 rig like every hardware gate). M9 tier 2c (this milestone) ships the incremental *resolve*'s decision core — the resolution snapshot (the name-grouped candidate stream plus winners keyed by their digest-vouched `(file, symbol)` positions), the shape-guarded reuse plan (input file list + dylib export surface; either moving refuses and the relink resolves in full), the seed-scoped precedence replay, and the equality gate against the full resolve including a randomized edit walk (`pgr-core/tests/m9_resolve_reuse.rs`, bench `pgr-core/benches/resolve.rs`: break-even past ~32 inputs, −21% at 64 files × 49 externals). The **record-side wiring** (this milestone) ships the decision core's delivery path: the record's **v5 section** carries the resolution snapshot (`LinkConfig::record_resolution` captures it on the recording link; `LinkConfig::resolve_reuse` feeds it back on the relink, and the relink's refreshed record re-captures the fresh state), the pipeline's Pass 2 plans through the recorded decisions (`link_cached` → `plan_reuse`/`install_reused`, refusing to the full install when the shape guard or the replay refuses), v1–v4 records decode to `None` and resolve in full. The **resident fusion wire rung** (this milestone) carries the M9 halves across the daemon wire (protocol v3): the request brings the previous record and the previous output's content hash (its bytes ride the `BLOB` exchange), and the reply brings the refreshed record plus the patch outcome; the session serves the §7.3 ladder in memory — integrity gate, the anchored relink config derived from the record, the pipeline warm over its POIs, the patch plan, the in-memory patch (`pgr_emit::incremental::apply_patch_bytes`, the file path's byte-twin) — and any refusal falls back inside the daemon to its clean full link, which captures whenever asked, so the incremental cycle survives daemon fallbacks (the driver's `-resident -incremental` relink runs the daemon path first, stands down to the in-process relink, and `-incremental-verify` keeps the audited relink in-process). The **audited fusion rung** (this milestone, wire v4) completes the audit's move: the request's `audit` flag asks the session to serve `-incremental-verify` on the patched relink — byte-identity against the reference emit (the engine's audit twin, `pgr_emit::incremental::audit`, shared with the driver's in-process gate) plus the strict verifier with the deliberate-unsigned carve-out — a divergence is healed in memory from the reference emit (re-recorded, outcome adjusted), the verdict rides the reply, and the client refuses to write a failing verdict (§7.2 crash-safety unchanged; the audited relink runs warm instead of standing down to a second cold pipeline). The **§7.2 output-residency rung** (this milestone, wire v5) closes the last deferred fusion item — the session-resident output buffer: every served image is stored as resident output state (a content-addressed blob under the same ceiling and LRU as every other blob), so the next cycle's `prev_output` reference finds it and the previous output stops re-crossing the wire; a tiles-asking client (the v5 request flag) receives a patched relink as the changed 16 KiB-tile stream (`pgr_emit::incremental::TilePatch`: `diff_tiles`/`apply_tiles`, the bytes-level twin of the file patch) plus the patched image's content hash, an untouched relink ships an empty stream (nothing is rewritten), and the client hash-verifies its replay before the atomic write — a diverged replay is refused with miette help text (`TileReplayRefusal`) and stands down to the in-process relink. The daemon still never touches the filesystem: residency is state, never a write path (a crash loses the cache, the client re-uploads). | `pgr-core/tests/m9_propagate.rs` (6), `pgr-emit/tests/incremental.rs` tier-2b gates (3) + tier-2 gates (6) + `linkedit_shrink_patches_through_segment_relayout` + `randomized_edit_sequences_keep_the_patch_byte_identical` + v5 codec gates (2), `m9_incremental::shrinking_edit_patches_through_the_relayout_tier_and_verifies`, `m9_incremental::record_v5_carries_the_resolution_and_the_relink_renews_it`, `m9_incremental::moved_file_list_resolves_in_full_and_still_patches`, `m9_randomized::randomized_edit_walk_survives_the_ladder_end_to_end`, `pgr-core/tests/m9_resolve_reuse.rs` (9, incl. the pipeline-level reuse + refused-fallback gates), benches `pgr-driver/incremental::segment_relayout_relink_8mib` + `pgr-driver/incremental_shrink::linkedit_shrink_relink_8mib` + `pgr-core/benches/resolve.rs` (tier-2c pair + `resolve_pipeline` pair) + `pgr-driver/resident-fusion::fusion_relink_64_objects`; the fusion rung's gates: `m9_resident_fusion.rs` (the cycle survives a daemon fallback, byte-for-byte parity with the one-shot cycle, stand-down without a daemon, the audit served by the daemon, the audited stand-down to the in-process audit), `pgr-daemon` session fusion gates (capture on request, record-bearing relink patching, untouched relink, stale previous output → full link, structural edit → daemon-internal fallback + renewal), `pgr-emit` bytes-twin gates (`output_integrity_matches_the_file_gate`, `apply_patch_bytes_matches_the_file_patch`); the residency rung's gates: `pgr-emit/tests/incremental.rs` (`tile_stream_replays_the_patch_losslessly`, `tile_stream_carries_the_replay_hash`), `pgr-daemon` session gates (`served_images_become_resident_output`, `tiles_relink_serves_the_changed_tile_stream`, `untouched_relink_ships_an_empty_tile_stream`, `tiles_not_asked_serves_no_stream`), `pgr-driver/tests/m9_resident_fusion.rs::resident_output_tiles_close_the_wire_crossing` (the tiles cycle end to end: transport on the outcome, byte parity with the one-shot cycle, the untouched relink rewrites nothing), bench `pgr-driver/resident-fusion` (transport asserted) + `pgr-emit/wire-tiles` (the diff/replay price) |
| LLVM bitcode (LTO) object detection + diagnostic | ✅ (diagnose-only) | M6 | `m6_ecosystem::m6_lto_bitcode_objects_are_detected_and_diagnosed` |
| ObjC `__objc_classrefs`/`__objc_selrefs`, Swift `__swift5_*` section pass-through | ✅ (pass-through) | M6 | `m6_ecosystem::m6_objc_and_swift_sections_pass_through_and_verify` |
| Symbol aliases (`-alias`: extra exported names pointing at one body — the alias rows ride the symtab as defined externals and the trie at the definition's address; the symtab's defined-external subrange keeps one row per name, the duplicate silently shadows) | ✅ | M24 | `pgr_core::alias`, `m24_alias::*`, the verifier's duplicate-external-name gate |
| Bundle binds against the host (`-bundle_loader`: a bundle's undefined references resolve against the host executable's export surface at link time and ride the main-executable ordinal `0xFF` at load time — dyld resolves them against the process; the pair gate replays every `0xFF` bind against the host's surface, family-blind) | ✅ | M25 | `pgr_core::bundle_loader`, `m25_bundle_loader::*`, `pgr_verify::pair::verify_bundle_loader` |
>>>>>>> ship-temp-ai

## Golden cross-validation

`crates/pgr-driver/tests/e2e.rs::m2_lld_golden_binds_slot_for_slot` links the same
GOT/branch/pointer corpus with `ld64.lld` (`-fixup_chains`) and compares dyld-simulation
semantics **slot-for-slot**: every bind slot's `(lib ordinal, symbol, addend, weak)` and every
rebase slot's presence must match the golden linker's.

> [!TIP]
> The test skips with a log line when `ld64.lld` is absent. Set `PGR_LLD64=/path/to/ld64.lld`
> or install the `lld` package — CI does.

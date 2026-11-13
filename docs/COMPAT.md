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

## Linking semantics

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

## Golden cross-validation

`crates/pgr-driver/tests/e2e.rs::m2_lld_golden_binds_slot_for_slot` links the same
GOT/branch/pointer corpus with `ld64.lld` (`-fixup_chains`) and compares dyld-simulation
semantics **slot-for-slot**: every bind slot's `(lib ordinal, symbol, addend, weak)` and every
rebase slot's presence must match the golden linker's.

> [!TIP]
> The test skips with a log line when `ld64.lld` is absent. Set `PGR_LLD64=/path/to/ld64.lld`
> or install the `lld` package — CI does.

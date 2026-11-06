# ld64 Compatibility Checklist (architecture doc D13)

Status tracking for the ld64 option/feature surface. Each row lands with a
fixture-backed test; "—" means the flag is accepted but has no effect yet.
Source: architecture doc §3 row D13, tracked "as a compat checklist from M2;
each flag has a fixture".

## Load commands

| Command | Status | Since | Fixture / test |
|---|---|---|---|
| `LC_SEGMENT_64` (canonical order) | ✅ | M0 | `pgr-verify` `check_segments` |
| `LC_BUILD_VERSION` (1 tool entry, `TOOL_LD`) | ✅ | M0 | `pgr-verify` `misc::check_entry_and_version` |
| `LC_MAIN` | ✅ | M0 | `pgr-verify` entry checks |
| `LC_SYMTAB` / `LC_DYSYMTAB` | ✅ | M0/M2 | `e2e::symtab_is_in_ld64_canonical_order`, `m2_links_printf_from_tbd` (indirect ranges) |
| `LC_LOAD_DYLINKER` | ✅ | M0 | `misc::check_entry_and_version` warning when absent |
| `LC_LOAD_DYLIB` (ordinal order, versions from `.tbd`) | ✅ | M2 | `e2e::m2_links_printf_from_tbd` |
| `LC_LOAD_WEAK_DYLIB` (`-weak_library`) | ✅ | M2 | `opts::tests::m2_flags_shape_the_config` + `Dylib.weak` surface |
| `LC_DYLD_CHAINED_FIXUPS` (rebase + bind, import table) | ✅ | M0/M2 | `fixups` unit tests + `verify_integration::bind_ordinal_out_of_range_detected` |
| `LC_DYLD_EXPORTS_TRIE` (executable exports + `__mh_execute_header`) | ✅ | M2 | `e2e::m2_links_printf_from_tbd`, `export_trie` walker tests |
| `LC_FUNCTION_STARTS` | ✅ | M0 | `misc::check_function_starts` |
| `LC_DATA_IN_CODE` | ✅ (pass-through) | M0 | `misc::check_linkedit_payloads` |
| `LC_UUID` (content-derived) | ✅ | M0 | `emit::write_signature` two-pass UUID |
| `LC_CODE_SIGNATURE` (ad-hoc, arm64 mandatory) | ✅ | M0 | `signature::check_signature` |
| `LC_RPATH` (`-rpath`) | ✅ | M2 | `e2e::m2_rpath_and_source_version_commands_land` |
| `LC_SOURCE_VERSION` (`-source_version A.B.C.D.E`) | ✅ | M2 | `e2e::m2_rpath_and_source_version_commands_land` |
| `LC_ID_DYLIB` (`-install_name`, `-current_version`, `-compatibility_version`) | ✅ | M3 | `e2e::m3_dylib_output_passes_verifier_strict` |
| `LC_REEXPORT_DYLIB` (`-reexport_library`) + trie REEXPORT nodes | ✅ | M3 | `e2e::m3_reexport_library_lands_in_the_trie` |
| `MH_DYLIB` / `MH_BUNDLE` outputs (`-dylib` / `-bundle`) | ✅ | M3 | `e2e::m3_dylib_output_passes_verifier_strict`, `e2e::m3_bundle_output_passes_verifier` |
| `__init_offsets` / `-init_offsets` | ❌ | later (newer deployment targets) | — |
| `LC_ENCRYPTION_INFO` | ❌ | won't support (iOS App Store path) | — |

## Driver flags

| Flag | Status | Since | Fixture / test |
|---|---|---|---|
| `-o -arch -platform_version -e -static` | ✅ | M0/M1 | `opts` unit tests |
| `-fixup_chains` / `-no_fixup_chains` | ✅ | M1 | `opts` unit tests |
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
| `-exported_symbols_list <file>` (exact-name subset; globs are a later milestone) | ✅ | M3 | `e2e::m3_export_filters_shape_trie_and_symtab` |
| `-unexported_symbols_list <file>` (exact-name subset) | ✅ | M3 | `e2e::m3_export_filters_shape_trie_and_symtab` (N_PEXT semantics) |
| `-mark_dead_strippable_dylib` | ✅ | M3 | `opts::tests::m3_dylib_flags_shape_the_config` |
| Mach-O dylib inputs (`.dylib` scan: install name + trie/symtab exports) | ✅ | M3 | `pgr_driver::scan_dylib`, `e2e::m3_exec_against_pgr_dylib_passes_the_pair_gate` |
| `-framework` / `-weak_framework` / `-lazy_framework` / `-lazy_library` | ❌ (rejected, actionable) | later | `opts::LATER_FLAGS` |
| `-filelist` | ❌ (rejected) | M5 | `opts::LATER_FLAGS` |
| `-dylinker` (MH_DYLINKER outputs) | ❌ (rejected) | later | `opts::LATER_FLAGS` |
| `-sub_umbrella` / `-sub_library` (umbrella re-exports) | ❌ (rejected) | later | `opts::LATER_FLAGS` |
| `-dead_strip` / `-order_file` | ❌ (rejected) | M5 | `opts::LATER_FLAGS` |

## Linking semantics

| Feature | Status | Since | Notes |
|---|---|---|---|
| Two-level namespace (`(dylib, name)` resolution) | ✅ | M2 | first-exporting `LC_LOAD_DYLIB` wins; ordinals in `n_desc` |
| GOT/stub synthesis (arm64: `adrp x16 / ldr x16 / br x16`) | ✅ | M2 | `__DATA_CONST,__got` + `__TEXT,__stubs`, indirect symbol table |
| Chained fixups: rebase + bind (`DYLD_CHAINED_PTR_64_OFFSET`, `IMPORT_ADDEND`) | ✅ | M0/M2 | import ordinals in first-use order (spike S6: matches `ld64.lld`) |
| Addend split (inline 0..=255 vs import-entry `i32`) | ✅ | M2 | mirrors lld's `ChainedFixupsSection` |
| Weak imports (`N_WEAK_REF` → weak binds, `MH_BINDS_TO_WEAK`) | ✅ | M2 | dynamic lookups and weak dylibs |
| `-flat_namespace` (flat-lookup ordinal `0xFE`, no `MH_TWOLEVEL`) | ✅ | M2 | |
| Minimal export trie (`__mh_execute_header` + all defined externs) | ✅ | M2 | dyld walk verified by `pgr-verify` |
| Full export trie for dylibs + re-export nodes (`flags & 0x08`) | ✅ | M3 | `e2e::m3_reexport_library_lands_in_the_trie`; verifier walk validates ordinals/strings |
| Dylib/bundle output contract (`__TEXT.vmaddr == fileoff`, no `LC_MAIN`/dylinker) | ✅ | M3 | `pgr-verify::check_dylib_contract`, `e2e::m3_dylib_output_passes_verifier_strict` |
| Dylib + executable pair gate (two-level binds vs the dylib's trie) | ✅ | M3 | `pgr_verify::pair::verify_dylib_pair`, `e2e::m3_exec_against_pgr_dylib_passes_the_pair_gate` |
| Export filters (`N_PEXT` symtab marking, trie exclusion) | ✅ | M3 | `e2e::m3_export_filters_shape_trie_and_symtab` |
| Indirect symbol table (`__got`/`__stubs` slots) | ✅ | M2 | `INDIRECT_SYMBOL_LOCAL` for unnamed rebases |
| Direct page reloc to an external symbol | ❌ **rejected** (ld64/lld both reject or mis-link) | M2 | error message points at GOT-load relocs |
| Archive members (`-all_load`, `-ObjC`, ranlib liveness) | ❌ | M3 | rank 3/4 in resolve |
| Full export tries for dylibs, re-exports | ❌ | M3 | trie walker already handles re-export nodes (warns) |
| `-dead_strip`, `-order_file`, ICF, thunks | ❌ | M5 | D12 |
| TLV (`__thread_vars`, `tlv_bootstrap`) | ❌ | M5 | reloc types parsed and rejected today |

## Golden cross-validation

`crates/pgr-driver/tests/e2e.rs::m2_lld_golden_binds_slot_for_slot` links the
same GOT/branch/pointer corpus with `ld64.lld` (`-fixup_chains`) and
compares the dyld-simulation semantics **slot-for-slot**: every bind slot's
`(lib ordinal, symbol, addend, weak)` and every rebase slot's presence must
match the golden linker's. The test skips with a log line when `ld64.lld`
is not installed; set `PGR_LLD64=/path/to/ld64.lld` or install the `lld`
package (CI does).

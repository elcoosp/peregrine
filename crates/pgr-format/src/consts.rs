//! Mach-O constants for arm64-apple-darwin (mirrored from LLVM `MachO.h` and
//! Apple's `fixup-chains.h`).
//!
//! TDD §2.4: constants are mirrored here (not imported at runtime) so the hot
//! path stays dependency-free, and every value that exists in the vendored
//! Apple headers inside the `object` crate is cross-checked against those
//! battle-tested values in `tests/constants_crosscheck.rs`. A mismatch there
//! is a test failure, not a silent wrong constant. Constants that postdate
//! the vendored header set (`N_COLD_FUNC`) or live outside it (chained
//! fixups, code signature) are marked and validated by bit-layout unit tests
//! derived from mold's Mach-O backend and LLVM `MachO.h`.

// ---------------------------------------------------------------------------
// Header magic and CPU types
// ---------------------------------------------------------------------------

/// 64-bit little-endian Mach-O magic (`0xFEEDFACF`).
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
/// Byte-swapped 64-bit magic (big-endian files; rejected by `pgr-format`).
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;
/// CPU type for Apple Silicon.
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
/// `arm64` subtype: all Apple Silicon CPUs.
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;

// ---------------------------------------------------------------------------
// File types
// ---------------------------------------------------------------------------

/// Relocatable object file (`.o`).
pub const MH_OBJECT: u32 = 1;
/// Demand-paged executable image.
pub const MH_EXECUTE: u32 = 2;
/// Core dump.
pub const MH_CORE: u32 = 4;
/// Preloaded executable.
pub const MH_PRELOAD: u32 = 5;
/// Dynamically bound shared library (dylib).
pub const MH_DYLIB: u32 = 6;
/// Dynamic link editor (`/usr/lib/dyld`).
pub const MH_DYLINKER: u32 = 7;
/// Dynamically bound bundle (plug-in).
pub const MH_BUNDLE: u32 = 8;
/// Shared library stub for static linking only (deprecated).
pub const MH_DYLIB_STUB: u32 = 9;
/// Companion file with only debug sections (`dSYM`).
pub const MH_DSYM: u32 = 0xa;
/// Kernel extension.
pub const MH_KEXT_BUNDLE: u32 = 0xb;
/// Fileset (kernel collection / multi-file image).
pub const MH_FILESET: u32 = 0xc;

// ---------------------------------------------------------------------------
// Header flags Peregrine's verifier reasons about
// ---------------------------------------------------------------------------

/// No undefined references (safe for `-flat_namespace` reasoning).
pub const MH_NOUNDEFS: u32 = 0x1;
/// Symtab/`LC_DYLD_INFO` disagreed at dyld load time (diagnostic flag).
pub const MH_NLIST_OUTOFSYNC_WITH_DYLDINFO: u32 = 0x0400_0000;
/// Set when the object was linked with `-dyld`.
pub const MH_DYLDLINK: u32 = 0x4;
/// Two-level namespace image.
pub const MH_TWOLEVEL: u32 = 0x80;
/// Image is position independent (mandatory for arm64 executables).
pub const MH_PIE: u32 = 0x0020_0000;
/// Input sections were split at symbol boundaries
/// (drives atomization, perf doc D1).
pub const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;
/// Dylibs re-exported by this image are dead-strippable.
pub const MH_NO_REEXPORTED_DYLIBS: u32 = 0x0010_0000;
/// Dead-strippable dylib.
pub const MH_DEAD_STRIPPABLE_DYLIB: u32 = 0x0040_0000;
/// Image has thread-local variable descriptors.
pub const MH_HAS_TLV_DESCRIPTORS: u32 = 0x0080_0000;
/// Heap is not executable.
pub const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;
/// Safe for application extensions.
pub const MH_APP_EXTENSION_SAFE: u32 = 0x0200_0000;
/// Image exposing weak definitions.
pub const MH_WEAK_DEFINES: u32 = 0x8000;
/// Image binds to weak symbols.
pub const MH_BINDS_TO_WEAK: u32 = 0x1_0000;
/// Stack is executable (note: arm64 requires `MAP_JIT` instead).
pub const MH_ALLOW_STACK_EXECUTION: u32 = 0x2_0000;

// ---------------------------------------------------------------------------
// Load command opcodes
// ---------------------------------------------------------------------------

/// `LC_REQ_DYLD` flag: when set, dyld rejects unknown commands.
pub const LC_REQ_DYLD: u32 = 0x8000_0000;
/// Segment, 32-bit.
pub const LC_SEGMENT: u32 = 0x1;
/// Symbol table.
pub const LC_SYMTAB: u32 = 0x2;
/// Dynamic symbol table.
pub const LC_DYSYMTAB: u32 = 0xb;
/// Link against a dylib (two-level ordinal base).
pub const LC_LOAD_DYLIB: u32 = 0xc;
/// This image's dylib identity (`-dylib` install name).
pub const LC_ID_DYLIB: u32 = 0xd;
/// Dynamic linker path (`/usr/lib/dyld`).
pub const LC_LOAD_DYLINKER: u32 = 0xe;
/// Link against a weak dylib (`-weak_library`).
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
/// Segment, 64-bit.
pub const LC_SEGMENT_64: u32 = 0x19;
/// `LC_UUID` — content-derived for Peregrine (TDD §9).
pub const LC_UUID: u32 = 0x1b;
/// Runtime search path (`-rpath`).
pub const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
/// Code signature (`SuperBlob`), always the last bytes of the file.
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
/// Segment split info (used by caches).
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;
/// Re-export another dylib's symbols.
pub const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
/// Lazy-load a dylib.
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
/// Classic `dyld_info` rebase/bind opcode streams (pre-macOS 12 fallback).
pub const LC_DYLD_INFO: u32 = 0x22;
/// Classic `dyld_info`, dyld-required form.
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
/// Link against an upward dylib.
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
/// Minimum macOS deployment target (legacy form).
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
/// Function start table (`LC_FUNCTION_STARTS`).
pub const LC_FUNCTION_STARTS: u32 = 0x26;
/// `LC_MAIN`: entry point offset into `__TEXT`.
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
/// Data-in-code entries (`LC_DATA_IN_CODE`).
pub const LC_DATA_IN_CODE: u32 = 0x29;
/// Source version (`LC_SOURCE_VERSION`).
pub const LC_SOURCE_VERSION: u32 = 0x2a;
/// 64-bit encryption info (App Store images).
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
/// Minimum tvOS target (legacy form).
pub const LC_VERSION_MIN_TVOS: u32 = 0x2f;
/// Minimum watchOS target (legacy form).
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
/// Arbitrary metadata notes.
pub const LC_NOTE: u32 = 0x31;
/// `LC_BUILD_VERSION`: platform + minos/sdk + tool entries.
pub const LC_BUILD_VERSION: u32 = 0x32;
/// Export trie (`LC_DYLD_EXPORTS_TRIE`).
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
/// Chained fixups payload (`LC_DYLD_CHAINED_FIXUPS`).
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;
/// Fileset entry.
pub const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;

// ---------------------------------------------------------------------------
// Segment / section definitions
// ---------------------------------------------------------------------------

/// Segment with no file bytes and no protection (`__PAGEZERO`).
pub const VM_PROT_NONE: u32 = 0;
/// Read protection bit.
pub const VM_PROT_READ: u32 = 0x1;
/// Write protection bit.
pub const VM_PROT_WRITE: u32 = 0x2;
/// Execute protection bit.
pub const VM_PROT_EXECUTE: u32 = 0x4;

/// `__PAGEZERO` segment name.
pub const SEG_PAGEZERO: &[u8] = b"__PAGEZERO";
/// `__TEXT` segment name.
pub const SEG_TEXT: &[u8] = b"__TEXT";
/// `__DATA_CONST` segment name (GOT; dyld re-protects after fixups).
pub const SEG_DATA_CONST: &[u8] = b"__DATA_CONST";
/// `__DATA` segment name.
pub const SEG_DATA: &[u8] = b"__DATA";
/// `__LINKEDIT` segment name (link-edit metadata: symtab, trie, signature).
pub const SEG_LINKEDIT: &[u8] = b"__LINKEDIT";

/// Section type mask within `flags`.
pub const SECTION_TYPE_MASK: u32 = 0x0000_00ff;
/// Section attributes mask (high bits of `flags`).
pub const SECTION_ATTR_MASK: u32 = 0xffff_ff00;

/// Regular section.
pub const S_REGULAR: u32 = 0x0;
/// Zero-fill on demand (`__bss`).
pub const S_ZEROFILL: u32 = 0x1;
/// Literals: C strings, deduped by the linker (perf doc D4).
pub const S_CSTRING_LITERALS: u32 = 0x2;
/// 4-byte literals.
pub const S_4BYTE_LITERALS: u32 = 0x3;
/// 8-byte literals.
pub const S_8BYTE_LITERALS: u32 = 0x4;
/// Literal pointers.
pub const S_LITERAL_POINTERS: u32 = 0x5;
/// Non-lazy symbol pointers (`__DATA_CONST,__got`).
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
/// Lazy symbol pointers (legacy dyld-info mode only).
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
/// Symbol stubs (`__TEXT,__stubs`, 12 bytes per slot on arm64).
pub const S_SYMBOL_STUBS: u32 = 0x8;
/// Module init function pointers (`__mod_init_func`).
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
/// Module term function pointers.
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0xa;
/// Coalesced symbols.
pub const S_COALESCED: u32 = 0xb;
/// GNU-style zero-fill (obsolete).
pub const S_GB_ZEROFILL: u32 = 0xc;
/// Interposing tuples.
pub const S_INTERPOSING: u32 = 0xd;
/// 16-byte literals.
pub const S_16BYTE_LITERALS: u32 = 0xe;
/// `DTrace` `DOF` section.
pub const S_DTRACE_DOF: u32 = 0xf;
/// Lazy dylib symbol pointers.
pub const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;
/// Thread-local regular data.
pub const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
/// Thread-local zero-fill.
pub const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
/// Thread-local variable descriptors.
pub const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;
/// Thread-local variable pointers.
pub const S_THREAD_LOCAL_VARIABLE_POINTERS: u32 = 0x14;
/// Thread-local init function pointers.
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u32 = 0x15;
/// Init function offsets (newer deployment targets, perf doc D13).
pub const S_INIT_FUNC_OFFSETS: u32 = 0x16;

/// Section contains code (attribute).
pub const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
/// Section has no TOC entries (attribute).
pub const S_ATTR_NO_TOC: u32 = 0x4000_0000;
/// Strip static symbols (attribute).
pub const S_ATTR_STRIP_STATIC_SYMS: u32 = 0x2000_0000;
/// Never dead-strip contents (attribute).
pub const S_ATTR_NO_DEAD_STRIP: u32 = 0x1000_0000;
/// Live support for block pointers (attribute).
pub const S_ATTR_LIVE_SUPPORT: u32 = 0x0800_0000;
/// Self-modifying code (attribute).
pub const S_ATTR_SELF_MODIFYING_CODE: u32 = 0x0400_0000;
/// Debug section (attribute).
pub const S_ATTR_DEBUG: u32 = 0x0200_0000;
/// Section has some machine instructions (attribute).
pub const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
/// Section has external relocations (attribute).
pub const S_ATTR_EXT_RELOC: u32 = 0x0000_0200;
/// Section has local relocations (attribute).
pub const S_ATTR_LOC_RELOC: u32 = 0x0000_0100;

/// `reserved1` of a `S_SYMBOL_STUBS` section: bytes per stub entry on arm64.
pub const STUB_SIZE_ARM64: u32 = 12;

// ---------------------------------------------------------------------------
// Symbol table (`nlist_64`)
// ---------------------------------------------------------------------------

/// External bit in `n_type`.
pub const N_EXT: u8 = 0x01;
/// Symbol-type mask in `n_type`.
pub const N_TYPE: u8 = 0x0e;
/// Stable (debugger) bit in `n_type`.
pub const N_PEXT: u8 = 0x10;
/// Stabs-entry mask in `n_type`.
pub const N_STAB: u8 = 0xe0;
/// Undefined (`N_TYPE` value).
pub const N_UNDF: u8 = 0x0;
/// Absolute (`N_TYPE` value).
pub const N_ABS: u8 = 0x2;
/// Defined in a section (`N_TYPE` value).
pub const N_SECT: u8 = 0xe;
/// Prebound undefined (`N_TYPE` value).
pub const N_PBUD: u8 = 0xc;
/// Indirect (`N_TYPE` value).
pub const N_INDR: u8 = 0xa;

/// `n_desc` reference-flag mask (bits 0-2).
pub const REFERENCE_TYPE: u16 = 0x7;
/// Undefined, non-lazy reference.
pub const REFERENCE_FLAG_UNDEFINED_NON_LAZY: u16 = 0x0;
/// Undefined, lazy reference.
pub const REFERENCE_FLAG_UNDEFINED_LAZY: u16 = 0x1;
/// Defined reference.
pub const REFERENCE_FLAG_DEFINED: u16 = 0x2;
/// Private defined reference.
pub const REFERENCE_FLAG_PRIVATE_DEFINED: u16 = 0x3;
/// Private undefined, non-lazy reference.
pub const REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY: u16 = 0x4;
/// Private undefined, lazy reference.
pub const REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY: u16 = 0x5;

/// `n_desc`: never dead-strip this symbol.
pub const N_NO_DEAD_STRIP: u16 = 0x0020;
/// `n_desc`: symbol is weakly referenced.
/// `n_desc` bit: symbol is referenced dynamically (ld64 sets it on
/// `__mh_execute_header`).
pub const REFERENCED_DYNAMICALLY: u16 = 0x0010;
/// `n_desc` bit: undefined symbol is weakly referenced.
pub const N_WEAK_REF: u16 = 0x0040;
/// `n_desc`: symbol has a weak definition.
pub const N_WEAK_DEF: u16 = 0x0080;
/// `n_desc`: symbol resolves through a symbol resolver.
pub const N_SYMBOL_RESOLVER: u16 = 0x0100;
/// `n_desc`: alternate entry point.
pub const N_ALT_ENTRY: u16 = 0x0200;
/// `n_desc`: cold function (layout hint; postdates the vendored header set
/// that `object` cross-checks against — kept from Apple's current loader.h).
pub const N_COLD_FUNC: u16 = 0x0400;

/// Library ordinal: this image (bind target is the image itself).
pub const BIND_SPECIAL_DYLIB_SELF: u16 = 0x0;
/// Library ordinal: main executable (-1, only valid in dylib contexts).
pub const BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: u16 = 0xff;
/// Library ordinal: flat lookup (-2).
pub const BIND_SPECIAL_DYLIB_FLAT_LOOKUP: u16 = 0xfe;
/// Library ordinal: weak lookup (-3).
pub const BIND_SPECIAL_DYLIB_WEAK_LOOKUP: u16 = 0xfd;

/// Extracts the 8-bit library ordinal from `n_desc` (two-level namespace).
#[must_use]
pub const fn get_library_ordinal(n_desc: u16) -> u16 {
    (n_desc >> 8) & 0xff
}

/// Extracts the common-symbol alignment exponent from `n_desc`.
#[must_use]
pub const fn get_comm_align(n_desc: u16) -> u32 {
    ((n_desc >> 8) & 0x0f) as u32
}

// ---------------------------------------------------------------------------
// Indirect symbol table sentinels
// ---------------------------------------------------------------------------

/// `LC_DYSYMTAB` indirect entry: slot has a local definition.
pub const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
/// `LC_DYSYMTAB` indirect entry: slot holds an absolute value.
pub const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

// ---------------------------------------------------------------------------
// Relocation types (arm64 and generic)
// ---------------------------------------------------------------------------

/// 64-bit absolute pointer in data (becomes a chained fixup, TDD §3.5).
pub const ARM64_RELOC_UNSIGNED: u32 = 0;
/// Paired subtraction relocation: `A - B + addend`.
pub const ARM64_RELOC_SUBTRACTOR: u32 = 1;
/// `B`/`BL` 26-bit branch immediate.
pub const ARM64_RELOC_BRANCH26: u32 = 2;
/// ADRP page immediate.
pub const ARM64_RELOC_PAGE21: u32 = 3;
/// ADD/LDR/STR 12-bit page-offset immediate.
pub const ARM64_RELOC_PAGEOFF12: u32 = 4;
/// ADRP to a GOT slot.
pub const ARM64_RELOC_GOT_LOAD_PAGE21: u32 = 5;
/// LDR through a GOT slot.
pub const ARM64_RELOC_GOT_LOAD_PAGEOFF12: u32 = 6;
/// Pointer whose value is a GOT address.
pub const ARM64_RELOC_POINTER_TO_GOT: u32 = 7;
/// ADRP for a TLV descriptor access.
pub const ARM64_RELOC_TLVP_LOAD_PAGE21: u32 = 8;
/// LDR for a TLV descriptor access.
pub const ARM64_RELOC_TLVP_LOAD_PAGEOFF12: u32 = 9;
/// Paired relocation carrying the addend (arm64 page relocs).
pub const ARM64_RELOC_ADDEND: u32 = 10;
/// arm64e authenticated pointer (schema only at M0).
pub const ARM64_RELOC_AUTHENTICATED_POINTER: u32 = 11;

/// Generic 32-bit absolute.
pub const GENERIC_RELOC_VANILLA: u32 = 0;

/// `r_length` encoding: 1 byte.
pub const RELOC_LENGTH_1: u32 = 0;
/// `r_length` encoding: 2 bytes.
pub const RELOC_LENGTH_2: u32 = 1;
/// `r_length` encoding: 4 bytes.
pub const RELOC_LENGTH_4: u32 = 2;
/// `r_length` encoding: 8 bytes.
pub const RELOC_LENGTH_8: u32 = 3;
/// Bit 31 of `r_address`: relocation is a `scattered_relocation_info`.
pub const R_SCATTERED: u32 = 0x8000_0000;

// ---------------------------------------------------------------------------
// Chained fixups (`fixup-chains.h`; validated against mold's Mach-O backend
// and LLVM `MachO.h` — not present in the vendored headers `object` exposes)
// ---------------------------------------------------------------------------

/// Pointer format: rebase targets are offsets from the image base
/// (`DYLD_CHAINED_PTR_64_OFFSET`, Peregrine's default, TDD §3.6).
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
/// Pointer format: rebase targets are VM addresses (`DYLD_CHAINED_PTR_64`).
pub const DYLD_CHAINED_PTR_64: u16 = 2;
/// Pointer format: arm64e authenticated pointers (schema only at M0).
pub const DYLD_CHAINED_PTR_ARM64E: u16 = 1;

/// Import table format: `dyld_chained_import` (no addend).
pub const DYLD_CHAINED_IMPORT: u32 = 1;
/// Import table format: `dyld_chained_import_addend` (32-bit addend).
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
/// Import table format: `dyld_chained_import_addend64` (64-bit addend).
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

/// `page_start[]` entry: no chain starts on this page.
pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xffff;
/// `page_start[]` entry high bit: value is an offset to a
/// `dyld_chained_starts_offsets` multi-start table.
pub const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;
/// Mask applied to a `page_start[]` entry to recover the multi-start offset.
pub const DYLD_CHAINED_PTR_START_MULTI_MASK: u16 = 0x7fff;

// ---------------------------------------------------------------------------
// Code signature (TDD §9; all signature structures are big-endian)
// ---------------------------------------------------------------------------

/// `SuperBlob` magic (`CSMAGIC_EMBEDDED_SIGNATURE`).
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
/// `CodeDirectory` blob magic (`CSMAGIC_CODEDIRECTORY`).
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
/// Requirements blob magic (`CSMAGIC_REQUIREMENTS`).
pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade_0c01;
/// Entitlements blob magic (`CSMAGIC_ENTITLEMENTS`).
pub const CSMAGIC_ENTITLEMENTS: u32 = 0xfade_0c07;
/// Blob wrapper (CMS data) magic.
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;

/// `BlobIndex` slot: the code directory.
pub const CSSLOT_CODEDIRECTORY: u32 = 0;
/// `BlobIndex` slot: the `Info.plist` hash slot.
pub const CSSLOT_INFO: u32 = 1;
/// `BlobIndex` slot: requirements set.
pub const CSSLOT_REQUIREMENTS: u32 = 2;
/// `BlobIndex` slot: resource directory hash.
pub const CSSLOT_RESOURCEDIR: u32 = 3;
/// `BlobIndex` slot: application-specific hash.
pub const CSSLOT_APPLICATION: u32 = 4;
/// `BlobIndex` slot: entitlements `CMS` blob.
pub const CSSLOT_ENTITLEMENTS: u32 = 5;
/// `BlobIndex` slot: alternate code directories start here.
pub const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
/// Number of alternate code directory slots.
pub const CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT: u32 = 5;
/// `BlobIndex` slot: `CMS` signature wrapper.
pub const CSSLOT_SIGNATURESLOT: u32 = 0x1_0000;

/// `CodeDirectory` flags: ad-hoc signature (`CS_ADHOC`).
pub const CS_ADHOC: u32 = 0x2;
/// `CodeDirectory` flags: linker-signed image.
pub const CS_LINKER_SIGNED: u32 = 0x0002_0000;
/// `CodeDirectory` `execSegFlags`: main binary (`CS_EXECSEG_MAIN_BINARY`).
pub const CS_EXECSEG_MAIN_BINARY: u64 = 0x1;

/// `CodeDirectory` hash type: SHA-256 (the type Peregrine emits).
pub const CS_HASHTYPE_SHA256: u8 = 2;
/// `CodeDirectory` hash type: SHA-1.
pub const CS_HASHTYPE_SHA1: u8 = 1;
/// `CodeDirectory` hash type: truncated SHA-256.
pub const CS_HASHTYPE_SHA256_TRUNCATED: u8 = 3;

/// `CodeDirectory` version introducing scatter support.
pub const CS_CODEDIRECTORY_VERSION_SCATTER: u32 = 0x20100;
/// `CodeDirectory` version introducing team IDs.
pub const CS_CODEDIRECTORY_VERSION_TEAMID: u32 = 0x20200;
/// `CodeDirectory` version introducing `codeLimit64`.
pub const CS_CODEDIRECTORY_VERSION_REST: u32 = 0x20300;
/// `CodeDirectory` version introducing exec-segment fields.
pub const CS_CODEDIRECTORY_VERSION_EXECSEG: u32 = 0x20400;

/// Code signature page size: log2 of 4096 (`pageSize` field), independent of
/// the 16 KiB VM page size (TDD §3.6 invariant 5).
pub const CS_PAGE_SIZE_LOG2: u8 = 12;
/// Code signature page size in bytes.
pub const CS_PAGE_SIZE: u64 = 1 << CS_PAGE_SIZE_LOG2 as u64;
/// Size of one SHA-256 hash in bytes.
pub const CS_SHA256_LEN: u32 = 32;

// ---------------------------------------------------------------------------
// Platform / build version
// ---------------------------------------------------------------------------

/// `LC_BUILD_VERSION` platform: macOS.
pub const PLATFORM_MACOS: u32 = 1;
/// `LC_BUILD_VERSION` platform: iOS.
pub const PLATFORM_IOS: u32 = 2;
/// `LC_BUILD_VERSION` platform: tvOS.
pub const PLATFORM_TVOS: u32 = 3;
/// `LC_BUILD_VERSION` platform: watchOS.
pub const PLATFORM_WATCHOS: u32 = 4;
/// Build tool: clang.
pub const TOOL_CLANG: u32 = 1;
/// Build tool: swift.
pub const TOOL_SWIFT: u32 = 2;
/// Build tool: ld.
pub const TOOL_LD: u32 = 3;

// ---------------------------------------------------------------------------
// Platform contract constants (TDD §3.6)
// ---------------------------------------------------------------------------

/// arm64 segment page size (16 KiB; 4 KiB on `x86_64` macOS).
pub const PAGE_SIZE_16K: u64 = 0x4000;
/// 64-bit `__PAGEZERO` size (4 GiB, unmapped).
pub const PAGEZERO_SIZE_64: u64 = 0x1_0000_0000;
/// Code-signature hashing page size in bytes (4 KiB, see `CS_PAGE_SIZE`).
pub const SIGNATURE_HASH_PAGE: u64 = 4096;

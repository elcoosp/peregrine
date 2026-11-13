//! Cross-checks every mirrored Mach-O constant against the vendored Apple
//! headers inside the `object` crate (TDD §2.4: "import them or mirror in
//! `pgr-format` with compile-time assertions"). Constants that postdate that
//! header set (`N_COLD_FUNC`) or live outside it (chained fixups, code
//! signature) are validated by bit-layout unit tests in their modules and
//! deliberately not referenced here.

use object::macho as om;
use pgr_format::consts as pc;

macro_rules! check {
    ($($ours:ident),* $(,)?) => {
        $(assert_eq!(u64::from(pc::$ours), u64::from(om::$ours), stringify!($ours));)*
    };
}

#[test]
fn magic_cpu_and_filetypes_match_object() {
    check!(
        MH_MAGIC_64,
        MH_CIGAM_64,
        CPU_SUBTYPE_ARM64_ALL,
        MH_OBJECT,
        MH_EXECUTE,
        MH_CORE,
        MH_PRELOAD,
        MH_DYLIB,
        MH_DYLINKER,
        MH_BUNDLE,
        MH_DYLIB_STUB,
        MH_DSYM,
        MH_KEXT_BUNDLE,
        MH_FILESET,
    );
    // CPU_TYPE_ARM64 is composed in `object`; compare against the composition.
    assert_eq!(pc::CPU_TYPE_ARM64, om::CPU_TYPE_ARM64);
}

#[test]
fn header_flags_match_object() {
    check!(
        MH_NOUNDEFS,
        MH_DYLDLINK,
        MH_TWOLEVEL,
        MH_PIE,
        MH_SUBSECTIONS_VIA_SYMBOLS,
        MH_NO_REEXPORTED_DYLIBS,
        MH_DEAD_STRIPPABLE_DYLIB,
        MH_HAS_TLV_DESCRIPTORS,
        MH_NO_HEAP_EXECUTION,
        MH_APP_EXTENSION_SAFE,
        MH_WEAK_DEFINES,
        MH_BINDS_TO_WEAK,
        MH_ALLOW_STACK_EXECUTION,
        MH_NLIST_OUTOFSYNC_WITH_DYLDINFO,
    );
}

#[test]
fn load_command_opcodes_match_object() {
    check!(
        LC_REQ_DYLD,
        LC_SEGMENT,
        LC_SYMTAB,
        LC_DYSYMTAB,
        LC_LOAD_DYLIB,
        LC_ID_DYLIB,
        LC_LOAD_DYLINKER,
        LC_SUB_UMBRELLA,
        LC_SUB_LIBRARY,
        LC_SUB_CLIENT,
        LC_LOAD_WEAK_DYLIB,
        LC_SEGMENT_64,
        LC_UUID,
        LC_RPATH,
        LC_CODE_SIGNATURE,
        LC_SEGMENT_SPLIT_INFO,
        LC_REEXPORT_DYLIB,
        LC_LAZY_LOAD_DYLIB,
        LC_DYLD_INFO,
        LC_DYLD_INFO_ONLY,
        LC_LOAD_UPWARD_DYLIB,
        LC_VERSION_MIN_MACOSX,
        LC_FUNCTION_STARTS,
        LC_DYLD_ENVIRONMENT,
        LC_MAIN,
        LC_DATA_IN_CODE,
        LC_SOURCE_VERSION,
        LC_ENCRYPTION_INFO_64,
        LC_VERSION_MIN_TVOS,
        LC_VERSION_MIN_WATCHOS,
        LC_NOTE,
        LC_BUILD_VERSION,
        LC_DYLD_EXPORTS_TRIE,
        LC_DYLD_CHAINED_FIXUPS,
        LC_FILESET_ENTRY,
    );
}

#[test]
fn protection_and_section_types_match_object() {
    check!(
        VM_PROT_READ,
        VM_PROT_WRITE,
        VM_PROT_EXECUTE,
        S_REGULAR,
        S_ZEROFILL,
        S_CSTRING_LITERALS,
        S_4BYTE_LITERALS,
        S_8BYTE_LITERALS,
        S_LITERAL_POINTERS,
        S_NON_LAZY_SYMBOL_POINTERS,
        S_LAZY_SYMBOL_POINTERS,
        S_SYMBOL_STUBS,
        S_MOD_INIT_FUNC_POINTERS,
        S_MOD_TERM_FUNC_POINTERS,
        S_COALESCED,
        S_GB_ZEROFILL,
        S_INTERPOSING,
        S_16BYTE_LITERALS,
        S_DTRACE_DOF,
        S_LAZY_DYLIB_SYMBOL_POINTERS,
        S_THREAD_LOCAL_REGULAR,
        S_THREAD_LOCAL_ZEROFILL,
        S_THREAD_LOCAL_VARIABLES,
        S_THREAD_LOCAL_VARIABLE_POINTERS,
        S_THREAD_LOCAL_INIT_FUNCTION_POINTERS,
        S_INIT_FUNC_OFFSETS,
        S_ATTR_PURE_INSTRUCTIONS,
        S_ATTR_NO_TOC,
        S_ATTR_STRIP_STATIC_SYMS,
        S_ATTR_NO_DEAD_STRIP,
        S_ATTR_LIVE_SUPPORT,
        S_ATTR_SELF_MODIFYING_CODE,
        S_ATTR_DEBUG,
        S_ATTR_SOME_INSTRUCTIONS,
        S_ATTR_EXT_RELOC,
        S_ATTR_LOC_RELOC,
    );
}

#[test]
fn symbol_constants_match_object() {
    check!(
        N_EXT,
        N_TYPE,
        N_PEXT,
        N_STAB,
        N_UNDF,
        N_ABS,
        N_SECT,
        N_PBUD,
        N_INDR,
        REFERENCE_TYPE,
        REFERENCE_FLAG_UNDEFINED_NON_LAZY,
        REFERENCE_FLAG_UNDEFINED_LAZY,
        REFERENCE_FLAG_DEFINED,
        REFERENCE_FLAG_PRIVATE_DEFINED,
        REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY,
        REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY,
        N_NO_DEAD_STRIP,
        N_WEAK_REF,
        N_WEAK_DEF,
        N_SYMBOL_RESOLVER,
        N_ALT_ENTRY,
        INDIRECT_SYMBOL_LOCAL,
        INDIRECT_SYMBOL_ABS,
    );
    // Special ordinals are negative i8 values in the vendored headers; the
    // two-level namespace encoding keeps the low 8 bits in `n_desc`.
    assert_eq!(
        pc::BIND_SPECIAL_DYLIB_SELF,
        (om::BIND_SPECIAL_DYLIB_SELF as u16) & 0xff
    );
    assert_eq!(
        pc::BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE,
        (om::BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE as u16) & 0xff
    );
    assert_eq!(
        pc::BIND_SPECIAL_DYLIB_FLAT_LOOKUP,
        (om::BIND_SPECIAL_DYLIB_FLAT_LOOKUP as u16) & 0xff
    );
    assert_eq!(
        pc::BIND_SPECIAL_DYLIB_WEAK_LOOKUP,
        (om::BIND_SPECIAL_DYLIB_WEAK_LOOKUP as u16) & 0xff
    );
}

#[test]
fn relocation_constants_match_object() {
    check!(
        ARM64_RELOC_UNSIGNED,
        ARM64_RELOC_SUBTRACTOR,
        ARM64_RELOC_BRANCH26,
        ARM64_RELOC_PAGE21,
        ARM64_RELOC_PAGEOFF12,
        ARM64_RELOC_GOT_LOAD_PAGE21,
        ARM64_RELOC_GOT_LOAD_PAGEOFF12,
        ARM64_RELOC_POINTER_TO_GOT,
        ARM64_RELOC_TLVP_LOAD_PAGE21,
        ARM64_RELOC_TLVP_LOAD_PAGEOFF12,
        ARM64_RELOC_ADDEND,
        ARM64_RELOC_AUTHENTICATED_POINTER,
        GENERIC_RELOC_VANILLA,
    );
}

#[test]
fn platform_and_tool_constants_match_object() {
    check!(
        PLATFORM_MACOS,
        PLATFORM_IOS,
        PLATFORM_TVOS,
        PLATFORM_WATCHOS,
        TOOL_CLANG,
        TOOL_SWIFT,
        TOOL_LD,
    );
    // visionOS shipped as xrOS in the vendored Apple header set the
    // `object` crate mirrors; the platform word is the same numeric
    // value (11) — M10 rung 2 pins the equality here so a header
    // refresh that renames (or renumbers) it cannot pass silently.
    assert_eq!(
        u64::from(pc::PLATFORM_VISIONOS),
        u64::from(om::PLATFORM_XROS),
        "PLATFORM_VISIONOS must track the vendored PLATFORM_XROS"
    );
}

#[test]
fn structure_sizes_match_object_structs() {
    use core::mem::size_of;
    use object::Endianness;
    use pgr_format::{
        BuildVersionCommand, DataInCodeEntry, DylibCommand, DylinkerCommand, DysymtabCommand,
        EntryPointCommand, LinkeditDataCommand, MachHeader64, Nlist64, RelocationInfo, Section64,
        SegmentCommand64, SourceVersionCommand, SymtabCommand, UuidCommand,
    };
    assert_eq!(
        size_of::<MachHeader64>(),
        size_of::<om::MachHeader64<Endianness>>()
    );
    assert_eq!(
        size_of::<SegmentCommand64>(),
        size_of::<om::SegmentCommand64<Endianness>>()
    );
    assert_eq!(
        size_of::<Section64>(),
        size_of::<om::Section64<Endianness>>()
    );
    assert_eq!(size_of::<Nlist64>(), size_of::<om::Nlist64<Endianness>>());
    assert_eq!(
        size_of::<SymtabCommand>(),
        size_of::<om::SymtabCommand<Endianness>>()
    );
    assert_eq!(
        size_of::<DysymtabCommand>(),
        size_of::<om::DysymtabCommand<Endianness>>()
    );
    assert_eq!(
        size_of::<DylibCommand>(),
        size_of::<om::DylibCommand<Endianness>>()
    );
    assert_eq!(
        size_of::<DylinkerCommand>(),
        size_of::<om::DylinkerCommand<Endianness>>()
    );
    assert_eq!(
        size_of::<EntryPointCommand>(),
        size_of::<om::EntryPointCommand<Endianness>>()
    );
    assert_eq!(
        size_of::<BuildVersionCommand>(),
        size_of::<om::BuildVersionCommand<Endianness>>()
    );
    assert_eq!(
        size_of::<UuidCommand>(),
        size_of::<om::UuidCommand<Endianness>>()
    );
    assert_eq!(
        size_of::<LinkeditDataCommand>(),
        size_of::<om::LinkeditDataCommand<Endianness>>()
    );
    assert_eq!(
        size_of::<SourceVersionCommand>(),
        size_of::<om::SourceVersionCommand<Endianness>>()
    );
    assert_eq!(
        size_of::<DataInCodeEntry>(),
        size_of::<om::DataInCodeEntry<Endianness>>()
    );
    // `object`'s RelocationInfo is a *decoded* struct, not the raw 8-byte
    // word; assert the raw word size the format fixes instead.
    assert_eq!(size_of::<RelocationInfo>(), 8);
}

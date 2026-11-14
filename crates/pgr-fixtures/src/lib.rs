//! Deterministic Mach-O test-image builder shared across the workspace —
//! the tests, benches and consumer examples of `pgr-verify`, `pgr-format`,
//! `pgr-core`, `pgr-emit`, `pgr-driver` and `pgr-daemon`, plus the fuzz
//! corpus seeding.
//!
//! The builder implements the TDD §8 layout contract directly:
//!
//! * segments 16 KiB aligned, `vmaddr = fileoff + delta` with
//!   `delta = 0x1_0000_0000` for executables and `0` for dylibs (the
//!   M15 `set_pagezero` knob names a different executable delta),
//! * `__PAGEZERO` = 4 GiB, `__TEXT` at `0x1_0000_0000` (executables;
//!   the knob overrides),
//! * chained fixups (`DYLD_CHAINED_PTR_64_OFFSET` by default, the
//!   `DYLD_CHAINED_PTR_ARM64E` family under the pointer-format knob, M10
//!   rung 4) with the mold-style payload: header | starts-in-image |
//!   imports | name blob,
//! * ad-hoc code signature: SHA-256 over 4 KiB pages, big-endian
//!   `CodeDirectory` v0x20400, `SuperBlob` last in the file,
//! * UUID derived from page hashes (two-pass: hashes with the UUID zeroed
//!   select the UUID, then final hashes go into the `CodeDirectory`).
//!
//! Everything is deterministic: no clocks, no entropy, fixed pseudo-random
//! fill (xorshift64*). Building the same spec twice yields identical bytes —
//! the determinism test asserts it.

use pgr_format::consts::{
    CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, CS_ADHOC, CS_CODEDIRECTORY_VERSION_EXECSEG,
    CS_EXECSEG_MAIN_BINARY, CS_HASHTYPE_SHA256, CS_PAGE_SIZE_LOG2, CS_SHA256_LEN,
    CSMAGIC_CODEDIRECTORY, CSMAGIC_EMBEDDED_SIGNATURE, CSSLOT_CODEDIRECTORY, DYLD_CHAINED_IMPORT,
    DYLD_CHAINED_IMPORT_ADDEND64, DYLD_CHAINED_PTR_64_OFFSET, DYLD_CHAINED_PTR_ARM64E,
    DYLD_CHAINED_PTR_START_NONE, INDIRECT_SYMBOL_LOCAL, LC_BUILD_VERSION, LC_CODE_SIGNATURE,
    LC_DYLD_CHAINED_FIXUPS, LC_DYLD_ENVIRONMENT, LC_DYLD_EXPORTS_TRIE, LC_DYSYMTAB,
    LC_FUNCTION_STARTS, LC_ID_DYLIB, LC_LOAD_DYLIB, LC_LOAD_DYLINKER, LC_MAIN, LC_SEGMENT_64,
    LC_SUB_CLIENT, LC_SUB_LIBRARY, LC_SUB_UMBRELLA, LC_SYMTAB, LC_UUID, MH_BUNDLE, MH_DYLDLINK,
    MH_DYLIB, MH_EXECUTE, MH_MAGIC_64, MH_NO_REEXPORTED_DYLIBS, MH_NOUNDEFS, MH_PIE, MH_TWOLEVEL,
    N_EXT, N_SECT, N_UNDF, N_WEAK_REF, PAGE_SIZE_16K, PAGEZERO_SIZE_64, PLATFORM_MACOS,
    S_NON_LAZY_SYMBOL_POINTERS, SEG_PAGEZERO, SIGNATURE_HASH_PAGE, TOOL_LD, VM_PROT_EXECUTE,
    VM_PROT_NONE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_format::fixups::{
    Import, encode_arm64e_auth_bind_word, encode_arm64e_auth_rebase_word, encode_arm64e_bind_word,
    encode_arm64e_rebase_word, encode_bind_word, encode_rebase_word,
};
use sha2::{Digest, Sha256};

/// The image type to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    /// Position-independent executable (`MH_EXECUTE`).
    Exec,
    /// Dylib (`MH_DYLIB`) with an `LC_ID_DYLIB` install name.
    Dylib,
    /// Bundle (`MH_BUNDLE`; the dlopen surface, M25 pair-gate shape).
    Bundle,
}

/// A relocation entry to attach to a section (bench realism; final linked
/// images carry none).
#[derive(Debug, Clone, Copy)]
pub struct RelocSpec {
    /// Section-relative address of the relocated item.
    pub offset: u32,
    /// `r_symbolnum` (symbol index or section ordinal).
    pub symbolnum: u32,
    /// PC-relative item.
    pub pcrel: bool,
    /// `r_length` exponent (0=1 .. 3=8 bytes).
    pub length_log2: u32,
    /// `r_extern` bit.
    pub extern_: bool,
    /// `ARM64_RELOC_*` / `GENERIC_RELOC_*` type.
    pub rtype: u32,
}

/// One output section to place inside a segment.
#[derive(Debug, Clone)]
pub struct SectionSpec {
    /// Section name (e.g. `__text`).
    pub name: String,
    /// Alignment exponent.
    pub align_log2: u32,
    /// `S_*` type and attributes.
    pub flags: u32,
    /// Section bytes (little-endian image data as stored in the file).
    pub data: Vec<u8>,
    /// Relocations to attach (only with `set_keep_relocs`).
    pub relocs: Vec<RelocSpec>,
}

/// One output segment; sections are placed in order within it.
#[derive(Debug, Clone)]
pub struct SegmentSpec {
    /// Segment name (`__TEXT`, `__DATA_CONST`, `__DATA`, ...).
    pub name: String,
    /// Maximum protection (`VM_PROT_*` bits).
    pub maxprot: u32,
    /// Initial protection.
    pub initprot: u32,
    /// Sections in placement order.
    pub sections: Vec<SectionSpec>,
}

/// A symbol to place in the output symbol table.
#[derive(Debug, Clone)]
pub enum SymbolSpec {
    /// External definition, anchored to the start of the section with the
    /// given global index (index across all segments' sections).
    Defined {
        /// Symbol name (mangled form, `_` prefix included).
        name: String,
        /// Global section index the symbol anchors to.
        section_index: usize,
    },
    /// Undefined external reference bound to a dylib ordinal.
    Undefined {
        /// Symbol name.
        name: String,
        /// 1-based library ordinal into the `LC_LOAD_DYLIB` list.
        lib_ordinal: u16,
        /// Weak reference bit.
        weak: bool,
    },
}

/// What a `__got` slot contains.
#[derive(Debug, Clone, Copy)]
pub enum SlotKind {
    /// Rebase: slot holds an image offset (pointer into this image).
    Rebase {
        /// Target image offset (under `DYLD_CHAINED_PTR_64_OFFSET`).
        target: u64,
    },
    /// Bind: slot holds an import-table ordinal.
    Bind {
        /// Index into the builder's symbol list (an `Undefined` symbol).
        sym_index: usize,
        /// Inline (unsigned 8-bit) addend carried in the bind word.
        addend: u8,
    },
    /// Authenticated rebase (`DYLD_CHAINED_PTR_ARM64E` only): the 32-bit
    /// runtime offset plus the pointer-authentication triple.
    AuthRebase {
        /// VM offset from the image base (the word's 32-bit field).
        offset: u64,
        /// Pointer-auth diversity value.
        diversity: u16,
        /// Address-diversity bit.
        addr_div: bool,
        /// PAC key (0 IA, 1 IB, 2 DA, 3 DB).
        key: u8,
    },
    /// Authenticated bind (`DYLD_CHAINED_PTR_ARM64E` only): the import
    /// ordinal plus the pointer-authentication triple.
    AuthBind {
        /// Index into the builder's symbol list (an `Undefined` symbol).
        sym_index: usize,
        /// Pointer-auth diversity value.
        diversity: u16,
        /// Address-diversity bit.
        addr_div: bool,
        /// PAC key (0 IA, 1 IB, 2 DA, 3 DB).
        key: u8,
    },
}

/// Chained-fixups import table format to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportsFormat {
    /// `DYLD_CHAINED_IMPORT` (no table addend; inline addend in the word).
    Plain,
    /// `DYLD_CHAINED_IMPORT_ADDEND64` (64-bit table addends, inline 0).
    Addend64,
}

/// The chain-word pointer format a fixture's fixup payload carries (M10
/// rung 4, slice 1: the arm64e read side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerFormatKind {
    /// `DYLD_CHAINED_PTR_64_OFFSET` — the historical default (4-byte
    /// strides, image-offset rebase targets, no auth words).
    Offset64,
    /// `DYLD_CHAINED_PTR_ARM64E` — 8-byte strides, VM-address unauth
    /// rebase targets, 32-bit auth runtime offsets, authenticated words.
    Arm64e,
}

impl PointerFormatKind {
    /// The `dyld_chained_starts_in_segment.pointer_format` value.
    #[must_use]
    pub const fn value(self) -> u16 {
        match self {
            Self::Offset64 => DYLD_CHAINED_PTR_64_OFFSET,
            Self::Arm64e => DYLD_CHAINED_PTR_ARM64E,
        }
    }
}

/// Anything the builder refuses to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildError(pub String);

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for BuildError {}

impl From<pgr_format::FormatError> for BuildError {
    fn from(e: pgr_format::FormatError) -> Self {
        BuildError(e.to_string())
    }
}

/// Recorded layout facts.
#[derive(Debug, Clone)]
pub struct LayoutMap {
    /// One entry per placed section, in placement order.
    pub sections: Vec<SectionInfo>,
    /// `__got` slot VM addresses in slot order.
    pub got_slot_addrs: Vec<u64>,
    /// Import table as encoded into the fixup payload.
    pub imports: Vec<Import>,
    /// Output symtab index of each symbol added via `add_symbol`.
    pub symbol_indices: Vec<u32>,
    /// Entry offset into `__TEXT` (`LC_MAIN.entryoff`).
    pub entryoff: u64,
    /// File offset where the code signature starts (`codeLimit`).
    pub sig_off: u64,
    /// The 16 UUID bytes embedded in `LC_UUID`.
    pub uuid: [u8; 16],
    /// `__TEXT` vmsize (used as `execSegLimit`).
    pub text_vmsize: u64,
    /// Import table format used (`DYLD_CHAINED_IMPORT*`).
    pub imports_format: u32,
}

/// Placement facts for one section.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    /// Section name.
    pub name: String,
    /// Parent segment name.
    pub segment: String,
    /// File offset of the section data.
    pub fileoff: u64,
    /// Virtual address of the section data.
    pub addr: u64,
    /// Size in bytes.
    pub size: u64,
}

/// Result of a build: bytes plus the layout facts tests assert against.
#[derive(Debug, Clone)]
pub struct Image {
    /// The complete Mach-O file bytes.
    pub bytes: Vec<u8>,
    /// Layout information extracted during the build.
    pub map: LayoutMap,
}

/// A builder for deterministic executable/dylib fixtures.
#[derive(Debug, Clone)]
pub struct ImageBuilder {
    kind: ImageKind,
    install_name: String,
    segments: Vec<SegmentSpec>,
    dylibs: Vec<String>,
    symbols: Vec<SymbolSpec>,
    got: Vec<SlotKind>,
    entryoff: u64,
    ident: String,
    imports_format: ImportsFormat,
    keep_relocs: bool,
    build_version: Option<(u32, u32, u32)>,
    pointer_format: PointerFormatKind,
    /// M15: the `__PAGEZERO` vmsize override (`None` = the 4 GiB
    /// Mach-O arm64 constant). Executables only.
    pagezero: Option<u64>,
    /// M19: the dylib/bundle preferred load address (the non-executable
    /// constant-delta delta).
    image_base: Option<u64>,
    /// M29: the header-region floor (the `-headerpad` reservation the
    /// `__TEXT` packing grows to before the first section). `None`
    /// keeps the pre-M29 natural region.
    header_pad: Option<u64>,
    /// M17: the per-segment protection overrides (`(name, maxprot,
    /// initprot)`; unnamed segments keep the house table). Written
    /// during assembly, so the ad-hoc signature is computed over the
    /// final bytes and strict verification runs with the hash recompute
    /// on. The values are the knob's — a hand-broken pair is the
    /// verifier's finding to name.
    seg_prots: Vec<(String, u32, u32)>,
    /// M18: the `LC_MAIN.stacksize` override (`None` = the pre-M18 zero
    /// — dyld's own main-thread default). Executables only; written
    /// during assembly, so the ad-hoc signature is computed over the
    /// final bytes and strict verification runs with the hash recompute
    /// on. The value is the knob's — a misaligned reserve is the
    /// verifier's finding to name.
    stack_size: Option<u64>,
    /// M20: the umbrella region members in flag order — `true` rides
    /// `LC_SUB_UMBRELLA`, `false` rides `LC_SUB_LIBRARY`. Written during
    /// assembly, so the ad-hoc signature is computed over the final
    /// bytes and strict verification runs with the hash recompute on.
    /// The values are the knob's — a member off a dylib, an empty name
    /// or a duplicate is the verifier's finding to name.
    sub_cmds: Vec<(bool, String)>,
    /// M21: the sub-client names in flag order — each rides
    /// `LC_SUB_CLIENT`. Written during assembly, so the ad-hoc
    /// signature is computed over the final bytes and strict
    /// verification runs with the hash recompute on. The values are the
    /// knob's — a client command off a dylib, an empty name or a
    /// duplicate is the verifier's finding to name.
    sub_clients: Vec<String>,
    /// M22: the dyld-environment pairs in flag order — each rides
    /// `LC_DYLD_ENVIRONMENT`. Written during assembly, so the ad-hoc
    /// signature is computed over the final bytes and strict
    /// verification runs with the hash recompute on. The values are the
    /// knob's — a command off an executable, a non-`DYLD_` variable or
    /// a duplicate is the verifier's finding to name.
    dyld_envs: Vec<String>,
    /// M26: the `LC_LOAD_DYLINKER` path the executable fixture names
    /// (the `-dylinker` knob). The default stays the hard-coded
    /// `/usr/lib/dyld` every pre-M26 fixture built with; an override is
    /// written during assembly, so the ad-hoc signature is computed
    /// over the final bytes. The value is the knob's — a relative path
    /// is the verifier's finding to name (the broken-shape gates build
    /// it on purpose).
    loader_path: Option<String>,
    /// M27: the executable fixture's `MH_PIE` bit. The default stays
    /// set (every pre-M27 fixture built PIE); dropping it is the
    /// `-no_pie` knob's image shape — the strict verifier accepts both
    /// (the flag is a decision, not a defect).
    pie: bool,
}

impl ImageBuilder {
    /// Starts an executable fixture; add `__TEXT` (and optionally
    /// `__DATA_CONST`/`__DATA`) via `add_segment`.
    #[must_use]
    pub fn executable(ident: &str) -> Self {
        Self {
            kind: ImageKind::Exec,
            install_name: String::new(),
            segments: Vec::new(),
            dylibs: Vec::new(),
            symbols: Vec::new(),
            got: Vec::new(),
            entryoff: 0,
            ident: ident.to_string(),
            imports_format: ImportsFormat::Plain,
            keep_relocs: false,
            build_version: None,
            pointer_format: PointerFormatKind::Offset64,
            pagezero: None,
            image_base: None,
            header_pad: None,
            seg_prots: Vec::new(),
            stack_size: None,
            sub_cmds: Vec::new(),
            sub_clients: Vec::new(),
            dyld_envs: Vec::new(),
            loader_path: None,
            pie: true,
        }
    }

    /// Starts a bundle fixture (`MH_BUNDLE`; M25's pair-gate shape —
    /// the same `__TEXT`-first build as a dylib, no `LC_ID_DYLIB`).
    #[must_use]
    pub fn bundle(ident: &str) -> Self {
        Self {
            kind: ImageKind::Bundle,
            install_name: String::new(),
            segments: Vec::new(),
            dylibs: Vec::new(),
            symbols: Vec::new(),
            got: Vec::new(),
            entryoff: 0,
            ident: ident.to_string(),
            imports_format: ImportsFormat::Plain,
            keep_relocs: false,
            build_version: None,
            pointer_format: PointerFormatKind::Offset64,
            pagezero: None,
            image_base: None,
            header_pad: None,
            seg_prots: Vec::new(),
            stack_size: None,
            sub_cmds: Vec::new(),
            sub_clients: Vec::new(),
            dyld_envs: Vec::new(),
            loader_path: None,
            pie: true,
        }
    }

    /// Starts a dylib fixture with the given install name.
    #[must_use]
    pub fn dylib(install_name: &str, ident: &str) -> Self {
        Self {
            kind: ImageKind::Dylib,
            install_name: install_name.to_string(),
            segments: Vec::new(),
            dylibs: Vec::new(),
            symbols: Vec::new(),
            got: Vec::new(),
            entryoff: 0,
            ident: ident.to_string(),
            imports_format: ImportsFormat::Plain,
            keep_relocs: false,
            build_version: None,
            pointer_format: PointerFormatKind::Offset64,
            pagezero: None,
            image_base: None,
            header_pad: None,
            seg_prots: Vec::new(),
            stack_size: None,
            sub_cmds: Vec::new(),
            sub_clients: Vec::new(),
            dyld_envs: Vec::new(),
            loader_path: None,
            pie: true,
        }
    }

    /// Appends a segment (`__TEXT` first; others in canonical order).
    pub fn add_segment(&mut self, seg: SegmentSpec) {
        self.segments.push(seg);
    }

    /// Registers a dependent dylib (`LC_LOAD_DYLIB`), returning its 1-based
    /// two-level ordinal.
    pub fn add_dylib(&mut self, install_name: &str) -> u16 {
        self.dylibs.push(install_name.to_string());
        self.dylibs.len() as u16
    }

    /// Adds a symbol, returning its builder index (map to the output symbol
    /// table through `LayoutMap::symbol_indices`).
    pub fn add_symbol(&mut self, sym: SymbolSpec) -> usize {
        self.symbols.push(sym);
        self.symbols.len() - 1
    }

    /// Sets the `__got` slot contents (a `__got` section is synthesized in
    /// the `__DATA_CONST` segment, which must exist).
    pub fn set_got(&mut self, slots: Vec<SlotKind>) {
        self.got = slots;
    }

    /// Sets the entry offset into `__TEXT` (executables only).
    pub fn set_entry(&mut self, entryoff: u64) {
        self.entryoff = entryoff;
    }

    /// Selects the import table format (default: `Plain`).
    pub fn set_imports_format(&mut self, fmt: ImportsFormat) {
        self.imports_format = fmt;
    }

    /// Keeps per-section relocation tables in the file (bench corpus
    /// realism; real linked executables carry none).
    pub fn set_keep_relocs(&mut self, keep: bool) {
        self.keep_relocs = keep;
    }

    /// Pins the `LC_BUILD_VERSION` payload (platform, minos, sdk) — the
    /// M10 rung 3 platform knob. The default stays the builder's
    /// historical macOS 12.0.0 / SDK 14.4.0 row; an override is written
    /// during assembly, so the ad-hoc signature is computed over the
    /// final bytes and strict verification runs with the hash recompute
    /// on (no post-build repatching).
    pub fn set_build_version(&mut self, platform: u32, minos: u32, sdk: u32) {
        self.build_version = Some((platform, minos, sdk));
    }

    /// Sets the executable's `__PAGEZERO` vmsize (the image base) — the
    /// M15 `-pagezero_size` knob. The default stays the 4 GiB Mach-O
    /// arm64 constant every pre-M15 fixture built with; an override is
    /// written during assembly (the `vmaddr = fileoff + delta` delta,
    /// the segment command and every rebase word ride it), so the
    /// ad-hoc signature is computed over the final bytes and strict
    /// verification runs with the hash recompute on.
    ///
    /// # Panics
    /// Never — a misaligned override is the verifier's finding to name
    /// (the broken-shape gates build it on purpose).
    pub fn set_pagezero(&mut self, vmsize: u64) {
        self.pagezero = Some(vmsize);
    }

    /// Sets the executable's `LC_LOAD_DYLINKER` path (the M26
    /// `-dylinker` knob). The default stays the hard-coded
    /// `/usr/lib/dyld` every pre-M26 fixture built with; an override is
    /// written during assembly (the command size rides the named
    /// path's length), so the ad-hoc signature is computed over the
    /// final bytes and strict verification runs with the hash
    /// recompute on. The value is the knob's — a relative path is the
    /// verifier's finding to name (the broken-shape gates build it on
    /// purpose).
    pub fn set_loader_path(&mut self, path: &str) {
        self.loader_path = Some(path.to_string());
    }

    /// Sets the executable's `MH_PIE` header bit (the M27 `-no_pie`
    /// knob). The default stays set — every pre-M27 fixture built PIE;
    /// a dropped bit is the decision's image shape, and the strict
    /// verifier accepts both (the strict-hash recompute rides the
    /// assembled bytes either way).
    pub fn set_pie(&mut self, pie: bool) {
        self.pie = pie;
    }

    /// Sets the dylib/bundle preferred load address (the image base) —
    /// the M19 `-image_base` knob. The default stays the M3 zero (the
    /// `__TEXT.vmaddr == fileoff` contract every pre-M19 fixture built
    /// with); an override is written during assembly (the
    /// `vmaddr = fileoff + delta` delta, the segment command and every
    /// rebase word ride it), so the ad-hoc signature is computed over
    /// the final bytes and strict verification runs with the hash
    /// recompute on.
    ///
    /// # Panics
    /// Never — a misaligned override is the verifier's finding to name
    /// (the broken-shape gates build it on purpose).
    pub fn set_image_base(&mut self, vmaddr: u64) {
        self.image_base = Some(vmaddr);
    }

    /// Reserves the header region the M29 `-headerpad` knob names: the
    /// fixture's `__TEXT` packing grows the reserved region to at least
    /// the named floor before the first section (the same decision the
    /// layout plans). `None` keeps the pre-M29 natural region — every
    /// earlier fixture built byte-identically.
    pub fn set_header_pad(&mut self, pad: Option<u64>) {
        self.header_pad = pad;
    }

    /// Overrides one segment's `(maxprot, initprot)` pair — the M17
    /// `-segprot` knob. Unnamed segments keep the house table; an
    /// override is written during assembly (the `LC_SEGMENT_64` fields
    /// and the ad-hoc signature ride it), so strict verification runs
    /// with the hash recompute on.
    ///
    /// # Panics
    /// Never — a hand-broken pair (an init beyond its ceiling, a W+X
    /// mapping, a protected `__PAGEZERO`) is the verifier's finding to
    /// name (the broken-shape gates build it on purpose).
    pub fn set_segment_prot(&mut self, name: &str, maxprot: u32, initprot: u32) {
        self.seg_prots.push((name.to_string(), maxprot, initprot));
    }

    /// Sets the executable's `LC_MAIN.stacksize` reserve — the M18
    /// `-stack_size` knob. The default stays the pre-M18 zero (dyld's
    /// own main-thread default); an override is written during assembly
    /// (the load command and the ad-hoc signature ride it), so strict
    /// verification runs with the hash recompute on.
    ///
    /// # Panics
    /// Never — a misaligned reserve is the verifier's finding to name
    /// (the broken-shape gates build it on purpose).
    pub fn set_stack_size(&mut self, bytes: u64) {
        self.stack_size = Some(bytes);
    }

    /// Names a sub-umbrella member of the umbrella region — the M20
    /// `-sub_umbrella` knob. Members are written during assembly (the
    /// region commands and the ad-hoc signature ride them), so strict
    /// verification runs with the hash recompute on.
    ///
    /// # Panics
    /// Never — a member the region cannot carry (a sub command off a
    /// dylib, an empty name, a duplicate) is the verifier's finding to
    /// name (the broken-shape gates build them on purpose).
    pub fn add_sub_umbrella(&mut self, name: &str) {
        self.sub_cmds.push((true, name.to_string()));
    }

    /// Names a sub-library member of the umbrella region — the M20
    /// `-sub_library` knob. Members are written during assembly (the
    /// region commands and the ad-hoc signature ride them), so strict
    /// verification runs with the hash recompute on.
    ///
    /// # Panics
    /// Never — a member the region cannot carry is the verifier's
    /// finding to name (the broken-shape gates build them on purpose).
    pub fn add_sub_library(&mut self, name: &str) {
        self.sub_cmds.push((false, name.to_string()));
    }

    /// Names a client of the identity block — the M21 `-sub_client`
    /// knob. Clients are written during assembly (the client commands
    /// and the ad-hoc signature ride them), so strict verification runs
    /// with the hash recompute on.
    ///
    /// # Panics
    /// Never — a client command the identity block cannot carry (off a
    /// dylib, an empty name, a duplicate) is the verifier's finding to
    /// name (the broken-shape gates build them on purpose).
    pub fn add_sub_client(&mut self, name: &str) {
        self.sub_clients.push(name.to_string());
    }

    /// Exports one dyld-environment pair — the M22 `-dyld_env` knob.
    /// Pairs are written during assembly (the environment commands and
    /// the ad-hoc signature ride them), so strict verification runs
    /// with the hash recompute on.
    ///
    /// # Panics
    /// Never — a command the loader cannot honor (off an executable, a
    /// non-`DYLD_` variable, an empty variable, a duplicate) is the
    /// verifier's finding to name (the broken-shape gates build them
    /// on purpose).
    pub fn add_dyld_env(&mut self, pair: &str) {
        self.dyld_envs.push(pair.to_string());
    }

    /// Selects the chain-word pointer format (default: `Offset64`). The
    /// M10 rung-4 knob: `Arm64e` encodes the `DYLD_CHAINED_PTR_ARM64E`
    /// family — unauth rebase words carry VM-address targets
    /// (`target + delta`), auth slots ride [`SlotKind::AuthRebase`] and
    /// [`SlotKind::AuthBind`], and strides count 8-byte units.
    pub fn set_pointer_format(&mut self, fmt: PointerFormatKind) {
        self.pointer_format = fmt;
    }

    fn prot(seg_name: &str) -> (u32, u32) {
        match seg_name {
            "__TEXT" => (
                VM_PROT_READ | VM_PROT_EXECUTE,
                VM_PROT_READ | VM_PROT_EXECUTE,
            ),
            "__DATA_CONST" | "__DATA" => {
                (VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE)
            }
            _ => (VM_PROT_READ, VM_PROT_READ),
        }
    }

    /// Assembles the image.
    ///
    /// # Errors
    /// [`BuildError`] on a structurally invalid spec (no leading `__TEXT`
    /// segment, a `__TEXT` after the first segment, an entry outside
    /// `__TEXT`, imports without a dylib list, or a GOT slot referencing a
    /// defined symbol).
    ///
    /// # Panics
    /// Never on well-formed builders; the deterministic filler and the
    /// digest math allocate but do not panic. A symbol referencing a
    /// section index beyond the segments aborts the build with a
    /// [`BuildError`], not a panic.
    pub fn build(&self) -> Result<Image, BuildError> {
        let exec = self.kind == ImageKind::Exec;
        let bundle = self.kind == ImageKind::Bundle;
        if self.segments.is_empty() || self.segments[0].name != "__TEXT" {
            return Err(BuildError("first segment must be __TEXT".into()));
        }
        for seg in &self.segments[1..] {
            if seg.name == "__TEXT" {
                return Err(BuildError("only one __TEXT segment".into()));
            }
        }
        for (i, slot) in self.got.iter().enumerate() {
            if let SlotKind::Bind { sym_index, .. } = *slot {
                if !matches!(
                    self.symbols.get(sym_index),
                    Some(SymbolSpec::Undefined { .. })
                ) {
                    return Err(BuildError(format!(
                        "got bind slot {i} does not name an undefined symbol"
                    )));
                }
            }
        }
        // Auth slots are an arm64e-family shape: under the 64_OFFSET
        // default there is no encoding for them, and the builder refuses
        // instead of emitting a word dyld cannot read.
        if !self.got.is_empty() {
            let has_auth_slots = self.got.iter().any(|slot| {
                matches!(
                    slot,
                    SlotKind::AuthRebase { .. } | SlotKind::AuthBind { .. }
                )
            });
            if has_auth_slots && self.pointer_format == PointerFormatKind::Offset64 {
                return Err(BuildError(
                    "auth slots require the arm64e pointer format".into(),
                ));
            }
        }

        let data_const_index = self.segments.iter().position(|s| s.name == "__DATA_CONST");
        if !self.got.is_empty() && data_const_index.is_none() {
            return Err(BuildError("set_got requires a __DATA_CONST segment".into()));
        }

        // Working copy of the segment list with the synthesized __got section.
        let mut segments = self.segments.clone();
        if !self.got.is_empty() {
            let dc = data_const_index.expect("checked above");
            segments[dc].sections.push(SectionSpec {
                name: "__got".into(),
                align_log2: 3,
                flags: S_NON_LAZY_SYMBOL_POINTERS,
                data: vec![0u8; self.got.len() * 8],
                relocs: Vec::new(),
            });
        }

        // ---- load command sizes (fixed before layout) -------------------
        let mut sizeofcmds: usize = 0;
        let mut ncmds: u32 = 0;
        let mut add_cmd = |size: usize| {
            sizeofcmds += size;
            ncmds += 1;
        };
        if exec {
            add_cmd(72); // __PAGEZERO
        }
        for seg in &segments {
            add_cmd(72 + 80 * seg.sections.len());
        }
        add_cmd(72); // __LINKEDIT
        add_cmd(32); // LC_BUILD_VERSION + 1 tool entry
        if exec {
            let loader = self.loader_path.as_deref().unwrap_or("/usr/lib/dyld");
            add_cmd(align_up(12 + loader.len() as u64 + 1, 8) as usize); // dylinker
            add_cmd(24); // LC_MAIN
        } else if !bundle {
            add_cmd(align_up(24 + self.install_name.len() as u64 + 1, 8) as usize); // LC_ID_DYLIB
        }
        for name in &self.dylibs {
            add_cmd(align_up(24 + name.len() as u64 + 1, 8) as usize);
        }
        for (is_umbrella, name) in &self.sub_cmds {
            let _ = is_umbrella;
            add_cmd(align_up(12 + name.len() as u64 + 1, 8) as usize); // LC_SUB_UMBRELLA / LC_SUB_LIBRARY
        }
        for name in &self.sub_clients {
            add_cmd(align_up(12 + name.len() as u64 + 1, 8) as usize); // LC_SUB_CLIENT
        }
        for pair in &self.dyld_envs {
            add_cmd(align_up(12 + pair.len() as u64 + 1, 8) as usize); // LC_DYLD_ENVIRONMENT
        }
        add_cmd(24); // LC_SYMTAB
        add_cmd(80); // LC_DYSYMTAB
        if !self.got.is_empty() {
            add_cmd(16); // LC_DYLD_CHAINED_FIXUPS
        }
        add_cmd(16); // LC_DYLD_EXPORTS_TRIE (always: executables export)
        add_cmd(16); // LC_FUNCTION_STARTS
        add_cmd(24); // LC_UUID
        add_cmd(16); // LC_CODE_SIGNATURE
        let header_len = 32 + sizeofcmds;
        if header_len as u64 > PAGE_SIZE_16K {
            return Err(BuildError("load commands exceed the header page".into()));
        }

        // ---- segment layout: 16 KiB aligned, constant vaddr-fileoff delta
        // M15: the delta is the configured `__PAGEZERO` vmsize (the
        // default stays the 4 GiB constant; a broken override is the
        // verifier's finding to name).
        let delta = if exec {
            self.pagezero.unwrap_or(PAGEZERO_SIZE_64)
        } else {
            self.image_base.unwrap_or(0)
        };
        let mut placed: Vec<(String, u64, u64)> = Vec::new(); // name, fileoff, vmsize
        let mut sect_infos: Vec<SectionInfo> = Vec::new();

        if exec {
            placed.push(("__PAGEZERO".into(), 0, delta));
        }
        for (seg_i, seg) in segments.iter().enumerate() {
            let seg_fileoff = if seg_i == 0 {
                0
            } else {
                align_up(placed.last().map_or(0, |(_, f, v)| f + v), PAGE_SIZE_16K)
            };
            let mut cursor = if seg_i == 0 {
                // M29: the named header-region floor grows the reserved
                // region to at least the named space before the first
                // section (the same decision the layout plans); a floor
                // at or below the natural region plans the pre-M29
                // bytes.
                align_up(
                    self.header_pad
                        .map_or(header_len as u64, |p| p.max(header_len as u64)),
                    16,
                )
            } else {
                seg_fileoff
            };
            for sec in &seg.sections {
                cursor = align_up(cursor, 1u64 << sec.align_log2.min(14));
                sect_infos.push(SectionInfo {
                    name: sec.name.clone(),
                    segment: seg.name.clone(),
                    fileoff: cursor,
                    addr: cursor + delta,
                    size: sec.data.len() as u64,
                });
                cursor += sec.data.len() as u64;
                if self.keep_relocs && !sec.relocs.is_empty() {
                    cursor += sec.relocs.len() as u64 * 8;
                }
            }
            let vmsize = align_up(cursor - seg_fileoff, PAGE_SIZE_16K).max(PAGE_SIZE_16K);
            placed.push((seg.name.clone(), seg_fileoff, vmsize));
        }

        // ---- symbol table (locals: none; defs then undefs) ---------------
        let mut strtab: Vec<u8> = vec![0];
        let mut symtab_entries: Vec<(u32, u8, u8, u16, u64)> = Vec::new();
        let mut symbol_indices_out = vec![0u32; self.symbols.len()];
        let mut n_defs = 0usize;
        for (i, sym) in self.symbols.iter().enumerate() {
            if let SymbolSpec::Defined {
                name,
                section_index,
            } = sym
            {
                let strx = strtab.len() as u32;
                strtab.extend_from_slice(name.as_bytes());
                strtab.push(0);
                let value = sect_infos
                    .get(*section_index)
                    .map(|s| s.addr)
                    .ok_or_else(|| BuildError("symbol section index out of range".into()))?;
                symtab_entries.push((strx, N_EXT | N_SECT, (*section_index + 1) as u8, 0, value));
                symbol_indices_out[i] = n_defs as u32;
                n_defs += 1;
            }
        }
        let mut n_undefs = 0usize;
        for (i, sym) in self.symbols.iter().enumerate() {
            if let SymbolSpec::Undefined {
                name,
                lib_ordinal,
                weak,
            } = sym
            {
                let strx = strtab.len() as u32;
                strtab.extend_from_slice(name.as_bytes());
                strtab.push(0);
                let mut desc = (*lib_ordinal & 0xff) << 8;
                if *weak {
                    desc |= N_WEAK_REF;
                }
                symtab_entries.push((strx, N_EXT | N_UNDF, 0, desc, 0));
                symbol_indices_out[i] = (n_defs + n_undefs) as u32;
                n_undefs += 1;
            }
        }
        let nsyms = symtab_entries.len();

        // ---- import table (dedup by bind name, in first-use order) -------
        // Auth binds register their import too (M10 rung 4, slice 5):
        // their word carries no addend field, so the table entry rides
        // addend 0 under every import format.
        let mut imports: Vec<Import> = Vec::new();
        let mut import_names: Vec<String> = Vec::new();
        for slot in &self.got {
            let (sym_index, addend) = match *slot {
                SlotKind::Bind { sym_index, addend } => (sym_index, addend),
                SlotKind::AuthBind { sym_index, .. } => (sym_index, 0),
                SlotKind::Rebase { .. } | SlotKind::AuthRebase { .. } => continue,
            };
            let Some(SymbolSpec::Undefined {
                name, lib_ordinal, ..
            }) = self.symbols.get(sym_index)
            else {
                continue;
            };
            if import_names.iter().any(|n| n == name) {
                continue;
            }
            let table_addend = match self.imports_format {
                ImportsFormat::Plain => 0,
                ImportsFormat::Addend64 => i64::from(addend),
            };
            import_names.push(name.clone());
            imports.push(Import {
                lib_ordinal: *lib_ordinal,
                weak_import: false,
                name_offset: 0, // patched once the name blob is laid out
                addend: table_addend,
            });
        }

        // ---- fixup payload + slot words (mold layout) --------------------
        let slot_fileoffs: Vec<u64> = if self.got.is_empty() {
            Vec::new()
        } else {
            let got_section = sect_infos
                .iter()
                .find(|s| s.name == "__got")
                .ok_or_else(|| BuildError("__got section missing".into()))?;
            (0..self.got.len())
                .map(|i| got_section.fileoff + i as u64 * 8)
                .collect()
        };
        let (got_seg_index, got_seg_fileoff) = if self.got.is_empty() {
            (0usize, 0u64)
        } else {
            let idx = data_const_index.expect("checked above") + usize::from(exec);
            (idx, placed[idx].1)
        };
        let (payload, slot_words) = if self.got.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            build_fixup_payload(FixupContext {
                placed: &placed,
                got_seg_index,
                got_seg_fileoff,
                slot_fileoffs: &slot_fileoffs,
                got: &self.got,
                symbols: &self.symbols,
                imports: &mut imports,
                names: &import_names,
                fmt: self.imports_format,
                pf: self.pointer_format,
                delta,
            })?
        };

        // ---- export trie + function starts -------------------------------
        let trie = build_minimal_trie(exec, &self.symbols, &sect_infos)?;
        let func_starts: Vec<u8> = vec![0x00]; // one ULEB delta: entry at 0

        // ---- __LINKEDIT segment + content layout ------------------------
        let linkedit_fileoff = align_up(placed.last().map_or(0, |(_, f, v)| f + v), PAGE_SIZE_16K);
        placed.push(("__LINKEDIT".into(), linkedit_fileoff, 0)); // vmsize patched below
        let mut cur = linkedit_fileoff;
        let mut take = |size: u64, align: u64| {
            cur = align_up(cur, align);
            let at = cur;
            cur += size;
            at
        };
        let symoff = take(nsyms as u64 * 16, 8);
        let stroff = take(strtab.len() as u64, 8);
        let nindirect = self.got.len() as u32;
        let indirectsymoff = if nindirect > 0 {
            take(u64::from(nindirect) * 4, 4)
        } else {
            0
        };
        let payload_off = if payload.is_empty() {
            0
        } else {
            take(payload.len() as u64, 8)
        };
        let trie_off = if trie.is_empty() {
            0
        } else {
            take(trie.len() as u64, 4)
        };
        let func_off = take(func_starts.len() as u64, 4);

        // ---- signature sizing (TDD §9 formulas) --------------------------
        let sig_off = align_up(cur, 8);
        let nblocks = sig_off.div_ceil(SIGNATURE_HASH_PAGE) as usize;
        let ident_padded = align_up(self.ident.len() as u64 + 1, 4) as usize;
        let dir_len = 88 + ident_padded + nblocks * 32;
        let blob_len = align_up((12 + 8 + dir_len) as u64, 8) as usize;
        let file_len = sig_off + blob_len as u64;
        let linkedit_size = file_len - linkedit_fileoff;
        let le_i = placed.len() - 1;
        placed[le_i].2 = align_up(linkedit_size, PAGE_SIZE_16K).max(linkedit_size);

        // ---- assemble header + load commands ----------------------------
        let mut buf = vec![0u8; file_len as usize];
        let flags = if exec {
            MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | if self.pie { MH_PIE } else { 0 }
        } else if bundle {
            // A bundle carries no re-export surface (dlopen-able, no
            // LC_ID_DYLIB).
            MH_DYLDLINK | MH_TWOLEVEL
        } else {
            // The minimal builder never re-exports: set the marker dyld
            // and the verifier expect on a re-export-free dylib.
            MH_DYLDLINK | MH_TWOLEVEL | MH_NO_REEXPORTED_DYLIBS
        };
        buf[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        buf[4..8].copy_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        buf[8..12].copy_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
        let filetype = if exec {
            MH_EXECUTE
        } else if bundle {
            MH_BUNDLE
        } else {
            MH_DYLIB
        };
        buf[12..16].copy_from_slice(&filetype.to_le_bytes());
        buf[16..20].copy_from_slice(&ncmds.to_le_bytes());
        buf[20..24].copy_from_slice(&(sizeofcmds as u32).to_le_bytes());
        buf[24..28].copy_from_slice(&flags.to_le_bytes());

        let mut lc = 32usize;
        let w32 =
            |buf: &mut [u8], at: usize, v: u32| buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let w64 =
            |buf: &mut [u8], at: usize, v: u64| buf[at..at + 8].copy_from_slice(&v.to_le_bytes());

        if exec {
            w32(&mut buf, lc, LC_SEGMENT_64);
            w32(&mut buf, lc + 4, 72);
            buf[lc + 8..lc + 24].copy_from_slice(&pad_name(SEG_PAGEZERO));
            w64(&mut buf, lc + 24, 0);
            // M15: the vmsize rides the configured override (the default
            // stays the 4 GiB constant).
            w64(&mut buf, lc + 32, delta);
            w64(&mut buf, lc + 40, 0);
            w64(&mut buf, lc + 48, 0);
            // M17: the protection knob reaches `__PAGEZERO` too — the
            // hand-broken-shape gates build a protected prefix on
            // purpose (the verifier's protection half names it).
            let pz_prot = self
                .seg_prots
                .iter()
                .find(|(n, _, _)| n.as_bytes() == SEG_PAGEZERO)
                .map_or((VM_PROT_NONE, VM_PROT_NONE), |&(_, max, init)| (max, init));
            w32(&mut buf, lc + 56, pz_prot.0);
            w32(&mut buf, lc + 60, pz_prot.1);
            lc += 72;
        }
        for (seg_i, seg) in segments.iter().enumerate() {
            let map_i = seg_i + usize::from(exec);
            let (_, fileoff, vmsize) = &placed[map_i];
            // M17: the named protection pair rides the segment (the
            // house table falling out of `None`, the override table
            // first-match-wins by name).
            let (maxprot, initprot) = self
                .seg_prots
                .iter()
                .find(|(n, _, _)| n == &seg.name)
                .map_or_else(|| Self::prot(&seg.name), |&(_, max, init)| (max, init));
            w32(&mut buf, lc, LC_SEGMENT_64);
            w32(&mut buf, lc + 4, (72 + 80 * seg.sections.len()) as u32);
            buf[lc + 8..lc + 24].copy_from_slice(&pad_name(seg.name.as_bytes()));
            w64(&mut buf, lc + 24, fileoff + delta);
            w64(&mut buf, lc + 32, *vmsize);
            w64(&mut buf, lc + 40, *fileoff);
            w64(&mut buf, lc + 48, *vmsize);
            w32(&mut buf, lc + 56, maxprot);
            w32(&mut buf, lc + 60, initprot);
            w32(&mut buf, lc + 64, seg.sections.len() as u32);
            lc += 72;
            for (sec_i, sec) in seg.sections.iter().enumerate() {
                let si = &sect_infos[global_section_base(&segments, seg_i) + sec_i];
                let mut sect = [0u8; 80];
                sect[0..16].copy_from_slice(&pad_name(sec.name.as_bytes()));
                sect[16..32].copy_from_slice(&pad_name(seg.name.as_bytes()));
                w64(&mut sect, 32, si.addr);
                w64(&mut sect, 40, si.size);
                w32(&mut sect, 48, si.fileoff as u32);
                w32(&mut sect, 52, sec.align_log2);
                let (reloff, nreloc) = if self.keep_relocs && !sec.relocs.is_empty() {
                    (si.fileoff + si.size, sec.relocs.len() as u32)
                } else {
                    (0, 0)
                };
                w32(&mut sect, 56, reloff as u32);
                w32(&mut sect, 60, nreloc);
                w32(&mut sect, 64, sec.flags);
                buf[lc..lc + 80].copy_from_slice(&sect);
                lc += 80;
            }
        }
        // __LINKEDIT (last segment, covers through EOF)
        {
            let (_, le_fileoff, le_vmsize) = placed[le_i];
            w32(&mut buf, lc, LC_SEGMENT_64);
            w32(&mut buf, lc + 4, 72);
            buf[lc + 8..lc + 24].copy_from_slice(&pad_name(b"__LINKEDIT"));
            w64(&mut buf, lc + 24, le_fileoff + delta);
            w64(&mut buf, lc + 32, le_vmsize);
            w64(&mut buf, lc + 40, le_fileoff);
            w64(&mut buf, lc + 48, linkedit_size);
            w32(&mut buf, lc + 56, VM_PROT_READ);
            w32(&mut buf, lc + 60, VM_PROT_READ);
            lc += 72;
        }
        let (bv_platform, bv_minos, bv_sdk) = self.build_version.unwrap_or((
            PLATFORM_MACOS,
            0x000c_0000, // minos 12.0.0
            0x000e_0400, // sdk 14.4.0
        ));
        w32(&mut buf, lc, LC_BUILD_VERSION);
        w32(&mut buf, lc + 4, 32);
        w32(&mut buf, lc + 8, bv_platform);
        w32(&mut buf, lc + 12, bv_minos);
        w32(&mut buf, lc + 16, bv_sdk);
        w32(&mut buf, lc + 20, 1);
        w32(&mut buf, lc + 24, TOOL_LD);
        w32(&mut buf, lc + 28, 0x000f_0200);
        lc += 32;
        if exec {
            let loader = self.loader_path.as_deref().unwrap_or("/usr/lib/dyld");
            let loader_size = align_up(12 + loader.len() as u64 + 1, 8) as u32;
            w32(&mut buf, lc, LC_LOAD_DYLINKER);
            w32(&mut buf, lc + 4, loader_size);
            w32(&mut buf, lc + 8, 12);
            buf[lc + 12..lc + 12 + loader.len()].copy_from_slice(loader.as_bytes());
            buf[lc + 12 + loader.len()] = 0;
            lc += loader_size as usize;
            w32(&mut buf, lc, LC_MAIN);
            w32(&mut buf, lc + 4, 24);
            w64(&mut buf, lc + 8, self.entryoff);
            // M18: the reserve rides the configured override (the
            // default stays the pre-M18 zero).
            w64(&mut buf, lc + 16, self.stack_size.unwrap_or(0));
            lc += 24;
        } else if !bundle {
            w32(&mut buf, lc, LC_ID_DYLIB);
            let n = format!("{}\0", self.install_name);
            let cmdsize = align_up(24 + n.len() as u64, 8) as usize;
            w32(&mut buf, lc + 4, cmdsize as u32);
            w32(&mut buf, lc + 8, 24);
            w32(&mut buf, lc + 12, 0);
            w32(&mut buf, lc + 16, 0x0001_0000);
            w32(&mut buf, lc + 20, 0);
            buf[lc + 24..lc + 24 + n.len()].copy_from_slice(n.as_bytes());
            lc += cmdsize;
        }
        // LC_DYLD_ENVIRONMENT per pair (M22): the loader-configuration
        // commands, in flag order — the 12-byte-fixed lc_str shape
        // `LC_RPATH` rides. Written unconditionally so the broken-shape
        // gates can build the inert off-executable placement.
        for pair in &self.dyld_envs {
            w32(&mut buf, lc, LC_DYLD_ENVIRONMENT);
            let n = format!("{pair}\0");
            let cmdsize = align_up(12 + n.len() as u64, 8) as usize;
            w32(&mut buf, lc + 4, cmdsize as u32);
            w32(&mut buf, lc + 8, 12);
            buf[lc + 12..lc + 12 + n.len()].copy_from_slice(n.as_bytes());
            lc += cmdsize;
        }
        for name in &self.dylibs {
            w32(&mut buf, lc, LC_LOAD_DYLIB);
            let n = format!("{name}\0");
            let cmdsize = align_up(24 + n.len() as u64, 8) as usize;
            w32(&mut buf, lc + 4, cmdsize as u32);
            w32(&mut buf, lc + 8, 24);
            w32(&mut buf, lc + 12, 0);
            w32(&mut buf, lc + 16, 0x0001_0000);
            w32(&mut buf, lc + 20, 0);
            buf[lc + 24..lc + 24 + n.len()].copy_from_slice(n.as_bytes());
            lc += cmdsize;
        }
        // LC_SUB_UMBRELLA / LC_SUB_LIBRARY per umbrella member (M20):
        // the identity block's region, in flag order — the 12-byte-fixed
        // lc_str shape `LC_RPATH` rides.
        for (is_umbrella, name) in &self.sub_cmds {
            let opcode = if *is_umbrella {
                LC_SUB_UMBRELLA
            } else {
                LC_SUB_LIBRARY
            };
            w32(&mut buf, lc, opcode);
            let n = format!("{name}\0");
            let cmdsize = align_up(12 + n.len() as u64, 8) as usize;
            w32(&mut buf, lc + 4, cmdsize as u32);
            w32(&mut buf, lc + 8, 12);
            buf[lc + 12..lc + 12 + n.len()].copy_from_slice(n.as_bytes());
            lc += cmdsize;
        }
        // LC_SUB_CLIENT per client name (M21): the identity block's
        // client list, in flag order right after the region — the same
        // 12-byte-fixed lc_str shape.
        for name in &self.sub_clients {
            w32(&mut buf, lc, LC_SUB_CLIENT);
            let n = format!("{name}\0");
            let cmdsize = align_up(12 + n.len() as u64, 8) as usize;
            w32(&mut buf, lc + 4, cmdsize as u32);
            w32(&mut buf, lc + 8, 12);
            buf[lc + 12..lc + 12 + n.len()].copy_from_slice(n.as_bytes());
            lc += cmdsize;
        }
        w32(&mut buf, lc, LC_SYMTAB);
        w32(&mut buf, lc + 4, 24);
        w32(&mut buf, lc + 8, symoff as u32);
        w32(&mut buf, lc + 12, nsyms as u32);
        w32(&mut buf, lc + 16, stroff as u32);
        w32(&mut buf, lc + 20, strtab.len() as u32);
        lc += 24;
        w32(&mut buf, lc, LC_DYSYMTAB);
        w32(&mut buf, lc + 4, 80);
        w32(&mut buf, lc + 20, n_defs as u32); // nextdefsym
        w32(&mut buf, lc + 24, n_defs as u32); // iundefsym
        w32(&mut buf, lc + 28, n_undefs as u32);
        w32(&mut buf, lc + 56, indirectsymoff as u32);
        w32(&mut buf, lc + 60, nindirect);
        lc += 80;
        if !self.got.is_empty() {
            w32(&mut buf, lc, LC_DYLD_CHAINED_FIXUPS);
            w32(&mut buf, lc + 4, 16);
            w32(&mut buf, lc + 8, payload_off as u32);
            w32(&mut buf, lc + 12, payload.len() as u32);
            lc += 16;
        }
        w32(&mut buf, lc, LC_DYLD_EXPORTS_TRIE);
        w32(&mut buf, lc + 4, 16);
        w32(&mut buf, lc + 8, trie_off as u32);
        w32(&mut buf, lc + 12, trie.len() as u32);
        lc += 16;
        w32(&mut buf, lc, LC_FUNCTION_STARTS);
        w32(&mut buf, lc + 4, 16);
        w32(&mut buf, lc + 8, func_off as u32);
        w32(&mut buf, lc + 12, func_starts.len() as u32);
        lc += 16;
        let uuid_at = lc + 8;
        w32(&mut buf, lc, LC_UUID);
        w32(&mut buf, lc + 4, 24);
        lc += 24;
        w32(&mut buf, lc, LC_CODE_SIGNATURE);
        w32(&mut buf, lc + 4, 16);
        w32(&mut buf, lc + 8, sig_off as u32);
        w32(&mut buf, lc + 12, blob_len as u32);
        lc += 16;
        debug_assert_eq!(lc, header_len, "load command assembly must match sizing");

        // ---- section data + relocation tables ---------------------------
        for (i, sec) in segments.iter().flat_map(|s| s.sections.iter()).enumerate() {
            let si = &sect_infos[i];
            buf[si.fileoff as usize..si.fileoff as usize + sec.data.len()]
                .copy_from_slice(&sec.data);
            if self.keep_relocs && !sec.relocs.is_empty() {
                let mut bytes = Vec::with_capacity(sec.relocs.len() * 8);
                for r in &sec.relocs {
                    let mut info = r.symbolnum & 0x00ff_ffff;
                    if r.pcrel {
                        info |= 1 << 24;
                    }
                    info |= (r.length_log2 & 0x3) << 25;
                    if r.extern_ {
                        info |= 1 << 27;
                    }
                    info |= (r.rtype & 0xf) << 28;
                    bytes.extend_from_slice(&r.offset.to_le_bytes());
                    bytes.extend_from_slice(&info.to_le_bytes());
                }
                let at = si.fileoff as usize + sec.data.len();
                buf[at..at + bytes.len()].copy_from_slice(&bytes);
            }
        }

        // ---- LINKEDIT payloads ------------------------------------------
        for (i, (strx, ty, sect, desc, value)) in symtab_entries.iter().enumerate() {
            let at = symoff as usize + i * 16;
            buf[at..at + 4].copy_from_slice(&strx.to_le_bytes());
            buf[at + 4] = *ty;
            buf[at + 5] = *sect;
            buf[at + 6..at + 8].copy_from_slice(&desc.to_le_bytes());
            buf[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
        }
        buf[stroff as usize..stroff as usize + strtab.len()].copy_from_slice(&strtab);
        if nindirect > 0 {
            for (i, slot) in self.got.iter().enumerate() {
                // The auth slots ride the same indirect shapes as their
                // plain twins: an (auth) bind carries its symbol's output
                // index, an (auth) rebase is unnamed (`INDIRECT_SYMBOL_LOCAL`).
                let entry = match slot {
                    SlotKind::Bind { sym_index, .. } | SlotKind::AuthBind { sym_index, .. } => {
                        symbol_indices_out[*sym_index]
                    }
                    SlotKind::Rebase { .. } | SlotKind::AuthRebase { .. } => INDIRECT_SYMBOL_LOCAL,
                };
                let at = indirectsymoff as usize + i * 4;
                buf[at..at + 4].copy_from_slice(&entry.to_le_bytes());
            }
        }
        if !payload.is_empty() {
            buf[payload_off as usize..payload_off as usize + payload.len()]
                .copy_from_slice(&payload);
        }
        if !trie.is_empty() {
            buf[trie_off as usize..trie_off as usize + trie.len()].copy_from_slice(&trie);
        }
        buf[func_off as usize..func_off as usize + func_starts.len()].copy_from_slice(&func_starts);

        // ---- chain words into the __got slots ---------------------------
        for (i, word) in slot_words.iter().enumerate() {
            let at = slot_fileoffs[i] as usize;
            buf[at..at + 8].copy_from_slice(&word.to_le_bytes());
        }

        // ---- UUID two-pass, then signature ------------------------------
        let h1 = page_hashes(&mut buf, uuid_at, nblocks, sig_off, true);
        let uuid = {
            let mut h = Sha256::new();
            h.update(&h1);
            let mut u = [0u8; 16];
            u.copy_from_slice(&h.finalize()[..16]);
            u
        };
        buf[uuid_at..uuid_at + 16].copy_from_slice(&uuid);
        let hashes = page_hashes(&mut buf, uuid_at, nblocks, sig_off, false);
        let sig = build_superblob(
            &self.ident,
            sig_off,
            &hashes,
            placed
                .iter()
                .find(|(n, _, _)| n == "__TEXT")
                .map_or(0, |(_, _, v)| *v),
            exec,
        );
        debug_assert_eq!(sig.len(), blob_len, "signature sizing must be exact");
        buf[sig_off as usize..sig_off as usize + sig.len()].copy_from_slice(&sig);

        Ok(Image {
            bytes: buf,
            map: LayoutMap {
                sections: sect_infos,
                got_slot_addrs: slot_fileoffs.iter().map(|f| f + delta).collect(),
                imports,
                symbol_indices: symbol_indices_out,
                entryoff: self.entryoff,
                sig_off,
                uuid,
                text_vmsize: placed
                    .iter()
                    .find(|(n, _, _)| n == "__TEXT")
                    .map_or(0, |(_, _, v)| *v),
                imports_format: match self.imports_format {
                    ImportsFormat::Plain => DYLD_CHAINED_IMPORT,
                    ImportsFormat::Addend64 => DYLD_CHAINED_IMPORT_ADDEND64,
                },
            },
        })
    }
}

/// Everything the fixup-payload builder needs, in one place.
struct FixupContext<'a> {
    /// Placed segments as `(name, fileoff, vmsize)`, header order.
    placed: &'a [(String, u64, u64)],
    /// Index into `placed` of the fixup-carrying segment.
    got_seg_index: usize,
    /// That segment's file offset (== payload `segment_offset`).
    got_seg_fileoff: u64,
    /// File offset of each `__got` slot, in slot order.
    slot_fileoffs: &'a [u64],
    /// Slot kinds.
    got: &'a [SlotKind],
    /// Builder symbol table.
    symbols: &'a [SymbolSpec],
    /// Import table (name offsets are assigned by the builder).
    imports: &'a mut [Import],
    /// Bind names, in first-use order, aligned with `imports`.
    names: &'a [String],
    /// Import entry format.
    fmt: ImportsFormat,
    /// Chain-word pointer format.
    pf: PointerFormatKind,
    /// The image-base delta (`vmaddr = fileoff + delta`): the unauth
    /// arm64e rebase target is a VM address, so the builder synthesizes
    /// `target + delta` into the word (dyld subtracts it walking back).
    delta: u64,
}

/// Builds the `LC_DYLD_CHAINED_FIXUPS` payload (mold layout) and the encoded
/// chain words for the `__got` slots. `imports` and `names` arrive in sync
/// (one entry per distinct bind name); the name offsets are assigned here.
fn build_fixup_payload(ctx: FixupContext<'_>) -> Result<(Vec<u8>, Vec<u64>), BuildError> {
    let FixupContext {
        placed,
        got_seg_index,
        got_seg_fileoff,
        slot_fileoffs,
        got,
        symbols,
        imports,
        names,
        fmt,
        pf,
        delta,
    } = ctx;
    // Import name offsets inside the payload's name blob (leading NUL).
    let mut name_off = 1u32; // after the leading NUL
    for (imp, name) in imports.iter_mut().zip(names.iter()) {
        imp.name_offset = name_off;
        name_off += name.len() as u32 + 1;
    }

    // ---- chain words: per 16 KiB page, sorted slots, single chain each
    let page_size = 0x4000u64;
    let mut page_slots: Vec<(u32, Vec<usize>)> = Vec::new(); // (page, slot indices)
    for (i, &f) in slot_fileoffs.iter().enumerate() {
        let page = ((f - got_seg_fileoff) / page_size) as u32;
        match page_slots.iter_mut().find(|(p, _)| *p == page) {
            Some((_, v)) => v.push(i),
            None => page_slots.push((page, vec![i])),
        }
    }
    page_slots.sort_by_key(|(p, _)| *p);
    let mut words = vec![0u64; got.len()];
    let mut page_start: Vec<u16> = Vec::new();
    // The page count rides the last slot's file offset; an empty slot
    // list here means the caller built __got slots without recording
    // their placement — a named refusal, not a panic on `.last()`
    // (the pre-slice-2 code unwrapped and crashed deep in the builder).
    let last_slot = slot_fileoffs.last().copied().ok_or_else(|| {
        BuildError("chain build got no __got slot placements (set_got must run)".into())
    })?;
    let npages = ((last_slot - got_seg_fileoff + 1).div_ceil(page_size)) as u16;
    for p in 0..npages {
        let Some((_, slots)) = page_slots.iter().find(|(pg, _)| *pg == u32::from(p)) else {
            page_start.push(DYLD_CHAINED_PTR_START_NONE);
            continue;
        };
        let mut sorted: Vec<usize> = slots.clone();
        sorted.sort_by_key(|&i| slot_fileoffs[i]);
        for (j, &si) in sorted.iter().enumerate() {
            let word = match &got[si] {
                SlotKind::Rebase { target } => match pf {
                    PointerFormatKind::Offset64 => {
                        let high8 = (target >> 56) as u8;
                        encode_rebase_word(
                            target & 0x00ff_ffff_ffff_ffff,
                            high8,
                            next_strides(&sorted, j, slot_fileoffs, 4),
                        )?
                    }
                    // Unauth arm64e rebase targets are VM addresses: the
                    // word carries `target + delta` (dyld subtracts the
                    // preferred load address walking back).
                    PointerFormatKind::Arm64e => encode_arm64e_rebase_word(
                        target + delta,
                        0,
                        next_strides(&sorted, j, slot_fileoffs, 8),
                    )?,
                },
                SlotKind::Bind { sym_index, addend } => {
                    let name = match symbols.get(*sym_index) {
                        Some(SymbolSpec::Undefined { name, .. }) => name.as_str(),
                        _ => return Err(BuildError("bind without a name".into())),
                    };
                    let ordinal = names
                        .iter()
                        .position(|n| n == name)
                        .ok_or_else(|| BuildError("bind name missing from import table".into()))?;
                    let inline = match fmt {
                        ImportsFormat::Plain => *addend,
                        ImportsFormat::Addend64 => 0,
                    };
                    match pf {
                        PointerFormatKind::Offset64 => encode_bind_word(
                            ordinal as u32,
                            inline,
                            next_strides(&sorted, j, slot_fileoffs, 4),
                        )?,
                        PointerFormatKind::Arm64e => encode_arm64e_bind_word(
                            ordinal as u32,
                            i64::from(inline),
                            next_strides(&sorted, j, slot_fileoffs, 8),
                        )?,
                    }
                }
                SlotKind::AuthRebase {
                    offset,
                    diversity,
                    addr_div,
                    key,
                } => {
                    if offset >> 32 != 0 {
                        return Err(BuildError(format!(
                            "auth rebase offset {offset:#x} exceeds the 32-bit runtime-offset field"
                        )));
                    }
                    encode_arm64e_auth_rebase_word(
                        *offset,
                        *diversity,
                        *addr_div,
                        *key,
                        next_strides(&sorted, j, slot_fileoffs, 8),
                    )?
                }
                SlotKind::AuthBind {
                    sym_index,
                    diversity,
                    addr_div,
                    key,
                } => {
                    let name = match symbols.get(*sym_index) {
                        Some(SymbolSpec::Undefined { name, .. }) => name.as_str(),
                        _ => return Err(BuildError("bind without a name".into())),
                    };
                    let ordinal = names
                        .iter()
                        .position(|n| n == name)
                        .ok_or_else(|| BuildError("bind name missing from import table".into()))?;
                    encode_arm64e_auth_bind_word(
                        ordinal as u32,
                        *diversity,
                        *addr_div,
                        *key,
                        next_strides(&sorted, j, slot_fileoffs, 8),
                    )?
                }
            };
            words[si] = word;
        }
        let first = sorted[0];
        let start_off =
            (slot_fileoffs[first] - (got_seg_fileoff + u64::from(p) * page_size)) as u16;
        page_start.push(start_off);
    }

    // ---- payload assembly --------------------------------------------
    let mut b = Vec::new();
    let push32 = |b: &mut Vec<u8>, v: u32| b.extend_from_slice(&v.to_le_bytes());
    let push16 = |b: &mut Vec<u8>, v: u16| b.extend_from_slice(&v.to_le_bytes());
    // header (backpatched)
    push32(&mut b, 0); // fixups_version
    push32(&mut b, 0); // starts_offset
    push32(&mut b, 0); // imports_offset
    push32(&mut b, 0); // symbols_offset
    push32(&mut b, imports.len() as u32);
    push32(
        &mut b,
        match fmt {
            ImportsFormat::Plain => DYLD_CHAINED_IMPORT,
            ImportsFormat::Addend64 => DYLD_CHAINED_IMPORT_ADDEND64,
        },
    );
    push32(&mut b, 0); // symbols_format
    while b.len() % 8 != 0 {
        b.push(0);
    }
    let starts_offset = b.len();
    // starts_in_image: one entry per segment command (pagezero included)
    let seg_count = placed.len();
    push32(&mut b, seg_count as u32);
    let seg_info_at = b.len();
    for _ in 0..seg_count {
        push32(&mut b, 0);
    }
    while b.len() % 8 != 0 {
        b.push(0);
    }
    let record_rel = b.len() - starts_offset;
    b[seg_info_at + got_seg_index * 4..seg_info_at + got_seg_index * 4 + 4]
        .copy_from_slice(&(record_rel as u32).to_le_bytes());
    // starts_in_segment for the got segment
    push32(&mut b, 22 + u32::from(npages) * 2);
    push16(&mut b, page_size as u16);
    push16(&mut b, pf.value());
    b.extend_from_slice(&got_seg_fileoff.to_le_bytes()); // segment_offset == fileoff
    push32(&mut b, 0); // max_valid_pointer
    push16(&mut b, npages);
    for start in &page_start {
        push16(&mut b, *start);
    }
    // imports table
    while b.len() % 8 != 0 {
        b.push(0);
    }
    let imports_offset = b.len();
    for imp in imports.iter() {
        match fmt {
            ImportsFormat::Plain => {
                let word = u32::from(imp.lib_ordinal & 0xff)
                    | (u32::from(imp.weak_import) << 8)
                    | (imp.name_offset << 9);
                push32(&mut b, word);
            }
            ImportsFormat::Addend64 => {
                let word = u64::from(imp.lib_ordinal)
                    | (u64::from(imp.weak_import) << 16)
                    | (u64::from(imp.name_offset) << 32);
                b.extend_from_slice(&word.to_le_bytes());
                b.extend_from_slice(&imp.addend.to_le_bytes());
            }
        }
    }
    // name blob
    let symbols_offset = b.len();
    b.push(0);
    for name in names {
        b.extend_from_slice(name.as_bytes());
        b.push(0);
    }
    while b.len() % 8 != 0 {
        b.push(0);
    }
    // backpatch header
    b[4..8].copy_from_slice(&(starts_offset as u32).to_le_bytes());
    b[8..12].copy_from_slice(&(imports_offset as u32).to_le_bytes());
    b[12..16].copy_from_slice(&(symbols_offset as u32).to_le_bytes());
    Ok((b, words))
}

/// Strides to the next fixup in the same chain (0 terminates), counted in
/// the pointer format's stride units (4-byte for the 64 family, 8-byte for
/// arm64e).
fn next_strides(sorted: &[usize], j: usize, slot_fileoffs: &[u64], stride: u64) -> u32 {
    match sorted.get(j + 1) {
        Some(&next_i) => ((slot_fileoffs[next_i] - slot_fileoffs[sorted[j]]) / stride) as u32,
        None => 0,
    }
}

/// Global section index of segment `seg_index`'s first section.
fn global_section_base(segments: &[SegmentSpec], seg_index: usize) -> usize {
    segments[..seg_index].iter().map(|s| s.sections.len()).sum()
}

/// Minimal valid export trie: executables export `_mh_execute_header` at
/// 0; dylibs export every defined symbol at its section address. The node
/// shape is the reader's order — a leaf is
/// `[terminal_size uleb][flags uleb][address uleb][child_count = 0]` (the
/// flags byte rides *in front of* the address), the root is a
/// non-terminal `[0][child_count][edges]` whose edges carry the exported
/// name and the leaf's absolute payload offset. A nameless terminal root
/// exported an empty name and misread its own flags byte — every pair
/// gate that walks the trie saw an empty surface.
fn build_minimal_trie(
    exec: bool,
    symbols: &[SymbolSpec],
    sect_infos: &[SectionInfo],
) -> Result<Vec<u8>, BuildError> {
    let leaves: Vec<(&str, u64)> = if exec {
        vec![("_mh_execute_header", 0)]
    } else {
        let mut out: Vec<(&str, u64)> = Vec::new();
        for s in symbols {
            if let SymbolSpec::Defined {
                name,
                section_index,
                ..
            } = s
            {
                let addr = sect_infos
                    .get(*section_index)
                    .map(|i| i.addr)
                    .ok_or_else(|| BuildError("export section index out of range".into()))?;
                out.push((name.as_str(), addr));
            }
        }
        if out.is_empty() {
            return Err(BuildError("dylib fixture needs a defined symbol".into()));
        }
        out.sort_unstable(); // deterministic edge order
        out
    };
    // Two-pass layout: the edge-table size depends on the leaf offsets,
    // which depend on the edge-table size. Converges in two rounds.
    let mut edge_widths: Vec<usize> = leaves.iter().map(|_| 1).collect();
    let (leaf_offsets, root_len) = loop {
        let mut offsets = Vec::with_capacity(leaves.len());
        let mut at = 2usize; // root terminal-size byte + child-count byte
        for ((name, _), w) in leaves.iter().zip(&edge_widths) {
            at += name.len() + 1 + w;
        }
        let root_len = at;
        let mut widths = Vec::with_capacity(leaves.len());
        let mut stable = true;
        for (i, (_, addr)) in leaves.iter().enumerate() {
            let off = root_len
                + leaves[..i]
                    .iter()
                    .map(|(n, _)| n.len() + 1 + uleb(*addr).len())
                    .sum::<usize>();
            offsets.push(off);
            let w = uleb(off as u64).len();
            widths.push(w);
            stable &= w == edge_widths[i];
        }
        edge_widths = widths;
        if stable {
            break (offsets, root_len);
        }
    };
    let mut out = Vec::with_capacity(root_len);
    out.push(0); // root: non-terminal
    let child_count = leaves.len();
    out.push(child_count as u8);
    for ((name, _), off) in leaves.iter().zip(&leaf_offsets) {
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(&uleb(*off as u64));
    }
    debug_assert_eq!(out.len(), root_len);
    for (_, addr) in &leaves {
        let addr_uleb = uleb(*addr);
        let terminal = 1 + addr_uleb.len(); // flags byte + address
        out.extend_from_slice(&uleb(terminal as u64));
        out.push(0); // flags: regular
        out.extend_from_slice(&addr_uleb);
        out.push(0); // no children
    }
    Ok(out)
}

/// ULEB128 encoding (function-starts / trie helper).
fn uleb(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
    out
}

/// Builds the ad-hoc `SuperBlob` (big-endian): one v0x20400 `CodeDirectory`
/// whose SHA-256 page hashes cover `code_limit` bytes.
fn build_superblob(
    ident: &str,
    code_limit: u64,
    hashes: &[u8],
    exec_seg_limit: u64,
    exec: bool,
) -> Vec<u8> {
    let be32 = |v: u32| v.to_be_bytes();
    let be64 = |v: u64| v.to_be_bytes();
    let ident_padded = align_up(ident.len() as u64 + 1, 4) as usize;
    let dir_len = 88 + ident_padded + hashes.len();
    let mut cd = Vec::with_capacity(dir_len);
    cd.extend_from_slice(&be32(CSMAGIC_CODEDIRECTORY));
    cd.extend_from_slice(&be32(dir_len as u32));
    cd.extend_from_slice(&be32(CS_CODEDIRECTORY_VERSION_EXECSEG));
    cd.extend_from_slice(&be32(CS_ADHOC));
    cd.extend_from_slice(&be32(((88 + ident_padded) / 4) as u32)); // hashOffset
    cd.extend_from_slice(&be32(22)); // identOffset = 88 / 4
    cd.extend_from_slice(&be32(0)); // nSpecialSlots
    cd.extend_from_slice(&be32((hashes.len() / 32) as u32));
    cd.extend_from_slice(&be32(code_limit as u32));
    cd.push(CS_SHA256_LEN as u8);
    cd.push(CS_HASHTYPE_SHA256);
    cd.push(0); // platform
    cd.push(CS_PAGE_SIZE_LOG2);
    cd.extend_from_slice(&be32(0)); // spare2
    cd.extend_from_slice(&be32(0)); // scatterOffset
    cd.extend_from_slice(&be32(0)); // teamOffset
    cd.extend_from_slice(&be32(0)); // spare3
    cd.extend_from_slice(&be64(code_limit));
    cd.extend_from_slice(&be64(0)); // execSegBase
    cd.extend_from_slice(&be64(exec_seg_limit));
    cd.extend_from_slice(&be64(if exec { CS_EXECSEG_MAIN_BINARY } else { 0 }));
    debug_assert_eq!(cd.len(), 88);
    cd.extend_from_slice(ident.as_bytes());
    cd.push(0);
    cd.resize(88 + ident_padded, 0);
    cd.extend_from_slice(hashes);

    let blob_len = align_up((12 + 8 + dir_len) as u64, 8) as usize;
    let mut sb = Vec::with_capacity(blob_len);
    sb.extend_from_slice(&be32(CSMAGIC_EMBEDDED_SIGNATURE));
    sb.extend_from_slice(&be32(blob_len as u32));
    sb.extend_from_slice(&be32(1));
    sb.extend_from_slice(&be32(CSSLOT_CODEDIRECTORY));
    sb.extend_from_slice(&be32(20));
    sb.extend_from_slice(&cd);
    while sb.len() < blob_len {
        sb.push(0);
    }
    sb
}

/// Deterministic fill for corpus data sections (xorshift64*).
#[must_use]
pub fn filler(seed: u64, len: usize) -> Vec<u8> {
    struct Rng(u64);
    let mut rng = Rng(seed | 1);
    let mut v = vec![0u8; len];
    for chunk in v.chunks_mut(8) {
        let mut x = rng.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        rng.0 = x;
        let b = x.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
    v
}

/// Computes the SHA-256 page hashes over `file[0..sig_off]`, optionally
/// zeroing the 16 UUID bytes first (two-pass UUID derivation).
fn page_hashes(
    buf: &mut [u8],
    uuid_at: usize,
    nblocks: usize,
    sig_off: u64,
    zero_uuid: bool,
) -> Vec<u8> {
    let saved: [u8; 16] = buf[uuid_at..uuid_at + 16].try_into().unwrap();
    if zero_uuid {
        buf[uuid_at..uuid_at + 16].fill(0);
    }
    let mut out = Vec::with_capacity(nblocks * 32);
    for p in 0..nblocks {
        let start = p * SIGNATURE_HASH_PAGE as usize;
        let end = ((p + 1) * SIGNATURE_HASH_PAGE as usize).min(sig_off as usize);
        let mut h = Sha256::new();
        h.update(&buf[start..end]);
        out.extend_from_slice(&h.finalize());
    }
    buf[uuid_at..uuid_at + 16].copy_from_slice(&saved);
    out
}

pub mod archive;
pub mod object;

pub use archive::ArchiveBuilder;
pub use object::{
    ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol, read_relocs, read_section, read_sym,
};

pub(crate) fn pad_name(name: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = name.len().min(16);
    out[..n].copy_from_slice(&name[..n]);
    out
}

fn align_up(v: u64, a: u64) -> u64 {
    v.div_ceil(a) * a
}

#[cfg(test)]
mod tests {
    use super::{
        ImageBuilder, ImportsFormat, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
    };
    use pgr_format::consts::*;
    use pgr_format::{CodeDirectory, SuperBlob};

    fn exec_spec() -> ImageBuilder {
        let mut b = ImageBuilder::executable("peregrine-fixture");
        b.add_segment(SegmentSpec {
            name: "__TEXT".into(),
            maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
            initprot: VM_PROT_READ | VM_PROT_EXECUTE,
            sections: vec![SectionSpec {
                name: "__text".into(),
                align_log2: 2,
                flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
                data: filler(0xC0_FFEE, 64),
                relocs: Vec::new(),
            }],
        });
        b.add_segment(SegmentSpec {
            name: "__DATA_CONST".into(),
            maxprot: VM_PROT_READ | VM_PROT_WRITE,
            initprot: VM_PROT_READ | VM_PROT_WRITE,
            sections: vec![],
        });
        b
    }

    #[test]
    fn exec_fixture_parses_and_matches_counts() {
        let mut b = exec_spec();
        let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
        assert_eq!(ord, 1);
        let undef = b.add_symbol(SymbolSpec::Undefined {
            name: "_printf".into(),
            lib_ordinal: ord,
            weak: false,
        });
        b.set_got(vec![SlotKind::Bind {
            sym_index: undef,
            addend: 0,
        }]);
        b.set_entry(0);
        let img = b.build().unwrap();

        let hdr = pgr_format::MachHeader64::parse(&img.bytes).unwrap();
        assert_eq!(hdr.filetype, MH_EXECUTE);
        assert_ne!(hdr.ncmds, 0);
        let summary = pgr_format::summarize(&img.bytes).unwrap();
        assert_eq!(summary.symbols, 1);
        assert_eq!(summary.external_symbols, 1);
        assert!(summary.has_chained_fixups);
        assert_eq!(summary.fixup_slots, 1);
        assert_eq!(summary.segments, 4); // pagezero + text + data_const + linkedit
    }

    #[test]
    fn exec_fixture_bind_word_and_imports() {
        let mut b = exec_spec();
        let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
        let undef = b.add_symbol(SymbolSpec::Undefined {
            name: "_printf".into(),
            lib_ordinal: ord,
            weak: false,
        });
        let rebase_target = 0x1234;
        b.set_got(vec![
            SlotKind::Bind {
                sym_index: undef,
                addend: 0xfe,
            },
            SlotKind::Rebase {
                target: rebase_target,
            },
        ]);
        let img = b.build().unwrap();

        // Slot 0: bind word (bit 63 set), ordinal 0, inline addend 0xfe.
        let got_at = img
            .map
            .sections
            .iter()
            .find(|s| s.name == "__got")
            .unwrap()
            .fileoff as usize;
        let slot0 = u64::from_le_bytes(img.bytes[got_at..got_at + 8].try_into().unwrap());
        let w0 = pgr_format::fixups::ChainWord64::new(slot0);
        assert!(w0.is_bind());
        assert_eq!(w0.bind_ordinal(), 0);
        assert_eq!(w0.bind_addend(), 0xfe);
        // next stride: slot 1 - slot 0 = 8 bytes = 2 strides of 4.
        assert_eq!(w0.next(), 2);

        // Slot 1: rebase word (bit 63 clear), target preserved.
        let slot1 = u64::from_le_bytes(img.bytes[got_at + 8..got_at + 16].try_into().unwrap());
        let w1 = pgr_format::fixups::ChainWord64::new(slot1);
        assert!(!w1.is_bind());
        assert_eq!(w1.rebase_target(), rebase_target);
        assert_eq!(w1.next(), 0); // chain terminates

        // Import table decoded from the payload matches the map.
        let hdr = pgr_format::MachHeader64::parse(&img.bytes).unwrap();
        let mut it =
            pgr_format::LoadCommandIter::new(&img.bytes, 32, hdr.ncmds, hdr.sizeofcmds).unwrap();
        let mut fixups_payload = None;
        while let Some(cmd) = it.next_command().unwrap() {
            if cmd.kind == pgr_format::LoadCommandKind::LinkeditData(LC_DYLD_CHAINED_FIXUPS) {
                fixups_payload = Some(pgr_format::LinkeditDataCommand::parse(cmd.bytes).unwrap());
            }
        }
        let payload = fixups_payload.unwrap().data(&img.bytes).unwrap();
        let hdr2 = pgr_format::fixups::parse_header(payload).unwrap();
        assert_eq!(hdr2.imports_format, DYLD_CHAINED_IMPORT);
        let imports = pgr_format::fixups::parse_imports(payload, &hdr2).unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].lib_ordinal, 1);
        assert_eq!(imports[0].name_offset, 1);
        assert_eq!(img.map.imports[0].lib_ordinal, 1);
    }

    #[test]
    fn signature_recompute_matches() {
        use sha2::{Digest, Sha256};
        let mut b = exec_spec();
        b.add_dylib("/usr/lib/libSystem.B.dylib");
        let undef = b.add_symbol(SymbolSpec::Undefined {
            name: "_printf".into(),
            lib_ordinal: 1,
            weak: false,
        });
        b.set_got(vec![SlotKind::Bind {
            sym_index: undef,
            addend: 0,
        }]);
        let img = b.build().unwrap();
        let sig_off = img.map.sig_off as usize;
        let sb = SuperBlob::parse(&img.bytes[sig_off..]).unwrap();
        let blob = sb.blob_for_slot(CSSLOT_CODEDIRECTORY).unwrap().unwrap();
        let cd = CodeDirectory::parse(blob).unwrap();
        assert_eq!(cd.flags, CS_ADHOC);
        assert_eq!(cd.hash_type, CS_HASHTYPE_SHA256);
        assert_eq!(cd.page_size_log2, CS_PAGE_SIZE_LOG2);
        assert_eq!(cd.code_limit, img.map.sig_off as u32);
        let nblocks = img.map.sig_off.div_ceil(4096) as usize;
        assert_eq!(cd.n_code_slots as usize, nblocks);
        let hashes = cd.code_hashes(blob).unwrap();
        for p in 0..nblocks {
            let start = p * 4096;
            let end = ((p + 1) * 4096).min(sig_off);
            let mut h = Sha256::new();
            h.update(&img.bytes[start..end]);
            assert_eq!(&hashes[p * 32..(p + 1) * 32], h.finalize().as_slice());
        }
        assert_eq!(cd.identifier(blob).unwrap(), b"peregrine-fixture");
    }

    #[test]
    fn builds_are_deterministic() {
        let b = exec_spec();
        let a = b.build().unwrap();
        let c = b.build().unwrap();
        assert_eq!(a.bytes, c.bytes);
    }

    #[test]
    fn dylib_fixture_carries_id_dylib_and_trie() {
        let mut b = ImageBuilder::dylib("@rpath/libfixture.dylib", "peregrine-fixture-dylib");
        b.add_segment(SegmentSpec {
            name: "__TEXT".into(),
            maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
            initprot: VM_PROT_READ | VM_PROT_EXECUTE,
            sections: vec![SectionSpec {
                name: "__text".into(),
                align_log2: 2,
                flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
                data: filler(42, 32),
                relocs: Vec::new(),
            }],
        });
        let def = b.add_symbol(SymbolSpec::Defined {
            name: "_fixture_init".into(),
            section_index: 0,
        });
        assert_eq!(def, 0);
        let img = b.build().unwrap();
        let hdr = pgr_format::MachHeader64::parse(&img.bytes).unwrap();
        assert_eq!(hdr.filetype, MH_DYLIB);
        let summary = pgr_format::summarize(&img.bytes).unwrap();
        assert_eq!(summary.symbols, 1);
        assert_eq!(summary.external_symbols, 1);
        assert!(!summary.has_chained_fixups);
    }

    #[test]
    fn addend64_format_roundtrip() {
        let mut b = exec_spec();
        b.add_dylib("/usr/lib/libSystem.B.dylib");
        let undef = b.add_symbol(SymbolSpec::Undefined {
            name: "_printf".into(),
            lib_ordinal: 1,
            weak: false,
        });
        b.set_imports_format(ImportsFormat::Addend64);
        b.set_got(vec![SlotKind::Bind {
            sym_index: undef,
            addend: 7,
        }]);
        let img = b.build().unwrap();
        assert_eq!(img.map.imports[0].addend, 7);
        assert_eq!(img.map.imports_format, DYLD_CHAINED_IMPORT_ADDEND64);
        let got_at = img
            .map
            .sections
            .iter()
            .find(|s| s.name == "__got")
            .unwrap()
            .fileoff as usize;
        let slot0 = u64::from_le_bytes(img.bytes[got_at..got_at + 8].try_into().unwrap());
        let w = pgr_format::fixups::ChainWord64::new(slot0);
        // Table carries the addend under format 3; the word is inline-0.
        assert_eq!(w.bind_addend(), 0);
        assert_eq!(w.bind_ordinal(), 0);
    }
}

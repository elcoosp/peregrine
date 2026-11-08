//! Pass 3 — layout & address assignment (TDD §5 Pass 3, §8).
//!
//! Output sections are bucketed by `(segment, section_name)` in the fixed
//! canonical order (`__TEXT`: `__text, __const, __cstring, __chain_starts`;
//! `__DATA_CONST`: `__const, __got`; `__DATA`: `__data, __bss, __common`),
//! input sections become *pieces* (M1 keeps whole sections as pieces —
//! symbol-boundary atomization joins with `-dead_strip` at M5), segments
//! follow the 16 KiB packing contract and the constant-delta scheme
//! (`vmaddr = fileoff + 0x1_0000_0000`), and `__LINKEDIT` chunks take the
//! fixed ld64-compatible order (§8.2) with the signature last.
//!
//! The patch plan is *fully resolved* here: every patch carries absolute
//! operands, so Pass 4 (emit) only writes bits into the output buffer.
//!
//! Address/fixed-point structure (§5 Pass 3 step 3): `__chain_starts` lives
//! in `__TEXT` but its size depends on the fixup packing, which depends on
//! `__DATA` addresses. Head counts and page-relative slot offsets are
//! invariant under 16 KiB-aligned address shifts, so one re-run converges.

use crate::LinkError;
use crate::fixups::{FixupKind, FixupPlan, FixupSlot, plan_fixups_with_imports};
use crate::ids::{FileId, StringId};
use crate::interner::Interner;
use crate::object::{InputObject, RelocKind, RelocTarget};
use crate::resolve::{Def, Rank, Resolution, UndefinedPolicy};
use pgr_format::consts::{
    BIND_SPECIAL_DYLIB_FLAT_LOOKUP, INDIRECT_SYMBOL_LOCAL, MH_BINDS_TO_WEAK, MH_TWOLEVEL,
    MH_WEAK_DEFINES, N_ABS, N_EXT, N_PEXT, N_SECT, N_UNDF, N_WEAK_DEF, N_WEAK_REF, PAGE_SIZE_16K,
    PAGEZERO_SIZE_64, REFERENCED_DYNAMICALLY, S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS,
    S_CSTRING_LITERALS, S_NON_LAZY_SYMBOL_POINTERS, S_REGULAR, S_SYMBOL_STUBS, S_ZEROFILL,
    SECTION_TYPE_MASK, STUB_SIZE_ARM64, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use rayon::prelude::*;

/// The output image kind (M3): `-static`/dynamic executables, `-dylib`
/// dylibs and `-bundle` bundles. The kind drives the file type, the image
/// base (`0x1_0000_0000` for executables, `0` for dylibs/bundles), the load
/// command set (`LC_MAIN`/`LC_LOAD_DYLINKER` only for executables,
/// `LC_ID_DYLIB` only for dylibs) and the header flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputType {
    /// `MH_EXECUTE` (the M1/M2 default).
    #[default]
    Execute,
    /// `MH_DYLIB` (`-dylib`): exports its defined externs, carries
    /// `LC_ID_DYLIB`, no entry point.
    Dylib,
    /// `MH_BUNDLE` (`-bundle`): dlopen-able, no `LC_ID_DYLIB`, no entry
    /// point.
    Bundle,
}

impl OutputType {
    /// The Mach-O file type for this output kind.
    #[must_use]
    pub const fn filetype(self) -> u32 {
        match self {
            Self::Execute => pgr_format::consts::MH_EXECUTE,
            Self::Dylib => pgr_format::consts::MH_DYLIB,
            Self::Bundle => pgr_format::consts::MH_BUNDLE,
        }
    }

    /// The image base: `__PAGEZERO` vmsize for executables (the
    /// constant-delta contract `vmaddr = fileoff + base`), `0` for dylibs
    /// and bundles (the verifier's dylib contract: `__TEXT.vmaddr ==
    /// fileoff`).
    #[must_use]
    pub const fn image_base(self) -> u64 {
        match self {
            Self::Execute => PAGEZERO_SIZE_64,
            Self::Dylib | Self::Bundle => 0,
        }
    }

    /// True when the image loads as a program (entry point + dylinker).
    #[must_use]
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::Execute)
    }
}

/// Link configuration the layout pass consumes (driver-derived).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkConfig {
    /// Identifier embedded in the code signature (output-path leaf).
    pub ident: String,
    /// Output image kind (M3; executables remain the default).
    pub filetype: OutputType,
    /// Entry symbol name (`-e`, default `_main`; executables only).
    pub entry_symbol: String,
    /// `LC_BUILD_VERSION` platform (macOS at M1).
    pub platform: u32,
    /// Packed minimum OS version (`X.Y.Z` → `(X<<16)|(Y<<8)|Z`).
    pub minos: u32,
    /// Packed SDK version.
    pub sdk: u32,
    /// Emit `LC_LOAD_DYLINKER` (verifier-clean images; true-static binaries
    /// omit it — M1 keeps it, matching the M0 fixtures). Dylibs and bundles
    /// never carry it.
    pub dynamic_linker: bool,
    /// `-no_fixup_chains` disables the chained-fixups payload.
    pub fixup_chains: bool,
    /// `-no_adhoc` skips the ad-hoc signature.
    pub adhoc: bool,
    /// Input dylibs in `LC_LOAD_DYLIB`/`LC_REEXPORT_DYLIB` order (M2;
    /// parsed `.tbd` stubs, M3 Mach-O dylib scans).
    pub dylibs: Vec<crate::resolve::Dylib>,
    /// `-flat_namespace`: binds carry the flat-lookup ordinal and the
    /// image drops `MH_TWOLEVEL` (M2).
    pub flat_namespace: bool,
    /// `-undefined error|dynamic_lookup` (M2).
    pub undefined_policy: UndefinedPolicy,
    /// `-rpath` entries in command order (`LC_RPATH` per entry).
    pub rpaths: Vec<String>,
    /// `-source_version A.B.C.D.E` (packed; `LC_SOURCE_VERSION` when set).
    pub source_version: Option<u64>,
    /// M3 `-install_name` (dylibs): the `LC_ID_DYLIB` string. Defaults to
    /// the output path in the driver when unset.
    pub install_name: Option<String>,
    /// M3 `-current_version` (dylibs, packed).
    pub current_version: u32,
    /// M3 `-compatibility_version` (dylibs, packed).
    pub compatibility_version: u32,
    /// M3 `-exported_symbols_list`: when set, ONLY these names export
    /// (exact-name subset of ld64's glob form; see docs/COMPAT.md).
    pub exported_only: Option<Vec<Vec<u8>>>,
    /// M3 `-unexported_symbols_list`: names removed from the export surface
    /// (marked `N_PEXT` in the symtab, absent from the trie).
    pub unexported: Vec<Vec<u8>>,
    /// M3 `-mark_dead_strippable_dylib`: sets `MH_DEAD_STRIPPABLE_DYLIB`.
    pub dead_strippable: bool,
    /// M5 `-dead_strip`: drop unreferenced atoms (D12; roots are the entry,
    /// `-u` load symbols, all extern defs for dylibs/bundles,
    /// `__mod_init_func` and `S_ATTR_NO_DEAD_STRIP` sections).
    pub dead_strip: bool,
    /// M5 `-u`/`-load` symbol names (raw bytes): liveness roots that also
    /// seed the archive pull loop (a member defining one of these is
    /// pulled even when nothing references it).
    pub load_symbols: Vec<Vec<u8>>,
    /// M6 `-icf`: identical-code-folding level (default `None`, ld64's
    /// documented default; see [`crate::icf`]).
    pub icf: crate::icf::IcfMode,
    /// M8-c slack-aware layout (§7.3 "layout stability"): when `Some`, every
    /// user-content output section reserves growth room (the policy's
    /// padding) so an incremental relink usually reuses its placement. The
    /// default `None` keeps the v1.0 exact packing — clean links stay
    /// bit-deterministic either way (padding is a pure function of size).
    pub layout_slack: Option<crate::slack::SlackPolicy>,
    /// M9 cross-link anchors (§7.3 "layout stability"): the padded sizes the
    /// *previous* link reserved, consulted when slack is active so a changed
    /// section keeps its on-disk size while its content fits (the in-place
    /// patch tier's precondition). Empty by default — with no anchors the
    /// M8-c recomputed-pad behavior is reproduced exactly.
    pub slack_anchor: Vec<crate::slack::SlackAnchor>,
    /// M9 tier-2a import anchor (§7.3 step 5): the previous link's recorded
    /// import table. When set, the chained-fixups planner keeps every
    /// recorded bind ordinal and appends genuinely new imports — an edit
    /// that adds a bind no longer renumbers the table. `None` (the default,
    /// and every clean link) keeps first-use assignment bit-for-bit. The
    /// M6 classic path (`-no_fixup_chains`) ignores the anchor: its bind
    /// opcodes stay first-use (the tier-2a scope is the chained payload).
    pub stable_imports: Option<Vec<crate::stable_imports::StableImport>>,
    /// M9 tier-2a signature-boundary anchor: the previous link's `sig_off`.
    /// With slack active, the `__LINKEDIT` tail reservation keeps the
    /// signature where it was while the chunk stream grows into the
    /// reserved gap — the precondition for patching symtab/import growth in
    /// place. The boundary moves again (and the §7.3 ladder observes it)
    /// only when the chunks outgrow the reservation. `None` computes the
    /// boundary from the chunk stream alone (every clean link).
    pub sig_anchor: Option<u64>,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            ident: String::new(),
            filetype: OutputType::Execute,
            entry_symbol: "_main".into(),
            platform: pgr_format::consts::PLATFORM_MACOS,
            minos: 0x000c_0000, // 12.0.0
            sdk: 0x000e_0400,   // 14.4.0
            dynamic_linker: true,
            fixup_chains: true,
            adhoc: true,
            dylibs: Vec::new(),
            flat_namespace: false,
            undefined_policy: UndefinedPolicy::default(),
            rpaths: Vec::new(),
            source_version: None,
            install_name: None,
            current_version: 0,
            compatibility_version: 0,
            exported_only: None,
            unexported: Vec::new(),
            dead_strippable: false,
            dead_strip: false,
            load_symbols: Vec::new(),
            icf: crate::icf::IcfMode::default(),
            layout_slack: None,
            slack_anchor: Vec::new(),
            stable_imports: None,
            sig_anchor: None,
        }
    }
}

/// A resolved patch operand: emit applies these mechanically (TDD §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOp {
    /// ADRP: encode `page_delta` (signed 21-bit page count) at `in_offset`.
    Adrp {
        /// Patch position, piece-relative.
        in_offset: u32,
        /// Signed page delta (target page − pc page, in 4 KiB pages).
        page_delta: i64,
    },
    /// ADD/LDR/STR imm12: encode `imm12` at `in_offset`.
    PageOff12 {
        /// Patch position, piece-relative.
        in_offset: u32,
        /// The 12-bit page-offset immediate.
        imm12: u32,
    },
    /// `B`/`BL` imm26: encode `delta = target - pc` (4-aligned, ±128 MiB).
    Branch26 {
        /// Patch position, piece-relative.
        in_offset: u32,
        /// PC of the branch (diagnostics / range check).
        pc: u64,
        /// Signed byte delta to the target.
        delta: i64,
    },
    /// 8-byte absolute write (subtractor results).
    Write64 {
        /// Patch position, piece-relative.
        in_offset: u32,
        /// The resolved 64-bit value.
        value: u64,
    },
}

/// One contribution to an output section: a whole input section (M1) or a
/// zero-fill chunk (commons).
#[derive(Debug, Clone)]
pub struct Piece {
    /// Owning input file.
    pub file: FileId,
    /// Input section index within its file (`usize::MAX` for commons).
    pub in_sect: usize,
    /// Byte range in the input object (empty for zero-fill pieces).
    pub in_range: core::ops::Range<u64>,
    /// Destination offset within the output section.
    pub offset: u64,
    /// Piece size in bytes.
    pub size: u64,
    /// Piece alignment exponent.
    pub align_log2: u32,
    /// True when the piece is zero-filled.
    pub zerofill: bool,
    /// The common symbol this piece allocates (`__common` pieces only).
    pub common_name: Option<StringId>,
    /// Fully-resolved patches (piece-relative offsets).
    pub patches: Vec<PatchOp>,
    /// Chained-fixup pointer slots: `(piece-relative offset, kind)`.
    pub fixup_slots: Vec<(u32, FixupKind)>,
    /// Synthetic content (M2 `__got`/`__stubs` slots): emit copies these
    /// bytes instead of input data, then applies `patches`.
    pub synth: Option<SynthPiece>,
}

/// A synthetic output piece: what it is and the exact bytes emit writes
/// before applying `patches`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynthPiece {
    /// The synthetic slot's identity.
    pub kind: SynthKind,
    /// Bytes emit copies into the output (then patches).
    pub bytes: Vec<u8>,
}

/// A synthetic output piece's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynthKind {
    /// One `__DATA_CONST,__got` slot binding `name` (or rebasing to it).
    GotSlot {
        /// The referenced symbol.
        name: StringId,
    },
    /// One `__TEXT,__stubs` entry jumping through `name`'s GOT slot.
    StubSlot {
        /// The called symbol.
        name: StringId,
    },
    /// M6 branch veneer: `adrp x16/add x16/br x16` reaching `target`
    /// through ADRP's ±4 GiB window, inserted right after the branch site
    /// `(file, input section, reloc offset)` (see [`crate::thunks`]).
    Veneer {
        /// The branch site this veneer serves (identity + redirect key).
        site: (u32, usize, u32),
        /// What the original branch referenced.
        target: RelocTarget,
    },
}

/// An output section with its placed pieces.
#[derive(Debug, Clone)]
pub struct PlacedSection {
    /// Output section name (`__text`...).
    pub name: String,
    /// Owning output segment name.
    pub seg_name: String,
    /// Merged `S_*` flags.
    pub flags: u32,
    /// Section alignment exponent (max over pieces).
    pub align_log2: u32,
    /// Absolute vaddr of the section start.
    pub vm_addr: u64,
    /// Section size in bytes.
    pub size: u64,
    /// File offset (0 for zero-fill sections).
    pub file_off: u64,
    /// True when zero-fill (`S_ZEROFILL` output).
    pub zerofill: bool,
    /// Placed pieces, in canonical (file, section) order.
    pub pieces: Vec<Piece>,
}

/// One `LC_SEGMENT_64` plan entry.
#[derive(Debug, Clone)]
pub struct SegmentPlan {
    /// Segment name.
    pub name: String,
    /// vaddr start.
    pub vmaddr: u64,
    /// Virtual size (covers zero-fill tails).
    pub vmsize: u64,
    /// File offset.
    pub fileoff: u64,
    /// File-backed size.
    pub filesize: u64,
    /// Maximum protection.
    pub maxprot: u32,
    /// Initial protection.
    pub initprot: u32,
    /// Indices (into `Layout::sections`) of this segment's sections.
    pub sections: Vec<usize>,
}

/// `__LINKEDIT` chunk plan (§8.2 fixed order: fixup payload → trie →
/// function starts → symtab → strtab → UUID → signature).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkeditPlan {
    /// File offset of the chained-fixups payload (0 when absent).
    pub fixup_payload_off: u64,
    /// Payload size in bytes.
    pub fixup_payload_size: usize,
    /// Export trie file offset.
    pub trie_off: u64,
    /// Export trie size.
    pub trie_size: usize,
    /// Function-starts file offset.
    pub func_starts_off: u64,
    /// Function-starts size.
    pub func_starts_size: usize,
    /// Symbol table file offset.
    pub sym_off: u64,
    /// Symbol table size.
    pub sym_size: usize,
    /// String table file offset.
    pub str_off: u64,
    /// String table size.
    pub str_size: usize,
    /// Indirect symbol table file offset (0 when empty).
    pub indirect_off: u64,
    /// Indirect symbol table size in bytes (0 when empty).
    pub indirect_size: usize,
    /// Byte offset of the `LC_UUID` uuid field inside the header bytes.
    pub uuid_at: u64,
    /// Code signature file offset (16-aligned).
    pub sig_off: u64,
    /// Code signature size.
    pub sig_size: u64,
    /// Classic rebase stream file offset (0 when absent — M6 legacy).
    pub dyld_rebase_off: u64,
    /// Classic rebase stream size.
    pub dyld_rebase_size: usize,
    /// Classic bind stream file offset (0 when absent — M6 legacy).
    pub dyld_bind_off: u64,
    /// Classic bind stream size.
    pub dyld_bind_size: usize,
}

/// One output symbol-table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputSymbol {
    /// Interned name.
    pub name: StringId,
    /// `n_type` byte (`N_EXT | N_SECT` for defs, locals keep `N_SECT`/abs).
    pub n_type: u8,
    /// 1-based output section index (0 for absolute).
    pub n_sect: u8,
    /// `n_desc` (`N_WEAK_DEF` passthrough).
    pub n_desc: u16,
    /// Output vaddr (or absolute value).
    pub value: u64,
    /// True when the entry belongs in the dysymtab extdef subrange.
    pub external: bool,
}

/// The final Pass 3 product: everything Pass 4 needs to write bytes.
#[derive(Debug, Clone)]
pub struct Layout {
    /// Echo of the config identifier (the signature's identity string).
    pub ident: String,
    /// The Mach-O file type (`MH_EXECUTE`/`MH_DYLIB`/`MH_BUNDLE`).
    pub filetype: u32,
    /// The image base (`__PAGEZERO` vmsize for executables, `0` for
    /// dylibs/bundles): every absolute fixup/trie address is relative to it.
    pub image_base: u64,
    /// Output segments in command order (PAGEZERO first, LINKEDIT last).
    pub segments: Vec<SegmentPlan>,
    /// Output sections in file order.
    pub sections: Vec<PlacedSection>,
    /// `__LINKEDIT` chunk plan.
    pub linkedit: LinkeditPlan,
    /// M6 legacy fixups: the classic `LC_DYLD_INFO_ONLY` opcode streams
    /// (`None` when the image uses chained fixups or carries no slots).
    pub dyld_info: Option<crate::dyld_info::DyldInfoPlan>,
    /// Header + load-command bytes (the UUID field is zeroed; emit patches
    /// it after hashing).
    pub header_bytes: Vec<u8>,
    /// Byte offset of the `LC_MAIN` entryoff field inside the header bytes
    /// (executables only; 0 otherwise).
    pub entryoff_at: u64,
    /// Total file size.
    pub file_size: u64,
    /// Entry point offset within `__TEXT` (executables only).
    pub entryoff: u64,
    /// `__TEXT` vmsize (the signature's execSegLimit).
    pub text_vmsize: u64,
    /// Output symbol table in emission order.
    pub symbols: Vec<OutputSymbol>,
    /// Export trie bytes (full trie: defined externs + re-exports, M3).
    pub trie: Vec<u8>,
    /// Function-starts ULEB delta stream.
    pub func_starts: Vec<u8>,
    /// String table bytes.
    pub strtab: Vec<u8>,
    /// Per-symbol `n_strx` (parallel to `symbols`).
    pub str_offsets: Vec<u32>,
    /// Indirect symbol table (`__got` slots then `__stubs` slots).
    pub indirect_syms: Vec<u32>,
    /// Fixup plan (payload, slot words, imports, `__chain_starts` mirror).
    pub fixups: FixupPlan,
    /// Coalesced copy runs covering every byte-carrying input piece (M4,
    /// perf doc §4.3) — the fused tile emit's copy list, sorted by `dst`.
    pub runs: Vec<CopyRun>,
    /// Per-file D8 resolution tables (M4, perf doc §3 D8), parallel to the
    /// input objects (empty when `layout()` ran without objects).
    pub resolved: Vec<ResolvedFile>,
}

/// One coalesced copy (M4, perf doc §4.3 "copy-run coalescing"): contiguous
/// input bytes from one object landing at one contiguous output range.
/// Pass 3 emits the run list alongside the pieces; the fused tile emit
/// (pgr-emit Pass 4 v2) copies runs instead of walking pieces, turning
/// millions of small `memcpy`s into thousands of large ones. Runs never
/// cover synthetic or zero-fill pieces (those stay zero / carry their own
/// bytes) and never overlap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyRun {
    /// Owning input file.
    pub file: FileId,
    /// Byte range in the input object.
    pub src: core::ops::Range<u64>,
    /// Absolute output file offset.
    pub dst: u64,
}

/// Per-file flat resolution table (M4, perf doc §3 D8): the final output
/// vaddr of every input symbol and input section, materialized once after
/// placement and read by the relocation scan — one file-local array load
/// replaces the map walks of M1–M3. Emit's patch stream carries absolute
/// operands already, so this table is the *only* resolution de-indirection
/// the pipeline needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedFile {
    /// Input symbol index → output vaddr (0 when not an in-image definition).
    pub syms: Box<[u64]>,
    /// Input section index → output vaddr (0 when unplaced or zero-fill).
    pub sects: Box<[u64]>,
}

/// One output bucket: `(segment, name, merged flags, zerofill)`.
type BucketTable = Vec<(String, String, u32, bool)>;

/// GOT/stub synthesis needs gathered from a full reloc scan (M2).
#[derive(Debug, Default)]
struct SynthNeeds {
    /// GOT slots in first-use order (one per referenced name; the slot
    /// binds or rebases depending on the resolution).
    got: Vec<StringId>,
    /// Stub slots in first-use order (dylib calls).
    stubs: Vec<StringId>,
    /// Names every GOT slot is for (parallel to `got`, dedup helper).
    got_set: std::collections::BTreeSet<u32>,
    /// Names with stubs (dedup helper).
    stub_set: std::collections::BTreeSet<u32>,
}

impl SynthNeeds {
    fn push_got(&mut self, id: StringId) {
        if self.got_set.insert(id.0) {
            self.got.push(id);
        }
    }

    fn push_stub(&mut self, id: StringId) {
        self.push_got(id);
        if self.stub_set.insert(id.0) {
            self.stubs.push(id);
        }
    }
}

/// Scans every relocation of every input (Pass 3 step 0): classifies
/// external references into GOT/stub synthesis needs and direct binds, and
/// rejects the constructs a dynamic link cannot represent (direct page
/// relocs to externals — clang emits GOT-load relocs for those).
fn scan_needs(
    objects: &[InputObject],
    res: &Resolution,
    interner: &Interner,
    live: &crate::deadstrip::LiveSet,
) -> Result<SynthNeeds, LinkError> {
    let mut needs = SynthNeeds::default();
    for obj in objects {
        for (si, in_sect) in obj.sections.iter().enumerate() {
            for r in &in_sect.relocs {
                // Dead atoms contribute nothing (M5/D12): their references
                // synthesize no slots and reject nothing. O(log atoms).
                if live.is_active() {
                    let ranges = obj.atoms_of(si);
                    if !ranges.is_empty() {
                        let idx = ranges
                            .partition_point(|range| range.start <= u64::from(r.offset))
                            .saturating_sub(1);
                        if live.is_atom_dead(obj.file.0, si, ranges[idx].start) {
                            continue;
                        }
                    }
                }
                let RelocTarget::Extern(id) = r.target else {
                    continue;
                };
                if res.def(id).is_some() {
                    // Locally defined: GOT-kind relocs still demand a slot
                    // (a rebase into the slot); page/branch relocs patch
                    // directly as at M1.
                    match r.kind {
                        RelocKind::GotLoadPage21 { .. }
                        | RelocKind::GotLoadPageOff12 { .. }
                        | RelocKind::PointerToGot => needs.push_got(id),
                        _ => {}
                    }
                    continue;
                }
                if res.dylib_ordinal(id).is_none() && !res.is_dynamic_lookup(id) {
                    // Unresolvable at all: reported by require_all_resolved
                    // already; nothing to synthesize.
                    continue;
                }
                match r.kind {
                    RelocKind::Branch26 => needs.push_stub(id),
                    RelocKind::GotLoadPage21 { .. } | RelocKind::GotLoadPageOff12 { .. } => {
                        needs.push_got(id);
                    }
                    RelocKind::PointerToGot => needs.push_got(id),
                    RelocKind::Unsigned => {} // direct bind, no slot needed
                    RelocKind::Page21 { .. } | RelocKind::PageOff12 { .. } => {
                        return Err(LinkError::Unsupported {
                            file: obj.name.clone(),
                            message: format!(
                                "direct page relocation to external symbol \"{}\" — dynamic \
                                 references must go through the GOT (clang emits GOT-load \
                                 relocations for externals; ld64 rejects direct binds too)",
                                interner.name(id)
                            ),
                        });
                    }
                    RelocKind::Subtractor { .. } => {
                        return Err(LinkError::Unsupported {
                            file: obj.name.clone(),
                            message: format!(
                                "subtractor relocation against external symbol \"{}\" \
                                 (relative-pointer pairs must target in-image symbols)",
                                interner.name(id)
                            ),
                        });
                    }
                }
            }
        }
    }
    Ok(needs)
}

/// Scans every placed `Branch26` patch for an out-of-range delta and plans
/// one veneer per new overflow site (M6). A site that already carries a
/// veneer and still overflows means its atom alone spans more than the
/// arm64 branch range — unrecoverable without splitting input atoms, so
/// the link fails with a diagnostic (ld64 reports the same condition).
fn scan_branch_overflow(
    objects: &[InputObject],
    state: &PlacedState,
    planned: &[crate::thunks::VeneerSpec],
) -> Result<Vec<crate::thunks::VeneerSpec>, LinkError> {
    let mut specs: Vec<crate::thunks::VeneerSpec> = Vec::new();
    for fp in &state.flat {
        for op in &fp.piece.patches {
            let PatchOp::Branch26 {
                in_offset, delta, ..
            } = op
            else {
                continue;
            };
            if delta.abs() <= crate::thunks::BRANCH26_RANGE {
                continue;
            }
            let site = (fp.piece.file.0, fp.piece.in_sect, *in_offset);
            if planned.iter().any(|v| v.site == site) || specs.iter().any(|v| v.site == site) {
                return Err(LinkError::Layout {
                    message: format!(
                        "branch site {site:?} is out of arm64 branch range even with a veneer \
                         — a single atom spans more than ±128 MiB"
                    ),
                });
            }
            // The veneer targets what the original relocation named.
            let obj = objects
                .get(fp.piece.file.0 as usize)
                .ok_or(LinkError::Internal {
                    message: "overflow site file missing".into(),
                })?;
            let reloc = obj
                .sections
                .get(fp.piece.in_sect)
                .and_then(|s| s.relocs.iter().find(|r| r.offset == *in_offset))
                .ok_or(LinkError::Internal {
                    message: "overflow site relocation missing".into(),
                })?;
            specs.push(crate::thunks::VeneerSpec {
                site,
                target: reloc.target,
            });
        }
    }
    Ok(specs)
}

/// Buckets input sections by `(segment, name)`; returns the bucket table,
/// the per-file section→bucket map (`usize::MAX` = skipped) and the count
/// of chained-fixup pointer slots.
fn bucket_inputs(
    objects: &[InputObject],
    res: &Resolution,
) -> Result<(BucketTable, Vec<Vec<usize>>, usize), LinkError> {
    let mut buckets: Vec<(String, String, u32, bool)> = Vec::new(); // (seg, name, flags, zerofill)
    let mut bucket_of: Vec<Vec<usize>> = Vec::with_capacity(objects.len());
    let mut fixup_slot_count = 0usize;
    for obj in objects {
        let mut per_sect = Vec::with_capacity(obj.sections.len());
        for in_sect in &obj.sections {
            let bucket = bucket_for(in_sect, obj, &mut buckets, &mut fixup_slot_count)?;
            per_sect.push(bucket);
        }
        bucket_of.push(per_sect);
    }
    if res.definitions().any(|(_, d)| d.rank == Rank::Common)
        && !buckets
            .iter()
            .any(|(seg, name, _, _)| seg == "__DATA" && name == "__common")
    {
        buckets.push(("__DATA".into(), "__common".into(), S_ZEROFILL, true));
    }
    Ok((buckets, bucket_of, fixup_slot_count))
}

/// Classifies one input section into its output bucket.
fn bucket_for(
    in_sect: &crate::object::InputSection,
    obj: &InputObject,
    buckets: &mut BucketTable,
    fixup_slot_count: &mut usize,
) -> Result<usize, LinkError> {
    if in_sect.size == 0 {
        return Ok(usize::MAX);
    }
    let debugish = in_sect.segment.starts_with("__LLVM")
        || matches!(in_sect.segment.as_str(), "__LD" | "__DWARF");
    if debugish {
        return Ok(usize::MAX); // no load-time bytes at M1
    }
    if !matches!(
        in_sect.segment.as_str(),
        "__TEXT" | "__DATA_CONST" | "__DATA"
    ) {
        return Err(LinkError::Unsupported {
            file: obj.name.clone(),
            message: format!(
                "input section {} in segment {} (M1 buckets __TEXT/__DATA_CONST/__DATA only)",
                in_sect.name, in_sect.segment
            ),
        });
    }
    let zerofill = in_sect.zerofill || in_sect.flags & SECTION_TYPE_MASK == S_ZEROFILL;
    let name = if zerofill {
        // Zero-fill inputs and commons share the __common bucket
        // (S_ZEROFILL output; the kernel zero-fills the tail).
        "__common".to_string()
    } else {
        in_sect.name.clone()
    };
    *fixup_slot_count += in_sect
        .relocs
        .iter()
        .filter(|r| r.kind == RelocKind::Unsigned)
        .count();
    Ok(
        if let Some(i) = buckets
            .iter()
            .position(|(seg, n, _, _)| seg == &in_sect.segment && n == &name)
        {
            buckets[i].2 |= in_sect.flags;
            i
        } else {
            buckets.push((in_sect.segment.clone(), name, in_sect.flags, zerofill));
            buckets.len() - 1
        },
    )
}

/// Appends the synthesized `__chain_starts` bucket (when chains are on) and
/// the M2 GOT/stub buckets (when synthesis is needed), then applies the
/// canonical ordering.
fn prepare_buckets(
    buckets: &mut BucketTable,
    bucket_of: &mut [Vec<usize>],
    chains_enabled: bool,
    needs_got: bool,
    needs_stubs: bool,
) {
    if needs_got {
        buckets.push((
            "__DATA_CONST".into(),
            "__got".into(),
            S_NON_LAZY_SYMBOL_POINTERS,
            false,
        ));
    }
    if needs_stubs {
        buckets.push((
            "__TEXT".into(),
            "__stubs".into(),
            S_SYMBOL_STUBS | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            false,
        ));
    }
    if chains_enabled {
        buckets.push(("__TEXT".into(), "__chain_starts".into(), S_REGULAR, false));
    }
    // Canonical ordering: stable sort keeps first-seen order for unknowns.
    let mut order: Vec<usize> = (0..buckets.len()).collect();
    order.sort_by_key(|&i| (canonical_rank(&buckets[i].0, &buckets[i].1), i));
    let mut rank_of = vec![0usize; buckets.len()];
    for (pos, &i) in order.iter().enumerate() {
        rank_of[i] = pos;
    }
    *buckets = order.iter().map(|&i| buckets[i].clone()).collect();
    for per_file in bucket_of.iter_mut() {
        for b in per_file.iter_mut() {
            if *b != usize::MAX {
                *b = rank_of[*b];
            }
        }
    }
}

/// Canonical rank: segments ordered TEXT < `DATA_CONST` < DATA; known section
/// names in the fixed canonical order; unknown names follow in first-seen
/// order (deterministic; TDD §8.4).
fn canonical_rank(segment: &str, name: &str) -> u64 {
    let seg: u64 = match segment {
        "__TEXT" => 0,
        "__DATA_CONST" => 1,
        "__DATA" => 2,
        _ => 3,
    };
    let name: u64 = match (segment, name) {
        ("__TEXT", "__text") | ("__DATA_CONST", "__const") | ("__DATA", "__data") => 0,
        ("__TEXT", "__stubs") | ("__DATA_CONST", "__got") | ("__DATA", "__bss") => 1,
        ("__TEXT", "__const") | ("__DATA", "__common") => 2,
        ("__TEXT", "__cstring") => 3,
        ("__TEXT", "__chain_starts") => 4,
        _ => 100,
    };
    seg * 1000 + name
}

/// Placement intermediate: sections, segments, flat pieces, address tables.
struct PlacedState {
    sections: Vec<PlacedSection>,
    segments: Vec<SegmentPlan>,
    /// Flat piece list (section order, piece order within a section).
    flat: Vec<FlatPiece>,
    /// (file, input section) → output vaddr base.
    addr_of: std::collections::HashMap<(u32, usize), u64>,
    /// M5/D1: (file, input section) → sorted `(section-relative start,
    /// output vaddr)` per atom piece. Empty when no atomization happened;
    /// the resolution paths consult it for containment lookups.
    atom_addr: std::collections::HashMap<(u32, usize), Vec<(u64, u64)>>,
    /// Interned name id → output vaddr (all resolved definitions).
    def_addr: std::collections::BTreeMap<u32, u64>,
    /// Interned name id → GOT slot vaddr (M2, in `__got` order).
    got_slot_addr: std::collections::BTreeMap<u32, u64>,
    /// Interned name id → stub vaddr (M2, in `__stubs` order).
    stub_addr: std::collections::BTreeMap<u32, u64>,
    /// M6: branch site `(file, in_sect, reloc offset)` → veneer vaddr.
    /// The relocation scan redirects out-of-range branches through this
    /// table instead of erroring.
    veneer_addr_of: std::collections::HashMap<(u32, usize, u32), u64>,
}

/// One flat piece: output section, position within its piece list, absolute
/// vaddr, and the piece (patches resolved in place).
#[derive(Debug, Clone)]
struct FlatPiece {
    section: usize,
    piece_idx: usize,
    addr: u64,
    piece: Piece,
}

/// Chained fixups require macOS ≥ 12 (TDD §3.6 invariant 3); older
/// deployment targets and `-no_fixup_chains` fall back to the classic
/// `LC_DYLD_INFO_ONLY` streams (M6).
pub const CHAINED_FIXUPS_MIN_MINOS: u32 = 0x000C_0000;

/// The `__LINKEDIT` tail reservation (M9 tier-2a, slack-mode links only):
/// room between the last chunk and the code signature for the chunk stream
/// to grow into — symtab entries (16 B each), import-table entries (8 B),
/// longer strings, longer streams. One 4 KiB hash page of headroom absorbs
/// ~250 symbol-table edits before the boundary moves and the §7.3 ladder
/// re-runs the full link; the reservation costs 4 KiB of zeros per
/// `-incremental` image and nothing on clean links.
pub const LINKEDIT_SLACK: u64 = 4096;

/// Lays out the image (Pass 3). See the module docs for the fixed-point
/// structure.
///
/// # Errors
/// [`LinkError::Layout`] on contract violations (header page overflow,
/// branch range), [`LinkError::Symbol`] on unresolvable references,
/// [`LinkError::Unsupported`] on M1-rejected input shapes.
pub fn layout(
    objects: &[InputObject],
    res: &Resolution,
    interner: &Interner,
    cfg: &LinkConfig,
    live: &crate::deadstrip::LiveSet,
    fold: &crate::icf::FoldPlan,
) -> Result<Layout, LinkError> {
    // Constant-delta base: `__PAGEZERO` vmsize for executables, 0 for
    // dylibs/bundles (M3). Every address math derives from this.
    let image_base = cfg.filetype.image_base();
    // ---- bucketing ---------------------------------------------------------
    let (mut buckets, mut bucket_of, fixup_slot_count) = bucket_inputs(objects, res)?;
    // M2: GOT/stub synthesis needs (first-use scan over every relocation).
    let needs = scan_needs(objects, res, interner, live)?;
    // The fixups payload exists when *any* slot is planned: input pointer
    // slots (M1 rebases), synthesized GOT binds and POINTER_TO_GOT rebases.
    let has_fixups = fixup_slot_count > 0 || !needs.got.is_empty();
    let use_chains = cfg.fixup_chains && has_fixups && cfg.minos >= CHAINED_FIXUPS_MIN_MINOS;
    let chains_enabled = use_chains;
    if std::env::var("PGR_DEBUG_LAYOUT").is_ok() {
        eprintln!(
            "[layout] fixup_chains={} has_fixups={} slot_count={} got={} minos={:#x} use_chains={}",
            cfg.fixup_chains,
            has_fixups,
            fixup_slot_count,
            needs.got.len(),
            cfg.minos,
            use_chains
        );
        for (i, o) in objects.iter().enumerate() {
            if std::env::var("PGR_DEBUG_LAYOUT").is_ok() {
                eprintln!(
                    "[layout] obj {i} {} relocs {:?}",
                    o.name,
                    o.sections
                        .iter()
                        .map(|s| s.relocs.len())
                        .collect::<Vec<_>>()
                );
            }
        }
    }
    let fixup_lc_kind = if use_chains {
        FixupLc::Chained
    } else if has_fixups {
        FixupLc::DyldInfo
    } else {
        FixupLc::None
    };
    prepare_buckets(
        &mut buckets,
        &mut bucket_of,
        chains_enabled,
        !needs.got.is_empty(),
        !needs.stubs.is_empty(),
    );

    // ---- commons (name-sorted for deterministic allocation) ----------------
    let mut commons: Vec<(StringId, &Def)> = res
        .definitions()
        .filter(|(_, d)| d.rank == Rank::Common)
        .collect();
    commons.sort_by(|a, b| interner.bytes(a.0).cmp(interner.bytes(b.0)));

    // ---- placement fixed-point loop -----------------------------------------
    // Two convergence conditions: the `__chain_starts` size assumption (M2)
    // and the M6 veneer set — an out-of-range `Branch26` patch adds a veneer
    // spec, the next iteration places it, and the loop re-resolves. Both
    // converge fast (chain size twice; veneers typically one extra round).
    let mut chain_starts_size = 8usize;
    let mut veneers: Vec<crate::thunks::VeneerSpec> = Vec::new();
    let mut converged: Option<PlacedState> = None;
    let mut final_plan: Option<FixupPlan> = None;
    let mut final_dyld_info: Option<crate::dyld_info::DyldInfoPlan> = None;
    for _ in 0..16 {
        let mut state = place(
            cfg,
            objects,
            &buckets,
            &bucket_of,
            &commons,
            chain_starts_size,
            &needs,
            fixup_lc_kind,
            live,
            fold,
            &veneers,
        )?;
        resolve_all(objects, &mut state, res, interner, cfg, fold)?;
        // M6 veneer scan: every out-of-range branch site plans one veneer.
        let new_specs = scan_branch_overflow(objects, &state, &veneers)?;
        let mut slots: Vec<FixupSlot> = Vec::new();
        for fp in &state.flat {
            for (off, kind) in &fp.piece.fixup_slots {
                slots.push(FixupSlot {
                    vaddr: fp.addr + u64::from(*off),
                    kind: *kind,
                });
            }
        }
        let segs: Vec<(u64, u64, u64)> = state
            .segments
            .iter()
            .map(|s| (s.vmaddr, s.vmsize, s.fileoff))
            .collect();
        let plan = if !has_fixups {
            // No pointer slots at all: no fixup metadata of either kind.
            FixupPlan {
                payload: Vec::new(),
                payload_off: 0,
                slot_words: Vec::new(),
                chain_starts: Vec::new(),
                slot_count: 0,
                imports: Vec::new(),
                import_names: Vec::new(),
                has_weak_binds: false,
                stable_keys: Vec::new(),
            }
        } else if chains_enabled {
            plan_fixups_with_imports(
                slots,
                &segs,
                image_base,
                PAGE_SIZE_16K,
                interner,
                cfg.stable_imports.as_deref(),
            )?
        } else {
            // M6 legacy: the classic opcode streams replace the chained
            // payload (no `__chain_starts`; slot bytes stay zero). The
            // import metadata (symtab/indirect construction reads it) is
            // built identically to the chained path.
            slots.sort_by_key(|s| s.vaddr);
            let (imports, import_names, has_weak, keys) =
                crate::fixups::build_import_table(&slots, interner);
            let stable_keys = keys
                .iter()
                .map(crate::fixups::import_key_identity)
                .collect();
            let info = crate::dyld_info::plan_dyld_info(slots, &segs, interner)?;
            if info.is_present() {
                final_dyld_info = Some(info.clone());
            }
            FixupPlan {
                payload: Vec::new(),
                payload_off: 0,
                slot_words: Vec::new(),
                chain_starts: Vec::new(),
                slot_count: 0,
                imports,
                import_names,
                has_weak_binds: has_weak || info.has_weak_binds,
                stable_keys,
            }
        };
        let actual = if chains_enabled {
            plan.chain_starts.len()
        } else {
            0
        };
        if actual == chain_starts_size && new_specs.is_empty() {
            // Converged: patch the section size (it equals the assumption).
            if let Some(cs) = state
                .sections
                .iter_mut()
                .find(|s| s.name == "__chain_starts")
            {
                cs.size = actual as u64;
            }
            final_plan = Some(plan);
            converged = Some(state);
            break;
        }
        chain_starts_size = actual;
        veneers.extend(new_specs);
    }
    let mut state = converged.ok_or(LinkError::Internal {
        message: "layout fixed point did not converge in 16 iterations".into(),
    })?;
    let fixups = final_plan.ok_or(LinkError::Internal {
        message: "fixup plan missing after convergence".into(),
    })?;
    // `None` for the chained path *and* for slot-less links; `Some` only
    // when classic streams carry bytes.
    let dyld_info = final_dyld_info;

    // ---- export visibility (M3) ------------------------------------------------
    // `-exported_symbols_list` restricts the surface to the listed names;
    // `-unexported_symbols_list` removes names. Hidden externals stay in the
    // symtab as private externals (`N_PEXT`) — ld64's behavior — and never
    // reach the trie.
    let visible = |name: &[u8]| -> bool {
        if let Some(only) = &cfg.exported_only {
            if !only.iter().any(|n| n.as_slice() == name) {
                return false;
            }
        }
        !cfg.unexported.iter().any(|n| n.as_slice() == name)
    };

    // ---- symbol table ---------------------------------------------------------
    let symtab_ctx = SymtabContext {
        sections: &state.sections,
        addr_of: &state.addr_of,
        atom_addr: &state.atom_addr,
        live,
        fold,
    };
    let mut symbols = build_symtab(objects, res, interner, &commons, &visible, &symtab_ctx);
    // `__mh_execute_header`: the image's own exported header symbol (ld64
    // and lld both emit it; the M2 trie lists it).
    // `link()` always interns the name; direct `layout()` callers without
    // it simply skip the entry.
    let text_vmaddr = state
        .segments
        .iter()
        .find(|s| s.name == "__TEXT")
        .map_or(PAGEZERO_SIZE_64, |s| s.vmaddr);
    let mh_header_sect = state
        .sections
        .iter()
        .position(|s| s.seg_name == "__TEXT" && s.size > 0)
        .map_or(1, |i| (i + 1) as u8);
    if let Some(id) = interner.lookup(b"__mh_execute_header") {
        if visible(b"__mh_execute_header") {
            symbols.push(OutputSymbol {
                name: id,
                n_type: N_EXT | N_SECT,
                n_sect: mh_header_sect,
                n_desc: REFERENCED_DYNAMICALLY,
                value: text_vmaddr,
                external: true,
            });
        }
    }

    // Undefined externals (dylib exports + dynamic lookups), in import
    // order — the two-level ordinals live in `n_desc` (TDD §3.3).
    let mut undef_syms: Vec<OutputSymbol> = Vec::new();
    for imp in &fixups.imports {
        // The import table's name pool order matches `imports`; recover the
        // name from the pool to re-intern.
        let name = fixups
            .import_names
            .get(imp.name_offset as usize..)
            .and_then(|rest| {
                let end = rest.iter().position(|&b| b == 0)?;
                Some(&rest[..end])
            })
            .unwrap_or(b"");
        let Some(id) = interner.lookup(name) else {
            return Err(LinkError::Internal {
                message: format!(
                    "import name {} missing from the interner",
                    String::from_utf8_lossy(name)
                ),
            });
        };
        let desc = if imp.lib_ordinal > res.dylibs().len() as u16
            && imp.lib_ordinal < BIND_SPECIAL_DYLIB_FLAT_LOOKUP
        {
            return Err(LinkError::Internal {
                message: "import ordinal outside the LC_LOAD_DYLIB list".into(),
            });
        } else {
            (imp.lib_ordinal << 8) | (u16::from(imp.weak_import) * N_WEAK_REF)
        };
        undef_syms.push(OutputSymbol {
            name: id,
            n_type: N_EXT | N_UNDF,
            n_sect: 0,
            n_desc: desc,
            value: 0,
            external: true,
        });
    }
    // One symtab entry per undefined name (multiple addends of one name
    // share the entry; the first import's ordinal wins).
    let mut undef_seen: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for u in &undef_syms {
        if undef_seen.insert(u.name.0) {
            symbols.push(u.clone());
        }
    }

    let n_locals = symbols.iter().filter(|s| !s.external).count();
    let n_defs = symbols
        .iter()
        .filter(|s| s.external && s.n_type & pgr_format::consts::N_TYPE != N_UNDF)
        .count();
    let n_undef = symbols
        .iter()
        .filter(|s| s.external && s.n_type & pgr_format::consts::N_TYPE == N_UNDF)
        .count();

    // ---- string table (dedup by interned name, emission order) ----------------
    let mut strtab: Vec<u8> = vec![0];
    let mut str_by_id: std::collections::BTreeMap<u32, u32> = std::collections::BTreeMap::new();
    for sym in &symbols {
        str_by_id.entry(sym.name.0).or_insert_with(|| {
            let o = strtab.len() as u32;
            strtab.extend_from_slice(interner.bytes(sym.name));
            strtab.push(0);
            o
        });
    }

    // Per-symbol string-table offsets (emit writes n_strx from these).
    let str_offsets: Vec<u32> = symbols.iter().map(|sym| str_by_id[&sym.name.0]).collect();

    // ---- function starts ---------------------------------------------------------
    let func_starts = build_func_starts(&state.sections, &symbols);

    // ---- indirect symbol table (M2): __got slots then __stubs slots ------
    // Entries name the symtab entry each pointer slot stands for (TDD
    // §3.3); `INDIRECT_SYMBOL_LOCAL` covers slots that only rebase.
    // (Hash map: O(1) lookups keep the pass linear in the M4 shapes.)
    let mut sym_index: std::collections::HashMap<u32, u32> =
        std::collections::HashMap::with_capacity(symbols.len());
    for (i, s) in symbols.iter().enumerate() {
        sym_index.entry(s.name.0).or_insert(i as u32);
    }
    let mut indirect_syms: Vec<u32> = Vec::new();
    for id in &needs.got {
        match sym_index.get(&id.0) {
            Some(i) => indirect_syms.push(*i),
            None => indirect_syms.push(INDIRECT_SYMBOL_LOCAL),
        }
    }
    for id in &needs.stubs {
        match sym_index.get(&id.0) {
            Some(i) => indirect_syms.push(*i),
            None => indirect_syms.push(INDIRECT_SYMBOL_LOCAL),
        }
    }

    // ---- export trie (M3 full trie) -----------------------------------------
    // Defined externs (visible ones) + `__mh_execute_header` carry regular
    // addresses; `-reexport_library` exports become REEXPORT nodes with the
    // dylib's 1-based ordinal. Local definitions shadow re-exports of the
    // same name (the trie builder keeps the first of each equal name).
    let mut exports: Vec<crate::trie::Export> = Vec::new();
    for sym in &symbols {
        if !sym.external || sym.n_type & N_SECT == 0 {
            continue;
        }
        let name = interner.bytes(sym.name);
        if !visible(name) {
            continue;
        }
        let flags = u32::from(sym.n_desc & N_WEAK_DEF != 0)
            * crate::trie::EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION;
        exports.push(crate::trie::Export {
            name,
            info: crate::trie::ExportInfo::Regular {
                flags,
                address: sym.value,
            },
        });
    }
    for (ord, d) in cfg.dylibs.iter().enumerate() {
        if !d.reexport {
            continue;
        }
        for name in &d.exports {
            if !visible(name) {
                continue;
            }
            exports.push(crate::trie::Export {
                name,
                info: crate::trie::ExportInfo::Reexport {
                    ordinal: u64::try_from(ord + 1).unwrap_or(1),
                    imported_name: b"",
                },
            });
        }
    }
    let trie = crate::trie::build(&mut exports, image_base)?;
    let has_reexports = cfg.dylibs.iter().any(|d| d.reexport);

    // ---- entry (executables only; dylibs/bundles have no LC_MAIN) --------------
    let entryoff = if cfg.filetype.is_executable() {
        let entry_id = interner
            .lookup(cfg.entry_symbol.as_bytes())
            .ok_or(LinkError::Symbol {
                name: cfg.entry_symbol.clone(),
                message: format!(
                    "entry symbol \"{}\" is not defined by any input",
                    cfg.entry_symbol
                ),
            })?;
        let entry_vaddr = state
            .def_addr
            .get(&entry_id.0)
            .copied()
            .ok_or(LinkError::Symbol {
                name: cfg.entry_symbol.clone(),
                message: format!(
                    "entry symbol \"{}\" is not defined by any input",
                    cfg.entry_symbol
                ),
            })?;
        entry_vaddr - image_base
    } else {
        0
    };

    // ---- __LINKEDIT chunks + signature sizing --------------------------------------
    let fixup_payload_size = if fixups.slot_count > 0 && chains_enabled {
        fixups.payload.len()
    } else {
        0
    };
    let dyld_rebase_size = dyld_info.as_ref().map_or(0, |d| {
        if d.rebase.is_empty() {
            0
        } else {
            d.rebase.len()
        }
    });
    let dyld_bind_size = dyld_info
        .as_ref()
        .map_or(0, |d| if d.bind.is_empty() { 0 } else { d.bind.len() });
    let le_idx = state
        .segments
        .iter()
        .position(|s| s.name == "__LINKEDIT")
        .ok_or(LinkError::Internal {
            message: "no __LINKEDIT segment".into(),
        })?;
    let mut cur = state.segments[le_idx].fileoff;
    let take = |size: usize, align: u64, cur: &mut u64| {
        *cur = cur.div_ceil(align) * align;
        let at = *cur;
        *cur += size as u64;
        at
    };
    let fixup_payload_off = if fixup_payload_size > 0 {
        take(fixup_payload_size, 8, &mut cur)
    } else {
        0
    };
    // M6 classic streams occupy the fixup payload's LINKEDIT slot.
    let dyld_rebase_off = if dyld_rebase_size > 0 {
        take(dyld_rebase_size, 8, &mut cur)
    } else {
        0
    };
    let dyld_bind_off = if dyld_bind_size > 0 {
        take(dyld_bind_size, 8, &mut cur)
    } else {
        0
    };
    let trie_off = take(trie.len(), 4, &mut cur);
    let func_off = if func_starts.is_empty() {
        0
    } else {
        take(func_starts.len(), 4, &mut cur)
    };
    let sym_off = take(symbols.len() * 16, 8, &mut cur);
    let str_off = take(strtab.len(), 8, &mut cur);
    let indirect_off = take(indirect_syms.len() * 4, 4, &mut cur);
    let (sig_off, sig_size, file_size) = if cfg.adhoc {
        // M9 tier-2a (§7.3 "Rebuild LINKEDIT pieces that changed — each is
        // a local edit when slack exists"): with slack active, the chunk
        // stream gets a tail reservation before the signature — the first
        // slack link reserves [`LINKEDIT_SLACK`] bytes, and an anchored
        // relink keeps the boundary while the chunks grow into the gap
        // (symtab entries, import-table growth, longer strings). Chunks
        // beyond the reservation move the boundary and the ladder observes
        // it. Without slack the boundary hugs the chunks exactly (the v1.0
        // bytes, bit-for-bit).
        let raw = match (cfg.layout_slack.is_some(), cfg.sig_anchor) {
            (true, Some(anchor)) if cur <= anchor => anchor,
            (true, None) => cur + LINKEDIT_SLACK,
            (_, _) => cur,
        };
        let aligned = raw.div_ceil(16) * 16;
        let nblocks = aligned.div_ceil(4096);
        let ident_padded = align_up_usize(cfg.ident.len() + 1, 4);
        let dir_len = 88 + ident_padded + (nblocks as usize) * 32;
        let blob = align_up_usize(12 + 8 + dir_len, 8) as u64;
        (aligned, blob, aligned + blob)
    } else {
        (0, 0, cur)
    };

    // __LINKEDIT covers through EOF (§8: verifier asserts this).
    let le_size = file_size - state.segments[le_idx].fileoff;
    state.segments[le_idx].filesize = le_size;
    state.segments[le_idx].vmsize =
        le_size.max(PAGE_SIZE_16K).div_ceil(PAGE_SIZE_16K) * PAGE_SIZE_16K;
    let text_vmsize = state
        .segments
        .iter()
        .find(|s| s.name == "__TEXT")
        .map_or(0, |s| s.vmsize);

    // ---- header + load commands -----------------------------------------------------
    let header_inputs = HeaderInputs {
        filetype: cfg.filetype,
        sym_off,
        nsyms: symbols.len(),
        str_off,
        strsize: strtab.len(),
        n_locals,
        n_defs,
        n_undef,
        indirect_off,
        indirect_count: indirect_syms.len(),
        fixup_off: fixup_payload_off,
        fixup_size: fixup_payload_size,
        dyld_rebase_off,
        dyld_rebase_size,
        dyld_bind_off,
        dyld_bind_size,
        trie_off,
        trie_len: trie.len(),
        func_off,
        func_len: func_starts.len(),
        sig_off,
        sig_size,
        entryoff,
        install_name: cfg.install_name.clone(),
        current_version: cfg.current_version,
        compatibility_version: cfg.compatibility_version,
        dylibs: cfg.dylibs.clone(),
        rpaths: cfg.rpaths.clone(),
        source_version: cfg.source_version,
        flat_namespace: cfg.flat_namespace,
        binds_to_weak: fixups.has_weak_binds || res.any_weak_bind(objects),
        weak_defines: res.definitions().any(|(_, d)| d.weak) || cfg.dylibs.iter().any(|d| d.weak),
        has_reexports,
        dead_strippable: cfg.dead_strippable,
    };
    let (header_bytes, uuid_at, entryoff_at) =
        build_header(cfg, &state.segments, &state.sections, &header_inputs)?;

    // The coalescing + D8 tables read the placed state before it moves into
    // the Layout.
    let runs = coalesce_runs(&state.sections);
    let resolved = build_resolved_tables(
        objects,
        &state.addr_of,
        &state.def_addr,
        res,
        &state.atom_addr,
        fold,
    );

    Ok(Layout {
        ident: cfg.ident.clone(),
        filetype: cfg.filetype.filetype(),
        image_base,
        segments: state.segments,
        sections: state.sections,
        linkedit: LinkeditPlan {
            fixup_payload_off,
            fixup_payload_size,
            trie_off,
            trie_size: trie.len(),
            func_starts_off: func_off,
            func_starts_size: func_starts.len(),
            sym_off,
            sym_size: symbols.len() * 16,
            str_off,
            str_size: strtab.len(),
            indirect_off,
            indirect_size: indirect_syms.len() * 4,
            uuid_at,
            sig_off,
            sig_size,
            dyld_rebase_off,
            dyld_rebase_size,
            dyld_bind_off,
            dyld_bind_size,
        },
        dyld_info,
        header_bytes,
        entryoff_at,
        file_size,
        entryoff,
        text_vmsize,
        symbols,
        trie,
        func_starts,
        strtab,
        str_offsets,
        indirect_syms,
        fixups,
        runs,
        resolved,
    })
}

/// Copy-run coalescing (M4, perf doc §4.3): merge consecutive byte-carrying
/// pieces that are adjacent in *both* the input object and the output image
/// into one [`CopyRun`]. Without dead-strip or ordering (M5) a whole input
/// section is already one piece, so runs stay section-granular; the merge
/// pays off as soon as pieces multiply (commons adjacency, M5 splits).
fn coalesce_runs(sections: &[PlacedSection]) -> Vec<CopyRun> {
    let mut runs: Vec<CopyRun> = Vec::new();
    for s in sections {
        if s.zerofill {
            continue;
        }
        for p in &s.pieces {
            if p.zerofill || p.synth.is_some() || p.in_range.is_empty() {
                continue;
            }
            let dst = s.file_off + p.offset;
            match runs.last_mut() {
                Some(last)
                    if last.file == p.file
                        && last.src.end == p.in_range.start
                        && last.dst + (last.src.end - last.src.start) == dst =>
                {
                    last.src.end = p.in_range.end;
                }
                _ => runs.push(CopyRun {
                    file: p.file,
                    src: p.in_range.clone(),
                    dst,
                }),
            }
        }
    }
    // Sections arrive in file order, so `runs` is already dst-sorted; sort
    // anyway to keep the invariant local to this function.
    runs.sort_by_key(|r| r.dst);
    runs
}

/// Materializes the per-file D8 resolution tables (perf doc §3 D8): a
/// sequential, prefetch-friendly parallel pass over the objects writing the
/// final vaddr of every input symbol and section. The relocation scan then
/// reads one file-local array instead of walking global maps. Commons
/// (which carry no input section) resolve through the placed `__common`
/// piece addresses in `def_addr`.
fn build_resolved_tables(
    objects: &[InputObject],
    addr_of: &std::collections::HashMap<(u32, usize), u64>,
    def_addr: &std::collections::BTreeMap<u32, u64>,
    res: &Resolution,
    atom_addr: &std::collections::HashMap<(u32, usize), Vec<(u64, u64)>>,
    fold: &crate::icf::FoldPlan,
) -> Vec<ResolvedFile> {
    // Commons resolve through the `__common` pieces; carry their final
    // addresses per (file, sym) so the flat tables cover every definition.
    let mut common_addr: Vec<Vec<(usize, u64)>> = vec![Vec::new(); objects.len()];
    for (id, def) in res.definitions() {
        if def.rank == Rank::Common && def.section.is_none() {
            if let Some(&addr) = def_addr.get(&id.0) {
                common_addr[def.file.0 as usize].push((def.sym, addr));
            }
        }
    }
    objects
        .par_iter()
        .zip(common_addr)
        .map(|(obj, commons)| {
            let mut syms: Vec<u64> = vec![0; obj.symbols.len()];
            for (i, sym) in obj.symbols.iter().enumerate() {
                if let Some(sect) = sym.section {
                    // M5/D1: atom-aware when the section split into pieces;
                    // M6 ICF: folded atoms redirect to the canonical copy.
                    if let Some(vaddr) = fold_aware_addr(
                        fold, objects, atom_addr, addr_of, obj.file.0, sect, sym.value,
                    ) {
                        syms[i] = vaddr;
                    }
                }
            }
            for (sym_idx, addr) in commons {
                syms[sym_idx] = addr;
            }
            let sects: Vec<u64> = (0..obj.sections.len())
                .map(|idx| addr_of.get(&(obj.file.0, idx)).copied().unwrap_or(0))
                .collect();
            ResolvedFile {
                syms: syms.into_boxed_slice(),
                sects: sects.into_boxed_slice(),
            }
        })
        .collect()
}

/// The containing atom's start of `off` (None for un-atomized lookups).
fn containing_atom_start(obj: &InputObject, sect: usize, off: u64) -> Option<u64> {
    let ranges = obj.atoms_of(sect);
    if ranges.is_empty() {
        return None;
    }
    let idx = ranges.partition_point(|r| r.start <= off).saturating_sub(1);
    ranges.get(idx).map(|r| r.start)
}

/// M6 ICF: the address of `(file, sect, value)`. Symbols inside folded
/// atoms resolve to the canonical copy's address with the in-atom offset
/// preserved; everything else takes the plain atom/section path.
fn fold_aware_addr(
    fold: &crate::icf::FoldPlan,
    objects: &[InputObject],
    atom_addr: &std::collections::HashMap<(u32, usize), Vec<(u64, u64)>>,
    addr_of: &std::collections::HashMap<(u32, usize), u64>,
    file: u32,
    sect: usize,
    value: u64,
) -> Option<u64> {
    if !fold.is_empty()
        && let Some(obj) = objects.get(file as usize)
        && let Some(atom_start) = containing_atom_start(obj, sect, value)
        && let Some((cf, cs, cstart)) = fold.canonical_of(file, sect, atom_start)
    {
        if let Some(atoms) = atom_addr.get(&(cf, cs)) {
            let idx = atoms
                .partition_point(|(start, _)| *start <= cstart)
                .saturating_sub(1);
            if let Some(&(start, out)) = atoms.get(idx)
                && start == cstart
            {
                return Some(out + (value - atom_start));
            }
        }
        // The canonical atom is missing from placement: a folded atom whose
        // canonical copy was not placed — a resolution bug upstream.
        return None;
    }
    atom_or_section_addr(atom_addr, addr_of, file, sect, value)
}

/// One `__cstring` literal instance (D4): a string atom of one input
/// section, with the canonical instance it resolves to (itself when no
/// earlier live copy exists). The piece list carries only canonical
/// instances; every instance gets an `atom_addr` remap entry so references
/// into duplicates land on the single output copy.
#[derive(Debug, Clone)]
pub struct CStringInstance {
    /// Owning input file.
    pub file: u32,
    /// Input section index.
    pub sect: usize,
    /// Section-relative start of the string (the atom start).
    pub start: u64,
    /// Section-relative end (past the NUL).
    pub end: u64,
    /// Index of the canonical instance in the same vector.
    pub canonical: usize,
}

/// Builds the per-bucket piece lists (offsets assigned later by `place`).
/// With dead-strip active (M5/D12), every live atom becomes one piece and
/// dead atoms are dropped; without it the M1–M4 shape (one piece per input
/// section) is preserved byte-for-byte. `S_CSTRING_LITERALS` buckets always
/// take the D4 path: one piece per unique string (first live instance
/// canonical), every instance recorded for the remap table.
fn build_bucket_pieces(
    objects: &[InputObject],
    buckets: &BucketTable,
    bucket_of: &[Vec<usize>],
    commons: &[(StringId, &Def)],
    live: &crate::deadstrip::LiveSet,
    fold: &crate::icf::FoldPlan,
) -> Result<(Vec<Vec<Piece>>, Vec<(usize, Vec<CStringInstance>)>), LinkError> {
    let mut pieces_of_bucket: Vec<Vec<Piece>> = vec![Vec::new(); buckets.len()];
    let mut cstring_instances: Vec<(usize, Vec<CStringInstance>)> = Vec::new();
    // D4 dedup: per cstring bucket, content → canonical instance index.
    // Hash-map lookup keeps the pass linear (the M4 discipline: no O(n²)
    // scans).
    let mut cstring_dedup: std::collections::HashMap<
        usize,
        std::collections::HashMap<Vec<u8>, usize>,
    > = std::collections::HashMap::new();
    for obj in objects {
        for (si, in_sect) in obj.sections.iter().enumerate() {
            let bi = bucket_of
                .get(obj.file.0 as usize)
                .and_then(|v| v.get(si))
                .copied();
            let Some(bi) = bi else { continue };
            if bi == usize::MAX {
                continue;
            }
            let is_cstring =
                !in_sect.zerofill && in_sect.flags & SECTION_TYPE_MASK == S_CSTRING_LITERALS;
            if is_cstring {
                // D4: collect this section's string instances; the bucket's
                // pieces are the canonical (first live) copy of each unique
                // string. Deterministic: files in FileId order, strings in
                // offset order.
                let bucket = &mut pieces_of_bucket[bi];
                if !cstring_instances.iter().any(|(b, _)| *b == bi) {
                    cstring_instances.push((bi, Vec::new()));
                }
                let Some((_, list)) = cstring_instances.iter_mut().find(|(b, _)| *b == bi) else {
                    unreachable!("cstring instance list was just inserted");
                };
                for range in obj.atoms_of(si) {
                    if live.is_active() && live.is_atom_dead(obj.file.0, si, range.start) {
                        list.push(CStringInstance {
                            file: obj.file.0,
                            sect: si,
                            start: range.start,
                            end: range.end,
                            canonical: usize::MAX, // dead: no canonical
                        });
                        continue;
                    }
                    let content = obj.bytes[in_sect.data.start as usize + range.start as usize
                        ..in_sect.data.start as usize + range.end as usize]
                        .to_vec();
                    let per_bucket = cstring_dedup.entry(bi).or_default();
                    if let Some(ci) = per_bucket.get(&content).copied() {
                        list.push(CStringInstance {
                            file: obj.file.0,
                            sect: si,
                            start: range.start,
                            end: range.end,
                            canonical: ci,
                        });
                    } else {
                        // New unique string: emit the canonical piece.
                        per_bucket.insert(content, list.len());
                        list.push(CStringInstance {
                            file: obj.file.0,
                            sect: si,
                            start: range.start,
                            end: range.end,
                            canonical: list.len(),
                        });
                        bucket.push(Piece {
                            file: obj.file,
                            in_sect: si,
                            in_range: in_sect.data.start + range.start
                                ..in_sect.data.start + range.end,
                            offset: 0,
                            size: range.end - range.start,
                            align_log2: in_sect.align_log2,
                            zerofill: false,
                            common_name: None,
                            patches: Vec::new(),
                            fixup_slots: Vec::new(),
                            synth: None,
                        });
                    }
                }
                continue;
            }
            // Zero-fill inputs keep the M1–M4 whole-section piece (their
            // bucket is S_ZEROFILL; nothing is copied — only the size
            // matters). Atomization is a content-section concern.
            // M6 ICF: text sections go piece-granular when folding may
            // remove atoms (dead-strip already implies the atom path).
            let atom_granular = live.is_active()
                || (!fold.is_empty() && in_sect.flags & S_ATTR_PURE_INSTRUCTIONS != 0);
            if in_sect.zerofill || !atom_granular {
                pieces_of_bucket[bi].push(Piece {
                    file: obj.file,
                    in_sect: si,
                    in_range: in_sect.data.clone(),
                    offset: 0,
                    size: in_sect.size,
                    align_log2: in_sect.align_log2,
                    zerofill: false,
                    common_name: None,
                    patches: Vec::new(),
                    fixup_slots: Vec::new(),
                    synth: None,
                });
                continue;
            }
            // Atom granularity: one piece per live atom (D1 splits at
            // symbol boundaries; other objects stay whole-section). M6 ICF:
            // folded atoms leave the layout; their symbols resolve to the
            // canonical copy through the fold map.
            for range in obj.atoms_of(si) {
                if live.is_atom_dead(obj.file.0, si, range.start)
                    || fold.is_folded(obj.file.0, si, range.start)
                {
                    continue;
                }
                pieces_of_bucket[bi].push(Piece {
                    file: obj.file,
                    in_sect: si,
                    in_range: in_sect.data.start + range.start..in_sect.data.start + range.end,
                    offset: 0,
                    size: range.end - range.start,
                    align_log2: in_sect.align_log2,
                    zerofill: false,
                    common_name: None,
                    patches: Vec::new(),
                    fixup_slots: Vec::new(),
                    synth: None,
                });
            }
        }
    }
    // Commons as zero-fill pieces (caller passes name-sorted order); dead
    // commons (M5) are dropped.
    for (id, def) in commons {
        if live.is_common_dead(*id) {
            continue;
        }
        let Some(bi) = buckets
            .iter()
            .position(|(seg, name, _, _)| seg == "__DATA" && name == "__common")
        else {
            return Err(LinkError::Internal {
                message: "__common bucket missing although commons exist".into(),
            });
        };
        pieces_of_bucket[bi].push(Piece {
            file: def.file,
            in_sect: usize::MAX,
            in_range: 0..0,
            offset: 0,
            size: def.common_size,
            align_log2: def.common_align,
            zerofill: true,
            common_name: Some(*id),
            patches: Vec::new(),
            fixup_slots: Vec::new(),
            synth: None,
        });
    }
    Ok((pieces_of_bucket, cstring_instances))
}

/// The arm64 stub prologue before patching: `adrp x16, <page>;
/// ldr x16, [x16, #<pageoff>]; br x16` (TDD §3.4; matches ld64's output).
fn stub_template() -> Vec<u8> {
    let mut b = Vec::with_capacity(STUB_SIZE_ARM64 as usize);
    b.extend_from_slice(&0x9000_0010u32.to_le_bytes()); // adrp x16, ADRP
    b.extend_from_slice(&0xF940_0210u32.to_le_bytes()); // ldr x16, [x16, #imm12]
    b.extend_from_slice(&0xD61F_0200u32.to_le_bytes()); // br x16
    b
}

/// Places every output section and packs segments (§8).
fn place(
    cfg: &LinkConfig,
    objects: &[InputObject],
    buckets: &BucketTable,
    bucket_of: &[Vec<usize>],
    commons: &[(StringId, &Def)],
    chain_starts_size: usize,
    needs: &SynthNeeds,
    fixup_lc: FixupLc,
    live: &crate::deadstrip::LiveSet,
    fold: &crate::icf::FoldPlan,
    veneers: &[crate::thunks::VeneerSpec],
) -> Result<PlacedState, LinkError> {
    let (mut pieces_of_bucket, cstring_instances) =
        build_bucket_pieces(objects, buckets, bucket_of, commons, live, fold)?;

    // ---- M2 synthetic pieces: __got slots + __stubs entries ------------------
    // First-use order (scan_needs) determines slot order, matching the
    // import table's first-use ordinals and the indirect symbol table.
    if let Some(bi) = buckets
        .iter()
        .position(|(seg, name, _, _)| seg == "__DATA_CONST" && name == "__got")
    {
        for id in &needs.got {
            pieces_of_bucket[bi].push(Piece {
                file: FileId(u32::MAX),
                in_sect: usize::MAX,
                in_range: 0..0,
                offset: 0,
                size: 8,
                align_log2: 3,
                zerofill: false,
                common_name: None,
                patches: Vec::new(),
                fixup_slots: Vec::new(),
                synth: Some(SynthPiece {
                    kind: SynthKind::GotSlot { name: *id },
                    bytes: vec![0u8; 8],
                }),
            });
        }
    }
    if let Some(bi) = buckets
        .iter()
        .position(|(seg, name, _, _)| seg == "__TEXT" && name == "__stubs")
    {
        for id in &needs.stubs {
            pieces_of_bucket[bi].push(Piece {
                file: FileId(u32::MAX),
                in_sect: usize::MAX,
                in_range: 0..0,
                offset: 0,
                size: u64::from(STUB_SIZE_ARM64),
                align_log2: 2,
                zerofill: false,
                common_name: None,
                patches: Vec::new(),
                fixup_slots: Vec::new(),
                synth: Some(SynthPiece {
                    kind: SynthKind::StubSlot { name: *id },
                    bytes: stub_template(),
                }),
            });
        }
    }

    // ---- M6 veneer pieces: one per planned out-of-range branch site -------
    // Inserted into the site's own bucket right after its piece, so the
    // site's redirected `B`/`BL` is always within the ±128 MiB reach.
    if !veneers.is_empty() {
        crate::thunks::insert_veneer_pieces(objects, &mut pieces_of_bucket, veneers);
    }

    // ---- piece offsets within each output section --------------------------
    let mut sections: Vec<PlacedSection> = Vec::with_capacity(buckets.len());
    for (bi, (seg_name, name, flags, zerofill)) in buckets.iter().enumerate() {
        let mut cursor = 0u64;
        let mut max_align = 0u32;
        let mut pieces = core::mem::take(&mut pieces_of_bucket[bi]);
        for p in &mut pieces {
            max_align = max_align.max(p.align_log2);
            cursor = align_up_u64(cursor, 1u64 << p.align_log2);
            p.offset = cursor;
            cursor += p.size;
        }
        let (align, size) = if name == "__chain_starts" {
            (2u32, chain_starts_size as u64)
        } else {
            (max_align, cursor)
        };
        // M8-c slack: user-content sections reserve growth room. Synthetic
        // sections (`__got`/`__stubs`/`__chain_starts`) are contract-coupled
        // to the fixup plan and stay exact; zero-fill tails are virtual and
        // need no reservation. M9: anchors from the previous link keep a
        // section's reserved size while its content still fits (§7.3
        // "layout stability" — the in-place patch tier's precondition).
        let size = match (&cfg.layout_slack, name.as_str()) {
            (Some(_), "__got" | "__stubs" | "__chain_starts") => size,
            (Some(policy), _) if size > 0 && !zerofill => {
                let anchor = cfg
                    .slack_anchor
                    .iter()
                    .find(|a| a.seg == *seg_name && a.name == *name)
                    .map(|a| a.padded);
                policy.pad_section_anchored(seg_name, name, size, align, anchor)
            }
            _ => size,
        };
        sections.push(PlacedSection {
            name: name.clone(),
            seg_name: seg_name.clone(),
            flags: if name == "__chain_starts" {
                S_REGULAR
            } else {
                *flags
            },
            align_log2: align,
            vm_addr: 0,
            size,
            file_off: 0,
            zerofill: *zerofill && name != "__chain_starts",
            pieces,
        });
    }

    // ---- sizeofcmds (computed before placement so __TEXT starts right) -----
    // Shared with `build_header` (one formula, one source of truth).
    let nsections = sections.iter().filter(|s| s.size > 0).count();
    // The fixups LC follows the payload presence (not the mirror section).
    let sizeofcmds = command_size(cfg, nsections, fixup_lc);
    let header_len = 32 + sizeofcmds;
    if header_len as u64 > PAGE_SIZE_16K {
        return Err(LinkError::Layout {
            message: format!(
                "header and load commands ({header_len} bytes) exceed the 16 KiB first page \
                 (TDD §8.1 rule 7)"
            ),
        });
    }

    // ---- segment packing (§8) ----------------------------------------------
    // Constant-delta base: 0x1_0000_0000 for executables (after __PAGEZERO),
    // 0 for dylibs/bundles (M3: `__TEXT.vmaddr == fileoff`, no __PAGEZERO).
    let base = cfg.filetype.image_base();
    let mut segments: Vec<SegmentPlan> = Vec::new();
    if base > 0 {
        segments.push(SegmentPlan {
            name: "__PAGEZERO".into(),
            vmaddr: 0,
            vmsize: base,
            fileoff: 0,
            filesize: 0,
            maxprot: 0,
            initprot: 0,
            sections: Vec::new(),
        });
    }

    for seg_name in ["__TEXT", "__DATA_CONST", "__DATA"] {
        let (maxprot, initprot) = match seg_name {
            "__TEXT" => (
                VM_PROT_READ | VM_PROT_EXECUTE,
                VM_PROT_READ | VM_PROT_EXECUTE,
            ),
            _ => (VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE),
        };
        let prev_end = segments
            .last()
            .map_or(PAGE_SIZE_16K, |s| s.fileoff + s.vmsize);
        let seg_fileoff = if seg_name == "__TEXT" {
            0
        } else {
            align_up_u64(prev_end, PAGE_SIZE_16K)
        };
        // VM and file cursors move in lockstep under the constant-delta
        // contract (`vmaddr = fileoff + base`); zero-fill sections advance
        // VM only (§8.1 rule 5).
        let mut cursor = if seg_name == "__TEXT" {
            align_up_u64(header_len as u64, 8)
        } else {
            seg_fileoff
        };
        let mut file_end = cursor;
        let mut sects: Vec<usize> = Vec::new();
        for (i, s) in sections.iter_mut().enumerate() {
            if s.seg_name != seg_name || s.size == 0 {
                continue;
            }
            cursor = align_up_u64(cursor, 1u64 << s.align_log2);
            s.vm_addr = cursor + base;
            if s.zerofill {
                s.file_off = 0;
            } else {
                s.file_off = cursor;
            }
            cursor += s.size;
            if !s.zerofill {
                file_end = cursor;
            }
            sects.push(i);
        }
        let vmsize = align_up_u64(cursor - seg_fileoff, PAGE_SIZE_16K).max(PAGE_SIZE_16K);
        segments.push(SegmentPlan {
            name: seg_name.into(),
            vmaddr: seg_fileoff + base,
            vmsize,
            fileoff: seg_fileoff,
            filesize: file_end - seg_fileoff,
            maxprot,
            initprot,
            sections: sects,
        });
    }
    let prev_end = segments.last().map_or(0, |s| s.fileoff + s.vmsize);
    let le_fileoff = align_up_u64(prev_end.max(PAGE_SIZE_16K), PAGE_SIZE_16K);
    segments.push(SegmentPlan {
        name: "__LINKEDIT".into(),
        vmaddr: le_fileoff + base,
        vmsize: 0,
        fileoff: le_fileoff,
        filesize: 0,
        maxprot: VM_PROT_READ,
        initprot: VM_PROT_READ,
        sections: Vec::new(),
    });

    // ---- flat pieces + address tables ---------------------------------------
    let mut flat: Vec<FlatPiece> = Vec::new();
    let mut addr_of: std::collections::HashMap<(u32, usize), u64> =
        std::collections::HashMap::new();
    let mut atom_addr: std::collections::HashMap<(u32, usize), Vec<(u64, u64)>> =
        std::collections::HashMap::new();
    // D4: canonical cstring piece addresses, keyed (file, sect, start).
    let mut cstring_out: std::collections::HashMap<(u32, usize, u64), u64> =
        std::collections::HashMap::new();
    let mut def_addr: std::collections::BTreeMap<u32, u64> = std::collections::BTreeMap::new();
    let mut got_slot_addr: std::collections::BTreeMap<u32, u64> = std::collections::BTreeMap::new();
    let mut stub_addr: std::collections::BTreeMap<u32, u64> = std::collections::BTreeMap::new();
    let mut veneer_addr_of: std::collections::HashMap<(u32, usize, u32), u64> =
        std::collections::HashMap::new();
    for (si, s) in sections.iter().enumerate() {
        let is_cstring = s.flags & SECTION_TYPE_MASK == S_CSTRING_LITERALS;
        for (pi, p) in s.pieces.iter().enumerate() {
            let addr = s.vm_addr + p.offset;
            flat.push(FlatPiece {
                section: si,
                piece_idx: pi,
                addr,
                piece: p.clone(),
            });
            if !p.zerofill && p.synth.is_none() && p.in_sect != usize::MAX {
                // First piece wins: `addr_of` stays the section base even
                // when the section split into atom pieces (M5/D1).
                addr_of.entry((p.file.0, p.in_sect)).or_insert(addr);
                let data_start = objects
                    .get(p.file.0 as usize)
                    .and_then(|o| o.sections.get(p.in_sect))
                    .map_or(0, |sect| sect.data.start);
                if is_cstring {
                    // D4: the canonical instance's output address.
                    cstring_out.insert(
                        (
                            p.file.0,
                            p.in_sect,
                            p.in_range.start.saturating_sub(data_start),
                        ),
                        addr,
                    );
                } else if live.is_active() || !fold.is_empty() {
                    // Atom identity: section-relative input start → output
                    // vaddr. The containment lookups (defs, section-target
                    // relocs) read this table.
                    atom_addr
                        .entry((p.file.0, p.in_sect))
                        .or_default()
                        .push((p.in_range.start.saturating_sub(data_start), addr));
                }
            }
            if let Some(id) = p.common_name {
                def_addr.insert(id.0, addr);
            }
            if let Some(synth) = &p.synth {
                match synth.kind {
                    SynthKind::GotSlot { name } => {
                        got_slot_addr.insert(name.0, addr);
                    }
                    SynthKind::StubSlot { name } => {
                        stub_addr.insert(name.0, addr);
                    }
                    SynthKind::Veneer { site, .. } => {
                        veneer_addr_of.insert(site, addr);
                    }
                }
            }
        }
    }
    // D4 remap entries: every live cstring instance resolves to its
    // canonical copy's address plus the in-string offset.
    for (_bi, instances) in &cstring_instances {
        for inst in instances {
            if inst.canonical == usize::MAX {
                continue; // dead under dead-strip: nothing references it
            }
            let canon = &instances[inst.canonical];
            let Some(&canon_addr) = cstring_out.get(&(canon.file, canon.sect, canon.start)) else {
                return Err(LinkError::Internal {
                    message: "cstring canonical piece missing from placement".into(),
                });
            };
            atom_addr
                .entry((inst.file, inst.sect))
                .or_default()
                .push((inst.start, canon_addr + (inst.start - canon.start)));
        }
    }
    for entries in atom_addr.values_mut() {
        entries.sort_unstable_by_key(|(start, _)| *start);
    }
    Ok(PlacedState {
        sections,
        segments,
        flat,
        addr_of,
        atom_addr,
        def_addr,
        got_slot_addr,
        stub_addr,
        veneer_addr_of,
    })
}

/// Resolves every piece's patches and fixup slots against placed addresses.
fn resolve_all(
    objects: &[InputObject],
    state: &mut PlacedState,
    res: &Resolution,
    interner: &Interner,
    cfg: &LinkConfig,
    fold: &crate::icf::FoldPlan,
) -> Result<(), LinkError> {
    // Definition addresses: commons already resolved; add section defs.
    // M5/D1: when the defining section split into atom pieces, the def's
    // address is its containing atom's output address plus the inner offset
    // (dead atoms carry no entry — nothing live references them).
    let mut def_addr: std::collections::BTreeMap<u32, u64> = state.def_addr.clone();
    for (id, def) in res.definitions() {
        if let Some(sect) = def.section
            && let Some(vaddr) = fold_aware_addr(
                fold,
                objects,
                &state.atom_addr,
                &state.addr_of,
                def.file.0,
                sect,
                def.value,
            )
        {
            def_addr.insert(id.0, vaddr);
        }
    }

    // Weak-reference flag per name (bind import weak bit; any weak-referencing
    // site makes the import weak — dyld coalesces at runtime).
    let mut weak_ref: std::collections::BTreeMap<u32, bool> = std::collections::BTreeMap::new();
    for (id, _def) in res.definitions() {
        let _ = id;
    }
    for obj in objects {
        for sym in &obj.symbols {
            if sym.external && sym.is_undefined() {
                let v = weak_ref.entry(sym.name.0).or_insert(false);
                *v |= sym.weak_ref;
            }
        }
    }

    // ---- D8: materialize the per-file resolved[] tables (M4, perf doc
    // §3 D8). The relocation scan below reads these flat arrays instead of
    // walking `addr_of`/`def_addr` maps per relocation — one file-local
    // load replaces the three dependent map hops.
    let resolved = build_resolved_tables(
        objects,
        &state.addr_of,
        &def_addr,
        res,
        &state.atom_addr,
        fold,
    );

    // Pass A: every piece except stubs (stubs need the GOT slot addresses
    // that this pass computes).
    for fp_idx in 0..state.flat.len() {
        let synth_kind = state.flat[fp_idx].piece.synth.as_ref().map(|s| s.kind);
        if matches!(synth_kind, Some(SynthKind::StubSlot { .. })) {
            continue;
        }
        let (file, in_sect_idx, addr, zerofill) = {
            let fp = &state.flat[fp_idx];
            (fp.piece.file, fp.piece.in_sect, fp.addr, fp.piece.zerofill)
        };
        let mut patches: Vec<PatchOp> = Vec::new();
        let mut slots: Vec<(u32, FixupKind)> = Vec::new();
        match synth_kind {
            Some(SynthKind::GotSlot { name }) => {
                // The GOT slot: rebase when the symbol resolves in-image,
                // bind when it comes from a dylib / dyld lookup.
                let kind = if let Some(v) = def_addr.get(&name.0).copied() {
                    FixupKind::Rebase { target_vaddr: v }
                } else {
                    let lib = if cfg.flat_namespace {
                        BIND_SPECIAL_DYLIB_FLAT_LOOKUP as u8
                    } else if let Some(ord) = res.dylib_ordinal(name) {
                        u8::try_from(ord).map_err(|_| LinkError::Internal {
                            message: "dylib ordinal beyond 255".into(),
                        })?
                    } else {
                        BIND_SPECIAL_DYLIB_FLAT_LOOKUP as u8
                    };
                    FixupKind::Bind {
                        lib_ordinal: lib,
                        name,
                        addend: 0,
                        weak: weak_ref.get(&name.0).copied().unwrap_or(false),
                    }
                };
                slots.push((0, kind));
            }
            Some(SynthKind::StubSlot { .. }) => unreachable!("stubs resolved in pass B"),
            Some(SynthKind::Veneer { target, .. }) => {
                // M6: `adrp x16, target@page` + `add x16, x16,
                // target@pageoff` — the `br x16` needs no patch. The target
                // resolves exactly like the original branch did (in-image
                // def, or the dylib call's synthesized stub).
                let obj = objects.get(file.0 as usize).ok_or(LinkError::Internal {
                    message: "veneer owner file missing".into(),
                })?;
                let space = AddrSpace {
                    got_slot_addr: &state.got_slot_addr,
                    stub_addr: &state.stub_addr,
                    interner,
                    res,
                    cfg,
                    resolved: &resolved,
                    atom_addr: &state.atom_addr,
                    veneer_of: &state.veneer_addr_of,
                };
                let target_addr = if let Some(t) = lookup_opt(obj, target, 0, &space)? {
                    t
                } else {
                    let RelocTarget::Extern(id) = target else {
                        return Err(LinkError::Internal {
                            message: "veneer without an external target".into(),
                        });
                    };
                    space
                        .stub_addr
                        .get(&id.0)
                        .copied()
                        .ok_or(LinkError::Internal {
                            message: format!(
                                "branch veneer to \"{}\" without a synthesized stub",
                                space.interner.name(id)
                            ),
                        })?
                };
                let page_delta = ((target_addr as i64) >> 12) - ((addr as i64) >> 12);
                if page_delta.unsigned_abs() > 0xF_FFFF {
                    return Err(LinkError::Layout {
                        message: format!(
                            "veneer at {addr:#x} to {target_addr:#x} exceeds the \n                            ±4 GiB ADRP range (image larger than 4 GiB of text)"
                        ),
                    });
                }
                patches.push(PatchOp::Adrp {
                    in_offset: 0,
                    page_delta,
                });
                patches.push(PatchOp::PageOff12 {
                    in_offset: 4,
                    imm12: (target_addr & 0xFFF) as u32,
                });
            }
            None => {
                if zerofill {
                    continue;
                }
                let obj = objects.get(file.0 as usize).ok_or(LinkError::Internal {
                    message: "piece file missing".into(),
                })?;
                let in_sect = &obj.sections[in_sect_idx];
                let space = AddrSpace {
                    got_slot_addr: &state.got_slot_addr,
                    stub_addr: &state.stub_addr,
                    interner,
                    res,
                    cfg,
                    resolved: &resolved,
                    atom_addr: &state.atom_addr,
                    veneer_of: &state.veneer_addr_of,
                };
                for r in &in_sect.relocs {
                    resolve_reloc(
                        obj,
                        in_sect_idx,
                        in_sect,
                        r,
                        addr,
                        &space,
                        &mut patches,
                        &mut slots,
                    )?;
                }
            }
        }
        state.flat[fp_idx].piece.patches = patches;
        state.flat[fp_idx].piece.fixup_slots = slots;
    }

    // Pass B: stub pieces (adrp/ldr through their GOT slot).
    for fp_idx in 0..state.flat.len() {
        let Some(SynthPiece {
            kind: SynthKind::StubSlot { name },
            ..
        }) = state.flat[fp_idx].piece.synth.as_ref()
        else {
            continue;
        };
        let slot_vaddr = state
            .got_slot_addr
            .get(&name.0)
            .copied()
            .ok_or(LinkError::Internal {
                message: format!(
                    "stub for \"{}\" has no GOT slot (scan/synthesis mismatch)",
                    interner.name(*name)
                ),
            })?;
        let stub_vaddr = state.flat[fp_idx].addr;
        let page_delta = ((slot_vaddr as i64) >> 12) - ((stub_vaddr as i64) >> 12);
        let imm12 = ((slot_vaddr & 0xFFF) >> 3) as u32; // ldr x16: /8 scale
        state.flat[fp_idx].piece.patches = vec![
            PatchOp::Adrp {
                in_offset: 0,
                page_delta,
            },
            PatchOp::PageOff12 {
                in_offset: 4,
                imm12,
            },
        ];
    }

    // Sync the resolved state back into the section view (Pass 4 reads
    // `sections[*].pieces`).
    for fp in &state.flat {
        let s = &mut state.sections[fp.section];
        let piece = &mut s.pieces[fp.piece_idx];
        piece.patches.clone_from(&fp.piece.patches);
        piece.fixup_slots.clone_from(&fp.piece.fixup_slots);
    }
    state.def_addr = def_addr;
    Ok(())
}

/// Borrowed view of the address space resolution reads (Pass 3 scratch).
struct AddrSpace<'a> {
    /// Interned name id → GOT slot vaddr (M2).
    got_slot_addr: &'a std::collections::BTreeMap<u32, u64>,
    /// Interned name id → stub vaddr (M2).
    stub_addr: &'a std::collections::BTreeMap<u32, u64>,
    /// Name bytes for diagnostics.
    interner: &'a Interner,
    /// Resolution (dylib ordinals, dynamic lookups).
    res: &'a Resolution,
    /// Link config (flat namespace).
    cfg: &'a LinkConfig,
    /// Per-file D8 resolution tables (M4): the flat arrays the relocation
    /// scan reads for every symbol/section target — the M1–M3 map walks
    /// (`addr_of`/`def_addr`) are gone from this hot path.
    resolved: &'a [ResolvedFile],
    /// M5/D1: per-(file, section) atom `((section-relative start, vaddr)`
    /// tables. Empty when no atomization happened — the hot path stays
    /// map-free for the M1–M4 shapes.
    atom_addr: &'a std::collections::HashMap<(u32, usize), Vec<(u64, u64)>>,
    /// M6: branch site `(file, in_sect, reloc offset)` → veneer vaddr.
    /// Non-empty only while the veneer fixed point runs.
    veneer_of: &'a std::collections::HashMap<(u32, usize, u32), u64>,
}

/// The bind library ordinal for an external reference (M2): the two-level
/// ordinal, or a `BIND_SPECIAL_DYLIB_*` special under `-flat_namespace` /
/// dynamic lookup.
fn bind_lib_ordinal(id: StringId, space: &AddrSpace<'_>) -> Result<u8, LinkError> {
    if space.cfg.flat_namespace {
        return Ok(BIND_SPECIAL_DYLIB_FLAT_LOOKUP as u8);
    }
    if let Some(ord) = space.res.dylib_ordinal(id) {
        return u8::try_from(ord).map_err(|_| LinkError::Internal {
            message: "dylib ordinal beyond 255".into(),
        });
    }
    Ok(BIND_SPECIAL_DYLIB_FLAT_LOOKUP as u8)
}

/// The output vaddr of `value` inside `(file, sect)`: atom containment when
/// the section split into atom pieces (M5/D1), the section base plus value
/// otherwise. `None` when the section was not placed or (under atomization)
/// the containing atom is dead.
fn atom_or_section_addr(
    atom_addr: &std::collections::HashMap<(u32, usize), Vec<(u64, u64)>>,
    addr_of: &std::collections::HashMap<(u32, usize), u64>,
    file: u32,
    sect: usize,
    value: u64,
) -> Option<u64> {
    if let Some(atoms) = atom_addr.get(&(file, sect)) {
        // Containment with clamping (references into padding keep the tail
        // atom alive — the same rule the mark phase applies).
        let idx = atoms
            .partition_point(|(start, _)| *start <= value)
            .saturating_sub(1);
        let (start, out) = atoms.get(idx).copied()?;
        return Some(out + (value - start));
    }
    addr_of.get(&(file, sect)).map(|base| base + value)
}

/// Resolves one relocation into a static patch or a fixup slot.
fn resolve_reloc(
    obj: &InputObject,
    in_sect_idx: usize,
    in_sect: &crate::object::InputSection,
    r: &crate::object::DecodedReloc,
    piece_addr: u64,
    space: &AddrSpace<'_>,
    patches: &mut Vec<PatchOp>,
    slots: &mut Vec<(u32, FixupKind)>,
) -> Result<(), LinkError> {
    let slot_v = piece_addr + u64::from(r.offset);
    match r.kind {
        RelocKind::Unsigned => {
            let at = in_sect.data.start as usize + r.offset as usize;
            let addend = read_slot_i64(&obj.bytes, at)?;
            if let Some(target) = lookup_opt(obj, r.target, addend, space)? {
                let value = (target as i64)
                    .checked_add(addend)
                    .ok_or(LinkError::Layout {
                        message: "fixup target overflow".into(),
                    })?;
                slots.push((
                    r.offset,
                    FixupKind::Rebase {
                        target_vaddr: value as u64,
                    },
                ));
            } else {
                // External (dylib export or dynamic lookup): chained
                // bind. The full addend travels in the import entry /
                // inline word per plan_fixups' split.
                let RelocTarget::Extern(id) = r.target else {
                    return Err(LinkError::Internal {
                        message: "section target without an address".into(),
                    });
                };
                slots.push((
                    r.offset,
                    FixupKind::Bind {
                        lib_ordinal: bind_lib_ordinal(id, space)?,
                        name: id,
                        addend,
                        weak: false,
                    },
                ));
            }
        }
        RelocKind::Page21 { addend } => {
            let target = lookup(obj, r.target, addend, space)?
                .checked_add_signed(addend)
                .ok_or(LinkError::Internal {
                    message: "page21 target overflow".into(),
                })?;
            let page_delta = ((target as i64) >> 12) - ((slot_v as i64) >> 12);
            patches.push(PatchOp::Adrp {
                in_offset: r.offset,
                page_delta,
            });
        }
        RelocKind::PageOff12 { addend } => {
            let target = lookup(obj, r.target, addend, space)?
                .checked_add_signed(addend)
                .ok_or(LinkError::Internal {
                    message: "pageoff12 target overflow".into(),
                })?;
            patches.push(PatchOp::PageOff12 {
                in_offset: r.offset,
                imm12: (target & 0xFFF) as u32,
            });
        }
        RelocKind::GotLoadPage21 { .. } => {
            let RelocTarget::Extern(id) = r.target else {
                return Err(LinkError::Internal {
                    message: "GOT-load relocation without an external target".into(),
                });
            };
            let slot = space
                .got_slot_addr
                .get(&id.0)
                .copied()
                .ok_or(LinkError::Internal {
                    message: format!(
                        "GOT-load for \"{}\" without a synthesized slot",
                        space.interner.name(id)
                    ),
                })?;
            let page_delta = ((slot as i64) >> 12) - ((slot_v as i64) >> 12);
            patches.push(PatchOp::Adrp {
                in_offset: r.offset,
                page_delta,
            });
        }
        RelocKind::GotLoadPageOff12 { .. } => {
            let RelocTarget::Extern(id) = r.target else {
                return Err(LinkError::Internal {
                    message: "GOT-load relocation without an external target".into(),
                });
            };
            let slot = space
                .got_slot_addr
                .get(&id.0)
                .copied()
                .ok_or(LinkError::Internal {
                    message: format!(
                        "GOT-load for \"{}\" without a synthesized slot",
                        space.interner.name(id)
                    ),
                })?;
            // LDR (immediate, unsigned offset): imm12 is scaled by the
            // access size (8 bytes for a 64-bit GOT load).
            patches.push(PatchOp::PageOff12 {
                in_offset: r.offset,
                imm12: ((slot & 0xFFF) >> r.length_log2) as u32,
            });
        }
        RelocKind::PointerToGot => {
            let RelocTarget::Extern(id) = r.target else {
                return Err(LinkError::Internal {
                    message: "POINTER_TO_GOT without an external target".into(),
                });
            };
            let slot = space
                .got_slot_addr
                .get(&id.0)
                .copied()
                .ok_or(LinkError::Internal {
                    message: format!(
                        "POINTER_TO_GOT for \"{}\" without a synthesized slot",
                        space.interner.name(id)
                    ),
                })?;
            // The pointer's value is the GOT slot's address: a chained
            // rebase (ASLR shifts it with the image).
            slots.push((r.offset, FixupKind::Rebase { target_vaddr: slot }));
        }
        RelocKind::Branch26 => {
            // M6: a planned veneer takes over the site's target — the branch
            // reaches the veneer (always within ±128 MiB: the veneer sits at
            // the site's piece end) and the veneer reaches the final target
            // through ADRP's ±4 GiB window.
            let target = if let Some(&veneer_vaddr) =
                space.veneer_of.get(&(obj.file.0, in_sect_idx, r.offset))
            {
                veneer_vaddr
            } else if let Some(t) = lookup_opt(obj, r.target, 0, space)? {
                t
            } else {
                // Dylib call: branch through the synthesized stub.
                let RelocTarget::Extern(id) = r.target else {
                    return Err(LinkError::Internal {
                        message: "external branch without a name".into(),
                    });
                };
                space
                    .stub_addr
                    .get(&id.0)
                    .copied()
                    .ok_or(LinkError::Internal {
                        message: format!(
                            "branch to \"{}\" without a synthesized stub",
                            space.interner.name(id)
                        ),
                    })?
            };
            let delta = (target as i64) - (slot_v as i64);
            // Out-of-range deltas are legal *mid-fixpoint* only: the layout
            // loop scans them and inserts a veneer before anything emits.
            // The 4-alignment contract still holds unconditionally.
            if delta % 4 != 0 {
                return Err(LinkError::Internal {
                    message: "branch target not 4-aligned".into(),
                });
            }
            patches.push(PatchOp::Branch26 {
                in_offset: r.offset,
                pc: slot_v,
                delta,
            });
        }
        RelocKind::Subtractor { minuend } => {
            let minuend_v = lookup(obj, minuend, 0, space)?;
            let subtrahend_v = lookup(obj, r.target, 0, space)?;
            let at = in_sect.data.start as usize + r.offset as usize;
            let addend = read_slot_i64(&obj.bytes, at)?;
            patches.push(PatchOp::Write64 {
                in_offset: r.offset,
                value: (minuend_v as i64)
                    .wrapping_sub(subtrahend_v as i64)
                    .wrapping_add(addend) as u64,
            });
        }
    }
    Ok(())
}

/// Reads the 8-byte slot addend at `at` (the classic Mach-O in-data addend).
fn read_slot_i64(bytes: &[u8], at: usize) -> Result<i64, LinkError> {
    bytes
        .get(at..at + 8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(i64::from_le_bytes)
        .ok_or(LinkError::Internal {
            message: "pointer slot out of input bounds".into(),
        })
}

/// Looks up a relocation target (extern or local section); externs that
/// resolve nowhere (dylib exports, dynamic lookups) yield `None` — the
/// caller decides between the bind path and an error.
///
/// `addend` is the relocation's in-section target offset: for section
/// targets under M5 atomization the containing atom of `addend` supplies
/// the base (its output address minus its input start), so the caller's
/// `+ addend` lands on the compacted address.
///
/// M4 (D8): reads the file-local `resolved[]` array — `res.def(id)` gives
/// the defining `(file, sym)` hop, then one indexed load — instead of a
/// global map walk per relocation.
fn lookup_opt(
    obj: &InputObject,
    target: RelocTarget,
    addend: i64,
    space: &AddrSpace<'_>,
) -> Result<Option<u64>, LinkError> {
    match target {
        RelocTarget::Extern(id) => match space.res.def(id) {
            Some(d) => space
                .resolved
                .get(d.file.0 as usize)
                .and_then(|t| t.syms.get(d.sym))
                .copied()
                .map(Some)
                .ok_or_else(|| LinkError::Internal {
                    message: format!(
                        "definition of \"{}\" missing from the resolved[] table",
                        space.interner.name(id)
                    ),
                }),
            None => Ok(None),
        },
        RelocTarget::Section(idx) => {
            if let Some(atoms) = space.atom_addr.get(&(obj.file.0, idx)) {
                // Atom containment (M5/D1): the base compensates for the
                // dead atoms stripped before this one.
                let off = u64::try_from(addend).map_err(|_| LinkError::Layout {
                    message: format!(
                        "negative addend ({addend}) into an atomized section of {}",
                        obj.name
                    ),
                })?;
                let at = atoms
                    .partition_point(|(start, _)| *start <= off)
                    .saturating_sub(1);
                if let Some((start, out)) = atoms.get(at) {
                    return Ok(Some(out.wrapping_sub(*start)));
                }
                return Err(LinkError::Internal {
                    message: format!(
                        "local reference into a dead-stripped region of {} (section {idx}, \n                         offset {off:#x})",
                        obj.name
                    ),
                });
            }
            match space
                .resolved
                .get(obj.file.0 as usize)
                .and_then(|t| t.sects.get(idx))
                .copied()
            {
                // Zero marks unplaced (zero-fill) sections — the M1–M3 map
                // lookup returned an error for those too.
                Some(v) if v != 0 => Ok(Some(v)),
                _ => Err(LinkError::Internal {
                    message: format!("local section {idx} of {} was not placed", obj.name),
                }),
            }
        }
    }
}

/// Looks up a relocation target that *must* resolve in-image.
fn lookup(
    obj: &InputObject,
    target: RelocTarget,
    addend: i64,
    space: &AddrSpace<'_>,
) -> Result<u64, LinkError> {
    lookup_opt(obj, target, addend, space)?.ok_or(LinkError::Symbol {
        name: match target {
            RelocTarget::Extern(id) => space.interner.name(id),
            RelocTarget::Section(_) => String::new(),
        },
        message: match target {
            RelocTarget::Extern(id) => format!(
                "undefined symbol \"{}\" (referenced from {})",
                space.interner.name(id),
                obj.name
            ),
            RelocTarget::Section(_) => "local section was not placed".into(),
        },
    })
}

/// The tables the symtab builder reads: the placed sections and the M5
/// address/liveness structures (D1/D4 containment, D12 filtering) plus the
/// M6 fold map.
struct SymtabContext<'a> {
    sections: &'a [PlacedSection],
    addr_of: &'a std::collections::HashMap<(u32, usize), u64>,
    atom_addr: &'a std::collections::HashMap<(u32, usize), Vec<(u64, u64)>>,
    live: &'a crate::deadstrip::LiveSet,
    fold: &'a crate::icf::FoldPlan,
}

/// Builds the output symbol table: locals (file order), ext defs (file
/// order), commons (name order); `n_sect` remapped to output sections.
/// M3: hidden externals (export filters) become private externals
/// (`N_SECT | N_PEXT`, `external: false`) merged into the locals range in
/// (file, sym) order — ld64's `-exported_symbols_list` behavior.
fn build_symtab(
    objects: &[InputObject],
    res: &Resolution,
    interner: &Interner,
    commons: &[(StringId, &Def)],
    visible: &dyn Fn(&[u8]) -> bool,
    ctx: &SymtabContext<'_>,
) -> Vec<OutputSymbol> {
    let (sections, addr_of, atom_addr, live, fold) =
        (ctx.sections, ctx.addr_of, ctx.atom_addr, ctx.live, ctx.fold);
    // Output section lookup by (file, input section): (index, base).
    let mut sect_of: std::collections::HashMap<(u32, usize), usize> =
        std::collections::HashMap::new();
    for (si, s) in sections.iter().enumerate() {
        for p in &s.pieces {
            if !p.zerofill {
                sect_of.insert((p.file.0, p.in_sect), si);
            }
        }
    }
    // M5/D1+D4: atom- and cstring-aware address of a symbol (containment in
    // the live/merged piece tables; the section base plus value otherwise).
    // M6 ICF: folded atoms redirect to the canonical copy.
    let sym_addr = |obj: &InputObject, sect: usize, value: u64| -> Option<u64> {
        fold_aware_addr(fold, objects, atom_addr, addr_of, obj.file.0, sect, value)
    };
    // Symbol-liveness (M5/D12): a section-defined symbol dies with its
    // containing atom (O(log atoms) containment).
    let sym_live = |obj: &InputObject, sym: &crate::object::InputSymbol| -> bool {
        !live.is_active()
            || sym.section.is_none_or(|sect| {
                let ranges = obj.atoms_of(sect);
                if ranges.is_empty() {
                    return true;
                }
                let idx = ranges
                    .partition_point(|r| r.start <= sym.value)
                    .saturating_sub(1);
                !live.is_atom_dead(obj.file.0, sect, ranges[idx].start)
            })
    };
    // Locals with their (file, sym) order key (hidden extdefs merge in).
    let mut locals: Vec<((u32, u32), OutputSymbol)> = Vec::new();
    let mut hidden: Vec<((u32, u32), OutputSymbol)> = Vec::new();
    let mut out: Vec<OutputSymbol> = Vec::new();

    // M6 ICF: a symbol inside a folded atom reports the canonical copy's
    // output section (its own piece is not placed).
    let osect_of = |file: u32, sect: usize, value: u64| -> usize {
        let key = if fold.is_empty() {
            (file, sect)
        } else {
            objects
                .get(file as usize)
                .and_then(|obj| containing_atom_start(obj, sect, value))
                .and_then(|start| fold.canonical_of(file, sect, start))
                .map_or((file, sect), |(cf, cs, _)| (cf, cs))
        };
        sect_of.get(&key).copied().unwrap_or(usize::MAX)
    };

    // Locals: file order, symbol order; stabs skipped; non-section locals
    // pass through as absolute.
    for obj in objects {
        for (sym_i, sym) in obj.symbols.iter().enumerate() {
            if sym.stab || sym.external {
                continue;
            }
            if !sym_live(obj, sym) {
                continue;
            }
            match sym.section.and_then(|sect| sym_addr(obj, sect, sym.value)) {
                Some(value) => {
                    let osect = sym
                        .section
                        .map(|sect| osect_of(obj.file.0, sect, sym.value));
                    locals.push((
                        (obj.file.0, sym_i as u32),
                        OutputSymbol {
                            name: sym.name,
                            n_type: N_SECT,
                            n_sect: osect.map_or(0, |i| (i + 1) as u8),
                            n_desc: 0,
                            value,
                            external: false,
                        },
                    ));
                }
                None => locals.push((
                    (obj.file.0, sym_i as u32),
                    OutputSymbol {
                        name: sym.name,
                        n_type: N_ABS,
                        n_sect: 0,
                        n_desc: 0,
                        value: sym.value,
                        external: false,
                    },
                )),
            }
        }
    }
    // Ext defs (section-defined) in (file, sym) order.
    let mut defs: Vec<(&Def, StringId)> = res
        .definitions()
        .filter(|(_, d)| d.section.is_some())
        .map(|(id, d)| (d, id))
        .collect();
    defs.sort_by_key(|(d, _)| (d.file, d.sym));
    for (def, id) in defs {
        let Some(sect) = def.section else { continue };
        let Some(obj) = objects.get(def.file.0 as usize) else {
            continue;
        };
        // Dead definitions (M5/D12) leave the symtab and the trie.
        if let Some(sym) = obj.symbols.get(def.sym)
            && !sym_live(obj, sym)
        {
            continue;
        }
        let Some(value) = sym_addr(obj, sect, def.value) else {
            continue;
        };
        let osect = osect_of(def.file.0, sect, def.value);
        let entry = OutputSymbol {
            name: id,
            n_type: N_EXT | N_SECT,
            n_sect: if osect == usize::MAX {
                0
            } else {
                (osect + 1) as u8
            },
            n_desc: if def.weak { N_WEAK_DEF } else { 0 },
            value,
            external: true,
        };
        if visible(interner.bytes(id)) {
            out.push(entry);
        } else {
            // Hidden: a private external local (`N_PEXT`), ordered by its
            // defining (file, sym) position within the locals range.
            hidden.push((
                (def.file.0, def.sym as u32),
                OutputSymbol {
                    n_type: N_SECT | N_PEXT,
                    external: false,
                    ..entry
                },
            ));
        }
    }
    // Commons: name-sorted (the allocation order); address from the
    // __common section layout via the piece's `common_name`.
    let common_sect = sections
        .iter()
        .position(|s| s.seg_name == "__DATA" && s.name == "__common");
    for (id, def) in commons {
        let Some(ci) = common_sect else { continue };
        let Some(piece) = sections[ci]
            .pieces
            .iter()
            .find(|p| p.common_name == Some(*id))
        else {
            continue;
        };
        let entry = OutputSymbol {
            name: *id,
            n_type: N_EXT | N_SECT,
            n_sect: (ci + 1) as u8,
            n_desc: 0,
            value: sections[ci].vm_addr + piece.offset,
            external: true,
        };
        if visible(interner.bytes(*id)) {
            out.push(entry);
        } else {
            hidden.push((
                (def.file.0, def.sym as u32),
                OutputSymbol {
                    n_type: N_SECT | N_PEXT,
                    external: false,
                    ..entry
                },
            ));
        }
    }
    // Merge hidden defs into the locals range (both sides already sorted by
    // (file, sym); a stable merge keeps the canonical order).
    if hidden.is_empty() {
        out.splice(0..0, locals.into_iter().map(|(_, s)| s));
    } else {
        let mut merged: Vec<OutputSymbol> = Vec::with_capacity(locals.len() + hidden.len());
        let mut h = hidden.into_iter().peekable();
        for (key, sym) in locals {
            while let Some((hk, _)) = h.peek() {
                if *hk <= key {
                    merged.push(h.next().expect("peeked").1);
                } else {
                    break;
                }
            }
            merged.push(sym);
        }
        merged.extend(h.map(|(_, s)| s));
        out.splice(0..0, merged);
    }
    out
}

/// Function-starts ULEB delta stream over `__TEXT,__text` symbols.
fn build_func_starts(sections: &[PlacedSection], symbols: &[OutputSymbol]) -> Vec<u8> {
    let Some(t) = sections
        .iter()
        .position(|s| s.seg_name == "__TEXT" && s.name == "__text")
    else {
        return Vec::new();
    };
    let base = sections[t].vm_addr;
    let mut starts: Vec<u64> = symbols
        .iter()
        .filter(|s| s.n_sect == (t + 1) as u8 && s.value >= base)
        .map(|s| s.value - base)
        .collect();
    starts.sort_unstable();
    starts.dedup();
    let mut out = Vec::with_capacity(starts.len() * 2);
    for v in starts {
        out.extend_from_slice(&uleb(v));
    }
    out
}

/// ULEB128 encoding.
#[must_use]
pub fn uleb(mut v: u64) -> Vec<u8> {
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

/// Which fixup load command the header carries (M6: the classic
/// `LC_DYLD_INFO_ONLY` joined the chained command as the legacy fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixupLc {
    /// No fixup metadata (no pointer slots).
    None,
    /// `LC_DYLD_CHAINED_FIXUPS` (macOS ≥ 12 default).
    Chained,
    /// `LC_DYLD_INFO_ONLY` classic opcode streams.
    DyldInfo,
}

impl FixupLc {
    /// The command's byte size (0 when absent).
    const fn size(self) -> usize {
        match self {
            Self::None => 0,
            Self::Chained => 16,
            Self::DyldInfo => 48,
        }
    }
}

/// Assembles header + load commands. Returns `(bytes, uuid_at, entryoff_at)`.
/// `__LINKEDIT` chunk positions the header references.
struct HeaderInputs {
    /// The output image kind (drives filetype, `LC_MAIN/LC_ID_DYLIB`).
    filetype: OutputType,
    /// `LC_SYMTAB`: file offset, entry count.
    sym_off: u64,
    nsyms: usize,
    /// `LC_SYMTAB` string table: file offset, byte size.
    str_off: u64,
    strsize: usize,
    /// `LC_DYLD_CHAINED_FIXUPS` payload (0 size = absent).
    fixup_off: u64,
    fixup_size: usize,
    /// M6 classic `LC_DYLD_INFO_ONLY` streams (0 size = absent).
    dyld_rebase_off: u64,
    dyld_rebase_size: usize,
    dyld_bind_off: u64,
    dyld_bind_size: usize,
    /// `LC_DYLD_EXPORTS_TRIE`.
    trie_off: u64,
    trie_len: usize,
    /// `LC_FUNCTION_STARTS`.
    func_off: u64,
    func_len: usize,
    /// `LC_CODE_SIGNATURE` (0 size = absent).
    sig_off: u64,
    sig_size: u64,
    /// `LC_DYSYMTAB` subranges.
    n_locals: usize,
    n_defs: usize,
    n_undef: usize,
    /// `LC_DYSYMTAB` indirect symbol table.
    indirect_off: u64,
    indirect_count: usize,
    /// `LC_MAIN` entry offset within `__TEXT` (executables only).
    entryoff: u64,
    /// M3 `LC_ID_DYLIB` inputs (dylibs only).
    install_name: Option<String>,
    current_version: u32,
    compatibility_version: u32,
    /// M2 load-command inputs.
    dylibs: Vec<crate::resolve::Dylib>,
    rpaths: Vec<String>,
    source_version: Option<u64>,
    flat_namespace: bool,
    binds_to_weak: bool,
    weak_defines: bool,
    /// M3: at least one `-reexport_library` (suppresses
    /// `MH_NO_REEXPORTED_DYLIBS`).
    has_reexports: bool,
    /// M3 `-mark_dead_strippable_dylib`.
    dead_strippable: bool,
}

/// The exact `LC_LOAD_DYLIB`/`LC_LOAD_WEAK_DYLIB`/`LC_REEXPORT_DYLIB`
/// command size for a name.
fn dylib_cmd_size(install_name: &str) -> usize {
    align8(24 + install_name.len() + 1)
}

/// The exact `LC_RPATH` command size for a path.
fn rpath_cmd_size(path: &str) -> usize {
    align8(12 + path.len() + 1)
}

fn build_header(
    cfg: &LinkConfig,
    segments: &[SegmentPlan],
    sections: &[PlacedSection],
    hi: &HeaderInputs,
) -> Result<(Vec<u8>, u64, u64), LinkError> {
    let is_exec = hi.filetype.is_executable();
    let dylinker_len = align8(12 + "/usr/lib/dyld\0".len());
    let emit_dylinker = is_exec && cfg.dynamic_linker;
    let fixup_lc = if hi.fixup_size > 0 {
        FixupLc::Chained
    } else if hi.dyld_rebase_size > 0 || hi.dyld_bind_size > 0 {
        FixupLc::DyldInfo
    } else {
        FixupLc::None
    };
    let dylib_cmds: Vec<u32> = hi
        .dylibs
        .iter()
        .map(|d| {
            if d.weak {
                pgr_format::consts::LC_LOAD_WEAK_DYLIB
            } else if d.reexport {
                pgr_format::consts::LC_REEXPORT_DYLIB
            } else {
                pgr_format::consts::LC_LOAD_DYLIB
            }
        })
        .collect();
    let ncmds: u32 = u32::try_from(segments.len()).map_err(|_| LinkError::Internal {
        message: "segment count exceeds u32".into(),
    })? + 1 // LC_BUILD_VERSION
        + u32::from(emit_dylinker)
        + u32::from(is_exec) // LC_MAIN
        + u32::from(hi.filetype == OutputType::Dylib) // LC_ID_DYLIB
        + 1 // LC_SYMTAB
        + 1 // LC_DYSYMTAB
        + u32::from(!matches!(fixup_lc, FixupLc::None))
        + 1 // LC_DYLD_EXPORTS_TRIE
        + 1 // LC_FUNCTION_STARTS
        + 1 // LC_UUID
        + u32::from(cfg.adhoc)
        + u32::try_from(hi.dylibs.len()).map_err(|_| LinkError::Internal {
            message: "dylib count exceeds u32".into(),
        })?
        + u32::try_from(hi.rpaths.len()).map_err(|_| LinkError::Internal {
            message: "rpath count exceeds u32".into(),
        })?
        + u32::from(hi.source_version.is_some());
    let nsections: usize = sections.iter().filter(|s| s.size > 0).count();
    let sizeofcmds = command_size(cfg, nsections, fixup_lc);
    debug_assert_eq!(
        32 + sizeofcmds,
        32 + 72 * segments.len()
            + 80 * nsections
            + 32 // LC_BUILD_VERSION
            + if emit_dylinker { dylinker_len } else { 0 }
            + if is_exec { 24 } else { 0 } // LC_MAIN
            + if hi.filetype == OutputType::Dylib {
                dylib_cmd_size(hi.install_name.as_deref().unwrap_or(""))
            } else {
                0
            }
            + 24 // LC_SYMTAB
            + 80 // LC_DYSYMTAB
            + fixup_lc.size()
            + 16 // LC_DYLD_EXPORTS_TRIE
            + 16 // LC_FUNCTION_STARTS
            + 24 // LC_UUID
            + if cfg.adhoc { 16 } else { 0 } // LC_CODE_SIGNATURE
            + hi.dylibs.iter().map(|d| dylib_cmd_size(&d.install_name)).sum::<usize>()
            + hi.rpaths.iter().map(|p| rpath_cmd_size(p)).sum::<usize>()
            + if hi.source_version.is_some() { 16 } else { 0 },
        "sizing formula drift"
    );
    let mut buf = vec![0u8; 32 + sizeofcmds];
    let w32 = |buf: &mut [u8], at: usize, v: u32| buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let w64 = |buf: &mut [u8], at: usize, v: u64| buf[at..at + 8].copy_from_slice(&v.to_le_bytes());

    w32(&mut buf, 0, pgr_format::consts::MH_MAGIC_64);
    w32(&mut buf, 4, pgr_format::consts::CPU_TYPE_ARM64);
    w32(&mut buf, 8, pgr_format::consts::CPU_SUBTYPE_ARM64_ALL);
    w32(&mut buf, 12, hi.filetype.filetype());
    w32(&mut buf, 16, ncmds);
    w32(&mut buf, 20, sizeofcmds as u32);
    // Header flags (M3 semantics): MH_NOUNDEFS only when the symtab carries
    // no undefined externals; MH_PIE only for executables; dylibs without
    // re-exports carry MH_NO_REEXPORTED_DYLIBS (ld64's convention).
    let mut flags = pgr_format::consts::MH_DYLDLINK;
    if hi.n_undef == 0 {
        flags |= pgr_format::consts::MH_NOUNDEFS;
    }
    if is_exec {
        flags |= pgr_format::consts::MH_PIE;
    }
    if hi.filetype == OutputType::Dylib && !hi.has_reexports {
        flags |= pgr_format::consts::MH_NO_REEXPORTED_DYLIBS;
    }
    if hi.dead_strippable {
        flags |= pgr_format::consts::MH_DEAD_STRIPPABLE_DYLIB;
    }
    if !hi.flat_namespace {
        flags |= MH_TWOLEVEL;
    }
    if hi.weak_defines {
        flags |= MH_WEAK_DEFINES;
    }
    if hi.binds_to_weak {
        flags |= MH_BINDS_TO_WEAK;
    }
    w32(&mut buf, 24, flags);

    let mut lc = 32usize;
    for seg in segments {
        let seg_sects: Vec<&PlacedSection> = seg
            .sections
            .iter()
            .filter_map(|&i| sections.get(i))
            .filter(|s| s.size > 0)
            .collect();
        w32(&mut buf, lc, pgr_format::consts::LC_SEGMENT_64);
        w32(&mut buf, lc + 4, (72 + 80 * seg_sects.len()) as u32);
        buf[lc + 8..lc + 24].copy_from_slice(&pad16(seg.name.as_bytes()));
        w64(&mut buf, lc + 24, seg.vmaddr);
        w64(&mut buf, lc + 32, seg.vmsize);
        w64(&mut buf, lc + 40, seg.fileoff);
        w64(&mut buf, lc + 48, seg.filesize);
        w32(&mut buf, lc + 56, seg.maxprot);
        w32(&mut buf, lc + 60, seg.initprot);
        w32(&mut buf, lc + 64, seg_sects.len() as u32);
        w32(&mut buf, lc + 68, 0);
        lc += 72;
        for s in seg_sects {
            let mut sect = [0u8; 80];
            sect[0..16].copy_from_slice(&pad16(s.name.as_bytes()));
            sect[16..32].copy_from_slice(&pad16(seg.name.as_bytes()));
            w64(&mut sect, 32, s.vm_addr);
            w64(&mut sect, 40, s.size);
            w32(&mut sect, 48, s.file_off as u32);
            w32(&mut sect, 52, s.align_log2);
            w32(&mut sect, 56, 0); // no output relocations
            w32(&mut sect, 60, 0);
            w32(&mut sect, 64, s.flags);
            buf[lc..lc + 80].copy_from_slice(&sect);
            lc += 80;
        }
    }
    // LC_BUILD_VERSION (one ld tool entry).
    w32(&mut buf, lc, pgr_format::consts::LC_BUILD_VERSION);
    w32(&mut buf, lc + 4, 32);
    w32(&mut buf, lc + 8, cfg.platform);
    w32(&mut buf, lc + 12, cfg.minos);
    w32(&mut buf, lc + 16, cfg.sdk);
    w32(&mut buf, lc + 20, 1);
    w32(&mut buf, lc + 24, pgr_format::consts::TOOL_LD);
    w32(&mut buf, lc + 28, 0x000f_0200);
    lc += 32;
    if emit_dylinker {
        w32(&mut buf, lc, pgr_format::consts::LC_LOAD_DYLINKER);
        w32(&mut buf, lc + 4, dylinker_len as u32);
        w32(&mut buf, lc + 8, 12);
        buf[lc + 12..lc + 12 + "/usr/lib/dyld\0".len()].copy_from_slice(b"/usr/lib/dyld\0");
        lc += dylinker_len;
    }
    // LC_ID_DYLIB (dylibs): the install name the two-level namespace keys on.
    if hi.filetype == OutputType::Dylib {
        let name = hi.install_name.as_deref().unwrap_or("");
        let cmdsize = dylib_cmd_size(name);
        w32(&mut buf, lc, pgr_format::consts::LC_ID_DYLIB);
        w32(&mut buf, lc + 4, cmdsize as u32);
        w32(&mut buf, lc + 8, 24); // name lc_str offset
        w32(&mut buf, lc + 12, 1); // timestamp (ld64 writes 1)
        w32(&mut buf, lc + 16, hi.current_version);
        w32(&mut buf, lc + 20, hi.compatibility_version);
        buf[lc + 24..lc + 24 + name.len()].copy_from_slice(name.as_bytes());
        buf[lc + 24 + name.len()] = 0;
        lc += cmdsize;
    }
    // LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB / LC_REEXPORT_DYLIB per input
    // dylib, in ordinal order — the two-level namespace index base
    // (TDD §3.3); re-exports join the same ordinal space (M3).
    for (d, &cmd) in hi.dylibs.iter().zip(dylib_cmds.iter()) {
        let name = d.install_name.as_bytes();
        let cmdsize = dylib_cmd_size(&d.install_name);
        w32(&mut buf, lc, cmd);
        w32(&mut buf, lc + 4, cmdsize as u32);
        w32(&mut buf, lc + 8, 24); // name lc_str offset
        w32(&mut buf, lc + 12, 1); // timestamp (ld64 writes 1)
        w32(&mut buf, lc + 16, d.current_version);
        w32(&mut buf, lc + 20, d.compatibility_version);
        buf[lc + 24..lc + 24 + name.len()].copy_from_slice(name);
        buf[lc + 24 + name.len()] = 0;
        lc += cmdsize;
    }
    // LC_RPATH per `-rpath` entry.
    for p in &hi.rpaths {
        let path = p.as_bytes();
        let cmdsize = rpath_cmd_size(p);
        w32(&mut buf, lc, pgr_format::consts::LC_RPATH);
        w32(&mut buf, lc + 4, cmdsize as u32);
        w32(&mut buf, lc + 8, 12); // path lc_str offset
        buf[lc + 12..lc + 12 + path.len()].copy_from_slice(path);
        buf[lc + 12 + path.len()] = 0;
        lc += cmdsize;
    }
    // LC_SOURCE_VERSION (when configured).
    if let Some(sv) = hi.source_version {
        w32(&mut buf, lc, pgr_format::consts::LC_SOURCE_VERSION);
        w32(&mut buf, lc + 4, 16);
        w64(&mut buf, lc + 8, sv);
        lc += 16;
    }
    // LC_MAIN: executables only (M3: dylibs and bundles carry none).
    let entryoff_at;
    if is_exec {
        w32(&mut buf, lc, pgr_format::consts::LC_MAIN);
        w32(&mut buf, lc + 4, 24);
        entryoff_at = lc + 8;
        w64(&mut buf, entryoff_at, hi.entryoff);
        w64(&mut buf, lc + 16, 0); // stacksize
        lc += 24;
    } else {
        entryoff_at = 0;
    }
    w32(&mut buf, lc, pgr_format::consts::LC_SYMTAB);
    w32(&mut buf, lc + 4, 24);
    w32(&mut buf, lc + 8, hi.sym_off as u32);
    w32(&mut buf, lc + 12, hi.nsyms as u32);
    w32(&mut buf, lc + 16, hi.str_off as u32);
    w32(&mut buf, lc + 20, hi.strsize as u32);
    lc += 24;
    w32(&mut buf, lc, pgr_format::consts::LC_DYSYMTAB);
    w32(&mut buf, lc + 4, 80);
    w32(&mut buf, lc + 8, 0); // ilocalsym
    w32(&mut buf, lc + 12, hi.n_locals as u32);
    w32(&mut buf, lc + 16, hi.n_locals as u32); // iextdefsym
    w32(&mut buf, lc + 20, hi.n_defs as u32);
    w32(&mut buf, lc + 24, (hi.n_locals + hi.n_defs) as u32); // iundefsym
    w32(&mut buf, lc + 28, hi.n_undef as u32);
    // toc/modtoc/extref... legacy zeros; the indirect symbol table lives in
    // the tail fields (off 56: indirectsymoff, off 60: nindirectsyms).
    w32(&mut buf, lc + 56, hi.indirect_off as u32);
    w32(&mut buf, lc + 60, hi.indirect_count as u32);
    lc += 80;
    if fixup_lc == FixupLc::Chained {
        w32(&mut buf, lc, pgr_format::consts::LC_DYLD_CHAINED_FIXUPS);
        w32(&mut buf, lc + 4, 16);
        w32(&mut buf, lc + 8, hi.fixup_off as u32);
        w32(&mut buf, lc + 12, hi.fixup_size as u32);
        lc += 16;
    } else if fixup_lc == FixupLc::DyldInfo {
        // M6 legacy fallback: the classic opcode streams (no lazy/weak
        // split — weak rides the bind stream's flags; exports live in
        // LC_DYLD_EXPORTS_TRIE).
        w32(&mut buf, lc, pgr_format::consts::LC_DYLD_INFO_ONLY);
        w32(&mut buf, lc + 4, 48);
        w32(&mut buf, lc + 8, hi.dyld_rebase_off as u32);
        w32(&mut buf, lc + 12, hi.dyld_rebase_size as u32);
        w32(&mut buf, lc + 16, hi.dyld_bind_off as u32);
        w32(&mut buf, lc + 20, hi.dyld_bind_size as u32);
        w32(&mut buf, lc + 24, 0); // weak_bind_off
        w32(&mut buf, lc + 28, 0); // weak_bind_size
        w32(&mut buf, lc + 32, 0); // lazy_bind_off
        w32(&mut buf, lc + 36, 0); // lazy_bind_size
        w32(&mut buf, lc + 40, 0); // export_off
        w32(&mut buf, lc + 44, 0); // export_size
        lc += 48;
    }
    w32(&mut buf, lc, pgr_format::consts::LC_DYLD_EXPORTS_TRIE);
    w32(&mut buf, lc + 4, 16);
    w32(&mut buf, lc + 8, hi.trie_off as u32);
    w32(&mut buf, lc + 12, hi.trie_len as u32);
    lc += 16;
    w32(&mut buf, lc, pgr_format::consts::LC_FUNCTION_STARTS);
    w32(&mut buf, lc + 4, 16);
    w32(&mut buf, lc + 8, hi.func_off as u32);
    w32(&mut buf, lc + 12, hi.func_len as u32);
    lc += 16;
    let uuid_at = lc + 8;
    w32(&mut buf, lc, pgr_format::consts::LC_UUID);
    w32(&mut buf, lc + 4, 24);
    lc += 24;
    if cfg.adhoc {
        w32(&mut buf, lc, pgr_format::consts::LC_CODE_SIGNATURE);
        w32(&mut buf, lc + 4, 16);
        w32(&mut buf, lc + 8, hi.sig_off as u32);
        w32(&mut buf, lc + 12, hi.sig_size as u32);
        lc += 16;
    }
    debug_assert_eq!(lc, buf.len(), "load command assembly must match sizing");
    Ok((buf, uuid_at as u64, entryoff_at as u64))
}

/// 16-byte NUL-padded name.
fn pad16(name: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = name.len().min(16);
    out[..n].copy_from_slice(&name[..n]);
    out
}

/// The exact `sizeofcmds` — the single source of truth shared by `place`
/// (section start math) and `build_header`.
fn command_size(cfg: &LinkConfig, nsections: usize, fixup_lc: FixupLc) -> usize {
    let is_exec = cfg.filetype.is_executable();
    let emit_dylinker = is_exec && cfg.dynamic_linker;
    let dylinker_len = if emit_dylinker {
        align8(12 + "/usr/lib/dyld\0".len())
    } else {
        0
    };
    // Executables carry __PAGEZERO (5 segments); dylibs/bundles do not (4).
    let nsegments = if is_exec { 5 } else { 4 };
    nsegments * 72
        + 80 * nsections
        + 32 // LC_BUILD_VERSION
        + dylinker_len
        + if cfg.filetype == OutputType::Dylib {
            dylib_cmd_size(cfg.install_name.as_deref().unwrap_or(""))
        } else {
            0
        }
        + cfg.dylibs.iter().map(|d| dylib_cmd_size(&d.install_name)).sum::<usize>()
        + cfg.rpaths.iter().map(|p| rpath_cmd_size(p)).sum::<usize>()
        + usize::from(cfg.source_version.is_some()) * 16 // LC_SOURCE_VERSION
        + usize::from(is_exec) * 24 // LC_MAIN
        + 24 // LC_SYMTAB
        + 80 // LC_DYSYMTAB
        + usize::from(fixup_lc == FixupLc::Chained) * 16 // LC_DYLD_CHAINED_FIXUPS
        + usize::from(fixup_lc == FixupLc::DyldInfo) * 48 // LC_DYLD_INFO_ONLY
        + 16 // LC_DYLD_EXPORTS_TRIE
        + 16 // LC_FUNCTION_STARTS
        + 24 // LC_UUID
        + usize::from(cfg.adhoc) * 16 // LC_CODE_SIGNATURE
}

fn align8(v: usize) -> usize {
    v.div_ceil(8) * 8
}

fn align_up_usize(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

fn align_up_u64(v: u64, a: u64) -> u64 {
    v.div_ceil(a) * a
}

#[cfg(test)]
mod tests {
    use super::{canonical_rank, uleb};

    #[test]
    fn canonical_order_is_fixed() {
        assert!(canonical_rank("__TEXT", "__text") < canonical_rank("__TEXT", "__cstring"));
        assert!(canonical_rank("__TEXT", "__cstring") < canonical_rank("__DATA", "__data"));
        assert_eq!(
            canonical_rank("__DATA", "__some_unknown"),
            canonical_rank("__DATA", "__another_unknown")
        );
    }

    #[test]
    fn uleb_encoding_matches_llvm() {
        assert_eq!(uleb(0), vec![0x00]);
        assert_eq!(uleb(127), vec![0x7f]);
        assert_eq!(uleb(128), vec![0x80, 0x01]);
        assert_eq!(uleb(0x1234), vec![0xb4, 0x24]);
    }
}

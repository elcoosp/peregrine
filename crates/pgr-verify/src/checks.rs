//! The selective verification surface (M12): named check families, the
//! [`CheckSet`] selector and the [`ImageCheck`] registry seam.
//!
//! Whole-image `verify()` runs every family in one fixed sequence. That is
//! the right contract for a final gate, but tooling often needs less: a
//! build system may want the segment contract alone on every relink and
//! the expensive page-hash recompute only at hand-off, or a diagnosis
//! wants exactly the fixup walk on a known-corrupt page. This module makes
//! that selection a nameable value instead of a private dispatch:
//!
//! * [`Check`] enumerates the families in canonical verify order;
//! * [`CheckSet`] is the selector (parse `"segments,fixups"`, build with
//!   [`CheckSet::with`]/[`CheckSet::all`]/[`CheckSet::empty`], render
//!   back with `Display`);
//! * [`ImageCheck`] is the seam each family implements — one unit per
//!   family, collected in [`image_checks`], driven by
//!   `crate::verify_with_checks`.
//!
//! Selection is strictly subtractive: a family runs against the same
//! parsed-image context it gets in the full pass, issues land in the same
//! [`Report`], and the aggregate stats contract (including the
//! fixup-slot count zeroing on any error) is unchanged. The empty set
//! runs the parse pre-pass only, so stats still describe the image.
//!
//! ```no_run
//! use pgr_verify::{CheckSet, Options, verify_with_checks};
//!
//! let bytes = std::fs::read("image").expect("read");
//! let set = CheckSet::parse("segments,fixups").expect("canonical names");
//! let report = verify_with_checks(&bytes, &Options::default(), &set);
//! println!("{}", report.issues.len());
//! ```

use std::fmt;
use std::str::FromStr;

use pgr_format::consts::{MH_BUNDLE, MH_DYLIB, MH_EXECUTE, MH_OBJECT};

use crate::Code;
use crate::Options;
use crate::Report;
use crate::branch_range;
use crate::chain_starts;
use crate::dyld_info;
use crate::dynamic;
use crate::misc;
use crate::signature;
use crate::structural::{self, ParsedImage};

/// One selectable verification family over a parsed image.
///
/// Implementors run against a [`CheckContext`] and push issues into
/// `context.report`. The contract mirrors the whole-image pass: checks
/// are total (never panic on malformed input), self-gate on the image
/// type they apply to (an executable-only check is a no-op on a dylib),
/// and declare up front which codes they may report ([`ImageCheck::codes`]
/// is the machine-readable half of that promise).
///
/// The built-in families live in [`image_checks`]; the trait is public so
/// tooling can read the registry's metadata (names, summaries, code
/// domains) and so a future consumer-side check can slot into the same
/// shape.
pub trait ImageCheck: Sync {
    /// The canonical selector key this unit answers to.
    fn check(&self) -> Check;

    /// The canonical selector name (the `--checks` token).
    fn name(&self) -> &'static str {
        self.check().as_str()
    }

    /// One-line summary (what the family covers; used by the CLI's
    /// `--list-checks`).
    fn summary(&self) -> &'static str;

    /// The issue codes this family may report.
    fn codes(&self) -> &'static [Code];

    /// Runs the family against the context.
    fn run(&self, ctx: &mut CheckContext<'_>);
}

/// Everything a family may read, collected once: the raw bytes, the
/// pre-validated parse, the verification knobs and the report to push
/// issues into.
pub struct CheckContext<'a> {
    /// Raw image bytes.
    pub bytes: &'a [u8],
    /// The parsed image (the parse pre-pass product, shared read-only).
    pub parsed: &'a ParsedImage<'a>,
    /// Verification knobs (`strict_warnings`, `skip_hash_recompute`).
    pub opts: &'a Options,
    /// The report issues land in (already seeded with parse stats).
    pub report: &'a mut Report,
}

/// A named check family, in canonical verify order.
///
/// The order is the whole-image pass's dispatch order
/// ([`image_checks`] mirrors it one-to-one), so a selection's issues
/// land in the same sorted report regardless of how the set was built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Check {
    /// Header magic/flags, load-command well-formedness and the
    /// dylib/bundle output contract.
    Structure,
    /// The 16 KiB segment congruence, ordering and section bounds.
    Segments,
    /// Symbol/indirect tables and the `MH_OBJECT` relocation contract.
    Symbols,
    /// Entry point, build version (incl. the chained-fixups floor),
    /// function starts, data-in-code and export-trie bounds (the UUID
    /// absence is the M32 suppression decision — nothing to gate).
    Linkedit,
    /// The `LC_DYLD_CHAINED_FIXUPS` payload and the full chain-walk
    /// simulation.
    Fixups,
    /// The `__TEXT,__chain_starts` static mirror against the payload
    /// (executables).
    ChainStarts,
    /// The `__TEXT,__unwind_info` synthesis contract (M34): the section
    /// dyld's unwinder walks — header arrays, index, second-level
    /// pages, LSDA rows — against the `__TEXT` the image maps.
    Unwind,
    /// The thread-local surface contract (M37): the
    /// `MH_HAS_TLV_DESCRIPTORS` marker against the `S_THREAD_LOCAL_*`
    /// sections the image carries, the `__thread_vars` descriptor
    /// stride, and the descriptors' thread-local data.
    Tlv,
    /// The `ObjC` registration contract (M115): the
    /// `__objc_catlist`/`__objc_nlcatlist` sections dyld's registration
    /// walk consumes ride whole pointer strides, whether the categories
    /// stay separate (the `-no_objc_category_merging` face) or their
    /// registration folded into the base classes (the default merge).
    Objc,
    /// The initializer-surface contract (M94): the
    /// `S_INIT_FUNC_OFFSETS`/`S_MOD_INIT_FUNC_POINTERS` sections dyld's
    /// load-time initializer walk consumes ride whole strides, the
    /// `__init_offsets` entries name targets an executable segment maps,
    /// and the offsets form stays at or above the platform's
    /// chained-fixups floor.
    InitOffsets,
    /// The `DTrace` `DOF` header contract (M118): every `__dtrace_dof`
    /// (`S_DTRACE_DOF`) section in the output carries a `DOF` payload
    /// whose identification magic and bounds the `DTrace` consumer's first
    /// walk gates on — the read-side backstop the producer's emit-side
    /// gate (under `-dtrace`) mirrors, regardless of how the section was
    /// produced.
    Dtrace,
    /// The `LC_DYSYMTAB` module table contract (M119): when the command
    /// carries a module table (`nmodtab > 0`, the `-single_module` shape),
    /// the table's bytes fit the file and every entry's
    /// `ilocalsym`/`nlocalsym`/`iextdefsym`/`nextdefsym` subrange stays
    /// within the symbol table — the read-side backstop the producer's
    /// emit-side gate mirrors, regardless of how the table was produced.
    ModuleTable,
    /// The debug-map stabs contract (M129): the `ld64`-shaped `n_type`
    /// rows `lldb`/`dsymutil` walk — `N_OSO` well-formedness (a non-empty
    /// path and a nonzero mtime), `N_FUN` bracketing (every begin row
    /// pairs with an end row), section-bearing stab addresses inside
    /// their defining section, and no stabs under `-S` (the existing
    /// strip-debug flag drops the whole map). The read-side backstop
    /// the producer's debug-map emit-side gate mirrors, regardless of
    /// how the stabs were produced.
    DebugMap,
    /// The `B`/`BL` branch-range decode pass (the veneer gate).
    BranchRange,
    /// The classic `LC_DYLD_INFO(_ONLY)` rebase/bind opcode streams.
    DyldInfo,
    /// The SuperBlob/CodeDirectory layout and the SHA-256 page-hash
    /// recompute.
    Signature,
    /// The mergeable literal-pool contract (M131, the D4 completion): the
    /// `S_4BYTE_LITERALS`/`S_8BYTE_LITERALS`/`S_16BYTE_LITERALS` sections
    /// the producer's D4 dedup emits ride a whole atom-width stride and an
    /// alignment at or above the width's own power of two (4→2, 8→3,
    /// 16→4) — the read-side backstop the producer's dedup emit-side gate
    /// mirrors, regardless of how the section was produced. The dedup
    /// correctness itself (one canonical copy per unique value) is pinned
    /// byte-identity by the `m131_literal_merge` gate, the M5 cstring
    /// precedent (cstrings carry no verify family).
    Literal,
    /// The `__objc_stubs` synthesis contract (M6/D-R3, M130 — the family
    /// the `Code::ObjcStubs` read-side backstop was reserved for, wired
    /// once the M130 constants the synthesis lane references ride the
    /// format table again): the `__TEXT,__objc_stubs` section ld64's
    /// `objc_msgSend` dispatch consumes rides `S_SYMBOL_STUBS` (the same
    /// type `__stubs` carries — the name distinguishes the objc family)
    /// and a whole `OBJC_STUB_SIZE_ARM64` stride (every stub is five
    /// arm64 words), and the paired `__TEXT,__objc_methname` section rides
    /// `S_CSTRING_LITERALS`. The read-side backstop the producer's
    /// stub-synthesis emit-side gate mirrors, regardless of how the
    /// section was produced (a malformed stub section the producer never
    /// wrote still reports); the producer's own synthesis lane is a
    /// follow-up, so the family is a no-op on peregrine-linked images
    /// until it lands and backstops third-party (`ld64`-linked) images
    /// carrying the section in the meantime.
    ObjcStubs,
    /// The exit-time terminator-surface contract (M132): the
    /// `S_MOD_TERM_FUNC_POINTERS` section dyld's exit walk consumes
    /// (`MachOAnalyzer::forEachTerminator`, the mirror of the initializer
    /// walk the [`InitOffsets`] family gates) rides a whole 8-byte pointer
    /// stride — the walk reads whole slots, and the slots are fixup words
    /// (chained rebase encodings under `LC_DYLD_CHAINED_FIXUPS`,
    /// opcode-driven rebases under the legacy streams), so the raw bytes
    /// stay unread and the stride is the shape the gate can honestly
    /// check (the M94 pointer-form precedent, one section type over —
    /// `S_MOD_TERM_FUNC_POINTERS` 0xa beside `S_MOD_INIT_FUNC_POINTERS`
    /// 0x9). The read-side backstop the producer's `__mod_term_func`
    /// emit-side stride assumes, regardless of how the section was
    /// produced (the M115/M131 read-side-backstop shape).
    ModTerm,
}

impl Check {
    /// Every family, in canonical verify order (the registry order).
    pub const ALL: [Check; 19] = [
        Check::Structure,
        Check::Segments,
        Check::Symbols,
        Check::Linkedit,
        Check::Fixups,
        Check::ChainStarts,
        Check::Unwind,
        Check::Tlv,
        Check::Objc,
        Check::InitOffsets,
        Check::Dtrace,
        Check::ModuleTable,
        Check::DebugMap,
        Check::BranchRange,
        Check::DyldInfo,
        Check::Signature,
        Check::Literal,
        Check::ObjcStubs,
        Check::ModTerm,
    ];

    /// Stable string identifier (the `--checks` token).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Check::Structure => "structure",
            Check::Segments => "segments",
            Check::Symbols => "symbols",
            Check::Linkedit => "linkedit",
            Check::Fixups => "fixups",
            Check::ChainStarts => "chain_starts",
            Check::Unwind => "unwind",
            Check::Tlv => "tlv",
            Check::Objc => "objc",
            Check::InitOffsets => "init_offsets",
            Check::Dtrace => "dtrace",
            Check::ModuleTable => "module_table",
            Check::DebugMap => "debugmap",
            Check::BranchRange => "branch_range",
            Check::DyldInfo => "dyld_info",
            Check::Signature => "signature",
            Check::Literal => "literal",
            Check::ObjcStubs => "objc_stubs",
            Check::ModTerm => "mod_term",
        }
    }

    /// Position in [`Check::ALL`] (the `CheckSet` bit index).
    const fn index(self) -> usize {
        match self {
            Check::Structure => 0,
            Check::Segments => 1,
            Check::Symbols => 2,
            Check::Linkedit => 3,
            Check::Fixups => 4,
            Check::ChainStarts => 5,
            Check::Unwind => 6,
            Check::Tlv => 7,
            Check::Objc => 8,
            Check::InitOffsets => 9,
            Check::Dtrace => 10,
            Check::ModuleTable => 11,
            Check::DebugMap => 12,
            Check::BranchRange => 13,
            Check::DyldInfo => 14,
            Check::Signature => 15,
            Check::Literal => 16,
            Check::ObjcStubs => 17,
            Check::ModTerm => 18,
        }
    }
}

/// A [`CheckSet::parse`] failure: the offending token plus the canonical
/// names, so the fix (not just the verdict) is one line away.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown check `{invalid}` (valid checks: {})", .valid.join(", "))]
pub struct CheckSetError {
    /// The token that named no family (empty for empty input).
    pub invalid: String,
    /// The canonical selector names, in verify order.
    pub valid: Vec<&'static str>,
}

/// The selector: a set of check families to run.
///
/// `CheckSet::all()` is the whole-image pass (what `verify` runs);
/// smaller sets subtract work. The mask is one bit per [`Check::ALL`]
/// position, so contains/dedup are bit tests and `Display` renders the
/// canonical names in verify order (which re-parses to the same set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckSet {
    mask: u32,
}

const fn bit(check: Check) -> u32 {
    1 << check.index()
}

/// One bit per [`Check::ALL`] entry.
const ALL_MASK: u32 = (1 << Check::ALL.len()) - 1;

impl CheckSet {
    /// The full pass: every family, exactly what `verify` runs.
    #[must_use]
    pub const fn all() -> Self {
        Self { mask: ALL_MASK }
    }

    /// The empty set: the parse pre-pass only (no families run, but the
    /// parse-derived stats still describe the image).
    #[must_use]
    pub const fn empty() -> Self {
        Self { mask: 0 }
    }

    /// Adds a family (dedup free — it is a bit test; the `checks` bench
    /// builds its per-family sets this way).
    #[must_use]
    pub const fn with(mut self, check: Check) -> Self {
        self.mask |= bit(check);
        self
    }

    /// True when the family will run.
    #[must_use]
    pub const fn contains(self, check: Check) -> bool {
        self.mask & bit(check) != 0
    }

    /// The selected families' canonical names, in verify order.
    pub fn names(&self) -> impl Iterator<Item = &'static str> {
        Check::ALL
            .iter()
            .copied()
            .filter(|c| self.contains(*c))
            .map(Check::as_str)
    }

    /// Parses a comma-separated selector (`"segments,fixups"`).
    ///
    /// Tokens are trimmed; duplicates collapse into the same set. Names
    /// are the exact lowercase canonical tokens (`Check::as_str`).
    ///
    /// # Errors
    /// [`CheckSetError`] naming the first unknown (or empty) token and
    /// carrying the canonical names.
    pub fn parse(names: &str) -> Result<Self, CheckSetError> {
        let mut mask = 0u32;
        for token in names.split(',') {
            let token = token.trim();
            match Check::ALL.iter().copied().find(|c| c.as_str() == token) {
                Some(check) => mask |= bit(check),
                None => {
                    return Err(CheckSetError {
                        invalid: token.to_owned(),
                        valid: Check::ALL.iter().copied().map(Check::as_str).collect(),
                    });
                }
            }
        }
        Ok(Self { mask })
    }
}

impl FromStr for CheckSet {
    type Err = CheckSetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CheckSet::parse(s)
    }
}

impl fmt::Display for CheckSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for name in self.names() {
            if !first {
                f.write_str(",")?;
            }
            f.write_str(name)?;
            first = false;
        }
        Ok(())
    }
}

// -------------------------------------------------------------- registry

struct StructureCheck;
struct SegmentsCheck;
struct SymbolsCheck;
struct LinkeditCheck;
struct UnwindCheck;
struct FixupsCheck;
struct ChainStartsCheck;
struct BranchRangeCheck;
struct DyldInfoCheck;
struct SignatureCheck;

impl ImageCheck for StructureCheck {
    fn check(&self) -> Check {
        Check::Structure
    }
    fn summary(&self) -> &'static str {
        "header magic/flags, load commands, dylib contract"
    }
    fn codes(&self) -> &'static [Code] {
        &[
            Code::HeaderInvalid,
            Code::LoadCommandMalformed,
            Code::LinkeditPayload,
            Code::Suspicious,
        ]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        structural::check_header(ctx.parsed, ctx.report);
        structural::check_load_commands(ctx.parsed, ctx.report);
        structural::check_dylib_contract(ctx.parsed, ctx.report);
    }
}

impl ImageCheck for SegmentsCheck {
    fn check(&self) -> Check {
        Check::Segments
    }
    fn summary(&self) -> &'static str {
        "16 KiB segment congruence, ordering and section bounds"
    }
    fn codes(&self) -> &'static [Code] {
        &[
            Code::SegmentContract,
            Code::SegmentLayout,
            Code::ImageBase,
            Code::SectionBounds,
            Code::Suspicious,
        ]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        structural::check_segments(ctx.bytes, ctx.parsed, ctx.report);
    }
}

impl ImageCheck for SymbolsCheck {
    fn check(&self) -> Check {
        Check::Symbols
    }
    fn summary(&self) -> &'static str {
        "symbol/indirect tables and the MH_OBJECT relocation contract"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::SymbolTable, Code::LoadCommandMalformed]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        structural::check_symbol_table(ctx.bytes, ctx.parsed, ctx.report);
        if ctx.parsed.header.filetype == MH_OBJECT {
            structural::check_object_contract(ctx.bytes, ctx.parsed, ctx.report);
        }
    }
}

impl ImageCheck for LinkeditCheck {
    fn check(&self) -> Check {
        Check::Linkedit
    }
    fn summary(&self) -> &'static str {
        "entry point, build version + fixups floor, LINKEDIT payloads"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::LinkeditPayload, Code::FixupsFloor]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        misc::check_entry_and_version(ctx.parsed, ctx.report);
        misc::check_linkedit_payloads(ctx.bytes, ctx.parsed, ctx.report);
    }
}

impl ImageCheck for FixupsCheck {
    fn check(&self) -> Check {
        Check::Fixups
    }
    fn summary(&self) -> &'static str {
        "chained-fixups payload structure and the full chain walk"
    }
    fn codes(&self) -> &'static [Code] {
        &[
            Code::FixupsPayload,
            Code::FixupsChain,
            Code::FixupsImport,
            Code::FixupsSegmentOffset,
        ]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        if !matches!(
            ctx.parsed.header.filetype,
            MH_EXECUTE | MH_DYLIB | MH_BUNDLE
        ) {
            return;
        }
        if let Some(lc) = &ctx.parsed.fixups {
            dynamic::check_fixups(ctx.bytes, ctx.parsed, lc, ctx.report);
        }
    }
}

impl ImageCheck for UnwindCheck {
    fn check(&self) -> Check {
        Check::Unwind
    }
    fn summary(&self) -> &'static str {
        "__unwind_info synthesis contract: header arrays, index, second-level pages, LSDA rows"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::UnwindInfo]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        crate::unwind::check_unwind_info(ctx.bytes, ctx.parsed, ctx.report);
    }
}

/// The M37 thread-local surface contract.
struct TlvCheck;

/// The M115 `ObjC` registration contract.
struct ObjcCheck;

impl ImageCheck for ObjcCheck {
    fn check(&self) -> Check {
        Check::Objc
    }
    fn summary(&self) -> &'static str {
        "ObjC registration: __objc_catlist/__objc_nlcatlist pointer strides"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::ObjcRegistration]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        crate::objc::check_objc_registration(ctx.bytes, ctx.report);
    }
}

/// The M94 initializer-surface contract.
struct InitOffsetsCheck;

impl ImageCheck for InitOffsetsCheck {
    fn check(&self) -> Check {
        Check::InitOffsets
    }
    fn summary(&self) -> &'static str {
        "initializer surface: S_INIT_FUNC_OFFSETS/S_MOD_INIT_FUNC_POINTERS strides, \
         __init_offsets targets in an executable segment, the chained-fixups floor"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::InitOffsets]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        if matches!(
            ctx.parsed.header.filetype,
            MH_EXECUTE | MH_DYLIB | MH_BUNDLE
        ) {
            crate::init_offsets::check_init_offsets(ctx.bytes, ctx.parsed, ctx.report);
        }
    }
}

/// The M118 `DTrace` `DOF` header contract.
struct DtraceCheck;

impl ImageCheck for DtraceCheck {
    fn check(&self) -> Check {
        Check::Dtrace
    }
    fn summary(&self) -> &'static str {
        "DTrace DOF header: __dtrace_dof (S_DTRACE_DOF) identification magic and bounds"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::DtraceDof]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        crate::dtrace::check_dtrace_dof(ctx.bytes, ctx.report);
    }
}

/// The M119 `LC_DYSYMTAB` module table contract.
struct ModuleTableCheck;

impl ImageCheck for ModuleTableCheck {
    fn check(&self) -> Check {
        Check::ModuleTable
    }
    fn summary(&self) -> &'static str {
        "LC_DYSYMTAB module table: modtaboff/nmodtab bounds and per-entry symtab subranges"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::ModuleTable]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        crate::module_table::check_module_table(ctx.bytes, ctx.report);
    }
}

/// The M129 debug-map stabs contract.
struct DebugMapCheck;

impl ImageCheck for DebugMapCheck {
    fn check(&self) -> Check {
        Check::DebugMap
    }
    fn summary(&self) -> &'static str {
        "debug-map stabs: N_OSO well-formedness, N_FUN bracketing, \
         section-bearing addresses inside their defining section, no stabs under -S"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::DebugMap]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        crate::debugmap::check_debug_map(ctx.bytes, ctx.parsed, ctx.report);
    }
}

/// The M131 mergeable literal-pool contract (the D4 completion).
struct LiteralCheck;

impl ImageCheck for LiteralCheck {
    fn check(&self) -> Check {
        Check::Literal
    }
    fn summary(&self) -> &'static str {
        "mergeable literal pools: __literal4/8/16 ride a whole atom-width \
         stride and an alignment at or above the width's own power of two"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::Literal]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        crate::literal::check_literals(ctx.bytes, ctx.parsed, ctx.report);
    }
}

/// The M6/D-R3 (M130) `__objc_stubs` synthesis contract — the family the
/// `Code::ObjcStubs` read-side backstop was reserved for, wired once the
/// M130 constants the synthesis lane references ride the format table
/// again (the family was implemented but never registered, leaving
/// `check_objc_stubs` dead code the M131 compile breakage had masked).
struct ObjcStubsCheck;

impl ImageCheck for ObjcStubsCheck {
    fn check(&self) -> Check {
        Check::ObjcStubs
    }
    fn summary(&self) -> &'static str {
        "objc stubs: __objc_stubs rides S_SYMBOL_STUBS and the \
         OBJC_STUB_SIZE_ARM64 stride, __objc_methname rides S_CSTRING_LITERALS"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::ObjcStubs]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        crate::objcstubs::check_objc_stubs(ctx.bytes, ctx.report);
    }
}

/// The M132 exit-time terminator-surface contract.
struct ModTermCheck;

impl ImageCheck for ModTermCheck {
    fn check(&self) -> Check {
        Check::ModTerm
    }
    fn summary(&self) -> &'static str {
        "terminator surface: __mod_term_func (S_MOD_TERM_FUNC_POINTERS) rides \
         the whole 8-byte pointer stride dyld's exit walk consumes"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::ModTerm]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        if matches!(
            ctx.parsed.header.filetype,
            MH_EXECUTE | MH_DYLIB | MH_BUNDLE
        ) {
            crate::mod_term::check_mod_term(ctx.bytes, ctx.parsed, ctx.report);
        }
    }
}

impl ImageCheck for TlvCheck {
    fn check(&self) -> Check {
        Check::Tlv
    }
    fn summary(&self) -> &'static str {
        "TLV contract: MH_HAS_TLV_DESCRIPTORS parity, __thread_vars descriptor stride, thread-local data"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::Tlv]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        if matches!(
            ctx.parsed.header.filetype,
            MH_EXECUTE | MH_DYLIB | MH_BUNDLE
        ) {
            crate::tlv::check_tlv(ctx.bytes, ctx.parsed, ctx.report);
        }
    }
}

impl ImageCheck for ChainStartsCheck {
    fn check(&self) -> Check {
        Check::ChainStarts
    }
    fn summary(&self) -> &'static str {
        "__chain_starts static mirror against the payload (executables)"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::LinkeditPayload]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        if ctx.parsed.header.filetype == MH_EXECUTE {
            chain_starts::check_chain_starts(ctx.bytes, ctx.parsed, ctx.report);
        }
    }
}

impl ImageCheck for BranchRangeCheck {
    fn check(&self) -> Check {
        Check::BranchRange
    }
    fn summary(&self) -> &'static str {
        "B/BL branch-range decode pass (the veneer gate)"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::BranchRange]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        if matches!(
            ctx.parsed.header.filetype,
            MH_EXECUTE | MH_DYLIB | MH_BUNDLE
        ) {
            branch_range::check_branch_range(ctx.bytes, ctx.parsed, ctx.report);
        }
    }
}

impl ImageCheck for DyldInfoCheck {
    fn check(&self) -> Check {
        Check::DyldInfo
    }
    fn summary(&self) -> &'static str {
        "classic LC_DYLD_INFO rebase/bind opcode streams"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::DyldInfoStreams]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        if matches!(
            ctx.parsed.header.filetype,
            MH_EXECUTE | MH_DYLIB | MH_BUNDLE
        ) {
            dyld_info::check_dyld_info(ctx.bytes, ctx.parsed, ctx.report);
        }
    }
}

impl ImageCheck for SignatureCheck {
    fn check(&self) -> Check {
        Check::Signature
    }
    fn summary(&self) -> &'static str {
        "SuperBlob/CodeDirectory layout and SHA-256 page-hash recompute"
    }
    fn codes(&self) -> &'static [Code] {
        &[
            Code::SignatureLayout,
            Code::SignatureHashMismatch,
            Code::Suspicious,
        ]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        if matches!(
            ctx.parsed.header.filetype,
            MH_EXECUTE | MH_DYLIB | MH_BUNDLE
        ) {
            signature::check_signature(
                ctx.bytes,
                ctx.parsed,
                !ctx.opts.skip_hash_recompute,
                ctx.report,
            );
        }
    }
}

/// A consumer-side check slotting beside the built-in families (M67).
///
/// [`ImageCheck`] is the registry's shape, but its identity is a
/// [`Check`] family key — closed over the eleven built-in families the
/// selector names. A project policy is none of those: this trait is the
/// consumer-side unit the registry's doc promised, same contract, own
/// identity:
///
/// * total (never panics on malformed input) like every family;
/// * self-gating on the image type it applies to (a no-op elsewhere);
/// * declaring its codes up front ([`CustomCheck::codes`] is the
///   machine-readable half of the promise) — a policy's own tokens ride
///   [`Code::Custom`], outside the canonical table;
/// * pushing issues into `context.report` (the run sorts them back).
///
/// The name and summary are metadata (tooling reads them the way the
/// CLI's `--list-checks` reads the registry); names are not deduplicated
/// and two same-named checks both run in caller order — the caller's
/// slice is the registry. `verify_with_extra_checks` drives the units
/// after the selected built-in families, into the same sorted report.
pub trait CustomCheck: Sync {
    /// The check's name (metadata; not a selector key).
    fn name(&self) -> &'static str;

    /// One-line summary (what the policy covers).
    fn summary(&self) -> &'static str;

    /// The issue codes this check may report (a policy's own tokens ride
    /// [`Code::Custom`]).
    fn codes(&self) -> &'static [Code];

    /// Runs the check against the context.
    fn run(&self, ctx: &mut CheckContext<'_>);
}

/// The built-in check registry, in canonical verify order (one unit per
/// [`Check::ALL`] entry, same sequence as the whole-image pass).
static IMAGE_CHECKS: [&'static dyn ImageCheck; 19] = [
    &StructureCheck,
    &SegmentsCheck,
    &SymbolsCheck,
    &LinkeditCheck,
    &FixupsCheck,
    &ChainStartsCheck,
    &UnwindCheck,
    &TlvCheck,
    &ObjcCheck,
    &InitOffsetsCheck,
    &DtraceCheck,
    &ModuleTableCheck,
    &DebugMapCheck,
    &BranchRangeCheck,
    &DyldInfoCheck,
    &SignatureCheck,
    &LiteralCheck,
    &ObjcStubsCheck,
    &ModTermCheck,
];

/// The built-in check registry, in canonical verify order.
///
/// Tooling reads this to enumerate the selector surface (names,
/// summaries, code domains); `verify_with_checks` drives it.
#[must_use]
pub fn image_checks() -> &'static [&'static dyn ImageCheck] {
    &IMAGE_CHECKS
}

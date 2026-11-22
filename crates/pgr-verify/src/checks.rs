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
    /// The `B`/`BL` branch-range decode pass (the veneer gate).
    BranchRange,
    /// The classic `LC_DYLD_INFO(_ONLY)` rebase/bind opcode streams.
    DyldInfo,
    /// The SuperBlob/CodeDirectory layout and the SHA-256 page-hash
    /// recompute.
    Signature,
}

impl Check {
    /// Every family, in canonical verify order (the registry order).
    pub const ALL: [Check; 15] = [
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
        Check::BranchRange,
        Check::DyldInfo,
        Check::Signature,
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
            Check::BranchRange => "branch_range",
            Check::DyldInfo => "dyld_info",
            Check::Signature => "signature",
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
            Check::BranchRange => 12,
            Check::DyldInfo => 13,
            Check::Signature => 14,
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
    mask: u16,
}

const fn bit(check: Check) -> u16 {
    1 << check.index()
}

/// One bit per [`Check::ALL`] entry.
const ALL_MASK: u16 = (1 << Check::ALL.len()) - 1;

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
        let mut mask = 0u16;
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
static IMAGE_CHECKS: [&'static dyn ImageCheck; 15] = [
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
    &BranchRangeCheck,
    &DyldInfoCheck,
    &SignatureCheck,
];

/// The built-in check registry, in canonical verify order.
///
/// Tooling reads this to enumerate the selector surface (names,
/// summaries, code domains); `verify_with_checks` drives it.
#[must_use]
pub fn image_checks() -> &'static [&'static dyn ImageCheck] {
    &IMAGE_CHECKS
}

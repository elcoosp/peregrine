//! Peregrine read-side verifier (M0, "verifier first").
//!
//! The verifier is the executable specification of Peregrine's Mach-O output
//! contract (TDD §3, §11): structural well-formedness, the 16 KiB segment
//! congruence, a full dyld chain-walk simulation of `LC_DYLD_CHAINED_FIXUPS`,
//! and recomputation of the ad-hoc signature's SHA-256 page hashes. It never
//! panics on malformed input — every check returns issues, and the fuzz
//! targets plus property tests keep that guarantee under mutation.
//!
//! The build-version gate is platform-aware (M10 rung 2): the five linked
//! platforms (`macos`, `ios`, `tvos`, `watchos`, `visionos`) verify clean,
//! an unknown platform constant is an error, and an SDK older than the
//! deployment target is refused — the platform the linker declares is the
//! platform the verifier checks, not "macOS or warn". Rung 3 closes the
//! encoding half of the same gate: the verifier reads the per-platform
//! chained-fixups floor (`pgr_format::consts::chained_fixups_floor`, the
//! canonical table the layout and `pgr_core::platform::FixupEncoding`
//! encode — one table, three readers), so chained words below the
//! declared platform's floor are a named `fixups_floor` error with the
//! fix in the message.
//!
//! Decomposition:
//!
//! * [`structural`] — header, load commands, segment contract, symbol tables
//!   and the misc `__LINKEDIT` payloads (function starts, data-in-code,
//!   build version, `LC_MAIN`, export trie bounds),
//! * [`dynamic`] — the chained-fixups payload and chain-walk simulation,
//! * [`signature`] — SuperBlob/CodeDirectory layout and page-hash recompute,
//! * [`pair`] — the M3 dylib + executable pair gate (two-level ordinals vs
//!   the dylib's export trie, replayed family-blind across both chain word
//!   families),
//! * [`branch_range`] — the M6 `B`/`BL` decode pass backing the veneer
//!   (thunk) placement gate.

pub mod branch_range;
pub mod chain_starts;
pub mod dyld_info;
pub mod dynamic;
pub mod export_trie;
pub mod misc;
pub mod pair;
pub mod signature;
pub mod structural;

use pgr_format::FormatError;
use pgr_format::consts::{MH_BUNDLE, MH_DYLIB, MH_EXECUTE, MH_OBJECT};

/// Verification target knobs (M0: fixed to the arm64-apple-darwin contract).
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Treat warnings as failures (CLI `--strict`).
    pub strict_warnings: bool,
    /// Skip the (relatively expensive) signature hash recompute.
    pub skip_hash_recompute: bool,
}

/// Issue severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Contract violation: the image is invalid for the Peregrine pipeline.
    Error,
    /// Suspicious but not contract-breaking.
    Warning,
}

/// Machine-checkable issue identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// Header magic, cpu type, size or reserved field is wrong.
    HeaderInvalid,
    /// A load command's size/alignment/region is malformed.
    LoadCommandMalformed,
    /// Segment vmaddr/fileoff congruence or protection contract broken.
    SegmentContract,
    /// Segment ordering, coverage or overlap violates the canonical layout.
    SegmentLayout,
    /// `__PAGEZERO` / `__TEXT` base contract broken (executables).
    ImageBase,
    /// A section lies outside its segment or the file.
    SectionBounds,
    /// Symbol/indirect/string table bounds or entries are invalid.
    SymbolTable,
    /// Chained-fixups payload structure is malformed or unsupported.
    FixupsPayload,
    /// A chain walk violated stride/page/termination invariants.
    FixupsChain,
    /// A bind ordinal, import entry or name is out of range.
    FixupsImport,
    /// `segment_offset` does not match the file-offset contract.
    FixupsSegmentOffset,
    /// Signature blob layout is malformed.
    SignatureLayout,
    /// A recomputed page hash does not match the `CodeDirectory`.
    SignatureHashMismatch,
    /// Entry point, build version or function-start payload invalid.
    LinkeditPayload,
    /// The export trie is malformed, unsorted or unreadable by dyld.
    ExportTrie,
    /// A `B`/`BL` target leaves the executable span or is mis-aligned
    /// (M6 veneer-placement gate).
    BranchRange,
    /// The classic `LC_DYLD_INFO` opcode streams are malformed or name an
    /// import outside the load-dylib list (M6 legacy fallback).
    DyldInfoStreams,
    /// `LC_DYLD_CHAINED_FIXUPS` rides in an image whose declared
    /// deployment target sits below the platform's chained-fixups floor
    /// (M10 rung 3) — the target's dyld cannot walk the chains.
    FixupsFloor,
    /// Suspicious but non-fatal condition.
    Suspicious,
}

impl Code {
    /// Stable string identifier (also used by the JSON report).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Code::HeaderInvalid => "header_invalid",
            Code::LoadCommandMalformed => "load_command_malformed",
            Code::SegmentContract => "segment_contract",
            Code::SegmentLayout => "segment_layout",
            Code::ImageBase => "image_base",
            Code::SectionBounds => "section_bounds",
            Code::SymbolTable => "symbol_table",
            Code::FixupsPayload => "fixups_payload",
            Code::FixupsChain => "fixups_chain",
            Code::FixupsImport => "fixups_import",
            Code::FixupsSegmentOffset => "fixups_segment_offset",
            Code::SignatureLayout => "signature_layout",
            Code::SignatureHashMismatch => "signature_hash_mismatch",
            Code::LinkeditPayload => "linkedit_payload",
            Code::ExportTrie => "export_trie",
            Code::BranchRange => "branch_range",
            Code::DyldInfoStreams => "dyld_info_streams",
            Code::FixupsFloor => "fixups_floor",
            Code::Suspicious => "suspicious",
        }
    }
}

/// One verification finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// Severity.
    pub severity: Severity,
    /// Machine-checkable code.
    pub code: Code,
    /// Human explanation.
    pub message: String,
    /// File offset the issue is anchored at, when meaningful.
    pub offset: Option<u64>,
}

impl Issue {
    /// Builds an error issue.
    pub fn error(code: Code, message: impl Into<String>, offset: Option<u64>) -> Self {
        Self {
            severity: Severity::Error,
            code,
            message: message.into(),
            offset,
        }
    }

    /// Builds a warning issue.
    pub fn warning(code: Code, message: impl Into<String>, offset: Option<u64>) -> Self {
        Self {
            severity: Severity::Warning,
            code,
            message: message.into(),
            offset,
        }
    }
}

/// Aggregate counts kept while checking.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Segments seen.
    pub segments: u32,
    /// Sections seen.
    pub sections: u32,
    /// Symbol-table entries seen.
    pub symbols: u32,
    /// Fixup slots visited by the chain-walk simulation.
    pub fixup_slots: u64,
    /// Code-signature page hashes recomputed.
    pub hash_pages: u64,
}

/// Result of verifying one image.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// All findings, sorted by anchor offset.
    pub issues: Vec<Issue>,
    /// Aggregate counters.
    pub stats: Stats,
}

impl Report {
    /// True when no error-severity issues were found (and, under
    /// `Options::strict_warnings`, no warnings either).
    #[must_use]
    pub fn is_ok(&self, opts: &Options) -> bool {
        !self.issues.iter().any(|i| match i.severity {
            Severity::Error => true,
            Severity::Warning => opts.strict_warnings,
        })
    }

    /// Pushes an issue, keeping the report sorted on access.
    fn push(&mut self, issue: Issue) {
        self.issues.push(issue);
    }

    fn sort(&mut self) {
        self.issues
            .sort_by_key(|i| (i.offset.unwrap_or(u64::MAX), i.severity as u8, i.code as u8));
    }
}

/// Verifies a complete Mach-O image against the Peregrine arm64 contract.
///
/// The image type shapes the checks: executables and dylibs get the full
/// segment/base/signature contract; bundles and other types get structural
/// checks only.
#[must_use]
pub fn verify(bytes: &[u8], opts: &Options) -> Report {
    let mut report = Report::default();
    let parsed = match structural::parse_image(bytes) {
        Ok(p) => p,
        Err(issue) => {
            report.push(issue);
            report.sort();
            return report;
        }
    };
    report.stats.segments = parsed.segments.len() as u32;
    report.stats.sections = parsed.nsections;
    report.stats.symbols = img_nsyms(&parsed);

    structural::check_header(&parsed, &mut report);
    structural::check_load_commands(&parsed, &mut report);
    structural::check_dylib_contract(&parsed, &mut report);
    structural::check_segments(bytes, &parsed, &mut report);
    structural::check_symbol_table(bytes, &parsed, &mut report);
    if parsed.header.filetype == MH_OBJECT {
        structural::check_object_contract(bytes, &parsed, &mut report);
    }
    misc::check_entry_and_version(bytes, &parsed, &mut report);
    misc::check_linkedit_payloads(bytes, &parsed, &mut report);
    if matches!(parsed.header.filetype, MH_EXECUTE | MH_DYLIB | MH_BUNDLE) {
        if let Some(payload) = &parsed.fixups {
            dynamic::check_fixups(bytes, &parsed, payload, &mut report);
        }
        if parsed.header.filetype == MH_EXECUTE {
            // M1: the static mirror must agree with the payload (TDD §7.5).
            chain_starts::check_chain_starts(bytes, &parsed, &mut report);
        }
        // M6: the branch-range gate (veneers included).
        branch_range::check_branch_range(bytes, &parsed, &mut report);
        // M6: the classic `LC_DYLD_INFO(_ONLY)` opcode-stream walk.
        dyld_info::check_dyld_info(bytes, &parsed, &mut report);
        signature::check_signature(bytes, &parsed, !opts.skip_hash_recompute, &mut report);
    }
    if report.issues.iter().any(|i| i.severity == Severity::Error) {
        report.stats.fixup_slots = 0;
    } else {
        report.stats.fixup_slots = parsed.fixup_slot_count;
    }
    report.sort();
    report
}

/// Convenience: verifies and returns only whether the image is acceptable.
#[must_use]
pub fn verify_ok(bytes: &[u8], opts: &Options) -> bool {
    verify(bytes, opts).is_ok(opts)
}

/// Symbol count from the parsed symtab (0 when stripped).
fn img_nsyms(img: &structural::ParsedImage<'_>) -> u32 {
    img.symtab.map_or(0, |st| st.nsyms)
}

/// Converts a parse error into an issue (used at every call boundary).
pub(crate) fn issue_from(err: &FormatError, code: Code) -> Issue {
    Issue::error(code, err.to_string(), Some(err.offset() as u64))
}

#[cfg(test)]
mod tests {
    use super::{Code, Issue, Options, Severity};
    use crate::Report;

    #[test]
    fn report_ok_respects_strict() {
        let mut r = Report::default();
        r.issues
            .push(Issue::warning(Code::Suspicious, "test warning", Some(0)));
        assert!(r.is_ok(&Options::default()));
        assert!(!r.is_ok(&Options {
            strict_warnings: true,
            skip_hash_recompute: false,
        }));
        r.issues
            .push(Issue::error(Code::HeaderInvalid, "bad", None));
        assert!(!r.is_ok(&Options::default()));
    }

    #[test]
    fn severity_ordering_is_defined() {
        assert_ne!(Severity::Error as u8, Severity::Warning as u8);
    }
}

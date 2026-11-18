//! M71 — the verifier's universal-container face: the driver links a
//! universal ("fat") container through its arm64 slice (M70), so the
//! verifier owes the same container a *read-side* story. Every slice
//! the table declares gets the strict pass over its own window
//! ([`crate::verify`] on the subslice — the container adds no contract the
//! image does not already carry), and the table's row must agree with
//! the slice's own header about the arch it names: the driver links by
//! the table's row, so a row that lies (naming `x86_64` for an `arm64`
//! window) is the shape the seam can break — it rides
//! [`Code::HeaderInvalid`] on that slice's verdict, anchored at the
//! slice's offset.
//!
//! The container's decode is the format reader's gate (the
//! offset-tagged [`pgr_format::FormatError`] verbatim to the caller — a malformed
//! table is a refusal, not a report), and the face rides the tracing
//! seam inert-until-subscriber like every check family: one `debug`
//! event names the slices it walked.

use pgr_format::MachHeader64;
use pgr_format::universal::parse_universal;

use crate::{CheckSet, Code, Options, Report, verify_with_checks};

/// One slice's verdict: the table row it rode and the strict pass's
/// report over its window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceVerdict {
    /// The table row (the `cputype` the driver linked by, the slice's
    /// own `offset` — the anchor the mismatch issue rides).
    pub arch: pgr_format::universal::FatArch,
    /// The strict pass over the slice's window (the container adds no
    /// contract the image does not already carry).
    pub report: Report,
}

/// The container's verdict: one [`SliceVerdict`] per table row, in
/// table order. `is_ok` is every slice's — the container ships only
/// when all of it does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UniversalReport {
    /// The per-slice verdicts, in table order.
    pub slices: Vec<SliceVerdict>,
}

impl UniversalReport {
    /// True when every slice's report is ok under `opts` (the
    /// container's own gate — the same rule [`Report::is_ok`] applies,
    /// one slice at a time).
    #[must_use]
    pub fn is_ok(&self, opts: &Options) -> bool {
        self.slices.iter().all(|s| s.report.is_ok(opts))
    }
}

/// Verifies every slice of a universal ("fat") container (M71): the
/// strict pass runs per declared slice, the table's rows are checked
/// against the slices' own headers, and the verdicts ride in table
/// order. The whole check surface runs — the M12 selector surface
/// ([`verify_universal_with_checks`]) narrows it.
///
/// # Errors
/// The format reader's offset-tagged [`pgr_format::FormatError`] when the
/// container is malformed (a truncated header, a lying count, an
/// out-of-bounds or overlapping window) — a malformed table is a
/// refusal, not a report: there is nothing to slice.
pub fn verify_universal(
    bytes: &[u8],
    opts: &Options,
) -> Result<UniversalReport, pgr_format::FormatError> {
    verify_universal_with_checks(bytes, opts, &CheckSet::all())
}

/// Verifies every slice of a universal ("fat") container over the named
/// check families only (M74): the M71 container face composed with the
/// M12 selector surface — one pass per declared slice over the selected
/// families, the table-row/header agreement riding as the container's
/// own contract (it is not one of the families, so a lying row refuses
/// under any selection), and the verdicts in table order. A build gate
/// auditing an SDK's fat dylibs prices a narrowed lane (`signature`
/// only) without re-running the whole pass; the full set is
/// [`verify_universal`].
///
/// # Errors
/// The format reader's offset-tagged [`pgr_format::FormatError`] when the
/// container is malformed — a malformed table is a refusal, not a
/// report: the selection never excuses the decode.
pub fn verify_universal_with_checks(
    bytes: &[u8],
    opts: &Options,
    checks: &CheckSet,
) -> Result<UniversalReport, pgr_format::FormatError> {
    let container = parse_universal(bytes)?;
    tracing::debug!(
        slices = container.arches.len(),
        magic = format!("{:#x}", container.magic),
        "universal container: verifying every declared slice"
    );
    let mut slices = Vec::with_capacity(container.arches.len());
    for arch in &container.arches {
        let window = container.slice(bytes, arch)?;
        let mut report = verify_with_checks(window, opts, checks);
        // The table's row and the window's own header must agree on the
        // arch they name — the driver links by the row, so a lie here
        // is the wrong slice's bytes linked under the right name.
        if let Ok(header) = MachHeader64::parse(window)
            && header.cputype != arch.cputype
        {
            report.issues.push(crate::Issue::error(
                Code::HeaderInvalid,
                format!(
                    "the slice table names cputype {:#x} but the slice's own header \
                     carries {:#x} — the table and the image disagree; link the arch \
                     the slice actually is",
                    arch.cputype, header.cputype
                ),
                Some(arch.offset),
            ));
        }
        slices.push(SliceVerdict {
            arch: *arch,
            report,
        });
    }
    Ok(UniversalReport { slices })
}

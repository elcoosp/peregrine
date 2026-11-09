//! The §7.3 audit twin (M9 GA rung 2): the bytes-level gate that proves a
//! patch before anything ships.
//!
//! `-incremental-verify` has always audited the relink on the driver's
//! file path: byte-identity against the full fused emit of the same plan
//! (the engine contract [`crate::incremental`] documents), then a strict
//! `pgr-verify` pass on the final bytes. This module extracts that audit
//! into the engine as pure bytes-level functions so **both** paths share
//! one implementation — the driver's in-process audit and the daemon's
//! wire-served audit (protocol v4: the session audits its in-memory patch
//! and hands the verdict across; the client still writes the file, so a
//! failing verdict ships nothing).
//!
//! The carve-out is deliberate and recorded: a `-no_adhoc` link has no
//! signature to verify — the verifier's "arm64 images require an ad-hoc
//! code signature" shape is the config's own choice, never a patch
//! defect. Everything else (fixups, chains, segments, symtab, the page
//! hashes of a signed image) gates at full strictness.
//!
//! Refusals render with miette help-text (the fix, not just the verdict)
//! and every step carries a `tracing` span — inert until a subscriber is
//! installed (the `pgr`/`pgrd` binaries install one under their debug
//! environment variables).

use pgr_verify::{Code, Options, Severity, verify};

/// The wire-facing audit verdict (protocol v4, daemon → client): the
/// identity check, whether the daemon healed the patched bytes from its
/// reference emit, and every blocking strict-verifier issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditOutcome {
    /// The patched bytes equaled the reference emit.
    pub identity_ok: bool,
    /// The daemon served its reference emit instead of the patched bytes
    /// (a divergence never ships — the heal is the §7.3 gate's bite).
    pub healed: bool,
    /// Blocking strict-verifier issues (empty = the strict pass is clean;
    /// the deliberate-unsigned carve-out already applied).
    pub verify_blocking: Vec<String>,
}

impl AuditOutcome {
    /// The small copyable summary the driver's `LinkOutcome` carries
    /// (what a build system sees).
    #[must_use]
    pub fn summary(&self) -> AuditSummary {
        AuditSummary {
            identity_ok: self.identity_ok,
            healed: self.healed,
            verify_ok: self.verify_blocking.is_empty(),
        }
    }
}

/// The small summary of a served audit (the driver's outcome surface).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditSummary {
    /// The patched bytes equaled the reference emit.
    pub identity_ok: bool,
    /// The producer healed the output from the reference emit.
    pub healed: bool,
    /// The strict verifier pass found nothing blocking.
    pub verify_ok: bool,
}

/// A refused-to-ship patch: the strict verifier named blocking issues on
/// the final bytes. The driver renders this (miette help-text) and exits;
/// the resident client refuses to write the file at all.
#[derive(Debug, Clone, thiserror::Error, miette::Diagnostic)]
#[error(
    "the patched image failed the strict verifier ({} blocking issue(s)):\n{}",
    .issues.len(),
    .issues.join("\n")
)]
#[diagnostic(help(
    "a divergence never ships: the next link re-runs the full emit and \
     re-records; re-run with PGR_INCREMENTAL_DEBUG=1 to log the ladder's \
     rungs, or drop -resident for the file-path audit"
))]
pub struct AuditRefusal {
    /// The blocking issues, in the verifier's own words.
    pub issues: Vec<String>,
}

impl AuditRefusal {
    /// Renders the refusal with its help text (multi-line, no backtrace
    /// noise) — the string the driver prints and the audit logs carry.
    #[must_use]
    pub fn render(&self) -> String {
        let report = miette::Report::new(self.clone());
        format!("{report:?}")
    }
}

/// The byte-identity audit: compares the patched bytes against the
/// reference — the full fused emit of the same plan (the engine
/// contract). Pure bytes in, verdict out; the caller owns the heal.
#[must_use]
pub fn audit_patch(reference: &[u8], patched: &[u8]) -> bool {
    let span = tracing::info_span!(
        "incremental_audit",
        reference_len = reference.len(),
        patched_len = patched.len()
    );
    let _entered = span.enter();
    let identity_ok = reference == patched;
    tracing::debug!(identity_ok, "the patch audit compared the bytes");
    identity_ok
}

/// The strict-verifier audit on the final bytes: every issue that blocks
/// shipping, in the verifier's own words. `signature_expected` applies
/// the deliberate-unsigned carve-out (`-no_adhoc`): the missing-signature
/// shape is the config's own choice, not a patch defect.
#[must_use]
pub fn audit_image(final_bytes: &[u8], signature_expected: bool) -> Vec<String> {
    let span = tracing::info_span!(
        "incremental_audit_verify",
        len = final_bytes.len(),
        signature_expected
    );
    let _entered = span.enter();
    let opts = Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(final_bytes, &opts);
    let blocking: Vec<String> = report
        .issues
        .iter()
        .filter(|i| match i.severity {
            Severity::Error => !(signature_expected && i.code == Code::SignatureLayout),
            Severity::Warning => opts.strict_warnings,
        })
        .map(|i| format!("{:?} [{}] {}", i.severity, i.code.as_str(), i.message))
        .collect();
    tracing::debug!(blocking = blocking.len(), "the strict audit finished");
    blocking
}

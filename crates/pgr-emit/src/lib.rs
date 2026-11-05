//! Peregrine emit pipeline: output buffer, relocation application, `pwrite`
//! writer pool, ad-hoc code signature.
//!
//! Deliberately empty at **M0 ("verifier first")**. The read-side verifier
//! (`pgr-verify`) is the executable specification this crate must satisfy when
//! the emit path lands: every emitted image has to pass chain-walk simulation
//! and signature recompute before anything else is trusted.
//!
//! Contract reminders carried forward from the TDD (do not lose them):
//!
//! * output is written through an anonymous in-memory buffer flushed by a
//!   4-writer `pwrite` pool — never a writable mapping of the output vnode
//!   (TDD §2.1.3, the macOS signature-taint trap);
//! * signature blobs are big-endian; everything else little-endian (TDD §9);
//! * when this crate introduces audited `unsafe` (perf doc §5 rule 9), it must
//!   opt in per crate with a design note — the workspace default stays
//!   `unsafe_code = "forbid"`.

/// Crate version, re-exported for tooling smoke tests.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_populated() {
        assert!(!super::VERSION.is_empty());
    }
}

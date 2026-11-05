//! Peregrine core pipeline: interner, SoA symbol table, resolution, layout.
//!
//! Deliberately empty at **M0 ("verifier first")**: the M0 gate ships
//! `pgr-format` (raw structs + cursor) and `pgr-verify` v1, and records the
//! parser-throughput baseline that Pass 1 will be measured against.
//! Implementation starts at M1 with the design fixed in TDD §6:
//!
//! * hash-binned thread-local interning (TDD §6.1),
//! * CAS-owner SoA symbol table (TDD §6.2),
//! * symbol-delimited atomization (perf doc D1),
//! * zero-copy relocation slices (perf doc D5).

/// Crate version, re-exported for tooling smoke tests.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_populated() {
        assert!(!super::VERSION.is_empty());
    }
}

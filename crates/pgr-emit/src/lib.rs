//! Peregrine emit pipeline (M1): output buffer, relocation application,
//! chained-fixup words, `__LINKEDIT` assembly, ad-hoc code signature and the
//! Pass 5 flush — TDD §5 Passes 4–5, §7, §9.
//!
//! Contract reminders carried from the TDD (unchanged since M0):
//!
//! * the output file is written through chunked writes into a fresh vnode —
//!   never a writable mapping of the output (TDD §2.1.3 risk R1);
//! * signature blobs are big-endian; everything else little-endian (§9);
//! * the 4-writer `pwrite` pool and `fallocate` preallocation join at M4;
//!   M1 keeps the write-only contract with one writer;
//! * when this crate introduces audited `unsafe` (perf doc §5 rule 9), it
//!   must opt in per crate with a design note — the workspace default stays
//!   `unsafe_code = "forbid"`.

pub mod emit;
pub mod reloc;
pub mod signature;
pub mod writer;

pub use emit::build_image;
pub use reloc::apply as apply_patch;
pub use signature::{blob_size, build_superblob, derive_uuid, page_hashes};
pub use writer::write_image;

/// Crate version, re-exported for tooling smoke tests.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A Pass 4/5 failure.
#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    /// A plan/operand inconsistency the layout pass should have caught.
    #[error("emit contract violated: {message}")]
    Contract {
        /// What failed.
        message: String,
    },
    /// An internal invariant failed (a bug, not user input).
    #[error("internal: {message}")]
    Internal {
        /// What invariant failed.
        message: String,
    },
    /// The output path could not be written.
    #[error("writing {path}: {source}")]
    Io {
        /// The failing path.
        path: String,
        /// The OS error.
        source: std::io::Error,
    },
}

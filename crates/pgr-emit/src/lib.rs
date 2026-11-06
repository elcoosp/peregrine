//! Peregrine emit pipeline (M1–M4): output buffer, relocation application,
//! chained-fixup words, `__LINKEDIT` assembly, ad-hoc code signature and the
//! Pass 5 flush — TDD §5 Passes 4–5, §7, §9; perf doc §4.4/§4.5.
//!
//! Contract reminders carried from the TDD (unchanged since M0):
//!
//! * the output file is written through chunked writes into a fresh vnode —
//!   never a writable mapping of the output (TDD §2.1.3 risk R1);
//! * signature blobs are big-endian; everything else little-endian (§9);
//! * the M4 speed pass activates the audited parallel paths *without*
//!   `unsafe`: the fused tile emit ([`tile`]) partitions the buffer into
//!   disjoint `par_chunks_mut` slices, and the M4 writer pool uses
//!   position-independent `pwrite` (`FileExt::write_at`) — the workspace
//!   `unsafe_code = "forbid"` gate stays intact.

pub mod emit;
pub mod reloc;
pub mod signature;
pub mod tile;
pub mod writer;

pub use emit::build_image;
pub use reloc::apply as apply_patch;
pub use signature::{blob_size, build_superblob, derive_uuid, page_hashes};
pub use tile::build_image_fused;
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

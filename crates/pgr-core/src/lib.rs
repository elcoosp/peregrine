//! Peregrine core pipeline (M1): input parsing, interning, resolution,
//! layout and fixup planning — TDD §5 Passes 1–3 and §6/§7 data structures.
//!
//! M1 scope ("static hello-world"): direct `.o` inputs only, single-threaded
//! pass bodies with the *API shape* the M4 parallel machinery will drive —
//! the per-pass arenas and total-ordered sorts are already in place, so the
//! hash-bin interner (§6.1), CAS symbol table (§6.2) and two-level prefix
//! scan (§6.4) swap in without touching callers.
//!
//! Determinism policy (§4.3): every ordering input is total-ordered
//! (command-line file order, symbol order within a file, canonical output
//! section order); nothing reads hash iteration order.

pub mod fixups;
pub mod ids;
pub mod interner;
pub mod layout;
pub mod link;
pub mod object;
pub mod resolve;

pub use fixups::{FixupPlan, MAX_CHAIN_STRIDE_BYTES, pack_page};
pub use ids::{FileId, StringId};
pub use interner::Interner;
pub use layout::{Layout, LinkConfig, OutputSymbol, PatchOp, Piece, PlacedSection, SegmentPlan};
pub use link::{LinkInput, LinkResult, link};
pub use object::{DecodedReloc, InputObject, RelocKind, RelocTarget};
pub use resolve::{Def, Rank, Resolution};

/// A fatal link error (M1 surface: inputs, symbols, layout, encoding).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    /// An input file could not be parsed.
    #[error("{file}: {message}")]
    Parse {
        /// Input file name.
        file: String,
        /// What failed.
        message: String,
    },
    /// A symbol problem: undefined reference or duplicate strong definition.
    #[error("{message}")]
    Symbol {
        /// The offending symbol name.
        name: String,
        /// What failed and where.
        message: String,
    },
    /// An input construct the M1 pipeline does not support.
    #[error("{file}: {message}")]
    Unsupported {
        /// Input file name.
        file: String,
        /// What and why.
        message: String,
    },
    /// The requested layout violates a Mach-O contract (header page, range).
    #[error("{message}")]
    Layout {
        /// What failed.
        message: String,
    },
    /// An internal invariant failed (a bug, not user input).
    #[error("internal: {message}")]
    Internal {
        /// What invariant failed.
        message: String,
    },
}

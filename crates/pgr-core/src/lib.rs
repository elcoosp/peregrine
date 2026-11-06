//! Peregrine core pipeline: input parsing, interning, resolution,
//! layout and fixup planning — TDD §5 Passes 1–3 and §6/§7 data structures.
//!
//! M1 scope ("static hello-world") grew through M3 (dynamic executables,
//! dylibs, bundles). M4 (architecture doc §10.3 row M4) makes the pipeline
//! **performance-shaped end to end**: Pass 1 parses LPT-scheduled in
//! parallel with giant-object splitting, the interner sorts on the pool,
//! Pass 3 materializes the D8 `resolved[]` de-indirection tables and the
//! copy-run coalescing the fused tile emit (pgr-emit, Pass 4 v2) consumes.
//!
//! Determinism policy (§4.3): every ordering input is total-ordered
//! (command-line file order, symbol order within a file, canonical output
//! section order); nothing reads hash iteration order. Parallel schedules
//! change who computes a result, never the result — gated in tests.

pub mod fixups;
pub mod ids;
pub mod interner;
pub mod layout;
pub mod link;
pub mod object;
pub mod pool;
pub mod resolve;
pub mod trie;

pub use fixups::{FixupKind, FixupPlan, MAX_CHAIN_STRIDE_BYTES, pack_page};
pub use ids::{FileId, StringId};
pub use interner::Interner;
pub use layout::{
    CopyRun, Layout, LinkConfig, OutputSymbol, PatchOp, Piece, PlacedSection, ResolvedFile,
    SegmentPlan,
};
pub use link::{LinkInput, LinkResult, Parallelism, link, link_with};
pub use object::{DecodedReloc, InputObject, RelocKind, RelocTarget};
pub use resolve::{Def, Rank, Resolution};
pub use trie::{Export, ExportInfo};

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

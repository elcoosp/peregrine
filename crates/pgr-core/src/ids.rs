//! Identity types (TDD §6.1): all cross-references are `u32` indices so the
//! metadata that fits in cache doubles; no realistic link exceeds 2³²
//! symbols/atoms/files. Newtypes keep the spaces distinct at compile time.

/// Input-file identity; command-line order == deterministic tie-break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileId(pub u32);

/// Interned symbol name; the interner's canonical byte slice is reachable
/// through it (TDD §6.1 — O(1) dereference, no hash lookup on the hot path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StringId(pub u32);

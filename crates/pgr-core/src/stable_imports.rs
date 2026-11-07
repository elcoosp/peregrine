//! M8-b — the insertion-stable import table (architecture doc §10.4 row
//! M8; §7.3 step 5: "stable ordinals assigned by canonical order with room
//! for appended entries").
//!
//! A chained-fixups bind word carries its import's *index* in the import
//! table (`DYLD_CHAINED_IMPORT_ADDEND`). The clean-link builder
//! ([`crate::fixups`]) assigns indices in first-use order over
//! address-sorted slots — minimal and deterministic, but *not* reusable
//! across links: one new bind in the middle of the image renumbers every
//! later import, which is why it is an M9 blocker.
//!
//! This table is the foundation the incremental path uses instead:
//!
//! * **clean build** — ordinals follow the canonical order
//!   `(name, lib_ordinal, outlined addend, weak)`, a total order that never
//!   depends on addresses (the D7 property, now load-bearing);
//! * **growth** — [`StableImports::insert`] keeps every existing entry's
//!   ordinal untouched and appends genuinely new entries in canonical
//!   order. A relink that adds imports extends the table; it never
//!   renumbers it.
//!
//! Ordinals are the vector index, so the on-disk table shape (and the name
//! pool layout) is exactly what [`pgr_format::fixups::Import`] encodes —
//! the M9 path can drop the assignment straight into a `FixupPlan`.

use pgr_format::fixups::Import;
use std::collections::BTreeSet;

/// One import identity: the chained import dedup key (not just the symbol
/// name — the same name can bind through two libraries, addends or weak
/// markers, and dyld treats each combination as its own import).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StableImport {
    /// 1-based `LC_LOAD_DYLIB` ordinal (or a `BIND_SPECIAL_DYLIB_*`).
    pub lib_ordinal: u8,
    /// Bind symbol name (raw bytes).
    pub name: Vec<u8>,
    /// Outlined addend half (the word's inline 0..=255 half dedups to 0).
    pub outlined_addend: i64,
    /// Weak import marker.
    pub weak: bool,
}

/// One [`StableImports::insert`] result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// The import's ordinal (its index in the table, = the bind-word field).
    pub ordinal: usize,
    /// The import itself.
    pub key: StableImport,
    /// True when this insert added the entry; false when it reused an
    /// existing ordinal.
    pub is_new: bool,
}

/// The insertion-stable import table: ordinal = vector index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StableImports {
    entries: Vec<StableImport>,
}

impl StableImports {
    /// Builds a table from a clean link's imports: canonical order
    /// (`(name, lib_ordinal, addend, weak)` ascending), duplicates removed.
    #[must_use]
    pub fn clean(keys: Vec<StableImport>) -> Self {
        let set: BTreeSet<StableImport> = keys.into_iter().collect();
        Self {
            entries: set.into_iter().collect(),
        }
    }

    /// Grows the table: every key already present keeps its ordinal
    /// (reported with `is_new == false`); new keys are appended in canonical
    /// order (reported with `is_new == true`). Repeatable — the table only
    /// ever grows.
    pub fn insert(&mut self, incoming: Vec<StableImport>) -> Vec<Assignment> {
        let mut out = Vec::with_capacity(incoming.len());
        let mut fresh: BTreeSet<StableImport> = BTreeSet::new();
        for key in incoming {
            if let Some(ordinal) = self.entries.iter().position(|k| *k == key) {
                out.push(Assignment {
                    ordinal,
                    key,
                    is_new: false,
                });
            } else {
                fresh.insert(key);
            }
        }
        for key in fresh {
            let ordinal = self.entries.len();
            self.entries.push(key.clone());
            out.push(Assignment {
                ordinal,
                key,
                is_new: true,
            });
        }
        out
    }

    /// The table entries in ordinal order.
    #[must_use]
    pub fn keys(&self) -> &[StableImport] {
        &self.entries
    }

    /// Number of imports.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The on-disk import table: `Import` entries plus the NUL-terminated
    /// name pool in ordinal order (`name_offset` patched) — the same shape
    /// the clean-path fixups builder produces.
    #[must_use]
    pub fn import_table(&self) -> (Vec<Import>, Vec<u8>) {
        let mut imports = Vec::with_capacity(self.entries.len());
        let mut pool = Vec::new();
        for k in &self.entries {
            let offset = pool.len() as u32;
            pool.extend_from_slice(&k.name);
            pool.push(0);
            imports.push(Import {
                lib_ordinal: u16::from(k.lib_ordinal),
                weak_import: k.weak,
                name_offset: offset,
                addend: k.outlined_addend,
            });
        }
        (imports, pool)
    }
}

#[cfg(test)]
mod tests {
    use super::{StableImport, StableImports};

    fn key(name: &str) -> StableImport {
        StableImport {
            lib_ordinal: 1,
            name: name.as_bytes().to_vec(),
            outlined_addend: 0,
            weak: false,
        }
    }

    #[test]
    fn empty_and_single() {
        let empty = StableImports::default();
        assert!(empty.is_empty());
        let one = StableImports::clean(vec![key("_a")]);
        assert_eq!(one.len(), 1);
        let (imports, pool) = one.import_table();
        assert_eq!(pool, b"_a\0");
        assert_eq!(imports[0].name_offset, 0);
    }

    #[test]
    fn duplicates_in_a_clean_build_collapse() {
        let table = StableImports::clean(vec![key("_a"), key("_a"), key("_b")]);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn insert_of_only_known_keys_adds_nothing() {
        let mut table = StableImports::clean(vec![key("_a"), key("_b")]);
        let assignments = table.insert(vec![key("_b"), key("_a")]);
        assert!(assignments.iter().all(|a| !a.is_new));
        assert_eq!(table.len(), 2);
        assert_eq!(assignments[0].ordinal, 1);
        assert_eq!(assignments[1].ordinal, 0);
    }
}

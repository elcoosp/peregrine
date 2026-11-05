//! Symbol-name interning (TDD §6.1).
//!
//! M1 keeps the *semantics* of the hash-bin interner — names dedup through a
//! canonicalizing total sort, never through hash-map iteration — in a
//! single-threaded body. M4 swaps the sort for per-bin dedup threads; the
//! lookup shape (`bytes()` dereference, no hashing) and determinism
//! guarantees are identical.

use crate::ids::StringId;

/// Interned symbol-name space.
///
/// `canon[i]` holds the canonical bytes of `StringId(i)`: the first
/// occurrence in (bytes, file, symbol) order. Dedup happened at build time;
/// every later lookup is a slice dereference.
#[derive(Debug, Clone, Default)]
pub struct Interner {
    canon: Vec<Vec<u8>>,
}

impl Interner {
    /// Builds the interner from every symbol name in command-line order.
    ///
    /// The canonicalizing sort deduplicates equal byte strings and assigns
    /// contiguous [`StringId`]s; the returned table maps each input position
    /// to its id.
    ///
    /// `names` are (position, bytes) pairs in any order — the sort fixes the
    /// numbering, so callers stay schedule-independent by construction.
    #[must_use]
    pub fn build(names: &[Vec<u8>]) -> (Self, Vec<StringId>) {
        let mut indexed: Vec<(usize, &[u8])> = names
            .iter()
            .enumerate()
            .map(|(i, n)| (i, n.as_slice()))
            .collect();
        // Total order on bytes; ties broken by position (unique), so the
        // numbering is a pure function of the input set.
        indexed.sort_by(|a, b| a.1.cmp(b.1).then(a.0.cmp(&b.0)));
        let mut canon: Vec<Vec<u8>> = Vec::new();
        let mut out = vec![StringId(0); names.len()];
        let mut last: Option<&[u8]> = None;
        for (pos, bytes) in indexed {
            if last != Some(bytes) {
                canon.push(bytes.to_vec());
                last = Some(bytes);
            }
            out[pos] = StringId((canon.len() - 1) as u32);
        }
        (Self { canon }, out)
    }

    /// The canonical bytes of an interned name (hot path: one index load).
    #[must_use]
    pub fn bytes(&self, id: StringId) -> &[u8] {
        &self.canon[id.0 as usize]
    }

    /// The name of an interned symbol as UTF-8 (lossy; Mach-O names are
    /// ASCII in practice).
    #[must_use]
    pub fn name(&self, id: StringId) -> String {
        String::from_utf8_lossy(&self.canon[id.0 as usize]).into_owned()
    }

    /// Number of unique names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.canon.len()
    }

    /// True when no names were interned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.canon.is_empty()
    }

    /// Finds the id of `name` if it was interned.
    #[must_use]
    pub fn lookup(&self, name: &[u8]) -> Option<StringId> {
        // canon is sorted by (bytes, position) with unique bytes ascending.
        self.canon
            .binary_search_by(|probe| probe.as_slice().cmp(name))
            .ok()
            .map(|i| StringId(i as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::Interner;

    #[test]
    fn equal_names_share_one_id() {
        let names = vec![
            b"_main".to_vec(),
            b"_greet".to_vec(),
            b"_main".to_vec(),
            b"_l_str".to_vec(),
            b"_greet".to_vec(),
        ];
        let (interner, ids) = Interner::build(&names);
        assert_eq!(interner.len(), 3);
        assert_eq!(ids[0], ids[2]);
        assert_eq!(ids[1], ids[4]);
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[0], ids[3]);
    }

    #[test]
    fn numbering_is_order_independent() {
        let a: Vec<Vec<u8>> = vec![b"b".to_vec(), b"a".to_vec(), b"c".to_vec()];
        let b: Vec<Vec<u8>> = vec![b"c".to_vec(), b"a".to_vec(), b"b".to_vec()];
        let (ia, ida) = Interner::build(&a);
        let (ib, idb) = Interner::build(&b);
        // Same *set* => same canonical space; per-position ids differ, but
        // the bytes behind them are identical.
        assert_eq!(ia.bytes(ida[0]), ib.bytes(idb[2]));
        assert_eq!(ia.bytes(ida[1]), ib.bytes(idb[1]));
        assert_eq!(ia.len(), ib.len());
    }

    #[test]
    fn lookup_roundtrips() {
        let names = vec![b"_main".to_vec(), b"_x".to_vec()];
        let (interner, ids) = Interner::build(&names);
        assert_eq!(interner.lookup(b"_main"), Some(ids[0]));
        assert_eq!(interner.lookup(b"_missing"), None);
        assert_eq!(interner.name(ids[0]), "_main");
    }

    #[test]
    fn empty_and_singleton() {
        let (interner, ids) = Interner::build(&[]);
        assert!(interner.is_empty());
        assert!(ids.is_empty());
        let (i2, ids2) = Interner::build(&[b"only".to_vec()]);
        assert_eq!(i2.len(), 1);
        assert_eq!(ids2.len(), 1);
    }
}

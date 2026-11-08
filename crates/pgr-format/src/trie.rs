//! Export-trie reading (`LC_DYLD_EXPORTS_TRIE` payload) — the M3 read side.
//!
//! dyld resolves two-level namespace and flat lookups by walking this trie:
//! each node is `ULEB terminal_size` (0 = pure prefix), optional terminal
//! info, then `u8 child_count` and per child `substring, 0x00, ULEB offset`.
//! Terminal info is `ULEB flags` followed by `ULEB address` — or, for
//! re-export nodes (`flags & 0x08`, M3), `ULEB ordinal` plus an optional
//! NUL-terminated imported name (absent means "same name").
//!
//! The walker is total like every parser in this crate: malformed payloads
//! yield typed [`FormatError`]s anchored at the offending byte, cycles and
//! out-of-range offsets are rejected, and no input shape can panic it. It
//! feeds the driver's Mach-O dylib scan (M3) and the fuzz corpus.

use crate::error::FormatError;

/// One exported symbol described by the trie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieExport {
    /// Full symbol name (all edge substrings concatenated).
    pub name: Vec<u8>,
    /// Raw `flags` ULEB (`0x01` weak definition, `0x08` re-export, ...).
    pub flags: u64,
    /// Export address (image-base-relative); `None` for re-exports.
    pub address: Option<u64>,
    /// Re-export ordinal (`flags & 0x08` nodes).
    pub reexport_ordinal: Option<u64>,
    /// The original name in the re-exported dylib (defaults to [`Self::name`]).
    pub imported_name: Vec<u8>,
}

/// Export flag: the node re-exports a symbol from another dylib (M3).
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;

/// ULEB128 decode at `at`; `(value, next)` or `None` on overflow/end.
fn uleb_at(data: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut i = at;
    loop {
        let byte = *data.get(i)?;
        i += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

/// Reads the NUL-terminated string starting at `at`; the NUL must exist
/// within `end`. Returns `(bytes-without-nul, next)`.
fn string_until(data: &[u8], at: usize, end: usize) -> Option<(&[u8], usize)> {
    let tail = data.get(at..end)?;
    let nul = tail.iter().position(|&b| b == 0)?;
    Some((&tail[..nul], at + nul + 1))
}

/// Walks the trie and collects every terminal node's export.
/// offsets, cycles, unterminated strings). Never panics.
///
/// # Errors
/// [`FormatError`] on any structural violation (truncation, out-of-range
pub fn exports(payload: &[u8]) -> Result<Vec<TrieExport>, FormatError> {
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut visited = std::collections::BTreeSet::new();
    walk(payload, 0, &mut Vec::new(), &mut visited, &mut out)?;
    Ok(out)
}

/// Typed [`FormatError::Invalid`] shorthand shared by the trie walkers.
fn invalid(offset: usize, what: &'static str, value: u64) -> FormatError {
    FormatError::Invalid {
        offset,
        what,
        value,
    }
}

/// Parses one node's terminal info — `ULEB flags` then a re-export ordinal
/// plus an optional imported name, or a plain export address — bounded by
/// `[terminal_start, info_end)`. Returns the export fields in walk order.
fn parse_terminal(
    data: &[u8],
    prefix: &[u8],
    terminal_start: usize,
    info_end: usize,
) -> Result<(u64, Option<u64>, Option<u64>, Vec<u8>), FormatError> {
    let (flags, after_flags) = uleb_at(data, terminal_start)
        .ok_or_else(|| invalid(terminal_start, "export flags ULEB overruns the terminal", 0))?;
    let mut address = None;
    let mut reexport_ordinal = None;
    let mut imported_name = prefix.to_vec();
    if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
        let (ordinal, after) = uleb_at(data, after_flags).ok_or_else(|| {
            invalid(
                after_flags,
                "re-export ordinal ULEB overruns the terminal",
                0,
            )
        })?;
        if ordinal == 0 {
            return Err(invalid(after_flags, "re-export ordinal is zero", 0));
        }
        reexport_ordinal = Some(ordinal);
        // The imported name is optional; when present it must fill the
        // terminal exactly (NUL included).
        if after < info_end {
            let (name, end) = string_until(data, after, info_end).ok_or_else(|| {
                invalid(after, "re-export imported name is not NUL-terminated", 0)
            })?;
            if end != info_end {
                return Err(invalid(
                    after,
                    "re-export imported name leaves trailing bytes",
                    0,
                ));
            }
            imported_name = name.to_vec();
        }
    } else {
        let (addr, after) = uleb_at(data, after_flags)
            .ok_or_else(|| invalid(after_flags, "export address ULEB overruns the terminal", 0))?;
        if after != info_end {
            return Err(invalid(
                after_flags,
                "export info does not fill the declared terminal size",
                0,
            ));
        }
        address = Some(addr);
    }
    Ok((flags, address, reexport_ordinal, imported_name))
}

/// Recursive dyld-shaped walk with an explicit prefix accumulator.
fn walk(
    data: &[u8],
    at: usize,
    prefix: &mut Vec<u8>,
    visited: &mut std::collections::BTreeSet<usize>,
    out: &mut Vec<TrieExport>,
) -> Result<(), FormatError> {
    if at >= data.len() {
        return Err(invalid(
            at,
            "trie node offset outside the payload",
            at as u64,
        ));
    }
    if !visited.insert(at) {
        return Err(invalid(
            at,
            "trie node offset visited twice (cycle)",
            at as u64,
        ));
    }
    let (terminal_size, mut cur) = uleb_at(data, at)
        .ok_or_else(|| invalid(at, "terminal size ULEB overruns the payload", 0))?;
    let terminal_start = cur;
    let terminal_end = terminal_start
        .checked_add(usize::try_from(terminal_size).unwrap_or(usize::MAX))
        .ok_or_else(|| {
            invalid(
                terminal_start,
                "terminal size overflows the payload",
                terminal_size,
            )
        })?;
    if terminal_end > data.len() {
        return Err(FormatError::Overrun {
            offset: terminal_start,
            overrun: terminal_end - data.len(),
        });
    }
    if terminal_size > 0 {
        let (flags, address, reexport_ordinal, imported_name) =
            parse_terminal(data, prefix, terminal_start, terminal_end)?;
        out.push(TrieExport {
            name: prefix.clone(),
            flags,
            address,
            reexport_ordinal,
            imported_name,
        });
    }
    cur = terminal_end;
    let Some(&child_count) = data.get(cur) else {
        return Err(invalid(cur, "trie payload ends before the child count", 0));
    };
    cur += 1;
    for _ in 0..child_count {
        let substr_start = cur;
        let Some(nul) = data[substr_start..].iter().position(|&b| b == 0) else {
            return Err(invalid(
                substr_start,
                "edge substring is not NUL-terminated",
                0,
            ));
        };
        let sub = &data[substr_start..substr_start + nul];
        cur = substr_start + nul + 1;
        if sub.is_empty() {
            return Err(invalid(substr_start, "edge substring is empty", 0));
        }
        let (child_off, after) = uleb_at(data, cur)
            .ok_or_else(|| invalid(cur, "child offset ULEB overruns the payload", 0))?;
        cur = after;
        let child_at = usize::try_from(child_off).unwrap_or(usize::MAX);
        if child_at >= data.len() {
            return Err(invalid(
                cur - 1,
                "child offset outside the payload",
                child_off,
            ));
        }
        prefix.extend_from_slice(sub);
        walk(data, child_at, prefix, visited, out)?;
        prefix.truncate(prefix.len() - sub.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::exports;

    fn uleb(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if v == 0 {
                break;
            }
        }
        out
    }

    #[test]
    fn empty_payload_walks_to_nothing() {
        assert_eq!(exports(&[]).unwrap(), Vec::new());
    }

    #[test]
    fn one_level_trie_reads_flags_and_address() {
        // Root with one child "_x": terminal (flags 1, addr 0xff).
        let mut b = vec![0u8];
        b.push(1); // child count
        b.extend_from_slice(b"_x");
        b.push(0);
        let off_child_at = b.len();
        b.push(0); // patched below
        // Child node: terminal size 3, [flags 1, addr 0xff], no children.
        let child = [uleb(3), vec![0x01], uleb(0xff), vec![0]].concat();
        let at_child = b.len();
        b.extend_from_slice(&child);
        b[off_child_at] = at_child as u8;
        let out = exports(&b).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, b"_x");
        assert_eq!(out[0].flags, 1);
        assert_eq!(out[0].address, Some(0xff));
        assert_eq!(out[0].reexport_ordinal, None);
    }

    #[test]
    fn reexport_terminal_defaults_the_imported_name() {
        let mut b = vec![0u8, 1];
        b.extend_from_slice(b"_r");
        b.push(0);
        let off = b.len();
        b.push(0);
        let at = b.len();
        // terminal size 2: [flags 0x08, ordinal 7], no children.
        let mut info = uleb(2);
        info.push(0x08);
        info.push(7);
        info.push(0); // no children
        b.extend_from_slice(&info);
        b[off] = at as u8;
        let out = exports(&b).unwrap();
        assert_eq!(out[0].reexport_ordinal, Some(7));
        assert_eq!(out[0].imported_name, b"_r");
        assert_eq!(out[0].address, None);
    }

    #[test]
    fn zero_reexport_ordinal_is_rejected() {
        let b = [uleb(4), vec![0x08, 0x00, 0]].concat();
        assert!(exports(&b).is_err(), "ordinal 0 carries no meaning");
    }

    #[test]
    fn address_terminal_must_fill_the_info() {
        // Declared terminal size 3 but only flags+partial address present.
        let b = [vec![3], vec![0x00, 0x40, 0x00]].concat();
        assert!(exports(&b).is_err());
    }

    #[test]
    fn deep_recursion_is_bounded_by_the_payload() {
        // A chain of prefix nodes: recursion depth scales with the payload,
        // and the visited set stops any cycle. Node size (5) × depth must
        // stay inside a one-byte ULEB offset for the fixture patcher.
        let depth = 20usize;
        let mut b = Vec::new();
        for _ in 0..depth {
            b.push(0); // terminal size 0
            b.push(1); // one child
            b.push(b'z');
            b.push(0);
            b.push(0); // placeholder offset
        }
        b.push(0); // terminal-only node
        b.push(0);
        for k in 0..depth {
            let child = k * 5 + 5;
            b[k * 5 + 4] = child as u8;
        }
        let out = exports(&b).unwrap();
        assert_eq!(out.len(), 0, "prefix-only chains export nothing");
    }
}

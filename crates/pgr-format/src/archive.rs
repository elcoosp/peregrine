//! Static-archive (`!<arch>`) parsing — the M5/S7 input surface.
//!
//! An `.a` archive is the BSD/GNU `ar` container Apple's `libtool`/`ranlib`
//! emit: an 8-byte `!<arch>\n` magic followed by a sequence of members, each
//! with a fixed 60-byte header (name, decimal metadata, decimal size, the
//! `` `\n `` end marker) and even-byte padding. Three members are structural
//! rather than content:
//!
//! * the **ranlib symbol table** — `__.SYMDEF`, `__.SYMDEF SORTED`,
//!   `__.SYMDEF_64 SORTED` (Apple) or `/` (GNU): a `u32`/`u64` count, then
//!   `(string-table offset, member offset)` pairs, then the string table.
//!   This is the S7 lazy-pull index: it maps *defined symbol* → *member*
//!   without parsing any member object,
//! * the GNU **long-name table** `//`, holding member names referenced as
//!   `/offset` from headers,
//! * BSD **long-name prefixes** `#1/<len>`, which place the name in the
//!   first `<len>` data bytes of the member itself.
//!
//! Like every format-layer parser it is total: malformed or malicious input
//! produces a typed [`FormatError`], never a panic (fuzz target
//! `parse_archive`, proptest gates in `tests/archive_parse.rs`). All
//! integers are little-endian — the arm64-apple-darwin byte order both
//! `libtool` and `ld64` write.
//!
//! Determinism: members and index entries are reported in stored file
//! order; the parser only rewrites index member offsets into indices into
//! `Archive::members` (header offset first, data offset as the fallback
//! some producers use).

use crate::error::FormatError;

/// The 8-byte archive magic.
pub const ARCHIVE_MAGIC: &[u8; 8] = b"!<arch>\n";

/// Size of one `ar` member header.
const HEADER_SIZE: usize = 60;

/// One content member of the archive (structural members excluded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveMember {
    /// Member name with long-name encodings resolved (`foo.o`).
    pub name: String,
    /// File offset of the member's *data* (header and long-name prefix
    /// excluded) — consumers slice `bytes[offset .. offset + size]`.
    pub offset: u64,
    /// Data size in bytes (long-name prefix excluded).
    pub size: u64,
    /// Header offsets are kept for ranlib-table matching and diagnostics.
    pub header_offset: u64,
    /// Member mtime (as stored; Peregrine never interprets it).
    pub mtime: u64,
    /// Member uid (as stored).
    pub uid: u32,
    /// Member gid (as stored).
    pub gid: u32,
    /// Member mode (as stored).
    pub mode: u32,
}

/// One ranlib-table entry: a defined symbol and the member that defines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveIndexEntry {
    /// Symbol name, with the C underscore (`_printf`).
    pub name: String,
    /// Index into [`Archive::members`].
    pub member: u32,
}

/// A parsed archive: content members in file order plus the ranlib index
/// (empty when the archive carries no symbol table).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Archive {
    /// Content members in file order (symbol-table and name-table members
    /// excluded).
    pub members: Vec<ArchiveMember>,
    /// Ranlib entries in stored order (name-sorted for `SORTED` tables).
    pub index: Vec<ArchiveIndexEntry>,
}

/// True when `bytes` starts with the archive magic (8 bytes).
#[must_use]
pub fn is_archive(bytes: &[u8]) -> bool {
    bytes.len() >= ARCHIVE_MAGIC.len() && &bytes[..8] == ARCHIVE_MAGIC
}

/// Parses an archive structurally.
///
/// # Errors
/// [`FormatError`] on any structural violation: bad magic, truncated or
/// corrupt member headers, bad decimal fields, a ranlib table whose entries
/// point outside the file or at no member, long-name references beyond the
/// name table, or a duplicated symbol table. The parser never panics on
/// arbitrary input.
pub fn parse_archive(bytes: &[u8]) -> Result<Archive, FormatError> {
    if !is_archive(bytes) {
        return Err(FormatError::BadMagic {
            offset: 0,
            magic: if bytes.len() >= 4 {
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            } else {
                0
            },
        });
    }

    let mut archive = Archive::default();
    let mut raw_index: Vec<(String, u64)> = Vec::new();
    let mut long_names: Option<&[u8]> = None;
    let mut saw_symbol_table = false;
    let mut pos = ARCHIVE_MAGIC.len();

    while pos < bytes.len() {
        let hdr_off = pos;
        if bytes.len() - pos < HEADER_SIZE {
            return Err(FormatError::Truncated {
                offset: pos,
                need: HEADER_SIZE,
                have: bytes.len() - pos,
            });
        }
        let hdr = &bytes[pos..pos + HEADER_SIZE];
        if hdr[58] != b'`' || hdr[59] != b'\n' {
            return Err(FormatError::Invalid {
                offset: pos + 58,
                what: "ar member end marker",
                value: u16::from_le_bytes([hdr[58], hdr[59]]) as u64,
            });
        }
        let size = decimal_field(hdr, 48, 10, pos + 48)? as u64;
        let mtime = decimal_field(hdr, 16, 12, pos + 16)? as u64;
        let uid = decimal_field(hdr, 28, 6, pos + 28)?;
        let gid = decimal_field(hdr, 34, 6, pos + 34)?;
        let mode = decimal_field(hdr, 40, 8, pos + 40)?;

        let name_field = trim_end_spaces(&hdr[..16]);
        let data_off = pos + HEADER_SIZE;
        let data_end = data_off
            .checked_add(size as usize)
            .ok_or(FormatError::Invalid {
                offset: pos + 48,
                what: "ar member size overflows",
                value: size,
            })?;
        if data_end > bytes.len() {
            return Err(FormatError::Overrun {
                offset: data_off,
                overrun: data_end - bytes.len(),
            });
        }

        // Structural member classification.
        let name = name_field.to_vec();
        if name == b"/" || name == b"__.SYMDEF" || name == b"__.SYMDEF SORTED" {
            if saw_symbol_table {
                return Err(FormatError::Malformed {
                    what: "duplicate archive symbol table".into(),
                });
            }
            saw_symbol_table = true;
            parse_symbol_table(bytes, data_off, size, false, &mut raw_index)?;
            pos = pad_end(data_end, size);
            continue;
        }
        if name == b"/SYM64/" || name == b"__.SYMDEF_64" || name == b"__.SYMDEF_64 SORTED" {
            if saw_symbol_table {
                return Err(FormatError::Malformed {
                    what: "duplicate archive symbol table".into(),
                });
            }
            saw_symbol_table = true;
            parse_symbol_table(bytes, data_off, size, true, &mut raw_index)?;
            pos = pad_end(data_end, size);
            continue;
        }
        if name == b"//" {
            long_names = Some(&bytes[data_off..data_end]);
            pos = pad_end(data_end, size);
            continue;
        }

        // Content member: resolve the name, then record it.
        let (name, data_start) = if name.starts_with(b"#1/") {
            // BSD long name: `#1/<len>` — the name is the first `<len>` data
            // bytes (NUL-padded).
            let name_len = decimal_field(hdr, 3, 13, pos + 3)? as usize;
            if name_len > size as usize {
                return Err(FormatError::Overrun {
                    offset: data_off,
                    overrun: name_len - size as usize,
                });
            }
            let raw = &bytes[data_off..data_off + name_len];
            let trimmed = trim_end_nul(raw);
            (
                core::str::from_utf8(trimmed)
                    .map_err(|_| FormatError::Malformed {
                        what: "BSD long member name is not UTF-8".into(),
                    })?
                    .to_string(),
                data_off + name_len,
            )
        } else if name.starts_with(b"/") {
            // GNU long-name reference: `/offset` into the `//` table.
            let off = decimal_field(hdr, 1, 15, pos + 1)? as usize;
            let table = long_names.ok_or(FormatError::Malformed {
                what: "member references the long-name table before it appears".into(),
            })?;
            let entry = table.get(off..).ok_or(FormatError::Overrun {
                offset: data_off,
                overrun: off.saturating_sub(table.len()),
            })?;
            let end = entry
                .iter()
                .position(|&b| b == b'\n' || b == b'\0')
                .unwrap_or(entry.len());
            // GNU writes `name/\n`; the trailing `/` is the separator.
            let entry = trim_end_spaces(&entry[..end]);
            let entry = entry.strip_suffix(b"/").unwrap_or(entry);
            (
                core::str::from_utf8(entry)
                    .map_err(|_| FormatError::Malformed {
                        what: "GNU long member name is not UTF-8".into(),
                    })?
                    .to_string(),
                data_off,
            )
        } else {
            // Short name: Apple space-padded (`foo.o`) or GNU `/`-suffixed
            // (`foo.o/`).
            let trimmed = trim_end_spaces(name_field);
            let trimmed = trimmed.strip_suffix(b"/").unwrap_or(trimmed);
            (
                core::str::from_utf8(trimmed)
                    .map_err(|_| FormatError::Malformed {
                        what: "member name is not UTF-8".into(),
                    })?
                    .to_string(),
                data_off,
            )
        };

        archive.members.push(ArchiveMember {
            name,
            offset: data_start as u64,
            size: (data_end - data_start) as u64,
            header_offset: hdr_off as u64,
            mtime,
            uid,
            gid,
            mode,
        });
        pos = pad_end(data_end, size);
    }

    resolve_index(&mut archive, raw_index)?;
    Ok(archive)
}

/// End of member data plus the odd-size pad byte (absent at EOF is fine).
fn pad_end(data_end: usize, size: u64) -> usize {
    if size % 2 == 1 && data_end < usize::MAX {
        // The pad byte is consumed on the next iteration only when present;
        // a missing pad at EOF is tolerated.
        data_end + 1
    } else {
        data_end
    }
}

/// Parses a ranlib symbol-table member body into raw `(name, offset)`
/// entries; offsets resolve to member indices once all members are known.
fn parse_symbol_table(
    bytes: &[u8],
    data_off: usize,
    size: u64,
    wide: bool,
    out: &mut Vec<(String, u64)>,
) -> Result<(), FormatError> {
    let data = &bytes[data_off..data_off + size as usize];
    let (count, cursor) = if wide {
        if data.len() < 8 {
            return Err(FormatError::Truncated {
                offset: data_off,
                need: 8,
                have: data.len(),
            });
        }
        (
            u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]),
            8usize,
        )
    } else {
        if data.len() < 4 {
            return Err(FormatError::Truncated {
                offset: data_off,
                need: 4,
                have: data.len(),
            });
        }
        (
            u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64,
            4usize,
        )
    };
    let entry_size = if wide { 16 } else { 8 };
    let entries_bytes = (count as usize)
        .checked_mul(entry_size)
        .ok_or(FormatError::Invalid {
            offset: data_off,
            what: "ranlib entry count overflows",
            value: count,
        })?;
    let strings_off = cursor
        .checked_add(entries_bytes)
        .ok_or(FormatError::Invalid {
            offset: data_off,
            what: "ranlib table overflows",
            value: count,
        })?;
    if strings_off > data.len() {
        return Err(FormatError::Overrun {
            offset: data_off,
            overrun: strings_off - data.len(),
        });
    }
    let strings = &data[strings_off..];
    for i in 0..count as usize {
        let base = cursor + i * entry_size;
        let (strx, member_off) = if wide {
            let strx = u64::from_le_bytes(data[base..base + 8].try_into().expect("16-byte entry"));
            let off =
                u64::from_le_bytes(data[base + 8..base + 16].try_into().expect("16-byte entry"));
            (strx, off)
        } else {
            let strx = u32::from_le_bytes(data[base..base + 4].try_into().expect("8-byte entry"));
            let off =
                u32::from_le_bytes(data[base + 4..base + 8].try_into().expect("8-byte entry"));
            (u64::from(strx), u64::from(off))
        };
        let name_bytes = strings.get(strx as usize..).ok_or(FormatError::Overrun {
            offset: data_off + base,
            overrun: strx as usize,
        })?;
        let end = name_bytes
            .iter()
            .position(|&b| b == 0)
            .ok_or(FormatError::Invalid {
                offset: data_off + base,
                what: "ranlib string-table entry without a NUL terminator",
                value: strx,
            })?;
        let name =
            core::str::from_utf8(&name_bytes[..end]).map_err(|_| FormatError::Malformed {
                what: "ranlib symbol name is not UTF-8".into(),
            })?;
        out.push((name.to_string(), member_off));
    }
    Ok(())
}

/// Rewrites raw ranlib member offsets into member indices: the header offset
/// matches first (libtool/ranlib), the data offset second (some producers),
/// anything else is a corrupt table.
fn resolve_index(archive: &mut Archive, raw: Vec<(String, u64)>) -> Result<(), FormatError> {
    for (name, off) in raw {
        let member = archive
            .members
            .iter()
            .position(|m| m.header_offset == off || m.offset == off)
            .ok_or(FormatError::Invalid {
                offset: 0,
                what: "ranlib entry points at no archive member",
                value: off,
            })?;
        archive.index.push(ArchiveIndexEntry {
            name,
            member: member as u32,
        });
    }
    Ok(())
}

/// Parses a blank-padded decimal field; blank fields read as 0.
fn decimal_field(hdr: &[u8], off: usize, len: usize, abs: usize) -> Result<u32, FormatError> {
    let field = trim_end_spaces(&hdr[off..off + len]);
    if field.is_empty() {
        return Ok(0);
    }
    let mut value: u64 = 0;
    for &b in field {
        if !b.is_ascii_digit() {
            return Err(FormatError::Invalid {
                offset: abs,
                what: "ar header decimal field",
                value: b as u64,
            });
        }
        value = value * 10 + u64::from(b - b'0');
        if value > u32::MAX as u64 {
            return Err(FormatError::Invalid {
                offset: abs,
                what: "ar header decimal field overflows u32",
                value,
            });
        }
    }
    Ok(value as u32)
}

fn trim_end_spaces(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().rposition(|&b| b != b' ').map_or(0, |p| p + 1);
    &bytes[..end]
}

fn trim_end_nul(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
    &bytes[..end]
}

#[cfg(test)]
mod tests {
    use super::{is_archive, parse_archive};

    #[test]
    fn rejects_short_and_non_archive_input() {
        assert!(parse_archive(&[]).is_err());
        assert!(parse_archive(b"!<arch>").is_err());
        assert!(parse_archive(b"\xcf\xfa\xed\xfe rest").is_err());
        assert!(!is_archive(b"!<arch>"));
        assert!(is_archive(b"!<arch>\n"));
    }

    #[test]
    fn member_name_styles_parse() {
        // Apple space padding, GNU slash suffix.
        let mut bytes: Vec<u8> = b"!<arch>\n".to_vec();
        let mut hdr = vec![b' '; 60];
        hdr[..6].copy_from_slice(b"foo.o/");
        hdr[48..50].copy_from_slice(b"0 ");
        hdr[58] = b'`';
        hdr[59] = b'\n';
        bytes.extend_from_slice(&hdr);
        let arch = parse_archive(&bytes).unwrap();
        assert_eq!(arch.members.len(), 1);
        assert_eq!(arch.members[0].name, "foo.o");
        assert_eq!(arch.members[0].size, 0);
    }
}

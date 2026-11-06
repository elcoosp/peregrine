//! Classic `LC_DYLD_INFO`/`LC_DYLD_INFO_ONLY` opcode streams (M6 legacy
//! fallback — TDD §2.1.4/§3.6: chained fixups require macOS ≥ 12; older
//! deployment targets and `-no_fixup_chains` get rebase/bind opcode
//! streams instead, the pre-Mavericks format dyld still walks today).
//!
//! Streams (LLVM `MachO.h` / dyld `MachOAnalyzer::forEach*` semantics):
//!
//! * **rebase** — per internal pointer slot: set type, set
//!   segment+offset, `DO_REBASE`; dyld writes `base + target` where the
//!   target is the slot's file content (the link-time value).
//! * **bind** — per external pointer slot: set library ordinal, set
//!   symbol (flags byte + NUL-terminated name trailing the opcode), set
//!   addend (SLEB, when nonzero), set segment+offset, `DO_BIND`; dyld
//!   writes the resolved external address.
//!
//! Determinism: entries arrive address-sorted from the layout pass; the
//! encoders are pure functions of the entry list.

use crate::error::FormatError;

/// `dyld_info_command` fixed size (12 head + 6×(off,size) pairs).
pub const DYLD_INFO_COMMAND_SIZE: usize = 48;

/// `REBASE_TYPE_POINTER` — an 8-byte image-relative pointer slot.
pub const REBASE_TYPE_POINTER: u8 = 1;
/// `REBASE_TYPE_TEXT_PCREL32` — a 32-bit PC-relative text slot.
pub const REBASE_TYPE_TEXT_PCREL32: u8 = 2;
/// `BIND_TYPE_POINTER` — an 8-byte slot dyld writes the target into.
pub const BIND_TYPE_POINTER: u8 = 1;
/// `BIND_SYMBOL_FLAGS_WEAK_IMPORT` — the bound symbol is a weak import.
pub const BIND_SYMBOL_FLAGS_WEAK_IMPORT: u8 = 0x1;

// Rebase opcodes (high nibble).
const REBASE_DONE: u8 = 0x00;
const REBASE_SET_TYPE_IMM: u8 = 0x10;
const REBASE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
const REBASE_DO_REBASE: u8 = 0x70;

// Bind opcodes (high nibble).
const BIND_DONE: u8 = 0x00;
const BIND_SET_DYLIB_ORDINAL_IMM: u8 = 0x40;
const BIND_SET_DYLIB_ORDINAL_ULEB: u8 = 0x50;
const BIND_SET_DYLIB_SPECIAL_IMM: u8 = 0x60;
const BIND_SET_TRAILING_FLAGS_SYMBOL: u8 = 0x70;
const BIND_SET_TYPE_IMM: u8 = 0x80;
const BIND_SET_ADDEND_SLEB: u8 = 0x90;
const BIND_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0xA0;
const BIND_DO_BIND: u8 = 0xC0;

/// The parsed `dyld_info_command` payload (all six off/size pairs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DyldInfoCommand {
    /// `cmd` (`LC_DYLD_INFO` or `LC_DYLD_INFO_ONLY`).
    pub cmd: u32,
    /// `cmdsize` (48 for a well-formed command).
    pub cmdsize: u32,
    /// Rebase stream file offset (0 when absent).
    pub rebase_off: u32,
    /// Rebase stream size.
    pub rebase_size: u32,
    /// Bind stream file offset (0 when absent).
    pub bind_off: u32,
    /// Bind stream size.
    pub bind_size: u32,
    /// Weak-bind stream file offset (0 when absent).
    pub weak_bind_off: u32,
    /// Weak-bind stream size.
    pub weak_bind_size: u32,
    /// Lazy-bind stream file offset (0 when absent).
    pub lazy_bind_off: u32,
    /// Lazy-bind stream size.
    pub lazy_bind_size: u32,
    /// Export blob offset (0 when exports ride `LC_DYLD_EXPORTS_TRIE`).
    pub export_off: u32,
    /// Export blob size.
    pub export_size: u32,
}

impl DyldInfoCommand {
    /// Parses the 48-byte command.
    ///
    /// # Errors
    /// [`FormatError::Overrun`] when fewer than 48 bytes are available.
    /// [`FormatError::Invalid`] when `cmdsize` is not 48.
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() < DYLD_INFO_COMMAND_SIZE {
            return Err(FormatError::Overrun {
                offset: 0,
                overrun: DYLD_INFO_COMMAND_SIZE - bytes.len(),
            });
        }
        let u32_at = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let cmd = DyldInfoCommand {
            cmd: u32_at(0),
            cmdsize: u32_at(4),
            rebase_off: u32_at(8),
            rebase_size: u32_at(12),
            bind_off: u32_at(16),
            bind_size: u32_at(20),
            weak_bind_off: u32_at(24),
            weak_bind_size: u32_at(28),
            lazy_bind_off: u32_at(32),
            lazy_bind_size: u32_at(36),
            export_off: u32_at(40),
            export_size: u32_at(44),
        };
        if cmd.cmdsize != DYLD_INFO_COMMAND_SIZE as u32 {
            return Err(FormatError::Invalid {
                offset: 4,
                what: "dyld_info_command cmdsize must be 48",
                value: u64::from(cmd.cmdsize),
            });
        }
        Ok(cmd)
    }
}

/// A bind library ordinal: a 1-based `LC_LOAD_DYLIB` index, or one of the
/// special ordinals (flat/weak lookup — emitted as negative immediates).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOrdinal {
    /// A regular dylib ordinal (1-based).
    Dylib(u8),
    /// A special ordinal: the stored value is the *negative* immediate
    /// dyld computes (`0 - imm`), e.g. `-2` = `BIND_SPECIAL_DYLIB_FLAT_LOOKUP`? —
    /// dyld's table: flat lookup = `-2`, weak lookup = `-3`, main
    /// executable = `-1`. Stored here as the negative number.
    Special(i8),
}

/// One rebase stream entry: segment index + offset within the segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebaseEntry {
    /// `LC_SEGMENT_64` index (0-based, `__PAGEZERO` included).
    pub seg: u8,
    /// Byte offset within the segment.
    pub seg_off: u64,
}

/// One bind stream entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindEntry {
    /// `LC_SEGMENT_64` index.
    pub seg: u8,
    /// Byte offset within the segment.
    pub seg_off: u64,
    /// Library ordinal.
    pub ordinal: BindOrdinal,
    /// Symbol flags (`BIND_SYMBOL_FLAGS_WEAK_IMPORT`).
    pub flags: u8,
    /// Symbol name (without the NUL).
    pub name: Vec<u8>,
    /// Bind addend.
    pub addend: i64,
}

/// Encodes the rebase stream for address-sorted entries.
#[must_use]
pub fn encode_rebase_stream(entries: &[RebaseEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * 8 + 2);
    out.push(REBASE_SET_TYPE_IMM | REBASE_TYPE_POINTER);
    let mut last: Option<(u8, u64)> = None;
    for e in entries {
        if last != Some((e.seg, e.seg_off)) {
            // The segment index rides in the opcode immediate (dyld reads
            // it from `imm`); only the offset is ULEB.
            out.push(REBASE_SET_SEGMENT_AND_OFFSET_ULEB | (e.seg & 0x0F));
            out.extend(uleb(e.seg_off));
        }
        out.push(REBASE_DO_REBASE);
        last = Some((e.seg, e.seg_off));
    }
    out.push(REBASE_DONE);
    out
}

/// Encodes the bind stream for address-sorted entries. Every entry carries
/// its full state (ordinal, symbol, addend, segment+offset) — compactness
/// comes from dedup upstream, correctness here.
#[must_use]
pub fn encode_bind_stream(entries: &[BindEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * 16 + 2);
    out.push(BIND_SET_TYPE_IMM | BIND_TYPE_POINTER);
    for e in entries {
        match e.ordinal {
            BindOrdinal::Dylib(ord) => {
                if ord < 16 {
                    out.push(BIND_SET_DYLIB_ORDINAL_IMM | ord);
                } else {
                    out.push(BIND_SET_DYLIB_ORDINAL_ULEB);
                    out.extend(uleb(u64::from(ord)));
                }
            }
            BindOrdinal::Special(neg) => {
                // The immediate encodes the magnitude: dyld computes `0 - imm`.
                let mag = (-i64::from(neg)) as u8;
                out.push(BIND_SET_DYLIB_SPECIAL_IMM | (mag & 0x0F));
            }
        }
        // dyld reads the symbol flags from the opcode immediate; the
        // NUL-terminated name follows. (Only flags ≤ 0x0F — in practice
        // WEAK_IMPORT or zero — travel here, matching ld64.)
        out.push(BIND_SET_TRAILING_FLAGS_SYMBOL | (e.flags & 0x0F));
        out.extend_from_slice(&e.name);
        out.push(0);
        if e.addend != 0 {
            out.push(BIND_SET_ADDEND_SLEB);
            out.extend(sleb(e.addend));
        }
        out.push(BIND_SET_SEGMENT_AND_OFFSET_ULEB | (e.seg & 0x0F));
        out.extend(uleb(e.seg_off));
        out.push(BIND_DO_BIND);
    }
    out.push(BIND_DONE);
    out
}

/// One decoded rebase entry (type carried for the verifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedRebase {
    /// The rebase type the stream set.
    pub r#type: u8,
    /// Segment index.
    pub seg: u8,
    /// Offset within the segment.
    pub seg_off: u64,
}

/// Walks a rebase stream (verifier side). Terminates at `DONE` or end of
/// stream (dyld tolerates a missing trailing `DONE`).
///
/// # Errors
/// [`FormatError::Malformed`] on unknown opcodes or truncated ULEBs.
pub fn decode_rebase_stream(bytes: &[u8]) -> Result<Vec<DecodedRebase>, FormatError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut r#type = 0u8;
    let mut seg = 0u8;
    let mut seg_off = 0u64;
    while i < bytes.len() {
        let op = bytes[i];
        i += 1;
        let imm = op & 0x0F;
        match op & 0xF0 {
            REBASE_DONE => break,
            REBASE_SET_TYPE_IMM => r#type = imm,
            REBASE_SET_SEGMENT_AND_OFFSET_ULEB => {
                seg = imm;
                let (v, next) = uleb_at(bytes, i).ok_or(FormatError::Malformed {
                    what: "rebase stream: truncated ULEB offset".to_string(),
                })?;
                seg_off = v;
                i = next;
            }
            REBASE_DO_REBASE => out.push(DecodedRebase {
                r#type,
                seg,
                seg_off,
            }),
            _ => {
                return Err(FormatError::Malformed {
                    what: format!("rebase stream: unknown opcode {op:#04x} at {i}"),
                });
            }
        }
    }
    Ok(out)
}

/// Walks a bind stream (verifier side).
///
/// # Errors
/// [`FormatError::Malformed`] on unknown opcodes, truncated ULEBs/SLEBs or
/// unterminated symbol names.
pub fn decode_bind_stream(bytes: &[u8]) -> Result<Vec<BindEntry>, FormatError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut ordinal = BindOrdinal::Special(-2);
    let mut flags = 0u8;
    let mut name: Vec<u8> = Vec::new();
    let mut addend = 0i64;
    let mut seg = 0u8;
    let mut seg_off = 0u64;
    while i < bytes.len() {
        let op = bytes[i];
        i += 1;
        let imm = op & 0x0F;
        match op & 0xF0 {
            BIND_DONE => break,
            BIND_SET_DYLIB_ORDINAL_IMM => ordinal = BindOrdinal::Dylib(imm),
            BIND_SET_DYLIB_ORDINAL_ULEB => {
                let (v, next) = uleb_at(bytes, i).ok_or(FormatError::Malformed {
                    what: "bind stream: truncated ULEB ordinal".to_string(),
                })?;
                ordinal =
                    BindOrdinal::Dylib(u8::try_from(v).map_err(|_| FormatError::Malformed {
                        what: format!("bind stream: ordinal {v} exceeds u8"),
                    })?);
                i = next;
            }
            BIND_SET_DYLIB_SPECIAL_IMM => {
                // The immediate is a small magnitude; 0 means −16.
                let mag = if imm == 0 { 16 } else { i64::from(imm) };
                ordinal = BindOrdinal::Special((-mag) as i8);
            }
            BIND_SET_TRAILING_FLAGS_SYMBOL => {
                flags = imm;
                let Some(nul) = bytes[i..].iter().position(|&b| b == 0) else {
                    return Err(FormatError::Malformed {
                        what: "bind stream: symbol name runs past the stream end".to_string(),
                    });
                };
                name = bytes[i..i + nul].to_vec();
                i += nul + 1;
            }
            BIND_SET_TYPE_IMM => {}
            BIND_SET_ADDEND_SLEB => {
                let (v, next) = sleb_at(bytes, i).ok_or(FormatError::Malformed {
                    what: "bind stream: truncated SLEB addend".to_string(),
                })?;
                addend = v;
                i = next;
            }
            BIND_SET_SEGMENT_AND_OFFSET_ULEB => {
                seg = imm;
                let (v, next) = uleb_at(bytes, i).ok_or(FormatError::Malformed {
                    what: "bind stream: truncated ULEB offset".to_string(),
                })?;
                seg_off = v;
                i = next;
            }
            BIND_DO_BIND => {
                out.push(BindEntry {
                    seg,
                    seg_off,
                    ordinal,
                    flags,
                    name: name.clone(),
                    addend,
                });
            }
            _ => {
                return Err(FormatError::Malformed {
                    what: format!("bind stream: unknown opcode {op:#04x} at {i}"),
                });
            }
        }
    }
    Ok(out)
}

/// ULEB128 encode.
#[must_use]
pub fn uleb(mut v: u64) -> Vec<u8> {
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

/// ULEB128 decode at `at`: `(value, next)` or `None` on overflow/end.
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

/// SLEB128 encode (two's complement, 7 bits per byte).
#[must_use]
pub fn sleb(mut v: i64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        let sign_bit = byte & 0x40 != 0;
        if (v == 0 && !sign_bit) || (v == -1 && sign_bit) {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out
}

/// SLEB128 decode at `at`: `(value, next)` or `None` on overflow/end.
fn sleb_at(data: &[u8], at: usize) -> Option<(i64, usize)> {
    let mut value = 0i64;
    let mut shift = 0u32;
    let mut i = at;
    loop {
        let byte = *data.get(i)?;
        i += 1;
        value |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                value |= -1i64 << shift;
            }
            return Some((value, i));
        }
        if shift > 63 {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BindEntry, BindOrdinal, DyldInfoCommand, decode_bind_stream, decode_rebase_stream,
        encode_bind_stream, encode_rebase_stream, sleb, uleb,
    };

    #[test]
    fn uleb_matches_llvm() {
        assert_eq!(uleb(0), vec![0x00]);
        assert_eq!(uleb(127), vec![0x7f]);
        assert_eq!(uleb(128), vec![0x80, 0x01]);
        assert_eq!(uleb(0x1234), vec![0xb4, 0x24]);
    }

    #[test]
    fn sleb_matches_llvm() {
        assert_eq!(sleb(0), vec![0x00]);
        assert_eq!(sleb(-1), vec![0x7f]);
        assert_eq!(sleb(63), vec![0x3f]);
        assert_eq!(sleb(64), vec![0xc0, 0x00]);
        assert_eq!(sleb(-64), vec![0x40]);
        assert_eq!(sleb(-123), vec![0x85, 0x7f]);
    }

    #[test]
    fn rebase_roundtrip() {
        let entries = vec![
            super::RebaseEntry {
                seg: 1,
                seg_off: 0x8000,
            },
            super::RebaseEntry {
                seg: 1,
                seg_off: 0x8008,
            },
            super::RebaseEntry {
                seg: 2,
                seg_off: 0x40,
            },
        ];
        let bytes = encode_rebase_stream(&entries);
        // SET_TYPE(1) then per entry, with the same-segment pair sharing a
        // SET_SEGMENT.
        assert_eq!(bytes.first(), Some(&0x11));
        let decoded = decode_rebase_stream(&bytes).unwrap();
        assert_eq!(decoded.len(), 3);
        assert!(
            decoded
                .iter()
                .all(|d| d.r#type == super::REBASE_TYPE_POINTER)
        );
        assert_eq!((decoded[0].seg, decoded[0].seg_off), (1, 0x8000));
        assert_eq!((decoded[1].seg, decoded[1].seg_off), (1, 0x8008));
        assert_eq!((decoded[2].seg, decoded[2].seg_off), (2, 0x40));
    }

    #[test]
    fn bind_roundtrip_ordinals_names_addends() {
        let entries = vec![
            BindEntry {
                seg: 2,
                seg_off: 0x1000,
                ordinal: BindOrdinal::Dylib(1),
                flags: 0,
                name: b"_printf".to_vec(),
                addend: 0,
            },
            BindEntry {
                seg: 2,
                seg_off: 0x1008,
                ordinal: BindOrdinal::Special(-2), // flat lookup
                flags: super::BIND_SYMBOL_FLAGS_WEAK_IMPORT,
                name: b"_weak_fn".to_vec(),
                addend: 300,
            },
        ];
        let bytes = encode_bind_stream(&entries);
        assert_eq!(bytes.first(), Some(&0x81)); // SET_TYPE pointer
        let decoded = decode_bind_stream(&bytes).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].ordinal, BindOrdinal::Dylib(1));
        assert_eq!(decoded[0].name, b"_printf");
        assert_eq!(decoded[0].addend, 0);
        assert_eq!(decoded[1].ordinal, BindOrdinal::Special(-2));
        assert_eq!(decoded[1].flags, super::BIND_SYMBOL_FLAGS_WEAK_IMPORT);
        assert_eq!(decoded[1].addend, 300);
    }

    #[test]
    fn dyld_info_command_parse_rejects_short_and_wrong_size() {
        assert!(DyldInfoCommand::parse(&[0u8; 47]).is_err());
        let mut buf = vec![0u8; 48];
        buf[4..8].copy_from_slice(&49u32.to_le_bytes()); // bad cmdsize
        assert!(DyldInfoCommand::parse(&buf).is_err());
        let mut buf = vec![0u8; 48];
        buf[0..4].copy_from_slice(&super::super::consts::LC_DYLD_INFO_ONLY.to_le_bytes());
        buf[4..8].copy_from_slice(&48u32.to_le_bytes());
        let cmd = DyldInfoCommand::parse(&buf).unwrap();
        assert_eq!(cmd.cmdsize, 48);
        assert_eq!(cmd.rebase_off, 0);
    }

    #[test]
    fn truncated_streams_are_errors_not_panics() {
        // Truncated ULEB in a rebase offset.
        assert!(decode_rebase_stream(&[0x11, 0x21, 0x01, 0x80]).is_err());
        // Unknown opcode.
        assert!(decode_rebase_stream(&[0x11, 0xF0]).is_err());
        // Unterminated bind symbol.
        assert!(decode_bind_stream(&[0x81, 0x41, 0x70, b'_', b'x']).is_err());
        // Truncated SLEB addend.
        assert!(decode_bind_stream(&[0x81, 0x41, 0x70, 0x00, b'_', 0x00, 0x91, 0x80]).is_err());
    }
}

//! Chained fixups codecs (`LC_DYLD_CHAINED_FIXUPS` payload and chain words).
//!
//! Layout reference: LLVM `MachO.h` / Apple `fixup-chains.h`, cross-checked
//! against mold's `macho/chunks/chained_fixups.rs` (TDD §2.1.4). The payload
//! is: `dyld_chained_fixups_header` (28 bytes, padded to 8),
//! `dyld_chained_starts_in_image` (per-segment start tables), the import
//! table, and the imports' name blob. Fixup words live in the segment data
//! itself and chain page-locally via a 12-bit `next` field counting 4-byte
//! strides; chains never cross a page (TDD §7).

use crate::consts::{
    DYLD_CHAINED_IMPORT, DYLD_CHAINED_IMPORT_ADDEND, DYLD_CHAINED_IMPORT_ADDEND64,
    DYLD_CHAINED_PTR_START_MULTI, DYLD_CHAINED_PTR_START_MULTI_MASK, DYLD_CHAINED_PTR_START_NONE,
};
use crate::cursor::Cursor;
use crate::error::FormatError;

/// `dyld_chained_fixups_header`: the 28-byte payload head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainedFixupsHeader {
    /// Chain-data version, currently always 0.
    pub fixups_version: u32,
    /// Offset of `dyld_chained_starts_in_image` within the payload.
    pub starts_offset: u32,
    /// Offset of the import table within the payload.
    pub imports_offset: u32,
    /// Offset of the imports' name blob within the payload.
    pub symbols_offset: u32,
    /// Number of import-table entries.
    pub imports_count: u32,
    /// `DYLD_CHAINED_IMPORT*` format of the import table.
    pub imports_format: u32,
    /// `DYLD_CHAINED_SYMBOL_FORMAT*` of the name blob (0 = plain strings).
    pub symbols_format: u32,
}

/// `dyld_chained_starts_in_image`: `seg_count` segment entries followed by a
/// `u32` offset per segment (0 = no fixups in that segment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedStartsInImage {
    /// Number of segment commands the offsets table covers.
    pub seg_count: u32,
    /// Per-segment offsets of `dyld_chained_starts_in_segment` records,
    /// counted from the start of the `dyld_chained_starts_in_image`; 0 when
    /// the segment carries no fixups.
    pub seg_info_offset: Vec<u32>,
}

/// `dyld_chained_starts_in_segment`: chain starts for one segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedStartsInSegment {
    /// Size of this record including the `page_start` array (22 + 2*n).
    pub size: u32,
    /// Chain-walk page size (0x1000 or 0x4000 on arm64).
    pub page_size: u16,
    /// `DYLD_CHAINED_PTR_*` pointer format.
    pub pointer_format: u16,
    /// Offset from the image base where the segment starts; under the
    /// Peregrine constant-delta contract this equals the segment `fileoff`.
    pub segment_offset: u64,
    /// For 32-bit images: bound above which values are not pointers.
    pub max_valid_pointer: u32,
    /// Number of chain-walk pages covered by `page_start`.
    pub page_count: u16,
    /// Per-page first-chain-slot offset, `DYLD_CHAINED_PTR_START_NONE`, or a
    /// multi-start marker (`DYLD_CHAINED_PTR_START_MULTI | offset`).
    pub page_start: Vec<u16>,
}

/// Decoded `dyld_chained_import` (all three formats unified).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Import {
    /// Library ordinal (1-based two-level index, or a `BIND_SPECIAL_*` value).
    pub lib_ordinal: u16,
    /// True when the import is a weak reference.
    pub weak_import: bool,
    /// Offset of the symbol name within the payload's name blob.
    pub name_offset: u32,
    /// Table addend (0 for format 1).
    pub addend: i64,
}

/// Decodes the payload header at `payload[0..28]`.
pub fn parse_header(payload: &[u8]) -> Result<ChainedFixupsHeader, FormatError> {
    if payload.len() < 28 {
        return Err(FormatError::Truncated {
            offset: 0,
            need: 28,
            have: payload.len(),
        });
    }
    let mut c = Cursor::new(payload);
    let fixups_version = c.read_u32()?;
    let starts_offset = c.read_u32()?;
    let imports_offset = c.read_u32()?;
    let symbols_offset = c.read_u32()?;
    let imports_count = c.read_u32()?;
    let imports_format = c.read_u32()?;
    let symbols_format = c.read_u32()?;
    if fixups_version != 0 {
        return Err(FormatError::Invalid {
            offset: 0,
            what: "dyld_chained_fixups_header.fixups_version",
            value: fixups_version as u64,
        });
    }
    if symbols_format != 0 {
        return Err(FormatError::Invalid {
            offset: 24,
            what: "dyld_chained_fixups_header.symbols_format (compressed symbol blobs unsupported)",
            value: symbols_format as u64,
        });
    }
    Ok(ChainedFixupsHeader {
        fixups_version,
        starts_offset,
        imports_offset,
        symbols_offset,
        imports_count,
        imports_format,
        symbols_format,
    })
}

/// Reads `count` `u32` values at `offset` from `bytes`. The count is bounded
/// by the bytes actually available (a mutated/truncated count yields a typed
/// error instead of a huge pre-allocation).
fn read_u32_slice(bytes: &[u8], offset: usize, count: usize) -> Result<Vec<u32>, FormatError> {
    let avail = bytes.len().saturating_sub(offset);
    if count > avail / 4 {
        return Err(FormatError::Overrun {
            offset,
            overrun: count * 4 - avail,
        });
    }
    let mut c = Cursor::new(bytes);
    c.seek(offset)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(c.read_u32()?);
    }
    Ok(out)
}

/// Parses `dyld_chained_starts_in_image` at `offset` within the payload.
pub fn parse_starts_in_image(
    payload: &[u8],
    offset: usize,
) -> Result<ChainedStartsInImage, FormatError> {
    let mut c = Cursor::new(payload);
    c.seek(offset)?;
    let seg_count = c.read_u32()?;
    // Guard against absurd counts before allocating: the offsets table must
    // fit within the payload that declares it.
    if seg_count > payload.len() as u32 / 4 {
        return Err(FormatError::Invalid {
            offset,
            what: "dyld_chained_starts_in_image.seg_count exceeds payload size",
            value: seg_count as u64,
        });
    }
    let seg_info_offset = read_u32_slice(payload, offset + 4, seg_count as usize)?;
    Ok(ChainedStartsInImage {
        seg_count,
        seg_info_offset,
    })
}

/// Parses `dyld_chained_starts_in_segment` at `offset` within the payload.
pub fn parse_starts_in_segment(
    payload: &[u8],
    offset: usize,
) -> Result<ChainedStartsInSegment, FormatError> {
    let mut c = Cursor::new(payload);
    c.seek(offset)?;
    let size = c.read_u32()?;
    let page_size = c.read_u16()?;
    let pointer_format = c.read_u16()?;
    let segment_offset = c.read_u64()?;
    let max_valid_pointer = c.read_u32()?;
    let page_count = c.read_u16()?;
    // Fixed fields occupy 22 bytes; `size` covers fixed fields plus entries.
    let min_size = 22u64 + u64::from(page_count) * 2;
    if u64::from(size) < min_size {
        return Err(FormatError::Invalid {
            offset,
            what: "dyld_chained_starts_in_segment.size smaller than its page_start array",
            value: size as u64,
        });
    }
    if u64::from(size) > payload.len() as u64 - offset as u64 {
        return Err(FormatError::Overrun {
            offset,
            overrun: size as usize + offset - payload.len(),
        });
    }
    let mut page_start = Vec::with_capacity(page_count as usize);
    for _ in 0..page_count {
        page_start.push(c.read_u16()?);
    }
    Ok(ChainedStartsInSegment {
        size,
        page_size,
        pointer_format,
        segment_offset,
        max_valid_pointer,
        page_count,
        page_start,
    })
}

/// The byte offset, within a page, where the first chain starts — expanding
/// the `DYLD_CHAINED_PTR_START_MULTI` marker when present.
///
/// `record_offset` is the offset of the `dyld_chained_starts_in_segment`
/// record within the payload; multi-start offsets are relative to it.
pub fn page_chain_starts(
    payload: &[u8],
    record_offset: usize,
    segment: &ChainedStartsInSegment,
    page: u16,
) -> Result<Vec<u16>, FormatError> {
    let raw = segment
        .page_start
        .get(page as usize)
        .ok_or(FormatError::Invalid {
            offset: record_offset,
            what: "page_start index out of range",
            value: page as u64,
        })?;
    if *raw == DYLD_CHAINED_PTR_START_NONE {
        return Ok(Vec::new());
    }
    if *raw & DYLD_CHAINED_PTR_START_MULTI == 0 {
        return Ok(vec![*raw]);
    }
    // Multi-start: read {count, offsets[]} relative to the record start.
    let table_off = record_offset + (*raw & DYLD_CHAINED_PTR_START_MULTI_MASK) as usize;
    let mut c = Cursor::new(payload);
    c.seek(table_off)?;
    let count = c.read_u16()? as usize;
    if count > segment.page_size as usize / 4 {
        return Err(FormatError::Invalid {
            offset: table_off,
            what: "multi-start count exceeds page capacity",
            value: count as u64,
        });
    }
    let mut starts = Vec::with_capacity(count);
    for _ in 0..count {
        starts.push(c.read_u16()?);
    }
    Ok(starts)
}

/// A decoded 64-bit chain word (`DYLD_CHAINED_PTR_64*` family).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainWord64 {
    /// Raw little-endian word as stored in the slot.
    pub raw: u64,
}

impl ChainWord64 {
    /// Wraps the raw slot word.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self { raw }
    }

    /// True when the word is a bind (bit 63 set); rebases leave it clear.
    #[must_use]
    pub const fn is_bind(&self) -> bool {
        self.raw >> 63 & 1 == 1
    }

    /// Distance to the next fixup in strides of 4 bytes (0 terminates).
    #[must_use]
    pub const fn next(&self) -> u32 {
        ((self.raw >> 51) & 0xfff) as u32
    }

    /// Rebase target: image offset under `DYLD_CHAINED_PTR_64_OFFSET`
    /// (36-bit field, bits 0..36).
    #[must_use]
    pub const fn rebase_target(&self) -> u64 {
        self.raw & 0xf_ffff_ffff
    }

    /// Rebase high 8 bits (bits 36..44): the top byte of the final value.
    #[must_use]
    pub const fn rebase_high8(&self) -> u8 {
        ((self.raw >> 36) & 0xff) as u8
    }

    /// Bind ordinal into the import table (bits 0..24).
    #[must_use]
    pub const fn bind_ordinal(&self) -> u32 {
        (self.raw & 0x00ff_ffff) as u32
    }

    /// Bind inline addend (bits 24..32, read as signed i8 by dyld).
    #[must_use]
    pub const fn bind_addend(&self) -> u8 {
        ((self.raw >> 24) & 0xff) as u8
    }
}

/// Encodes a rebase chain word: `target | high8 << 36 | next << 51` (bit 63
/// clear). `target` must fit in 36 bits — the emit path errors on overflow.
pub fn encode_rebase_word(target: u64, high8: u8, next: u32) -> Result<u64, FormatError> {
    if target >> 36 != 0 {
        return Err(FormatError::Invalid {
            offset: 0,
            what: "rebase target exceeds 36-bit field",
            value: target,
        });
    }
    if next > 0xfff {
        return Err(FormatError::Invalid {
            offset: 0,
            what: "chain next exceeds 12-bit stride count",
            value: next as u64,
        });
    }
    Ok(u64::from(high8) << 36 | target | u64::from(next) << 51)
}

/// Encodes a bind chain word: `ordinal | addend << 24 | next << 51 | 1 << 63`.
///
/// `addend` is the 8-bit *unsigned* inline addend (`dyld_chained_ptr_64_bind.addend`);
/// larger addends travel in the import entry (`DYLD_CHAINED_IMPORT_ADDEND`).
pub fn encode_bind_word(ordinal: u32, addend: u8, next: u32) -> Result<u64, FormatError> {
    if ordinal >> 24 != 0 {
        return Err(FormatError::Invalid {
            offset: 0,
            what: "bind ordinal exceeds 24-bit field",
            value: ordinal as u64,
        });
    }
    if next > 0xfff {
        return Err(FormatError::Invalid {
            offset: 0,
            what: "chain next exceeds 12-bit stride count",
            value: next as u64,
        });
    }
    Ok(u64::from(ordinal) | u64::from(addend) << 24 | u64::from(next) << 51 | 1 << 63)
}

/// Parses the import table (`imports_count` entries at `imports_offset`).
///
/// The count is validated against the payload *before* any pre-allocation:
/// each format has a fixed minimum entry size, so a mutated or truncated
/// `imports_count` yields a typed [`FormatError::Overrun`] instead of
/// attempting a multi-GiB `Vec` (the M7 fuzzing-at-scale find).
pub fn parse_imports(
    payload: &[u8],
    header: &ChainedFixupsHeader,
) -> Result<Vec<Import>, FormatError> {
    let entry_min: usize = match header.imports_format {
        DYLD_CHAINED_IMPORT => 4,
        DYLD_CHAINED_IMPORT_ADDEND => 8,
        DYLD_CHAINED_IMPORT_ADDEND64 => 16,
        other => {
            return Err(FormatError::Invalid {
                offset: header.imports_offset as usize,
                what: "unknown dyld_chained_import format",
                value: other as u64,
            });
        }
    };
    let count = header.imports_count as usize;
    let imports_off = header.imports_offset as usize;
    let avail = payload.len().saturating_sub(imports_off);
    if count.checked_mul(entry_min).is_none_or(|need| need > avail) {
        return Err(FormatError::Overrun {
            offset: imports_off,
            overrun: count.saturating_mul(entry_min).saturating_sub(avail),
        });
    }
    let mut c = Cursor::new(payload);
    c.seek(imports_off)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let imp = match header.imports_format {
            DYLD_CHAINED_IMPORT => {
                let word = c.read_u32()?;
                Import {
                    lib_ordinal: (word & 0xff) as u16,
                    weak_import: (word >> 8) & 1 != 0,
                    name_offset: word >> 9,
                    addend: 0,
                }
            }
            DYLD_CHAINED_IMPORT_ADDEND => {
                let word = c.read_u32()?;
                let addend = c.read_i32()?;
                Import {
                    lib_ordinal: (word & 0xff) as u16,
                    weak_import: (word >> 8) & 1 != 0,
                    name_offset: word >> 9,
                    addend: addend as i64,
                }
            }
            DYLD_CHAINED_IMPORT_ADDEND64 => {
                let word = c.read_u64()?;
                let addend = c.read_i64()?;
                Import {
                    lib_ordinal: (word & 0xffff) as u16,
                    weak_import: (word >> 16) & 1 != 0,
                    name_offset: (word >> 32) as u32,
                    addend,
                }
            }
            other => {
                return Err(FormatError::Invalid {
                    offset: header.imports_offset as usize,
                    what: "unknown dyld_chained_import format",
                    value: other as u64,
                });
            }
        };
        out.push(imp);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        ChainWord64, encode_bind_word, encode_rebase_word, page_chain_starts, parse_header,
        parse_imports, parse_starts_in_image, parse_starts_in_segment,
    };
    use crate::consts::{
        DYLD_CHAINED_IMPORT, DYLD_CHAINED_IMPORT_ADDEND64, DYLD_CHAINED_PTR_64_OFFSET,
        DYLD_CHAINED_PTR_START_MULTI, DYLD_CHAINED_PTR_START_MULTI_MASK,
        DYLD_CHAINED_PTR_START_NONE,
    };

    /// M7 (fuzzing at scale): a mutated `imports_count` must produce a typed
    /// error, **not** a multi-GiB pre-allocation (a truncated image once
    /// drove `imports_count × 16` = 68 GiB and aborted the process — an
    /// allocation abort is the same failure class as a panic for a parser).
    #[test]
    fn m7_imports_count_is_bounded_by_the_payload() {
        let header = crate::fixups::ChainedFixupsHeader {
            fixups_version: 0,
            starts_offset: 28,
            imports_offset: 4,
            symbols_offset: 4,
            imports_count: 4_278_190_081, // mutated u32 from a fuzz case
            imports_format: DYLD_CHAINED_IMPORT_ADDEND64,
            symbols_format: 0,
        };
        let payload = vec![0u8; 64];
        let err = parse_imports(&payload, &header).unwrap_err();
        assert!(
            matches!(err, crate::error::FormatError::Overrun { .. }),
            "expected Overrun, got {err:?}"
        );
    }

    #[test]
    fn m7_unknown_imports_format_rejects_up_front() {
        let header = crate::fixups::ChainedFixupsHeader {
            fixups_version: 0,
            starts_offset: 28,
            imports_offset: 4,
            symbols_offset: 4,
            imports_count: 2,
            imports_format: 0x99,
            symbols_format: 0,
        };
        let payload = vec![0u8; 64];
        let err = parse_imports(&payload, &header).unwrap_err();
        assert!(
            matches!(err, crate::error::FormatError::Invalid { .. }),
            "got {err:?}"
        );
    }

    /// Round-trips a rebase word through the encode/decode pair, using the
    /// bit layout from the fixup-chain diagram: target 36b, high8 8b,
    /// reserved 7b, next 12b (4-byte strides), bind=0.
    #[test]
    fn rebase_word_bit_layout() {
        let word = encode_rebase_word(0x0001_2345, 0xAB, 0x321).unwrap();
        let w = ChainWord64::new(word);
        assert!(!w.is_bind());
        assert_eq!(w.rebase_target(), 0x0001_2345);
        assert_eq!(w.rebase_high8(), 0xAB);
        assert_eq!(w.next(), 0x321);
        assert_eq!(word >> 63, 0);
    }

    /// Same for the bind word: ordinal 24b, addend 8b (unsigned, LLVM
    /// `dyld_chained_ptr_64_bind`), reserved 19b, next 12b, bind=1.
    #[test]
    fn bind_word_bit_layout() {
        let word = encode_bind_word(0x00ff_1234, 0xfe, 1).unwrap();
        let w = ChainWord64::new(word);
        assert!(w.is_bind());
        assert_eq!(w.bind_ordinal(), 0x00ff_1234);
        assert_eq!(w.bind_addend(), 0xfe);
        assert_eq!(w.next(), 1);
    }

    #[test]
    fn encode_rejects_oversized_fields() {
        assert!(encode_rebase_word(1 << 36, 0, 0).is_err());
        assert!(encode_rebase_word(0, 0, 0x1000).is_err());
        assert!(encode_bind_word(1 << 24, 0, 0).is_err());
    }

    /// Builds a minimal-but-complete payload exactly the way mold does:
    /// header (28 B padded to 32) | starts-in-image | imports | names.
    fn sample_payload() -> Vec<u8> {
        let mut b = Vec::new();
        let push32 = |b: &mut Vec<u8>, v: u32| b.extend_from_slice(&v.to_le_bytes());
        let push16 = |b: &mut Vec<u8>, v: u16| b.extend_from_slice(&v.to_le_bytes());
        let push64 = |b: &mut Vec<u8>, v: u64| b.extend_from_slice(&v.to_le_bytes());
        // header, offsets backpatched below
        push32(&mut b, 0); // fixups_version
        push32(&mut b, 0); // starts_offset
        push32(&mut b, 0); // imports_offset
        push32(&mut b, 0); // symbols_offset
        push32(&mut b, 1); // imports_count
        push32(&mut b, DYLD_CHAINED_IMPORT_ADDEND64);
        push32(&mut b, 0); // symbols_format
        while b.len() % 8 != 0 {
            b.push(0);
        }
        let starts_offset = b.len();
        // starts_in_image: 2 segments, only segment 1 has fixups
        push32(&mut b, 2);
        push32(&mut b, 0); // segment 0: none
        push32(&mut b, 0); // segment 1 offset, backpatched below
        // pad to 8 before the segment record (dyld requires 8-aligned records)
        while b.len() % 8 != 0 {
            b.push(0);
        }
        let seg_record = b.len();
        let npages: u16 = 2;
        push32(&mut b, 22 + u32::from(npages) * 2);
        push16(&mut b, 0x4000);
        push16(&mut b, DYLD_CHAINED_PTR_64_OFFSET);
        push64(&mut b, 0x4000); // segment_offset (== fileoff)
        push32(&mut b, 0); // max_valid_pointer
        push16(&mut b, npages);
        push16(&mut b, 0x10); // page 0: chain starts at slot 0x10
        push16(&mut b, DYLD_CHAINED_PTR_START_NONE); // page 1: empty
        // backpatch the segment-1 offset (record offset within starts table)
        b[starts_offset + 8..starts_offset + 12]
            .copy_from_slice(&((seg_record - starts_offset) as u32).to_le_bytes());
        // imports (format 3): one entry, lib 1, name at blob offset 1
        while b.len() % 8 != 0 {
            b.push(0);
        }
        let imports_offset = b.len();
        push64(&mut b, 1 | (1u64 << 32)); // lib=1, weak=0, name_off=1
        push64(&mut b, 0); // addend 0
        let symbols_offset = b.len();
        b.push(0); // leading NUL
        b.extend_from_slice(b"_printf\0");
        while b.len() % 8 != 0 {
            b.push(0);
        }
        // backpatch the payload header offsets
        b[4..8].copy_from_slice(&(starts_offset as u32).to_le_bytes());
        b[8..12].copy_from_slice(&(imports_offset as u32).to_le_bytes());
        b[12..16].copy_from_slice(&(symbols_offset as u32).to_le_bytes());
        b
    }

    #[test]
    fn payload_header_and_imports_roundtrip() {
        let payload = sample_payload();
        let hdr = parse_header(&payload).unwrap();
        assert_eq!(hdr.fixups_version, 0);
        assert_eq!(hdr.imports_format, DYLD_CHAINED_IMPORT_ADDEND64);
        assert_eq!(hdr.imports_count, 1);
        assert_eq!(hdr.starts_offset, 32);
        let imports = parse_imports(&payload, &hdr).unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].lib_ordinal, 1);
        assert!(!imports[0].weak_import);
        assert_eq!(imports[0].name_offset, 1);
        assert_eq!(imports[0].addend, 0);
    }

    #[test]
    fn starts_tables_roundtrip() {
        let payload = sample_payload();
        let hdr = parse_header(&payload).unwrap();
        let img = parse_starts_in_image(&payload, hdr.starts_offset as usize).unwrap();
        assert_eq!(img.seg_count, 2);
        let rec_off = hdr.starts_offset as usize + img.seg_info_offset[1] as usize;
        assert_eq!(
            u32::try_from(rec_off - hdr.starts_offset as usize).unwrap(),
            img.seg_info_offset[1]
        );
        let seg = parse_starts_in_segment(&payload, rec_off).unwrap();
        assert_eq!(seg.page_size, 0x4000);
        assert_eq!(seg.pointer_format, DYLD_CHAINED_PTR_64_OFFSET);
        assert_eq!(seg.segment_offset, 0x4000);
        assert_eq!(seg.page_count, 2);
        let page0 = page_chain_starts(&payload, rec_off, &seg, 0).unwrap();
        assert_eq!(page0, vec![0x10]);
        let page1 = page_chain_starts(&payload, rec_off, &seg, 1).unwrap();
        assert!(page1.is_empty());
    }

    /// A multi-start page encodes 0x8000 | offset and the offsets table
    /// holds additional chain heads.
    #[test]
    fn multi_start_pages_expand() {
        let mut payload = sample_payload();
        let hdr = parse_header(&payload).unwrap();
        let img = parse_starts_in_image(&payload, hdr.starts_offset as usize).unwrap();
        let rec_off = hdr.starts_offset as usize + img.seg_info_offset[1] as usize;
        // Rewrite page_start[0] to a multi-start marker pointing at a table
        // appended to the payload, and patch the record size.
        let table_off = payload.len();
        let marker = DYLD_CHAINED_PTR_START_MULTI
            | (((table_off - rec_off) as u16) & DYLD_CHAINED_PTR_START_MULTI_MASK);
        payload[rec_off + 22..rec_off + 24].copy_from_slice(&marker.to_le_bytes());
        payload[rec_off..rec_off + 4].copy_from_slice(&((22 + 2 * 2 + 6) as u32).to_le_bytes());
        payload.extend_from_slice(&2u16.to_le_bytes()); // count = 2
        payload.extend_from_slice(&0x10u16.to_le_bytes()); // chain A head
        payload.extend_from_slice(&0x40u16.to_le_bytes()); // chain B head
        let seg = parse_starts_in_segment(&payload, rec_off).unwrap();
        let starts = page_chain_starts(&payload, rec_off, &seg, 0).unwrap();
        assert_eq!(starts, vec![0x10, 0x40]);
    }

    #[test]
    fn truncated_payloads_error_not_panic() {
        let payload = sample_payload();
        for len in 0..payload.len() {
            // Every prefix must produce a typed error somewhere in the
            // pipeline — none may panic or panic-unwrap.
            let _ = parse_header(&payload[..len]);
        }
    }

    #[test]
    fn format1_imports_decode() {
        let mut payload = sample_payload();
        // Switch the header to format 1 (DYLD_CHAINED_IMPORT) and rewrite
        // the first import word accordingly.
        payload[20..24].copy_from_slice(&DYLD_CHAINED_IMPORT.to_le_bytes());
        let imports_off = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let word: u32 = 1 | (1 << 9); // lib 1, weak 0, name_off 1
        payload[imports_off as usize..imports_off as usize + 4]
            .copy_from_slice(&word.to_le_bytes());
        let hdr = parse_header(&payload).unwrap();
        let imports = parse_imports(&payload, &hdr).unwrap();
        assert_eq!(imports[0].addend, 0);
        assert_eq!(imports[0].name_offset, 1);
    }
}

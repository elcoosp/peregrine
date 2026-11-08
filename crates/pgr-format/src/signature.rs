//! Code-signature structures: `SuperBlob`, `BlobIndex` and `CodeDirectory`.
//!
//! Signature structures are **big-endian** (TDD §9); everything else in a
//! Mach-O file is little-endian. The verifier recomputes SHA-256 page hashes
//! from this module's parsed fields (`pgr-verify::signature`), so the parse
//! here only validates structure and bounds — never hash content.

use crate::consts::{CSMAGIC_CODEDIRECTORY, CSMAGIC_EMBEDDED_SIGNATURE};
use crate::cursor::Cursor;
use crate::error::FormatError;

/// One `SuperBlob` index entry (8 bytes, big-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobIndex {
    /// `CSSLOT_*` slot type.
    pub slot_type: u32,
    /// Offset of the blob within the `SuperBlob`.
    pub offset: u32,
}

/// A parsed `SuperBlob` over borrowed bytes.
#[derive(Debug)]
pub struct SuperBlob<'a> {
    bytes: &'a [u8],
    count: u32,
}

impl<'a> SuperBlob<'a> {
    /// Parses the `SuperBlob` head at `bytes[0..12]` and validates the magic.
    ///
    /// # Errors
    /// [`FormatError`] when the input structure is malformed or truncated.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FormatError> {
        if bytes.len() < 12 {
            return Err(FormatError::Truncated {
                offset: 0,
                need: 12,
                have: bytes.len(),
            });
        }
        let mut c = Cursor::new(bytes);
        let magic = c.read_u32be()?;
        let length = c.read_u32be()?;
        let count = c.read_u32be()?;
        if magic != CSMAGIC_EMBEDDED_SIGNATURE {
            return Err(FormatError::BadMagic { offset: 0, magic });
        }
        // count * 8 index entries must fit within the declared length.
        let index_end = 12 + count as usize * 8;
        if index_end > bytes.len() {
            return Err(FormatError::Overrun {
                offset: 12,
                overrun: index_end - bytes.len(),
            });
        }
        if length as usize > bytes.len() {
            return Err(FormatError::Overrun {
                offset: 0,
                overrun: length as usize - bytes.len(),
            });
        }
        Ok(Self {
            bytes: &bytes[..length as usize],
            count,
        })
    }

    /// Number of indexed blobs.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// The index entry `i`.
    ///
    /// # Errors
    /// [`FormatError`] when the input structure is malformed or truncated.
    pub fn index(&self, i: u32) -> Result<BlobIndex, FormatError> {
        if i >= self.count {
            return Err(FormatError::Invalid {
                offset: 12 + i as usize * 8,
                what: "blob index out of range",
                value: u64::from(i),
            });
        }
        let mut c = Cursor::new(self.bytes);
        c.seek(12 + i as usize * 8)?;
        Ok(BlobIndex {
            slot_type: c.read_u32be()?,
            offset: c.read_u32be()?,
        })
    }

    /// Finds the first blob occupying `slot_type`.
    ///
    /// # Errors
    /// [`FormatError`] when the input structure is malformed or truncated.
    pub fn blob_for_slot(&self, slot_type: u32) -> Result<Option<&'a [u8]>, FormatError> {
        for i in 0..self.count {
            let idx = self.index(i)?;
            if idx.slot_type == slot_type {
                return Ok(Some(self.blob_at(idx.offset)?));
            }
        }
        Ok(None)
    }

    /// The bytes of the blob at `offset`, bounded by the blob's own length
    /// header and the `SuperBlob` end.
    fn blob_at(&self, offset: u32) -> Result<&'a [u8], FormatError> {
        let start = offset as usize;
        if start < 12 || start + 4 > self.bytes.len() {
            return Err(FormatError::Invalid {
                offset: start,
                what: "blob offset outside SuperBlob",
                value: u64::from(offset),
            });
        }
        let mut c = Cursor::new(self.bytes);
        c.seek(start)?;
        let magic = c.read_u32be()?;
        let length = c.read_u32be()?;
        if magic == 0 {
            return Err(FormatError::Invalid {
                offset: start,
                what: "blob magic is zero",
                value: 0,
            });
        }
        let end = start + length as usize;
        if end > self.bytes.len() {
            return Err(FormatError::Overrun {
                offset: start,
                overrun: end - self.bytes.len(),
            });
        }
        Ok(&self.bytes[start..end])
    }
}

/// A parsed `CodeDirectory` (v0x20400 layout; optional tail fields are `None`
/// for older versions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeDirectory {
    /// Format version (0x20100 ... 0x20400+).
    pub version: u32,
    /// `CS_*` flags (adhoc, linker-signed, ...).
    pub flags: u32,
    /// Offset of the code-slot hash array, counted in 4-byte units.
    pub hash_offset: u32,
    /// Offset of the identifier string, counted in 4-byte units.
    pub ident_offset: u32,
    /// Number of special slots preceding the code slots (negative indices).
    pub n_special_slots: u32,
    /// Number of 4 KiB code-slot hashes.
    pub n_code_slots: u32,
    /// Number of file bytes covered by the code hashes.
    pub code_limit: u32,
    /// Hash size in bytes (32 for SHA-256).
    pub hash_size: u8,
    /// `CS_HASHTYPE_*` value (2 for SHA-256).
    pub hash_type: u8,
    /// Platform restriction (0 = any).
    pub platform: u8,
    /// Page size exponent (log2); 12 = 4 KiB code pages.
    pub page_size_log2: u8,
    /// 64-bit code limit (`None` below version 0x20300).
    pub code_limit64: Option<u64>,
    /// Exec segment start (`None` below version 0x20400).
    pub exec_seg_base: Option<u64>,
    /// Exec segment end (`None` below version 0x20400).
    pub exec_seg_limit: Option<u64>,
    /// Exec segment flags (`CS_EXECSEG_*`, `None` below 0x20400).
    pub exec_seg_flags: Option<u64>,
}

impl CodeDirectory {
    /// Parses a `CodeDirectory` from blob bytes (big-endian fields).
    ///
    /// # Errors
    /// [`FormatError`] when the input structure is malformed or truncated.
    pub fn parse(blob: &[u8]) -> Result<Self, FormatError> {
        let mut c = Cursor::new(blob);
        let magic = c.read_u32be()?;
        if magic != CSMAGIC_CODEDIRECTORY {
            return Err(FormatError::BadMagic { offset: 0, magic });
        }
        let length = c.read_u32be()?;
        if length as usize > blob.len() {
            return Err(FormatError::Overrun {
                offset: 0,
                overrun: length as usize - blob.len(),
            });
        }
        let version = c.read_u32be()?;
        let flags = c.read_u32be()?;
        let hash_offset = c.read_u32be()?;
        let ident_offset = c.read_u32be()?;
        let n_special_slots = c.read_u32be()?;
        let n_code_slots = c.read_u32be()?;
        let code_limit = c.read_u32be()?;
        let hash_size = c.read_u8()?;
        let hash_type = c.read_u8()?;
        let platform = c.read_u8()?;
        let page_size_log2 = c.read_u8()?;
        let _spare2 = c.read_u32()?;

        // Optional tail, per version.
        let has_scatter = version >= crate::consts::CS_CODEDIRECTORY_VERSION_SCATTER;
        let has_rest = version >= crate::consts::CS_CODEDIRECTORY_VERSION_REST;
        let has_execseg = version >= crate::consts::CS_CODEDIRECTORY_VERSION_EXECSEG;

        let mut scatter_offset = 0u32;
        let mut team_offset = 0u32;
        let mut code_limit64 = None;
        let mut exec_seg = None;

        if has_scatter {
            scatter_offset = c.read_u32be()?;
            team_offset = c.read_u32be()?;
            let _spare3 = c.read_u32be()?;
        }
        if has_rest {
            code_limit64 = Some(c.read_u64be()?);
        }
        if has_execseg {
            let base = c.read_u64be()?;
            let limit = c.read_u64be()?;
            let segflags = c.read_u64be()?;
            exec_seg = Some((base, limit, segflags));
        }
        let _ = (scatter_offset, team_offset);

        Ok(Self {
            version,
            flags,
            hash_offset,
            ident_offset,
            n_special_slots,
            n_code_slots,
            code_limit,
            hash_size,
            hash_type,
            platform,
            page_size_log2,
            code_limit64,
            exec_seg_base: exec_seg.map(|(b, _, _)| b),
            exec_seg_limit: exec_seg.map(|(_, l, _)| l),
            exec_seg_flags: exec_seg.map(|(_, _, f)| f),
        })
    }

    /// The identifier string (NUL-terminated at `ident_offset * 4`).
    ///
    /// # Errors
    /// [`FormatError`] when the input structure is malformed or truncated.
    pub fn identifier<'a>(&self, blob: &'a [u8]) -> Result<&'a [u8], FormatError> {
        let start = self.ident_offset as usize * 4;
        if start == 0 || start >= blob.len() {
            return Err(FormatError::Invalid {
                offset: start,
                what: "CodeDirectory identifier offset outside blob",
                value: u64::from(self.ident_offset),
            });
        }
        let mut c = Cursor::new(blob);
        c.seek(start)?;
        let s = c.read_cstr()?;
        Ok(s)
    }

    /// The code-slot hash slice: `n_code_slots * hash_size` bytes at
    /// `hash_offset * 4`, bounded by the blob.
    ///
    /// # Errors
    /// [`FormatError`] when the input structure is malformed or truncated.
    pub fn code_hashes<'a>(&self, blob: &'a [u8]) -> Result<&'a [u8], FormatError> {
        let start = self.hash_offset as usize * 4;
        let len = self
            .n_code_slots
            .checked_mul(u32::from(self.hash_size))
            .ok_or(FormatError::Invalid {
                offset: start,
                what: "code hash array size overflow",
                value: u64::from(self.n_code_slots),
            })? as usize;
        let end = start.checked_add(len).ok_or(FormatError::Invalid {
            offset: start,
            what: "code hash array end overflow",
            value: len as u64,
        })?;
        if end > blob.len() {
            return Err(FormatError::Overrun {
                offset: start,
                overrun: end - blob.len(),
            });
        }
        Ok(&blob[start..end])
    }

    /// The hash of special slot `index` (1-based negative index: -1 is the
    /// Info.plist slot, -2 requirements, ...). `None` when out of range.
    #[must_use]
    pub fn special_slot<'a>(&self, blob: &'a [u8], index: u32) -> Option<&'a [u8]> {
        if index == 0 || index > self.n_special_slots {
            return None;
        }
        let end = self.hash_offset as usize * 4;
        let size = self.hash_size as usize;
        let start = end.checked_sub(index as usize * size)?;
        let stop = end.checked_sub((index - 1) as usize * size)?;
        if stop > end || end > blob.len() || start >= stop {
            return None;
        }
        blob.get(start..stop)
    }
}

#[cfg(test)]
mod tests {
    use super::{CodeDirectory, SuperBlob};
    use crate::consts::{
        CS_ADHOC, CS_CODEDIRECTORY_VERSION_EXECSEG, CS_HASHTYPE_SHA256, CS_PAGE_SIZE_LOG2,
        CS_SHA256_LEN, CSMAGIC_CODEDIRECTORY, CSMAGIC_EMBEDDED_SIGNATURE, CSSLOT_CODEDIRECTORY,
    };

    const IDENT: &[u8] = b"peregrine-fixture";

    /// Builds a valid `SuperBlob`: one code directory over `nblocks` fake
    /// page hashes, big-endian fields (fixtures-side encoder logic).
    pub fn build_superblob(code_limit: u32, hashes: &[u8]) -> Vec<u8> {
        let nblocks = hashes.len() / CS_SHA256_LEN as usize;
        let ident_padded = (IDENT.len() + 1).div_ceil(4) * 4;
        let dir_len = 88 + ident_padded + hashes.len();
        let blob_len = 12 + 8 + dir_len;
        let be32 = |v: u32| v.to_be_bytes();
        let mut cd = Vec::with_capacity(dir_len);
        cd.extend_from_slice(&be32(CSMAGIC_CODEDIRECTORY));
        cd.extend_from_slice(&be32(dir_len as u32));
        cd.extend_from_slice(&be32(CS_CODEDIRECTORY_VERSION_EXECSEG));
        cd.extend_from_slice(&be32(CS_ADHOC));
        let hash_off = (88 + ident_padded) / 4;
        cd.extend_from_slice(&be32(hash_off as u32));
        cd.extend_from_slice(&be32(22)); // ident_offset = 88 / 4
        cd.extend_from_slice(&be32(0)); // n_special_slots
        cd.extend_from_slice(&be32(nblocks as u32));
        cd.extend_from_slice(&be32(code_limit));
        cd.push(CS_SHA256_LEN as u8);
        cd.push(CS_HASHTYPE_SHA256);
        cd.push(0); // platform
        cd.push(CS_PAGE_SIZE_LOG2);
        cd.extend_from_slice(&be32(0)); // spare2
        cd.extend_from_slice(&be32(0)); // scatter
        cd.extend_from_slice(&be32(0)); // team
        cd.extend_from_slice(&be32(0)); // spare3
        cd.extend_from_slice(&u64::from(code_limit).to_be_bytes());
        cd.extend_from_slice(&0u64.to_be_bytes()); // execSegBase
        cd.extend_from_slice(&0x4000u64.to_be_bytes()); // execSegLimit
        cd.extend_from_slice(&1u64.to_be_bytes()); // execSegFlags = MAIN_BINARY
        assert_eq!(cd.len(), 88);
        cd.extend_from_slice(IDENT);
        cd.resize(88 + ident_padded, 0);
        cd.extend_from_slice(hashes);
        assert_eq!(cd.len(), dir_len);

        let mut sb = Vec::with_capacity(blob_len);
        sb.extend_from_slice(&be32(CSMAGIC_EMBEDDED_SIGNATURE));
        sb.extend_from_slice(&be32(blob_len as u32));
        sb.extend_from_slice(&be32(1)); // count
        sb.extend_from_slice(&be32(CSSLOT_CODEDIRECTORY));
        sb.extend_from_slice(&be32(20)); // blob offset
        sb.extend_from_slice(&cd);
        while sb.len() % 8 != 0 {
            sb.push(0);
        }
        sb
    }

    #[test]
    fn superblob_and_directory_roundtrip() {
        let hashes = vec![0xAAu8; 32 * 3];
        let sb_bytes = build_superblob(3 * 4096, &hashes);
        let sb = SuperBlob::parse(&sb_bytes).unwrap();
        assert_eq!(sb.count(), 1);
        let blob = sb.blob_for_slot(CSSLOT_CODEDIRECTORY).unwrap().unwrap();
        let cd = CodeDirectory::parse(blob).unwrap();
        assert_eq!(cd.version, CS_CODEDIRECTORY_VERSION_EXECSEG);
        assert_eq!(cd.flags, CS_ADHOC);
        assert_eq!(cd.hash_type, CS_HASHTYPE_SHA256);
        assert_eq!(cd.page_size_log2, CS_PAGE_SIZE_LOG2);
        assert_eq!(cd.n_code_slots, 3);
        assert_eq!(cd.code_limit, 3 * 4096);
        assert_eq!(cd.code_limit64, Some(3 * 4096));
        assert_eq!(cd.exec_seg_flags, Some(1));
        assert_eq!(cd.identifier(blob).unwrap(), IDENT);
        let parsed_hashes = cd.code_hashes(blob).unwrap();
        assert_eq!(parsed_hashes, &hashes[..]);
    }

    #[test]
    fn special_slots_slice_correctly() {
        // Two special slots then two code slots.
        let mut cd_bytes = Vec::new();
        let special = [0x11u8; 32 * 2];
        let code = [0x22u8; 32 * 2];
        let ident_padded = 4;
        let dir_len = 88 + ident_padded + special.len() + code.len();
        let be32 = |v: u32| v.to_be_bytes();
        cd_bytes.extend_from_slice(&be32(CSMAGIC_CODEDIRECTORY));
        cd_bytes.extend_from_slice(&be32(dir_len as u32));
        cd_bytes.extend_from_slice(&be32(CS_CODEDIRECTORY_VERSION_EXECSEG));
        cd_bytes.extend_from_slice(&be32(0));
        let hash_off = (88 + ident_padded + special.len()) / 4;
        cd_bytes.extend_from_slice(&be32(hash_off as u32)); // hashOffset
        cd_bytes.extend_from_slice(&be32(22)); // identOffset
        cd_bytes.extend_from_slice(&be32(2)); // nSpecialSlots
        cd_bytes.extend_from_slice(&be32(2)); // nCodeSlots
        cd_bytes.extend_from_slice(&be32(8192));
        cd_bytes.push(32);
        cd_bytes.push(CS_HASHTYPE_SHA256);
        cd_bytes.push(0);
        cd_bytes.push(CS_PAGE_SIZE_LOG2);
        cd_bytes.extend_from_slice(&be32(0));
        cd_bytes.extend_from_slice(&be32(0));
        cd_bytes.extend_from_slice(&be32(0));
        cd_bytes.extend_from_slice(&be32(0));
        cd_bytes.extend_from_slice(&8192u64.to_be_bytes());
        cd_bytes.extend_from_slice(&0u64.to_be_bytes());
        cd_bytes.extend_from_slice(&0u64.to_be_bytes());
        cd_bytes.extend_from_slice(&0u64.to_be_bytes());
        cd_bytes.extend_from_slice(b"id\0\0");
        cd_bytes.extend_from_slice(&special);
        cd_bytes.extend_from_slice(&code);
        let cd = CodeDirectory::parse(&cd_bytes).unwrap();
        // Slot -2 (Info.plist) comes first, then -1 (requirements).
        assert_eq!(cd.special_slot(&cd_bytes, 1).unwrap(), &[0x11u8; 32]);
        assert_eq!(cd.special_slot(&cd_bytes, 2).unwrap(), &[0x11u8; 32]);
        assert!(cd.special_slot(&cd_bytes, 3).is_none());
        let code_hashes = cd.code_hashes(&cd_bytes).unwrap();
        assert_eq!(code_hashes[0], 0x22);
        assert_eq!(code_hashes.len(), 64);
    }

    #[test]
    fn rejects_bad_magic_and_overrun() {
        let hashes = vec![0u8; 32];
        let sb = build_superblob(4096, &hashes);
        // Corrupt the SuperBlob magic.
        let mut bad = sb.clone();
        bad[0] = 0xde;
        assert!(SuperBlob::parse(&bad).is_err());
        // Truncated superblob.
        assert!(SuperBlob::parse(&sb[..8]).is_err());
        // Directory length beyond blob: patch CD length field at offset 24
        // (20 blob start + 4). The SuperBlob still parses; locating the
        // directory fails with an Overrun.
        let mut bad2 = sb.clone();
        let cd_len = u32::from_be_bytes([bad2[24], bad2[25], bad2[26], bad2[27]]);
        bad2[24..28].copy_from_slice(&(cd_len + 4096).to_be_bytes());
        let sb2 = SuperBlob::parse(&bad2).unwrap();
        assert!(sb2.blob_for_slot(CSSLOT_CODEDIRECTORY).is_err());
    }
}

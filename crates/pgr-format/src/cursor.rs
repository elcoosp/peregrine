//! Bounds-checked little-endian cursor over mmap'd input bytes.
//!
//! This is the only sanctioned way `pgr-format` code walks raw bytes: every
//! read is bounds-checked and returns a typed error instead of panicking, and
//! the cursor never allocates. Pass 1-style hot loops keep a single cursor and
//! re-`seek` to table starts rather than building per-table cursors.

use crate::error::FormatError;

/// A checked read position over a byte slice.
///
/// Mach-O is little-endian on arm64; the cursor reads little-endian only.
#[derive(Debug, Clone, Copy)]
pub struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Wraps a byte slice; the cursor starts at offset 0.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Current read offset.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Bytes left between the cursor and the end of the input.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    /// True when the cursor sits at the end of the input.
    #[must_use]
    pub const fn at_end(&self) -> bool {
        self.pos == self.bytes.len()
    }

    /// Moves the cursor to `pos`, which must be within the input.
    pub fn seek(&mut self, pos: usize) -> Result<(), FormatError> {
        if pos > self.bytes.len() {
            return Err(FormatError::Truncated {
                offset: self.pos,
                need: pos - self.pos,
                have: 0,
            });
        }
        self.pos = pos;
        Ok(())
    }

    /// Advances by `n` checked bytes.
    pub fn skip(&mut self, n: usize) -> Result<(), FormatError> {
        let new_pos = self.pos.checked_add(n).ok_or(FormatError::Invalid {
            offset: self.pos,
            what: "cursor advance overflow",
            value: n as u64,
        })?;
        self.seek(new_pos)
    }

    /// Reads one `u8`.
    pub fn read_u8(&mut self) -> Result<u8, FormatError> {
        let here = self.pos;
        let b = *self.bytes.get(self.pos).ok_or(FormatError::Truncated {
            offset: here,
            need: 1,
            have: self.remaining(),
        })?;
        self.pos += 1;
        Ok(b)
    }

    /// Reads a little-endian `u16`.
    pub fn read_u16(&mut self) -> Result<u16, FormatError> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Reads a little-endian `u32`.
    pub fn read_u32(&mut self) -> Result<u32, FormatError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a big-endian `u32` (code-signature structures are big-endian).
    pub fn read_u32be(&mut self) -> Result<u32, FormatError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a big-endian `u64` (code-signature structures are big-endian).
    pub fn read_u64be(&mut self) -> Result<u64, FormatError> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Reads a little-endian `u64`.
    pub fn read_u64(&mut self) -> Result<u64, FormatError> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Reads a little-endian `i8`.
    pub fn read_i8(&mut self) -> Result<i8, FormatError> {
        Ok(self.read_u8()? as i8)
    }

    /// Reads a little-endian `i32`.
    pub fn read_i32(&mut self) -> Result<i32, FormatError> {
        Ok(self.read_u32()? as i32)
    }

    /// Reads a little-endian `i64`.
    pub fn read_i64(&mut self) -> Result<i64, FormatError> {
        Ok(self.read_u64()? as i64)
    }

    /// Reads a checked slice of `len` bytes.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], FormatError> {
        let here = self.pos;
        let end = here.checked_add(len).ok_or(FormatError::Invalid {
            offset: here,
            what: "read length overflow",
            value: len as u64,
        })?;
        if end > self.bytes.len() {
            return Err(FormatError::Truncated {
                offset: here,
                need: len,
                have: self.bytes.len() - here,
            });
        }
        self.pos = end;
        Ok(&self.bytes[here..end])
    }

    /// Reads a fixed-width name field (segment/section names) and trims the
    /// trailing NUL padding, returning the name bytes.
    pub fn read_name16(&mut self) -> Result<&'a [u8], FormatError> {
        let raw = self.read_bytes(16)?;
        let len = raw.iter().position(|&b| b == 0).unwrap_or(16);
        Ok(&raw[..len])
    }

    /// Reads a NUL-terminated string starting at the cursor.
    pub fn read_cstr(&mut self) -> Result<&'a [u8], FormatError> {
        let start = self.pos;
        let rest = &self.bytes[start..];
        let len = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(FormatError::Invalid {
                offset: start,
                what: "unterminated string",
                value: 0,
            })?;
        self.pos = start + len + 1;
        Ok(&rest[..len])
    }
}

/// Reads a `bytemuck::Pod` structure at an absolute offset without moving a
/// cursor, checking bounds only (alignment is not required: the bytes are
/// copied field-wise, which keeps malformed inputs panic-free).
pub fn pod_read_unaligned_at<T: bytemuck::Pod>(
    bytes: &[u8],
    offset: usize,
) -> Result<T, FormatError> {
    let size = core::mem::size_of::<T>();
    let end = offset.checked_add(size).ok_or(FormatError::Invalid {
        offset,
        what: "struct offset overflow",
        value: size as u64,
    })?;
    if end > bytes.len() {
        return Err(FormatError::Overrun {
            offset,
            overrun: end - bytes.len(),
        });
    }
    Ok(bytemuck::pod_read_unaligned(&bytes[offset..end]))
}

#[cfg(test)]
mod tests {
    use super::{Cursor, pod_read_unaligned_at};
    use crate::error::FormatError;

    #[test]
    fn reads_little_endian_primitives() {
        let mut c = Cursor::new(&[
            0x34, 0x12, // u16 0x1234
            0x78, 0x56, 0xEF, 0xCD, // u32 0xCDEF_5678
            0x90, 0xAB, // u16 0xAB90
        ]);
        assert_eq!(c.read_u16().unwrap(), 0x1234);
        assert_eq!(c.read_u32().unwrap(), 0xCDEF_5678);
        assert_eq!(c.read_u16().unwrap(), 0xAB90);
    }

    #[test]
    fn truncated_reads_error_not_panic() {
        for len in 0..8usize {
            let buf = vec![0u8; len];
            let mut c = Cursor::new(&buf);
            let err = c.read_u64().unwrap_err();
            assert!(matches!(err, FormatError::Truncated { .. }));
            assert_eq!(err.offset(), 0);
        }
    }

    #[test]
    fn seek_beyond_end_errors() {
        let mut c = Cursor::new(&[1u8, 2, 3]);
        assert!(c.seek(3).is_ok());
        assert!(c.at_end());
        assert!(c.seek(4).is_err());
    }

    #[test]
    fn name16_trims_nul_padding() {
        let mut c = Cursor::new(b"__text\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(c.read_name16().unwrap(), b"__text");
    }

    #[test]
    fn name16_without_nul_is_full_width() {
        let mut c = Cursor::new(b"ABCDEFGHIJKLMNOP");
        assert_eq!(c.read_name16().unwrap(), b"ABCDEFGHIJKLMNOP");
    }

    #[test]
    fn cstr_requires_terminator() {
        let mut c = Cursor::new(b"abc");
        assert!(c.read_cstr().is_err());
        let mut c2 = Cursor::new(b"abc\0def\0");
        assert_eq!(c2.read_cstr().unwrap(), b"abc");
        assert_eq!(c2.position(), 4);
        assert_eq!(c2.read_cstr().unwrap(), b"def");
    }

    #[test]
    fn pod_at_checks_bounds() {
        #[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
        #[repr(C)]
        struct Two {
            a: u32,
            b: u32,
        }
        let bytes = [1u8, 0, 0, 0, 2, 0, 0, 0, 3, 0];
        let v: Two = pod_read_unaligned_at(&bytes, 0).unwrap();
        assert_eq!((v.a, v.b), (1, 2));
        // Unaligned but fully in-bounds reads are fine (the copy is field-wise).
        let v2: Two = pod_read_unaligned_at(&bytes, 1).unwrap();
        assert_eq!(v2.a, u32::from_le_bytes([0, 0, 0, 2]));
        assert!(pod_read_unaligned_at::<Two>(&bytes, 3).is_err());
        assert!(pod_read_unaligned_at::<Two>(&bytes, 9).is_err());
    }

    #[test]
    fn skip_detects_overflow() {
        let mut c = Cursor::new(&[0u8; 4]);
        assert!(c.skip(usize::MAX).is_err());
    }
}

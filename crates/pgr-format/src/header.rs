//! `mach_header_64` and its immediate fields.

use crate::consts::{MH_CIGAM_64, MH_MAGIC_64};
use crate::cursor::Cursor;
use crate::error::FormatError;

/// The 32-byte `mach_header_64` (TDD §3.1).
///
/// Immediately followed by `ncmds` load commands occupying `sizeofcmds`
/// bytes; everything else in the file is reached through load commands.
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct MachHeader64 {
    /// `MH_MAGIC_64` for little-endian arm64 images.
    pub magic: u32,
    /// `CPU_TYPE_ARM64` for Peregrine's target.
    pub cputype: u32,
    /// CPU subtype (`CPU_SUBTYPE_ARM64_ALL` typically).
    pub cpusubtype: u32,
    /// One of the `MH_*` file types (object, execute, dylib, bundle...).
    pub filetype: u32,
    /// Number of load commands following the header.
    pub ncmds: u32,
    /// Total size in bytes of all load commands.
    pub sizeofcmds: u32,
    /// `MH_*` flag bits.
    pub flags: u32,
    /// Reserved, must be zero.
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<MachHeader64>() == 32);

impl MachHeader64 {
    /// Size of the header in bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Parses and validates the header from the start of `bytes`.
    ///
    /// Only little-endian (`MH_MAGIC_64`) images are supported: arm64
    /// Mach-O is little-endian, and big-endian slices are rejected with
    /// [`FormatError::BadMagic`] so downstream code can never misparse one.
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() < Self::SIZE {
            return Err(FormatError::Truncated {
                offset: 0,
                need: Self::SIZE,
                have: bytes.len(),
            });
        }
        let mut c = Cursor::new(bytes);
        let magic = c.read_u32()?;
        if magic != MH_MAGIC_64 {
            if magic == MH_CIGAM_64 {
                return Err(FormatError::Invalid {
                    offset: 0,
                    what: "big-endian Mach-O is not supported on arm64",
                    value: magic as u64,
                });
            }
            return Err(FormatError::BadMagic { offset: 0, magic });
        }
        Ok(Self {
            magic,
            cputype: c.read_u32()?,
            cpusubtype: c.read_u32()?,
            filetype: c.read_u32()?,
            ncmds: c.read_u32()?,
            sizeofcmds: c.read_u32()?,
            flags: c.read_u32()?,
            reserved: c.read_u32()?,
        })
    }

    /// True when the header claims an arm64 cputype.
    #[must_use]
    pub const fn is_arm64(&self) -> bool {
        self.cputype == crate::consts::CPU_TYPE_ARM64
    }
}

#[cfg(test)]
mod tests {
    use super::MachHeader64;
    use crate::consts::{CPU_TYPE_ARM64, MH_CIGAM_64, MH_EXECUTE, MH_MAGIC_64};
    use crate::error::FormatError;

    fn minimal_header_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        v.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        v.extend_from_slice(&MH_EXECUTE.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // ncmds
        v.extend_from_slice(&0u32.to_le_bytes()); // sizeofcmds
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved
        v
    }

    #[test]
    fn parses_minimal_header() {
        let h = MachHeader64::parse(&minimal_header_bytes()).unwrap();
        assert_eq!(h.magic, MH_MAGIC_64);
        assert!(h.is_arm64());
        assert_eq!(h.filetype, MH_EXECUTE);
        assert_eq!(h.ncmds, 0);
    }

    #[test]
    fn rejects_truncated_header() {
        let bytes = minimal_header_bytes();
        for len in 0..32usize {
            assert!(MachHeader64::parse(&bytes[..len]).is_err());
        }
    }

    #[test]
    fn rejects_bad_and_swapped_magic() {
        let mut bytes = minimal_header_bytes();
        bytes[0] = 0xDE;
        bytes[1] = 0xAD;
        assert!(matches!(
            MachHeader64::parse(&bytes),
            Err(FormatError::BadMagic { .. })
        ));

        let mut swapped = minimal_header_bytes();
        swapped[0..4].copy_from_slice(&MH_CIGAM_64.to_le_bytes());
        assert!(matches!(
            MachHeader64::parse(&swapped),
            Err(FormatError::Invalid { .. })
        ));
    }

    #[test]
    fn fixed_size_is_32_bytes() {
        assert_eq!(MachHeader64::SIZE, 32);
    }
}

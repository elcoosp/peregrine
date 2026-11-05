//! `LC_SEGMENT_64`: segments and their sections.

use crate::cursor::pod_read_unaligned_at;
use crate::error::FormatError;

/// The 72-byte `segment_command_64`.
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct SegmentCommand64 {
    /// `LC_SEGMENT_64`.
    pub cmd: u32,
    /// Total command size including the section array.
    pub cmdsize: u32,
    /// 16-byte NUL-padded segment name.
    pub segname: [u8; 16],
    /// Virtual memory address of the segment start.
    pub vmaddr: u64,
    /// Virtual memory size (includes `__bss` tails, alignment.png).
    pub vmsize: u64,
    /// File offset of the segment's file-backed bytes.
    pub fileoff: u64,
    /// File-backed size (excludes zero-fill tails).
    pub filesize: u64,
    /// Maximum protection (`VM_PROT_*` bits).
    pub maxprot: u32,
    /// Initial protection.
    pub initprot: u32,
    /// Number of `section_64` entries following this command.
    pub nsects: u32,
    /// Segment flags.
    pub flags: u32,
}

const _: () = assert!(core::mem::size_of::<SegmentCommand64>() == 72);

/// The 80-byte `section_64`.
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct Section64 {
    /// 16-byte NUL-padded section name.
    pub sectname: [u8; 16],
    /// 16-byte NUL-padded segment name (must match the parent's).
    pub segname: [u8; 16],
    /// Virtual address of the section start.
    pub addr: u64,
    /// Section size in bytes.
    pub size: u64,
    /// File offset of the section's bytes (zerofill: advisory only).
    pub offset: u32,
    /// Alignment exponent (`2^align`); 16 KiB pages cap this at 14.
    pub align: u32,
    /// File offset of the relocation table.
    pub reloff: u32,
    /// Number of relocation entries.
    pub nreloc: u32,
    /// `S_*` type and attribute flags.
    pub flags: u32,
    /// Reserved for section type semantics (stub size, first stub symbol).
    pub reserved1: u32,
    /// Reserved for section type semantics (stub/TLV sizing).
    pub reserved2: u32,
    /// Reserved, must be zero.
    pub reserved3: u32,
}

const _: () = assert!(core::mem::size_of::<Section64>() == 80);

impl SegmentCommand64 {
    /// Fixed size of the segment command head in bytes (sections follow).
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Parses a segment command from the 72 bytes at `offset`.
    pub fn parse(bytes: &[u8], offset: usize) -> Result<Self, FormatError> {
        pod_read_unaligned_at::<Self>(bytes, offset)
    }

    /// The segment name, trimmed at its NUL terminator.
    pub fn name(&self) -> Result<&str, FormatError> {
        let end = self
            .segname
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.segname.len());
        core::str::from_utf8(&self.segname[..end]).map_err(|_| FormatError::Invalid {
            offset: 0,
            what: "segment name is not valid UTF-8",
            value: 0,
        })
    }

    /// Parses the `nsects` section records that follow this command at
    /// `sections_offset` (usually `cmd_offset + 72`).
    pub fn sections<'a>(
        &self,
        bytes: &'a [u8],
        sections_offset: usize,
    ) -> Result<&'a [Section64], FormatError> {
        let total = self
            .nsects
            .checked_mul(core::mem::size_of::<Section64>() as u32)
            .ok_or(FormatError::Invalid {
                offset: sections_offset,
                what: "section array size overflow",
                value: self.nsects as u64,
            })? as usize;
        let end = sections_offset
            .checked_add(total)
            .ok_or(FormatError::Invalid {
                offset: sections_offset,
                what: "section array end overflow",
                value: total as u64,
            })?;
        if end > bytes.len() {
            return Err(FormatError::Overrun {
                offset: sections_offset,
                overrun: end - bytes.len(),
            });
        }
        // `try_cast_slice` keeps malformed inputs panic-free: a mutated
        // command chain can leave the table start misaligned.
        bytemuck::try_cast_slice(&bytes[sections_offset..end]).map_err(|e| match e {
            bytemuck::PodCastError::TargetAlignmentGreaterAndInputNotAligned => {
                FormatError::Unaligned {
                    offset: sections_offset,
                    align: core::mem::align_of::<Section64>(),
                }
            }
            bytemuck::PodCastError::SizeMismatch => FormatError::Overrun {
                offset: sections_offset,
                overrun: 0,
            },
            _ => FormatError::Invalid {
                offset: sections_offset,
                what: "section array cast failed",
                value: total as u64,
            },
        })
    }
}

impl Section64 {
    /// The section name, trimmed at its NUL terminator.
    pub fn name(&self) -> Result<&str, FormatError> {
        let end = self
            .sectname
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.sectname.len());
        core::str::from_utf8(&self.sectname[..end]).map_err(|_| FormatError::Invalid {
            offset: 0,
            what: "section name is not valid UTF-8",
            value: 0,
        })
    }

    /// The section type (low byte of `flags`).
    #[must_use]
    pub const fn section_type(&self) -> u32 {
        self.flags & crate::consts::SECTION_TYPE_MASK
    }

    /// The section attributes (everything above the type byte).
    #[must_use]
    pub const fn attributes(&self) -> u32 {
        self.flags & crate::consts::SECTION_ATTR_MASK
    }
}

#[cfg(test)]
mod tests {
    use super::{Section64, SegmentCommand64};

    fn segment_bytes(nsects: u32) -> Vec<u8> {
        let seg = SegmentCommand64 {
            cmd: crate::consts::LC_SEGMENT_64,
            cmdsize: 72 + 80 * nsects,
            segname: *b"__TEXT\0\0\0\0\0\0\0\0\0\0",
            vmaddr: 0x1_0000_0000,
            vmsize: 0x4000,
            fileoff: 0,
            filesize: 0x4000,
            maxprot: 5,
            initprot: 5,
            nsects,
            flags: 0,
        };
        let mut v = Vec::new();
        v.extend_from_slice(bytemuck::bytes_of(&seg));
        for i in 0..nsects {
            let sect = Section64 {
                sectname: *b"__text\0\0\0\0\0\0\0\0\0\0",
                segname: seg.segname,
                addr: 0x1_0000_0000 + u64::from(i) * 16,
                size: 16,
                offset: 32,
                align: 4,
                reloff: 0,
                nreloc: 0,
                flags: 0x8000_0000,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            };
            v.extend_from_slice(bytemuck::bytes_of(&sect));
        }
        v
    }

    #[test]
    fn parses_segment_and_sections() {
        let bytes = segment_bytes(2);
        let seg = SegmentCommand64::parse(&bytes, 0).unwrap();
        assert_eq!(seg.name().unwrap(), "__TEXT");
        assert_eq!(seg.cmdsize, 72 + 160);
        let sects = seg.sections(&bytes, 72).unwrap();
        assert_eq!(sects.len(), 2);
        assert_eq!(sects[0].name().unwrap(), "__text");
        assert_eq!(sects[0].section_type(), 0);
        assert_eq!(sects[0].attributes(), 0x8000_0000);
    }

    #[test]
    fn section_array_bounds_checked() {
        let bytes = segment_bytes(2);
        let seg = SegmentCommand64::parse(&bytes, 0).unwrap();
        // Region beyond the buffer: error, not panic.
        assert!(seg.sections(&bytes[..100], 72).is_err());
        assert!(seg.sections(&bytes, 72 + 80).is_err());
    }

    #[test]
    fn struct_sizes_match_the_format() {
        assert_eq!(core::mem::size_of::<SegmentCommand64>(), 72);
        assert_eq!(core::mem::size_of::<Section64>(), 80);
    }

    #[test]
    fn name_without_nul_reads_full_field() {
        let mut seg = SegmentCommand64::parse(&segment_bytes(0), 0).unwrap();
        seg.segname = *b"ABCDEFGHIJKLMNOP"; // no NUL at all
        assert_eq!(seg.name().unwrap(), "ABCDEFGHIJKLMNOP");
    }
}

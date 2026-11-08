//! Relocation entries: `relocation_info` bitfields and pair classification.
//!
//! TDD §3.5 and perf doc D5: input relocations stay as raw 8-byte
//! `relocation_info` words (zero-copy slices into the input mmap); decoding
//! happens on the fly. `pgr-format` provides the bitfield accessors so the
//! decode logic exists exactly once.

use crate::consts::{ARM64_RELOC_ADDEND, ARM64_RELOC_SUBTRACTOR, R_SCATTERED};
use crate::cursor::pod_read_unaligned_at;
use crate::error::FormatError;

/// The 8-byte `relocation_info` (two `u32` words, little-endian).
///
/// Word 0 is `r_address` (bit 31 doubles as `r_scattered`); word 1 packs
/// `r_symbolnum:24 | r_pcrel:1 | r_length:2 | r_extern:1 | r_type:4`.
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct RelocationInfo {
    /// Address of the item to relocate (section-relative); bit 31 is
    /// `r_scattered` (never set on arm64 input).
    pub r_address: u32,
    /// Packed `r_symbolnum:24 | r_pcrel:1 | r_length:2 | r_extern:1 | r_type:4`.
    pub r_info: u32,
}

const _: () = assert!(core::mem::size_of::<RelocationInfo>() == 8);

impl RelocationInfo {
    /// Parses one entry at `offset`.
    ///
    /// # Errors
    /// [`FormatError`] when the input structure is malformed or truncated.
    pub fn parse(bytes: &[u8], offset: usize) -> Result<Self, FormatError> {
        pod_read_unaligned_at::<Self>(bytes, offset)
    }

    /// True when the entry is a scattered relocation (rejected on arm64
    /// input: modern clang does not generate them, TDD §5 Pass 1).
    #[must_use]
    pub const fn is_scattered(&self) -> bool {
        self.r_address & R_SCATTERED != 0
    }

    /// Symbol index (`r_extern`) or section ordinal (`!r_extern`).
    #[must_use]
    pub const fn symbolnum(&self) -> u32 {
        self.r_info & 0x00ff_ffff
    }

    /// True when the relocated item is PC-relative.
    #[must_use]
    pub const fn pcrel(&self) -> bool {
        (self.r_info >> 24) & 1 != 0
    }

    /// `r_length` exponent: 0=1 byte, 1=2, 2=4, 3=8.
    #[must_use]
    pub const fn length_log2(&self) -> u32 {
        (self.r_info >> 25) & 0x3
    }

    /// Length of the relocated item in bytes.
    #[must_use]
    pub const fn length(&self) -> u64 {
        1 << self.length_log2()
    }

    /// True when `r_symbolnum` names a symbol table entry.
    #[must_use]
    pub const fn is_extern(&self) -> bool {
        (self.r_info >> 27) & 1 != 0
    }

    /// The `ARM64_RELOC_*` / `GENERIC_RELOC_*` type.
    #[must_use]
    pub const fn rtype(&self) -> u32 {
        (self.r_info >> 28) & 0xf
    }

    /// True when this relocation type must be followed by its paired entry
    /// (`ARM64_RELOC_SUBTRACTOR` → `UNSIGNED`, `ARM64_RELOC_ADDEND` → target).
    #[must_use]
    pub const fn requires_pair(&self) -> bool {
        self.rtype() == ARM64_RELOC_SUBTRACTOR || self.rtype() == ARM64_RELOC_ADDEND
    }
}

#[cfg(test)]
mod tests {
    use super::RelocationInfo;
    use crate::consts::{
        ARM64_RELOC_BRANCH26, ARM64_RELOC_PAGEOFF12, ARM64_RELOC_SUBTRACTOR, ARM64_RELOC_UNSIGNED,
        RELOC_LENGTH_8,
    };

    fn make(
        addr: u32,
        symbolnum: u32,
        pcrel: bool,
        len: u32,
        ext: bool,
        ty: u32,
    ) -> RelocationInfo {
        let mut info = symbolnum & 0x00ff_ffff;
        if pcrel {
            info |= 1 << 24;
        }
        info |= (len & 0x3) << 25;
        if ext {
            info |= 1 << 27;
        }
        info |= (ty & 0xf) << 28;
        RelocationInfo {
            r_address: addr,
            r_info: info,
        }
    }

    #[test]
    fn bitfields_roundtrip() {
        let r = make(
            0x1234,
            0xdead,
            true,
            RELOC_LENGTH_8,
            true,
            ARM64_RELOC_BRANCH26,
        );
        assert_eq!(r.symbolnum(), 0xdead);
        assert!(r.pcrel());
        assert_eq!(r.length_log2(), RELOC_LENGTH_8);
        assert_eq!(r.length(), 8);
        assert!(r.is_extern());
        assert_eq!(r.rtype(), ARM64_RELOC_BRANCH26);
        assert!(!r.is_scattered());
        assert!(!r.requires_pair());
    }

    #[test]
    fn subtractor_requires_pair() {
        let r = make(0, 3, false, RELOC_LENGTH_8, true, ARM64_RELOC_SUBTRACTOR);
        assert!(r.requires_pair());
    }

    #[test]
    fn scattered_bit_is_top_of_address_word() {
        let r = make(0x8000_0000, 1, false, 2, false, ARM64_RELOC_UNSIGNED);
        assert!(r.is_scattered());
    }

    #[test]
    fn parse_roundtrip_via_bytes() {
        let r = make(0x40, 7, false, 2, false, ARM64_RELOC_PAGEOFF12);
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(bytemuck::bytes_of(&r));
        let p = RelocationInfo::parse(&buf, 0).unwrap();
        assert_eq!(p.rtype(), ARM64_RELOC_PAGEOFF12);
        assert_eq!(p.symbolnum(), 7);
        let bad = RelocationInfo::parse(&buf, 9);
        assert!(bad.is_err());
    }
}

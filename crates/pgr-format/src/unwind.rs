//! The compact-unwind read seam (M34): the object-side
//! `__LD,__compact_unwind` table — one 32-byte entry per function
//! (`range_start` pointer-sized, `range_length`/`encoding` 32-bit,
//! `personality`/`lsda` pointer-sized; arm64 pointers are 8 bytes, so
//! one entry is 32 bytes) — decoded into typed entries the layout's
//! carriage translates onto the output `__TEXT,__unwind_info`.
//!
//! The section is the shape Apple's own toolchain carries: the table
//! carries `S_ATTR_DEBUG` ("ignored by older linkers; removed by the
//! new linker, so never ends up in final executables" —
//! `mach-o/compact_unwind_encoding.h`), which is why the tree's
//! debug-ish segment skip silently dropped it before M34. The one
//! structural rule the format itself carries is the entry width: a
//! payload that is not a multiple of 32 is a malformed table, refused
//! with the typed error (never silently truncated or defaulted).

use crate::cursor::pod_read_unaligned_at;
use crate::error::FormatError;

/// One 32-byte `compact_unwind_entry` (arm64: 8-byte pointers).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct CompactUnwindEntry {
    /// The function's start address in the object's address space
    /// (blob-relative under the LLVM single-segment convention — the
    /// same space the symbol `n_value`s name).
    pub range_start: u64,
    /// Number of bytes of function code.
    pub range_length: u32,
    /// The `compact_unwind_encoding_t` word (opaque here; the verifier
    /// validates the arm64 mode nibble, the output personality index
    /// rides `UNWIND_PERSONALITY_MASK`).
    pub encoding: u32,
    /// The personality function's address, or 0.
    pub personality: u64,
    /// The LSDA data's address (`__gcc_except_tab`), or 0.
    pub lsda: u64,
}

const _: () = assert!(core::mem::size_of::<CompactUnwindEntry>() == 32);

/// The byte width of one [`CompactUnwindEntry`] (the table's one
/// structural rule).
pub const COMPACT_UNWIND_ENTRY_SIZE: usize = 32;

/// Decodes a `__LD,__compact_unwind` table: one 32-byte
/// [`CompactUnwindEntry`] per 32 payload bytes, in stream order. The
/// one structural rule the format itself carries is the entry width —
/// a payload that is not a multiple of 32 is a malformed table,
/// refused with the typed error (never silently truncated).
///
/// # Errors
/// [`FormatError::Invalid`] when the payload is not a multiple of the
/// 32-byte entry (a truncated tail would re-read as a zero entry).
pub fn read_compact_unwind(data: &[u8]) -> Result<Vec<CompactUnwindEntry>, FormatError> {
    if data.len() % COMPACT_UNWIND_ENTRY_SIZE != 0 {
        return Err(FormatError::Invalid {
            offset: 0,
            what: "compact-unwind payload is not a multiple of the 32-byte entry",
            value: data.len() as u64,
        });
    }
    let mut out = Vec::with_capacity(data.len() / COMPACT_UNWIND_ENTRY_SIZE);
    for i in 0..data.len() / COMPACT_UNWIND_ENTRY_SIZE {
        out.push(pod_read_unaligned_at::<CompactUnwindEntry>(
            data,
            i * COMPACT_UNWIND_ENTRY_SIZE,
        )?);
    }
    Ok(out)
}

/// Re-encodes entries back into the object-side table shape (the
/// fixtures' builder and the round-trip gate share one writer).
#[must_use]
pub fn write_compact_unwind(entries: &[CompactUnwindEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * COMPACT_UNWIND_ENTRY_SIZE);
    for e in entries {
        out.extend_from_slice(bytemuck::bytes_of(e));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{CompactUnwindEntry, read_compact_unwind, write_compact_unwind};
    use crate::consts::UNWIND_ARM64_MODE_FRAME;

    fn entry(start: u64, len: u32) -> CompactUnwindEntry {
        CompactUnwindEntry {
            range_start: start,
            range_length: len,
            encoding: UNWIND_ARM64_MODE_FRAME,
            personality: 0,
            lsda: 0,
        }
    }

    #[test]
    fn the_table_decodes_entries_in_order() {
        let entries = [entry(0, 4), entry(8, 12)];
        let bytes = write_compact_unwind(&entries);
        assert_eq!(bytes.len(), 64);
        assert_eq!(read_compact_unwind(&bytes).unwrap(), entries);
        assert_eq!(read_compact_unwind(&[]).unwrap(), Vec::new());
    }

    #[test]
    fn a_truncated_tail_refuses_typed() {
        // 33 bytes: not a multiple of the 32-byte entry — refused,
        // never silently truncated to a zero entry.
        let err = read_compact_unwind(&[0u8; 33]).unwrap_err();
        assert!(
            err.to_string().contains("multiple of the 32-byte entry"),
            "{err}"
        );
    }

    #[test]
    fn the_entry_width_is_the_arm64_layout() {
        // Pointer-sized start/personality/lsda + 32-bit length/encoding:
        // 8 + 4 + 4 + 8 + 8.
        let e = entry(0x1000, 0x20);
        let bytes = write_compact_unwind(&[e]);
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 0x1000);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 0x20);
        assert_eq!(
            u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            UNWIND_ARM64_MODE_FRAME
        );
    }
}

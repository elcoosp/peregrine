//! The universal ("fat") container (M70): ld64 links against
//! multi-arch binaries daily — every SDK dylib and static archive ships
//! one — and the container is the one input shape
//! [`crate::header::MachHeader64::parse`]
//! cannot see (the fat magic rides big-endian `0xcafebabe`, a value no
//! Mach-O magic matches). The module decodes the `fat_header` and its
//! slice table — both widths (`fat_arch`, 20 bytes; `fat_arch_64`, 32) —
//! and hands out the slice windows; the driver picks the arm64 slice
//! ([`Universal::arm64`]) and the per-kind dispatch runs on it unchanged.
//!
//! Every field on disk is big-endian (`<mach-o/fat.h>`), the read the
//! [`Cursor`]'s big-endian half already serves for the code-signature
//! structures. Every refusal is the offset-tagged [`FormatError`] the
//! other parsers carry — the container stops making sense at a named
//! byte, never a panic (the fuzz targets' total-behavior contract).

use crate::consts::{CPU_TYPE_ARM64, FAT_MAGIC, FAT_MAGIC_64};
use crate::cursor::Cursor;
use crate::error::FormatError;

/// One `fat_arch`/`fat_arch_64` row: the slice's arch identity and its
/// window in the container (the 32-bit form's fields widen losslessly;
/// the 64-bit form's trailing `reserved` rides unvalidated — the reader
/// stays tolerant of widths the header's magic does not name yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatArch {
    /// The slice's `cpu_type_t` ([`CPU_TYPE_ARM64`] for the linked arch).
    pub cputype: u32,
    /// The slice's `cpu_subtype_t` (unvalidated — subtypes name their
    /// platform via the top bits and the pipeline never re-reads them).
    pub cpusubtype: u32,
    /// The slice's byte offset in the container.
    pub offset: u64,
    /// The slice's size in bytes.
    pub size: u64,
    /// The slice's alignment as `log2` (real containers align `2^12`–`2^14`).
    pub align_log2: u32,
}

impl FatArch {
    /// The 20-byte `fat_arch` row (the [`FAT_MAGIC`] width).
    pub const ENTRY_SIZE: usize = 20;
    /// The 32-byte `fat_arch_64` row (the [`FAT_MAGIC_64`] width).
    pub const ENTRY_SIZE_64: usize = 32;
    /// Every slice must at least carry a Mach-O header — a smaller
    /// window cannot be a slice (the header parse the dispatch runs
    /// next would refuse it anyway; the table names it now).
    const MIN_SLICE: u64 = 32;
}

/// A decoded container: the magic it rode and the slice table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Universal {
    /// [`FAT_MAGIC`] or [`FAT_MAGIC_64`] — the width the table decoded at.
    pub magic: u32,
    /// The slices, in table order (ld64 writes the offsets ascending;
    /// the parse refuses a table that walks backwards).
    pub arches: Vec<FatArch>,
}

/// True when `bytes` opens with a fat magic (both widths).
///
/// The four-byte probe the driver's input dispatch runs before every
/// other classification — a non-universal input costs one comparison.
#[must_use]
pub fn is_universal(bytes: &[u8]) -> bool {
    match bytes.first_chunk::<4>() {
        Some(head) => {
            let magic = u32::from_be_bytes(*head);
            magic == FAT_MAGIC || magic == FAT_MAGIC_64
        }
        None => false,
    }
}

/// Parses the container: header, slice table, and every slice's window
/// bounds (in-bounds, header-sized, ascending, non-overlapping — the
/// table is the container's own contract with every consumer that
/// slices it).
///
/// # Errors
/// [`FormatError`] when the container is malformed: a truncated header
/// or table (offset-tagged at the field the read needed), a slice
/// window that overruns the container or cannot carry a Mach-O header,
/// a table that walks backwards or overlaps, or a magic that names no
/// width.
pub fn parse_universal(bytes: &[u8]) -> Result<Universal, FormatError> {
    let mut c = Cursor::new(bytes);
    let magic = c.read_u32be()?;
    if magic != FAT_MAGIC && magic != FAT_MAGIC_64 {
        return Err(FormatError::BadMagic { offset: 0, magic });
    }
    let nfat = c.read_u32be()?;
    let entry = if magic == FAT_MAGIC {
        FatArch::ENTRY_SIZE
    } else {
        FatArch::ENTRY_SIZE_64
    };
    // The table is one extent: the count names bytes the file must
    // carry (a count that lies refuses here, at the table's own start,
    // before any entry read can half-decode it).
    let table_bytes = usize::try_from(nfat)
        .ok()
        .and_then(|n| n.checked_mul(entry))
        .ok_or(FormatError::Invalid {
            offset: 4,
            what: "fat_arch count",
            value: u64::from(nfat),
        })?;
    let table_end = 8usize
        .checked_add(table_bytes)
        .ok_or(FormatError::Invalid {
            offset: 4,
            what: "fat_arch count",
            value: u64::from(nfat),
        })?;
    if table_end > bytes.len() {
        return Err(FormatError::Truncated {
            offset: 8,
            need: table_bytes,
            have: bytes.len() - 8,
        });
    }
    let mut arches = Vec::with_capacity(nfat as usize);
    let mut prev_end: u64 = 0;
    for i in 0..nfat as usize {
        let entry_at = 8 + i * entry;
        c.seek(entry_at)?;
        let cputype = c.read_u32be()?;
        let cpusubtype = c.read_u32be()?;
        let (offset, size, align_log2) = if magic == FAT_MAGIC {
            (
                u64::from(c.read_u32be()?),
                u64::from(c.read_u32be()?),
                u64::from(c.read_u32be()?),
            )
        } else {
            (c.read_u64be()?, c.read_u64be()?, u64::from(c.read_u32be()?))
        };
        let align_log2 = u32::try_from(align_log2).unwrap_or(u32::MAX);
        if align_log2 >= 64 {
            return Err(FormatError::Invalid {
                offset: entry_at,
                what: "fat slice align",
                value: u64::from(align_log2),
            });
        }
        if offset
            .checked_add(size)
            .is_none_or(|end| end > bytes.len() as u64)
        {
            return Err(FormatError::Overrun {
                offset: usize::try_from(offset).unwrap_or(bytes.len()),
                overrun: usize::try_from(
                    offset
                        .saturating_add(size)
                        .saturating_sub(bytes.len() as u64),
                )
                .unwrap_or(0),
            });
        }
        if size < FatArch::MIN_SLICE {
            return Err(FormatError::Invalid {
                offset: usize::try_from(offset).unwrap_or(0),
                what: "fat slice size",
                value: size,
            });
        }
        if offset < prev_end {
            return Err(FormatError::Invalid {
                offset: usize::try_from(offset).unwrap_or(0),
                what: "fat slice table (walks backwards or overlaps the previous slice)",
                value: prev_end,
            });
        }
        prev_end = offset.saturating_add(size);
        arches.push(FatArch {
            cputype,
            cpusubtype,
            offset,
            size,
            align_log2,
        });
    }
    Ok(Universal { magic, arches })
}

impl Universal {
    /// The slice window `arch` names: in-bounds, header-sized (the
    /// bounds the parse gated re-checked — the row may come from a
    /// caller's own hand).
    ///
    /// # Errors
    /// [`FormatError::Overrun`] when the window leaves `bytes`;
    /// [`FormatError::Invalid`] when it cannot carry a Mach-O header.
    pub fn slice<'a>(&self, bytes: &'a [u8], arch: &FatArch) -> Result<&'a [u8], FormatError> {
        let end = arch
            .offset
            .checked_add(arch.size)
            .ok_or(FormatError::Overrun {
                offset: usize::try_from(arch.offset).unwrap_or(bytes.len()),
                overrun: 0,
            })?;
        if end > bytes.len() as u64 {
            return Err(FormatError::Overrun {
                offset: usize::try_from(arch.offset).unwrap_or(bytes.len()),
                overrun: usize::try_from(end - bytes.len() as u64).unwrap_or(0),
            });
        }
        if arch.size < FatArch::MIN_SLICE {
            return Err(FormatError::Invalid {
                offset: usize::try_from(arch.offset).unwrap_or(0),
                what: "fat slice size",
                value: arch.size,
            });
        }
        let start = usize::try_from(arch.offset).map_err(|_| FormatError::Overrun {
            offset: bytes.len(),
            overrun: 0,
        })?;
        let end = usize::try_from(end).map_err(|_| FormatError::Overrun {
            offset: start,
            overrun: 0,
        })?;
        Ok(&bytes[start..end])
    }

    /// The arm64 slice's window — the slice the driver links (the
    /// `-arch` match ld64 runs; the surface links `arm64`, so the
    /// cputype match is exact).
    ///
    /// # Errors
    /// [`FormatError::Malformed`] when the container carries no arm64
    /// slice — the refusal names the cputypes it does, so the fix (the
    /// container's own rebuild, or linking the arch it carries) is one
    /// line away.
    pub fn arm64<'a>(&self, bytes: &'a [u8]) -> Result<&'a [u8], FormatError> {
        let Some(arch) = self.arches.iter().find(|a| a.cputype == CPU_TYPE_ARM64) else {
            let cputypes: Vec<String> = self
                .arches
                .iter()
                .map(|a| format!("{:#x}", a.cputype))
                .collect();
            return Err(FormatError::Malformed {
                what: format!(
                    "the universal container carries no arm64 slice (cputypes present: \
                     {}) — rebuild the container with an arm64 slice or link the \
                     arch it carries",
                    cputypes.join(", ")
                ),
            });
        };
        self.slice(bytes, arch)
    }
}

#[cfg(test)]
mod tests {
    use super::{FatArch, Universal, is_universal, parse_universal};
    use crate::consts::{CPU_TYPE_ARM64, FAT_MAGIC, FAT_MAGIC_64, MH_MAGIC_64};
    use crate::error::FormatError;

    /// A minimal 32-byte Mach-O header marked with `cputype`.
    fn slice_bytes(cputype: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        v.extend_from_slice(&cputype.to_le_bytes());
        v.extend_from_slice(&[0u8; 24]);
        v
    }

    /// A `FAT_MAGIC` container: header, two entries, aligned windows.
    fn container(slices: &[(&[u8], u32)]) -> Vec<u8> {
        let align = 12u32;
        let mut offsets = Vec::new();
        let mut pos = 8u64 + 20 * slices.len() as u64;
        for (bytes, _) in slices {
            let offset = (pos + ((1 << align) - 1)) & !((1 << align) - 1);
            offsets.push(offset);
            pos = offset + bytes.len() as u64;
        }
        let mut v = Vec::new();
        v.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        v.extend_from_slice(&(slices.len() as u32).to_be_bytes());
        for ((bytes, cputype), offset) in slices.iter().zip(&offsets) {
            v.extend_from_slice(&cputype.to_be_bytes());
            v.extend_from_slice(&0u32.to_be_bytes());
            let offset32 = u32::try_from(*offset).expect("the offset fits u32");
            v.extend_from_slice(&offset32.to_be_bytes());
            v.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            v.extend_from_slice(&align.to_be_bytes());
        }
        for ((bytes, _), offset) in slices.iter().zip(&offsets) {
            let target = *offset as usize;
            v.resize(target, 0);
            v.extend_from_slice(bytes);
        }
        v
    }

    #[test]
    fn decodes_both_widths() {
        let arm64 = slice_bytes(CPU_TYPE_ARM64);
        let foreign = slice_bytes(0x0100_0007);
        let fat = container(&[(&arm64, CPU_TYPE_ARM64), (&foreign, 0x0100_0007)]);
        assert!(is_universal(&fat));
        let u = parse_universal(&fat).expect("the container decodes");
        assert_eq!(u.magic, FAT_MAGIC);
        assert_eq!(u.arches.len(), 2);
        assert_eq!(u.arm64(&fat).expect("the arm64 slice selects"), &arm64[..]);
    }

    #[test]
    fn the_64_bit_width_decodes() {
        let arm64 = slice_bytes(CPU_TYPE_ARM64);
        let mut v = Vec::new();
        v.extend_from_slice(&FAT_MAGIC_64.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&CPU_TYPE_ARM64.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&0x1000u64.to_be_bytes());
        v.extend_from_slice(&(arm64.len() as u64).to_be_bytes());
        v.extend_from_slice(&12u32.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes()); // reserved
        let mut fat = v;
        fat.resize(0x1000, 0);
        fat.extend_from_slice(&arm64);
        let u = parse_universal(&fat).expect("the 64-bit container decodes");
        assert_eq!(u.magic, FAT_MAGIC_64);
        assert_eq!(u.arches[0].offset, 0x1000);
        assert_eq!(u.arm64(&fat).expect("the arm64 slice selects"), &arm64[..]);
    }

    #[test]
    fn refusals_carry_their_offsets() {
        let arm64 = slice_bytes(CPU_TYPE_ARM64);
        let fat = container(&[(&arm64, CPU_TYPE_ARM64)]);
        assert!(matches!(
            parse_universal(&fat[..2]),
            Err(FormatError::Truncated { offset: 0, .. })
        ));
        assert!(matches!(
            parse_universal(&fat[..6]),
            Err(FormatError::Truncated { offset: 4, .. })
        ));
        // The count lies (two entries claimed, one entry's bytes in the
        // file): the refusal anchors at the table's start.
        let mut lying = Vec::new();
        lying.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        lying.extend_from_slice(&2u32.to_be_bytes());
        lying.extend_from_slice(&[0u8; 20]); // one entry, zeros
        assert!(matches!(
            parse_universal(&lying),
            Err(FormatError::Truncated { offset: 8, .. })
        ));
        // A sub-header slice.
        let mut tiny = container(&[(&arm64, CPU_TYPE_ARM64)]);
        let size_at = 20;
        tiny[size_at..size_at + 4].copy_from_slice(&16u32.to_be_bytes());
        assert!(matches!(
            parse_universal(&tiny),
            Err(FormatError::Invalid {
                what: "fat slice size",
                ..
            })
        ));
    }

    #[test]
    fn the_selection_miss_names_the_cputypes() {
        let arm64 = slice_bytes(CPU_TYPE_ARM64);
        let foreign = slice_bytes(0x0100_0007);
        let fat = container(&[(&foreign, 0x0100_0007), (&arm64, 0x0100_000d)]);
        let u = parse_universal(&fat).expect("the container decodes");
        let err = u.arm64(&fat).expect_err("no arm64 slice rides");
        let text = err.to_string();
        assert!(text.contains("0x1000007") && text.contains("0x100000d"));
    }

    #[test]
    fn the_table_must_walk_forward() {
        let arm64 = slice_bytes(CPU_TYPE_ARM64);
        let foreign = slice_bytes(0x0100_0007);
        let mut fat = container(&[(&arm64, CPU_TYPE_ARM64), (&foreign, 0x0100_0007)]);
        // Drag the second slice onto the first's offset.
        let offset_at = 8 + 20 + 8;
        fat[offset_at..offset_at + 4].copy_from_slice(&0x1000u32.to_be_bytes());
        assert!(matches!(
            parse_universal(&fat),
            Err(FormatError::Invalid {
                what: "fat slice table (walks backwards or overlaps the previous slice)",
                ..
            })
        ));
    }

    #[test]
    fn slice_re_checks_a_hand_written_row() {
        let arm64 = slice_bytes(CPU_TYPE_ARM64);
        let fat = container(&[(&arm64, CPU_TYPE_ARM64)]);
        let u = parse_universal(&fat).expect("the container decodes");
        let hand = FatArch {
            cputype: CPU_TYPE_ARM64,
            cpusubtype: 0,
            offset: u64::try_from(fat.len()).expect("the length fits u64"),
            size: 0x40,
            align_log2: 12,
        };
        assert!(matches!(
            u.slice(&fat, &hand),
            Err(FormatError::Overrun { .. })
        ));
        let u2 = Universal {
            magic: FAT_MAGIC,
            arches: vec![hand],
        };
        assert!(matches!(
            u2.slice(&fat, &hand),
            Err(FormatError::Overrun { .. })
        ));
    }
}

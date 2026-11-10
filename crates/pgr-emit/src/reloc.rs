//! Relocation application (TDD §5 Pass 4 "copy + apply", §3.5): arm64
//! immediate patching over the output buffer's disjoint ranges.
//!
//! Every patch operand is pre-resolved (Pass 3); this module only writes
//! bits. Encodings follow the ARM Architecture Reference Manual:
//!
//! * ADRP — `op:1 immlo:2 10000 immhi:19 Rd:5` (imm21 signed, in 4 KiB pages),
//! * ADD/LDR/STR imm12 — `[21:10]` unsigned immediate,
//! * `B`/`BL` — `[25:0]` signed imm26 in 4-byte units,
//! * subtractor results are plain 8-byte LE writes.

use crate::EmitError;
use pgr_core::PatchOp;

/// Applies one patch to the buffer at absolute file offset `at`.
///
/// # Errors
/// [`EmitError::Contract`] on out-of-range immediates;
/// [`EmitError::Internal`] when `at` leaves the buffer.
pub fn apply(buf: &mut [u8], op: &PatchOp, at: u64) -> Result<(), EmitError> {
    match *op {
        PatchOp::Adrp {
            in_offset: _,
            page_delta,
        } => {
            let end = at + 4;
            let word_bytes = buf
                .get(at as usize..end as usize)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .ok_or(EmitError::Internal {
                    message: format!("adrp patch at {at:#x} leaves the output buffer"),
                })?;
            let word = u32::from_le_bytes(word_bytes);
            // imm21 is two's complement in 21 bits: immlo = bits [1:0],
            // immhi = bits [20:2].
            if page_delta.unsigned_abs() > 0xF_FFFF {
                return Err(EmitError::Contract {
                    message: format!(
                        "adrp page delta {page_delta} exceeds the ±1M-page (±4 GiB) arm64 range"
                    ),
                });
            }
            let imm21 = (page_delta as i32 & 0x001F_FFFF) as u32;
            let immlo = imm21 & 0x3;
            let immhi = (imm21 >> 2) & 0x0007_FFFF;
            let cleared = word & !((0x3 << 29) | (0x0007_FFFF << 5));
            let patched = cleared | (immlo << 29) | (immhi << 5);
            buf[at as usize..end as usize].copy_from_slice(&patched.to_le_bytes());
        }
        PatchOp::PageOff12 {
            in_offset: _,
            imm12,
        } => {
            let end = at + 4;
            let word_bytes = buf
                .get(at as usize..end as usize)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .ok_or(EmitError::Internal {
                    message: format!("pageoff12 patch at {at:#x} leaves the output buffer"),
                })?;
            let word = u32::from_le_bytes(word_bytes);
            let patched = (word & !(0xFFF << 10)) | ((imm12 & 0xFFF) << 10);
            buf[at as usize..end as usize].copy_from_slice(&patched.to_le_bytes());
        }
        PatchOp::Branch26 {
            in_offset: _,
            pc: _,
            delta,
        } => {
            let end = at + 4;
            let word_bytes = buf
                .get(at as usize..end as usize)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .ok_or(EmitError::Internal {
                    message: format!("branch26 patch at {at:#x} leaves the output buffer"),
                })?;
            let word = u32::from_le_bytes(word_bytes);
            if delta % 4 != 0 {
                return Err(EmitError::Internal {
                    message: format!("branch delta {delta} is not 4-aligned"),
                });
            }
            // imm26 = delta / 4, two's complement 26 bits.
            let imm26 = ((delta / 4) as i32 & 0x03FF_FFFF) as u32;
            let patched = (word & 0xFC00_0000) | imm26;
            buf[at as usize..end as usize].copy_from_slice(&patched.to_le_bytes());
        }
        PatchOp::Write64 {
            in_offset: _,
            value,
        } => {
            let end = at + 8;
            let Some(dst) = buf.get_mut(at as usize..end as usize) else {
                return Err(EmitError::Internal {
                    message: format!("write64 patch at {at:#x} leaves the output buffer"),
                });
            };
            dst.copy_from_slice(&value.to_le_bytes());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::apply;
    use crate::EmitError;
    use pgr_core::PatchOp;

    fn word_of(buf: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(buf[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn adrp_forward_and_backward() {
        // A clang-style adrp placeholder word.
        let mut buf = vec![0u8; 16];
        let base: u32 = 0x9000_0000; // ADRP x0, #0
        buf[0..4].copy_from_slice(&base.to_le_bytes());

        // +2 pages: imm21 = 2 → immlo (bits [1:0]) = 2, immhi = 0.
        apply(
            &mut buf,
            &PatchOp::Adrp {
                in_offset: 0,
                page_delta: 2,
            },
            0,
        )
        .unwrap();
        let w = word_of(&buf, 0);
        assert_eq!((w >> 29) & 0x3, 2, "immlo carries the low bits of imm21");
        assert_eq!((w >> 5) & 0x7FFFF, 0, "immhi carries imm21 >> 2");
        // +8 pages: imm21 = 8 → immlo 0, immhi 2.
        apply(
            &mut buf,
            &PatchOp::Adrp {
                in_offset: 0,
                page_delta: 8,
            },
            0,
        )
        .unwrap();
        let w = word_of(&buf, 0);
        assert_eq!((w >> 29) & 0x3, 0, "immlo");
        assert_eq!((w >> 5) & 0x7FFFF, 2, "immhi");
        assert_eq!(w & 0x9F00_001F, base & 0x9F00_001F, "op/fixed/Rd untouched");

        // −1 page: imm21 = 0x1FFFFF → immlo 3, immhi 0x7FFFF.
        apply(
            &mut buf,
            &PatchOp::Adrp {
                in_offset: 0,
                page_delta: -1,
            },
            0,
        )
        .unwrap();
        let w = word_of(&buf, 0);
        assert_eq!((w >> 29) & 0x3, 3, "immlo of -1");
        assert_eq!((w >> 5) & 0x7FFFF, 0x7FFFF, "immhi of -1");
    }

    #[test]
    fn adrp_out_of_range_errors() {
        let mut buf = vec![0u8; 8];
        let err = apply(
            &mut buf,
            &PatchOp::Adrp {
                in_offset: 0,
                page_delta: 1 << 21,
            },
            0,
        )
        .unwrap_err();
        assert!(matches!(err, EmitError::Contract { .. }), "{err}");
    }

    #[test]
    fn pageoff12_replaces_immediate() {
        let mut buf = vec![0u8; 8];
        // ADD x0, x0, #0 with reserved bits around imm12.
        let base: u32 = 0x9100_0000 | (0x5 << 10); // stale imm 5
        buf[0..4].copy_from_slice(&base.to_le_bytes());
        apply(
            &mut buf,
            &PatchOp::PageOff12 {
                in_offset: 0,
                imm12: 0x123,
            },
            0,
        )
        .unwrap();
        let w = word_of(&buf, 0);
        assert_eq!((w >> 10) & 0xFFF, 0x123);
        assert_eq!(w & !(0xFFF << 10), base & !(0xFFF << 10));
    }

    #[test]
    fn branch26_encodes_signed_delta() {
        let mut buf = vec![0u8; 8];
        let base: u32 = 0x9400_0000; // BL #0
        buf[0..4].copy_from_slice(&base.to_le_bytes());
        // +16 bytes = 4 units.
        apply(
            &mut buf,
            &PatchOp::Branch26 {
                in_offset: 0,
                pc: 0x1000,
                delta: 16,
            },
            0,
        )
        .unwrap();
        assert_eq!(word_of(&buf, 0) & 0x03FF_FFFF, 4);
        // −8 bytes = −2 units.
        apply(
            &mut buf,
            &PatchOp::Branch26 {
                in_offset: 0,
                pc: 0x1000,
                delta: -8,
            },
            0,
        )
        .unwrap();
        assert_eq!(word_of(&buf, 0) & 0x03FF_FFFF, 0x03FF_FFFE);
        // Opcode bits survive.
        assert_eq!(word_of(&buf, 0) >> 26, 0x25);
    }

    #[test]
    fn write64_roundtrip() {
        let mut buf = vec![0u8; 16];
        apply(
            &mut buf,
            &PatchOp::Write64 {
                in_offset: 0,
                value: 0xDEAD_BEEF_1234_5678,
            },
            4,
        )
        .unwrap();
        assert_eq!(
            u64::from_le_bytes(buf[4..12].try_into().unwrap()),
            0xDEAD_BEEF_1234_5678
        );
    }

    #[test]
    fn patches_past_the_buffer_error() {
        let mut buf = vec![0u8; 8];
        assert!(
            apply(
                &mut buf,
                &PatchOp::Write64 {
                    in_offset: 0,
                    value: 1
                },
                4
            )
            .is_err()
        );
        assert!(
            apply(
                &mut buf,
                &PatchOp::Adrp {
                    in_offset: 0,
                    page_delta: 1
                },
                6
            )
            .is_err()
        );
    }
}

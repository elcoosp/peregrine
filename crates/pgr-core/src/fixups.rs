//! Chained-fixup planning (TDD §7): slot classification, the stride-bounded
//! greedy chain packer (§7.4), the `LC_DYLD_CHAINED_FIXUPS` payload assembler
//! and the `__TEXT,__chain_starts` static mirror (§7.5).
//!
//! M1 emits rebase-only chains (`DYLD_CHAINED_PTR_64_OFFSET`): every pointer
//! slot references an in-image definition, so the import table is empty and
//! every chain word is `dyld_chained_ptr_64_rebase`. Binds join at M2.
//!
//! Determinism: slots are sorted by output address, pages packed in ascending
//! order, multi-start overflow tables appended in first-discovery order — the
//! whole payload is a pure function of the layout.

use crate::LinkError;
use pgr_format::consts::{
    DYLD_CHAINED_IMPORT_ADDEND, DYLD_CHAINED_PTR_64_OFFSET, DYLD_CHAINED_PTR_START_MULTI,
    DYLD_CHAINED_PTR_START_MULTI_MASK, DYLD_CHAINED_PTR_START_NONE,
};

/// `next` counts 4-byte units with 12 bits; only 0 ends a chain (TDD §7.4).
pub const MAX_CHAIN_STRIDE: u32 = 0xFFF;
/// Maximum forward distance between two fixups in the same chain (16 380 B).
pub const MAX_CHAIN_STRIDE_BYTES: u64 = (MAX_CHAIN_STRIDE as u64) * 4;

/// One pointer slot that becomes a chained fixup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixupSlot {
    /// Output vaddr of the 8-byte slot (8-byte aligned).
    pub vaddr: u64,
    /// Final pointer value: the target's output vaddr (target address plus
    /// the slot's in-data addend, already resolved).
    pub target_vaddr: u64,
}

/// A fixup mid-packing: page offset, encoded word, chain stride.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackingSlot {
    /// Offset of the slot within its chain-walk page.
    pub page_off: u32,
    /// Distance to the next fixup, in 4-byte units (0 terminates).
    pub next: u32,
    /// Encoded word without the `next` field.
    pub word_base: u64,
}

/// Packs one page's fixups into chains (TDD §7.4, the stride-bounded greedy
/// linker). `page_off` must be ascending across `fx`. Returns the chain
/// heads as page offsets, in ascending slot order.
#[must_use]
pub fn pack_page(fx: &mut [PackingSlot]) -> Vec<u16> {
    debug_assert!(fx.windows(2).all(|w| w[0].page_off <= w[1].page_off));
    let mut heads = Vec::new();
    let mut i = 0usize;
    while i < fx.len() {
        heads.push(fx[i].page_off as u16); // new chain head
        let mut j = i;
        while j + 1 < fx.len() {
            let gap = u64::from(fx[j + 1].page_off - fx[j].page_off);
            if !(4..=MAX_CHAIN_STRIDE_BYTES).contains(&gap) {
                break; // must start a fresh chain
            }
            j += 1;
        }
        for k in i..j {
            fx[k].next = (fx[k + 1].page_off - fx[k].page_off) / 4;
        }
        fx[j].next = 0; // terminate
        i = j + 1;
    }
    heads
}

/// Encodes a rebase chain word: `target44 | high8 << 36 | next << 51` (bit 63
/// clear, `DYLD_CHAINED_PTR_64_OFFSET`).
fn rebase_word(target_image_off: u64, next: u32) -> Result<u64, LinkError> {
    if target_image_off >> 44 != 0 {
        return Err(LinkError::Layout {
            message: format!(
                "rebase target {target_image_off:#x} exceeds the 44-bit chained-fixup field \
                 (image larger than 16 TiB)"
            ),
        });
    }
    let target36 = target_image_off & 0xF_FFFF_FFFF;
    let high8 = (target_image_off >> 36) as u8;
    Ok(u64::from(high8) << 36 | target36 | u64::from(next) << 51)
}

/// Packing result for one segment.
#[derive(Debug, Default)]
struct SegmentChains {
    /// `page_start[]` entries (start offset / `START_NONE` / multi marker).
    page_start: Vec<u16>,
    /// Multi-start overflow tables in first-discovery order (each: count +
    /// head offsets, little-endian `u16`s).
    overflow: Vec<Vec<u8>>,
    /// Encoded slot words: `(slot vaddr, final word)` ascending.
    slot_words: Vec<(u64, u64)>,
    /// Image offsets of every chain head slot, ascending.
    head_image_offs: Vec<u32>,
}

impl SegmentChains {
    /// `dyld_chained_starts_in_segment.size` (22 fixed bytes + page_start
    /// array + overflow tables).
    fn record_size(&self) -> usize {
        22 + self.page_start.len() * 2 + self.overflow.iter().map(|t| t.len()).sum::<usize>()
    }
}

/// The complete M1 fixup plan.
#[derive(Debug, Clone)]
pub struct FixupPlan {
    /// `LC_DYLD_CHAINED_FIXUPS` payload bytes (header | starts | empty
    /// import table | empty name blob).
    pub payload: Vec<u8>,
    /// File offset where the payload lands in `__LINKEDIT` (patched by the
    /// layout pass).
    pub payload_off: u64,
    /// Final slot words: `(slot vaddr, encoded word)` sorted by vaddr.
    pub slot_words: Vec<(u64, u64)>,
    /// `__TEXT,__chain_starts` section bytes (static mirror, TDD §7.5):
    /// `u32 pointer_format, u32 chain_count, u32 heads[]` as image offsets.
    pub chain_starts: Vec<u8>,
    /// Number of fixup slots packed.
    pub slot_count: usize,
}

/// Plans all rebase fixups for the image.
///
/// `segments` are the image's `LC_SEGMENT_64` entries in command order as
/// `(vmaddr, vmsize, fileoff)`; each slot lands in the segment containing
/// its vaddr. `image_base` is `__PAGEZERO` vmsize (the constant-delta base);
/// `page_size` the chain-walk page size (16 KiB on arm64).
///
/// # Errors
/// [`LinkError::Layout`] on slots outside any segment, misaligned slots, or
/// targets beyond the 44-bit field.
pub fn plan_fixups(
    mut slots: Vec<FixupSlot>,
    segments: &[(u64, u64, u64)],
    image_base: u64,
    page_size: u64,
) -> Result<FixupPlan, LinkError> {
    slots.sort_by_key(|s| s.vaddr);
    for s in &slots {
        if s.vaddr % 8 != 0 {
            return Err(LinkError::Layout {
                message: format!("fixup slot at {:#x} is not 8-byte aligned", s.vaddr),
            });
        }
    }

    // ---- group slots per segment ----------------------------------------
    let mut per_segment: Vec<Vec<FixupSlot>> = vec![Vec::new(); segments.len()];
    for s in &slots {
        let seg_i = segments
            .iter()
            .position(|&(vm, vmsz, _)| s.vaddr >= vm && s.vaddr < vm + vmsz)
            .ok_or(LinkError::Layout {
                message: format!("fixup slot at {:#x} is outside every segment", s.vaddr),
            })?;
        per_segment[seg_i].push(*s);
    }

    // ---- pack chains per segment (independent; TDD §7.4) -----------------
    let mut chains: Vec<SegmentChains> = Vec::with_capacity(segments.len());
    let mut total_heads = 0usize;
    for (seg_i, seg_slots) in per_segment.iter().enumerate() {
        let (vmaddr, vmsize, _fileoff) = segments[seg_i];
        let mut seg = SegmentChains::default();
        if !seg_slots.is_empty() {
            let page_count = vmsize.div_ceil(page_size).max(1) as usize;
            let mut pages: Vec<Vec<PackingSlot>> = vec![Vec::new(); page_count];
            for s in seg_slots {
                let rel = s.vaddr - vmaddr;
                let page = (rel / page_size) as usize;
                let off_in_page = (rel % page_size) as u32;
                let image_off = s.target_vaddr - image_base;
                pages[page].push(PackingSlot {
                    page_off: off_in_page,
                    next: 0,
                    word_base: rebase_word(image_off, 0)?,
                });
            }
            for page in &mut pages {
                page.sort_by_key(|p| p.page_off);
            }

            let mut overflow_heads: Vec<Vec<u16>> = Vec::new();
            let mut page_start: Vec<u16> = Vec::with_capacity(page_count);
            for (page_i, page) in pages.iter().enumerate() {
                if page.is_empty() {
                    page_start.push(DYLD_CHAINED_PTR_START_NONE);
                    continue;
                }
                let mut page = page.clone();
                let heads = pack_page(&mut page);
                for slot in &page {
                    let vaddr = vmaddr + page_i as u64 * page_size + u64::from(slot.page_off);
                    seg.slot_words
                        .push((vaddr, slot.word_base | u64::from(slot.next) << 51));
                }
                if heads.len() == 1 {
                    page_start.push(heads[0]);
                } else {
                    // Multi-start (TDD §7.4): the marker indexes an overflow
                    // table appended after the page_start array.
                    overflow_heads.push(heads.clone());
                    page_start.push(DYLD_CHAINED_PTR_START_MULTI);
                }
                // Head slots: `pack_page` returns the chain starts in
                // ascending page-offset order.
                for h in heads {
                    let head_vaddr = vmaddr + page_i as u64 * page_size + u64::from(h);
                    seg.head_image_offs.push((head_vaddr - image_base) as u32);
                }
            }
            seg.page_start = page_start;
            seg.overflow = overflow_heads
                .iter()
                .map(|heads| {
                    let mut b = Vec::with_capacity(2 + heads.len() * 2);
                    b.extend_from_slice(&(heads.len() as u16).to_le_bytes());
                    for &off in heads {
                        b.extend_from_slice(&off.to_le_bytes());
                    }
                    b
                })
                .collect();
            total_heads += seg.head_image_offs.len();
        }
        chains.push(seg);
    }

    // ---- payload assembly -------------------------------------------------
    // header (28 B padded to 32) | starts_in_image | per-segment records
    // (each 8-aligned) | imports (empty) | name blob (empty)
    let starts_offset: usize = 32;
    let seg_count = segments.len() as u32;
    let image_record_len = 4 + 4 * segments.len();

    // Phase 1: record offsets.
    let mut record_offsets = vec![0u32; segments.len()];
    let mut cursor = starts_offset + image_record_len;
    for (i, seg) in chains.iter().enumerate() {
        if seg.page_start.is_empty() {
            continue;
        }
        cursor = (cursor + 7) & !7;
        record_offsets[i] = (cursor - starts_offset) as u32;
        cursor += seg.record_size();
    }

    let mut payload: Vec<u8> = vec![0u8; cursor];
    payload[0..4].copy_from_slice(&0u32.to_le_bytes()); // fixups_version
    payload[4..8].copy_from_slice(&(starts_offset as u32).to_le_bytes());
    payload[8..12].copy_from_slice(&(cursor as u32).to_le_bytes()); // imports_offset (empty)
    payload[12..16].copy_from_slice(&(cursor as u32).to_le_bytes()); // symbols_offset (empty)
    payload[16..20].copy_from_slice(&0u32.to_le_bytes()); // imports_count
    payload[20..24].copy_from_slice(&DYLD_CHAINED_IMPORT_ADDEND.to_le_bytes());
    payload[24..28].copy_from_slice(&0u32.to_le_bytes()); // symbols_format (uncompressed)
    payload[starts_offset..starts_offset + 4].copy_from_slice(&seg_count.to_le_bytes());
    for (i, off) in record_offsets.iter().enumerate() {
        let at = starts_offset + 4 + i * 4;
        payload[at..at + 4].copy_from_slice(&off.to_le_bytes());
    }
    for (i, seg) in chains.iter().enumerate() {
        if seg.page_start.is_empty() {
            continue;
        }
        let (_vmaddr, _vmsize, fileoff) = segments[i];
        let at = starts_offset + record_offsets[i] as usize;
        payload[at..at + 4].copy_from_slice(&(seg.record_size() as u32).to_le_bytes());
        payload[at + 4..at + 6].copy_from_slice(&(page_size as u16).to_le_bytes());
        payload[at + 6..at + 8].copy_from_slice(&DYLD_CHAINED_PTR_64_OFFSET.to_le_bytes());
        // segment_offset is image-base-relative; under the constant-delta
        // contract that equals the segment's file offset (the verifier
        // asserts exactly this).
        payload[at + 8..at + 16].copy_from_slice(&fileoff.to_le_bytes());
        payload[at + 16..at + 20].copy_from_slice(&0u32.to_le_bytes()); // max_valid_pointer
        payload[at + 20..at + 22].copy_from_slice(&(seg.page_start.len() as u16).to_le_bytes());
        let mut w = at + 22;
        let mut marker_seen = 0usize;
        let page_start_end = 22 + 2 * seg.page_start.len();
        for (pi, &ps) in seg.page_start.iter().enumerate() {
            if ps == DYLD_CHAINED_PTR_START_MULTI {
                let mut toff = 0usize;
                for t in 0..marker_seen {
                    toff += seg.overflow[t].len();
                }
                let marker = DYLD_CHAINED_PTR_START_MULTI
                    | u16::try_from(page_start_end + toff).map_err(|_| LinkError::Layout {
                        message: "multi-start overflow table beyond 15-bit marker".into(),
                    })? & DYLD_CHAINED_PTR_START_MULTI_MASK;
                payload[w..w + 2].copy_from_slice(&marker.to_le_bytes());
                marker_seen += 1;
            } else {
                payload[w..w + 2].copy_from_slice(&ps.to_le_bytes());
            }
            let _ = pi;
            w += 2;
        }
        for table in &seg.overflow {
            payload[w..w + table.len()].copy_from_slice(table);
            w += table.len();
        }
    }

    // ---- outputs -----------------------------------------------------------
    let mut slot_words: Vec<(u64, u64)> = Vec::new();
    for seg in &chains {
        slot_words.extend_from_slice(&seg.slot_words);
    }
    slot_words.sort_by_key(|(v, _)| *v);

    let mut chain_starts = Vec::with_capacity(8 + total_heads * 4);
    chain_starts.extend_from_slice(&(u32::from(DYLD_CHAINED_PTR_64_OFFSET)).to_le_bytes());
    chain_starts.extend_from_slice(&(total_heads as u32).to_le_bytes());
    for seg in &chains {
        for h in &seg.head_image_offs {
            chain_starts.extend_from_slice(&h.to_le_bytes());
        }
    }

    Ok(FixupPlan {
        payload,
        payload_off: 0,
        slot_words,
        chain_starts,
        slot_count: slots.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::{FixupSlot, MAX_CHAIN_STRIDE_BYTES, PackingSlot, pack_page, plan_fixups};
    use pgr_format::consts::{
        DYLD_CHAINED_PTR_64_OFFSET, DYLD_CHAINED_PTR_START_MULTI, DYLD_CHAINED_PTR_START_NONE,
        PAGE_SIZE_16K,
    };
    use pgr_format::fixups::{
        ChainWord64, page_chain_starts, parse_header, parse_imports, parse_starts_in_image,
        parse_starts_in_segment,
    };

    fn slot(page_off: u32) -> PackingSlot {
        PackingSlot {
            page_off,
            next: 0,
            word_base: 0,
        }
    }

    #[test]
    fn one_chain_across_dense_slots() {
        let mut page = vec![slot(0x10), slot(0x18), slot(0x20), slot(0x28)];
        let heads = pack_page(&mut page);
        assert_eq!(heads, vec![0x10]);
        assert_eq!(page[0].next, 2, "0x10 -> 0x18 is 8 bytes = 2 strides");
        assert_eq!(page[1].next, 2);
        assert_eq!(page[2].next, 2);
        assert_eq!(page[3].next, 0, "chain terminates");
    }

    #[test]
    fn stride_overflow_starts_a_fresh_chain() {
        // 0x10, then a slot beyond MAX_CHAIN_STRIDE_BYTES: new chain.
        let far = 0x10 + MAX_CHAIN_STRIDE_BYTES as u32 + 8;
        let mut page = vec![slot(0x10), slot(far)];
        let heads = pack_page(&mut page);
        assert_eq!(heads, vec![0x10, far as u16]);
        assert_eq!(page[0].next, 0);
        assert_eq!(page[1].next, 0);
    }

    #[test]
    fn max_stride_is_accepted() {
        let far = 0x10 + MAX_CHAIN_STRIDE_BYTES as u32;
        let mut page = vec![slot(0x10), slot(far)];
        let heads = pack_page(&mut page);
        assert_eq!(heads, vec![0x10]);
        assert_eq!(page[0].next, 0xFFF);
        assert_eq!(page[1].next, 0);
    }

    #[test]
    fn gaps_smaller_than_four_bytes_split() {
        // 8-aligned slots are always >= 4 apart, but the packer guards
        // anyway (misaligned adversarial input).
        let mut page = vec![slot(0x10), slot(0x11)];
        let heads = pack_page(&mut page);
        assert_eq!(heads, vec![0x10, 0x11]);
    }

    #[test]
    fn payload_roundtrips_through_the_format_parser() {
        // Segment 0 (__TEXT at fileoff 0, 1 page) empty; segment 1 (__DATA
        // at fileoff 0x4000) with two dense slots on page 0.
        let slots = vec![
            FixupSlot {
                vaddr: 0x1_0000_4000,
                target_vaddr: 0x1_0000_0000,
            },
            FixupSlot {
                vaddr: 0x1_0000_4008,
                target_vaddr: 0x1_0000_1000,
            },
        ];
        let segments = [
            (0x1_0000_0000, PAGE_SIZE_16K, 0),
            (0x1_0000_4000, PAGE_SIZE_16K, 0x4000),
        ];
        let plan = plan_fixups(slots, &segments, 0x1_0000_0000, PAGE_SIZE_16K).unwrap();

        let hdr = parse_header(&plan.payload).unwrap();
        assert_eq!(hdr.imports_count, 0);
        let starts = parse_starts_in_image(&plan.payload, hdr.starts_offset as usize).unwrap();
        assert_eq!(starts.seg_count, 2);
        assert_eq!(starts.seg_info_offset[0], 0, "no fixups in __TEXT");
        assert!(starts.seg_info_offset[1] != 0);
        let rec = parse_starts_in_segment(
            &plan.payload,
            hdr.starts_offset as usize + starts.seg_info_offset[1] as usize,
        )
        .unwrap();
        assert_eq!(rec.pointer_format, DYLD_CHAINED_PTR_64_OFFSET);
        assert_eq!(rec.page_size, PAGE_SIZE_16K as u16);
        assert_eq!(rec.segment_offset, 0x4000);
        assert_eq!(rec.page_count, 1);
        let heads = page_chain_starts(
            &plan.payload,
            hdr.starts_offset as usize + starts.seg_info_offset[1] as usize,
            &rec,
            0,
        )
        .unwrap();
        assert_eq!(heads, vec![0], "first slot sits at page offset 0");

        // The slot words decode as rebases to the expected image offsets.
        assert_eq!(plan.slot_words.len(), 2);
        let w0 = ChainWord64::new(plan.slot_words[0].1);
        assert!(!w0.is_bind());
        assert_eq!(w0.rebase_target(), 0);
        assert_eq!(w0.rebase_high8(), 0);
        assert_eq!(w0.next(), 2, "0x4000 -> 0x4008: 8 bytes = 2 strides");
        let w1 = ChainWord64::new(plan.slot_words[1].1);
        assert_eq!(w1.rebase_target(), 0x1000);
        assert_eq!(w1.next(), 0);

        // Empty imports parse cleanly.
        let imports = parse_imports(&plan.payload, &hdr).unwrap();
        assert!(imports.is_empty());
    }

    #[test]
    fn dense_page_packs_one_chain_with_every_slot() {
        // Within a 16 KiB page every pair of 8-aligned slots is at most
        // 0x3FF8 = 16 376 bytes apart, under the 16 380-byte stride bound,
        // so all four slots join one chain (multi-start is unreachable for
        // 64-bit formats on 16 KiB pages — kept for 32-bit/arm64e later).
        let slots = vec![
            FixupSlot {
                vaddr: 0x1_0000_4010,
                target_vaddr: 0x1_0000_0000,
            },
            FixupSlot {
                vaddr: 0x1_0000_4018,
                target_vaddr: 0x1_0000_0000,
            },
            FixupSlot {
                vaddr: 0x1_0000_4100,
                target_vaddr: 0x1_0000_0000,
            },
            FixupSlot {
                vaddr: 0x1_0000_4108,
                target_vaddr: 0x1_0000_0000,
            },
        ];
        let segments = [(0x1_0000_4000, 2 * PAGE_SIZE_16K, 0x4000)];
        let plan = plan_fixups(slots, &segments, 0x1_0000_0000, PAGE_SIZE_16K).unwrap();

        let hdr = parse_header(&plan.payload).unwrap();
        let starts = parse_starts_in_image(&plan.payload, hdr.starts_offset as usize).unwrap();
        let rec_off = hdr.starts_offset as usize + starts.seg_info_offset[0] as usize;
        let rec = parse_starts_in_segment(&plan.payload, rec_off).unwrap();
        assert_eq!(rec.page_count, 2);
        let heads0 = page_chain_starts(&plan.payload, rec_off, &rec, 0).unwrap();
        assert_eq!(heads0, vec![0x10], "single chain, head at page offset 0x10");
        assert_eq!(rec.page_start[1], DYLD_CHAINED_PTR_START_NONE);
        assert_eq!(plan.slot_words.len(), 4);
        // The chain walks 0x10 -> 0x18 -> 0x100 -> 0x108 -> end.
        assert_eq!(ChainWord64::new(plan.slot_words[0].1).next(), 2);
        assert_eq!(ChainWord64::new(plan.slot_words[2].1).next(), 2);
        assert_eq!(ChainWord64::new(plan.slot_words[3].1).next(), 0);
        let _ = DYLD_CHAINED_PTR_START_MULTI;
    }

    #[test]
    fn chain_starts_mirror_lists_every_head() {
        let slots = vec![
            FixupSlot {
                vaddr: 0x1_0000_4010,
                target_vaddr: 0x1_0000_0000,
            },
            FixupSlot {
                vaddr: 0x1_0000_4018,
                target_vaddr: 0x1_0000_0000,
            },
            FixupSlot {
                vaddr: 0x1_0000_8010,
                target_vaddr: 0x1_0000_0000,
            },
        ];
        let segments = [(0x1_0000_4000, 2 * PAGE_SIZE_16K, 0x4000)];
        let plan = plan_fixups(slots, &segments, 0x1_0000_0000, PAGE_SIZE_16K).unwrap();
        assert_eq!(plan.chain_starts.len(), 8 + 2 * 4);
        let fmt = u32::from_le_bytes(plan.chain_starts[0..4].try_into().unwrap());
        let count = u32::from_le_bytes(plan.chain_starts[4..8].try_into().unwrap());
        assert_eq!(fmt, DYLD_CHAINED_PTR_64_OFFSET as u32);
        assert_eq!(count, 2, "one head on page 0, one on page 1");
        let h0 = u32::from_le_bytes(plan.chain_starts[8..12].try_into().unwrap());
        let h1 = u32::from_le_bytes(plan.chain_starts[12..16].try_into().unwrap());
        assert_eq!(h0, 0x4010, "image offset of the first head");
        assert_eq!(h1, 0x8010, "image offset of the page-1 head");
    }

    #[test]
    fn slots_outside_segments_error() {
        let slots = vec![FixupSlot {
            vaddr: 0x2_0000_0000,
            target_vaddr: 0,
        }];
        let segments = [(0x1_0000_0000, PAGE_SIZE_16K, 0)];
        assert!(plan_fixups(slots, &segments, 0x1_0000_0000, PAGE_SIZE_16K).is_err());
    }

    #[test]
    fn misaligned_slots_error() {
        let slots = vec![FixupSlot {
            vaddr: 0x1_0004_4012,
            target_vaddr: 0,
        }];
        let segments = [(0x1_0000_4000, PAGE_SIZE_16K, 0x4000)];
        assert!(plan_fixups(slots, &segments, 0x1_0000_0000, PAGE_SIZE_16K).is_err());
    }

    #[test]
    fn out_of_range_target_errors() {
        let slots = vec![FixupSlot {
            vaddr: 0x1_0004_4010,
            target_vaddr: 0x10_0000_0000_0000, // > 44 bits
        }];
        let segments = [(0x1_0000_4000, PAGE_SIZE_16K, 0x4000)];
        assert!(plan_fixups(slots, &segments, 0, PAGE_SIZE_16K).is_err());
    }
}

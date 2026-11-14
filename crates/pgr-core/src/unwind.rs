//! The compact-unwind synthesis seam (M34): the input
//! `__LD,__compact_unwind` tables (one 32-byte row per function —
//! [`pgr_format::CompactUnwindEntry`], read by
//! [`pgr_format::read_compact_unwind`]) translate through the placed
//! piece list onto `__TEXT`-relative entries, and this module folds
//! them into the output `__TEXT,__unwind_info` — the section dyld's
//! exception unwinder and every backtrace reader walks
//! (`mach-o/compact_unwind_encoding.h`; the layout below mirrors the
//! header's own field names).
//!
//! The section layout (one exact ordering, the sizes the
//! [`synthesized_size`] planner and the [`synthesize`] builder share
//! so the plan's reservation and the emitted bytes can never drift):
//!
//! ```text
//! unwind_info_section_header                  28 bytes
//! common encodings array                      0 rows (M34: the regular
//!                                             pages carry full encodings;
//!                                             the table joins the M35
//!                                             compressed-page rung)
//! personality array                           4 bytes × first-use rows
//! index                                       12 bytes × (pages + 1) —
//!                                             one per second-level page,
//!                                             plus the terminator (its
//!                                             secondLevelPagesSectionOffset
//!                                             is 0)
//! second-level pages                          8-byte page header + 8 bytes
//!                                             per regular row, ≤ 4096 rows
//!                                             per page
//! lsda index array                            8 bytes × rows, sorted
//! ```
//!
//! Determinism: entries sort by function offset, personalities
//! dedup in first-use order over the sorted stream, and every array
//! size is a pure function of the entry slice — no hash iteration
//! order anywhere. The M34 pages are all [`regular`]: the compressed
//! page family is the next rung (M35), refused by the verifier until
//! it walks.
//!
//! [`regular`]: UNWIND_SECOND_LEVEL_REGULAR

use pgr_format::consts::{
    UNWIND_ARM64_MODE_DWARF, UNWIND_ARM64_MODE_FRAME, UNWIND_ARM64_MODE_FRAME_PAUTH_LR,
    UNWIND_ARM64_MODE_FRAMELESS, UNWIND_ARM64_MODE_MASK, UNWIND_PERSONALITY_MASK,
    UNWIND_SECOND_LEVEL_REGULAR, UNWIND_SECTION_VERSION,
};

/// The maximum number of entries one second-level page carries. The
/// page header's `entryCount` is a `u16`; 4096 keeps every page one
/// fixed-size shape (8-byte rows, 32 KiB content max) and the page
/// split deterministic.
pub const MAX_PAGE_ENTRIES: usize = 4096;

/// The regular-page header's byte width (`kind` u32 + two `u16`s).
const PAGE_HEADER_SIZE: usize = 8;
/// The `unwind_info_section_header`'s byte width (seven `u32` words).
const HEADER_SIZE: usize = 28;
/// The `unwind_info_section_header_index_entry`'s byte width.
const INDEX_ENTRY_SIZE: usize = 12;
/// The `unwind_info_section_header_lsda_index_entry`'s byte width.
const LSDA_ENTRY_SIZE: usize = 8;
/// One regular second-level entry's byte width.
const REGULAR_ENTRY_SIZE: usize = 8;

/// One translated unwind row: every offset is output
/// `__TEXT`-relative (the values the section's entries carry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindEntry {
    /// The function's start, `__TEXT`-relative.
    pub function_offset: u32,
    /// The function's length in bytes.
    pub range_length: u32,
    /// The `compact_unwind_encoding_t` word, personality bits still
    /// carrying the pre-index form the carriage translated from (the
    /// synthesizer rewrites them into the output personality array's
    /// one-based indices).
    pub encoding: u32,
    /// The personality function's `__TEXT`-relative offset, 0 = none.
    pub personality_offset: u32,
    /// The LSDA data's `__TEXT`-relative offset, 0 = none.
    pub lsda_offset: u32,
}

/// The synthesized `__unwind_info` section: the bytes plus the shape
/// counts a build system can plan with before any link runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindInfo {
    /// The section bytes (the `__TEXT,__unwind_info` content).
    pub bytes: Vec<u8>,
    /// The regular-page entry count.
    pub entry_count: usize,
    /// The second-level page count (the index carries `page_count + 1`
    /// entries — one terminator).
    pub page_count: usize,
    /// The common-encodings array count (0 under the M34 regular-page
    /// shape; the array joins the M35 compressed rung).
    pub common_encoding_count: usize,
    /// The personality-array count (first-use order).
    pub personality_count: usize,
    /// The LSDA-index count.
    pub lsda_count: usize,
}

/// A [`synthesize`] refusal: the shape and its identity are named, never
/// just the verdict. The carriage filters these shapes before calling
/// (dead rows drop, ranges validate at parse) — a refusal here means a
/// caller synthesized a table no linker plan can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SynthesisError {
    /// An empty entry slice synthesizes nothing — the entry-free
    /// corpus plans the pre-M34 bytes (no section at all).
    #[error("no unwind entries: an empty table plans no section at all")]
    NoEntries,
    /// Entry `index` carries a zero-length range — a function row that
    /// annotates no bytes is the malformed shape the parse refuses.
    #[error("unwind entry {index} carries a zero-length range")]
    ZeroLengthRange {
        /// The offending entry's position in the (unsorted) slice.
        index: usize,
    },
    /// A function offset that is not 4-byte aligned — arm64 functions
    /// sit on 4-byte boundaries; the section's consumers decode
    /// offsets at that granularity.
    #[error(
        "unwind entry function offset {offset:#x} is not 4-byte aligned (arm64 functions sit on 4-byte boundaries)"
    )]
    UnalignedFunctionOffset {
        /// The offending offset.
        offset: u32,
    },
    /// Two entries name the same function offset — the section's
    /// consumers binary-search the rows; a duplicate is a malformed
    /// table (the ICF fold drops the duplicate before this runs).
    #[error("two unwind entries name function offset {offset:#x}")]
    DuplicateFunctionOffset {
        /// The duplicated offset.
        offset: u32,
    },
    /// The encoding's arm64 mode nibble names no arm64 unwinder mode
    /// (the x86 families ride the same bit positions with different
    /// values; a table carrying one on an arm64 image is the
    /// cross-architecture lie the verifier gates).
    #[error(
        "encoding {encoding:#010x} names no arm64 unwind mode (the arm64 modes are frameless, DWARF, frame and frame-with-authenticated-LR)"
    )]
    InvalidArm64EncodingMode {
        /// The offending encoding word.
        encoding: u32,
    },
}

/// The arm64 mode nibbles the unwinder defines (the modes the
/// verifier and the synthesizer both accept).
const ARM64_MODES: [u32; 4] = [
    UNWIND_ARM64_MODE_FRAMELESS,
    UNWIND_ARM64_MODE_DWARF,
    UNWIND_ARM64_MODE_FRAME,
    UNWIND_ARM64_MODE_FRAME_PAUTH_LR,
];

/// The exact section size for the shape the counts name (the planner
/// the layout's convergence reads — one formula with [`synthesize`]'s
/// builder, so the reserved slot and the emitted bytes agree).
///
/// Zero when the corpus keeps no entries (the pre-M34 default: no
/// section).
#[must_use]
pub fn synthesized_size(entries: usize, personalities: usize, lsdas: usize) -> usize {
    if entries == 0 {
        return 0;
    }
    let pages = entries.div_ceil(MAX_PAGE_ENTRIES);
    HEADER_SIZE
        + personalities * 4
        + (pages + 1) * INDEX_ENTRY_SIZE
        + pages * PAGE_HEADER_SIZE
        + entries * REGULAR_ENTRY_SIZE
        + lsdas * LSDA_ENTRY_SIZE
}

/// Folds the translated entries into the `__unwind_info` section bytes.
/// Entries sort by function offset; personalities dedup in first-use
/// order over the sorted stream; the encoding's personality bits
/// rewrite into the array's one-based indices.
///
/// # Errors
/// [`SynthesisError`] when the table carries a shape no linker plan
/// can hold (zero-length ranges, unaligned or duplicate offsets, a
/// non-arm64 mode nibble).
pub fn synthesize(entries: &[UnwindEntry]) -> Result<UnwindInfo, SynthesisError> {
    if entries.is_empty() {
        return Err(SynthesisError::NoEntries);
    }
    let mut sorted: Vec<&UnwindEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| e.function_offset);
    for (i, e) in sorted.iter().enumerate() {
        if e.range_length == 0 {
            return Err(SynthesisError::ZeroLengthRange { index: i });
        }
        if e.function_offset % 4 != 0 {
            return Err(SynthesisError::UnalignedFunctionOffset {
                offset: e.function_offset,
            });
        }
        if i > 0 && sorted[i - 1].function_offset == e.function_offset {
            return Err(SynthesisError::DuplicateFunctionOffset {
                offset: e.function_offset,
            });
        }
        if !ARM64_MODES.contains(&(e.encoding & UNWIND_ARM64_MODE_MASK)) {
            return Err(SynthesisError::InvalidArm64EncodingMode {
                encoding: e.encoding,
            });
        }
    }

    // Personalities dedup in first-use order over the sorted stream.
    let mut personalities: Vec<u32> = Vec::new();
    for e in &sorted {
        if e.personality_offset != 0 && !personalities.contains(&e.personality_offset) {
            personalities.push(e.personality_offset);
        }
    }
    let personality_index = |offset: u32| -> u32 {
        if offset == 0 {
            0
        } else {
            // One-based; the search is exact (the pass above collected
            // every referenced offset).
            personalities
                .iter()
                .position(|p| *p == offset)
                .map_or(0, |p| p as u32 + 1)
        }
    };

    let lsdas: Vec<(u32, u32)> = sorted
        .iter()
        .filter(|e| e.lsda_offset != 0)
        .map(|e| (e.function_offset, e.lsda_offset))
        .collect();

    let pages: Vec<&[&UnwindEntry]> = sorted.chunks(MAX_PAGE_ENTRIES).collect();
    let size = synthesized_size(sorted.len(), personalities.len(), lsdas.len());
    debug_assert_eq!(
        size,
        HEADER_SIZE
            + personalities.len() * 4
            + (pages.len() + 1) * INDEX_ENTRY_SIZE
            + pages.len() * PAGE_HEADER_SIZE
            + sorted.len() * REGULAR_ENTRY_SIZE
            + lsdas.len() * LSDA_ENTRY_SIZE
    );
    let mut out = Vec::with_capacity(size);

    // ---- header --------------------------------------------------------------
    let personality_off = HEADER_SIZE;
    let index_off = personality_off + personalities.len() * 4;
    let page_off = index_off + (pages.len() + 1) * INDEX_ENTRY_SIZE;
    let lsda_off = page_off
        + pages
            .iter()
            .map(|p| PAGE_HEADER_SIZE + p.len() * REGULAR_ENTRY_SIZE)
            .sum::<usize>();
    out.extend_from_slice(&UNWIND_SECTION_VERSION.to_le_bytes());
    out.extend_from_slice(&(HEADER_SIZE as u32).to_le_bytes()); // common encodings at 28
    out.extend_from_slice(&0u32.to_le_bytes()); // common encodings count (M34)
    out.extend_from_slice(&(personality_off as u32).to_le_bytes());
    out.extend_from_slice(&(personalities.len() as u32).to_le_bytes());
    out.extend_from_slice(&(index_off as u32).to_le_bytes());
    out.extend_from_slice(&((pages.len() + 1) as u32).to_le_bytes());

    // ---- personalities --------------------------------------------------------
    for p in &personalities {
        out.extend_from_slice(&p.to_le_bytes());
    }

    // ---- index ----------------------------------------------------------------
    let last_end = sorted[sorted.len() - 1]
        .function_offset
        .saturating_add(sorted[sorted.len() - 1].range_length);
    let mut page_cursor = page_off;
    for page in &pages {
        out.extend_from_slice(&page[0].function_offset.to_le_bytes());
        out.extend_from_slice(&(page_cursor as u32).to_le_bytes());
        out.extend_from_slice(&(lsda_off as u32).to_le_bytes());
        page_cursor += PAGE_HEADER_SIZE + page.len() * REGULAR_ENTRY_SIZE;
    }
    // The terminator: coverage ends at the last row's end; its page
    // pointer is the absent sentinel (`0`, the unwind-info convention).
    out.extend_from_slice(&last_end.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(lsda_off as u32).to_le_bytes());

    // ---- second-level pages (regular) -----------------------------------------
    for page in &pages {
        out.extend_from_slice(&UNWIND_SECOND_LEVEL_REGULAR.to_le_bytes());
        out.extend_from_slice(&(PAGE_HEADER_SIZE as u16).to_le_bytes());
        out.extend_from_slice(&(page.len() as u16).to_le_bytes());
        for e in *page {
            let encoding = (e.encoding & !UNWIND_PERSONALITY_MASK)
                | (personality_index(e.personality_offset) << 28);
            out.extend_from_slice(&e.function_offset.to_le_bytes());
            out.extend_from_slice(&encoding.to_le_bytes());
        }
    }

    // ---- lsda index array -------------------------------------------------------
    for (f, l) in &lsdas {
        out.extend_from_slice(&f.to_le_bytes());
        out.extend_from_slice(&l.to_le_bytes());
    }

    debug_assert_eq!(out.len(), size);
    tracing::debug!(
        entries = sorted.len(),
        pages = pages.len(),
        personalities = personalities.len(),
        lsdas = lsdas.len(),
        bytes = size,
        "the unwind-info section synthesizes"
    );
    Ok(UnwindInfo {
        bytes: out,
        entry_count: sorted.len(),
        page_count: pages.len(),
        common_encoding_count: 0,
        personality_count: personalities.len(),
        lsda_count: lsdas.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ARM64_MODES, MAX_PAGE_ENTRIES, SynthesisError, UnwindEntry, UnwindInfo, synthesize,
        synthesized_size,
    };
    use pgr_format::consts::{
        UNWIND_ARM64_MODE_DWARF, UNWIND_ARM64_MODE_FRAME, UNWIND_ARM64_MODE_FRAMELESS,
        UNWIND_SECOND_LEVEL_REGULAR,
    };

    fn entry(offset: u32, len: u32, encoding: u32) -> UnwindEntry {
        UnwindEntry {
            function_offset: offset,
            range_length: len,
            encoding,
            personality_offset: 0,
            lsda_offset: 0,
        }
    }

    #[test]
    fn the_size_planner_and_the_builder_agree() {
        for n in [1usize, 2, 16, MAX_PAGE_ENTRIES, MAX_PAGE_ENTRIES + 1] {
            let entries: Vec<UnwindEntry> = (0..n)
                .map(|f| entry((f * 4) as u32, 4, UNWIND_ARM64_MODE_FRAME))
                .collect();
            let info = synthesize(&entries).expect("the table synthesizes");
            assert_eq!(
                info.bytes.len(),
                synthesized_size(n, 0, 0),
                "the planner and the builder agree at {n} entries"
            );
            assert_eq!(info.page_count, n.div_ceil(MAX_PAGE_ENTRIES));
        }
    }

    #[test]
    fn the_header_names_the_arrays_in_order() {
        let info = synthesize(&[entry(0, 4, UNWIND_ARM64_MODE_FRAME)])
            .expect("the single-row table synthesizes");
        let b = &info.bytes;
        let rd = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        assert_eq!(rd(0), 1, "UNWIND_SECTION_VERSION");
        assert_eq!(rd(4), 28, "common encodings at 28");
        assert_eq!(rd(8), 0, "no common encodings under the M34 shape");
        assert_eq!(rd(12), 28, "the personality array rides the header");
        assert_eq!(rd(16), 0, "no personalities");
        assert_eq!(rd(20), 28, "the index rides the (empty) arrays");
        assert_eq!(rd(24), 2, "one page + the terminator");
        // index[0]: the page; index[1]: the terminator (page pointer 0).
        assert_eq!(rd(28), 0, "the page covers function 0");
        assert_eq!(rd(32), 52, "the page starts at 28 + 2×12");
        assert_eq!(rd(44), 0, "the terminator carries no page");
    }

    #[test]
    fn the_regular_page_decodes() {
        let info = synthesize(&[
            entry(0, 4, UNWIND_ARM64_MODE_FRAME),
            entry(8, 4, UNWIND_ARM64_MODE_FRAMELESS | (0x20 << 12)),
            entry(0x10, 4, UNWIND_ARM64_MODE_DWARF | 0x42),
        ])
        .expect("the table synthesizes");
        let b = &info.bytes;
        let page = u32::from_le_bytes([b[32], b[33], b[34], b[35]]) as usize;
        assert_eq!(
            u32::from_le_bytes([b[page], b[page + 1], b[page + 2], b[page + 3]]),
            UNWIND_SECOND_LEVEL_REGULAR
        );
        assert_eq!(
            u16::from_le_bytes([b[page + 4], b[page + 5]]),
            8,
            "entries at +8"
        );
        assert_eq!(u16::from_le_bytes([b[page + 6], b[page + 7]]), 3);
        let rd32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        assert_eq!(rd32(page + 8), 0);
        assert_eq!(rd32(page + 16), 8);
        assert_eq!(rd32(page + 24), 0x10);
    }

    #[test]
    fn personalities_dedup_in_first_use_order() {
        let info = synthesize(&[
            UnwindEntry {
                function_offset: 0,
                range_length: 4,
                encoding: UNWIND_ARM64_MODE_FRAME,
                personality_offset: 0x1000,
                lsda_offset: 0,
            },
            UnwindEntry {
                function_offset: 8,
                range_length: 4,
                encoding: UNWIND_ARM64_MODE_FRAME,
                personality_offset: 0x2000,
                lsda_offset: 0,
            },
            UnwindEntry {
                function_offset: 0x10,
                range_length: 4,
                encoding: UNWIND_ARM64_MODE_FRAME,
                personality_offset: 0x1000,
                lsda_offset: 0,
            },
        ])
        .expect("the table synthesizes");
        assert_eq!(info.personality_count, 2, "the second use dedups");
        let b = &info.bytes;
        let rd32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        assert_eq!(rd32(28), 0x1000, "first use order");
        assert_eq!(rd32(32), 0x2000);
        let page = rd32(40) as usize;
        assert_eq!(
            rd32(page + 12) >> 28,
            1,
            "the first entry's encoding names index 1"
        );
        assert_eq!(
            rd32(page + 20) >> 28,
            2,
            "the second entry's encoding names index 2"
        );
        assert_eq!(
            rd32(page + 28) >> 28,
            1,
            "the third entry reuses the first personality's index"
        );
    }

    #[test]
    fn the_lsda_rows_ride_sorted() {
        let info = synthesize(&[
            UnwindEntry {
                function_offset: 0,
                range_length: 4,
                encoding: UNWIND_ARM64_MODE_FRAME,
                personality_offset: 0,
                lsda_offset: 0x100,
            },
            UnwindEntry {
                function_offset: 8,
                range_length: 4,
                encoding: UNWIND_ARM64_MODE_FRAME,
                personality_offset: 0,
                lsda_offset: 0x200,
            },
        ])
        .expect("the table synthesizes");
        assert_eq!(info.lsda_count, 2);
        let b = &info.bytes;
        let rd32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let lsda_off = rd32(36) as usize;
        assert_eq!(rd32(lsda_off), 0);
        assert_eq!(rd32(lsda_off + 4), 0x100);
        assert_eq!(rd32(lsda_off + 8), 8);
        assert_eq!(rd32(lsda_off + 12), 0x200);
    }

    #[test]
    fn the_refusals_name_the_shape() {
        assert!(matches!(synthesize(&[]), Err(SynthesisError::NoEntries)));
        let zero = [entry(0, 0, UNWIND_ARM64_MODE_FRAME)];
        assert!(matches!(
            synthesize(&zero),
            Err(SynthesisError::ZeroLengthRange { index: 0 })
        ));
        let unaligned = [entry(2, 4, UNWIND_ARM64_MODE_FRAME)];
        assert!(matches!(
            synthesize(&unaligned),
            Err(SynthesisError::UnalignedFunctionOffset { offset: 2 })
        ));
        let dup = [
            entry(0, 4, UNWIND_ARM64_MODE_FRAME),
            entry(0, 4, UNWIND_ARM64_MODE_FRAME),
        ];
        assert!(matches!(
            synthesize(&dup),
            Err(SynthesisError::DuplicateFunctionOffset { offset: 0 })
        ));
        let x86_mode = [entry(0, 4, 0x0100_0000)];
        let err = synthesize(&x86_mode).expect_err("the x86 mode refuses");
        assert!(err.to_string().contains("arm64"));
    }

    #[test]
    fn the_mode_table_is_the_arm64_set() {
        assert_eq!(ARM64_MODES.len(), 4);
        assert!(ARM64_MODES.contains(&UNWIND_ARM64_MODE_FRAMELESS));
        assert!(ARM64_MODES.contains(&UNWIND_ARM64_MODE_DWARF));
        assert!(ARM64_MODES.contains(&UNWIND_ARM64_MODE_FRAME));
        assert!(
            !ARM64_MODES.contains(&0),
            "mode 0 is the x86 reserved shape"
        );
    }

    #[test]
    fn the_unsorted_input_sorts() {
        let entries = [
            entry(0x10, 4, UNWIND_ARM64_MODE_FRAME),
            entry(0, 4, UNWIND_ARM64_MODE_FRAME),
            entry(8, 4, UNWIND_ARM64_MODE_FRAME),
        ];
        let info = synthesize(&entries).expect("the unsorted table synthesizes");
        let sorted = synthesize(&[
            entry(0, 4, UNWIND_ARM64_MODE_FRAME),
            entry(8, 4, UNWIND_ARM64_MODE_FRAME),
            entry(0x10, 4, UNWIND_ARM64_MODE_FRAME),
        ])
        .expect("the sorted table synthesizes");
        assert_eq!(info, sorted, "the section bytes are order-normalized");
    }

    #[test]
    fn the_counts_ride_the_info() {
        let info = synthesize(&[
            entry(0, 4, UNWIND_ARM64_MODE_FRAME),
            entry(8, 4, UNWIND_ARM64_MODE_FRAME),
        ])
        .expect("the table synthesizes");
        assert_eq!(
            info,
            UnwindInfo {
                bytes: info.bytes.clone(),
                entry_count: 2,
                page_count: 1,
                common_encoding_count: 0,
                personality_count: 0,
                lsda_count: 0,
            }
        );
    }
}

//! The compact-unwind synthesis seam (M34, M35): the input
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
//! [`synthesized_size_shape`] planner and the [`synthesize`] builder
//! share so the plan's reservation and the emitted bytes can never
//! drift):
//!
//! ```text
//! unwind_info_section_header                  28 bytes
//! common encodings array                      4 bytes × rows — the
//!                                             table's distinct final
//!                                             words in first-use
//!                                             order, capped at the
//!                                             8-bit index space
//!                                             (M35)
//! personality array                           4 bytes × first-use rows
//! index                                       12 bytes × (pages + 1) —
//!                                             one per second-level page,
//!                                             plus the terminator (its
//!                                             secondLevelPagesSectionOffset
//!                                             is 0)
//! second-level pages                          regular: 8-byte header +
//!                                             8 bytes per row;
//!                                             compressed: 12-byte
//!                                             header + 4 bytes per row
//!                                             (M35); each page carries
//!                                             ≤ 4096 rows
//! lsda index array                            8 bytes × rows, sorted
//! ```
//!
//! The compressed rung (M35): a row rides the compressed family
//! (`UNWIND_SECOND_LEVEL_COMPRESSED`) exactly when it qualifies — its
//! function offset fits the compressed entry's 24-bit field and its
//! final encoding word (the personality index folded in) sits in the
//! common encodings array — and consecutive same-family rows share a
//! second-level page (a page never mixes families; the family is one
//! kind word the page header carries). A row past the 16 MiB `__TEXT`
//! mark or whose word sits past the encoding cap rides the regular
//! family (the M34 shape), so a table past either bound plans the
//! pre-M35 bytes. The common array gathers the distinct final words
//! in first-use order over the offset-qualifying stream, capped at
//! the 8-bit index space — every row it carries is referenced by at
//! least one qualifying row, so the array carries no dead rows, and
//! the compressed page's own page-local encodings array rides empty
//! (the two-tier decode libunwind runs answers at tier one; the
//! verifier walks both tiers).
//!
//! Determinism: entries sort by function offset, personalities
//! dedup in first-use order over the sorted stream, the common
//! array's rows and every page's family are pure functions of the
//! entry slice — no hash iteration order anywhere. The verifier's
//! `unwind` family walks both page families.

use pgr_format::consts::{
    UNWIND_ARM64_MODE_DWARF, UNWIND_ARM64_MODE_FRAME, UNWIND_ARM64_MODE_FRAME_PAUTH_LR,
    UNWIND_ARM64_MODE_FRAMELESS, UNWIND_ARM64_MODE_MASK,
    UNWIND_INFO_COMPRESSED_ENTRY_ENCODING_INDEX_SHIFT,
    UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET_MASK, UNWIND_PERSONALITY_MASK,
    UNWIND_SECOND_LEVEL_COMPRESSED, UNWIND_SECOND_LEVEL_REGULAR, UNWIND_SECTION_VERSION,
};

/// The maximum number of entries one second-level page carries. The
/// page header's `entryCount` is a `u16`; 4096 keeps every page one
/// fixed-size shape (8-byte rows, 32 KiB content max) and the page
/// split deterministic.
pub const MAX_PAGE_ENTRIES: usize = 4096;

/// The maximum number of rows the common encodings array carries —
/// the compressed entry's `encodingIndex` is 8 bits (`(entry >> 24) &
/// 0xFF`), so index 256 has no encoding to name. Words past the cap
/// stay out of the array, and the rows that name them keep their
/// pages regular.
pub const MAX_COMMON_ENCODINGS: usize = 256;

/// The regular-page header's byte width (`kind` u32 + two `u16`s).
const PAGE_HEADER_SIZE: usize = 8;
/// The compressed-page header's byte width (`kind` u32 + four `u16`s
/// — the entry array's offset/count, then the page-local encodings
/// array's offset/count).
const COMPRESSED_PAGE_HEADER_SIZE: usize = 12;
/// The `unwind_info_section_header`'s byte width (seven `u32` words).
const HEADER_SIZE: usize = 28;
/// The `unwind_info_section_header_index_entry`'s byte width.
const INDEX_ENTRY_SIZE: usize = 12;
/// The `unwind_info_section_header_lsda_index_entry`'s byte width.
const LSDA_ENTRY_SIZE: usize = 8;
/// One regular second-level entry's byte width.
const REGULAR_ENTRY_SIZE: usize = 8;
/// One compressed second-level entry's byte width (`(encodingIndex
/// << 24) | functionOffset`).
const COMPRESSED_ENTRY_SIZE: usize = 4;
/// The first function offset the compressed entry's 24-bit field
/// cannot carry (the field's mask is the low 24 bits — 16 MiB of
/// `__TEXT`).
const FUNC_OFFSET_LIMIT: u32 = UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET_MASK + 1;

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
    /// The second-level entry count (regular and compressed rows).
    pub entry_count: usize,
    /// The second-level page count (the index carries `page_count + 1`
    /// entries — one terminator).
    pub page_count: usize,
    /// The page count riding the compressed family (`UNWIND_SECOND_LEVEL_COMPRESSED`)
    /// — the rest ride the regular family (M35).
    pub compressed_page_count: usize,
    /// The common-encodings array count (0 when no page rides the
    /// compressed family; the array's rows are the distinct final
    /// words the compressed entries index through).
    pub common_encoding_count: usize,
    /// The personality-array count (first-use order).
    pub personality_count: usize,
    /// The LSDA-index count.
    pub lsda_count: usize,
}

/// The shape a table plans into: the counts [`synthesized_size_shape`]
/// sizes the section from — the planner and the builder share one
/// decision, so the reservation and the bytes can never drift (M35).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindShape {
    /// The second-level entry count (regular and compressed rows).
    pub entry_count: usize,
    /// The personality-array count (first-use order).
    pub personality_count: usize,
    /// The LSDA-index count.
    pub lsda_count: usize,
    /// The common-encodings array count (the distinct final words the
    /// compressed entries index through, capped at
    /// [`MAX_COMMON_ENCODINGS`]).
    pub common_encoding_count: usize,
    /// The second-level page count.
    pub page_count: usize,
    /// The page count riding the compressed family.
    pub compressed_page_count: usize,
    /// The entry count riding the compressed family (the rest ride
    /// the regular pages' 8-byte rows).
    pub compressed_entry_count: usize,
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
    /// The index is the entry's position in the offset-sorted stream
    /// (the order the synthesizer canonicalizes to).
    #[error("unwind entry {index} carries a zero-length range")]
    ZeroLengthRange {
        /// The offending entry's position in the sorted stream.
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

/// One planned second-level page: the rows it carries (a range of
/// the sorted stream) and the family it rides (`compressed` false =
/// the regular family, the M34 shape). A page never mixes families —
/// consecutive same-family rows share one.
struct PagePlan {
    start: usize,
    len: usize,
    compressed: bool,
}

/// The full synthesis decision: the validated, sorted stream plus
/// every array and page family it plans into. One decision path for
/// [`plan_shape`] (the public planner), [`synthesized_size_shape`]
/// (the exact formula) and [`synthesize`] (the builder) to share.
struct SynthesisPlan<'a> {
    sorted: Vec<&'a UnwindEntry>,
    personalities: Vec<u32>,
    lsdas: Vec<(u32, u32)>,
    common: Vec<u32>,
    pages: Vec<PagePlan>,
    shape: UnwindShape,
}

/// The row's final encoding word: the personality bits rewritten into
/// the output personality array's one-based indices (the form the
/// section's entries and the common array's rows carry).
fn final_word(entry: &UnwindEntry, personality_index: impl Fn(u32) -> u32) -> u32 {
    (entry.encoding & !UNWIND_PERSONALITY_MASK)
        | (personality_index(entry.personality_offset) << 28)
}

/// Validates the table and plans its shape: the sorted stream, the
/// personality/LSDA arrays, the common encodings array (first-use
/// order over the offset-qualifying stream, capped at
/// [`MAX_COMMON_ENCODINGS`]) and each page's family. One decision
/// path — [`synthesize`] emits from exactly this plan.
fn plan(entries: &[UnwindEntry]) -> Result<SynthesisPlan<'_>, SynthesisError> {
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

    // The common encodings array: the distinct final words in
    // first-use order over the offset-qualifying stream, capped at
    // the 8-bit index space. Only offset-qualifying rows nominate
    // words, so every row the array carries is referenced by at
    // least one qualifying row.
    let mut common: Vec<u32> = Vec::new();
    for e in &sorted {
        if e.function_offset < FUNC_OFFSET_LIMIT {
            let word = final_word(e, personality_index);
            if !common.contains(&word) && common.len() < MAX_COMMON_ENCODINGS {
                common.push(word);
            }
        }
    }

    // A row rides the compressed family exactly when its offset fits
    // the 24-bit field and its final word sits in the array (the
    // index is the word's position — tier one of libunwind's
    // two-tier decode; the page-local tier rides empty). Consecutive
    // same-family rows share a page; a family change starts one.
    let word_index = |e: &UnwindEntry| -> Option<usize> {
        if e.function_offset >= FUNC_OFFSET_LIMIT {
            return None;
        }
        common
            .iter()
            .position(|w| *w == final_word(e, personality_index))
    };

    let mut pages: Vec<PagePlan> = Vec::new();
    for (start, e) in sorted.iter().enumerate() {
        let compressed = word_index(e).is_some();
        if pages.last().is_some_and(|p: &PagePlan| {
            p.compressed == compressed && p.start + p.len == start && p.len < MAX_PAGE_ENTRIES
        }) {
            pages.last_mut().expect("checked above").len += 1;
        } else {
            pages.push(PagePlan {
                start,
                len: 1,
                compressed,
            });
        }
    }

    let compressed_entry_count = pages.iter().filter(|p| p.compressed).map(|p| p.len).sum();
    let shape = UnwindShape {
        entry_count: sorted.len(),
        personality_count: personalities.len(),
        lsda_count: lsdas.len(),
        common_encoding_count: common.len(),
        page_count: pages.len(),
        compressed_page_count: pages.iter().filter(|p| p.compressed).count(),
        compressed_entry_count,
    };
    Ok(SynthesisPlan {
        sorted,
        personalities,
        lsdas,
        common,
        pages,
        shape,
    })
}

/// The exact section size for the shape the counts name — one formula
/// with [`synthesize`]'s builder, so the plan's reservation and the
/// emitted bytes can never drift (M35; the planner the layout's
/// convergence reads and the surface a build system sizes with
/// before any link runs).
///
/// [`plan_shape`] names the shape a table plans into; the all-regular
/// [`synthesized_size`] is exact for the tables that plan the
/// pre-M35 shape (no row qualifies — every offset past the 24-bit
/// mark or every word past the cap, so the common array stays empty
/// and the layout is the M34 layout verbatim).
#[must_use]
pub fn synthesized_size_shape(shape: &UnwindShape) -> usize {
    HEADER_SIZE
        + shape.common_encoding_count * 4
        + shape.personality_count * 4
        + (shape.page_count + 1) * INDEX_ENTRY_SIZE
        + shape.compressed_page_count * COMPRESSED_PAGE_HEADER_SIZE
        + shape.compressed_entry_count * COMPRESSED_ENTRY_SIZE
        + (shape.page_count - shape.compressed_page_count) * PAGE_HEADER_SIZE
        + (shape.entry_count - shape.compressed_entry_count) * REGULAR_ENTRY_SIZE
        + shape.lsda_count * LSDA_ENTRY_SIZE
}

/// The all-regular shape's exact size (the M34 layout: no common
/// rows, every row in an 8-byte regular page). Exact for the tables
/// that plan it — no row qualifies, so the common array stays empty;
/// a table with qualifying rows plans its exact size through
/// [`plan_shape`]/[`synthesized_size_shape`] (M35).
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

/// The shape a table plans into — the pure decision a build system
/// reads before any link runs: the array counts, the page count and
/// how many pages ride the compressed family. The same validation
/// [`synthesize`] runs (the refusals name the shape), so a table that
/// plans synthesizes.
///
/// # Errors
/// [`SynthesisError`] when the table carries a shape no linker plan
/// can hold (zero-length ranges, unaligned or duplicate offsets, a
/// non-arm64 mode nibble).
pub fn plan_shape(entries: &[UnwindEntry]) -> Result<UnwindShape, SynthesisError> {
    Ok(plan(entries)?.shape)
}

/// Folds the translated entries into the `__unwind_info` section bytes.
/// Entries sort by function offset; personalities dedup in first-use
/// order over the sorted stream; the encoding's personality bits
/// rewrite into the array's one-based indices. A row rides the
/// compressed family when it qualifies (the offset fits the 24-bit
/// field and the word sits in the common array) and consecutive
/// same-family rows share a page — the density rung past the M34
/// regular pages (M35).
///
/// # Errors
/// [`SynthesisError`] when the table carries a shape no linker plan
/// can hold (zero-length ranges, unaligned or duplicate offsets, a
/// non-arm64 mode nibble).
///
/// # Panics
/// Never on caller-controlled input: the one reachable assertion
/// (`a compressed page's rows all indexed at plan time`) names the
/// plan-internal invariant that a compressed page's rows all carry a
/// common-array index — impossible to break through the public
/// surface, because [`plan`] qualifies a compressed page's rows
/// against the same array the emit resolves through.
pub fn synthesize(entries: &[UnwindEntry]) -> Result<UnwindInfo, SynthesisError> {
    let p = plan(entries)?;
    let shape = p.shape;
    let page_entries = |page: &PagePlan| &p.sorted[page.start..page.start + page.len];
    let page_size = |page: &PagePlan| {
        if page.compressed {
            COMPRESSED_PAGE_HEADER_SIZE + page.len * COMPRESSED_ENTRY_SIZE
        } else {
            PAGE_HEADER_SIZE + page.len * REGULAR_ENTRY_SIZE
        }
    };

    let size = synthesized_size_shape(&shape);
    debug_assert_eq!(
        size,
        HEADER_SIZE
            + p.common.len() * 4
            + p.personalities.len() * 4
            + (p.pages.len() + 1) * INDEX_ENTRY_SIZE
            + p.pages.iter().map(&page_size).sum::<usize>()
            + p.lsdas.len() * LSDA_ENTRY_SIZE
    );
    let mut out = Vec::with_capacity(size);

    // ---- header --------------------------------------------------------------
    let personality_off = HEADER_SIZE + p.common.len() * 4;
    let index_off = personality_off + p.personalities.len() * 4;
    let lsda_off = index_off
        + (p.pages.len() + 1) * INDEX_ENTRY_SIZE
        + p.pages.iter().map(&page_size).sum::<usize>();
    out.extend_from_slice(&UNWIND_SECTION_VERSION.to_le_bytes());
    out.extend_from_slice(&(HEADER_SIZE as u32).to_le_bytes()); // common encodings at 28
    out.extend_from_slice(&(p.common.len() as u32).to_le_bytes());
    out.extend_from_slice(&(personality_off as u32).to_le_bytes());
    out.extend_from_slice(&(p.personalities.len() as u32).to_le_bytes());
    out.extend_from_slice(&(index_off as u32).to_le_bytes());
    out.extend_from_slice(&((p.pages.len() + 1) as u32).to_le_bytes());

    // ---- common encodings array -------------------------------------------------
    for w in &p.common {
        out.extend_from_slice(&w.to_le_bytes());
    }

    // ---- personalities --------------------------------------------------------
    for pers in &p.personalities {
        out.extend_from_slice(&pers.to_le_bytes());
    }

    // ---- index ----------------------------------------------------------------
    let last = p.sorted[p.sorted.len() - 1];
    let last_end = last.function_offset.saturating_add(last.range_length);
    let mut page_cursor = index_off + (p.pages.len() + 1) * INDEX_ENTRY_SIZE;
    for page in &p.pages {
        out.extend_from_slice(&p.sorted[page.start].function_offset.to_le_bytes());
        out.extend_from_slice(&(page_cursor as u32).to_le_bytes());
        out.extend_from_slice(&(lsda_off as u32).to_le_bytes());
        page_cursor += page_size(page);
    }
    // The terminator: coverage ends at the last row's end; its page
    // pointer is the absent sentinel (`0`, the unwind-info convention).
    out.extend_from_slice(&last_end.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(lsda_off as u32).to_le_bytes());

    // ---- second-level pages -----------------------------------------------------
    let personality_of = personality_index_for(&p.personalities);
    for page in &p.pages {
        let rows = page_entries(page);
        if page.compressed {
            out.extend_from_slice(&UNWIND_SECOND_LEVEL_COMPRESSED.to_le_bytes());
            out.extend_from_slice(&(COMPRESSED_PAGE_HEADER_SIZE as u16).to_le_bytes());
            out.extend_from_slice(&(page.len as u16).to_le_bytes());
            // The page-local encodings array rides empty: every index
            // resolves at tier one (the section-level common array).
            out.extend_from_slice(
                &((COMPRESSED_PAGE_HEADER_SIZE + page.len * COMPRESSED_ENTRY_SIZE) as u16)
                    .to_le_bytes(),
            );
            out.extend_from_slice(&0u16.to_le_bytes());
            for e in rows {
                let idx = p
                    .common
                    .iter()
                    .position(|w| *w == final_word(e, &personality_of))
                    .expect("a compressed page's rows all indexed at plan time");
                let word = (idx as u32) << UNWIND_INFO_COMPRESSED_ENTRY_ENCODING_INDEX_SHIFT
                    | e.function_offset;
                out.extend_from_slice(&word.to_le_bytes());
            }
        } else {
            out.extend_from_slice(&UNWIND_SECOND_LEVEL_REGULAR.to_le_bytes());
            out.extend_from_slice(&(PAGE_HEADER_SIZE as u16).to_le_bytes());
            out.extend_from_slice(&(page.len as u16).to_le_bytes());
            for e in rows {
                out.extend_from_slice(&e.function_offset.to_le_bytes());
                out.extend_from_slice(&final_word(e, &personality_of).to_le_bytes());
            }
        }
    }

    // ---- lsda index array -------------------------------------------------------
    for (f, l) in &p.lsdas {
        out.extend_from_slice(&f.to_le_bytes());
        out.extend_from_slice(&l.to_le_bytes());
    }

    debug_assert_eq!(out.len(), size);
    tracing::debug!(
        entries = shape.entry_count,
        pages = shape.page_count,
        compressed_pages = shape.compressed_page_count,
        common = shape.common_encoding_count,
        personalities = shape.personality_count,
        lsdas = shape.lsda_count,
        bytes = size,
        "the unwind-info section synthesizes"
    );
    Ok(UnwindInfo {
        bytes: out,
        entry_count: shape.entry_count,
        page_count: shape.page_count,
        compressed_page_count: shape.compressed_page_count,
        common_encoding_count: shape.common_encoding_count,
        personality_count: shape.personality_count,
        lsda_count: shape.lsda_count,
    })
}

/// The one-based personality index resolver, bound to one plan's
/// personality array (the emit loop's per-row rewrites share it).
fn personality_index_for(personalities: &[u32]) -> impl Fn(u32) -> u32 + '_ {
    move |offset: u32| {
        if offset == 0 {
            0
        } else {
            personalities
                .iter()
                .position(|p| *p == offset)
                .map_or(0, |p| p as u32 + 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_COMMON_ENCODINGS, MAX_PAGE_ENTRIES, SynthesisError, UnwindEntry, UnwindInfo,
        UnwindShape, plan_shape, synthesize, synthesized_size, synthesized_size_shape,
    };
    use pgr_format::consts::{
        UNWIND_ARM64_MODE_DWARF, UNWIND_ARM64_MODE_FRAME, UNWIND_ARM64_MODE_FRAMELESS,
        UNWIND_SECOND_LEVEL_COMPRESSED, UNWIND_SECOND_LEVEL_REGULAR,
    };

    /// The first offset the compressed entry's 24-bit field cannot
    /// carry.
    const BEYOND_24_BIT: u32 = 0x0100_0000;

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
            let shape = plan_shape(&entries).expect("the table plans");
            assert_eq!(
                info.bytes.len(),
                synthesized_size_shape(&shape),
                "the planner and the builder agree at {n} entries"
            );
            assert_eq!(info.page_count, n.div_ceil(MAX_PAGE_ENTRIES));
            assert_eq!(
                info.compressed_page_count, info.page_count,
                "the single-word table compresses every page"
            );
        }
    }

    #[test]
    fn the_all_regular_planner_names_the_fallback_shape() {
        // Every offset past the 24-bit field: the pre-M35 shape, so
        // the M34 planner is exact.
        let entries: Vec<UnwindEntry> = (0..3)
            .map(|f| entry(BEYOND_24_BIT + (f * 4) as u32, 4, UNWIND_ARM64_MODE_FRAME))
            .collect();
        let info = synthesize(&entries).expect("the table synthesizes");
        assert_eq!(info.bytes.len(), synthesized_size(3, 0, 0));
        assert_eq!(info.compressed_page_count, 0);
        assert_eq!(info.common_encoding_count, 0);
    }

    #[test]
    fn the_header_names_the_arrays_in_order() {
        // An uncompressible table keeps the M34 header layout: no
        // common rows, the personality array riding the header.
        let entries = [entry(BEYOND_24_BIT, 4, UNWIND_ARM64_MODE_FRAME)];
        let info = synthesize(&entries).expect("the single-row table synthesizes");
        let b = &info.bytes;
        let rd = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        assert_eq!(rd(0), 1, "UNWIND_SECTION_VERSION");
        assert_eq!(rd(4), 28, "common encodings at 28");
        assert_eq!(rd(8), 0, "no common rows without compression");
        assert_eq!(rd(12), 28, "the personality array rides the header");
        assert_eq!(rd(16), 0, "no personalities");
        assert_eq!(rd(20), 28, "the index rides the (empty) arrays");
        assert_eq!(rd(24), 2, "one page + the terminator");
        // index[0]: the page; index[1]: the terminator (page pointer 0).
        assert_eq!(rd(28), BEYOND_24_BIT, "the page covers the function");
        assert_eq!(rd(32), 52, "the page starts at 28 + 2×12");
        assert_eq!(rd(44), 0, "the terminator carries no page");
    }

    #[test]
    fn the_regular_page_decodes() {
        // An uncompressible table rides the regular family: full
        // encoding words in 8-byte rows.
        let entries = [
            entry(BEYOND_24_BIT, 4, UNWIND_ARM64_MODE_FRAME),
            entry(
                BEYOND_24_BIT + 8,
                4,
                UNWIND_ARM64_MODE_FRAMELESS | (0x20 << 12),
            ),
            entry(BEYOND_24_BIT + 0x10, 4, UNWIND_ARM64_MODE_DWARF | 0x42),
        ];
        let info = synthesize(&entries).expect("the table synthesizes");
        assert_eq!(info.compressed_page_count, 0);
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
        assert_eq!(rd32(page + 8), BEYOND_24_BIT);
        assert_eq!(rd32(page + 16), BEYOND_24_BIT + 8);
        assert_eq!(rd32(page + 24), BEYOND_24_BIT + 0x10);
    }

    #[test]
    fn the_compressed_page_header_names_five_fields() {
        let entries = [
            entry(0, 4, UNWIND_ARM64_MODE_FRAME),
            entry(4, 4, UNWIND_ARM64_MODE_FRAME),
        ];
        let info = synthesize(&entries).expect("the table synthesizes");
        let b = &info.bytes;
        let rd32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let index_off = rd32(20) as usize;
        let page = rd32(index_off + 4) as usize;
        assert_eq!(rd32(page), UNWIND_SECOND_LEVEL_COMPRESSED, "the page kind");
        assert_eq!(
            u16::from_le_bytes([b[page + 4], b[page + 5]]),
            12,
            "entries at +12 (the compressed header's five fields)"
        );
        assert_eq!(u16::from_le_bytes([b[page + 6], b[page + 7]]), 2);
        assert_eq!(
            u16::from_le_bytes([b[page + 8], b[page + 9]]),
            12 + 2 * 4,
            "the page-local array would ride behind the entries"
        );
        assert_eq!(
            u16::from_le_bytes([b[page + 10], b[page + 11]]),
            0,
            "the page-local tier rides empty"
        );
        // The entries: (index << 24) | function offset.
        assert_eq!(
            (rd32(page + 12) >> 24, rd32(page + 12) & 0x00FF_FFFF),
            (0, 0)
        );
        assert_eq!(
            (rd32(page + 16) >> 24, rd32(page + 16) & 0x00FF_FFFF),
            (0, 4)
        );
    }

    #[test]
    fn personalities_dedup_in_first_use_order() {
        let mk = |offset: u32, personality: u32| UnwindEntry {
            function_offset: offset,
            range_length: 4,
            encoding: UNWIND_ARM64_MODE_FRAME,
            personality_offset: personality,
            lsda_offset: 0,
        };
        let info = synthesize(&[mk(0, 0x1000), mk(8, 0x2000), mk(0x10, 0x1000)])
            .expect("the table synthesizes");
        assert_eq!(info.personality_count, 2, "the second use dedups");
        assert_eq!(
            info.common_encoding_count, 2,
            "the personality index rides inside the word — two distinct words"
        );
        assert_eq!(info.compressed_page_count, 1);
        let b = &info.bytes;
        let rd32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        // The common array rides at 28: the final words (personality
        // index folded in), first-use order.
        assert_eq!(rd32(28), UNWIND_ARM64_MODE_FRAME | (1 << 28), "common[0]");
        assert_eq!(rd32(32), UNWIND_ARM64_MODE_FRAME | (2 << 28), "common[1]");
        // The personality array rides behind the common rows.
        assert_eq!(rd32(36), 0x1000, "first use order");
        assert_eq!(rd32(40), 0x2000);
        // The compressed entries name the common rows' indices.
        let index_off = rd32(20) as usize;
        let page = rd32(index_off + 4) as usize;
        let e0 = rd32(page + 12);
        let e1 = rd32(page + 16);
        let e2 = rd32(page + 20);
        assert_eq!(e0 >> 24, 0, "the first entry names index 0");
        assert_eq!(e1 >> 24, 1, "the second entry names index 1");
        assert_eq!(e2 >> 24, 0, "the third entry reuses the first word's index");
    }

    #[test]
    fn the_lsda_rows_ride_sorted() {
        let mk = |offset: u32, lsda: u32| UnwindEntry {
            function_offset: offset,
            range_length: 4,
            encoding: UNWIND_ARM64_MODE_FRAME,
            personality_offset: 0,
            lsda_offset: lsda,
        };
        let info = synthesize(&[mk(0, 0x100), mk(8, 0x200)]).expect("the table synthesizes");
        assert_eq!(info.lsda_count, 2);
        let b = &info.bytes;
        let rd32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let index_off = rd32(20) as usize;
        let lsda_off = rd32(index_off + 8) as usize;
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
        let modes = super::ARM64_MODES;
        assert_eq!(modes.len(), 4);
        assert!(modes.contains(&UNWIND_ARM64_MODE_FRAMELESS));
        assert!(modes.contains(&UNWIND_ARM64_MODE_DWARF));
        assert!(modes.contains(&UNWIND_ARM64_MODE_FRAME));
        assert!(!modes.contains(&0), "mode 0 is the x86 reserved shape");
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
                compressed_page_count: 1,
                common_encoding_count: 1,
                personality_count: 0,
                lsda_count: 0,
            }
        );
    }

    #[test]
    fn the_common_array_caps_at_the_index_space() {
        // 257 distinct words: the first 256 join the array and
        // compress; the last one has no index and rides the regular
        // family on its own page.
        let entries: Vec<UnwindEntry> = (0..257)
            .map(|f| entry((f * 4) as u32, 4, UNWIND_ARM64_MODE_DWARF | (f as u32)))
            .collect();
        let shape = plan_shape(&entries).expect("the table plans");
        assert_eq!(shape.common_encoding_count, MAX_COMMON_ENCODINGS);
        assert_eq!(shape.compressed_entry_count, MAX_COMMON_ENCODINGS);
        assert_eq!(
            shape.compressed_page_count, 1,
            "the qualifying rows share a page"
        );
        assert_eq!(shape.page_count, 2, "one page per family");
        let mut truncated = entries.clone();
        truncated.truncate(256);
        let shape = plan_shape(&truncated).expect("the table plans");
        assert_eq!(shape.compressed_page_count, 1, "every row now indexes");
        assert_eq!(shape.page_count, 1);
        assert_eq!(
            synthesized_size_shape(&shape),
            synthesize(&truncated)
                .expect("the table synthesizes")
                .bytes
                .len()
        );
    }

    #[test]
    fn the_shape_is_copy_and_pure() {
        let entries = [entry(0, 4, UNWIND_ARM64_MODE_FRAME)];
        let a = plan_shape(&entries).expect("plans");
        let b = plan_shape(&entries).expect("plans");
        assert_eq!(a, b, "the shape is a pure function of the table");
        let copied: UnwindShape = a;
        assert_eq!(copied, a, "the shape copies");
    }
}

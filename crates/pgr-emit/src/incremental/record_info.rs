//! The link record's read side (M13 rung 2): the `.pgr-inc` sidecar
//! becomes a *surface* — a typed file reader and a summary a build
//! system can render — instead of a blob only the relink engine decodes.
//!
//! Before this module the record was engine-internal: `LinkRecord` and
//! its fields are public, but reading a sidecar from disk meant calling
//! [`LinkRecord::decode`] on raw bytes and matching `None` — no reason,
//! no layer, no fix (the engine's fallback path treats every refusal
//! the same, correctly: a record is an accelerator, so *silently*
//! re-recording is the right behavior *for the engine*). A build system
//! asking "what did the last incremental link record, and will the next
//! relink patch?" had no honest answer. This module is that answer:
//!
//! * [`read_record`] — the whole record, with every frame-layer
//!   refusal typed ([`RecordReadError`]): too small, foreign magic,
//!   length mismatch, checksum, foreign revision, malformed body;
//! * [`read_summary`] — the [`RecordSummary`]: the record's shape
//!   (identity, skeleton, span/digest/hash counts, resolve capture)
//!   rendered as deterministic text ([`RecordSummary::render`]).
//!
//! The trust model is unchanged and restated honestly: the record
//! trusts that the on-disk output is the one it recorded; the checksum
//! proves the *sidecar* is intact, nothing more. Every refusal here is
//! a diagnosis, never a link failure — the next full link re-records.

use std::fmt;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::{FORMAT_VERSION, LinkRecord, MAGIC};

/// The record frame's header length (magic 8 + version 4 + payload
/// length 8 + checksum 32) — the reader's minimum size gate.
const HEADER_LEN: usize = 52;

/// A [`read_record`]/[`read_summary`] refusal: the frame layer that
/// failed, with the fix in the message (the house error convention).
///
/// The variants are ordered by how early the reader refuses — size,
/// then magic, then length, then checksum, then version, then body —
/// so the error a consumer sees is always the *outermost* honest
/// layer, never a deep decode of a frame that was already wrong.
#[derive(Debug, thiserror::Error)]
pub enum RecordReadError {
    /// The sidecar could not be read from disk.
    #[error("{path}: {source} (a record is written by `pgr -incremental` next to the output)")]
    Io {
        /// The sidecar path.
        path: String,
        /// The OS error.
        source: std::io::Error,
    },
    /// The file is smaller than the frame header — not a record.
    #[error(
        "{len} bytes is smaller than the {need}-byte record header; \
         not a Peregrine link record (`<output>.pgr-inc`)"
    )]
    TooSmall {
        /// The file's size.
        len: usize,
        /// The header's size (the minimum the frame needs).
        need: usize,
    },
    /// The magic does not name a Peregrine record (a foreign file, or
    /// a sidecar from a different tool).
    #[error(
        "not a Peregrine link record (magic mismatch); the sidecar is written by `pgr -incremental` next to the output"
    )]
    Magic,
    /// The frame's declared payload length and the file's size disagree
    /// (a truncated or extended file).
    #[error(
        "record length mismatch: the frame declares {expected} bytes, the file carries {found} \
         (truncated or extended; the next full link re-records)"
    )]
    Length {
        /// The size the frame header declares.
        expected: u64,
        /// The size on disk.
        found: u64,
    },
    /// The payload's SHA-256 does not match the frame's checksum — the
    /// sidecar is corrupt (a flipped byte, a partially written file).
    #[error(
        "record checksum mismatch; the sidecar is corrupt and the next full link re-records it (the record is an accelerator, never the truth)"
    )]
    Checksum,
    /// A checksum-honest record from a foreign format revision.
    #[error(
        "record format {found} unsupported (this build records {supported}); \
         relink once without -incremental to re-record in this shape"
    )]
    Version {
        /// The revision the record declares.
        found: u32,
        /// The revision this build writes.
        supported: u32,
    },
    /// The frame is honest but the body does not decode (a shape this
    /// build's decoder refuses).
    #[error("record body is malformed for format {found}; the next full link re-records it")]
    Malformed {
        /// The (frame-verified) format version the body claimed.
        found: u32,
    },
}

/// Reads a link record from disk: the engine's decoder with a typed
/// error surface.
///
/// # Errors
/// [`RecordReadError`] naming the outermost layer that failed — the
/// reader refuses at the frame before it ever decodes the body, so a
/// corrupt sidecar can never surface as a body error.
pub fn read_record(path: &Path) -> Result<LinkRecord, RecordReadError> {
    let bytes = std::fs::read(path).map_err(|source| RecordReadError::Io {
        path: path.display().to_string(),
        source,
    })?;
    read_record_bytes(&bytes).map_err(|err| {
        // The reader names its contract on the tracing seam (inert
        // until a subscriber installs — the house convention).
        tracing::debug!(
            path = %path.display(),
            error = %err,
            "record read refused"
        );
        err
    })
}

/// Reads a link record from an in-memory frame (the disk reader's
/// classification without the I/O).
///
/// # Panics
/// Never on any input — the frame-length gate bounds every fixed-width
/// slice taken below, and the body decode is the engine's total
/// ([`LinkRecord::decode`] never panics either).
///
/// # Errors
/// [`RecordReadError`] as [`read_record`].
pub fn read_record_bytes(bytes: &[u8]) -> Result<LinkRecord, RecordReadError> {
    if bytes.len() < HEADER_LEN {
        return Err(RecordReadError::TooSmall {
            len: bytes.len(),
            need: HEADER_LEN,
        });
    }
    if bytes[..8] != *MAGIC {
        return Err(RecordReadError::Magic);
    }
    let declared = u64::from_le_bytes(
        bytes[12..20]
            .try_into()
            .expect("the 8-byte slice is bounds-checked above"),
    );
    let found = bytes.len() as u64;
    if declared != found - HEADER_LEN as u64 {
        return Err(RecordReadError::Length {
            expected: declared,
            found: found - HEADER_LEN as u64,
        });
    }
    let want: [u8; 32] = bytes[20..52]
        .try_into()
        .expect("the 32-byte slice is bounds-checked above");
    let got: [u8; 32] = Sha256::digest(&bytes[HEADER_LEN..]).into();
    if got != want {
        return Err(RecordReadError::Checksum);
    }
    let found_version = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .expect("the 4-byte slice is bounds-checked above"),
    );
    if found_version != FORMAT_VERSION {
        return Err(RecordReadError::Version {
            found: found_version,
            supported: FORMAT_VERSION,
        });
    }
    LinkRecord::decode(bytes).ok_or(RecordReadError::Malformed {
        found: found_version,
    })
}

/// One recorded segment's summary row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSegmentRow {
    /// Segment name.
    pub name: String,
    /// vaddr start.
    pub vmaddr: u64,
    /// Virtual size.
    pub vmsize: u64,
    /// File offset.
    pub fileoff: u64,
    /// File-backed size.
    pub filesize: u64,
}

/// One recorded section's summary row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSectionRow {
    /// Owning segment name.
    pub seg: String,
    /// Section name.
    pub name: String,
    /// vaddr.
    pub vm_addr: u64,
    /// Reserved (padded) output size — the anchor value.
    pub size: u64,
    /// Content bytes (the pre-slack cursor).
    pub content_size: u64,
    /// File offset.
    pub file_off: u64,
    /// Zero-fill (no file bytes).
    pub zerofill: bool,
}

/// The record's shape, as a build system reads it: identity, skeleton,
/// the span/digest/hash counts that size the next relink's diff, and
/// the resolve-capture flag. Build with [`read_summary`] (from disk) or
/// [`RecordSummary::of`] (from an in-memory record); render with
/// [`RecordSummary::render`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSummary {
    /// The format revision the record decodes under.
    pub format_version: u32,
    /// The image identity the record names.
    pub ident: String,
    /// Mach-O file type word.
    pub filetype: u32,
    /// Total output file size.
    pub file_size: u64,
    /// The image base.
    pub image_base: u64,
    /// `__TEXT` vmsize.
    pub text_vmsize: u64,
    /// Entry offset within `__TEXT`.
    pub entryoff: u64,
    /// True when the recorded image carries a signature.
    pub signed: bool,
    /// The signed prefix length (0 when unsigned).
    pub code_limit: u64,
    /// The recorded segments, in command order.
    pub segments: Vec<RecordSegmentRow>,
    /// The recorded sections, in file order.
    pub sections: Vec<RecordSectionRow>,
    /// Every recorded emit span (all five families summed).
    pub spans: usize,
    /// The recorded import identities (the next relink's anchors).
    pub imports: usize,
    /// The parse's change-detection seeds (the propagation gate's table).
    pub section_digests: usize,
    /// The output sections' content digests (the relayout tier's table).
    pub content_digests: usize,
    /// The signature's recorded page hashes.
    pub page_hashes: usize,
    /// True when the record carries the Pass-2 resolution snapshot.
    pub resolve_captured: bool,
}

impl RecordSummary {
    /// Summarizes an in-memory record (the disk path is
    /// [`read_summary`]).
    #[must_use]
    pub fn of(record: &LinkRecord) -> Self {
        let spans = record.spans.runs.len()
            + record.spans.synths.len()
            + record.spans.blobs.len()
            + record.spans.patches.len()
            + record.spans.words.len();
        Self {
            format_version: record.format_version,
            ident: record.ident.clone(),
            filetype: record.filetype,
            file_size: record.file_size,
            image_base: record.image_base,
            text_vmsize: record.text_vmsize,
            entryoff: record.entryoff,
            signed: record.code_limit > 0,
            code_limit: record.code_limit,
            segments: record
                .segments
                .iter()
                .map(|s| RecordSegmentRow {
                    name: s.name.clone(),
                    vmaddr: s.vmaddr,
                    vmsize: s.vmsize,
                    fileoff: s.fileoff,
                    filesize: s.filesize,
                })
                .collect(),
            sections: record
                .sections
                .iter()
                .map(|s| RecordSectionRow {
                    seg: s.seg.clone(),
                    name: s.name.clone(),
                    vm_addr: s.vm_addr,
                    size: s.size,
                    content_size: s.content_size,
                    file_off: s.file_off,
                    zerofill: s.zerofill,
                })
                .collect(),
            spans,
            imports: record.imports.len(),
            section_digests: record.section_digests.len(),
            content_digests: record.content_digests.len(),
            page_hashes: record.page_hashes.len(),
            resolve_captured: record.resolution.is_some(),
        }
    }

    /// Renders the summary as deterministic text: one header block, the
    /// skeleton's rows in record order (segments, then their sections).
    /// The same record renders byte-identical text — the map's contract
    /// (`pgr_core::map`), applied to the sidecar.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(1024);
        s.push_str("# Peregrine link record\n");
        let _ = writeln!(s, "# ident: {}", self.ident);
        let _ = writeln!(s, "# filetype: {:#x}", self.filetype);
        let _ = writeln!(s, "# record version: {}", self.format_version);
        let _ = writeln!(
            s,
            "# file size: {} bytes, image base {:#x}, __TEXT vmsize {:#x}, entryoff {:#x}",
            self.file_size, self.image_base, self.text_vmsize, self.entryoff
        );
        let _ = writeln!(
            s,
            "# signed: {} (code limit {})",
            if self.signed { "yes" } else { "no" },
            self.code_limit
        );
        let _ = writeln!(
            s,
            "# state: {} segment(s), {} section(s), spans: {}",
            self.segments.len(),
            self.sections.len(),
            self.spans
        );
        let _ = writeln!(
            s,
            "# tables: {} import(s), {} parse digest(s), {} content digest(s), {} page hash(es); resolve snapshot: {}",
            self.imports,
            self.section_digests,
            self.content_digests,
            self.page_hashes,
            if self.resolve_captured {
                "captured"
            } else {
                "none"
            }
        );
        for seg in &self.segments {
            let _ = writeln!(
                s,
                "segment {:<16} vm 0x{:08x}..0x{:08x}  file 0x{:08x}..0x{:08x}",
                seg.name,
                seg.vmaddr,
                seg.vmaddr + seg.vmsize,
                seg.fileoff,
                seg.fileoff + seg.filesize,
            );
        }
        for sect in &self.sections {
            let _ = writeln!(
                s,
                "  section {:<12} vm 0x{:08x}  size 0x{:x} (content 0x{:x})  file 0x{:x}{}",
                sect.name,
                sect.vm_addr,
                sect.size,
                sect.content_size,
                sect.file_off,
                if sect.zerofill { " (zerofill)" } else { "" },
            );
        }
        s
    }
}

impl fmt::Display for RecordSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// Reads a sidecar and summarizes it (the consumer one-liner).
///
/// # Errors
/// [`RecordReadError`] as [`read_record`].
pub fn read_summary(path: &Path) -> Result<RecordSummary, RecordReadError> {
    let record = read_record(path)?;
    Ok(RecordSummary::of(&record))
}

#[cfg(test)]
mod tests {
    use super::{RecordSummary, read_record_bytes};
    use crate::incremental::{LinkRecord, RecordReadError};

    /// A hand-built minimal record (one segment, one section, no
    /// signature): the degenerate shape the summary must still render.
    fn minimal_record() -> LinkRecord {
        LinkRecord {
            format_version: crate::incremental::FORMAT_VERSION,
            file_size: 0x2000,
            image_base: 0x1_0000_0000,
            filetype: 2,
            text_vmsize: 0x1000,
            entryoff: 0x4000,
            ident: "minimal".into(),
            code_limit: 0,
            linkedit: pgr_core::layout::LinkeditPlan::default(),
            header_sha: [0; 32],
            segments: vec![crate::incremental::RecordedSegment {
                name: "__TEXT".into(),
                vmaddr: 0x1_0000_0000,
                vmsize: 0x1000,
                fileoff: 0,
                filesize: 0x1000,
                maxprot: 5,
                initprot: 5,
            }],
            sections: vec![crate::incremental::RecordedSection {
                seg: "__TEXT".into(),
                name: "__text".into(),
                flags: 0,
                align_log2: 2,
                vm_addr: 0x1_0000_0000 + 0x4000,
                content_size: 8,
                size: 8,
                file_off: 0x4000,
                zerofill: false,
            }],
            spans: crate::incremental::SpanTable::default(),
            page_hashes: Vec::new(),
            imports: Vec::new(),
            section_digests: Vec::new(),
            content_digests: Vec::new(),
            resolution: None,
        }
    }

    #[test]
    fn too_small_names_the_need() {
        let err = read_record_bytes(b"short").expect_err("not a record");
        assert!(
            matches!(err, RecordReadError::TooSmall { len: 5, need: 52 }),
            "{err:?}"
        );
    }

    #[test]
    fn foreign_magic_names_itself() {
        let mut bytes = vec![0u8; 64];
        bytes[..8].copy_from_slice(b"PGRINC2\0");
        assert!(
            matches!(read_record_bytes(&bytes), Err(RecordReadError::Magic)),
            "the foreign magic refuses at the frame layer"
        );
    }

    #[test]
    fn the_minimal_record_summarizes_and_renders() {
        let record = minimal_record();
        let s = RecordSummary::of(&record);
        assert!(!s.signed, "code_limit 0 is the unsigned record");
        assert_eq!(s.segments.len(), 1);
        assert_eq!(s.spans, 0, "an empty span table sums to zero");
        let text = s.render();
        assert!(text.starts_with("# Peregrine link record"));
        assert!(text.contains("record version:"));
        assert!(text.contains("segment __TEXT"));
        assert!(text.contains("section __text"));
        assert!(text.contains("resolve snapshot: none"));
        assert_eq!(text, s.render(), "deterministic render");
    }
}

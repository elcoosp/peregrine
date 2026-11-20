//! M71 — the verifier's universal-container face: the driver links a
//! universal ("fat") container through its arm64 slice (M70), so the
//! verifier owes the same container a *read-side* story. Every slice
//! the table declares gets the strict pass over its own window
//! ([`crate::verify`] on the subslice — the container adds no contract the
//! image does not already carry), and the table's row must agree with
//! the slice's own header about the arch it names: the driver links by
//! the table's row, so a row that lies (naming `x86_64` for an `arm64`
//! window) is the shape the seam can break — it rides
//! [`Code::HeaderInvalid`] on that slice's verdict, anchored at the
//! slice's offset.
//!
//! The container's decode is the format reader's gate (the
//! offset-tagged [`pgr_format::FormatError`] verbatim to the caller — a malformed
//! table is a refusal, not a report), and the face rides the tracing
//! seam inert-until-subscriber like every check family: one `debug`
//! event names the slices it walked.

use pgr_format::MachHeader64;
use pgr_format::universal::parse_universal;

use crate::{CheckSet, Code, Options, Report, verify_with_checks};

/// One slice's stable name in the machine faces (M96): the file path the
/// run was handed, the table position the slice rode, and the window the
/// table declared for it. The label is the identity the JSON face writes
/// ([`slice_label`]) and the container baseline's reader restores
/// (`parse_slice_label`) — one grammar, one writer, one reader, so a
/// recorded baseline pairs its lines with the rows they vouch for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceLabel {
    /// The file path the run was handed (the `--json` face's `file`
    /// field, verbatim).
    pub file: String,
    /// The table position the slice rode (the M74 face's per-slice walk
    /// order — the row's index, not an identity).
    pub index: usize,
    /// The window the table declared: the row's `cputype`.
    pub cputype: u32,
    /// The window's byte offset in the container.
    pub offset: u64,
    /// The window's byte size.
    pub size: u64,
}

/// One slice's window as the baseline gate pairs it (M96): the triple
/// the table declares — the identity a recorded baseline's line must
/// agree on before its findings vouch for the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceWindow {
    /// The row's `cputype`.
    pub cputype: u32,
    /// The window's byte offset in the container.
    pub offset: u64,
    /// The window's byte size.
    pub size: u64,
}

impl std::fmt::Display for SliceWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cputype {:#x} at {:#x}, {} bytes",
            self.cputype, self.offset, self.size
        )
    }
}

/// Writes one slice's machine-face label (M96): the exact string the
/// M74 `--json` face has always written — `{file}[slice {index} cputype
/// {cputype:#x} at {offset:#x}, {size} bytes]` — promoted into the
/// library so the writer and the baseline reader share one grammar (the
/// face's bytes do not move; the reader stops guessing at display text).
#[must_use]
pub fn slice_label(file: &str, index: usize, arch: &pgr_format::universal::FatArch) -> String {
    format!(
        "{file}[slice {index} cputype {:#x} at {:#x}, {} bytes]",
        arch.cputype, arch.offset, arch.size
    )
}

/// Reads one slice label back ([`slice_label`]'s own grammar, M96): the
/// label's `[slice …]` suffix carries the window the line vouches for.
/// `None` when the label names no slice window — a hand-authored line
/// cannot vouch for a row it does not name, and the container baseline's
/// reader refuses it with the fix (the container's own `--json` output).
///
/// The suffix is the label's tail: the file path rides verbatim before
/// it (a path may itself carry brackets), so the reader takes the last
/// `[slice ` that parses through the string's end.
#[must_use]
pub(crate) fn parse_slice_label(label: &str) -> Option<SliceLabel> {
    let head = label.rfind("[slice ")?;
    let rest = &label[head + "[slice ".len()..];
    let rest = rest.strip_suffix(']')?;
    let (index, rest) = decimal_field(rest)?;
    let rest = rest.strip_prefix(" cputype ")?;
    let (cputype, rest) = hex_field32(rest)?;
    let rest = rest.strip_prefix(" at ")?;
    let (offset, rest) = hex_field64(rest)?;
    let rest = rest.strip_prefix(", ")?;
    let (size, rest) = decimal_field(rest)?;
    let rest = rest.strip_prefix(" bytes")?;
    if !rest.is_empty() {
        return None;
    }
    let size = u64::try_from(size).ok()?;
    Some(SliceLabel {
        file: label[..head].to_string(),
        index,
        cputype,
        offset,
        size,
    })
}

/// Reads one decimal field up to the next separator.
fn decimal_field(s: &str) -> Option<(usize, &str)> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    let value = s[..end].parse().ok()?;
    Some((value, &s[end..]))
}

/// Reads one `0x`-hex field up to the next separator (the `cputype`
/// word's width).
fn hex_field32(s: &str) -> Option<(u32, &str)> {
    let rest = s.strip_prefix("0x")?;
    let end = rest
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(rest.len());
    if end == 0 || end > 8 {
        return None;
    }
    let value = u32::from_str_radix(&rest[..end], 16).ok()?;
    Some((value, &rest[end..]))
}

/// Reads one `0x`-hex field up to the next separator (the window
/// offset's width — a container's offsets are 64-bit quantities).
fn hex_field64(s: &str) -> Option<(u64, &str)> {
    let rest = s.strip_prefix("0x")?;
    let end = rest
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(rest.len());
    if end == 0 || end > 16 {
        return None;
    }
    let value = u64::from_str_radix(&rest[..end], 16).ok()?;
    Some((value, &rest[end..]))
}

/// One slice's verdict: the table row it rode and the strict pass's
/// report over its window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceVerdict {
    /// The table row (the `cputype` the driver linked by, the slice's
    /// own `offset` — the anchor the mismatch issue rides).
    pub arch: pgr_format::universal::FatArch,
    /// The strict pass over the slice's window (the container adds no
    /// contract the image does not already carry).
    pub report: Report,
}

/// The container's verdict: one [`SliceVerdict`] per table row, in
/// table order. `is_ok` is every slice's — the container ships only
/// when all of it does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UniversalReport {
    /// The per-slice verdicts, in table order.
    pub slices: Vec<SliceVerdict>,
}

impl UniversalReport {
    /// True when every slice's report is ok under `opts` (the
    /// container's own gate — the same rule [`Report::is_ok`] applies,
    /// one slice at a time).
    #[must_use]
    pub fn is_ok(&self, opts: &Options) -> bool {
        self.slices.iter().all(|s| s.report.is_ok(opts))
    }
}

/// Verifies every slice of a universal ("fat") container (M71): the
/// strict pass runs per declared slice, the table's rows are checked
/// against the slices' own headers, and the verdicts ride in table
/// order. The whole check surface runs — the M12 selector surface
/// ([`verify_universal_with_checks`]) narrows it.
///
/// # Errors
/// The format reader's offset-tagged [`pgr_format::FormatError`] when the
/// container is malformed (a truncated header, a lying count, an
/// out-of-bounds or overlapping window) — a malformed table is a
/// refusal, not a report: there is nothing to slice.
pub fn verify_universal(
    bytes: &[u8],
    opts: &Options,
) -> Result<UniversalReport, pgr_format::FormatError> {
    verify_universal_with_checks(bytes, opts, &CheckSet::all())
}

/// Verifies every slice of a universal ("fat") container over the named
/// check families only (M74): the M71 container face composed with the
/// M12 selector surface — one pass per declared slice over the selected
/// families, the table-row/header agreement riding as the container's
/// own contract (it is not one of the families, so a lying row refuses
/// under any selection), and the verdicts in table order. A build gate
/// auditing an SDK's fat dylibs prices a narrowed lane (`signature`
/// only) without re-running the whole pass; the full set is
/// [`verify_universal`].
///
/// # Errors
/// The format reader's offset-tagged [`pgr_format::FormatError`] when the
/// container is malformed — a malformed table is a refusal, not a
/// report: the selection never excuses the decode.
pub fn verify_universal_with_checks(
    bytes: &[u8],
    opts: &Options,
    checks: &CheckSet,
) -> Result<UniversalReport, pgr_format::FormatError> {
    let container = parse_universal(bytes)?;
    tracing::debug!(
        slices = container.arches.len(),
        magic = format!("{:#x}", container.magic),
        "universal container: verifying every declared slice"
    );
    let mut slices = Vec::with_capacity(container.arches.len());
    for arch in &container.arches {
        let window = container.slice(bytes, arch)?;
        let mut report = verify_with_checks(window, opts, checks);
        // The table's row and the window's own header must agree on the
        // arch they name — the driver links by the row, so a lie here
        // is the wrong slice's bytes linked under the right name.
        if let Ok(header) = MachHeader64::parse(window)
            && header.cputype != arch.cputype
        {
            report.issues.push(crate::Issue::error(
                Code::HeaderInvalid,
                format!(
                    "the slice table names cputype {:#x} but the slice's own header \
                     carries {:#x} — the table and the image disagree; link the arch \
                     the slice actually is",
                    arch.cputype, header.cputype
                ),
                Some(arch.offset),
            ));
        }
        slices.push(SliceVerdict {
            arch: *arch,
            report,
        });
    }
    Ok(UniversalReport { slices })
}

#[cfg(test)]
mod tests {
    use super::{parse_slice_label, slice_label};
    use pgr_format::consts::CPU_TYPE_ARM64;
    use pgr_format::universal::FatArch;

    fn arch(offset: u64, size: u64) -> FatArch {
        FatArch {
            cputype: CPU_TYPE_ARM64,
            cpusubtype: 0,
            offset,
            size,
            align_log2: 12,
        }
    }

    #[test]
    fn the_label_round_trips_through_the_reader() {
        let label = slice_label("build/fat.dylib", 1, &arch(0x4000, 0x8000));
        assert_eq!(
            label, "build/fat.dylib[slice 1 cputype 0x100000c at 0x4000, 32768 bytes]",
            "the M74 face's exact grammar (the size rides decimal, the addresses hex)"
        );
        let parsed = parse_slice_label(&label).expect("the label restores");
        assert_eq!(parsed.file, "build/fat.dylib");
        assert_eq!(parsed.index, 1);
        assert_eq!(parsed.cputype, CPU_TYPE_ARM64);
        assert_eq!(parsed.offset, 0x4000);
        assert_eq!(parsed.size, 0x8000);
    }

    #[test]
    fn a_label_without_the_suffix_names_no_window() {
        assert!(parse_slice_label("app").is_none());
        assert!(parse_slice_label("app[slice 0 cputype nope]").is_none());
        assert!(parse_slice_label("app[slice 0 cputype 0x100000c at 0x0, 8 bytes").is_none());
        assert!(parse_slice_label("app[slice 0 cputype 0x100000c at nope, 8 bytes]").is_none());
        assert!(
            parse_slice_label("app[slice 0 cputype 0x100000c at 0x0, 8 bytes] trailing").is_none()
        );
    }

    #[test]
    fn a_path_carrying_brackets_keeps_its_name() {
        let label = slice_label("weird[slice 9]name", 0, &arch(0x0, 0x10));
        let parsed = parse_slice_label(&label).expect("the last suffix wins");
        assert_eq!(parsed.file, "weird[slice 9]name");
    }
}

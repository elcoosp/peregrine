//! M60 — the build-system dependency record: ld64's `-dependency_info`
//! sidecar, the file Xcode's incremental builds read to learn which
//! files a link read and which one it wrote. The format is ld64's own
//! (`Options::writeDependencyInfo`, apple-oss-distributions ld64
//! `src/ld/Options.cpp`; the opcode enum in `src/ld/Options.h`): a
//! linker-version row — one [`LINKER_VERSION`] (`0x00`) opcode byte,
//! then the version string, NUL-terminated — followed by `(opcode,
//! path)` rows, each row the opcode byte and a NUL-terminated path:
//! every file the link read rides [`INPUT`] (`0x10`; ld64's
//! `depObjectFile`/`depDirectDylib`/`depIndirectDylib`/`depArchive`/
//! `depFileList`/`depSection`/`depBundleLoader`/`depMisc` names are
//! aliases of one opcode in the field), a probed-but-missing search
//! candidate rides [`NOT_FOUND`] (`0x11`), and the output — the `-map`
//! beside it — rides [`OUTPUT`] (`0x40`). The entries sort by
//! `(opcode, path)` for build reproducibility (ld64's
//! <rdar://30750137> sort), so two links of the same command line write
//! byte-identical records.
//!
//! The seam is pure: it validates and renders, it never touches the
//! filesystem. ld64's `addDependency` runs non-absolute paths through
//! `realpath()` at record time — the driver mirrors that before calling
//! in, keeping this module byte-shaping only. [`DependencyRecord::parse`]
//! is the strict reader (the `to_json`/`parse_report_json` round-trip
//! convention): it restores the writer's data exactly — gated — and
//! refuses the broken shapes (a foreign opcode, a truncated row, an
//! empty path) with the byte position named.

/// The linker-version row's opcode (`0x00`): the record's first byte,
/// followed by the version string, NUL-terminated (ld64's
/// `depLinkerVersion`).
pub const LINKER_VERSION: u8 = 0x00;

/// The input-family opcode (`0x10`): every file the link read — ld64's
/// `depObjectFile`, `depDirectDylib`, `depIndirectDylib`,
/// `depUpwardDirectDylib`, `depUpwardIndirectDylib`, `depArchive`,
/// `depFileList`, `depSection`, `depBundleLoader` and `depMisc` are all
/// aliases of this one opcode in the field.
pub const INPUT: u8 = 0x10;

/// The not-found opcode (`0x11`): a search candidate the link probed and
/// missed (ld64's `checkFileExists` records each miss — the consumer
/// learns what the search asked for and where).
pub const NOT_FOUND: u8 = 0x11;

/// The output opcode (`0x40`): the image the link wrote — and the `-map`
/// beside it, ld64's own shape (`depOutputFile` records both).
pub const OUTPUT: u8 = 0x40;

/// One `(opcode, path)` row: the ld64 dependency entry. The path is the
/// file's bytes as the linker read them — filesystem bytes, not a UTF-8
/// promise (the reader restores them verbatim).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyEntry {
    /// The row's opcode ([`INPUT`], [`NOT_FOUND`] or [`OUTPUT`]).
    pub opcode: u8,
    /// The file's path bytes, NUL-free (the format terminates the row).
    pub path: Vec<u8>,
}

/// The refused shapes of the dependency record — the writer's grammar and
/// the reader's rigid schema, one typed error each (the house convention:
/// the position or the row is named, never a bare verdict).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DepInfoError {
    /// The linker version is empty — the record names the tool that wrote
    /// it (ld64 writes its own version string first).
    #[error("the linker version is empty — the record names the tool that wrote it")]
    EmptyVersion,
    /// The linker version carries a NUL byte — the format terminates the
    /// row with one, so a NUL inside truncates it.
    #[error(
        "the linker version carries a NUL byte at offset {offset} — the format is NUL-terminated"
    )]
    NulVersion {
        /// The NUL byte's offset inside the version string.
        offset: usize,
    },
    /// A recorded path is empty — a dependency row names a file.
    #[error("the {row} path is empty — a dependency row names a file")]
    EmptyPath {
        /// Which row refused (`input`, `not-found` or `output`).
        row: &'static str,
    },
    /// A recorded path carries a NUL byte — the format terminates the row.
    #[error("the {row} path carries a NUL byte at offset {offset} — the format is NUL-terminated")]
    NulPath {
        /// Which row refused (`input`, `not-found` or `output`).
        row: &'static str,
        /// The NUL byte's offset inside the path.
        offset: usize,
    },
    /// The bytes are empty — the linker-version row leads the file.
    #[error("the dependency record is empty — the linker-version row leads the file")]
    EmptyRecord,
    /// The first byte is not the linker-version opcode — a record that
    /// skips the version row is not one ld64 (or this module) wrote.
    #[error("the record leads with opcode {opcode:#04x}, not the linker-version row (0x00)")]
    VersionRowMissing {
        /// The opcode the file led with instead.
        opcode: u8,
    },
    /// The linker-version string is not UTF-8 — the writer writes it from
    /// a valid string, so a file that carries anything else is broken.
    #[error("the linker-version string is not UTF-8 — the writer writes it from a valid string")]
    VersionNotUtf8,
    /// A row's opcode is outside the ld64 family.
    #[error(
        "unknown dependency opcode {opcode:#04x} at byte {offset} — the ld64 family is 0x00 (version), 0x10 (input), 0x11 (not-found), 0x40 (output)"
    )]
    UnknownOpcode {
        /// The foreign opcode as read.
        opcode: u8,
        /// The byte offset of the row's opcode.
        offset: usize,
    },
    /// A row (or the version string) has no NUL terminator before the end
    /// of the file — the record is truncated.
    #[error("the row at byte {offset} has no NUL terminator — the record is truncated")]
    Truncated {
        /// The byte offset of the truncated row's opcode.
        offset: usize,
    },
    /// A parsed row carries an empty path — the writer never emits one
    /// (the grammar refuses it), so a reader that sees one is reading a
    /// broken file (the rigid-schema rule, the map JSON's own).
    #[error("the row at byte {offset} carries an empty path — a dependency row names a file")]
    EmptyRowPath {
        /// The byte offset of the offending row's opcode.
        offset: usize,
    },
}

/// The dependency record as the driver builds it and a build system reads
/// it back: the linker-version row plus the `(opcode, path)` entries in
/// the format's canonical order (sorted by opcode, then path — ld64's
/// <rdar://30750137> reproducibility sort). The sort is eager, so every
/// face — [`Self::entries`], [`Self::render`], [`Self::parse`] — reads
/// the same canonical order and a record built in any insertion order
/// renders identically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyRecord {
    linker_version: String,
    entries: Vec<DependencyEntry>,
}

impl DependencyRecord {
    /// Opens the record with the linker-version row. The version is the
    /// tool's own identity string (the driver writes its `--version`
    /// line's stem; ld64 writes its own version string).
    ///
    /// # Errors
    /// [`DepInfoError::EmptyVersion`] on an empty version,
    /// [`DepInfoError::NulVersion`] when the version carries a NUL byte
    /// (the format terminates the row with one).
    pub fn new(version: &str) -> Result<Self, DepInfoError> {
        if version.is_empty() {
            return Err(DepInfoError::EmptyVersion);
        }
        if let Some(offset) = version.find('\0') {
            return Err(DepInfoError::NulVersion { offset });
        }
        Ok(Self {
            linker_version: version.to_owned(),
            entries: Vec::new(),
        })
    }

    /// The linker-version row (the tool that wrote the record).
    #[must_use]
    pub fn linker_version(&self) -> &str {
        &self.linker_version
    }

    /// The entries in the format's canonical order (opcode, then path).
    /// Duplicates ride verbatim — ld64 records a path once per decision
    /// that read it and never deduplicates.
    #[must_use]
    pub fn entries(&self) -> &[DependencyEntry] {
        &self.entries
    }

    /// Records one input row ([`INPUT`]): a file the link read — an
    /// object, an archive, a resolved library, a `-sectcreate` payload,
    /// a list file, the bundle loader.
    ///
    /// # Errors
    /// [`DepInfoError::EmptyPath`] / [`DepInfoError::NulPath`] when the
    /// path cannot ride the NUL-terminated format.
    pub fn record_input(&mut self, path: &str) -> Result<(), DepInfoError> {
        self.record(INPUT, path, "input")
    }

    /// Records one not-found row ([`NOT_FOUND`]): a search candidate the
    /// link probed and missed (ld64's `checkFileExists` shape).
    ///
    /// # Errors
    /// [`DepInfoError::EmptyPath`] / [`DepInfoError::NulPath`] when the
    /// path cannot ride the NUL-terminated format.
    pub fn record_not_found(&mut self, path: &str) -> Result<(), DepInfoError> {
        self.record(NOT_FOUND, path, "not-found")
    }

    /// Records one output row ([`OUTPUT`]): the image the link wrote —
    /// and the `-map` beside it (ld64 records both under
    /// `depOutputFile`).
    ///
    /// # Errors
    /// [`DepInfoError::EmptyPath`] / [`DepInfoError::NulPath`] when the
    /// path cannot ride the NUL-terminated format.
    pub fn record_output(&mut self, path: &str) -> Result<(), DepInfoError> {
        self.record(OUTPUT, path, "output")
    }

    /// The one insert path: validates, stores in the canonical order — a
    /// `partition_point` insert keeps the rows sorted with one memmove
    /// per row (the rows are few, the format's own order is the contract
    /// every face reads).
    fn record(&mut self, opcode: u8, path: &str, row: &'static str) -> Result<(), DepInfoError> {
        if path.is_empty() {
            return Err(DepInfoError::EmptyPath { row });
        }
        let bytes = path.as_bytes();
        if let Some(offset) = bytes.iter().position(|&b| b == 0) {
            return Err(DepInfoError::NulPath { row, offset });
        }
        let pos = self.entries.partition_point(|e| {
            e.opcode < opcode || (e.opcode == opcode && e.path.as_slice() < bytes)
        });
        self.entries.insert(
            pos,
            DependencyEntry {
                opcode,
                path: bytes.to_vec(),
            },
        );
        Ok(())
    }

    /// Renders the record: the version row (`0x00`, the version string,
    /// NUL-terminated) then one NUL-terminated `(opcode, path)` row per
    /// entry, in the canonical order. Two records of the same command
    /// line render byte-identically (the format's build-reproducibility
    /// contract).
    #[must_use]
    pub fn render(&self) -> Vec<u8> {
        let row_bytes: usize = self.entries.iter().map(|e| e.path.len() + 2).sum();
        let mut out = Vec::with_capacity(2 + self.linker_version.len() + row_bytes);
        out.push(LINKER_VERSION);
        out.extend_from_slice(self.linker_version.as_bytes());
        out.push(b'\0');
        for entry in &self.entries {
            out.push(entry.opcode);
            out.extend_from_slice(&entry.path);
            out.push(b'\0');
        }
        out
    }

    /// The strict reader: restores the writer's data exactly (the
    /// round-trip convention, gated in the tests) or refuses the broken
    /// shapes with the byte position named. Rows parse into the
    /// canonical order — the format defines it, so a record read back is
    /// the record a well-formed writer ships.
    ///
    /// # Errors
    /// [`DepInfoError::EmptyRecord`] on empty bytes,
    /// [`DepInfoError::VersionRowMissing`] when the file does not lead
    /// with the version row, [`DepInfoError::VersionNotUtf8`] when the
    /// version string is not UTF-8, [`DepInfoError::UnknownOpcode`] for
    /// an opcode outside the ld64 family, [`DepInfoError::Truncated`]
    /// when a row has no NUL terminator, [`DepInfoError::EmptyRowPath`]
    /// when a row carries an empty path.
    pub fn parse(bytes: &[u8]) -> Result<Self, DepInfoError> {
        let Some((&version_opcode, rest)) = bytes.split_first() else {
            return Err(DepInfoError::EmptyRecord);
        };
        if version_opcode != LINKER_VERSION {
            return Err(DepInfoError::VersionRowMissing {
                opcode: version_opcode,
            });
        }
        let version_end = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(DepInfoError::Truncated { offset: 0 })?;
        let linker_version = std::str::from_utf8(&rest[..version_end])
            .map_err(|_| DepInfoError::VersionNotUtf8)?
            .to_owned();
        let mut entries = Vec::new();
        // The version row is the opcode byte, the version string and the
        // terminating NUL: the entry rows start behind it.
        let mut cursor = version_end + 2;
        while cursor < bytes.len() {
            let opcode = bytes[cursor];
            if !matches!(opcode, INPUT | NOT_FOUND | OUTPUT) {
                return Err(DepInfoError::UnknownOpcode {
                    opcode,
                    offset: cursor,
                });
            }
            let row = &bytes[cursor + 1..];
            let path_end = row
                .iter()
                .position(|&b| b == 0)
                .ok_or(DepInfoError::Truncated { offset: cursor })?;
            let path = &row[..path_end];
            if path.is_empty() {
                return Err(DepInfoError::EmptyRowPath { offset: cursor });
            }
            entries.push(DependencyEntry {
                opcode,
                path: path.to_vec(),
            });
            cursor += path_end + 2;
        }
        let mut record = Self {
            linker_version,
            entries,
        };
        record
            .entries
            .sort_unstable_by(|a, b| a.opcode.cmp(&b.opcode).then_with(|| a.path.cmp(&b.path)));
        Ok(record)
    }
}

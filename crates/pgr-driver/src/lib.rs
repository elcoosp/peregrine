//! The `pgr` driver library (TDD §5 Pass 0 + the driver loop): option
//! parsing, input mapping, and the Pass 1–5 orchestration.
//!
//! The M4 loop: map inputs (`.o` objects and `.tbd`/`.dylib` dylib stubs,
//! plus the `-l` library search) → parse/intern/resolve/layout (`pgr-core`:
//! LPT-parallel Pass 1, D8 `resolved[]`, copy-run coalescing) → **fused tile
//! emit** (`pgr-emit::build_image_fused`, perf doc §4.4) → pooled flush.
//! Determinism is an end-to-end property (§4.3): linking the same corpus
//! twice in separate calls produces byte-identical images, and the fused
//! emit is byte-identical to the preserved pre-fusion reference
//! (`link_reference_bytes`) — both asserted in the integration tests.
//!
//! Since M8/M9 the loop also orchestrates the §7.2/§7.3 rungs: `-resident`
//! routes a link through the `pgrd` daemon (any refusal stands down
//! silently to the one-shot path), `-incremental` re-links in place from
//! the recorded emit plan (the §7.3 ladder classifying every shape it
//! cannot patch), and the fusion of both — the resident relink whose reply
//! is the changed-tile stream, replayed and hash-gated client-side.
//! [`run`] returns a [`LinkOutcome`] carrying the patch report, the audit
//! verdict and the wire transport, so a consumer can see which path served
//! the image.

pub mod opts;
pub mod synth;

use pgr_core::BundleLoader;
use pgr_core::LinkArchive;
use pgr_core::LinkArchiveMember;
use pgr_core::LinkInput;
use pgr_core::SymbolMatcher;
use pgr_core::cache::PoiCache;
use pgr_core::observe::LinkObserver as _;
use pgr_core::resolve::Dylib;
use pgr_emit::{write_image, write_image_observed};
use std::path::Path;

/// The load-command kind a framework flag names (M14; M45 adds the
/// upward kind): plain load, weak load, lazy load or upward load — the
/// `-framework` search is shared, the kind is per flag list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DylibKind {
    /// `-framework` (plain `LC_LOAD_DYLIB`).
    Load,
    /// `-reexport_framework` (`LC_REEXPORT_DYLIB`, the M3 re-export
    /// shape through the framework search).
    Reexport,
    /// `-weak_framework` (`LC_LOAD_WEAK_DYLIB`, weak binds).
    Weak,
    /// `-lazy_framework` (`LC_LAZY_LOAD_DYLIB`).
    Lazy,
    /// `-upward_framework` (`LC_LOAD_UPWARD_DYLIB`, the M45
    /// umbrella-relationship mark).
    Upward,
}

/// The driver outcome: bytes written, plus the plan for diagnostics.
#[derive(Debug)]
pub struct LinkOutcome {
    /// The output file path.
    pub output: String,
    /// Total image size in bytes.
    pub file_size: u64,
    /// Entry offset within `__TEXT`.
    pub entryoff: u64,
    /// Chained-fixup slots packed.
    pub fixup_slots: usize,
    /// M9: the in-place patch report (`None` on a full link).
    pub patch: Option<pgr_emit::incremental::PatchOutcome>,
    /// M9 GA rung 2: the served audit verdict (`Some` when
    /// `-incremental-verify` ran — daemon-served on the resident path,
    /// in-process otherwise; `None` on a full link or an untouched
    /// relink, where the audit's subject never exists).
    pub audit: Option<pgr_emit::incremental::audit::AuditSummary>,
    /// M9 output-residency rung (wire v5): how the resident reply's
    /// image crossed the wire (`Some` only on the resident path — the
    /// tile summary is the §7.2 rung's honest record; `None` on every
    /// non-resident path).
    pub transport: Option<pgr_daemon::Transport>,
    /// M73: the link's own verify gate (`-verify`): the strict pass's
    /// summary on the produced bytes — `Some` when the flag ran. The gate
    /// sits before the write, so an outcome with a failing gate never
    /// exists (the driver refused instead, `DriverError::Verify`);
    /// `None` on every path the gate does not ride (no flag, the `-r`
    /// object, the relink ladder's own audit). M76: the resident lane
    /// rides too — the summary is the session's own served verdict
    /// ([`gate_from_served`]) on the exact bytes the reply carried, one
    /// verifier pass per resident link, never two.
    pub verify: Option<VerifySummary>,
}

/// The verify gate's summary (M73): the strict pass's verdict on the
/// produced bytes, the shape the outcome line and a build system read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifySummary {
    /// The strict pass found nothing (no error- and no warning-severity
    /// issue — the strict contract: `is_ok` under
    /// `strict_warnings`). The gate refuses otherwise, before the write.
    pub ok: bool,
    /// Error-severity issues the pass named (zero when `ok`).
    pub errors: usize,
    /// Warning-severity issues the pass named (zero when `ok` — the
    /// strict gate counts them as blocking).
    pub warnings: usize,
}

/// The gate's full face (M73): the summary plus every issue the strict
/// pass named, in the verifier's own words — the refusal's body.
#[derive(Debug, Clone)]
pub struct VerifyGate {
    /// The verdict's summary (what `LinkOutcome::verify` carries).
    pub summary: VerifySummary,
    /// Every issue, rendered (`{:?} [code] message` — the audit's
    /// shape).
    pub issues: Vec<String>,
}

impl VerifyGate {
    /// The refusal (the fix, not just the verdict): the miette-rendered
    /// error the driver maps onto [`DriverError::Verify`].
    #[must_use]
    pub fn refusal(&self) -> VerifyRefusal {
        VerifyRefusal {
            issues: self.issues.clone(),
        }
    }
}

/// A refused-to-ship image: the link's own verify gate named issues on
/// the produced bytes. The driver renders this (miette help-text) and
/// exits — and because the gate sits before the write, the output file
/// is never created.
#[derive(Debug, Clone, thiserror::Error, miette::Diagnostic)]
#[error(
    "the image failed the link's verify gate ({} issue(s)):\n{}",
    .issues.len(),
    .issues.join("\n")
)]
#[diagnostic(help(
    "a failing gate ships nothing: the verifier's own words above name \
     each finding — re-run the link after fixing the input, or inspect \
     the image with pgr-verify --json for the machine-readable report"
))]
pub struct VerifyRefusal {
    /// The issues, in the verifier's own words.
    pub issues: Vec<String>,
}

impl VerifyRefusal {
    /// Renders the refusal with its help text (multi-line, no backtrace
    /// noise) — the string the driver prints (the audit's convention).
    #[must_use]
    pub fn render(&self) -> String {
        let report = miette::Report::new(self.clone());
        format!("{report:?}")
    }
}

/// The link's own gate (M73): the strict verifier on the produced bytes,
/// the `-no_adhoc` carve-out applied the audit's way (the
/// missing-signature shape is the config's own choice, never a defect
/// the gate names), one `tracing` span (inert until a subscriber
/// installs — the workspace convention). The driver runs it before the
/// write; library callers can run it on any bytes — the corrupted-twin
/// gate is the same face. The full pass, every family — the shape the
/// flagless gate runs; [`verify_gate_selected`] narrows it.
#[must_use]
pub fn verify_gate(bytes: &[u8], signature_expected: bool) -> VerifyGate {
    verify_gate_selected(bytes, signature_expected, &pgr_verify::CheckSet::all())
}

/// The link's own gate over a **selected** pass (M77): the M12 selector
/// narrows the strict verifier to the named families — the same
/// subtractive contract the verifier CLI's `--checks` carries (fewer
/// families against the same parsed image; the parse pre-pass and the
/// stats ride regardless, the `-no_adhoc` carve-out and the strict
/// contract unchanged). A build gate that prices only one contract runs
/// the families it prices; the cold lane and, over wire v44, the
/// resident lane's served pass narrow to the same set.
#[must_use]
pub fn verify_gate_selected(
    bytes: &[u8],
    signature_expected: bool,
    checks: &pgr_verify::CheckSet,
) -> VerifyGate {
    let span = tracing::info_span!(
        "verify_gate",
        len = bytes.len(),
        signature_expected,
        selected = %checks
    );
    let _entered = span.enter();
    let opts = pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let mut report = pgr_verify::verify_with_checks(bytes, &opts, checks);
    report.issues.retain(|issue| match issue.severity {
        pgr_verify::Severity::Error => {
            issue.code != pgr_verify::Code::SignatureLayout || signature_expected
        }
        pgr_verify::Severity::Warning => true,
    });
    let errors = report
        .issues
        .iter()
        .filter(|i| i.severity == pgr_verify::Severity::Error)
        .count();
    let warnings = report.issues.len() - errors;
    let issues = report
        .issues
        .iter()
        .map(|i| format!("{:?} [{}] {}", i.severity, i.code.as_str(), i.message))
        .collect();
    let summary = VerifySummary {
        ok: errors == 0 && warnings == 0,
        errors,
        warnings,
    };
    tracing::debug!(ok = summary.ok, "the driver's verify gate finished");
    VerifyGate { summary, issues }
}

/// The resident lane's served gate face (M76): builds the gate's verdict
/// from the reply's own report — the session's strict pass on the exact
/// bytes the image tail carries (the `-no_adhoc` carve-out applied the
/// session's way, wire v43). The client consumes the served verdict
/// instead of re-running the pass: one verifier pass per resident link,
/// not two, and the face prices O(issues), never the image walk. The
/// strict contract holds either way — a warning-severity issue blocks
/// the summary, so an outcome this face shaped is a clean one.
#[must_use]
pub fn gate_from_served(report: &pgr_verify::Report) -> VerifyGate {
    let span = tracing::debug_span!("served_verify_gate", issues = report.issues.len());
    let _entered = span.enter();
    let errors = report
        .issues
        .iter()
        .filter(|i| i.severity == pgr_verify::Severity::Error)
        .count();
    let warnings = report.issues.len() - errors;
    let issues = report
        .issues
        .iter()
        .map(|i| format!("{:?} [{}] {}", i.severity, i.code.as_str(), i.message))
        .collect();
    let summary = VerifySummary {
        ok: errors == 0 && warnings == 0,
        errors,
        warnings,
    };
    tracing::debug!(ok = summary.ok, "the served verify gate finished");
    VerifyGate { summary, issues }
}

/// A driver failure: options, I/O, or link errors.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// Command-line problems (exit code 2).
    #[error(transparent)]
    Opts(#[from] opts::OptsError),
    /// Link pipeline failures (exit code 1).
    #[error(transparent)]
    Link(#[from] pgr_core::LinkError),
    /// Emit/flush failures (exit code 1).
    #[error(transparent)]
    Emit(#[from] pgr_emit::EmitError),
    /// An input file could not be read.
    #[error("reading {path}: {source}")]
    Io {
        /// The failing path.
        path: String,
        /// The OS error.
        source: std::io::Error,
    },
    /// A `.tbd` stub failed to parse or a library was not found.
    #[error("{path}: {source}")]
    Tbd {
        /// The stub path (or the flag that wanted one).
        path: String,
        /// The parse failure.
        source: pgr_format::FormatError,
    },
    /// A universal ("fat") input refused (M70): the container's slice
    /// table is malformed (the format reader's offset-tagged refusal)
    /// or it carries no arm64 slice (the refusal names the cputypes it
    /// does — the fix is the container's own rebuild, or linking the
    /// arch it carries).
    #[error("{path}: {source}")]
    Universal {
        /// The universal input path.
        path: String,
        /// The container refusal (the format reader's offset-tagged error).
        source: pgr_format::FormatError,
    },
    /// A `-sectcreate` payload could not become a synthetic object: the
    /// section or segment name exceeds the 16-byte Mach-O field (M67 —
    /// the typed refusal, no longer misfiled under the `.tbd` variant).
    #[error("-sectcreate {0}")]
    SectionCreate(#[from] crate::synth::SynthError),
    /// A `-u` force-load symbol did not resolve to an in-image definition.
    #[error("-u {symbol}: {message}")]
    ForceLoad {
        /// The force-loaded symbol.
        symbol: String,
        /// What failed.
        message: String,
    },
    /// An M9 incremental patch failed outside the fallback contract (I/O
    /// or a plan contract). The relink falls back to the full link, which
    /// then surfaced this error too, or the patch itself was unrecoverable.
    #[error("incremental relink: {0}")]
    Incremental(#[from] pgr_emit::incremental::PatchError),
    /// `-incremental-verify` refused to ship the patched image: the
    /// strict verifier named blocking issues on the final bytes (the
    /// miette-rendered refusal, help text included). The output file is
    /// untouched when this comes from the resident path — the client
    /// refuses to write — and healed from the full emit when it comes
    /// from the in-process audit's identity half.
    #[error("{path}: {detail}")]
    Audit {
        /// The output path the audit gates.
        path: String,
        /// The rendered refusal (issue list + miette help text).
        detail: String,
    },
    /// M73 `-verify` refused to ship the image: the link's own gate ran
    /// the strict verifier on the produced bytes and named issues — the
    /// miette-rendered refusal, help text included. The output file is
    /// untouched when this fires: the gate sits before the write.
    #[error("{path}: {detail}")]
    Verify {
        /// The output path the gate gates.
        path: String,
        /// The rendered refusal (issue list + miette help text).
        detail: String,
    },
    /// An input is an LLVM bitcode object (LTO): the M6 scope detects it
    /// and diagnoses clearly instead of failing deep in the Mach-O parser.
    #[error(
        "{path}: LLVM bitcode object (LTO) is not supported by this linker; \
         rebuild with -fno-lto or link the LTO backend's output instead"
    )]
    LtoObject {
        /// The bitcode input path.
        path: String,
    },
    /// A `-exported_symbols_list`/`-unexported_symbols_list` file could not
    /// be read or parsed.
    #[error("{flag} {path}: {message}")]
    SymbolList {
        /// The flag that wanted the file.
        flag: String,
        /// The file path.
        path: String,
        /// What went wrong.
        message: String,
    },
    /// The `-order_file` could not be read or parsed (M11): the parse
    /// refusals name their line — the file is small, the fix is local.
    #[error("-order_file {path}: {message}")]
    OrderFile {
        /// The order-file path.
        path: String,
        /// The parse refusal (line-tagged).
        message: String,
    },
    /// A `-why_export` query named a symbol nothing interned (M56): the
    /// vacuous query refuses the run — the misspelling is named, the
    /// C-underscore hint is the fix (`pgr_core::provenance`).
    #[error("{0}")]
    WhyExport(#[from] pgr_core::provenance::ProvenanceError),
    /// The M60 dependency record refused a row (a NUL or an empty path —
    /// the format is NUL-terminated): the seam's typed error, the row
    /// named.
    #[error("dependency record: {0}")]
    DepInfo(#[from] pgr_core::dep_info::DepInfoError),
    /// A `.pgr-inc` sidecar could not be read as a link record (M13
    /// rung 2, the `--print-record` query): the frame layer that
    /// refused — size, magic, length, checksum, version or body — and
    /// the fix in the message.
    #[error("link record: {0}")]
    Record(#[from] pgr_emit::incremental::RecordReadError),
}

/// Reads a symbol-list file (one entry per line, `#` comments and blank
/// lines ignored; M14: each line parses as a [`pgr_core::SymbolPattern`] —
/// an exact name or a `*` glob, the ld64 subset Peregrine supports; see
/// docs/COMPAT.md).
fn read_symbol_patterns(
    flag: &str,
    path: &str,
) -> Result<Vec<pgr_core::SymbolPattern>, DriverError> {
    let text = std::fs::read_to_string(path).map_err(|e| DriverError::SymbolList {
        flag: flag.to_string(),
        path: path.to_string(),
        message: e.to_string(),
    })?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // M14: a line is a `SymbolPattern` — exact, or a `*` glob. A
        // malformed line refuses here, with the fix in the message (a
        // typo must never silently widen or narrow the export surface).
        let pattern = pgr_core::SymbolPattern::parse(line.as_bytes()).map_err(|e| {
            DriverError::SymbolList {
                flag: flag.to_string(),
                path: path.to_string(),
                message: e.to_string(),
            }
        })?;
        out.push(pattern);
    }
    Ok(out)
}

/// Scans a Mach-O dylib binary into a [`Dylib`] input (M3): the install
/// name and versions come from `LC_ID_DYLIB`, the exports from
/// `LC_DYLD_EXPORTS_TRIE` (or, when stripped, the symtab's external
/// definitions).
///
/// # Errors
/// [`DriverError::Tbd`] on malformed images (the variant carries any
/// Mach-O parse failure; named for the M2 text-stub path it extends).
pub fn scan_dylib(path: &str, bytes: &[u8]) -> Result<Dylib, DriverError> {
    let header = pgr_format::MachHeader64::parse(bytes).map_err(|e| DriverError::Tbd {
        path: path.to_string(),
        source: e,
    })?;
    if header.filetype != pgr_format::consts::MH_DYLIB {
        return Err(DriverError::Tbd {
            path: path.to_string(),
            source: pgr_format::FormatError::Malformed {
                what: format!(
                    "not a dylib (filetype {:#x}); Peregrine links .o objects and .tbd/.dylib \
                     dylibs",
                    header.filetype
                ),
            },
        });
    }
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .map_err(|e| DriverError::Tbd {
        path: path.to_string(),
        source: e,
    })?;
    let mut install_name = None;
    let mut current_version = 0u32;
    let mut compatibility_version = 0u32;
    let mut trie_payload: Option<&[u8]> = None;
    let mut symtab: Option<(u32, u32, u32, u32)> = None; // (symoff, nsyms, stroff, strsize)
    while let Some(cmd) = it.next_command().map_err(|e| DriverError::Tbd {
        path: path.to_string(),
        source: e,
    })? {
        match cmd.kind {
            pgr_format::LoadCommandKind::IdDylib => {
                let d =
                    pgr_format::DylibCommand::parse(cmd.bytes).map_err(|e| DriverError::Tbd {
                        path: path.to_string(),
                        source: e,
                    })?;
                if let Ok(name) = d.name(cmd.bytes) {
                    install_name = Some(String::from_utf8_lossy(name).into_owned());
                    current_version = d.current_version;
                    compatibility_version = d.compatibility_version;
                }
            }
            pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_EXPORTS_TRIE) => {
                if let Ok(lc) = pgr_format::LinkeditDataCommand::parse(cmd.bytes) {
                    if let Ok(payload) = lc.data(bytes) {
                        trie_payload = Some(payload);
                    }
                }
            }
            pgr_format::LoadCommandKind::Symtab => {
                if let Ok(st) = pgr_format::SymtabCommand::parse(cmd.bytes, 0) {
                    symtab = Some((st.symoff, st.nsyms, st.stroff, st.strsize));
                }
            }
            _ => {}
        }
    }
    let Some(install_name) = install_name else {
        return Err(DriverError::Tbd {
            path: path.to_string(),
            source: pgr_format::FormatError::Malformed {
                what: "dylib carries no LC_ID_DYLIB install name".into(),
            },
        });
    };
    // Export surface: the trie is authoritative; the symtab extdefs are the
    // fallback for dylibs without an export trie.
    let mut exports: Vec<Vec<u8>> = Vec::new();
    if let Some(payload) = trie_payload {
        for e in pgr_format::trie::exports(payload).map_err(|e| DriverError::Tbd {
            path: path.to_string(),
            source: e,
        })? {
            exports.push(e.name);
        }
    } else if let Some((symoff, nsyms, stroff, strsize)) = symtab {
        for i in 0..nsyms as usize {
            let Ok(sym) = pgr_format::cursor::pod_read_unaligned_at::<pgr_format::Nlist64>(
                bytes,
                symoff as usize + i * 16,
            ) else {
                break;
            };
            let defined = sym.is_external()
                && !sym.is_stab()
                && sym.n_type & pgr_format::consts::N_TYPE == pgr_format::consts::N_SECT;
            if !defined {
                continue;
            }
            let strx = sym.n_strx as usize;
            let Some(rest) = bytes.get(stroff as usize + strx..stroff as usize + strsize as usize)
            else {
                break;
            };
            let Some(end) = rest.iter().position(|&b| b == 0) else {
                break;
            };
            exports.push(rest[..end].to_vec());
        }
    }
    Ok(Dylib {
        install_name,
        current_version,
        compatibility_version,
        exports,
        weak: false,
        reexport: false,
        lazy: false,
        upward: false,
    })
}

/// The in-memory link product: image bytes plus the plan facts.
#[derive(Debug)]
pub struct ImageAndPlan {
    /// The complete output image.
    pub image: Vec<u8>,
    /// Entry offset within `__TEXT`.
    pub entryoff: u64,
    /// Chained-fixup slots packed.
    pub fixup_slots: usize,
}

/// Classifies an input by content: `true` when the bytes look like a
/// text-based dylib stub (`--- !tapi-tbd` / `--- !tbd-tbd`).
#[must_use]
fn looks_like_tbd(bytes: &[u8]) -> bool {
    bytes.starts_with(b"--- !tapi-tbd")
        || bytes.starts_with(b"--- !tbd-tbd")
        || bytes.starts_with(b"--- !tbd-tbd-version")
}

/// M70: the universal read seam — a fat container is linked through its
/// arm64 slice (ld64's `-arch` match; the surface links arm64, so the
/// cputype match is exact). The container decodes, the arm64 window is
/// copied out, and the caller's per-kind dispatch runs on it unchanged —
/// every arm below (`map_input`'s tbd/dylib/archive/object chain, the
/// `-l`/`-framework` scans) links the slice it already linked. A
/// non-universal input rides untouched (`None` — the probe is one
/// four-byte magic read, no copy), so every pre-M70 link is
/// byte-identical (the parity gate lives in `tests/m70_universal_input.rs`).
///
/// # Errors
/// [`DriverError::Universal`] when the container is malformed (the
/// offset-tagged format refusal) or carries no arm64 slice (the refusal
/// names the cputypes it does).
fn universal_arm64_slice(path: &str, bytes: &[u8]) -> Result<Option<Vec<u8>>, DriverError> {
    if !pgr_format::is_universal(bytes) {
        return Ok(None);
    }
    let container =
        pgr_format::parse_universal(bytes).map_err(|source| DriverError::Universal {
            path: path.to_string(),
            source,
        })?;
    let slice = container
        .arm64(bytes)
        .map_err(|source| DriverError::Universal {
            path: path.to_string(),
            source,
        })?;
    Ok(Some(slice.to_vec()))
}

/// Maps one `.tbd` document to a [`Dylib`] input.
///
/// # Errors
/// [`DriverError::Tbd`] on parse failures, [`DriverError::Io`] on reads.
pub fn tbd_to_dylib(path: &str, bytes: &[u8], weak: bool) -> Result<Dylib, DriverError> {
    tbd_to_dylib_cached(path, bytes, weak, None)
}

/// The M6 frozen-`.tbd` path (Stage A): the YAML parse is cached under the
/// stub's content hash; a hit decodes the frozen export set instead of
/// parsing text (the `.tbd` startup gate). `weak` stays a caller property.
///
/// # Errors
/// [`DriverError::Tbd`] on malformed stubs.
pub fn tbd_to_dylib_cached(
    path: &str,
    bytes: &[u8],
    weak: bool,
    cache: Option<&pgr_core::cache::PoiCache>,
) -> Result<Dylib, DriverError> {
    if let Some(cache) = cache {
        let key = pgr_core::cache::PoiCache::content_key(bytes, false);
        if let Some(frozen) = cache.load_dylib(&key) {
            let mut d: Dylib = frozen.into();
            d.weak = weak;
            return Ok(d);
        }
    }
    let tbd = pgr_format::parse_tbd(bytes).map_err(|e| DriverError::Tbd {
        path: path.to_string(),
        source: e,
    })?;
    let dylib = Dylib {
        install_name: tbd.install_name,
        current_version: tbd.current_version,
        compatibility_version: tbd.compatibility_version,
        exports: tbd
            .exports
            .into_iter()
            .map(|s| s.name.into_bytes())
            .collect(),
        weak,
        reexport: false,
        lazy: false,
        upward: false,
    };
    if let Some(cache) = cache {
        let key = pgr_core::cache::PoiCache::content_key(bytes, false);
        cache.store_dylib(&key, &pgr_core::cache::FrozenDylib::from(&dylib));
    }
    Ok(dylib)
}

/// Scans a `-bundle_loader` host executable (M25): the export surface
/// the bundle's undefined references bind against. The host is an
/// `MH_EXECUTE` image — its trie carries the names dyld resolves
/// without the symbol table, and a minimal trie (an executable ships
/// only what it must export) can understate the surface a bundle's
/// loader binds may reach; the symtab's defined externals complete it
/// (dyld resolves a main-executable bind through the host process's
/// own symbol surface). One reader, two consumers: the driver's scan
/// and the verifier's pair gate both read
/// [`pgr_format::loader_export_surface`].
///
/// # Errors
/// [`DriverError::Tbd`] on any malformed host (not Mach-O, not an
/// executable, a broken surface) — the message names the path and the
/// fix.
pub fn scan_loader_executable(path: &str, bytes: &[u8]) -> Result<BundleLoader, DriverError> {
    // M70: a universal host rides its arm64 slice (the bundle_loader
    // host is an SDK executable — it ships fat). One unwrap: the
    // dispatch never re-enters, a slice that still opens with a fat
    // magic refuses at the Mach-O header below (a container inside a
    // container is not a host).
    let bytes = if pgr_format::is_universal(bytes) {
        let container =
            pgr_format::parse_universal(bytes).map_err(|source| DriverError::Universal {
                path: path.to_string(),
                source,
            })?;
        container
            .arm64(bytes)
            .map_err(|source| DriverError::Universal {
                path: path.to_string(),
                source,
            })?
    } else {
        bytes
    };
    let header = pgr_format::MachHeader64::parse(bytes).map_err(|e| DriverError::Tbd {
        path: path.to_string(),
        source: e,
    })?;
    if header.filetype != pgr_format::consts::MH_EXECUTE {
        return Err(DriverError::Tbd {
            path: path.to_string(),
            source: pgr_format::FormatError::Malformed {
                what: format!(
                    "not an executable (filetype {:#x}); -bundle_loader names the \
                     MH_EXECUTE host the bundle binds against",
                    header.filetype
                ),
            },
        });
    }
    let exports = pgr_format::loader_export_surface(bytes).map_err(|e| DriverError::Tbd {
        path: path.to_string(),
        source: e,
    })?;
    BundleLoader::new(path, exports).map_err(|e| DriverError::Tbd {
        path: path.to_string(),
        source: pgr_format::FormatError::Malformed {
            what: e.to_string(),
        },
    })
}

/// Resolves `-l<name>` against the given search dirs (already ld64-effective:
/// `-syslibroot`-reshaped, defaults included — see
/// [`opts::effective_lib_dirs`]) to a `.tbd` stub, a Mach-O dylib binary, or
/// — M5 — a static archive (dylib candidates win, matching ld64's search
/// order). Every probed-but-missing candidate lands in `not_found` (the
/// M60 dependency record's `0x11` rows — ld64's `checkFileExists` records
/// each miss; a `-syslibroot`-prefixed candidate keeps its prefixed form,
/// the path the search actually probed).
///
/// # Errors
/// [`DriverError::Io`] when the file exists but cannot be read.
pub fn resolve_lib(
    name: &str,
    lib_dirs: &[String],
    not_found: &mut Vec<String>,
) -> Result<Option<(String, Vec<u8>)>, DriverError> {
    let candidates = [
        "lib".to_owned() + name + ".tbd",
        name.to_owned() + ".tbd",
        "lib".to_owned() + name + ".dylib",
        name.to_owned() + ".dylib",
        "lib".to_owned() + name + ".a",
        name.to_owned() + ".a",
    ];
    for dir in lib_dirs {
        for cand in &candidates {
            let p = Path::new(dir).join(cand);
            if p.is_file() {
                let bytes = std::fs::read(&p).map_err(|source| DriverError::Io {
                    path: p.display().to_string(),
                    source,
                })?;
                return Ok(Some((p.display().to_string(), bytes)));
            }
            not_found.push(p.display().to_string());
        }
    }
    Ok(None)
}

/// Resolves `-framework <name>` against the given search dirs (already
/// ld64-effective: `-syslibroot`-reshaped, defaults included — see
/// [`opts::effective_framework_dirs`]): `<dir>/<Name>.framework/<Name>`
/// (+ `.tbd`). Every probed-but-missing candidate lands in `not_found`
/// (the M60 dependency record's `0x11` rows — the `-l` search's shape).
///
/// # Errors
/// [`DriverError::Io`] when the file exists but cannot be read.
pub fn resolve_framework(
    name: &str,
    framework_dirs: &[String],
    not_found: &mut Vec<String>,
) -> Result<Option<(String, Vec<u8>)>, DriverError> {
    let stems = [
        format!("{name}.framework/{name}.tbd"),
        format!("{name}.framework/{name}"),
    ];
    for dir in framework_dirs {
        for stem in &stems {
            let p = Path::new(dir).join(stem);
            if p.is_file() {
                let bytes = std::fs::read(&p).map_err(|source| DriverError::Io {
                    path: p.display().to_string(),
                    source,
                })?;
                return Ok(Some((p.display().to_string(), bytes)));
            }
            not_found.push(p.display().to_string());
        }
    }
    Ok(None)
}

/// Links the option inputs into image bytes (no filesystem). Exposed for
/// tests, benchmarks and the verifier pipeline. Runs the M4 pipeline: the
/// parallel Pass 1–3 front half plus the fused tile emit.
///
/// M8 `-resident`: the prepared link state is offered to the resident
/// daemon first ([`pgr_daemon::link_via_daemon`]); any failure — no daemon,
/// stale socket, protocol mismatch, link error — silently falls back to the
/// one-shot path (§7.2 "optional and transparent"; `PGR_RESIDENT_DEBUG=1`
/// prints the fallback reason for diagnosis).
///
/// # Errors
/// [`DriverError`] on option, link, emit, tbd or I/O failures.
pub fn link_to_image(opts: &opts::Options) -> Result<ImageAndPlan, DriverError> {
    Ok(link_to_image_recorded(opts, None)?.0)
}

/// The one-shot pipeline's pending measurement faces (M68): the timing
/// flags' collectors ride out of [`link_to_image_recorded`] so Pass 5's
/// flush — the atomic write the caller performs — joins the same
/// collection before the faces build (one collection per run; the
/// report's rows stay in link order through the emit half). The time
/// face carries its own clock: the pipeline wall's anchor (the total
/// band's measurement rides the same `Some`).
struct PendingFaces {
    /// The `--time`/`--time-json` collector beside the clock the
    /// pipeline started on (`None` when no time face asked — the band
    /// keys stay the library caller's).
    time: Option<(pgr_core::TimeCollector, std::time::Instant)>,
    /// The `--trace` collector (`None` when no timeline asked).
    trace: Option<pgr_core::trace::TraceCollector>,
}

/// The driver's observer slot over the two optional faces (M58/M61/M68):
/// `--time` feeds the report collector, `--trace` the timeline collector,
/// both compose behind one subscription — the `None`-forwarding twin of
/// [`pgr_core::ObserverPair`], the one subscription the pipeline's phases,
/// the emit half and the flush report through.
struct FaceSlot<'a> {
    time: Option<&'a mut dyn pgr_core::LinkObserver>,
    trace: Option<&'a mut dyn pgr_core::LinkObserver>,
}

impl<'a> FaceSlot<'a> {
    /// Slots the two collectors (each face asks for itself; a face that
    /// did not ask subscribes to nothing).
    fn new(
        time: Option<&'a mut pgr_core::TimeCollector>,
        trace: Option<&'a mut pgr_core::trace::TraceCollector>,
    ) -> Self {
        Self {
            time: time.map(|t| t as &'a mut dyn pgr_core::LinkObserver),
            trace: trace.map(|t| t as &'a mut dyn pgr_core::LinkObserver),
        }
    }
}

impl pgr_core::LinkObserver for FaceSlot<'_> {
    fn on_phase(&mut self, event: pgr_core::observe::PhaseEvent) {
        if let Some(obs) = self.time.as_deref_mut() {
            obs.on_phase(event.clone());
        }
        if let Some(obs) = self.trace.as_deref_mut() {
            obs.on_phase(event);
        }
    }

    fn on_task(&mut self, task: pgr_core::observe::TaskEvent) {
        if let Some(obs) = self.time.as_deref_mut() {
            obs.on_task(task.clone());
        }
        if let Some(obs) = self.trace.as_deref_mut() {
            obs.on_task(task);
        }
    }

    fn on_note(&mut self, note: pgr_core::observe::LinkNote) {
        if let Some(obs) = self.time.as_deref_mut() {
            obs.on_note(note.clone());
        }
        if let Some(obs) = self.trace.as_deref_mut() {
            obs.on_note(note);
        }
    }
}

/// The M56 `-why_export` answers (the driver's consumer face): one text
/// report per queried name, in flag order — the definition the
/// resolution installed and every reference site the M8-a reverse index
/// recorded (`pgr_core::provenance` renders both faces; the driver
/// prints the text one). The index builds once per link, the queries
/// read it; a vacuous query refuses the run (the misspelling named — a
/// question the link cannot answer is never silently empty).
fn print_why_export(
    objects: &[pgr_core::object::InputObject],
    resolution: &pgr_core::resolve::Resolution,
    interner: &pgr_core::interner::Interner,
    queries: &[String],
) -> Result<(), DriverError> {
    let index = pgr_core::ReverseIndex::build_all(objects);
    for name in queries {
        let answer = pgr_core::explain_export(&index, objects, resolution, interner, name)?;
        print!("{}", answer.render());
    }
    Ok(())
}

/// [`link_to_image`] plus the M9 record: when `-incremental` is active and
/// the one-shot pipeline produced the image, the link's record is built in
/// the same pass (no pipeline re-run). The resident daemon path returns the
/// daemon's refreshed record (M9 GA fusion rung: the wire carries both
/// halves, so a resident full link re-records the state and the
/// incremental cycle survives daemon fallbacks).
///
/// `seed` is the M65 handover note: when the in-place ladder fell back to
/// this full link with a timing face riding, the note leads the report
/// (the collectors carry it into the table's note lines and the
/// timeline's instants — one report per run, the handover named where the
/// output actually came from). `None` on every other caller.
fn link_to_image_recorded(
    opts: &opts::Options,
    seed: Option<&pgr_core::observe::LinkNote>,
) -> Result<
    (
        ImageAndPlan,
        Option<pgr_emit::incremental::LinkRecord>,
        PendingFaces,
        // M76: the resident lane's served verify gate (`-resident
        // -verify`) — the session's own strict pass on the served bytes,
        // the face the caller gates the write on. `None` on every other
        // path: the one-shot lane, the fallback, the fusion relink (the
        // ladder's audit gates it).
        Option<VerifyGate>,
    ),
    DriverError,
> {
    let (mut prepared, cache) = prepare_link(opts)?;
    // M58/M61: the observed faces — the time report's and the timeline's
    // collectors ride the one-shot pipeline (the resident lane is served
    // on the wire — v40/v41, the session's own observed run; the
    // incremental lane rides its own since M65).
    let timing = opts.time || opts.time_json || opts.trace_path.is_some();
    if opts.resident {
        // M9 GA fusion rung: an `-incremental` cycle's full link asks the
        // daemon to capture the fresh record (§7.3 — the sidecar must stay
        // fresh across resident links, or the next relink falls back
        // forever); a plain `-resident` link links clean as before.
        let mut job = if opts.incremental {
            pgr_daemon::LinkJob::build_capturing(
                &prepared.config,
                &prepared.force_load,
                &prepared.inputs,
                &prepared.archives,
            )
        } else {
            pgr_daemon::LinkJob::build(
                &prepared.config,
                &prepared.force_load,
                &prepared.inputs,
                &prepared.archives,
            )
        };
        // M58/M59 (wire v40): a timed link asks the session to observe its
        // own pipeline and serve the report on the reply.
        job.request.time = timing;
        // M61/M62 (wire v41): a trace-asking link asks the same of the
        // session's timeline (the rendered document rides the reply's
        // tail; the client writes it to `--trace`'s path verbatim).
        job.request.trace = opts.trace_path.is_some();
        // M76: a verify-asking link asks the session for its own strict
        // pass on the final bytes (v43's flag, M72's served verdict) —
        // the client gates the write on the served verdict below, the
        // audit's rule on the resident lane.
        job.request.verify = opts.verify;
        // M77 (wire v44): the gate's check selection crosses with the
        // flag — the session's served pass narrows to the families the
        // client named, the same set the cold lane's gate would run.
        job.request.verify_checks = opts.verify_checks;
        // M79 (wire v45): a query-asking link asks the session's own
        // full walk for the answers — the served renders print beside
        // the resident link exactly as the cold lane prints its own
        // (the fallback below prints the one-shot's; either lane, the
        // same face).
        job.request.why_export.clone_from(&opts.why_export);
        job.request.why_load = opts.why_load;
        // M80 (wire v46): a map-asking link asks the session's own full
        // walk for the placed image's report — the served document is
        // written to the `-map` path below, verbatim (the daemon never
        // touches the filesystem; the fallback below writes the
        // one-shot's own render).
        job.request.map = opts.map_path.is_some();
        let socket = opts
            .resident_socket
            .clone()
            .map_or_else(pgr_daemon::default_socket, std::path::PathBuf::from);
        let exe_hint = std::env::current_exe().ok();
        match pgr_daemon::link_via_daemon(&socket, exe_hint.as_deref(), &job) {
            Ok(img) => {
                // The served report prints beside the resident link (the
                // session's own observed pipeline); the fallback below
                // prints the one-shot's — either way the run is observed.
                if timing {
                    if let Some(served) = &img.time_report {
                        if opts.time {
                            print!("{}", served.render());
                        }
                        if opts.time_json {
                            println!("{}", served.render_json());
                        }
                    }
                }
                // M62: the served timeline writes beside the resident link
                // (the document rides the reply verbatim; the `-map`
                // contract — the sidecar writes when the link completes).
                if let (Some(path), Some(json)) = (&opts.trace_path, &img.trace_json) {
                    std::fs::write(Path::new(path), json).map_err(|source| DriverError::Io {
                        path: path.clone(),
                        source,
                    })?;
                }
                // M79: the served answers print beside the resident link
                // — the session's own renders, verbatim (the wire never
                // re-shapes the face the client prints; the vacuous
                // query is the session's `ERROR` — the fallback below
                // refuses with the same message).
                if let Some(served) = &img.provenance {
                    for export in &served.exports {
                        print!("{}", export.render);
                    }
                    if let Some(loads) = &served.loads {
                        print!("{loads}");
                    }
                }
                // M80: the served map writes beside the resident link
                // (the document rides the reply verbatim — the same
                // `-map` contract the trace rides, the sidecar writes
                // when the link completes; the daemon never touches the
                // filesystem, the client does).
                if let (Some(path), Some(document)) = (&opts.map_path, &img.map_text) {
                    std::fs::write(Path::new(path), document).map_err(|source| {
                        DriverError::Io {
                            path: path.clone(),
                            source,
                        }
                    })?;
                }
                let record = img.record.and_then(|bytes| {
                    let decoded = pgr_emit::incremental::LinkRecord::decode(&bytes);
                    if decoded.is_none() {
                        // The workspace's observability convention: a span,
                        // not a bare eprintln — the debug envs install the
                        // subscriber (main.rs); without one the event is
                        // inert, and library consumers keep their own.
                        tracing::warn!("the daemon's record did not decode; dropping it");
                    }
                    decoded
                });
                // M60: the dependency record is the client-side read set
                // (the request's own input list — Pass 0 mapped it before
                // the wire), so the served link writes it too; the daemon
                // never touches the filesystem, the client does.
                write_dependency_record(opts, &prepared.deps)?;
                // M76: the served verdict is the resident lane's gate face
                // — the session's own strict pass on the exact bytes the
                // reply carries (the `-no_adhoc` carve-out applied the
                // session's way, v43). The caller gates the write on it; a
                // verdict the protocol somehow rode absent falls back to
                // the caller's local pass on the same bytes.
                let served_gate = if opts.verify {
                    img.verify_report.as_ref().map(gate_from_served)
                } else {
                    None
                };
                return Ok((
                    ImageAndPlan {
                        image: img.image,
                        entryoff: img.entryoff,
                        fixup_slots: usize::try_from(img.fixup_slots).unwrap_or(usize::MAX),
                    },
                    record,
                    // The served faces rode the wire (the session's own
                    // observed pipeline); the client collects nothing
                    // locally (M59/M62's shape, unchanged).
                    PendingFaces {
                        time: None,
                        trace: None,
                    },
                    served_gate,
                ));
            }
            Err(e) => {
                // The span, not the eprintln (the workspace convention):
                // the debug envs install the subscriber, and library
                // consumers keep their own.
                tracing::warn!(error = %e, "the resident cycle fell back to the one-shot link");
            }
        }
    }
    // The M9 resolve wiring, capture half: the recording link carries its
    // Pass-2 snapshot out of the pipeline so the record's v5 section can
    // hold it. The resident path above captures through the wire; this
    // half serves the one-shot path.
    prepared.config.record_resolution = opts.incremental;
    // M58/M61/M68: `--time`/`--time-json`/`--trace` subscribe the
    // collectors to the M54 observation seam — the same pipeline,
    // observed (the parity gate is the seam's own contract: neither face
    // moves a byte of the plan). Both faces read the one observed run;
    // the [`FaceSlot`] serves them together when both ride, and stays
    // the subscription the emit half reports through below.
    let started = std::time::Instant::now();
    let mut times = pgr_core::TimeCollector::default();
    let mut traces = pgr_core::trace::TraceCollector::new();
    let result = if timing {
        let mut slot = FaceSlot::new(
            (opts.time || opts.time_json).then_some(&mut times),
            opts.trace_path.is_some().then_some(&mut traces),
        );
        // M65: the ladder's handover note leads the report — the
        // collectors carry it into the run that actually produced the
        // output (a table that hid the fallback would misread the run;
        // the same convention that names the resolve-reuse fallback on
        // the one-shot report).
        if let Some(note) = seed {
            slot.on_note(note.clone());
        }
        pgr_core::link_observed(
            &prepared.inputs,
            &prepared.archives,
            &prepared.config,
            pgr_core::Parallelism::Auto,
            cache.as_ref(),
            &mut slot,
        )?
    } else {
        pgr_core::link_cached(
            &prepared.inputs,
            &prepared.archives,
            &prepared.config,
            pgr_core::Parallelism::Auto,
            cache.as_ref(),
        )?
    };
    check_force_load(&result, &prepared.force_load)?;
    // M11: the ld64-style advisory — an order-file entry that ranked no
    // placed piece is a typo, not an error (the layout plans what the
    // inputs define). Warn once per unranked entry, in entry order.
    for name in &result.layout.order_unmatched {
        tracing::warn!(
            symbol = %String::from_utf8_lossy(name),
            "the order-file entry ranked no placed piece"
        );
        eprintln!(
            "pgr: warning: order file symbol {} not matched by any input",
            String::from_utf8_lossy(name)
        );
    }
    // M14: the filter's advisory — a list pattern that matched no
    // symbol in the plan is a typo, not an error (the link is correct,
    // the intent is not; ld64 warns the same way on order files). Warn
    // once per unmatched pattern, in list order.
    {
        let patterns = prepared
            .config
            .exported_only
            .iter()
            .flatten()
            .chain(prepared.config.unexported.iter());
        for pattern in patterns {
            let matched = result
                .layout
                .symbols
                .iter()
                .any(|s| pattern.matches(result.interner.bytes(s.name)));
            if !matched {
                tracing::warn!(
                    pattern = %String::from_utf8_lossy(pattern.source()),
                    "the export-filter pattern matched no symbol"
                );
                eprintln!(
                    "pgr: warning: symbol list pattern {} matched no symbol",
                    String::from_utf8_lossy(pattern.source())
                );
            }
        }
    }
    // M68: the emit half rides the seam — the fused tile emit (Pass 4)
    // reports its completion to the same subscription the pipeline's
    // phases used (the parity gate is the seam's own contract); the
    // flush (Pass 5) joins the same collection in [`run`], the caller's
    // atomic write, so one collection covers the run end to end.
    let image = if timing {
        let mut slot = FaceSlot::new(
            (opts.time || opts.time_json).then_some(&mut times),
            opts.trace_path.is_some().then_some(&mut traces),
        );
        pgr_emit::build_image_fused_observed(&result.layout, &result.objects, &mut slot)?
    } else {
        pgr_emit::build_image_fused(&result.layout, &result.objects)?
    };
    // M11: the link map — the plan's own segments/sections/symbols,
    // rendered deterministically and written beside the link.
    if let Some(map_path) = &opts.map_path {
        let map = pgr_core::map::build_link_map(&result.layout, &result.interner);
        std::fs::write(Path::new(map_path), map.render()).map_err(|source| DriverError::Io {
            path: map_path.clone(),
            source,
        })?;
    }
    // M60: the dependency record — the link's read set plus the output
    // (and the map beside it), written once the link succeeded (ld64
    // writes the file when the link completes).
    write_dependency_record(opts, &prepared.deps)?;
    // M56: the provenance queries — one text report per queried name,
    // in flag order, over the link's own Pass-2 product (a vacuous
    // query refuses the run: the misspelling is named, never empty).
    print_why_export(
        &result.objects,
        &result.resolution,
        &result.interner,
        &opts.why_export,
    )?;
    // M57: the load report — why each archive member rode the pull
    // (and, under `-dead_strip_dylibs`, every input dylib's carriage).
    if opts.why_load {
        print!("{}", result.loads.render());
    }
    // M68: the pending faces ride out to the caller — the flush (Pass 5,
    // the pooled atomic write) joins the same collection before the faces
    // build (one collection per run; the report's rows stay in link
    // order through the emit half, the total band measuring the wall
    // through the flush). The band face stays the library caller's: the
    // driver's rows ride the seam, `report.emit` stays `None`.
    let faces = PendingFaces {
        time: (opts.time || opts.time_json).then_some((times, started)),
        trace: opts.trace_path.is_some().then_some(traces),
    };
    let record = if opts.incremental {
        Some(pgr_emit::incremental::LinkRecord::record(
            &result.layout,
            &result.objects,
            &image,
            result.resolve_snapshot.as_ref(),
        )?)
    } else {
        None
    };
    Ok((
        ImageAndPlan {
            entryoff: result.layout.entryoff,
            fixup_slots: result.layout.fixups.slot_count,
            image,
        },
        record,
        faces,
        // M76: the one-shot lane gates through the caller's local pass —
        // no served verdict rode the wire here.
        None,
    ))
}

/// Links the option inputs through the **pre-fusion reference emit** (the
/// M1–M3 Pass 4 body, kept verbatim). The M4 correctness gate compares this
/// byte-for-byte against [`link_to_image`]; benches use it as the baseline.
///
/// # Errors
/// [`DriverError`] on option, link, emit, tbd or I/O failures.
pub fn link_reference_image(opts: &opts::Options) -> Result<ImageAndPlan, DriverError> {
    let result = link_inputs_for_emit(opts)?;
    let image = pgr_emit::build_image(&result.layout, &result.objects)?;
    Ok(ImageAndPlan {
        entryoff: result.layout.entryoff,
        fixup_slots: result.layout.fixups.slot_count,
        image,
    })
}

/// The M8 prepared link state: everything Pass 0 mapped, ready for the
/// pipeline. Both the one-shot path and the resident path (`-resident`)
/// consume it — the resident client turns it into a wire request.
#[derive(Debug)]
pub struct PreparedLink {
    /// Direct object inputs, in command order (bytes included).
    pub inputs: Vec<LinkInput>,
    /// Static archives, in command order (members lazy).
    pub archives: Vec<LinkArchive>,
    /// The link configuration handed to Pass 3.
    pub config: pgr_core::layout::LinkConfig,
    /// `-u` names (the daemon runs the same gate).
    pub force_load: Vec<Vec<u8>>,
    /// The M60 dependency record Pass 0 built: every file the mapping
    /// read (objects, archives, resolved libraries, `-sectcreate`
    /// payloads, list files, the bundle loader, the order file) and
    /// every probed-but-missing `-l`/`-framework` candidate — the link's
    /// read set, recorded while the reads happen. The output rows join
    /// at the write site (the consumer knows the flag's path).
    pub deps: pgr_core::dep_info::DependencyRecord,
}

/// Runs Passes 0–3 for the option inputs and returns the emit plan (the
/// shared front half of [`link_to_image`] and [`link_reference_image`]).
fn link_inputs_for_emit(opts: &opts::Options) -> Result<pgr_core::LinkResult, DriverError> {
    let (prepared, cache) = prepare_link(opts)?;
    let result = pgr_core::link_cached(
        &prepared.inputs,
        &prepared.archives,
        &prepared.config,
        pgr_core::Parallelism::Auto,
        cache.as_ref(),
    )?;
    check_force_load(&result, &prepared.force_load)?;
    Ok(result)
}

/// The driver's `-u` gate over the shared [`pgr_core::check_load_symbols`]
/// (the resident server runs the same check; the message shape stays the
/// M5 driver's).
fn check_force_load(result: &pgr_core::LinkResult, names: &[Vec<u8>]) -> Result<(), DriverError> {
    pgr_core::check_load_symbols(result, names).map_err(|e| match e {
        pgr_core::LinkError::Symbol { name, .. } => DriverError::ForceLoad {
            symbol: name,
            message: "not defined by any input (direct objects or pulled archive members)".into(),
        },
        other => other.into(),
    })
}

/// Pass 0 (M8 shape): maps the option inputs into a [`PreparedLink`] plus
/// the optional Stage A cache (the one-shot path consumes the cache;
/// the resident daemon holds its own in-memory state instead).
fn prepare_link(opts: &opts::Options) -> Result<(PreparedLink, Option<PoiCache>), DriverError> {
    // M6 Stage A caches: opt-in via `-cache <dir>` / `PGR_CACHE_DIR`;
    // `-no_cache` always wins. A cache failure never fails the link.
    // M7: the directory is size-bounded (oldest-mtime LRU eviction) —
    // `-cache_max <bytes>` / `PGR_CACHE_MAX`, default 2 GiB; `0` = unbounded.
    const DEFAULT_CACHE_MAX: u64 = 2 * 1024 * 1024 * 1024;
    // M60: the dependency record opens with the tool's version row and
    // fills while Pass 0 reads (each read site records its own row — the
    // record is the link's read set, never a post-hoc reconstruction).
    let mut deps = pgr_core::dep_info::DependencyRecord::new(&version_line())?;
    let cache_max = opts.cache_max.or_else(|| {
        std::env::var("PGR_CACHE_MAX")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
    });
    let cache = if opts.no_cache {
        None
    } else {
        opts.cache_dir
            .clone()
            .or_else(|| std::env::var("PGR_CACHE_DIR").ok())
            .and_then(|dir| {
                pgr_core::cache::PoiCache::open_limited(
                    std::path::Path::new(&dir),
                    cache_max.unwrap_or(DEFAULT_CACHE_MAX),
                )
                .ok()
            })
    };
    let mut inputs = Vec::with_capacity(opts.inputs.len());
    let mut archives: Vec<LinkArchive> = Vec::new();
    let mut dylibs: Vec<Dylib> = Vec::new();

    // M5 `-filelist`: expand newline-separated paths (each relative to the
    // optional base dir) ahead of the command-line inputs — the expansion
    // order is the command-line order.
    let mut expanded_inputs: Vec<String> = Vec::new();
    for (path, dir) in &opts.filelists {
        let text = std::fs::read_to_string(path).map_err(|source| DriverError::Io {
            path: path.clone(),
            source,
        })?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let resolved = match dir {
                Some(d) => Path::new(d).join(line).display().to_string(),
                None => line.to_string(),
            };
            expanded_inputs.push(resolved);
        }
    }

    // Expanded filelist entries carry no `-weak_library`/`-reexport_library`
    // markers (those flags push onto `opts.inputs` directly).
    for path in &expanded_inputs {
        map_input(
            path,
            None,
            opts,
            cache.as_ref(),
            &mut deps,
            &mut inputs,
            &mut archives,
            &mut dylibs,
        )?;
    }
    for (i, path) in opts.inputs.iter().enumerate() {
        map_input(
            path,
            Some(i),
            opts,
            cache.as_ref(),
            &mut deps,
            &mut inputs,
            &mut archives,
            &mut dylibs,
        )?;
    }
    // `-l` library search: `.tbd` stubs (M2), Mach-O dylib binaries (M3),
    // static archives (M5). M7: the search list is the ld64-effective
    // dirs — `-syslibroot`-reshaped, defaults appended.
    let lib_dirs = opts::effective_lib_dirs(&opts.lib_dirs, &opts.syslibroots);
    for name in &opts.libs {
        // M60: the search's probes and hits ride the dependency record —
        // ld64's `checkFileExists` records every probed-but-missing
        // candidate (the consumer learns where the search looked), and
        // the resolved file rides an input row.
        let mut probes = Vec::new();
        let found = resolve_lib(name, &lib_dirs, &mut probes)?;
        // The misses ride the record whether or not a later candidate
        // hit — ld64 records them at stat time, the search's own story.
        for probe in &probes {
            deps.record_not_found(&dep_path(probe))?;
        }
        let Some((path, bytes)) = found else {
            return Err(DriverError::Tbd {
                path: format!("lib{name}.tbd"),
                source: pgr_format::FormatError::Malformed {
                    what: format!(
                        "library not found (searched: {} — each -syslibroot-prefixed \
                         as ld64 does)",
                        lib_dirs.join(", ")
                    ),
                },
            });
        };
        deps.record_input(&dep_path(&path))?;
        // M70: a universal container rides its arm64 slice — the unwrap
        // runs before the per-kind dispatch (the `.tbd`/dylib/archive
        // arms below link the slice they already linked).
        let bytes = match universal_arm64_slice(&path, &bytes)? {
            Some(sliced) => sliced,
            None => bytes,
        };
        if looks_like_tbd(&bytes) {
            dylibs.push(tbd_to_dylib_cached(&path, &bytes, false, cache.as_ref())?);
        } else if pgr_format::MachHeader64::parse(&bytes)
            .is_ok_and(|h| h.filetype == pgr_format::consts::MH_DYLIB)
        {
            dylibs.push(scan_dylib(&path, &bytes)?);
        } else if pgr_format::is_archive(&bytes) {
            push_archive(&mut archives, &path, bytes, opts)?;
        } else if is_llvm_bitcode(&bytes) {
            return Err(DriverError::LtoObject { path });
        } else {
            return Err(DriverError::Tbd {
                path,
                source: pgr_format::FormatError::Malformed {
                    what: "not a .tbd stub, Mach-O dylib or static archive".into(),
                },
            });
        }
    }
    // M5 `-framework` search (M7: ld64-effective `-F` dirs + defaults).
    // M14: the weak/lazy framework kinds resolve through the same search
    // after the plain frameworks (the lists are separate in `Options`;
    // the LC order — and with it the two-level ordinals — is plain,
    // weak, then lazy). M23: the re-export frameworks resolve through
    // the same search after the plain frameworks and before the weak
    // ones (the order is plain, re-export, weak, then lazy — an empty
    // list leaves every pre-M23 link byte-identical). M45: the upward
    // frameworks resolve after the lazy ones (the order is plain,
    // re-export, weak, lazy, then upward — the umbrella mark rides last).
    let framework_dirs = opts::effective_framework_dirs(&opts.framework_dirs, &opts.syslibroots);
    for (name, kind) in opts
        .frameworks
        .iter()
        .map(|n| (n, DylibKind::Load))
        .chain(
            opts.reexport_frameworks
                .iter()
                .map(|n| (n, DylibKind::Reexport)),
        )
        .chain(opts.weak_frameworks.iter().map(|n| (n, DylibKind::Weak)))
        .chain(opts.lazy_frameworks.iter().map(|n| (n, DylibKind::Lazy)))
        .chain(
            opts.upward_frameworks
                .iter()
                .map(|n| (n, DylibKind::Upward)),
        )
    {
        // M60: the framework search rides the record like the `-l`
        // search (the probes and the resolved payload).
        let mut probes = Vec::new();
        let found = resolve_framework(name, &framework_dirs, &mut probes)?;
        for probe in &probes {
            deps.record_not_found(&dep_path(probe))?;
        }
        let Some((path, bytes)) = found else {
            return Err(DriverError::Tbd {
                path: format!("{name}.framework/{name}"),
                source: pgr_format::FormatError::Malformed {
                    what: format!(
                        "framework not found (searched: {})",
                        framework_dirs.join(", ")
                    ),
                },
            });
        };
        deps.record_input(&dep_path(&path))?;
        // M70: a universal container rides its arm64 slice (SDK
        // frameworks ship fat) — the unwrap runs before the dispatch.
        let bytes = match universal_arm64_slice(&path, &bytes)? {
            Some(sliced) => sliced,
            None => bytes,
        };
        let mut dylib = if looks_like_tbd(&bytes) {
            tbd_to_dylib_cached(&path, &bytes, kind == DylibKind::Weak, cache.as_ref())?
        } else if pgr_format::MachHeader64::parse(&bytes)
            .is_ok_and(|h| h.filetype == pgr_format::consts::MH_DYLIB)
        {
            let mut scanned = scan_dylib(&path, &bytes)?;
            scanned.weak = kind == DylibKind::Weak;
            scanned
        } else {
            return Err(DriverError::Tbd {
                path,
                source: pgr_format::FormatError::Malformed {
                    what: "framework payload is not a .tbd stub or Mach-O dylib".into(),
                },
            });
        };
        dylib.lazy = kind == DylibKind::Lazy;
        dylib.reexport = kind == DylibKind::Reexport;
        dylib.upward = kind == DylibKind::Upward;
        dylibs.push(dylib);
    }
    // M5 `-sectcreate`: section contents from a file, carried as a synthetic
    // single-section object (no symbols — placed by the bucketing pass).
    for (seg, sect, file) in &opts.sectcreate {
        let data = std::fs::read(file).map_err(|source| DriverError::Io {
            path: file.clone(),
            source,
        })?;
        // M60: the section payload rides the record (ld64's `depSection`
        // — an input-family row like every other read file).
        deps.record_input(&dep_path(file))?;
        // M67: the name-length refusal rides its typed `SynthError` (it
        // stopped masquerading as a `.tbd` parse failure).
        let obj = synth::section_object(seg, sect, &data)?;
        inputs.push(LinkInput {
            name: format!("-sectcreate {seg},{sect} ({file})"),
            bytes: obj,
        });
    }

    let mut config = opts.config.clone();
    config.dylibs = dylibs;
    // M25 `-bundle_loader`: the host's export surface is scanned here
    // (Pass 0 reads the host file once; the exports ride the config to
    // Pass 2 and across the wire — protocol v16).
    if let Some(path) = &opts.bundle_loader {
        let bytes = std::fs::read(path).map_err(|source| DriverError::Io {
            path: path.clone(),
            source,
        })?;
        // M60: the host file rides the record (ld64's `depBundleLoader`).
        deps.record_input(&dep_path(path))?;
        config.bundle_loader = Some(scan_loader_executable(path, &bytes)?);
    }
    config.load_symbols = opts
        .force_load
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
    // M3 dylib defaults: the install name defaults to the output path
    // (ld64 behavior); M44 `-final_output` supplies the default when
    // named (the man-page rule — the multi-arch driver records the
    // universal path, not the slice's `-o` path; the explicit
    // `-install_name` always wins); dylibs/bundles never load a
    // dylinker.
    if config.filetype == pgr_core::layout::OutputType::Dylib && config.install_name.is_none() {
        config.install_name = Some(match opts.final_output.clone() {
            Some(final_output) => final_output,
            None => opts.output.clone(),
        });
    }
    if config.filetype != pgr_core::layout::OutputType::Execute {
        config.dynamic_linker = false;
    }
    // M3 export filters, M14 glob-widened (the patterns ride the config;
    // the wire mirrors them — protocol v7).
    if let Some(path) = &opts.exported_list_path {
        // M60: the symbol lists ride the record (ld64's `depMisc` rows —
        // the files the link read to shape the export surface).
        deps.record_input(&dep_path(path))?;
        config.exported_only = Some(read_symbol_patterns("-exported_symbols_list", path)?);
    }
    if let Some(path) = &opts.unexported_list_path {
        deps.record_input(&dep_path(path))?;
        config.unexported = read_symbol_patterns("-unexported_symbols_list", path)?;
    }
    // M11: the order file — read, parse (typed, line-tagged refusals),
    // and rank before Pass 3. The advisory for entries that rank nothing
    // rides the finished layout (ld64 warns; Peregrine does the same
    // after the link, where the symbol universe is known).
    if let Some(path) = &opts.order_file {
        let text = std::fs::read_to_string(path).map_err(|source| DriverError::Io {
            path: path.clone(),
            source,
        })?;
        // M60: the order file rides the record (a file the link read —
        // the rank table is as much a build input as any object).
        deps.record_input(&dep_path(path))?;
        let file =
            pgr_core::order::OrderFile::parse(&text).map_err(|e| DriverError::OrderFile {
                path: path.clone(),
                message: e.to_string(),
            })?;
        config.symbol_order = Some(pgr_core::order::SymbolOrder::build(&file));
    }
    let force_load: Vec<Vec<u8>> = opts
        .force_load
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
    Ok((
        PreparedLink {
            inputs,
            archives,
            config,
            force_load,
            deps,
        },
        cache,
    ))
}

/// Detects LLVM bitcode: raw bitcode files start with `BC\xC0\xDE`, the
/// wrapper format with `0x0B17C0DE` (little-endian bytes `DE C0 17 0B`).
#[must_use]
pub fn is_llvm_bitcode(bytes: &[u8]) -> bool {
    bytes.starts_with(b"BC\xC0\xDE") || bytes.starts_with(&[0xDE, 0xC0, 0x17, 0x0B])
}

/// The path the M60 dependency record carries: ld64's `addDependency`
/// runs non-absolute paths through `realpath()` at record time (the
/// resolved file is what the build system tracks) and keeps the path as
/// written when the resolution fails — the same shape here, one helper
/// so every read site records the same view of one file.
fn dep_path(path: &str) -> String {
    if path.starts_with('/') {
        return path.to_owned();
    }
    std::fs::canonicalize(path).map_or_else(|_| path.to_owned(), |p| p.display().to_string())
}

/// Writes the M60 dependency record beside the link: the output (and the
/// `-map` beside it — ld64's own shape) join the record Pass 0 built,
/// and the bytes land at the flag's path. The write happens once per
/// successful link, after the image is in hand (ld64 writes the file
/// when the link completes); a failure to write it is a real I/O error,
/// never a silent skip — the map write's own contract.
fn write_dependency_record(
    opts: &opts::Options,
    deps: &pgr_core::dep_info::DependencyRecord,
) -> Result<(), DriverError> {
    if let Some(path) = &opts.dependency_info {
        let mut record = deps.clone();
        record.record_output(&opts.output)?;
        if let Some(map) = &opts.map_path {
            record.record_output(map)?;
        }
        std::fs::write(Path::new(path), record.render()).map_err(|source| DriverError::Io {
            path: path.clone(),
            source,
        })?;
    }
    Ok(())
}

/// Classifies and maps one input path: `.tbd`/dylib → [`Dylib`], archive →
/// [`LinkArchive`] (lazy members), anything else → a [`LinkInput`] object.
/// `opts_index` carries the `-weak_library`/`-reexport_library` marker index
/// (`None` for filelist-expanded paths).
fn map_input(
    path: &str,
    opts_index: Option<usize>,
    opts: &opts::Options,
    cache: Option<&pgr_core::cache::PoiCache>,
    deps: &mut pgr_core::dep_info::DependencyRecord,
    inputs: &mut Vec<LinkInput>,
    archives: &mut Vec<LinkArchive>,
    dylibs: &mut Vec<Dylib>,
) -> Result<(), DriverError> {
    let bytes = std::fs::read(path).map_err(|source| DriverError::Io {
        path: path.to_string(),
        source,
    })?;
    // M60: the mapped input rides the record whichever kind it turns out
    // to be (ld64's object/dylib/archive rows are one input-family opcode
    // in the field) — the file the link read is the row, not its class.
    deps.record_input(&dep_path(path))?;
    // M70: a universal container rides its arm64 slice — the unwrap runs
    // before the per-kind dispatch, so every arm below links the slice it
    // already linked.
    let bytes = match universal_arm64_slice(path, &bytes)? {
        Some(sliced) => sliced,
        None => bytes,
    };
    if looks_like_tbd(&bytes) {
        let weak = opts_index.is_some_and(|i| opts.weak_library_inputs.contains(&i));
        let mut dylib = tbd_to_dylib_cached(path, &bytes, weak, cache)?;
        dylib.reexport = opts_index.is_some_and(|i| opts.reexport_library_inputs.contains(&i));
        dylib.lazy = opts_index.is_some_and(|i| opts.lazy_library_inputs.contains(&i));
        dylib.upward = opts_index.is_some_and(|i| opts.upward_library_inputs.contains(&i));
        dylibs.push(dylib);
        return Ok(());
    }
    // M3: Mach-O dylib binaries are linkable inputs (install name + exports
    // scanned from the image).
    if pgr_format::MachHeader64::parse(&bytes)
        .is_ok_and(|h| h.filetype == pgr_format::consts::MH_DYLIB)
    {
        let mut dylib = scan_dylib(path, &bytes)?;
        dylib.reexport = opts_index.is_some_and(|i| opts.reexport_library_inputs.contains(&i));
        dylib.lazy = opts_index.is_some_and(|i| opts.lazy_library_inputs.contains(&i));
        dylib.upward = opts_index.is_some_and(|i| opts.upward_library_inputs.contains(&i));
        dylibs.push(dylib);
        return Ok(());
    }
    // M5: static archives carry their members lazily — the ranlib index
    // drives the pull fixpoint (S7).
    if pgr_format::is_archive(&bytes) {
        push_archive(archives, path, bytes, opts)?;
        return Ok(());
    }
    if opts_index.is_some_and(|i| opts.reexport_library_inputs.contains(&i)) {
        return Err(DriverError::Tbd {
            path: path.to_string(),
            source: pgr_format::FormatError::Malformed {
                what: "-reexport_library input is not a dylib (.tbd or Mach-O)".into(),
            },
        });
    }
    // M6 LTO pass-through scope: bitcode objects are detected up front and
    // diagnosed (the roadmap's LTO backend integration is a later item).
    if is_llvm_bitcode(&bytes) {
        return Err(DriverError::LtoObject {
            path: path.to_string(),
        });
    }
    let i = opts_index.unwrap_or(usize::MAX);
    inputs.push(LinkInput {
        name: format!("{path} (input {i})"),
        bytes,
    });
    Ok(())
}

/// Builds a [`LinkArchive`] from raw archive bytes and pushes it (the `-l`
/// path; force-load matching is by resolved path).
fn push_archive(
    archives: &mut Vec<LinkArchive>,
    path: &str,
    bytes: Vec<u8>,
    opts: &opts::Options,
) -> Result<(), DriverError> {
    let parsed = pgr_format::parse_archive(&bytes).map_err(|e| DriverError::Tbd {
        path: path.to_string(),
        source: e,
    })?;
    let force = opts
        .force_load_archives
        .iter()
        .any(|f| Path::new(f) == Path::new(path));
    archives.push(LinkArchive {
        name: path.to_string(),
        bytes,
        index: parsed
            .index
            .iter()
            .map(|e| (e.name.clone().into_bytes(), e.member))
            .collect(),
        members: parsed
            .members
            .iter()
            .map(|m| LinkArchiveMember {
                name: m.name.clone(),
                offset: m.offset,
                size: m.size,
            })
            .collect(),
        all_load: opts.all_load || force,
    });
    Ok(())
}
/// Links `inputs` into image bytes (no filesystem). Kept for callers that
/// only need the bytes (the M4 fused pipeline).
///
/// # Errors
/// [`DriverError`] on option, link or emit failures.
pub fn link_to_bytes(opts: &opts::Options) -> Result<Vec<u8>, DriverError> {
    Ok(link_to_image(opts)?.image)
}

/// Links `inputs` into image bytes through the pre-fusion reference emit.
/// The M4 gate's baseline (see [`link_reference_image`]).
///
/// # Errors
/// [`DriverError`] on option, link or emit failures.
pub fn link_reference_bytes(opts: &opts::Options) -> Result<Vec<u8>, DriverError> {
    Ok(link_reference_image(opts)?.image)
}

/// Runs the full driver: link and write the output file.
///
/// M9 `-incremental`: the in-place relink is attempted first (record →
/// plan → patch → re-sign); any §7.3 fallback — no record, changed output,
/// moved skeleton, everything-dirty — silently re-runs the full link, and
/// the full link (re-)records the state for the next round. The fallback
/// is always available and always correct.
///
/// # Errors
/// [`DriverError`] on option, link, emit or filesystem failures.
pub fn run(opts: &opts::Options) -> Result<LinkOutcome, DriverError> {
    // M10 rung 1: `-r` bypasses the image pipeline entirely — Passes 1–2
    // plus the object emit; no segment layout, no record, no
    // signature (the conflicting knobs are refused at parse time).
    // M83: the resident lane serves the object shape — a stand-down
    // (no daemon, a session refusal) hands over to the one-shot
    // relocatable link, whose own walk produces the same bytes.
    if opts.config.filetype == pgr_core::layout::OutputType::Relocatable {
        if opts.resident {
            match run_resident_relocatable(opts) {
                Ok(outcome) => return Ok(outcome),
                Err(ResidentAttempt::Error(e)) => return Err(e),
                Err(ResidentAttempt::StandDown(reason)) => {
                    if std::env::var_os("PGR_RESIDENT_DEBUG").is_some() {
                        eprintln!("pgr: resident relocatable stand-down: {reason}");
                    }
                }
            }
        }
        return run_relocatable(opts);
    }
    if opts.incremental && opts.resident {
        // M9 GA fusion rung: with a daemon reachable the relink runs
        // inside the resident session (warm POIs; the patched bytes cross
        // the wire and the write below stays the client's) — and since
        // the audited rung (wire v4) the daemon also *serves* the
        // `-incremental-verify` audit, so `-resident -incremental
        // -incremental-verify` no longer stands down. Any stand-down — no
        // daemon, no record, a §7.3 refusal — hands over to the
        // in-process relink, then to the full link: the ladder's rungs in
        // order, every one always available.
        match resident_relink(opts) {
            Ok(outcome) => return Ok(outcome),
            Err(ResidentAttempt::Error(e)) => return Err(e),
            Err(ResidentAttempt::StandDown(reason)) => {
                if std::env::var_os("PGR_RESIDENT_DEBUG").is_some() {
                    eprintln!("pgr: resident relink stand-down: {reason}");
                }
            }
        }
    }
    // M65: the timing flags ride the ladder. The collectors own the whole
    // run here — the ladder's rungs report through the observer (the warm
    // pipeline's Passes 1–3 included), and a successful ladder prints the
    // faces it collected (the emit band absent: the relink's Pass-4 half
    // is the in-memory patch, the session's own convention). A fallback
    // seeds its note into the full link's report below — the run that
    // produced the output names the handover (one report per run, never
    // two).
    let mut handover_note: Option<pgr_core::observe::LinkNote> = None;
    if opts.incremental {
        let timing = opts.time || opts.time_json || opts.trace_path.is_some();
        let ladder = if timing {
            let started = std::time::Instant::now();
            let mut times = pgr_core::TimeCollector::default();
            let mut traces = pgr_core::trace::TraceCollector::new();
            let relink = if opts.trace_path.is_some() && (opts.time || opts.time_json) {
                let mut pair = pgr_core::ObserverPair::new(&mut times, &mut traces);
                incremental_relink(opts, Some(&mut pair))
            } else if opts.trace_path.is_some() {
                incremental_relink(opts, Some(&mut traces))
            } else {
                incremental_relink(opts, Some(&mut times))
            };
            match relink {
                Ok(outcome) => {
                    let total = started.elapsed();
                    let mut report = times.report();
                    report.total = Some(total);
                    if opts.time {
                        print!("{}", report.render());
                    }
                    if opts.time_json {
                        println!("{}", report.render_json());
                    }
                    if let Some(trace_path) = &opts.trace_path {
                        let timeline = traces.finish();
                        std::fs::write(Path::new(trace_path), timeline.render()).map_err(
                            |source| DriverError::Io {
                                path: trace_path.clone(),
                                source,
                            },
                        )?;
                    }
                    Some(Ok(outcome))
                }
                Err(RelinkAttempt::Error(e)) => Some(Err(e)),
                Err(RelinkAttempt::Fallback(reason)) => {
                    if std::env::var_os("PGR_INCREMENTAL_DEBUG").is_some() {
                        eprintln!("pgr: incremental fallback: {reason}");
                    }
                    handover_note = Some(pgr_core::observe::LinkNote::RelinkFallback {
                        reason: reason.to_string(),
                    });
                    None
                }
            }
        } else {
            match incremental_relink(opts, None) {
                Ok(outcome) => Some(Ok(outcome)),
                Err(RelinkAttempt::Error(e)) => Some(Err(e)),
                Err(RelinkAttempt::Fallback(reason)) => {
                    if std::env::var_os("PGR_INCREMENTAL_DEBUG").is_some() {
                        eprintln!("pgr: incremental fallback: {reason}");
                    }
                    None
                }
            }
        };
        if let Some(res) = ladder {
            return res;
        }
    }
    // §7.3 "layout stability": the in-place tier stands on slack anchors,
    // so `-incremental` implies slack layout for the whole link cycle —
    // the cold full link reserves the same padding its record describes,
    // and the first edited relink can patch in place. M65: the ladder's
    // handover note leads the full link's report (the collectors seed it
    // before the pipeline runs — the note names why the rungs stop, the
    // rows name the run that produced the output).
    let (linked, record, mut faces, served_gate) =
        if opts.incremental && opts.config.layout_slack.is_none() {
            let mut slacked = opts.clone();
            slacked.config.layout_slack = Some(pgr_core::slack::SlackPolicy::default());
            link_to_image_recorded(&slacked, handover_note.as_ref())?
        } else {
            link_to_image_recorded(opts, handover_note.as_ref())?
        };
    // M73: the link's own gate. `-verify` runs the strict verifier on
    // the produced bytes before the write — a failing gate ships
    // nothing (the file is never created; the audit's rule, on the cold
    // path), and a passing one rides the outcome's summary. M76: on the
    // resident lane the session's own served verdict is the gate face
    // (the strict pass on the exact bytes the reply carries, the
    // `-no_adhoc` carve-out applied the session's way) — the client
    // consumes it instead of re-running the pass; every other lane runs
    // the local gate. Either way the gate sits before the write. M77:
    // the check selection narrows the pass to the named families —
    // cold and fallback lanes run the selected pass locally, the
    // resident lane's served verdict was narrowed by the session
    // (wire v44 carries the set).
    let gate_summary = if opts.verify {
        let gate = served_gate.unwrap_or_else(|| match &opts.verify_checks {
            Some(set) => verify_gate_selected(&linked.image, opts.config.adhoc, set),
            None => verify_gate(&linked.image, opts.config.adhoc),
        });
        if !gate.summary.ok {
            return Err(DriverError::Verify {
                path: opts.output.clone(),
                detail: gate.refusal().render(),
            });
        }
        Some(gate.summary)
    } else {
        None
    };
    // M68: the flush (Pass 5, the pooled atomic write) joins the same
    // collection before the faces build — the report's rows stay in link
    // order through the emit half, the total band measuring the wall
    // through the flush (the reports print beside the link, not inside
    // it — the M58 convention, now with the whole pipeline on the rows).
    if faces.time.is_some() || faces.trace.is_some() {
        {
            let mut slot = FaceSlot::new(
                faces.time.as_mut().map(|(times, _)| times),
                faces.trace.as_mut(),
            );
            write_image_observed(&linked.image, Path::new(&opts.output), &mut slot)?;
        }
        // M58: the per-pass wall report — the collector's phase rows
        // (the pipeline's passes and the emit half) plus the total band
        // (the wall through the flush), printed beside the link (the
        // text face under `--time`, the interchange line under
        // `--time-json`; the `emit` band stays the library caller's —
        // the driver's rows ride the seam).
        if let Some((times, started)) = faces.time.take() {
            let mut report = times.report();
            report.total = Some(started.elapsed());
            if opts.time {
                print!("{}", report.render());
            }
            if opts.time_json {
                println!("{}", report.render_json());
            }
        }
        // M61: the Chrome-trace timeline — the collector's spans rendered
        // in the Trace Event Format's object form, written beside the
        // link (the `-map` contract: the sidecar writes when the link
        // completes).
        if let Some(traces) = faces.trace.take() {
            if let Some(trace_path) = &opts.trace_path {
                let timeline = traces.finish();
                std::fs::write(Path::new(trace_path), timeline.render()).map_err(|source| {
                    DriverError::Io {
                        path: trace_path.clone(),
                        source,
                    }
                })?;
            }
        }
    } else {
        write_image(&linked.image, Path::new(&opts.output))?;
    }
    if let Some(record) = record {
        store_record(opts, &record);
    }
    Ok(LinkOutcome {
        output: opts.output.clone(),
        file_size: linked.image.len() as u64,
        entryoff: linked.entryoff,
        fixup_slots: linked.fixup_slots,
        patch: None,
        audit: None,
        transport: None,
        verify: gate_summary,
    })
}

/// The M83 resident relocatable attempt: the session runs the object
/// walk (Passes 1–2 over the raw blobs — the POI cache is the segmented
/// pipeline's optimization, the object path re-parses) and the reply's
/// IMAGE tail carries the `MH_OBJECT` verbatim; the client writes it,
/// the served faces print beside the link and the dependency record is
/// the client-side read set (M60's rule, every lane that reads the
/// files). The replay faces never ride: the surface refuses the knobs
/// beside `-r`, and a session that refuses the shape anyway is the
/// stand-down back to [`run_relocatable`].
///
/// # Errors
/// [`ResidentAttempt::Error`] on a driver-level failure (input
/// preparation, the write, the faces); [`ResidentAttempt::StandDown`]
/// when no daemon answers or the session refuses the request — the
/// caller's one-shot link is the ladder's bottom rung.
fn run_resident_relocatable(opts: &opts::Options) -> Result<LinkOutcome, ResidentAttempt> {
    let (prepared, _cache) = prepare_link(opts).map_err(ResidentAttempt::Error)?;
    let timing = opts.time || opts.time_json || opts.trace_path.is_some();
    let mut job = pgr_daemon::LinkJob::build(
        &prepared.config,
        &prepared.force_load,
        &prepared.inputs,
        &prepared.archives,
    );
    // M58/M59 (wire v40): the session observes its own walk.
    job.request.time = timing;
    // M61/M62 (wire v41): the same for the timeline.
    job.request.trace = opts.trace_path.is_some();
    // M79 (wire v45): the provenance queries ride the object's Pass-2
    // product (the relocatable lane's own face — the cold lane prints
    // the same renders).
    job.request.why_export.clone_from(&opts.why_export);
    job.request.why_load = opts.why_load;
    let socket = opts
        .resident_socket
        .clone()
        .map_or_else(pgr_daemon::default_socket, std::path::PathBuf::from);
    let exe_hint = std::env::current_exe().ok();
    match pgr_daemon::link_via_daemon(&socket, exe_hint.as_deref(), &job) {
        Ok(img) => {
            // The served report prints beside the resident link (the
            // session's own observed walk); a fallback prints the
            // one-shot's — either way the run is observed.
            if timing {
                if let Some(served) = &img.time_report {
                    if opts.time {
                        print!("{}", served.render());
                    }
                    if opts.time_json {
                        println!("{}", served.render_json());
                    }
                }
            }
            if let (Some(path), Some(json)) = (&opts.trace_path, &img.trace_json) {
                std::fs::write(Path::new(path), json).map_err(|source| {
                    ResidentAttempt::Error(DriverError::Io {
                        path: path.clone(),
                        source,
                    })
                })?;
            }
            // M79: the served answers print beside the resident link —
            // the session's own renders, verbatim.
            if let Some(served) = &img.provenance {
                for export in &served.exports {
                    print!("{}", export.render);
                }
                if let Some(loads) = &served.loads {
                    print!("{loads}");
                }
            }
            write_image(&img.image, Path::new(&opts.output))
                .map_err(|e| ResidentAttempt::Error(e.into()))?;
            // M60: the dependency record is the client-side read set
            // (the request's own input list — Pass 0 mapped it before
            // the wire), so the served object writes it too.
            write_dependency_record(opts, &prepared.deps).map_err(ResidentAttempt::Error)?;
            Ok(LinkOutcome {
                output: opts.output.clone(),
                file_size: img.image.len() as u64,
                entryoff: img.entryoff,
                fixup_slots: usize::try_from(img.fixup_slots).unwrap_or(usize::MAX),
                patch: None,
                audit: None,
                transport: Some(img.transport),
                verify: None,
            })
        }
        Err(e) => {
            // The span, not the eprintln (the workspace convention): the
            // debug envs install the subscriber, and library consumers
            // keep their own.
            tracing::warn!(error = %e, "the resident relocatable attempt stood down");
            Err(ResidentAttempt::StandDown(e.to_string()))
        }
    }
}

/// The `-r` path (M10 rung 1): Pass 0 maps the inputs exactly as the
/// image pipeline does (filelists, archives, `.tbd` dylibs), Passes 1–2
/// run through [`pgr_core::link_reloc`] — undefined externals stay open,
/// the object is a link *input* — and `pgr_emit::build_object_image`
/// assembles the `MH_OBJECT`. The `-u`/`-force_load` liveness roots ride
/// the archive pull fixpoint through the config; the image-only
/// force-load resolution gate has no object shape (nothing must resolve).
fn run_relocatable(opts: &opts::Options) -> Result<LinkOutcome, DriverError> {
    let (prepared, _cache) = prepare_link(opts)?;
    // M58/M61: the observed reloc run — the object shape's own five
    // phases ride the report and the timeline; the report's emit band
    // stays `None` (the `-r` Pass 4 is the object assembly, not the
    // fused tile emit) and the total carries the front half's wall
    // through the assembly.
    let timing = opts.time || opts.time_json || opts.trace_path.is_some();
    let started = std::time::Instant::now();
    let mut times = pgr_core::TimeCollector::default();
    let mut traces = pgr_core::trace::TraceCollector::new();
    let linked = if timing {
        if opts.trace_path.is_some() && (opts.time || opts.time_json) {
            let mut pair = pgr_core::ObserverPair::new(&mut times, &mut traces);
            pgr_core::link_reloc_observed(
                &prepared.inputs,
                &prepared.archives,
                &prepared.config,
                pgr_core::Parallelism::Auto,
                &mut pair,
            )?
        } else if opts.trace_path.is_some() {
            pgr_core::link_reloc_observed(
                &prepared.inputs,
                &prepared.archives,
                &prepared.config,
                pgr_core::Parallelism::Auto,
                &mut traces,
            )?
        } else {
            pgr_core::link_reloc_observed(
                &prepared.inputs,
                &prepared.archives,
                &prepared.config,
                pgr_core::Parallelism::Auto,
                &mut times,
            )?
        }
    } else {
        pgr_core::link_reloc(
            &prepared.inputs,
            &prepared.archives,
            &prepared.config,
            pgr_core::Parallelism::Auto,
        )?
    };
    let image = pgr_emit::build_object_image(&linked, &prepared.config)?;
    let total = started.elapsed();
    write_image(&image, Path::new(&opts.output))?;
    // M60: the relocatable link reads its inputs exactly as the image
    // pipeline does — the record names them (ld64 serves the file for
    // every link kind).
    write_dependency_record(opts, &prepared.deps)?;
    // M56: the provenance queries ride the relocatable shape too — the
    // object's Pass-2 product is the same arena the query reads.
    print_why_export(
        &linked.objects,
        &linked.resolution,
        &linked.interner,
        &opts.why_export,
    )?;
    // M57: the load report (the pull's members; the dylib rows ride
    // empty — `-r` refuses the `-dead_strip_dylibs` knob).
    if opts.why_load {
        print!("{}", linked.loads.render());
    }
    // M58: the per-pass wall report — the object shape's own run (no
    // fused-emit row: the `-r` Pass 4 is the object assembly, and the
    // total band carries the wall through it).
    if opts.time || opts.time_json {
        let mut report = times.report();
        report.total = Some(total);
        if opts.time {
            print!("{}", report.render());
        }
        if opts.time_json {
            println!("{}", report.render_json());
        }
    }
    // M61: the timeline — the object shape's own run, written beside the
    // object (the `-map` contract).
    if let Some(trace_path) = &opts.trace_path {
        let timeline = traces.finish();
        std::fs::write(Path::new(trace_path), timeline.render()).map_err(|source| {
            DriverError::Io {
                path: trace_path.clone(),
                source,
            }
        })?;
    }
    Ok(LinkOutcome {
        output: opts.output.clone(),
        file_size: image.len() as u64,
        entryoff: 0,
        fixup_slots: 0,
        patch: None,
        audit: None,
        transport: None,
        verify: None,
    })
}

/// Why the M9 incremental attempt did not produce the outcome: a §7.3
/// fallback (the full link follows) or a real driver error (propagated).
enum RelinkAttempt {
    Fallback(pgr_emit::incremental::FallbackReason),
    Error(DriverError),
}

impl From<pgr_emit::incremental::FallbackReason> for RelinkAttempt {
    fn from(reason: pgr_emit::incremental::FallbackReason) -> Self {
        Self::Fallback(reason)
    }
}

/// The record sidecar path: `<output>.pgr-inc`, or `PGR_INCREMENTAL_RECORD`
/// when set (build systems pin it next to their own state).
fn record_path(opts: &opts::Options) -> std::path::PathBuf {
    std::env::var("PGR_INCREMENTAL_RECORD")
        .ok()
        .filter(|s| !s.is_empty())
        .map_or_else(
            || {
                let mut name = std::path::PathBuf::from(&opts.output).into_os_string();
                name.push(".pgr-inc");
                std::path::PathBuf::from(name)
            },
            std::path::PathBuf::from,
        )
}

/// Why the daemon-side relink did not produce the outcome: a stand-down
/// (the in-process relink runs next — never an error, the §7.2
/// transparency contract) or a real driver error (propagated).
enum ResidentAttempt {
    StandDown(String),
    Error(DriverError),
}

impl From<DriverError> for ResidentAttempt {
    fn from(e: DriverError) -> Self {
        Self::Error(e)
    }
}

/// Why a record/previous-output read stood the resident attempt down: a
/// missing file is the ordinary first-cycle shape ("no record yet"), and
/// any other failure says so with its cause — the stand-down reason is the
/// diagnostic the user gets, so a permission error must be diagnosable,
/// not lied about.
fn stand_down_reason(source: &std::io::Error) -> String {
    if source.kind() == std::io::ErrorKind::NotFound {
        "no record for this output yet".into()
    } else {
        format!("the record is unreadable: {source}")
    }
}

/// The M9 GA fusion relink (§7.3 through the daemon, §7.2 transport): the
/// previous record and the previous output's content hash cross the wire
/// (the bytes ride only when the session does not already hold them —
/// every served image is resident output state, wire v5); the daemon runs
/// the ladder — integrity gate, the anchored relink config derived from
/// the record, the pipeline warm over its POIs, the patch plan, the
/// in-memory patch — and returns the changed-tile stream plus the renewed
/// record. The client replays the stream against its local previous
/// output, verifies it against the stream's content hash, and writes the
/// file: the daemon never writes the output (a daemon death mid-link
/// leaves at most a dead socket, never a corrupt output).
///
/// Any refusal stands down to the in-process relink: no daemon, no record,
/// an undecodable record, or the daemon's own internal fallback (its full
/// link answered — but with a fresh record this client then patches from
/// next cycle; standing down keeps the outcome identical to the one-shot
/// cycle).
fn resident_relink(opts: &opts::Options) -> Result<LinkOutcome, ResidentAttempt> {
    let _span = tracing::debug_span!("resident_relink", output = opts.output.as_str()).entered();
    // M84: the provenance queries read the relink's own walk — and the
    // fusion patch serves bytes, not answers (no wire tail carries the
    // walk's Pass-2 product; the session holds it, the client cannot
    // re-derive it from the tiles it replays). The honest lane is the
    // in-process ladder, whose own walk serves the answers either tier:
    // the resident attempt stands down, the next rung in order runs (the
    // §7.2 transparency contract — the handover is named, never a
    // silently unanswered question).
    if !opts.why_export.is_empty() || opts.why_load {
        return Err(ResidentAttempt::StandDown(
            "the provenance queries read the relink's own walk; the fusion patch serves \
             bytes, not answers — the in-process relink serves them"
                .into(),
        ));
    }
    // M85: the read set is the client's Pass 0 — the session's reads live
    // inside the daemon and the wire carries no read set, so a
    // record-bearing relink hands over to the in-process ladder, whose
    // own Pass 0 records the files it mapped (the same stand-down
    // contract: the handover is named, never a record that misreports
    // the run).
    if opts.dependency_info.is_some() {
        return Err(ResidentAttempt::StandDown(
            "the dependency record names the files the relink's Pass 0 read; the fusion \
             ladder's reads live inside the daemon — the in-process relink records its own"
                .into(),
        ));
    }
    let record_bytes = std::fs::read(record_path(opts))
        .map_err(|source| ResidentAttempt::StandDown(stand_down_reason(&source)))?;
    if pgr_emit::incremental::LinkRecord::decode(&record_bytes).is_none() {
        return Err(ResidentAttempt::StandDown(
            "the record did not decode; the in-process relink re-records".into(),
        ));
    }
    let prev = std::fs::read(Path::new(&opts.output)).map_err(|source| {
        ResidentAttempt::StandDown(if source.kind() == std::io::ErrorKind::NotFound {
            "no previous output yet; the in-process relink re-links".into()
        } else {
            format!("the previous output is unreadable: {source}")
        })
    })?;
    // §7.3 "layout stability": the in-place tier stands on slack anchors,
    // so the relink implies the M8-c policy exactly like the in-process
    // path (the daemon anchors the sections from the record itself).
    let mut slacked = opts.clone();
    if slacked.config.layout_slack.is_none() {
        slacked.config.layout_slack = Some(pgr_core::slack::SlackPolicy::default());
    }
    let (prepared, _cache) = prepare_link(&slacked)?;
    let mut job = pgr_daemon::LinkJob::build_incremental(
        &prepared.config,
        &prepared.force_load,
        &prepared.inputs,
        &prepared.archives,
        record_bytes,
        &prev,
    );
    // M9 GA rung 2 (wire v4): the audit rides the request when
    // `-incremental-verify` is on — the daemon's ladder serves the
    // bytes-level audit and the verdict crosses the wire.
    job.request.audit = opts.incremental_verify;
    // M66 (v42 in service): the timing faces ride the fusion relink —
    // the session's ladder reports its rungs beside the warm pipeline
    // (wire v42 registered the vocabulary at M65) and the reply's tails
    // carry both faces.
    let timing = opts.time || opts.time_json || opts.trace_path.is_some();
    job.request.time = timing;
    job.request.trace = opts.trace_path.is_some();
    // M87: the map ask rides the request — the session's ladder runs the
    // full Passes 1–3, so its own Pass-3 product renders the document
    // the v46 tail carries verbatim (the M80 face over the replay lane;
    // an old server's refusal is the ERROR reply the stand-down below
    // already speaks — the in-process ladder answers either way).
    job.request.map = opts.map_path.is_some();
    let socket = opts
        .resident_socket
        .clone()
        .map_or_else(pgr_daemon::default_socket, std::path::PathBuf::from);
    let exe_hint = std::env::current_exe().ok();
    let served = pgr_daemon::link_via_daemon(&socket, exe_hint.as_deref(), &job)
        .map_err(|e| ResidentAttempt::StandDown(e.to_string()))?;
    // The daemon's §7.3 ladder fell back internally: its reply is a full
    // link. The client patches nothing; handing over to the in-process
    // relink keeps the outcome identical to the one-shot cycle (and the
    // fresh record the daemon returned still rides below on the next
    // stand-down-free cycle... the in-process relink re-records anyway).
    if served.patch.is_none() {
        return Err(ResidentAttempt::StandDown(
            "the daemon's ladder fell back to its full link".into(),
        ));
    }
    // The served audit's verdict gates the write (§7.3 "a divergence
    // never ships"): the client refuses to ship a failing verdict by not
    // writing the file at all. The daemon already healed a divergence
    // from its reference emit in memory — `healed` says so.
    if let Some(audit) = &served.audit {
        if !audit.verify_blocking.is_empty() {
            let detail = pgr_emit::incremental::audit::AuditRefusal {
                issues: audit.verify_blocking.clone(),
            }
            .render();
            return Err(ResidentAttempt::Error(DriverError::Audit {
                path: opts.output.clone(),
                detail,
            }));
        }
        if audit.healed && std::env::var_os("PGR_INCREMENTAL_DEBUG").is_some() {
            eprintln!(
                "pgr: incremental-verify (daemon): the patched bytes diverged; \
                 the daemon healed from its reference emit"
            );
        }
    }
    // The §7.2 output-residency rung (wire v5): a tiles reply is replayed
    // against the local previous output BEFORE anything is written — the
    // stream's content hash gates the replay, and a divergence never
    // ships (the miette-rendered refusal rides the stand-down back to the
    // in-process relink, which re-patches from the local record). An
    // untouched relink ships nothing and rewrites nothing: the file the
    // client holds already is the output.
    let rebuilt = match (&served.tiles, served.patch.as_ref()) {
        (Some(_), Some(patch)) if patch.untouched => None,
        (Some(stream), _) => {
            let span = tracing::info_span!(
                "resident_tile_replay",
                tiles = stream.tiles.len(),
                bytes = stream.wire_bytes()
            )
            .entered();
            let rebuilt = pgr_emit::incremental::apply_tiles(&prev, stream);
            let got = pgr_daemon::protocol::hex(&pgr_daemon::content_hash(&rebuilt));
            if got != pgr_daemon::protocol::hex(&stream.image_hash) {
                let refusal = pgr_emit::incremental::TileReplayRefusal {
                    want: pgr_daemon::protocol::hex(&stream.image_hash),
                    got,
                };
                return Err(ResidentAttempt::StandDown(refusal.render()));
            }
            drop(span);
            Some(rebuilt)
        }
        (None, _) => None,
    };
    match (&served.tiles, rebuilt) {
        (Some(_), None) => {} // untouched: the output was left byte-for-byte alone
        (Some(_), Some(bytes)) => {
            write_image(&bytes, Path::new(&opts.output)).map_err(DriverError::from)?;
        }
        (None, _) => {
            write_image(&served.image, Path::new(&opts.output)).map_err(DriverError::from)?;
        }
    }
    // The renewed record: store it so the next cycle starts from the
    // patched state (best-effort, like the in-process path).
    if let Some(record_bytes) = &served.record {
        store_record_bytes(opts, record_bytes);
    } else if std::env::var_os("PGR_INCREMENTAL_DEBUG").is_some() {
        eprintln!("pgr: the daemon's relink returned no record; keeping the old one");
    }
    // M87: the served map writes beside the fusion relink (the document
    // rides the reply's v46 tail verbatim — the session's ladder rendered
    // its own Pass-3 product; the daemon never touches the filesystem,
    // the client does — the same `-map` contract the full-link lane and
    // the one-shot ride). The write gates on the served verdict's write
    // below ordering: the map lands with the image, once the run served.
    if let (Some(path), Some(document)) = (&opts.map_path, &served.map_text) {
        std::fs::write(Path::new(path), document).map_err(|source| DriverError::Io {
            path: path.clone(),
            source,
        })?;
    }
    // M66 (v42 in service): the served faces print/write beside the
    // fusion relink — the report is the session's observed ladder run (no
    // Parse row: the POIs are resident), the timeline the same document
    // the one-shot lane writes. Either lane, one observed run.
    if timing {
        if let Some(report) = &served.time_report {
            if opts.time {
                print!("{}", report.render());
            }
            if opts.time_json {
                println!("{}", report.render_json());
            }
        }
        if let (Some(path), Some(json)) = (&opts.trace_path, &served.trace_json) {
            std::fs::write(Path::new(path), json).map_err(|source| DriverError::Io {
                path: path.clone(),
                source,
            })?;
        }
    }
    Ok(LinkOutcome {
        output: opts.output.clone(),
        // A tiles reply carries no image bytes — the size is the stream's
        // final size (the patched image's own).
        file_size: match &served.tiles {
            Some(stream) => stream.final_size,
            None => served.image.len() as u64,
        },
        entryoff: served.entryoff,
        fixup_slots: usize::try_from(served.fixup_slots).unwrap_or(usize::MAX),
        patch: served.patch,
        audit: served.audit.map(|a| a.summary()),
        transport: Some(served.transport),
        verify: None,
    })
}

/// The M9 in-place relink (architecture doc §7.3, tier 1): load the
/// record, gate the previous output, re-run the pipeline with slack
/// anchors, plan the patch, clone-and-patch the output, re-sign the dirty
/// pages and rename. Returns the patch outcome plus the refreshed record
/// (written here so the *next* relink starts from the new state).
///
/// M65: the ladder reports its rungs through the observation seam — the
/// integrity gate, the patch plan, the clone-and-patch and the
/// `-incremental-verify` audit ride the seam as
/// [`pgr_core::observe::Phase`]s (the warm pipeline's Passes 1–3 report
/// through [`pgr_core::link_observed`]), and every fallback rung names
/// itself as a [`pgr_core::observe::LinkNote::RelinkFallback`] before the
/// handover (the full link follows; the note says why the ladder's rungs
/// stop where they do). `None` = the historical silence — the seam costs
/// nothing when nobody subscribes.
fn incremental_relink(
    opts: &opts::Options,
    mut observer: Option<&mut dyn pgr_core::observe::LinkObserver>,
) -> Result<LinkOutcome, RelinkAttempt> {
    let record_bytes = std::fs::read(record_path(opts))
        .map_err(|_| RelinkAttempt::Fallback(pgr_emit::incremental::FallbackReason::NoRecord))?;
    let Some(record) = pgr_emit::incremental::LinkRecord::decode(&record_bytes) else {
        emit_relink_fallback(
            &mut observer,
            &pgr_emit::incremental::FallbackReason::RecordUnreadable,
        );
        return Err(pgr_emit::incremental::FallbackReason::RecordUnreadable.into());
    };
    // M82: the ladder's named admission — `pgr_emit::incremental::LinkRecord::admits`,
    // the same decision the session's §7.3 ladder reads. A config naming a
    // different chain word family than the record's hands over to the full
    // link (the patch cannot renegotiate the word shape in place), which
    // re-plans the family the request named and re-records — the knob the
    // caller asked for is the knob that lands, never a silently patched
    // over shape.
    if let Err(reason) = record.admits(&opts.config) {
        emit_relink_fallback(&mut observer, &reason);
        return Err(reason.into());
    }
    let output = Path::new(&opts.output);
    // Any integrity-gate failure — missing, resized, corrupt — falls back:
    // the full link never needs the previous output. The gate is real work
    // (the record's page-hash sample hashed against the output) and rides
    // the seam when someone subscribes (M65).
    let gate_started = std::time::Instant::now();
    let gate = pgr_emit::incremental::check_output(output, &record);
    match gate {
        Ok(pgr_emit::incremental::Integrity::Match) => {
            emit_relink_phase(
                &mut observer,
                pgr_core::observe::Phase::RelinkGate,
                pgr_core::observe::PhaseDetail::Gate {
                    pages: usize::try_from(record.hashed_pages()).unwrap_or(usize::MAX),
                },
                gate_started.elapsed(),
            );
        }
        Ok(pgr_emit::incremental::Integrity::Mismatch { detail }) => {
            let reason = pgr_emit::incremental::FallbackReason::OutputChanged { detail };
            emit_relink_fallback(&mut observer, &reason);
            return Err(reason.into());
        }
        Err(e) => {
            let reason = pgr_emit::incremental::FallbackReason::OutputChanged {
                detail: e.to_string(),
            };
            emit_relink_fallback(&mut observer, &reason);
            return Err(reason.into());
        }
    }

    let (prepared, cache) = prepare_link(opts).map_err(RelinkAttempt::Error)?;
    // §7.3 "layout stability": the in-place tier stands on the slack
    // anchors — the driver implies the M8-c policy when the caller left it
    // unset and anchors every recorded section at its reserved size.
    let mut cfg = prepared.config.clone();
    cfg.layout_slack = cfg
        .layout_slack
        .or_else(|| Some(pgr_core::slack::SlackPolicy::default()));
    cfg.slack_anchor = record
        .sections
        .iter()
        .map(|s| pgr_core::slack::SlackAnchor {
            seg: s.seg.clone(),
            name: s.name.clone(),
            padded: s.size,
        })
        .collect();
    // M9 tier-2a (§7.3 step 5): the recorded import table anchors the
    // chained-bind ordinals — recorded entries keep them, new binds append,
    // and an import-adding edit stops renumbering the table (which would
    // dirty every page holding a rewritten bind word).
    cfg.stable_imports = Some(record.imports.clone());
    // M9 tier-2a: the signature boundary anchors too — the LINKEDIT tail
    // reservation lets the chunk stream grow (symtab, imports, strings)
    // without moving `sig_off`, so those edits patch in place.
    cfg.sig_anchor = (record.linkedit.sig_off > 0).then_some(record.linkedit.sig_off);
    // M9 GA rung — the resolve's record-side wiring, reuse half: the
    // recorded Pass-2 snapshot hands the pipeline its decisions, and the
    // capture flag re-records the fresh state for the next cycle. Records
    // from before the wiring (no v5 section) resolve in full.
    cfg.record_resolution = true;
    if let Some(resolution) = &record.resolution {
        cfg.resolve_reuse = Some(pgr_core::resolve_reuse::ResolveReuseSeed {
            snapshot: resolution.clone(),
            digests: record.section_digests.clone(),
        });
    }
    // M65: the relink's warm pipeline rides the observation seam when a
    // subscriber watches (the same entry the one-shot path uses — the
    // Passes 1–3 events land in the caller's collectors; a link through
    // the POI cache is still a parse the consumer waited on).
    let result = match observer.as_deref_mut() {
        Some(obs) => pgr_core::link_observed(
            &prepared.inputs,
            &prepared.archives,
            &cfg,
            pgr_core::Parallelism::Auto,
            cache.as_ref(),
            obs,
        ),
        None => pgr_core::link_cached(
            &prepared.inputs,
            &prepared.archives,
            &cfg,
            pgr_core::Parallelism::Auto,
            cache.as_ref(),
        ),
    }
    .map_err(|e| RelinkAttempt::Error(e.into()))?;
    check_force_load(&result, &prepared.force_load).map_err(RelinkAttempt::Error)?;

    let plan_started = std::time::Instant::now();
    let decision = pgr_emit::incremental::plan_patch(
        &record,
        &result.layout,
        &result.objects,
        cfg.layout_slack.as_ref(),
    )
    .map_err(|e| RelinkAttempt::Error(e.into()))?;
    let plan = match decision {
        pgr_emit::incremental::PatchDecision::InPlace(plan) => plan,
        pgr_emit::incremental::PatchDecision::Fallback(reason) => {
            emit_relink_fallback(&mut observer, &reason);
            return Err(RelinkAttempt::Fallback(reason));
        }
    };
    emit_relink_phase(
        &mut observer,
        pgr_core::observe::Phase::RelinkPlan,
        pgr_core::observe::PhaseDetail::Plan {
            tiles: usize::try_from(plan.total_tiles).unwrap_or(usize::MAX),
            dirty: plan.dirty_tiles.len(),
        },
        plan_started.elapsed(),
    );
    // Nothing changed: leave the output byte-for-byte alone (§7.3 — the
    // relink's job is done), refresh the record, report the no-op.
    if plan.is_untouched() {
        store_record(opts, &record);
        // M84: the answers ride the relink's own walk even when nothing
        // patched — the walk ran (the plan is the walk's product), and a
        // queried run answers from it.
        serve_relink_faces(opts, &prepared, &result)?;
        return Ok(LinkOutcome {
            output: opts.output.clone(),
            file_size: record.file_size,
            entryoff: result.layout.entryoff,
            fixup_slots: result.layout.fixups.slot_count,
            patch: Some(pgr_emit::incremental::PatchOutcome {
                bytes_patched: 0,
                dirty_tiles: 0,
                total_tiles: plan.total_tiles,
                untouched: true,
            }),
            audit: None,
            transport: None,
            verify: None,
        });
    }
    let patch_started = std::time::Instant::now();
    let (mut outcome, new_record) = pgr_emit::incremental::apply_patch(
        output,
        &record,
        &plan,
        &result.layout,
        &result.objects,
        output,
        result.resolve_snapshot.clone(),
    )
    .map_err(|e| match e {
        pgr_emit::incremental::PatchError::Fallback(reason) => {
            emit_relink_fallback(&mut observer, &reason);
            RelinkAttempt::Fallback(reason)
        }
        other => RelinkAttempt::Error(other.into()),
    })?;
    emit_relink_phase(
        &mut observer,
        pgr_core::observe::Phase::RelinkPatch,
        pgr_core::observe::PhaseDetail::Patch {
            bytes: outcome.bytes_patched,
            tiles: usize::try_from(outcome.dirty_tiles).unwrap_or(usize::MAX),
        },
        patch_started.elapsed(),
    );

    // `-incremental-verify` (§7.3): the audit gate, through the engine's
    // audit twin (the same implementation the daemon serves on the wire).
    // Byte-identity against the full fused emit of the same plan first;
    // a divergence never ships — the output is rewritten from the full
    // emit and re-recorded. Then the strict verifier pass on the final
    // bytes (with the deliberate-unsigned carve-out for `-no_adhoc`).
    let mut audit_summary = None;
    if opts.incremental_verify {
        let audit_started = std::time::Instant::now();
        let full = pgr_emit::build_image_fused(&result.layout, &result.objects)
            .map_err(|e| RelinkAttempt::Error(e.into()))?;
        let patched = std::fs::read(output)
            .map_err(|source| DriverError::Io {
                path: opts.output.clone(),
                source,
            })
            .map_err(RelinkAttempt::Error)?;
        let identity_ok = pgr_emit::incremental::audit::audit_patch(&full, &patched);
        let healed = !identity_ok;
        if healed {
            if std::env::var_os("PGR_INCREMENTAL_DEBUG").is_some() {
                eprintln!("pgr: incremental-verify: patched output diverged; healing");
            }
            write_image(&full, output).map_err(|e| RelinkAttempt::Error(e.into()))?;
            let healed_record = pgr_emit::incremental::LinkRecord::record(
                &result.layout,
                &result.objects,
                &full,
                result.resolve_snapshot.as_ref(),
            )
            .map_err(|e| RelinkAttempt::Error(e.into()))?;
            store_record(opts, &healed_record);
            outcome.bytes_patched = full.len() as u64;
            outcome.dirty_tiles = plan.total_tiles;
        }
        let final_bytes = std::fs::read(output)
            .map_err(|source| DriverError::Io {
                path: opts.output.clone(),
                source,
            })
            .map_err(RelinkAttempt::Error)?;
        // A deliberately unsigned link (`-no_adhoc`) has no signature LC:
        // the verifier's "arm64 images require an ad-hoc code signature"
        // shape is the config's own choice — the carve-out lives in the
        // twin; everything else gates at full strictness.
        let blocking = pgr_emit::incremental::audit::audit_image(&final_bytes, !cfg.adhoc);
        // The audit is real work (the reference emit rebuilt, the strict
        // verifier walked) and rides the seam whether it ships or refuses
        // (a blocking issue count is the audit's own finding — M65).
        emit_relink_phase(
            &mut observer,
            pgr_core::observe::Phase::RelinkAudit,
            pgr_core::observe::PhaseDetail::Audit {
                healed,
                issues: blocking.len(),
            },
            audit_started.elapsed(),
        );
        if !blocking.is_empty() {
            let detail = pgr_emit::incremental::audit::AuditRefusal { issues: blocking }.render();
            return Err(RelinkAttempt::Error(DriverError::Audit {
                path: opts.output.clone(),
                detail,
            }));
        }
        audit_summary = Some(pgr_emit::incremental::audit::AuditSummary {
            identity_ok,
            healed,
            verify_ok: true,
        });
    }

    store_record(opts, &new_record);
    // M84: the answers ride the relink's own walk — the same faces the
    // one-shot prints, over the walk product this relink just patched
    // from.
    serve_relink_faces(opts, &prepared, &result)?;
    Ok(LinkOutcome {
        output: opts.output.clone(),
        // The patched state's size — the relayout tier grows the image, so
        // this is the refreshed record's, not the previous link's.
        file_size: new_record.file_size,
        entryoff: result.layout.entryoff,
        fixup_slots: result.layout.fixups.slot_count,
        patch: Some(outcome),
        audit: audit_summary,
        transport: None,
        verify: None,
    })
}

/// The ladder's own faces (M84, M85, M86), served at both relink exits —
/// the patched exit and the untouched one, where the walk ran and
/// nothing patched:
///
/// * `-map` renders [`pgr_core::map::build_link_map`] over
///   [`pgr_core::LinkResult::layout`] — the relink's own Pass-3 product,
///   the same pure function the one-shot writes its document from (the
///   map and the bytes cannot disagree — M11's rule). The document the
///   ladder writes names the placed image the relink just planned, never
///   the previous link's, and lands before the record write so the
///   dependency record's output row names a sidecar that exists (the
///   one-shot's own order — the map, then the record).
/// * `-dependency_info` writes [`PreparedLink::deps`] — the M60 record
///   Pass 0 built while the relink's mapping read the inputs (the same
///   recording `prepare_link` runs for the one-shot; the re-parse is the
///   digest source, so the read set is real). The sidecar the relink
///   rewrites names the files the ladder actually read, and the output
///   row joins at the write site — never the previous link's list.
/// * `-why_export` renders [`pgr_core::LinkResult::resolution`] — the
///   relink's own Pass-2 product, the same face [`print_why_export`]
///   serves the one-shot. A vacuous query refuses the relink exactly as
///   it refuses the cold link (the misspelling named, never silently
///   empty).
/// * `-why_load` renders [`pgr_core::LinkResult::loads`] — the pull
///   record the relink's own walk collected (the re-pull rode the same
///   fixpoint), not the previous link's.
///
/// The faces order after `store_record`: a refused face (a vacuous
/// query) leaves the run's record already renewed, so the next relink
/// re-plans from the fresh state (the one-shot's own order — the write,
/// then the queries).
///
/// # Errors
/// [`RelinkAttempt::Error`] on a filesystem failure writing the record
/// or the map, or a vacuous `-why_export` query.
fn serve_relink_faces(
    opts: &opts::Options,
    prepared: &PreparedLink,
    result: &pgr_core::LinkResult,
) -> Result<(), RelinkAttempt> {
    // M86: the map is the walk's own Pass-3 product — the relink ran the
    // full Passes 1–3, so the placed image the report names is this
    // relink's, at both exits (the patched one and the untouched one).
    // The one-shot's order: the map lands, then the record names it.
    if let Some(map_path) = &opts.map_path {
        let map = pgr_core::map::build_link_map(&result.layout, &result.interner);
        std::fs::write(Path::new(map_path), map.render()).map_err(|source| {
            RelinkAttempt::Error(DriverError::Io {
                path: map_path.clone(),
                source,
            })
        })?;
    }
    write_dependency_record(opts, &prepared.deps).map_err(RelinkAttempt::Error)?;
    print_why_export(
        &result.objects,
        &result.resolution,
        &result.interner,
        &opts.why_export,
    )
    .map_err(RelinkAttempt::Error)?;
    if opts.why_load {
        print!("{}", result.loads.render());
    }
    Ok(())
}

/// Emits one ladder rung through the observer slot (M65 — `None` = the
/// historical silence, the seam costs nothing when nobody subscribes; the
/// same shape the core pipeline's own `emit_phase` carries).
fn emit_relink_phase(
    observer: &mut Option<&mut dyn pgr_core::observe::LinkObserver>,
    phase: pgr_core::observe::Phase,
    detail: pgr_core::observe::PhaseDetail,
    elapsed: std::time::Duration,
) {
    if let Some(obs) = observer.as_deref_mut() {
        obs.on_phase(pgr_core::observe::PhaseEvent {
            phase,
            detail,
            elapsed,
        });
    }
}

/// Names a fallback rung on the observer slot before the handover (M65):
/// the full link follows, and the note says why the ladder's rungs stop
/// where they do — the same "silent-correct, not silent-blind" wording
/// the `PGR_INCREMENTAL_DEBUG` line carries.
fn emit_relink_fallback(
    observer: &mut Option<&mut dyn pgr_core::observe::LinkObserver>,
    reason: &pgr_emit::incremental::FallbackReason,
) {
    if let Some(obs) = observer.as_deref_mut() {
        obs.on_note(pgr_core::observe::LinkNote::RelinkFallback {
            reason: reason.to_string(),
        });
    }
}

/// Best-effort record store (a failed write only costs the next link a
/// fallback, and is reported under `PGR_INCREMENTAL_DEBUG`).
fn store_record(opts: &opts::Options, record: &pgr_emit::incremental::LinkRecord) {
    store_record_bytes(opts, &record.encode());
}

/// [`store_record`] over already-encoded bytes (the daemon returns the
/// renewed record encoded).
fn store_record_bytes(opts: &opts::Options, bytes: &[u8]) {
    if let Err(e) = std::fs::write(record_path(opts), bytes) {
        if std::env::var_os("PGR_INCREMENTAL_DEBUG").is_some() {
            eprintln!("pgr: storing link record failed: {e}");
        }
    }
}

/// The one-line version banner.
#[must_use]
pub fn version_line() -> String {
    format!("pgr (Peregrine) {}", env!("CARGO_PKG_VERSION"))
}

/// The `--help` text (the current flag surface).
#[must_use]
pub fn usage() -> String {
    let mut s = String::with_capacity(1600);
    s.push_str(&version_line());
    s.push_str("\n\nPeregrine: ultra-fast Mach-O linker for arm64-apple-darwin.\n\n");
    s.push_str("Executables, dylibs, bundles and (M10) relocatable objects: .o/.tbd/.dylib\n");
    s.push_str("inputs, two-level namespace, GOT/stub synthesis, chained fixups\n");
    s.push_str("(rebase+bind), full export trie with re-exports, export filters,\n");
    s.push_str("ad-hoc signature.\n\n");
    s.push_str("Usage: pgr [options] <object files>\n\n");
    s.push_str("Options:\n");
    s.push_str("  -o <path>                    output file (required)\n");
    s.push_str("  -arch arm64                  target architecture (arm64 only)\n");
    s.push_str("  -platform_version <p> <min> <sdk>   build version; the platform is\n");
    s.push_str("                               macos, ios, tvos, watchos or visionos\n");
    s.push_str("                               (M10), and the SDK must be at least the\n");
    s.push_str("                               deployment target\n");
    s.push_str("  -e <symbol>                  entry symbol (default _main)\n");
    s.push_str("  -static                      static semantics (M1 default)\n");
    s.push_str("  -dylib                       link a dylib (MH_DYLIB)\n");
    s.push_str("  -bundle                      link a bundle (MH_BUNDLE)\n");
    s.push_str("  -r                           relocatable output (MH_OBJECT):\n");
    s.push_str("                               merged sections, preserved relocation\n");
    s.push_str("                               entries, open undefineds — the output\n");
    s.push_str("                               is itself a link input (M10)\n");
    s.push_str("  -install_name <path>         LC_ID_DYLIB install name (with -dylib;\n");
    s.push_str("                               defaults to the output path)\n");
    s.push_str("  -final_output <path>         the install-name default when -install_name\n");
    s.push_str("                               is absent (M44): the multi-arch driver\n");
    s.push_str("                               names the universal path, every slice\n");
    s.push_str("                               records it (refused without -dylib)\n");
    s.push_str("  -current_version <X.Y.Z>     LC_ID_DYLIB current version\n");
    s.push_str("  -compatibility_version <X.Y.Z>   LC_ID_DYLIB compatibility version\n");
    s.push_str("  -reexport_library <path>     LC_REEXPORT_DYLIB + trie re-exports\n");
    s.push_str("  -exported_symbols_list <f>   export only the listed symbols\n");
    s.push_str("  -unexported_symbols_list <f> hide the listed symbols (N_PEXT)\n");
    s.push_str("  -mark_dead_strippable_dylib  set MH_DEAD_STRIPPABLE_DYLIB\n");
    s.push_str("  -l <name> | -l<name>         link a library (searched via -L)\n");
    s.push_str("  -L <dir>                     library search directory\n");
    s.push_str("  -rpath <path>                LC_RPATH runtime search path\n");
    s.push_str("  -flat_namespace              flat-lookup binds (drop MH_TWOLEVEL)\n");
    s.push_str("  -undefined error|dynamic_lookup   unresolved-reference policy\n");
    s.push_str("  -u <symbol>                  force the symbol to be defined\n");
    s.push_str("  -U <symbol>                  mark the symbol undefined while linking (M39):\n");
    s.push_str("                               the definition drops, the reference binds\n");
    s.push_str("                               per -undefined (refused with -r)\n");
    s.push_str("  -no_dead_strip_inits_and_terms   the initialization and termination\n");
    s.push_str("                               routines never strip (M52): the\n");
    s.push_str("                               termination-pointer sections join the\n");
    s.push_str("                               init sections' dead-strip roots (the\n");
    s.push_str("                               init half is the default)\n");
    s.push_str("  -allow_stack_execute          mark the executable so every stack in\n");
    s.push_str("                               the task (main and pthreads) maps\n");
    s.push_str("                               executable (M51): MH_ALLOW_STACK_EXECUTION\n");
    s.push_str("                               rides the header word (refused with\n");
    s.push_str("                               -dylib, -bundle and -r)\n");
    s.push_str("  -rename_section <fromSeg> <fromSect> <toSeg> <toSect>   rename the\n");
    s.push_str("                               input section before grouping (M53): the\n");
    s.push_str("                               renamed section groups with its new name\n");
    s.push_str("                               and lands in the new segment (names max\n");
    s.push_str("                               16 bytes; the synthetic targets refuse;\n");
    s.push_str("                               inert with -r)\n");
    s.push_str("  -no_weak_imports             refuse weak imports dyld must look up\n");
    s.push_str("                               at runtime (M50): a weak reference no\n");
    s.push_str("                               link-time input resolves refuses with the\n");
    s.push_str("                               symbol named; a resolved one never does\n");
    s.push_str("  -ObjC                        pull archive members implementing an\n");
    s.push_str("                               Objective-C class or category (M43):\n");
    s.push_str("                               the metadata names no static reference —\n");
    s.push_str("                               the runtime registers by section address\n");
    s.push_str("  -order_file <path>           rank symbols in the output (M11): one\n");
    s.push_str("                               `symbol` or `object.o:symbol` per line;\n");
    s.push_str("                               ranked pieces lead, unranked keep their\n");
    s.push_str("                               order (refused with -r; serves beside\n");
    s.push_str("                               -resident since M81 — wire v47 carries\n");
    s.push_str("                               the rank table)\n");
    s.push_str("  -weak_library <path>         weak-load a dylib\n");
    s.push_str("  -lazy_library <path>         lazy-load a dylib (LC_LAZY_LOAD_DYLIB)\n");
    s.push_str("  -upward_library <path>       load a dylib as the umbrella relationship\n");
    s.push_str("                               (LC_LOAD_UPWARD_DYLIB, M45): the\n");
    s.push_str("                               sub-umbrella its umbrella loads upward\n");
    s.push_str("  -weak_framework <name>       weak-load a framework dylib\n");
    s.push_str("  -lazy_framework <name>       lazy-load a framework dylib\n");
    s.push_str("  -upward_framework <name>     load a framework dylib as the umbrella\n");
    s.push_str("                               relationship (LC_LOAD_UPWARD_DYLIB, M45)\n");
    s.push_str("  -source_version <A.B.C.D.E>  LC_SOURCE_VERSION\n");
    s.push_str("  -fixup_chains | -no_fixup_chains    chained fixups (default on)\n");
    s.push_str("  -fixup_chains_format <fmt>   chain word family: offset64 (default)\n");
    s.push_str("                               or arm64e (M10 rung 4); shapes the\n");
    s.push_str("                               chained-fixup words, not the fixups\n");
    s.push_str("  -adhoc | -no_adhoc           ad-hoc code signature (default on)\n");
    s.push_str("  -headerpad <n>               reserve header space (M29): the region\n");
    s.push_str("                               the header and its load commands\n");
    s.push_str("                               occupy grows to the named floor (a\n");
    s.push_str("                               non-zero multiple of 8 up to 0x4000);\n");
    s.push_str("                               refused with -r\n");
    s.push_str("  -segalign <n>                0x1000 or 0x4000 (default 0x4000)\n");
    s.push_str("  -sectcreate <seg> <sect> <file>   place file bytes in a section\n");
    s.push_str("  -sectalign <seg> <sect> <n>  raise a named section's alignment\n");
    s.push_str("                               (M28): the floor is the max of the\n");
    s.push_str("                               input's and the named power of two\n");
    s.push_str("                               (up to 0x4000); refused with -r\n");
    s.push_str("  -map <path>                  write the link map (segments,\n");
    s.push_str("                               sections, symbols — the placed\n");
    s.push_str("                               image's report; refused with -r;\n");
    s.push_str("                               serves beside -resident since M80\n");
    s.push_str("                               (the session's own walk renders it,\n");
    s.push_str("                               wire v46) and beside -incremental\n");
    s.push_str("                               since M86 (the relink's own walk\n");
    s.push_str("                               renders it — the fusion lane since\n");
    s.push_str("                               M87, the served document riding the\n");
    s.push_str("                               same tail)\n");
    s.push_str("  -syslibroot <dir>            SDK root prefixed onto every search\n");
    s.push_str("                               path (repeatable; ld64 pairing rule)\n");
    s.push_str("  @<response-file>             expand arguments from a file\n");
    s.push_str("  -cache <dir>                 Stage A link cache (POI + frozen .tbd)\n");
    s.push_str("  -cache_max <bytes>           cache size bound (LRU eviction;\n");
    s.push_str("                               default 2 GiB, 0 = unbounded)\n");
    s.push_str("  -no_cache                    disable the link cache\n");
    s.push_str("  -icf=safe|-icf=all|-no_icf   identical code folding (default none)\n");
    s.push_str("  -export_dynamic              preserve every global symbol during dead\n");
    s.push_str("                               stripping (M46): each definition roots the\n");
    s.push_str("                               mark phase — the dlsym surface (refused\n");
    s.push_str("                               with -dylib, -bundle and -r)\n");
    s.push_str("  -no_branch_islands           refuse the branch veneers the layout\n");
    s.push_str("                               plans for out-of-range B/BL (M47): a\n");
    s.push_str("                               branch the ±128 MiB imm26 window cannot\n");
    s.push_str("                               reach then fails the link with the site\n");
    s.push_str("                               named (default: islands on, ld64's)\n");
    s.push_str("  -init <symbol>               the load-time initializer dyld calls when\n");
    s.push_str("                               the dylib loads (M48): the resolved\n");
    s.push_str("                               address rides LC_ROUTINES_64 (refused\n");
    s.push_str("                               with executables, bundles and -r)\n");
    s.push_str("  -incremental                 M9 in-place relink: patch only the\n");
    s.push_str("                               changed 16 KiB tiles into a clone of\n");
    s.push_str("                               the previous output and re-sign the\n");
    s.push_str("                               dirty pages (record: <output>.pgr-inc;\n");
    s.push_str("                               any structure move falls back to the\n");
    s.push_str("                               full link silently)\n");
    s.push_str("  -no_incremental              disable the in-place relink\n");
    s.push_str("  -incremental-verify          after a successful patch, audit\n");
    s.push_str("                               byte-identity against the full\n");
    s.push_str("                               fused emit (daemon-served under\n");
    s.push_str("                               -resident; in-process else) and\n");
    s.push_str("                               run the strict verifier on the\n");
    s.push_str("                               patched bytes\n");
    s.push_str("  -verify                      after the pipeline produces the\n");
    s.push_str("                               image, run the strict verifier on\n");
    s.push_str("                               the produced bytes and refuse to\n");
    s.push_str("                               ship a failing verdict (the gate\n");
    s.push_str("                               sits before the write; the relink\n");
    s.push_str("                               ladder's gate is\n");
    s.push_str("                               -incremental-verify)\n");
    s.push_str("  -verify-checks <families>    the families the -verify gate runs\n");
    s.push_str("                               (comma-separated, the\n");
    s.push_str("                               `pgr-verify --checks` tokens:\n");
    s.push_str("                               structure, segments, symbols,\n");
    s.push_str("                               linkedit, fixups, chain_starts,\n");
    s.push_str("                               unwind, tlv, branch_range,\n");
    s.push_str("                               dyld_info, signature — default:\n");
    s.push_str("                               the full pass)\n");
    s.push_str("  -resident                    route the link through the resident\n");
    s.push_str("                               daemon (pgrd); falls back to the\n");
    s.push_str("                               one-shot link when unreachable\n");
    s.push_str("  -resident_socket <path>      daemon socket (default $PGR_DAEMON_SOCK,\n");
    s.push_str("                               else {tmpdir}/pgr-<uid|pid>.sock — SUDO_UID\n");
    s.push_str("                               when present, else the process id)\n");
    s.push_str("  --print-fixup-encoding <p> <min> <sdk>\n");
    s.push_str("                               name the fixup encoding a\n");
    s.push_str("                               -platform_version target plans\n");
    s.push_str("                               (chained fixups or the classic\n");
    s.push_str("                               opcode streams) before any link\n");
    s.push_str("                               runs (M10); a below-floor answer\n");
    s.push_str("                               renders its advisory on stderr\n");
    s.push_str("  --print-record <path>        summarize a link record sidecar\n");
    s.push_str("                               (<output>.pgr-inc, M13): the\n");
    s.push_str("                               identity, skeleton and table\n");
    s.push_str("                               counts the last -incremental\n");
    s.push_str("                               link recorded — the what-will-\n");
    s.push_str("                               the-relink-patch query\n");
    s.push_str("  -why_export <symbol>         after the link, answer *why is\n");
    s.push_str("                               this symbol exported?* — the\n");
    s.push_str("                               definition the resolution\n");
    s.push_str("                               installed and every reference\n");
    s.push_str("                               site the reverse index\n");
    s.push_str("                               recorded (M56; repeatable; the\n");
    s.push_str("                               name is the C symbol, underscore\n");
    s.push_str("                               included)\n");
    s.push_str("  -why_load                    after the link, report why each\n");
    s.push_str("                               archive member was loaded (the\n");
    s.push_str("                               pull's decision: the reference\n");
    s.push_str("                               that reached it, -all_load,\n");
    s.push_str("                               -ObjC) and — under\n");
    s.push_str("                               -dead_strip_dylibs — every input\n");
    s.push_str("                               dylib's carriage (M57)\n");
    s.push_str("  --time                       after the link, print the per-pass\n");
    s.push_str("                               wall report — the passes the pipeline\n");
    s.push_str("                               ran (parse through layout), each\n");
    s.push_str("                               with its own shape and wall time,\n");
    s.push_str("                               the fused emit and the pipeline's\n");
    s.push_str("                               total (M58; the resident lane serves\n");
    s.push_str("                               its own observed run — wire v40,\n");
    s.push_str("                               M59; the incremental lane rides\n");
    s.push_str("                               since M65 — the ladder's rungs join\n");
    s.push_str("                               the report as phases)\n");
    s.push_str("  --time-json                  the same measurement as the compact\n");
    s.push_str("                               JSON interchange line (one line, the\n");
    s.push_str("                               report-JSON escape rules; walls in\n");
    s.push_str("                               microseconds) (M58)\n");
    s.push_str("  -dependency_info <path>      after a successful link, write the\n");
    s.push_str("                               build-system dependency record —\n");
    s.push_str("                               ld64's sidecar artifact: the linker\n");
    s.push_str("                               version, every file the link read\n");
    s.push_str("                               (objects, archives, libraries,\n");
    s.push_str("                               payloads, list files), the probed\n");
    s.push_str("                               misses, the output (M60; refused\n");
    s.push_str("                               with -incremental — the relink\n");
    s.push_str("                               re-reads no input file)\n");
    s.push_str("  -help, -h                    this text\n");
    s.push_str("  -version, -V                 version banner\n\n");
    s.push_str("M5 — real-world link surface: .a archives with ranlib-guided lazy\n");
    s.push_str("member pull (S7), -dead_strip, -all_load/-force_load, -ObjC, -filelist,\n");
    s.push_str("-framework/-F, -sectcreate, __cstring merging; -order_file and\n");
    s.push_str("-map shipped at M11, --print-record at M13 (the queries above).\n");
    s
}

/// The fixup-encoding answer a build system reads before the link runs
/// (M10 rung 3, slice 2 — roadmap §10.4 row M10: the encoding decision
/// is a typed value a build system reads before Pass 3 runs; slice 1
/// named it in `pgr_core::platform`, slice 2 puts it on the driver
/// surface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodingReport {
    /// The encoding Pass 3 plans with for this target.
    pub encoding: pgr_core::platform::FixupEncoding,
    /// The platform's chained-fixups floor (the packed `X.Y.Z` word).
    pub floor: u32,
    /// The parsed deployment target (the packed `X.Y.Z` word).
    pub minos: u32,
    /// The below-floor advisory (the fix, not just the verdict);
    /// `None` at or above the floor.
    pub advisory: Option<BelowFloorAdvisory>,
}

impl EncodingReport {
    /// The floor as the `-platform_version` grammar displays it.
    #[must_use]
    pub fn floor_text(&self) -> String {
        fmt_version_word(self.floor)
    }

    /// The deployment target as the flag grammar displays it.
    #[must_use]
    pub fn minos_text(&self) -> String {
        fmt_version_word(self.minos)
    }
}

/// The below-floor advisory, rendered as miette help text (the fix, not
/// just the verdict — the same convention the option refusals and the
/// `platform_floor` example use).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
#[error("{platform} {minos} links the classic opcode streams: chained fixups start at {floor}")]
#[diagnostic(help(
    "raise the deployment target to {floor} or plan for the classic `LC_DYLD_INFO_ONLY` \
     streams — the encoding flips, the fixups do not"
))]
pub struct BelowFloorAdvisory {
    /// The `-platform_version` platform name as written.
    pub platform: String,
    /// The deployment target, displayed (`X.Y.Z`).
    pub minos: String,
    /// The platform's chained-fixups floor, displayed (`X.Y.Z`).
    pub floor: String,
}

/// The packed `X.Y.Z` word as the `-platform_version` grammar displays
/// it (the same rendering the verifier's build-version messages use).
pub(crate) fn fmt_version_word(v: u32) -> String {
    format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)
}

/// Answers the fixup-encoding question for a `-platform_version`
/// (platform, deployment target, SDK) triple *before* any link runs —
/// the build-system seam the roadmap scopes for rung 3. The decision
/// comes from [`pgr_core::platform::FixupEncoding`], which reads the
/// same per-platform floor table the layout encodes (one table, three
/// readers — never a re-derivation).
///
/// The platform is the `-platform_version` spelling (`macos`, `ios`,
/// `tvos`, `watchos`, `visionos`); the versions follow the flag's
/// `X[.Y[.Z]]` grammar, and the same parse-time refusals apply: an
/// unknown platform names the five linked platforms, and an SDK older
/// than the deployment target refuses (the SDK ships the deployment
/// target's interfaces). The query rides the tracing seam (inert until
/// a subscriber installs), and a below-floor answer carries the miette
/// advisory the `pgr` binary renders on stderr.
///
/// # Errors
/// [`opts::OptsError::Unsupported`] on an unknown platform name,
/// [`opts::OptsError::InvalidValue`] on an unparseable version,
/// [`opts::OptsError::VersionOrder`] when the SDK is older than the
/// deployment target.
pub fn fixup_encoding_report(
    platform: &str,
    minos: &str,
    sdk: &str,
) -> Result<EncodingReport, opts::OptsError> {
    let _query_span = tracing::info_span!(
        "encoding_query",
        platform = %platform,
        minos = %minos,
        sdk = %sdk,
    )
    .entered();
    let constant = opts::platform_const(platform).ok_or_else(|| opts::OptsError::Unsupported {
        flag: "-platform_version".into(),
        hint: format!(
            "platform {platform:?} is not a linked platform (the surface links \
             macos, ios, tvos, watchos and visionos)"
        ),
    })?;
    let minos_word = opts::parse_version(minos).ok_or_else(|| opts::OptsError::InvalidValue {
        flag: "-platform_version".into(),
        value: minos.into(),
    })?;
    let sdk_word = opts::parse_version(sdk).ok_or_else(|| opts::OptsError::InvalidValue {
        flag: "-platform_version".into(),
        value: sdk.into(),
    })?;
    if sdk_word < minos_word {
        return Err(opts::OptsError::VersionOrder {
            minos: minos.into(),
            sdk: sdk.into(),
        });
    }
    let encoding = pgr_core::platform::FixupEncoding::for_target(constant, minos_word);
    let floor = pgr_core::platform::FixupEncoding::floor_for(constant);
    let advisory = if encoding == pgr_core::platform::FixupEncoding::ClassicOpcodes {
        Some(BelowFloorAdvisory {
            platform: platform.to_string(),
            minos: fmt_version_word(minos_word),
            floor: fmt_version_word(floor),
        })
    } else {
        None
    };
    tracing::debug!(
        platform = %platform,
        minos = %minos_word,
        floor,
        ?encoding,
        "the encoding query answered before the link"
    );
    Ok(EncodingReport {
        encoding,
        floor,
        minos: minos_word,
        advisory,
    })
}

/// The `--print-record <path>` answer (M13 rung 2): reads the `.pgr-inc`
/// sidecar a previous `-incremental` link recorded and summarizes it —
/// the identity, the skeleton, the span/digest/hash counts and the
/// resolve-capture flag — the "what did the last incremental link
/// record, and will the next relink patch?" seam a build system asks
/// without relinking. The record's trust model is unchanged: the read
/// is a diagnosis, never a link failure.
///
/// # Errors
/// [`DriverError::Record`] with the frame layer that refused (missing
/// file, foreign bytes, truncation, corruption, foreign revision).
pub fn record_report(path: &str) -> Result<pgr_emit::incremental::RecordSummary, DriverError> {
    let _query_span = tracing::info_span!(
        "record_query",
        path = %path,
    )
    .entered();
    Ok(pgr_emit::incremental::read_summary(std::path::Path::new(
        path,
    ))?)
}

#[cfg(test)]
mod tests {
    use super::{link_to_bytes, usage, version_line};
    use crate::opts::Options;
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

    /// The resident stand-down's record-read classification: a missing
    /// record is the ordinary first-cycle reason, and every other read
    /// failure carries its io cause instead of masquerading as a missing
    /// record (the stand-down reason is diagnostic output — a permission
    /// error must be diagnosable, not lied about).
    #[test]
    fn stand_down_reason_classifies_the_record_read() {
        use super::stand_down_reason;
        let missing = stand_down_reason(&std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(missing, "no record for this output yet");
        let denied = stand_down_reason(&std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(
            denied.starts_with("the record is unreadable: "),
            "the cause rides the reason: {denied}"
        );
        assert!(
            denied.contains("permission"),
            "the os message rides the reason: {denied}"
        );
    }

    /// hello.o: _main ADRP+ADD loads _msg, BL _greet, returns 0.
    fn hello_main() -> Vec<u8> {
        let text: Vec<u8> = [
            0x9000_0000u32, // adrp x0, _msg@page
            0x9100_0000u32, // add x0, x0, #_msg@pageoff
            0x9400_0000u32, // bl _greet
            0x5280_0000u32, // mov w0, #0
            0xD65F_03C0u32, // ret
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
        let mut b = ObjectBuilder::new("hello.o");
        let sect = b.add_section(ObjectSection::text(
            "__text",
            text,
            vec![
                ObjectReloc::addend(0).at(0),
                ObjectReloc::page21(1).at(0),
                ObjectReloc::addend(0).at(4),
                ObjectReloc::pageoff12(1).at(4),
                ObjectReloc::branch26(2).at(8),
            ],
        ));
        b.add_section(ObjectSection::cstring("hello, peregrine\n"));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Defined {
            name: "_msg".into(),
            section_index: 1,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_greet".into(),
            weak_ref: false,
        });
        b.build().unwrap()
    }

    /// greet.o: _greet + a __data pointer to _main + a subtractor pair +
    /// a common symbol.
    fn greet() -> Vec<u8> {
        let mut b = ObjectBuilder::new("greet.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![
                0x91, 0x00, 0x00, 0x00, // add x0, x0, #0 (immediate kept)
                0xC0, 0x03, 0x5F, 0xD6, // ret
            ],
            vec![],
        ));
        // __data: [ptr to _greet][subtractor result ptr_a - ptr_b]
        let data_sect = b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
        let greet_sym = b.add_symbol(ObjectSymbol::Defined {
            name: "_greet".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        let ptr_a = b.add_symbol(ObjectSymbol::Defined {
            name: "_ptr_a".into(),
            section_index: data_sect,
            value: 8,
            weak: false,
        });
        let ptr_b = b.add_symbol(ObjectSymbol::Defined {
            name: "_ptr_b".into(),
            section_index: data_sect,
            value: 8,
            weak: false,
        });
        b.section_mut(data_sect).relocs = vec![
            ObjectReloc::unsigned(greet_sym as u32).at(0),
            ObjectReloc::subtractor(ptr_a as u32).at(8),
            ObjectReloc::unsigned(ptr_b as u32).at(8),
        ];
        b.add_symbol(ObjectSymbol::Common {
            name: "_common_buf".into(),
            size: 64,
            align_log2: 4,
        });
        b.build().unwrap()
    }

    fn opts_for(files: &[(&str, &[u8])]) -> (Options, Vec<std::path::PathBuf>) {
        let dir = std::env::temp_dir().join("pgr_driver_tests");
        std::fs::create_dir_all(&dir).unwrap();
        let mut opts = Options::default();
        let mut paths = Vec::new();
        for (i, (name, bytes)) in files.iter().enumerate() {
            let p = dir.join(format!("obj_{i}_{name}"));
            std::fs::write(&p, bytes).unwrap();
            paths.push(p.clone());
            opts.inputs.push(p.display().to_string());
        }
        opts.output = dir.join("out.bin").display().to_string();
        opts.config.ident = "peregrine-test".into();
        (opts, paths)
    }

    #[test]
    fn link_is_deterministic() {
        let (o1, _) = opts_for(&[("hello.o", &hello_main()), ("greet.o", &greet())]);
        let (o2, _) = opts_for(&[("hello.o", &hello_main()), ("greet.o", &greet())]);
        let a = link_to_bytes(&o1).unwrap();
        let b = link_to_bytes(&o2).unwrap();
        assert_eq!(a, b, "double link must be byte-identical (TDD §4.3)");
        // At least one 16 KiB __TEXT page plus __LINKEDIT.
        assert!(a.len() > 0x4000, "image size {}", a.len());
    }

    #[test]
    fn banner_and_usage_are_shaped() {
        assert!(version_line().starts_with("pgr (Peregrine)"));
        assert!(usage().contains("-o <path>"));
        assert!(usage().contains("M1"));
    }
}

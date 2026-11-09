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

pub mod opts;
pub mod synth;

use pgr_core::LinkArchive;
use pgr_core::LinkArchiveMember;
use pgr_core::LinkInput;
use pgr_core::cache::PoiCache;
use pgr_core::resolve::Dylib;
use pgr_emit::write_image;
use std::path::Path;

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
}

/// Reads a symbol-list file (one symbol per line, `#` comments and blank
/// lines ignored — the ld64 subset Peregrine supports; see docs/COMPAT.md).
fn read_symbol_list(flag: &str, path: &str) -> Result<Vec<Vec<u8>>, DriverError> {
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
        out.push(line.as_bytes().to_vec());
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
    };
    if let Some(cache) = cache {
        let key = pgr_core::cache::PoiCache::content_key(bytes, false);
        cache.store_dylib(&key, &pgr_core::cache::FrozenDylib::from(&dylib));
    }
    Ok(dylib)
}

/// Resolves `-l<name>` against the given search dirs (already ld64-effective:
/// `-syslibroot`-reshaped, defaults included — see
/// [`opts::effective_lib_dirs`]) to a `.tbd` stub, a Mach-O dylib binary, or
/// — M5 — a static archive (dylib candidates win, matching ld64's search
/// order).
///
/// # Errors
/// [`DriverError::Io`] when the file exists but cannot be read.
pub fn resolve_lib(
    name: &str,
    lib_dirs: &[String],
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
        }
    }
    Ok(None)
}

/// Resolves `-framework <name>` against the given search dirs (already
/// ld64-effective: `-syslibroot`-reshaped, defaults included — see
/// [`opts::effective_framework_dirs`]): `<dir>/<Name>.framework/<Name>`
/// (+ `.tbd`).
///
/// # Errors
/// [`DriverError::Io`] when the file exists but cannot be read.
pub fn resolve_framework(
    name: &str,
    framework_dirs: &[String],
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
    Ok(link_to_image_recorded(opts)?.0)
}

/// [`link_to_image`] plus the M9 record: when `-incremental` is active and
/// the one-shot pipeline produced the image, the link's record is built in
/// the same pass (no pipeline re-run). The resident daemon path returns the
/// daemon's refreshed record (M9 GA fusion rung: the wire carries both
/// halves, so a resident full link re-records the state and the
/// incremental cycle survives daemon fallbacks).
fn link_to_image_recorded(
    opts: &opts::Options,
) -> Result<(ImageAndPlan, Option<pgr_emit::incremental::LinkRecord>), DriverError> {
    let (mut prepared, cache) = prepare_link(opts)?;
    if opts.resident {
        // M9 GA fusion rung: an `-incremental` cycle's full link asks the
        // daemon to capture the fresh record (§7.3 — the sidecar must stay
        // fresh across resident links, or the next relink falls back
        // forever); a plain `-resident` link links clean as before.
        let job = if opts.incremental {
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
        let socket = opts
            .resident_socket
            .clone()
            .map_or_else(pgr_daemon::default_socket, std::path::PathBuf::from);
        let exe_hint = std::env::current_exe().ok();
        match pgr_daemon::link_via_daemon(&socket, exe_hint.as_deref(), &job) {
            Ok(img) => {
                let record = img.record.and_then(|bytes| {
                    let decoded = pgr_emit::incremental::LinkRecord::decode(&bytes);
                    if decoded.is_none() && std::env::var_os("PGR_INCREMENTAL_DEBUG").is_some() {
                        eprintln!("pgr: the daemon's record did not decode; dropping it");
                    }
                    decoded
                });
                return Ok((
                    ImageAndPlan {
                        image: img.image,
                        entryoff: img.entryoff,
                        fixup_slots: usize::try_from(img.fixup_slots).unwrap_or(usize::MAX),
                    },
                    record,
                ));
            }
            Err(e) => {
                if std::env::var_os("PGR_RESIDENT_DEBUG").is_some() {
                    eprintln!("pgr: resident fallback: {e}");
                }
            }
        }
    }
    // The M9 resolve wiring, capture half: the recording link carries its
    // Pass-2 snapshot out of the pipeline so the record's v5 section can
    // hold it. The resident path above captures through the wire; this
    // half serves the one-shot path.
    prepared.config.record_resolution = opts.incremental;
    let result = pgr_core::link_cached(
        &prepared.inputs,
        &prepared.archives,
        &prepared.config,
        pgr_core::Parallelism::Auto,
        cache.as_ref(),
    )?;
    check_force_load(&result, &prepared.force_load)?;
    let image = pgr_emit::build_image_fused(&result.layout, &result.objects)?;
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
        match resolve_lib(name, &lib_dirs)? {
            Some((path, bytes)) => {
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
            None => {
                return Err(DriverError::Tbd {
                    path: format!("lib{name}.tbd"),
                    source: pgr_format::FormatError::Malformed {
                        what: "library not found (searched the -L dirs and /usr/lib, each \
                               -syslibroot-prefixed as ld64 does)"
                            .into(),
                    },
                });
            }
        }
    }
    // M5 `-framework` search (M7: ld64-effective `-F` dirs + defaults).
    let framework_dirs = opts::effective_framework_dirs(&opts.framework_dirs, &opts.syslibroots);
    for name in &opts.frameworks {
        match resolve_framework(name, &framework_dirs)? {
            Some((path, bytes)) => {
                if looks_like_tbd(&bytes) {
                    dylibs.push(tbd_to_dylib_cached(&path, &bytes, false, cache.as_ref())?);
                } else if pgr_format::MachHeader64::parse(&bytes)
                    .is_ok_and(|h| h.filetype == pgr_format::consts::MH_DYLIB)
                {
                    dylibs.push(scan_dylib(&path, &bytes)?);
                } else {
                    return Err(DriverError::Tbd {
                        path,
                        source: pgr_format::FormatError::Malformed {
                            what: "framework payload is not a .tbd stub or Mach-O dylib".into(),
                        },
                    });
                }
            }
            None => {
                return Err(DriverError::Tbd {
                    path: format!("{name}.framework/{name}"),
                    source: pgr_format::FormatError::Malformed {
                        what: "framework not found (searched -F dirs)".into(),
                    },
                });
            }
        }
    }
    // M5 `-sectcreate`: section contents from a file, carried as a synthetic
    // single-section object (no symbols — placed by the bucketing pass).
    for (seg, sect, file) in &opts.sectcreate {
        let data = std::fs::read(file).map_err(|source| DriverError::Io {
            path: file.clone(),
            source,
        })?;
        let obj = synth::section_object(seg, sect, &data).map_err(|message| DriverError::Tbd {
            path: file.clone(),
            source: pgr_format::FormatError::Malformed { what: message },
        })?;
        inputs.push(LinkInput {
            name: format!("-sectcreate {seg},{sect} ({file})"),
            bytes: obj,
        });
    }

    let mut config = opts.config.clone();
    config.dylibs = dylibs;
    config.load_symbols = opts
        .force_load
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
    // M3 dylib defaults: the install name defaults to the output path
    // (ld64 behavior); dylibs/bundles never load a dylinker.
    if config.filetype == pgr_core::layout::OutputType::Dylib && config.install_name.is_none() {
        config.install_name = Some(opts.output.clone());
    }
    if config.filetype != pgr_core::layout::OutputType::Execute {
        config.dynamic_linker = false;
    }
    // M3 export filters.
    if let Some(path) = &opts.exported_list_path {
        config.exported_only = Some(read_symbol_list("-exported_symbols_list", path)?);
    }
    if let Some(path) = &opts.unexported_list_path {
        config.unexported = read_symbol_list("-unexported_symbols_list", path)?;
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

/// Classifies and maps one input path: `.tbd`/dylib → [`Dylib`], archive →
/// [`LinkArchive`] (lazy members), anything else → a [`LinkInput`] object.
/// `opts_index` carries the `-weak_library`/`-reexport_library` marker index
/// (`None` for filelist-expanded paths).
fn map_input(
    path: &str,
    opts_index: Option<usize>,
    opts: &opts::Options,
    cache: Option<&pgr_core::cache::PoiCache>,
    inputs: &mut Vec<LinkInput>,
    archives: &mut Vec<LinkArchive>,
    dylibs: &mut Vec<Dylib>,
) -> Result<(), DriverError> {
    let bytes = std::fs::read(path).map_err(|source| DriverError::Io {
        path: path.to_string(),
        source,
    })?;
    if looks_like_tbd(&bytes) {
        let weak = opts_index.is_some_and(|i| opts.weak_library_inputs.contains(&i));
        let mut dylib = tbd_to_dylib_cached(path, &bytes, weak, cache)?;
        dylib.reexport = opts_index.is_some_and(|i| opts.reexport_library_inputs.contains(&i));
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
    if opts.incremental {
        match incremental_relink(opts) {
            Ok(outcome) => return Ok(outcome),
            Err(RelinkAttempt::Error(e)) => return Err(e),
            Err(RelinkAttempt::Fallback(reason)) => {
                if std::env::var_os("PGR_INCREMENTAL_DEBUG").is_some() {
                    eprintln!("pgr: incremental fallback: {reason}");
                }
            }
        }
    }
    // §7.3 "layout stability": the in-place tier stands on slack anchors,
    // so `-incremental` implies slack layout for the whole link cycle —
    // the cold full link reserves the same padding its record describes,
    // and the first edited relink can patch in place.
    let (linked, record) = if opts.incremental && opts.config.layout_slack.is_none() {
        let mut slacked = opts.clone();
        slacked.config.layout_slack = Some(pgr_core::slack::SlackPolicy::default());
        link_to_image_recorded(&slacked)?
    } else {
        link_to_image_recorded(opts)?
    };
    write_image(&linked.image, Path::new(&opts.output))?;
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
    let record_bytes = std::fs::read(record_path(opts))
        .map_err(|_| ResidentAttempt::StandDown("no record for this output yet".into()))?;
    if pgr_emit::incremental::LinkRecord::decode(&record_bytes).is_none() {
        return Err(ResidentAttempt::StandDown(
            "the record did not decode; the in-process relink re-records".into(),
        ));
    }
    let prev = std::fs::read(Path::new(&opts.output)).map_err(|source| {
        ResidentAttempt::StandDown(format!("the previous output is unreadable: {source}"))
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
    })
}

/// The M9 in-place relink (architecture doc §7.3, tier 1): load the
/// record, gate the previous output, re-run the pipeline with slack
/// anchors, plan the patch, clone-and-patch the output, re-sign the dirty
/// pages and rename. Returns the patch outcome plus the refreshed record
/// (written here so the *next* relink starts from the new state).
fn incremental_relink(opts: &opts::Options) -> Result<LinkOutcome, RelinkAttempt> {
    let record_bytes = std::fs::read(record_path(opts))
        .map_err(|_| RelinkAttempt::Fallback(pgr_emit::incremental::FallbackReason::NoRecord))?;
    let Some(record) = pgr_emit::incremental::LinkRecord::decode(&record_bytes) else {
        return Err(pgr_emit::incremental::FallbackReason::RecordUnreadable.into());
    };
    let output = Path::new(&opts.output);
    // Any integrity-gate failure — missing, resized, corrupt — falls back:
    // the full link never needs the previous output.
    match pgr_emit::incremental::check_output(output, &record) {
        Ok(pgr_emit::incremental::Integrity::Match) => {}
        Ok(pgr_emit::incremental::Integrity::Mismatch { detail }) => {
            return Err(pgr_emit::incremental::FallbackReason::OutputChanged { detail }.into());
        }
        Err(e) => {
            return Err(pgr_emit::incremental::FallbackReason::OutputChanged {
                detail: e.to_string(),
            }
            .into());
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
    let result = pgr_core::link_cached(
        &prepared.inputs,
        &prepared.archives,
        &cfg,
        pgr_core::Parallelism::Auto,
        cache.as_ref(),
    )
    .map_err(|e| RelinkAttempt::Error(e.into()))?;
    check_force_load(&result, &prepared.force_load).map_err(RelinkAttempt::Error)?;

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
            return Err(RelinkAttempt::Fallback(reason));
        }
    };
    // Nothing changed: leave the output byte-for-byte alone (§7.3 — the
    // relink's job is done), refresh the record, report the no-op.
    if plan.is_untouched() {
        store_record(opts, &record);
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
        });
    }
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
        pgr_emit::incremental::PatchError::Fallback(reason) => RelinkAttempt::Fallback(reason),
        other => RelinkAttempt::Error(other.into()),
    })?;

    // `-incremental-verify` (§7.3): the audit gate, through the engine's
    // audit twin (the same implementation the daemon serves on the wire).
    // Byte-identity against the full fused emit of the same plan first;
    // a divergence never ships — the output is rewritten from the full
    // emit and re-recorded. Then the strict verifier pass on the final
    // bytes (with the deliberate-unsigned carve-out for `-no_adhoc`).
    let mut audit_summary = None;
    if opts.incremental_verify {
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
    })
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

/// The `--help` text (the M3 flag surface).
#[must_use]
pub fn usage() -> String {
    let mut s = String::with_capacity(1600);
    s.push_str(&version_line());
    s.push_str("\n\nPeregrine: ultra-fast Mach-O linker for arm64-apple-darwin.\n\n");
    s.push_str("M3 — dynamic executables, dylibs and bundles: .o/.tbd/.dylib inputs,\n");
    s.push_str("two-level namespace, GOT/stub synthesis, chained fixups (rebase+bind),\n");
    s.push_str("full export trie with re-exports, export filters, ad-hoc signature.\n\n");
    s.push_str("Usage: pgr [options] <object files>\n\n");
    s.push_str("Options:\n");
    s.push_str("  -o <path>                    output file (required)\n");
    s.push_str("  -arch arm64                  target architecture (arm64 only)\n");
    s.push_str("  -platform_version <p> <min> <sdk>   build version (macos only)\n");
    s.push_str("  -e <symbol>                  entry symbol (default _main)\n");
    s.push_str("  -static                      static semantics (M1 default)\n");
    s.push_str("  -dylib                       link a dylib (MH_DYLIB)\n");
    s.push_str("  -bundle                      link a bundle (MH_BUNDLE)\n");
    s.push_str("  -install_name <path>         LC_ID_DYLIB install name (with -dylib;\n");
    s.push_str("                               defaults to the output path)\n");
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
    s.push_str("  -weak_library <path>         weak-load a dylib\n");
    s.push_str("  -source_version <A.B.C.D.E>  LC_SOURCE_VERSION\n");
    s.push_str("  -fixup_chains | -no_fixup_chains    chained fixups (default on)\n");
    s.push_str("  -adhoc | -no_adhoc           ad-hoc code signature (default on)\n");
    s.push_str("  -headerpad <n>               reserve header space (advisory)\n");
    s.push_str("  -segalign <n>                0x1000 or 0x4000 (default 0x4000)\n");
    s.push_str("  -sectcreate <seg> <sect> <file>   place file bytes in a section\n");
    s.push_str("  -syslibroot <dir>            SDK root prefixed onto every search\n");
    s.push_str("                               path (repeatable; ld64 pairing rule)\n");
    s.push_str("  @<response-file>             expand arguments from a file\n");
    s.push_str("  -cache <dir>                 Stage A link cache (POI + frozen .tbd)\n");
    s.push_str("  -cache_max <bytes>           cache size bound (LRU eviction;\n");
    s.push_str("                               default 2 GiB, 0 = unbounded)\n");
    s.push_str("  -no_cache                    disable the link cache\n");
    s.push_str("  -icf=safe|-icf=all|-no_icf   identical code folding (default none)\n");
    s.push_str("  -incremental                 M9 in-place relink: patch only the\n");
    s.push_str("                               changed 16 KiB tiles into a clone of\n");
    s.push_str("                               the previous output and re-sign the\n");
    s.push_str("                               dirty pages (record: <output>.pgr-inc;\n");
    s.push_str("                               any structure move falls back to the\n");
    s.push_str("                               full link silently)\n");
    s.push_str("  -no_incremental              disable the in-place relink\n");
    s.push_str("  -incremental-verify          after patching, audit byte-identity\n");
    s.push_str("                               and strict-verify (daemon-served\n");
    s.push_str("                               under -resident; in-process else)\n");
    s.push_str("                               against the full emit and run the\n");
    s.push_str("                               strict verifier on the result\n");
    s.push_str("  -resident                    route the link through the resident\n");
    s.push_str("                               daemon (pgrd); falls back to the\n");
    s.push_str("                               one-shot link when unreachable\n");
    s.push_str("  -resident_socket <path>      daemon socket (default $PGR_DAEMON_SOCK,\n");
    s.push_str("                               else {tmpdir}/pgr-<uid>.sock)\n");
    s.push_str("  -help, -h                    this text\n");
    s.push_str("  -version, -V                 version banner\n\n");
    s.push_str("M5 — real-world link surface: .a archives with ranlib-guided lazy\n");
    s.push_str("member pull (S7), -dead_strip, -all_load/-force_load, -filelist,\n");
    s.push_str("-framework/-F, -sectcreate, __cstring merging. -order_file stays\n");
    s.push_str("roadmap-gated.\n");
    s
}

#[cfg(test)]
mod tests {
    use super::{link_to_bytes, usage, version_line};
    use crate::opts::Options;
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

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

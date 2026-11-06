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

/// Resolves `-l<name>` against the `-L` search dirs (then the default
/// `/usr/lib`) to a `.tbd` stub, a Mach-O dylib binary, or — M5 — a static
/// archive (dylib candidates win, matching ld64's search order).
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
    let mut dirs: Vec<&str> = lib_dirs.iter().map(String::as_str).collect();
    dirs.push("/usr/lib");
    for dir in &dirs {
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

/// Resolves `-framework <name>` against the `-F` dirs (then Apple's default
/// framework directories) to a `.tbd` stub or a Mach-O dylib binary:
/// `<dir>/<Name>.framework/<Name>` (+ `.tbd`).
///
/// # Errors
/// [`DriverError::Io`] when the file exists but cannot be read.
pub fn resolve_framework(
    name: &str,
    framework_dirs: &[String],
) -> Result<Option<(String, Vec<u8>)>, DriverError> {
    let mut dirs: Vec<String> = framework_dirs.to_vec();
    dirs.push("/System/Library/Frameworks".into());
    dirs.push("/Library/Frameworks".into());
    let stems = [
        format!("{name}.framework/{name}.tbd"),
        format!("{name}.framework/{name}"),
    ];
    for dir in &dirs {
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
/// # Errors
/// [`DriverError`] on option, link, emit, tbd or I/O failures.
pub fn link_to_image(opts: &opts::Options) -> Result<ImageAndPlan, DriverError> {
    let result = link_inputs_for_emit(opts)?;
    let image = pgr_emit::build_image_fused(&result.layout, &result.objects)?;
    Ok(ImageAndPlan {
        entryoff: result.layout.entryoff,
        fixup_slots: result.layout.fixups.slot_count,
        image,
    })
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

/// Runs Passes 0–3 for the option inputs and returns the emit plan (the
/// shared front half of [`link_to_image`] and [`link_reference_image`]).
fn link_inputs_for_emit(opts: &opts::Options) -> Result<pgr_core::LinkResult, DriverError> {
    // M6 Stage A caches: opt-in via `-cache <dir>` / `PGR_CACHE_DIR`;
    // `-no_cache` always wins. A cache failure never fails the link.
    let cache = if opts.no_cache {
        None
    } else {
        opts.cache_dir
            .clone()
            .or_else(|| std::env::var("PGR_CACHE_DIR").ok())
            .and_then(|dir| pgr_core::cache::PoiCache::open(std::path::Path::new(&dir)).ok())
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
    // static archives (M5).
    for name in &opts.libs {
        match resolve_lib(name, &opts.lib_dirs)? {
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
                        what: "library not found (searched -L dirs and /usr/lib)".into(),
                    },
                });
            }
        }
    }
    // M5 `-framework` search.
    for name in &opts.frameworks {
        match resolve_framework(name, &opts.framework_dirs)? {
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
    let result = pgr_core::link_cached(
        &inputs,
        &archives,
        &config,
        pgr_core::Parallelism::Auto,
        cache.as_ref(),
    )?;

    // `-u <symbol>`: the symbol must resolve to an in-image definition. The
    // name also seeds the archive pull loop, so a member defining it is
    // pulled even when nothing else references it (ld64 `-u` semantics).
    for sym in &opts.force_load {
        let defined = result.layout.symbols.iter().any(|s| {
            s.external
                && s.n_type & pgr_format::consts::N_TYPE != pgr_format::consts::N_UNDF
                && result.interner.bytes(s.name) == sym.as_bytes()
        });
        if !defined {
            return Err(DriverError::ForceLoad {
                symbol: sym.clone(),
                message: "not defined by any input (direct objects or pulled archive members)"
                    .into(),
            });
        }
    }
    Ok(result)
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
/// # Errors
/// [`DriverError`] on option, link, emit or filesystem failures.
pub fn run(opts: &opts::Options) -> Result<LinkOutcome, DriverError> {
    let linked = link_to_image(opts)?;
    write_image(&linked.image, Path::new(&opts.output))?;
    Ok(LinkOutcome {
        output: opts.output.clone(),
        file_size: linked.image.len() as u64,
        entryoff: linked.entryoff,
        fixup_slots: linked.fixup_slots,
    })
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
        let _data = b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
        let greet_sym = b.add_symbol(ObjectSymbol::Defined {
            name: "_greet".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        let ptr_a = b.add_symbol(ObjectSymbol::Defined {
            name: "_ptr_a".into(),
            section_index: _data,
            value: 8,
            weak: false,
        });
        let ptr_b = b.add_symbol(ObjectSymbol::Defined {
            name: "_ptr_b".into(),
            section_index: _data,
            value: 8,
            weak: false,
        });
        b.section_mut(_data).relocs = vec![
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

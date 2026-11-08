//! ld64-compatible option surface (TDD §5 Pass 0, M2 subset).
//!
//! M2 links direct `.o` inputs against `.tbd` dylib stubs: `-l`/`-L`
//! library search, `-rpath`, `-flat_namespace`, `-undefined`,
//! `-weak_library`, `-u` and `-source_version` join the surface. Flags real
//! builds use that arrive at later milestones (`-dylib`, `-dead_strip`,
//! `-framework`, `-filelist`, `-order_file`, TLV, bitcode) are rejected with
//! actionable messages rather than silently ignored — a linker that pretends
//! to understand a flag it drops is worse than one that says "not yet".

use pgr_core::layout::LinkConfig;

/// Parsed driver options (M2 surface).
#[derive(Debug, Clone)]
pub struct Options {
    /// Output path (`-o`).
    pub output: String,
    /// Input object paths, in command-line order (the resolution tie-break).
    pub inputs: Vec<String>,
    /// The link configuration handed to Pass 3.
    pub config: LinkConfig,
    /// Minimum page size accepted for `-segalign` on arm64 (16 KiB default).
    pub segalign: u64,
    /// `-headerpad` (advisory at M1: commands never grow after the link).
    pub headerpad: u64,
    /// `-L` library search directories, in command-line order.
    pub lib_dirs: Vec<String>,
    /// `-l` requested library basenames (`-lfoo` / `-l foo`), in order.
    pub libs: Vec<String>,
    /// `-u <symbol>`: force the symbol to be treated as defined (must
    /// resolve; a plain liveness marker at M2).
    pub force_load: Vec<String>,
    /// Indices into `inputs` loaded weakly (`-weak_library`).
    pub weak_library_inputs: Vec<usize>,
    /// Indices into `inputs` loaded as `LC_REEXPORT_DYLIB`
    /// (`-reexport_library`, M3).
    pub reexport_library_inputs: Vec<usize>,
    /// Path of the `-exported_symbols_list` file (read by the driver).
    pub exported_list_path: Option<String>,
    /// Path of the `-unexported_symbols_list` file (read by the driver).
    pub unexported_list_path: Option<String>,
    /// M5 `-all_load`: pull every archive member regardless of liveness.
    pub all_load: bool,
    /// M5 `-force_load <archive>`: pull every member of the named archive.
    pub force_load_archives: Vec<String>,
    /// M5 `-filelist <path>[,<dir>]`: newline-separated input paths,
    /// resolved against the optional base directory.
    pub filelists: Vec<(String, Option<String>)>,
    /// M5 `-framework <name>` (searched via `-F` dirs).
    pub frameworks: Vec<String>,
    /// M5 `-F <dir>`: framework search directories.
    pub framework_dirs: Vec<String>,
    /// M5 `-sectcreate <seg> <sect> <file>`: section contents from a file.
    pub sectcreate: Vec<(String, String, String)>,
    /// M6 `-cache <dir>` / `PGR_CACHE_DIR`: the Stage A POI + frozen-`.tbd`
    /// cache directory (opt-in; `None` disables caching).
    pub cache_dir: Option<String>,
    /// M6 `-no_cache`: force caching off even when a directory is set.
    pub no_cache: bool,
    /// M7 `-syslibroot <dir>` (repeatable): SDK roots that reshape the
    /// library/framework search paths (ld64 rule — see
    /// [`effective_lib_dirs`]).
    pub syslibroots: Vec<String>,
    /// M7 `-cache_max <bytes>` / `PGR_CACHE_MAX`: the cache directory's size
    /// bound (oldest-mtime LRU eviction; `0` = unbounded). Defaults to 2 GiB
    /// when a cache directory is active.
    pub cache_max: Option<u64>,
    /// M8 `-resident`: route the link through the resident daemon
    /// (`pgrd`, architecture doc §7.2). Optional and transparent by
    /// contract: an unreachable daemon falls back to the one-shot link.
    pub resident: bool,
    /// M8 `-resident_socket <path>`: the daemon socket (default:
    /// `$PGR_DAEMON_SOCK`, else `{tmpdir}/pgr-<uid>.sock`).
    pub resident_socket: Option<String>,
    /// M9 `-incremental` (architecture doc §7.3): the in-place incremental
    /// relink. Records the link state next to the output
    /// (`<output>.pgr-inc`) and, on the next link, patches only the changed
    /// 16 KiB tiles into a clone of the previous output. Any skeleton
    /// move, output change or record problem silently falls back to the
    /// full link (the fallback must always be available). Implies slack
    /// layout (`LinkConfig::layout_slack`) when the caller left it unset.
    pub incremental: bool,
    /// M9 `-incremental-verify`: after a successful in-place patch, audit
    /// it — byte-identity against the full fused emit of the same plan,
    /// then a strict `pgr-verify` pass on the patched bytes (the §7.3
    /// "no stale-signature or stale-fixup failures" gate). A divergence
    /// never ships: the output is rewritten from the full emit.
    pub incremental_verify: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            output: String::new(),
            inputs: Vec::new(),
            config: LinkConfig::default(),
            segalign: pgr_format::consts::PAGE_SIZE_16K,
            headerpad: 0,
            lib_dirs: Vec::new(),
            libs: Vec::new(),
            force_load: Vec::new(),
            weak_library_inputs: Vec::new(),
            reexport_library_inputs: Vec::new(),
            exported_list_path: None,
            unexported_list_path: None,
            all_load: false,
            force_load_archives: Vec::new(),
            filelists: Vec::new(),
            frameworks: Vec::new(),
            framework_dirs: Vec::new(),
            sectcreate: Vec::new(),
            cache_dir: None,
            no_cache: false,
            cache_max: None,
            syslibroots: Vec::new(),
            resident: false,
            resident_socket: None,
            incremental: false,
            incremental_verify: false,
        }
    }
}

/// A command-line problem (exit code 2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OptsError {
    /// A required flag or value is missing.
    #[error("missing value for {flag}")]
    MissingValue {
        /// The flag that wanted a value.
        flag: String,
    },
    /// The flag is not part of the M1 surface.
    #[error("unsupported flag {flag} (M1 links direct .o inputs only; {hint})")]
    Unsupported {
        /// The offending flag.
        flag: String,
        /// What to do instead / when it lands.
        hint: String,
    },
    /// A flag value is malformed.
    #[error("invalid value for {flag}: {value}")]
    InvalidValue {
        /// The flag.
        flag: String,
        /// The bad value.
        value: String,
    },
    /// No output path or no inputs.
    #[error("{message}")]
    Missing {
        /// What is missing.
        message: String,
    },
    /// Duplicate `-o` or a repeated flag that must be unique.
    #[error("{message}")]
    Repeated {
        /// What was repeated.
        message: String,
    },
    /// A `@response-file` could not be read, nested too deeply, or contained
    /// a malformed token (exit code 2).
    #[error("response file {path}: {message}")]
    ResponseFile {
        /// The `@path` argument as written.
        path: String,
        /// What went wrong.
        message: String,
    },
}

/// Flags accepted with no effect at M1 (their features do not exist yet).
/// M7 adds the build-system no-ops: demangling (symtab names are stored
/// verbatim, exactly ld64's on-disk effect) and the deduplicate toggle
/// (cstring/code dedup stays on — the arm64 default).
const NOOP_FLAGS: [&str; 8] = [
    "-no_adhoc_extensions",
    "-keep_private_externs",
    "-no_uuid",
    "-no_function_starts",
    "-no_data_in_code",
    "-demangle",
    "-no_demangle",
    "-no_deduplicate",
];

/// Flags that arrive at a later milestone (rejected with the roadmap entry).
const LATER_FLAGS: [(&str, &str); 9] = [
    ("-dylinker", "MH_DYLINKER outputs are a later milestone"),
    ("-weak_framework", "framework bundles are a later milestone"),
    ("-lazy_framework", "framework bundles are a later milestone"),
    ("-lazy_library", "later milestone"),
    (
        "-order_file",
        "M5 scope (symbol-boundary ordering lands with the atomizer)",
    ),
    ("-U", "later milestone (make-undefined)"),
    ("-pagezero_size", "later milestone"),
    (
        "-sub_library",
        "umbrella re-exports beyond -reexport_library are a later milestone",
    ),
    (
        "-sub_umbrella",
        "umbrella re-exports beyond -reexport_library are a later milestone",
    ),
];

/// Parses argv (without the program name). `@response-file` arguments are
/// expanded in place first (recursively, ld64-style tokenization).
///
/// # Errors
/// [`OptsError`] on any malformed or unsupported flag.
pub fn parse(args: &[std::ffi::OsString]) -> Result<Options, OptsError> {
    let expanded = expand_response_files(args, 0)?;
    let args: &[std::ffi::OsString] = &expanded;
    let mut opts = Options::default();
    let mut output_seen = false;
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].to_str().ok_or_else(|| OptsError::InvalidValue {
            flag: "<arg>".into(),
            value: args[i].to_string_lossy().into_owned(),
        })?;
        if arg == "-o" {
            if output_seen {
                return Err(OptsError::Repeated {
                    message: "-o given more than once".into(),
                });
            }
            opts.output = next_value(args, &mut i, arg)?;
            output_seen = true;
        } else if arg.starts_with('-') {
            apply_flag(&mut opts, arg, args, &mut i)?;
        } else {
            opts.inputs.push(arg.to_string());
        }
        i += 1;
    }
    finish(&opts)
}

/// The next argv element as a flag value.
fn next_value(args: &[std::ffi::OsString], i: &mut usize, flag: &str) -> Result<String, OptsError> {
    *i += 1;
    args.get(*i)
        .and_then(|v| v.to_str())
        .map(str::to_string)
        .ok_or_else(|| OptsError::MissingValue {
            flag: flag.to_string(),
        })
}

/// Maximum `@response-file` nesting depth (cycle protection).
const RESPONSE_FILE_MAX_DEPTH: usize = 32;

/// Expands `@path` arguments in place (M7): the file's contents are
/// tokenized ld64-style (whitespace-separated, `#` comments, `"` grouping
/// with `\` escapes) and spliced into the argument list at the argument's
/// position. Response files nest (a token starting with `@` inside a file is
/// expanded recursively, bounded by [`RESPONSE_FILE_MAX_DEPTH`]).
///
/// Expansion is **opportunistic, exactly ld64's rule**: a token starting
/// with `@` only expands when the referenced file exists — otherwise the
/// token passes through untouched, which is what keeps `-install_name
/// @rpath/libfoo.dylib` (and every other `@`-prefixed value) working.
fn expand_response_files(
    args: &[std::ffi::OsString],
    depth: usize,
) -> Result<Vec<std::ffi::OsString>, OptsError> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        let s = arg.to_str().ok_or_else(|| OptsError::InvalidValue {
            flag: "<arg>".into(),
            value: arg.to_string_lossy().into_owned(),
        })?;
        if let Some(path) = s.strip_prefix('@') {
            if !std::path::Path::new(path).is_file() {
                // ld64 semantics: not a readable response file — literal.
                out.push(arg.clone());
                continue;
            }
            if depth >= RESPONSE_FILE_MAX_DEPTH {
                return Err(OptsError::ResponseFile {
                    path: s.to_string(),
                    message: format!("nested more than {RESPONSE_FILE_MAX_DEPTH} levels (cycle?)"),
                });
            }
            let text = std::fs::read_to_string(path).map_err(|e| OptsError::ResponseFile {
                path: s.to_string(),
                message: e.to_string(),
            })?;
            let tokens = tokenize_response_file(&text).map_err(|m| OptsError::ResponseFile {
                path: s.to_string(),
                message: m,
            })?;
            let inner: Vec<std::ffi::OsString> =
                tokens.into_iter().map(std::ffi::OsString::from).collect();
            out.extend(expand_response_files(&inner, depth + 1)?);
        } else {
            out.push(arg.clone());
        }
    }
    Ok(out)
}

/// Tokenizes one response file body: whitespace-separated tokens, `#`
/// comments to end of line, `"`-quoted sections with `\` escaping the next
/// character (so `\` + space joins a token). Errors name the line.
fn tokenize_response_file(text: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let mut it = line.chars().peekable();
        while let Some(&c) = it.peek() {
            if c.is_whitespace() {
                it.next();
                continue;
            }
            if c == '#' {
                break;
            }
            let mut tok = String::new();
            let mut quoted = false;
            while let Some(&c) = it.peek() {
                match c {
                    '"' => {
                        quoted = !quoted;
                        it.next();
                    }
                    '\\' => {
                        it.next();
                        if let Some(&n) = it.peek() {
                            tok.push(n);
                            it.next();
                        }
                    }
                    c if c.is_whitespace() && !quoted => break,
                    c => {
                        tok.push(c);
                        it.next();
                    }
                }
            }
            if quoted {
                return Err(format!("line {}: unterminated quote", n + 1));
            }
            out.push(tok);
        }
    }
    Ok(out)
}

/// Joins one `-syslibroot` with a search dir (ld64 pairs the SDK root with
/// every search path; absolute dirs concatenate cleanly).
fn join_root(root: &str, dir: &str) -> String {
    let root = root.trim_end_matches('/');
    if dir.starts_with('/') {
        format!("{root}{dir}")
    } else {
        format!("{root}/{dir}")
    }
}

/// The effective library search dirs (M7, ld64 `-syslibroot` rule):
///
/// * no roots: the `-L` dirs, then the default `/usr/lib`;
/// * exactly one root: **only the root-prefixed variants** are searched
///   (`<root>/<dir>` for every `-L` dir and the default) — the SDK stands in
///   for the host;
/// * two or more roots: the **union** — every root-prefixed variant plus the
///   original path itself.
#[must_use]
pub fn effective_lib_dirs(lib_dirs: &[String], syslibroots: &[String]) -> Vec<String> {
    effective_dirs(lib_dirs, syslibroots, &["/usr/lib"])
}

/// [`effective_lib_dirs`] for frameworks: the `-F` dirs plus Apple's default
/// framework directories.
#[must_use]
pub fn effective_framework_dirs(framework_dirs: &[String], syslibroots: &[String]) -> Vec<String> {
    effective_dirs(
        framework_dirs,
        syslibroots,
        &["/System/Library/Frameworks", "/Library/Frameworks"],
    )
}

/// The shared `-syslibroot` combination rule (see [`effective_lib_dirs`]).
fn effective_dirs(dirs: &[String], roots: &[String], defaults: &[&str]) -> Vec<String> {
    if roots.is_empty() {
        let mut out: Vec<String> = dirs.to_vec();
        out.extend(defaults.iter().map(|s| (*s).to_string()));
        return out;
    }
    let mut out = Vec::new();
    let push_all = |out: &mut Vec<String>, d: &str| {
        if roots.len() == 1 {
            out.push(join_root(&roots[0], d));
        } else {
            for r in roots {
                out.push(join_root(r, d));
            }
            out.push(d.to_string());
        }
    };
    for d in dirs {
        push_all(&mut out, d);
    }
    for d in defaults {
        push_all(&mut out, d);
    }
    out
}

/// Applies one option flag to the configuration.
fn apply_flag(
    opts: &mut Options,
    arg: &str,
    args: &[std::ffi::OsString],
    i: &mut usize,
) -> Result<(), OptsError> {
    match arg {
        "-arch" => {
            let v = next_value(args, i, arg)?;
            if v != "arm64" {
                return Err(OptsError::Unsupported {
                    flag: arg.into(),
                    hint: "M1 targets arm64-apple-darwin exclusively".into(),
                });
            }
        }
        "-platform_version" => {
            let platform = next_value(args, i, arg)?;
            let minos = next_value(args, i, arg)?;
            let sdk = next_value(args, i, arg)?;
            if platform != "macos" {
                return Err(OptsError::Unsupported {
                    flag: arg.into(),
                    hint: format!("platform {platform:?} (M1 supports macos only)"),
                });
            }
            opts.config.minos = parse_version(&minos).ok_or_else(|| OptsError::InvalidValue {
                flag: arg.into(),
                value: minos,
            })?;
            opts.config.sdk = parse_version(&sdk).ok_or_else(|| OptsError::InvalidValue {
                flag: arg.into(),
                value: sdk,
            })?;
        }
        "-e" | "-entry" => {
            opts.config.entry_symbol = next_value(args, i, arg)?;
        }
        "-headerpad" => {
            let v = next_value(args, i, arg)?;
            opts.headerpad = parse_number(&v).ok_or_else(|| OptsError::InvalidValue {
                flag: arg.into(),
                value: v,
            })?;
        }
        "-segalign" => {
            let v = next_value(args, i, arg)?;
            let n = parse_number(&v).ok_or_else(|| OptsError::InvalidValue {
                flag: arg.into(),
                value: v.clone(),
            })?;
            if n != 0x1000 && n != 0x4000 {
                return Err(OptsError::InvalidValue {
                    flag: arg.into(),
                    value: format!("{v} (chained fixups need a -segalign of 0x1000 or 0x4000)"),
                });
            }
            opts.segalign = n;
        }
        "-static" => {
            // The M1 default; accepted for ld64 compatibility.
        }
        "-fixup_chains" => opts.config.fixup_chains = true,
        "-no_fixup_chains" => opts.config.fixup_chains = false,
        "-adhoc" => opts.config.adhoc = true,
        "-no_adhoc" => opts.config.adhoc = false,
        "-flat_namespace" => opts.config.flat_namespace = true,
        "-no_flat_namespace" | "-twolevel_namespace" => {
            opts.config.flat_namespace = false;
        }
        "-undefined" => {
            let v = next_value(args, i, arg)?;
            opts.config.undefined_policy = match v.as_str() {
                "error" => pgr_core::resolve::UndefinedPolicy::Error,
                "dynamic_lookup" => pgr_core::resolve::UndefinedPolicy::DynamicLookup,
                other => {
                    return Err(OptsError::InvalidValue {
                        flag: arg.into(),
                        value: format!("{other} (error | dynamic_lookup)"),
                    });
                }
            };
        }
        "-rpath" => {
            let v = next_value(args, i, arg)?;
            opts.config.rpaths.push(v);
        }
        "-syslibroot" => {
            let v = next_value(args, i, arg)?;
            opts.syslibroots.push(v);
        }
        "-object_path_lto" => {
            // The LTO object scratch path build systems pass; accepted, no
            // effect (bitcode objects are diagnosed at input mapping, M6).
            let _v = next_value(args, i, arg)?;
        }
        "-source_version" => {
            let v = next_value(args, i, arg)?;
            let sv = parse_source_version(&v).ok_or_else(|| OptsError::InvalidValue {
                flag: arg.into(),
                value: format!("{v} (A24.B10.C10.D10.E10, e.g. 1.2.3.4.5)"),
            })?;
            opts.config.source_version = Some(sv);
        }
        "-weak_library" => {
            // The whole dylib loads weakly (LC_LOAD_WEAK_DYLIB + weak binds).
            let v = next_value(args, i, arg)?;
            opts.inputs.push(v);
            opts.weak_library_inputs.push(opts.inputs.len() - 1);
        }
        "-dylib" => {
            if opts.config.filetype != pgr_core::layout::OutputType::Execute {
                return Err(OptsError::Repeated {
                    message: "-dylib and -bundle are mutually exclusive".into(),
                });
            }
            opts.config.filetype = pgr_core::layout::OutputType::Dylib;
        }
        "-bundle" => {
            if opts.config.filetype != pgr_core::layout::OutputType::Execute {
                return Err(OptsError::Repeated {
                    message: "-dylib and -bundle are mutually exclusive".into(),
                });
            }
            opts.config.filetype = pgr_core::layout::OutputType::Bundle;
        }
        "-install_name" => {
            let v = next_value(args, i, arg)?;
            opts.config.install_name = Some(v);
        }
        "-current_version" => {
            let v = next_value(args, i, arg)?;
            opts.config.current_version =
                parse_version(&v).ok_or_else(|| OptsError::InvalidValue {
                    flag: arg.into(),
                    value: format!("{v} (X.Y.Z)"),
                })?;
        }
        "-compatibility_version" => {
            let v = next_value(args, i, arg)?;
            opts.config.compatibility_version =
                parse_version(&v).ok_or_else(|| OptsError::InvalidValue {
                    flag: arg.into(),
                    value: format!("{v} (X.Y.Z)"),
                })?;
        }
        "-reexport_library" => {
            // Loads the dylib as LC_REEXPORT_DYLIB and re-exports its
            // symbols through this image's trie (M3).
            let v = next_value(args, i, arg)?;
            opts.inputs.push(v);
            opts.reexport_library_inputs.push(opts.inputs.len() - 1);
        }
        "-exported_symbols_list" => {
            let v = next_value(args, i, arg)?;
            if opts.exported_list_path.is_some() {
                return Err(OptsError::Repeated {
                    message: "-exported_symbols_list given more than once".into(),
                });
            }
            opts.exported_list_path = Some(v);
        }
        "-unexported_symbols_list" => {
            let v = next_value(args, i, arg)?;
            if opts.unexported_list_path.is_some() {
                return Err(OptsError::Repeated {
                    message: "-unexported_symbols_list given more than once".into(),
                });
            }
            opts.unexported_list_path = Some(v);
        }
        "-mark_dead_strippable_dylib" => opts.config.dead_strippable = true,
        "-dead_strip" => opts.config.dead_strip = true,
        "-no_dead_strip" => opts.config.dead_strip = false,
        "-icf" => {
            // ld64 separates flag and value: `-icf safe`. The attached form
            // (`-icf=safe`) is matched below.
            let v = next_value(args, i, arg)?;
            opts.config.icf = parse_icf_level(&v).ok_or_else(|| OptsError::InvalidValue {
                flag: "-icf".into(),
                value: v.clone(),
            })?;
        }
        a if a.starts_with("-icf=") => {
            let v = &a[5..];
            opts.config.icf = parse_icf_level(v).ok_or_else(|| OptsError::InvalidValue {
                flag: "-icf".into(),
                value: v.to_string(),
            })?;
        }
        "-no_icf" => opts.config.icf = pgr_core::icf::IcfMode::None,
        "-cache" => {
            let v = next_value(args, i, arg)?;
            opts.cache_dir = Some(v);
        }
        "-cache_max" => {
            let v = next_value(args, i, arg)?;
            let n = parse_number(&v).ok_or_else(|| OptsError::InvalidValue {
                flag: arg.into(),
                value: v.clone(),
            })?;
            opts.cache_max = Some(n);
        }
        "-no_cache" => opts.no_cache = true,
        "-resident" => opts.resident = true,
        "-no_resident" => opts.resident = false,
        "-resident_socket" => {
            let v = next_value(args, i, arg)?;
            opts.resident_socket = Some(v);
        }
        "-incremental" => opts.incremental = true,
        "-no_incremental" => opts.incremental = false,
        // The §7.3 audit gate implies the in-place tier.
        "-incremental-verify" => {
            opts.incremental = true;
            opts.incremental_verify = true;
        }
        "-all_load" => opts.all_load = true,
        "-force_load" => {
            let v = next_value(args, i, arg)?;
            opts.force_load_archives.push(v);
        }
        "-filelist" => {
            let v = next_value(args, i, arg)?;
            // `path[,dir]`: entries resolve against the optional directory.
            let (path, dir) = match v.split_once(',') {
                Some((p, d)) => (p.to_string(), Some(d.to_string())),
                None => (v, None),
            };
            opts.filelists.push((path, dir));
        }
        "-framework" => {
            let v = next_value(args, i, arg)?;
            opts.frameworks.push(v);
        }
        "-F" => {
            let v = next_value(args, i, arg)?;
            opts.framework_dirs.push(v);
        }
        "-sectcreate" => {
            let seg = next_value(args, i, arg)?;
            let sect = next_value(args, i, arg)?;
            let file = next_value(args, i, arg)?;
            opts.sectcreate.push((seg, sect, file));
        }
        "-l" | "-L" | "-u" => {
            let v = next_value(args, i, arg)?;
            match arg {
                "-l" => opts.libs.push(v),
                "-L" => opts.lib_dirs.push(v),
                _ => opts.force_load.push(v),
            }
        }
        "-help" | "--help" | "-h" => Err(OptsError::Unsupported {
            flag: arg.into(),
            hint: "handled by the CLI shell before parsing".into(),
        })?,
        _ if arg.starts_with("-l") && arg.len() > 2 && !arg.starts_with("-lazy") => {
            // Attached library form: -lSystem, -lfoo.
            opts.libs.push(arg[2..].to_string());
        }
        _ if NOOP_FLAGS.contains(&arg) => {
            // Accepted no-ops at M1 (the features they toggle do not exist
            // yet; emitting nothing matches the requested state).
        }
        _ if LATER_FLAGS.iter().any(|(f, _)| *f == arg) => {
            let hint = LATER_FLAGS
                .iter()
                .find(|(f, _)| *f == arg)
                .map(|(_, h)| (*h).to_string())
                .unwrap_or_default();
            return Err(OptsError::Unsupported {
                flag: arg.into(),
                hint,
            });
        }
        _ => {
            return Err(OptsError::Unsupported {
                flag: arg.into(),
                hint: "unknown flag (see --help for the M1 surface)".into(),
            });
        }
    }
    Ok(())
}

/// Post-conditions: an output path, at least one input, and the M3 flag
/// combinations consistent with the output kind.
fn finish(opts: &Options) -> Result<Options, OptsError> {
    if opts.output.is_empty() {
        return Err(OptsError::Missing {
            message: "no output path (use -o <path>)".into(),
        });
    }
    if opts.inputs.is_empty() {
        return Err(OptsError::Missing {
            message: "no input object files".into(),
        });
    }
    match opts.config.filetype {
        pgr_core::layout::OutputType::Execute => {
            if opts.config.install_name.is_some() {
                return Err(OptsError::InvalidValue {
                    flag: "-install_name".into(),
                    value: "only valid with -dylib".into(),
                });
            }
            if opts.config.current_version != 0 {
                return Err(OptsError::InvalidValue {
                    flag: "-current_version".into(),
                    value: "only valid with -dylib".into(),
                });
            }
            if opts.config.compatibility_version != 0 {
                return Err(OptsError::InvalidValue {
                    flag: "-compatibility_version".into(),
                    value: "only valid with -dylib".into(),
                });
            }
            if opts.config.dead_strippable {
                return Err(OptsError::InvalidValue {
                    flag: "-mark_dead_strippable_dylib".into(),
                    value: "only valid with -dylib".into(),
                });
            }
        }
        pgr_core::layout::OutputType::Bundle => {
            if opts.config.install_name.is_some() {
                return Err(OptsError::InvalidValue {
                    flag: "-install_name".into(),
                    value: "only valid with -dylib".into(),
                });
            }
        }
        pgr_core::layout::OutputType::Dylib => {
            // ld64 defaults the install name to the output path; the driver
            // applies the default before linking.
        }
    }
    Ok(opts.clone())
}

/// Parses the `-icf` level (ld64's `none|safe|all` vocabulary).
#[must_use]
pub fn parse_icf_level(v: &str) -> Option<pgr_core::icf::IcfMode> {
    match v {
        "none" => Some(pgr_core::icf::IcfMode::None),
        "safe" => Some(pgr_core::icf::IcfMode::Safe),
        "all" => Some(pgr_core::icf::IcfMode::All),
        _ => None,
    }
}

/// Parses `X.Y.Z` into the packed `(X<<16)|(Y<<8)|Z` version.
#[must_use]
pub fn parse_version(v: &str) -> Option<u32> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let mut out = 0u32;
    for (k, p) in parts.iter().enumerate() {
        let n: u32 = p.parse().ok()?;
        if n > 0xFF {
            return None;
        }
        out |= n << (16 - 8 * k);
    }
    Some(out)
}

/// Parses `A.B.C.D.E` into the packed `A24.B10.C10.D10.E10` source version.
#[must_use]
pub fn parse_source_version(v: &str) -> Option<u64> {
    let mut out = 0u64;
    let bits = [24u32, 10, 10, 10, 10];
    for (seen, part) in v.split('.').enumerate() {
        if part.is_empty() {
            return None;
        }
        let n: u64 = part.parse().ok()?;
        if seen >= 5 || n >= (1 << bits[seen]) {
            return None;
        }
        let shift = bits[seen..].iter().sum::<u32>() - bits[seen];
        out |= n << shift;
    }
    Some(out)
}

/// Parses a number in decimal or 0x-hex form.
#[must_use]
pub fn parse_number(v: &str) -> Option<u64> {
    if let Some(hex) = v.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        v.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{OptsError, parse, parse_number, parse_version};
    use std::ffi::OsString;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(std::ffi::OsString::from).collect()
    }

    #[test]
    fn minimal_invocation_parses() {
        let o = parse(&args(&["-o", "out", "a.o", "b.o"])).unwrap();
        assert_eq!(o.output, "out");
        assert_eq!(o.inputs, ["a.o", "b.o"]);
        assert_eq!(o.config.entry_symbol, "_main");
        assert!(o.config.fixup_chains);
        assert!(o.config.adhoc);
    }

    #[test]
    fn flags_shape_the_config() {
        let o = parse(&args(&[
            "-o",
            "out",
            "-arch",
            "arm64",
            "-platform_version",
            "macos",
            "13.0",
            "15.1",
            "-e",
            "_start",
            "-no_fixup_chains",
            "-no_adhoc",
            "-headerpad",
            "0x800",
            "-segalign",
            "0x1000",
            "a.o",
        ]))
        .unwrap();
        assert_eq!(o.config.minos, (13 << 16));
        assert_eq!(o.config.sdk, (15 << 16) | (1 << 8));
        assert_eq!(o.config.entry_symbol, "_start");
        assert!(!o.config.fixup_chains);
        assert!(!o.config.adhoc);
        assert_eq!(o.headerpad, 0x800);
        assert_eq!(o.segalign, 0x1000);
    }

    #[test]
    fn missing_output_or_inputs_error() {
        assert!(matches!(
            parse(&args(&["a.o"])),
            Err(OptsError::Missing { .. })
        ));
        assert!(matches!(
            parse(&args(&["-o", "out"])),
            Err(OptsError::Missing { .. })
        ));
    }

    #[test]
    fn later_milestone_flags_are_rejected_actionably() {
        let err = parse(&args(&["-o", "out", "-order_file", "f.txt", "a.o"])).unwrap_err();
        assert!(err.to_string().contains("M5"), "{err}");
        let err = parse(&args(&["-o", "out", "-weak_framework", "Foo", "a.o"])).unwrap_err();
        assert!(err.to_string().contains("framework"), "{err}");
        let err = parse(&args(&["-o", "out", "--wat", "a.o"])).unwrap_err();
        assert!(err.to_string().contains("unknown flag"), "{err}");
    }

    #[test]
    fn m5_flags_shape_the_config() {
        let o = parse(&args(&[
            "-o",
            "out",
            "-dead_strip",
            "-all_load",
            "-force_load",
            "/libs/liba.a",
            "-filelist",
            "objs.txt,objdir",
            "-framework",
            "Foundation",
            "-F",
            "/sdks/MacOSX.sdk/System/Library/Frameworks",
            "-sectcreate",
            "__DATA",
            "__plist",
            "info.plist",
            "-u",
            "_forced",
            "a.o",
        ]))
        .unwrap();
        assert!(o.config.dead_strip);
        assert!(o.all_load);
        assert_eq!(o.force_load_archives, ["/libs/liba.a"]);
        assert_eq!(
            o.filelists,
            vec![("objs.txt".to_string(), Some("objdir".to_string()))]
        );
        assert_eq!(o.frameworks, ["Foundation"]);
        assert_eq!(
            o.framework_dirs,
            ["/sdks/MacOSX.sdk/System/Library/Frameworks"]
        );
        assert_eq!(
            o.sectcreate,
            vec![(
                "__DATA".to_string(),
                "__plist".to_string(),
                "info.plist".to_string()
            )]
        );
        assert_eq!(o.force_load, ["_forced"]);
        // `-no_dead_strip` overrides (last wins).
        let o = parse(&args(&[
            "-o",
            "out",
            "-dead_strip",
            "-no_dead_strip",
            "a.o",
        ]))
        .unwrap();
        assert!(!o.config.dead_strip);
    }

    #[test]
    fn m3_dylib_flags_shape_the_config() {
        let o = parse(&args(&[
            "-o",
            "libfoo.dylib",
            "-dylib",
            "-install_name",
            "@rpath/libfoo.dylib",
            "-current_version",
            "1.2.0",
            "-compatibility_version",
            "1.0.0",
            "-mark_dead_strippable_dylib",
            "-exported_symbols_list",
            "/tmp/exports.txt",
            "a.o",
        ]))
        .unwrap();
        assert_eq!(o.config.filetype, pgr_core::layout::OutputType::Dylib);
        assert_eq!(
            o.config.install_name.as_deref(),
            Some("@rpath/libfoo.dylib")
        );
        assert_eq!(o.config.current_version, (1 << 16) | (2 << 8));
        assert_eq!(o.config.compatibility_version, 1 << 16);
        assert!(o.config.dead_strippable);
        assert_eq!(o.exported_list_path.as_deref(), Some("/tmp/exports.txt"));
    }

    #[test]
    fn m3_bundle_flag_shapes_the_config() {
        let o = parse(&args(&["-o", "plug.bundle", "-bundle", "a.o"])).unwrap();
        assert_eq!(o.config.filetype, pgr_core::layout::OutputType::Bundle);
    }

    #[test]
    fn m3_flag_combinations_are_validated() {
        // dylib + bundle are mutually exclusive.
        assert!(parse(&args(&["-o", "x", "-dylib", "-bundle", "a.o"])).is_err());
        // install_name only with -dylib.
        assert!(
            parse(&args(&["-o", "x", "-install_name", "@rpath/x", "a.o"])).is_err(),
            "install_name without -dylib"
        );
        assert!(
            parse(&args(&[
                "-o",
                "x",
                "-bundle",
                "-install_name",
                "@rpath/x",
                "a.o"
            ]))
            .is_err(),
            "install_name with -bundle"
        );
        // versions only with -dylib.
        assert!(
            parse(&args(&["-o", "x", "-current_version", "1.0.0", "a.o"])).is_err(),
            "current_version without -dylib"
        );
        assert!(
            parse(&args(&[
                "-o",
                "x",
                "-dylib",
                "-current_version",
                "1.2.3.4",
                "a.o"
            ]))
            .is_err(),
            "bad version value"
        );
    }

    #[test]
    fn m3_reexport_library_records_the_input() {
        let o = parse(&args(&[
            "-o",
            "x",
            "-reexport_library",
            "libbar.tbd",
            "-weak_library",
            "libw.tbd",
            "a.o",
        ]))
        .unwrap();
        assert_eq!(o.inputs, ["libbar.tbd", "libw.tbd", "a.o"]);
        assert_eq!(o.reexport_library_inputs, [0]);
        assert_eq!(o.weak_library_inputs, [1]);
    }

    #[test]
    fn m2_flags_shape_the_config() {
        let o = parse(&args(&[
            "-o",
            "out",
            "-l",
            "System",
            "-lfoo",
            "-L",
            "/opt/libs",
            "-rpath",
            "/opt/r",
            "-flat_namespace",
            "-undefined",
            "dynamic_lookup",
            "-u",
            "_force_me",
            "-weak_library",
            "/opt/weak.tbd",
            "-source_version",
            "1.2.3.4.5",
            "a.o",
        ]))
        .unwrap();
        assert_eq!(o.libs, ["System", "foo"]);
        assert_eq!(o.lib_dirs, ["/opt/libs"]);
        assert_eq!(o.config.rpaths, ["/opt/r"]);
        assert!(o.config.flat_namespace);
        assert_eq!(
            o.config.undefined_policy,
            pgr_core::resolve::UndefinedPolicy::DynamicLookup
        );
        assert_eq!(o.force_load, ["_force_me"]);
        assert_eq!(o.weak_library_inputs, [0]);
        assert_eq!(
            o.config.source_version,
            Some(1u64 << 40 | 2 << 30 | 3 << 20 | 4 << 10 | 5)
        );
    }

    #[test]
    fn m2_flag_values_are_validated() {
        assert!(parse(&args(&["-o", "out", "-undefined", "wat", "a.o"])).is_err());
        assert!(
            parse(&args(&[
                "-o",
                "out",
                "-source_version",
                "1.2.3.4.5.6",
                "a.o"
            ]))
            .is_err()
        );
        assert!(parse(&args(&["-o", "out", "-source_version", "1.2000.0", "a.o"])).is_err());
        assert!(parse(&args(&["-o", "out", "-twolevel_namespace", "a.o"])).is_ok());
    }

    #[test]
    fn bad_values_error() {
        assert!(parse(&args(&["-o"])).is_err());
        assert!(parse(&args(&["-o", "out", "-segalign", "0x2000", "a.o"])).is_err());
        assert!(
            parse(&args(&[
                "-o",
                "out",
                "-platform_version",
                "macos",
                "x",
                "1",
                "a.o"
            ]))
            .is_err()
        );
    }

    #[test]
    fn version_and_number_parsers() {
        assert_eq!(parse_version("12.0.0"), Some(0x000c_0000));
        assert_eq!(parse_version("14.4"), Some(0x000e_0400));
        assert_eq!(parse_version("15"), Some(0x000f_0000));
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_number("0x4000"), Some(0x4000));
        assert_eq!(parse_number("16384"), Some(16384));
        assert_eq!(parse_number("nope"), None);
    }

    // ---- M7: build-system integration surface ----------------------------

    fn write_rf(dir: &str, name: &str, body: &str) -> String {
        let p = std::env::temp_dir().join(dir).join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        p.display().to_string()
    }

    #[test]
    fn m7_response_file_expands_in_place() {
        let rf = write_rf(
            "pgr_opts_m7",
            "simple.rsp",
            "# one arg per line (CMake/Ninja shape)\n\nfirst.o\n\"quoted path.o\"\n-L rspdir\n",
        );
        let o = parse(&args(&["-o", "out", &format!("@{rf}"), "last.o"])).unwrap();
        assert_eq!(
            o.inputs,
            ["first.o", "quoted path.o", "last.o"],
            "expansion is positional"
        );
        assert_eq!(o.lib_dirs, ["rspdir"], "flags inside the file flow");
    }

    #[test]
    fn m7_response_file_quotes_and_escapes() {
        let rf = write_rf(
            "pgr_opts_m7",
            "quotes.rsp",
            "\"a b.o\" \"c\\\"d.o\" e\\ f.o f.o\n",
        );
        let o = parse(&args(&["-o", "out", &format!("@{rf}")])).unwrap();
        assert_eq!(o.inputs, ["a b.o", "c\"d.o", "e f.o", "f.o"]);
    }

    #[test]
    fn m7_response_files_nest_and_flags_flow() {
        let inner = write_rf("pgr_opts_m7", "inner.rsp", "-L innerdir\n-L second\n");
        let outer = write_rf("pgr_opts_m7", "outer.rsp", &format!("a.o @{}", inner));
        let o = parse(&args(&["-o", "out", &format!("@{outer}")])).unwrap();
        assert_eq!(o.inputs, ["a.o"]);
        assert_eq!(o.lib_dirs, ["innerdir", "second"]);
    }

    #[test]
    fn m7_response_file_missing_passes_through_ld64_style() {
        // ld64's rule: a token starting with `@` only expands when the file
        // exists — otherwise it is a literal (this is what keeps
        // `-install_name @rpath/libfoo.dylib` working).
        let o = parse(&args(&[
            "-dylib",
            "-o",
            "out",
            "-install_name",
            "@rpath/libfoo.dylib",
            "@/no/such/file.rsp",
        ]))
        .unwrap();
        assert_eq!(o.config.install_name, Some("@rpath/libfoo.dylib".into()));
        assert_eq!(o.inputs, ["@/no/such/file.rsp"], "literal passthrough");
    }

    #[test]
    fn m7_response_file_cycles_are_depth_bounded() {
        let base = std::env::temp_dir().join("pgr_opts_m7");
        std::fs::create_dir_all(&base).unwrap();
        let a = base.join("cycle_a.rsp").display().to_string();
        let b = base.join("cycle_b.rsp").display().to_string();
        std::fs::write(&a, format!("@{b}")).unwrap();
        std::fs::write(&b, format!("@{a}")).unwrap();
        let err = parse(&args(&["-o", "out", &format!("@{a}")])).unwrap_err();
        assert!(matches!(err, OptsError::ResponseFile { .. }), "got {err:?}");
    }

    #[test]
    fn m7_syslibroot_shapes_the_search_paths() {
        let o = parse(&args(&[
            "-o",
            "out",
            "-L",
            "lib",
            "-L",
            "other",
            "-syslibroot",
            "/sdk",
            "-F",
            "fws",
            "a.o",
        ]))
        .unwrap();
        assert_eq!(o.syslibroots, ["/sdk"]);
        // Single root: prefixed paths only (ld64 rule).
        assert_eq!(
            super::effective_lib_dirs(&o.lib_dirs, &o.syslibroots),
            ["/sdk/lib", "/sdk/other", "/sdk/usr/lib"]
        );
        assert_eq!(
            super::effective_framework_dirs(&o.framework_dirs, &o.syslibroots),
            [
                "/sdk/fws",
                "/sdk/System/Library/Frameworks",
                "/sdk/Library/Frameworks"
            ]
        );
        // No roots: the raw paths plus the defaults.
        let o2 = parse(&args(&["-o", "out", "-L", "lib", "a.o"])).unwrap();
        assert_eq!(
            super::effective_lib_dirs(&o2.lib_dirs, &o2.syslibroots),
            ["lib", "/usr/lib"]
        );
    }

    #[test]
    fn m7_multiple_syslibroots_search_the_union() {
        let o = parse(&args(&[
            "-o",
            "out",
            "-L",
            "lib",
            "-syslibroot",
            "/sdk1",
            "-syslibroot",
            "/sdk2",
            "a.o",
        ]))
        .unwrap();
        // ≥ 2 roots: every root-prefixed variant *plus* the original path.
        assert_eq!(
            super::effective_lib_dirs(&o.lib_dirs, &o.syslibroots),
            [
                "/sdk1/lib",
                "/sdk2/lib",
                "lib",
                "/sdk1/usr/lib",
                "/sdk2/usr/lib",
                "/usr/lib"
            ]
        );
    }

    #[test]
    fn m7_build_system_noop_flags_are_accepted() {
        // Flags Xcode/clang -fuse-ld/CMake pass that Peregrine honors by
        // doing exactly what it already does (no demangling, no dedup
        // toggles): accepted, no effect, value flags consume their value.
        let o = parse(&args(&[
            "-o",
            "out",
            "-demangle",
            "-no_deduplicate",
            "a.o",
            "-object_path_lto",
            "/tmp/lto.o",
            "b.o",
        ]))
        .unwrap();
        assert_eq!(o.inputs, ["a.o", "b.o"]);
        let o2 = parse(&args(&["-o", "out", "-no_demangle", "a.o"])).unwrap();
        assert_eq!(o2.inputs, ["a.o"]);
    }
}

//! ld64-compatible option surface (TDD §5 Pass 0; grown milestone by
//! milestone: M2 library search, M3 dylibs/bundles, M5 archives and
//! frameworks, M6 caches, M7 `-syslibroot`, M8 `-resident`, M9
//! `-incremental`, M10 `-r` relocatable output and the platform surface).
//! Flags real builds use that have not landed yet (the `MH_DYLINKER`
//! output kind, make-undefined, TLV, bitcode) are
//! rejected with actionable messages rather than silently ignored — a
//! linker that pretends to understand a flag it drops is worse than one
//! that says "not yet". `-order_file` landed at M11 (the rank-based
//! subset TDD §12 scoped from the start).

use pgr_core::fixups::FixupPointerFormat;
use pgr_core::layout::LinkConfig;
use pgr_format::consts::{
    PLATFORM_IOS, PLATFORM_MACOS, PLATFORM_TVOS, PLATFORM_VISIONOS, PLATFORM_WATCHOS,
};

/// Maps a `-platform_version` platform name onto its `LC_BUILD_VERSION`
/// constant (M10 rung 2). The five names are the platforms the pipeline
/// links; anything else refuses with the surface in the hint. The
/// encoding query (`fixup_encoding_report`, rung 3 slice 2) reads the
/// same table — one mapping, two surfaces, no re-derivation drift.
pub(crate) fn platform_const(name: &str) -> Option<u32> {
    match name {
        "macos" => Some(PLATFORM_MACOS),
        "ios" => Some(PLATFORM_IOS),
        "tvos" => Some(PLATFORM_TVOS),
        "watchos" => Some(PLATFORM_WATCHOS),
        "visionos" => Some(PLATFORM_VISIONOS),
        _ => None,
    }
}

/// Parsed driver options (the current milestone surface; M10 adds `-r`).
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
    /// Indices into `inputs` loaded lazily (`-lazy_library`, M14:
    /// `LC_LAZY_LOAD_DYLIB`).
    pub lazy_library_inputs: Vec<usize>,
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
    /// M14 `-weak_framework <name>` (repeatable): the framework dylib
    /// loads weakly (`LC_LOAD_WEAK_DYLIB`) and every bind to it is weak.
    pub weak_frameworks: Vec<String>,
    /// M14 `-lazy_framework <name>` (repeatable): the framework dylib
    /// loads as `LC_LAZY_LOAD_DYLIB` (dyld's delay-load surface).
    pub lazy_frameworks: Vec<String>,
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
    /// `$PGR_DAEMON_SOCK`, else `{tmpdir}/pgr-<uid|pid>.sock` — the
    /// `SUDO_UID` when the environment carries it, else the process id;
    /// `pgr_daemon::default_socket` is the derivation).
    pub resident_socket: Option<String>,
    /// M9 `-incremental` (architecture doc §7.3): the in-place incremental
    /// relink. Records the link state next to the output
    /// (`<output>.pgr-inc`) and, on the next link, patches only the changed
    /// 16 KiB tiles into a clone of the previous output. Any skeleton
    /// move, output change or record problem silently falls back to the
    /// full link (the fallback must always be available). Implies slack
    /// layout (`LinkConfig::layout_slack`) when the caller left it unset.
    pub incremental: bool,
    /// M9 `-incremental-verify`: after a successful patch, audit
    /// byte-identity against the full fused emit of the same plan (the
    /// daemon serves the audit on the resident path — wire v4;
    /// in-process otherwise), then a strict `pgr-verify` pass on the
    /// patched bytes (the §7.3 "no stale-signature or stale-fixup
    /// failures" gate). A divergence never ships: the output is
    /// rewritten from the full emit.
    pub incremental_verify: bool,
    /// M10 rung 4, slice 5: `-fixup_chains_format` was passed explicitly
    /// (either spelling). The default (`false`) keeps the documented
    /// below-floor fallback — the layout silently plans the classic
    /// opcode streams when no family was named — while an explicitly
    /// named family the floor cannot carry is a refused knob, never a
    /// silently dropped one (the surface's own contract).
    pub chain_word_format_explicit: bool,
    /// M11 `-order_file <path>`: the order file's path (read and ranked
    /// by the driver before Pass 3 — see [`pgr_core::order`]). `None`
    /// (the default) packs the layout exactly as before.
    pub order_file: Option<String>,
    /// M11 `-map <path>`: write the link map (the placed image's
    /// segments/sections/symbols, rendered by [`pgr_core::map`]) next to
    /// the link. `None` (the default) writes no map.
    pub map_path: Option<String>,
    /// M15: `-pagezero_size` was passed explicitly. The default (`false`)
    /// keeps the seam's own default on every non-executable output — the
    /// flag only applies to executables, and an explicitly named knob
    /// that cannot apply is a refused conflict, never a silently
    /// dropped one (the `-fixup_chains_format` surface convention).
    pub pagezero_explicit: bool,
    /// M16: `-init_offsets` / `-no_init_offsets` was passed explicitly.
    /// `Some(true)` is the named form — validated against the platform's
    /// chained-fixups floor in `finish` (it sees the whole surface: the
    /// `-platform_version` target may be parsed after this flag);
    /// `Some(false)` is always valid. The default (`None`) keeps the
    /// M1-locked classic pointer sections — every pre-M16 link stays
    /// byte-identical.
    pub init_offsets_flag: Option<bool>,
    /// M17: the `-segprot` decisions staged in command order. `finish`
    /// inserts them into the config (the core seam validates the value
    /// and refuses a second decision for one segment) after the
    /// relocatable conflict gate sees the whole surface — a `-segprot`
    /// on `-r` is a refused conflict, never a silently dropped flag.
    pub seg_prot_stage: Vec<(pgr_core::segprot::SegName, pgr_core::segprot::SegProt)>,
    /// M18: `-stack_size` was passed explicitly. The value is validated
    /// at parse time (the core seam pays the same validation); the
    /// output-kind conflict is `finish`'s (it sees the whole surface).
    /// The default (`false`) keeps the pre-M18 zero reserve — every
    /// pre-M18 link stays byte-identical.
    pub stack_size_explicit: bool,
    /// M19: `-image_base` was passed explicitly. The value is validated
    /// against the core seam's grammar at parse time; the output-kind
    /// conflict is `finish`'s (it sees the whole surface).
    pub image_base_explicit: bool,
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
            lazy_library_inputs: Vec::new(),
            reexport_library_inputs: Vec::new(),
            exported_list_path: None,
            unexported_list_path: None,
            all_load: false,
            force_load_archives: Vec::new(),
            filelists: Vec::new(),
            frameworks: Vec::new(),
            weak_frameworks: Vec::new(),
            lazy_frameworks: Vec::new(),
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
            chain_word_format_explicit: false,
            order_file: None,
            map_path: None,
            pagezero_explicit: false,
            init_offsets_flag: None,
            seg_prot_stage: Vec::new(),
            stack_size_explicit: false,
            image_base_explicit: false,
        }
    }
}

/// A command-line problem (exit code 2).
///
/// Refusals carry miette help text (the fix, not just the verdict) —
/// rendered by the `pgr` binary the way the audit refusal is (M10 rung
/// 2 wires the platform surface's help through the same derive).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
pub enum OptsError {
    /// A required flag or value is missing.
    #[error("missing value for {flag}")]
    MissingValue {
        /// The flag that wanted a value.
        flag: String,
    },
    /// The flag is not part of the linked surface.
    #[error("unsupported flag {flag} ({hint})")]
    #[diagnostic(help("{hint}"))]
    Unsupported {
        /// The offending flag.
        flag: String,
        /// What to do instead / when it lands.
        hint: String,
    },
    /// A flag value is malformed.
    #[error("invalid value for {flag}: {value}")]
    #[diagnostic(help(
        "versions are `X[.Y[.Z]]` decimal triples packed into the Mach-O build-version word"
    ))]
    InvalidValue {
        /// The flag.
        flag: String,
        /// The bad value.
        value: String,
    },
    /// An unknown `-fixup_chains_format` word family (M10 rung 4,
    /// slice 5): the flag's vocabulary is two names, and the help names
    /// them — the shared `InvalidValue` help text (the version-triple
    /// grammar) never fit this flag.
    #[error("invalid value for -fixup_chains_format: {value}")]
    #[diagnostic(help(
        "the chain word families are `offset64` (the M2 default) and `arm64e` (the rung-4 producer family)"
    ))]
    ChainFormatValue {
        /// The unknown family as written.
        value: String,
    },
    /// A `-pagezero_size` value the grammar refuses (M15): the size is
    /// a non-zero multiple of the 16 KiB arm64 page — the same
    /// validation the core seam pays — and the help names the grammar
    /// (the fix, not just the verdict).
    #[error("invalid value for -pagezero_size: {value}")]
    #[diagnostic(help(
        "the size is a non-zero multiple of the 16 KiB arm64 page (0x4000), decimal or 0x-hex — \
         e.g. 0x40000000; the default is 0x100000000"
    ))]
    PageZeroValue {
        /// The refused value as written.
        value: String,
    },
    /// A `-pagezero_size` surface conflict (M15): `__PAGEZERO` exists
    /// on executables only (the M3 contract: `__TEXT.vmaddr ==
    /// fileoff` for dylibs/bundles, no segments for `-r`). The verdict
    /// names the shape conflict; the help is the fix — the house
    /// convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    PageZeroConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// An `-init_offsets` surface refusal (M16): the named form cannot
    /// apply where it was requested — below the platform's
    /// chained-fixups floor (that dyld cannot consume
    /// `S_INIT_FUNC_OFFSETS` at all), or on the relocatable output (the
    /// M10 rung-1 contract preserves input sections verbatim — nothing
    /// for the transform to own). The verdict names the shape conflict;
    /// the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    InitOffsetsConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-segprot` value the grammar refuses (M17): the protections are
    /// subsets of `rwx` and the segment is one of the planned names —
    /// the same validation the core seam pays. The verdict is the core
    /// seam's refusal (it names the fix); the help restates the grammar.
    #[error("-segprot: {detail}")]
    #[diagnostic(help(
        "the protections are subsets of `rwx` (e.g. `rw` or `rx`); the segment is one of \
         __TEXT, __DATA_CONST, __DATA, __LINKEDIT"
    ))]
    SegProtValue {
        /// The core seam's refusal (grammar, unknown segment, kernel rule).
        detail: String,
    },
    /// A `-segprot` surface conflict (M17): the relocatable output
    /// carries no segments (the M10 rung-1 contract — nothing for a
    /// protection pair to land on), or one segment is named twice. The
    /// verdict names the shape conflict; the help is the fix — the house
    /// convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    SegProtConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-stack_size` value the grammar refuses (M18): the reserve is
    /// a non-zero multiple of the 16 KiB arm64 page — the same
    /// validation the core seam pays — and the help names the grammar
    /// (the fix, not just the verdict).
    #[error("invalid value for -stack_size: {value}")]
    #[diagnostic(help(
        "the stack size is a non-zero multiple of the 16 KiB arm64 page (0x4000), \
         decimal or 0x-hex — e.g. 0x1000000"
    ))]
    StackSizeValue {
        /// The refused value as written.
        value: String,
    },
    /// A `-stack_size` surface conflict (M18): `LC_MAIN` exists on
    /// executables only (the M3 contract: dylibs, bundles and the
    /// relocatable output carry none) — a named reserve has no field to
    /// land on. The verdict names the shape conflict; the help is the
    /// fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    StackSizeConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// An `-image_base` value the grammar refuses (M19): the base is
    /// a non-zero multiple of the 16 KiB arm64 page — the same
    /// validation the core seam pays — and the help names the grammar
    /// (the fix, not just the verdict).
    #[error("invalid value for -image_base: {value}")]
    #[diagnostic(help(
        "the image base is a non-zero multiple of the 16 KiB arm64 page (0x4000), \
         decimal or 0x-hex — e.g. 0x80000"
    ))]
    ImageBaseValue {
        /// The refused value as written.
        value: String,
    },
    /// An `-image_base` surface conflict (M19): the knob moves a dylib
    /// or bundle's preferred load address — an executable's base is
    /// `__PAGEZERO`'s job (M15 named `-pagezero_size` for it) and the
    /// relocatable output carries no segments. The verdict names the
    /// shape conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    ImageBaseConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-sub_umbrella`/`-sub_library` member the core seam refuses
    /// (M20): non-empty, NUL-free, named once. The seam's refusal rides
    /// the help — the grammar the flag accepts, not just the verdict.
    #[error("invalid value for -{kind}: {raw}")]
    #[diagnostic(help("{message}"))]
    UmbrellaValue {
        /// The flag's kind (`sub_umbrella`/`sub_library`).
        kind: String,
        /// The refused name as written.
        raw: String,
        /// The core seam's refusal (the fix).
        message: String,
    },
    /// A `-sub_umbrella`/`-sub_library` surface conflict (M20): the
    /// umbrella region is a dylib's identity block — an executable's
    /// identity is `LC_MAIN` + `LC_LOAD_DYLINKER`, a bundle dlopens
    /// without a region, and the relocatable output carries no identity
    /// commands at all. The verdict names the shape conflict; the help
    /// is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    UmbrellaConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// An argv element is not valid UTF-8 (the surface stores paths and
    /// values as `String`s — the Mach-O string tables are UTF-8 too).
    /// The message names what happened and which bytes; the old shape
    /// misreported it as an "invalid value for `<arg>`".
    #[error("argument is not valid UTF-8: {value}")]
    #[diagnostic(help(
        "paths and values are carried as UTF-8 (the Mach-O string tables are UTF-8); \
         rename the file or pass an escaped form"
    ))]
    NonUtf8Arg {
        /// The offending bytes, lossily rendered.
        value: String,
    },
    /// A `-fixup_chains_format` surface conflict (M10 rung 4): the
    /// requested chain word family cannot be encoded where it was
    /// requested. The verdict names the shape conflict; the help is the
    /// fix — the house convention (the fix, not just the verdict).
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    ChainFormatConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// An `-order_file` surface conflict (M11): the rank table cannot be
    /// applied (or carried) where it was requested. The verdict names the
    /// shape conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    OrderFileConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// `-platform_version`: the SDK is older than the deployment target
    /// (M10 rung 2). The SDK ships the deployment target's interfaces;
    /// building against an older one produces images dyld may refuse.
    #[error("-platform_version: SDK version {sdk} is older than the deployment target {minos}")]
    #[diagnostic(help(
        "bump the SDK or lower the deployment target — the SDK must be at least the deployment target"
    ))]
    VersionOrder {
        /// The deployment target as written.
        minos: String,
        /// The SDK as written.
        sdk: String,
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
/// M14 released the weak/lazy dylib family (`-weak_framework`,
/// `-lazy_framework`, `-lazy_library`), M15 released `-pagezero_size`
/// (the image-base seam) and M20 released the umbrella re-exports
/// (`-sub_umbrella`, `-sub_library`) — the `MH_DYLINKER` output kind,
/// make-undefined and `ObjC` semantics stay here with their roadmap entry.
const LATER_FLAGS: [(&str, &str); 3] = [
    ("-dylinker", "MH_DYLINKER outputs are a later milestone"),
    ("-U", "later milestone (make-undefined)"),
    (
        "-ObjC",
        "ObjC/Swift semantics beyond section pass-through are a later milestone",
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
        let arg = args[i].to_str().ok_or_else(|| OptsError::NonUtf8Arg {
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
    finish(&mut opts)
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
        let s = arg.to_str().ok_or_else(|| OptsError::NonUtf8Arg {
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
            // M10 rung 2: the five linked platforms, not macOS only.
            opts.config.platform =
                platform_const(&platform).ok_or_else(|| OptsError::Unsupported {
                    flag: arg.into(),
                    hint: format!(
                        "platform {platform:?} is not a linked platform (the surface links \
                     macos, ios, tvos, watchos and visionos)"
                    ),
                })?;
            opts.config.minos = parse_version(&minos).ok_or_else(|| OptsError::InvalidValue {
                flag: arg.into(),
                value: minos.clone(),
            })?;
            opts.config.sdk = parse_version(&sdk).ok_or_else(|| OptsError::InvalidValue {
                flag: arg.into(),
                value: sdk.clone(),
            })?;
            if opts.config.sdk < opts.config.minos {
                return Err(OptsError::VersionOrder { minos, sdk });
            }
            // The flag→config seam, spanned like the pipeline seams (inert
            // until a subscriber installs).
            tracing::debug!(
                platform = %platform,
                minos = %minos,
                sdk = %sdk,
                "the -platform_version seam shaped the config"
            );
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
        "-fixup_chains_format" => {
            // M10 rung 4, slice 2: the chain word family. ld64 separates
            // flag and value; the attached form is matched below (the
            // `-icf=` convention).
            let v = next_value(args, i, arg)?;
            opts.config.chain_word_format =
                parse_chain_format(&v).ok_or_else(|| OptsError::ChainFormatValue {
                    value: format!("{v} (offset64 | arm64e)"),
                })?;
            // The flag was named explicitly: the floor gate (slice 5)
            // reads this, the default stays the silent fallback.
            opts.chain_word_format_explicit = true;
            // The flag→config seam, spanned like the pipeline seams (inert
            // until a subscriber installs).
            tracing::debug!(
                format = %v,
                "the -fixup_chains_format seam shaped the config"
            );
        }
        a if a.starts_with("-fixup_chains_format=") => {
            let v = &a[21..];
            opts.config.chain_word_format =
                parse_chain_format(v).ok_or_else(|| OptsError::ChainFormatValue {
                    value: format!("{v} (offset64 | arm64e)"),
                })?;
            opts.chain_word_format_explicit = true;
        }
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
        "-lazy_library" => {
            // M14: the whole dylib delays (LC_LAZY_LOAD_DYLIB) — dyld
            // loads it when a bind from it first resolves; under chained
            // fixups the command rides the two-level ordinal space like
            // a plain load.
            let v = next_value(args, i, arg)?;
            opts.inputs.push(v);
            opts.lazy_library_inputs.push(opts.inputs.len() - 1);
        }
        "-weak_framework" => {
            // M14: the framework dylib loads weakly (the -framework
            // search with the weak-load kind).
            let v = next_value(args, i, arg)?;
            opts.weak_frameworks.push(v);
        }
        "-lazy_framework" => {
            // M14: the framework dylib delays (LC_LAZY_LOAD_DYLIB).
            let v = next_value(args, i, arg)?;
            opts.lazy_frameworks.push(v);
        }
        "-dylib" => match opts.config.filetype {
            // A repeated kind is idempotent; only a kind *switch* is a
            // conflict (a duplicate used to be reported as the mutual-
            // exclusion error — a diagnosis about a conflict that never
            // happened).
            pgr_core::layout::OutputType::Dylib => {}
            pgr_core::layout::OutputType::Execute => {
                opts.config.filetype = pgr_core::layout::OutputType::Dylib;
            }
            pgr_core::layout::OutputType::Relocatable => {
                return Err(OptsError::Repeated {
                    message: "-dylib and -r are mutually exclusive".into(),
                });
            }
            pgr_core::layout::OutputType::Bundle => {
                return Err(OptsError::Repeated {
                    message: "-dylib and -bundle are mutually exclusive".into(),
                });
            }
        },
        "-bundle" => match opts.config.filetype {
            pgr_core::layout::OutputType::Bundle => {}
            pgr_core::layout::OutputType::Execute => {
                opts.config.filetype = pgr_core::layout::OutputType::Bundle;
            }
            pgr_core::layout::OutputType::Relocatable => {
                return Err(OptsError::Repeated {
                    message: "-bundle and -r are mutually exclusive".into(),
                });
            }
            pgr_core::layout::OutputType::Dylib => {
                return Err(OptsError::Repeated {
                    message: "-dylib and -bundle are mutually exclusive".into(),
                });
            }
        },
        // M10 rung 1: `-r` relocatable output — an MH_OBJECT the next
        // link consumes as an input. The conflicting knobs (dead-strip,
        // ICF, the incremental record, the resident daemon) are refused
        // in `finish`, whatever order the flags arrived in.
        "-r" => match opts.config.filetype {
            pgr_core::layout::OutputType::Relocatable => {}
            pgr_core::layout::OutputType::Execute => {
                opts.config.filetype = pgr_core::layout::OutputType::Relocatable;
            }
            pgr_core::layout::OutputType::Dylib => {
                return Err(OptsError::Repeated {
                    message: "-r and -dylib are mutually exclusive".into(),
                });
            }
            pgr_core::layout::OutputType::Bundle => {
                return Err(OptsError::Repeated {
                    message: "-r and -bundle are mutually exclusive".into(),
                });
            }
        },
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
        // M11: the order file is read (and its parse refusals named) by
        // the driver before Pass 3; the surface stores the path.
        "-order_file" => {
            let v = next_value(args, i, arg)?;
            opts.order_file = Some(v);
        }
        // M11: the link map is rendered from the finished plan (the same
        // layout the fused emit writes) and written after the link.
        "-map" => {
            let v = next_value(args, i, arg)?;
            opts.map_path = Some(v);
        }
        // M15: the image base (the `__PAGEZERO` vmsize an executable
        // plans with). The same validation the core seam pays runs here,
        // so the refusal names the grammar; the output-kind conflict is
        // `finish`'s (it sees the whole surface).
        "-pagezero_size" => {
            let v = next_value(args, i, arg)?;
            let n =
                parse_number(&v).ok_or_else(|| OptsError::PageZeroValue { value: v.clone() })?;
            opts.config.pagezero = pgr_core::PageZero::from_override(n)
                .map_err(|_| OptsError::PageZeroValue { value: v.clone() })?;
            opts.pagezero_explicit = true;
        }
        // M16: the initializer form (the flag pair names it exactly like
        // the chain word family names its encoding). The same validation
        // the core seam pays runs in `finish` — it sees the whole
        // surface, so the `-platform_version` target may be parsed
        // after this flag.
        "-init_offsets" => {
            opts.init_offsets_flag = Some(true);
        }
        "-no_init_offsets" => {
            opts.init_offsets_flag = Some(false);
        }
        // M17: the segment protections (`-segprot <seg> <max> <init>` —
        // ld64's grammar). The same validation the core seam pays runs
        // here (the refusal names the grammar); the surface conflicts
        // (the relocatable output, a twice-named segment) are
        // `finish`'s — it sees the whole surface.
        "-segprot" => {
            let seg_raw = next_value(args, i, arg)?;
            let max_raw = next_value(args, i, arg)?;
            let init_raw = next_value(args, i, arg)?;
            let seg = pgr_core::segprot::SegName::parse(&seg_raw).map_err(|e| {
                OptsError::SegProtValue {
                    detail: e.to_string(),
                }
            })?;
            let prot = pgr_core::segprot::SegProt::parse(&max_raw, &init_raw).map_err(|e| {
                OptsError::SegProtValue {
                    detail: e.to_string(),
                }
            })?;
            opts.seg_prot_stage.push((seg, prot));
        }
        // M18: the stack reserve (the executable's `LC_MAIN.stacksize`).
        // The same validation the core seam pays runs here, so the
        // refusal names the grammar; the output-kind conflict is
        // `finish`'s (it sees the whole surface).
        "-stack_size" => {
            let v = next_value(args, i, arg)?;
            let n =
                parse_number(&v).ok_or_else(|| OptsError::StackSizeValue { value: v.clone() })?;
            opts.config.stack_size = Some(
                pgr_core::StackSize::from_override(n)
                    .map_err(|_| OptsError::StackSizeValue { value: v.clone() })?,
            );
            opts.stack_size_explicit = true;
        }
        // M19: the dylib/bundle preferred load address. The same
        // validation the core seam pays runs here, so the refusal names
        // the grammar; the output-kind conflict is `finish`'s (it sees
        // the whole surface).
        "-image_base" => {
            let v = next_value(args, i, arg)?;
            let n =
                parse_number(&v).ok_or_else(|| OptsError::ImageBaseValue { value: v.clone() })?;
            opts.config.image_base = Some(
                pgr_core::ImageBase::from_override(n)
                    .map_err(|_| OptsError::ImageBaseValue { value: v.clone() })?,
            );
            opts.image_base_explicit = true;
        }
        // M20: the umbrella region's members. The same validation the
        // core seam pays runs here, so the refusal names the grammar;
        // the output-kind conflict is `finish`'s (it sees the whole
        // surface).
        "-sub_umbrella" | "-sub_library" => {
            let v = next_value(args, i, arg)?;
            let kind = if arg == "-sub_umbrella" {
                pgr_core::umbrella::UmbrellaKind::SubUmbrella
            } else {
                pgr_core::umbrella::UmbrellaKind::SubLibrary
            };
            let member = pgr_core::UmbrellaMember::from_flag(kind, &v).map_err(|e| {
                OptsError::UmbrellaValue {
                    kind: arg.trim_start_matches('-').to_string(),
                    raw: v.clone(),
                    message: e.to_string(),
                }
            })?;
            opts.config
                .umbrella
                .push(member)
                .map_err(|e| OptsError::UmbrellaValue {
                    kind: arg.trim_start_matches('-').to_string(),
                    raw: v.clone(),
                    message: e.to_string(),
                })?;
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
                hint: "unknown flag (see --help for the linked surface)".into(),
            });
        }
    }
    Ok(())
}

/// Post-conditions: an output path, at least one input, and the M3 flag
/// combinations consistent with the output kind.
fn finish(opts: &mut Options) -> Result<Options, OptsError> {
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
    // M10 rung 4, slice 2: the requested word family must be encodable
    // where it is requested — a refusal, never a silently dropped knob.
    if opts.config.chain_word_format == FixupPointerFormat::Arm64e {
        if !opts.config.fixup_chains {
            return Err(OptsError::ChainFormatConflict {
                verdict: "the classic opcode streams have no chain words to shape".into(),
                fix: "drop -fixup_chains_format or re-enable chained fixups".into(),
            });
        }
        if opts.resident {
            return Err(OptsError::ChainFormatConflict {
                verdict: "the resident session's reuse gates plan Offset64 shapes this slice \
                          (the v6 wire mirrors the family, the gates do not consume it yet)"
                    .into(),
                fix: "drop -resident or -fixup_chains_format".into(),
            });
        }
    }
    // M16: the initializer form. The named form validates against the
    // platform's chained-fixups floor (the one table
    // `pgr_format::consts::chained_fixups_floor` gates every reader);
    // below it the target's dyld cannot consume `S_INIT_FUNC_OFFSETS`
    // at all — a refusal, never a silently dropped knob. The
    // relocatable conflict is the filetype match's (it sees the whole
    // surface, like the pagezero one).
    if let Some(forced) = opts.init_offsets_flag {
        opts.config.init_offsets =
            pgr_core::InitOffsets::from_flag(Some(forced), opts.config.platform, opts.config.minos)
                .map_err(|_| OptsError::InitOffsetsConflict {
                    verdict: format!(
                        "-init_offsets needs a target at or above the platform's \
                         chained-fixups floor {} (the target's dyld cannot consume \
                         __init_offsets)",
                        crate::fmt_version_word(pgr_format::consts::chained_fixups_floor(
                            opts.config.platform,
                        ))
                    ),
                    fix: "raise the -platform_version deployment target or use \
                          -no_init_offsets"
                        .into(),
                })?;
    }
    // M15: the image base is an executable decision — `__PAGEZERO`
    // exists on executables only (the M3 contract: `__TEXT.vmaddr ==
    // fileoff` for dylibs/bundles, no segments for `-r`). An explicitly
    // named knob that cannot apply is a refusal, never a silently
    // dropped one.
    if opts.pagezero_explicit && opts.config.filetype != pgr_core::layout::OutputType::Execute {
        return Err(OptsError::PageZeroConflict {
            verdict: format!(
                "-pagezero_size names an image base, but the {} output carries no __PAGEZERO",
                match opts.config.filetype {
                    pgr_core::layout::OutputType::Dylib => "-dylib",
                    pgr_core::layout::OutputType::Bundle => "-bundle",
                    pgr_core::layout::OutputType::Relocatable => "-r",
                    pgr_core::layout::OutputType::Execute => unreachable!("guarded above"),
                }
            ),
            fix: "drop -pagezero_size or link an executable (the default output)".into(),
        });
    }
    // M17: the segment protections are a segmented-output decision —
    // `-r` preserves input sections verbatim and plans no segments (the
    // M10 rung-1 contract), so a named pair has nothing to land on. An
    // explicitly named knob that cannot apply is a refusal, never a
    // silently dropped one; the staged decisions then insert into the
    // config, where the core seam refuses a twice-named segment.
    if !opts.seg_prot_stage.is_empty()
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::SegProtConflict {
            verdict: "-segprot names a segment protection, but the relocatable output \
                      carries no segments"
                .into(),
            fix: "drop -segprot or link a segmented output (an executable, dylib or \
                  bundle)"
                .into(),
        });
    }
    for (seg, prot) in opts.seg_prot_stage.drain(..) {
        if let Err(err) = opts.config.seg_prots.insert(seg, prot) {
            return Err(OptsError::SegProtConflict {
                verdict: err.to_string(),
                fix: "one -segprot per segment".into(),
            });
        }
    }
    // M18: the stack reserve is an executable decision — `LC_MAIN`
    // exists there only (the M3 contract: dylibs, bundles and the
    // relocatable output carry none), so a named reserve has nothing to
    // land on. An explicitly named knob that cannot apply is a refusal,
    // never a silently dropped one.
    if opts.stack_size_explicit && opts.config.filetype != pgr_core::layout::OutputType::Execute {
        return Err(OptsError::StackSizeConflict {
            verdict: "-stack_size reserves the LC_MAIN stack, but this output carries no \
                      LC_MAIN"
                .into(),
            fix: "drop -stack_size or link an executable (the default output)".into(),
        });
    }
    // M19: the image base is a dylib/bundle decision — an executable's
    // constant-delta base is `__PAGEZERO`'s job (M15 named
    // `-pagezero_size` for it) and the relocatable output carries no
    // segments at all. An explicitly named knob that cannot apply is a
    // refusal, never a silently dropped one.
    if opts.image_base_explicit {
        use pgr_core::layout::OutputType as Ot;
        match opts.config.filetype {
            Ot::Execute => {
                return Err(OptsError::ImageBaseConflict {
                    verdict: "-image_base moves a dylib or bundle's preferred load \
                              address, but this output is an executable"
                        .into(),
                    fix: "the executable's base is __PAGEZERO's job: name it with \
                          -pagezero_size (M15) or drop -image_base"
                        .into(),
                });
            }
            Ot::Relocatable => {
                return Err(OptsError::ImageBaseConflict {
                    verdict: "-image_base moves a mapped image's preferred load \
                              address, but the relocatable output carries no segments"
                        .into(),
                    fix: "drop -image_base or link a dylib/bundle".into(),
                });
            }
            Ot::Dylib | Ot::Bundle => {}
        }
    }
    // M20: the umbrella region is a dylib's identity block — the same
    // refusal shape as the M19 base above: an explicitly named knob
    // that cannot apply is a refusal, never a silently dropped one.
    if !opts.config.umbrella.is_empty() {
        use pgr_core::layout::OutputType as Ot;
        match opts.config.filetype {
            Ot::Execute => {
                return Err(OptsError::UmbrellaConflict {
                    verdict: "-sub_umbrella/-sub_library name an umbrella dylib's region, \
                              but this output is an executable"
                        .into(),
                    fix: "the region rides LC_ID_DYLIB's identity block: link a dylib \
                          (-dylib) or drop the flags"
                        .into(),
                });
            }
            Ot::Bundle => {
                return Err(OptsError::UmbrellaConflict {
                    verdict: "-sub_umbrella/-sub_library name an umbrella dylib's region, \
                              but this output is a bundle"
                        .into(),
                    fix: "bundles dlopen without an umbrella region: link a dylib \
                          (-dylib) or drop the flags"
                        .into(),
                });
            }
            Ot::Relocatable => {
                return Err(OptsError::UmbrellaConflict {
                    verdict: "-sub_umbrella/-sub_library name an umbrella dylib's region, \
                              but the relocatable output carries no identity commands"
                        .into(),
                    fix: "drop the flags or link a dylib (-dylib)".into(),
                });
            }
            Ot::Dylib => {}
        }
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
        pgr_core::layout::OutputType::Relocatable => {
            // The object path keeps every section and relocation verbatim:
            // the size/codegen knobs and the M8/M9 session machinery have
            // nothing to attach to (no image, no record, no daemon shape).
            if opts.config.dead_strip {
                return Err(OptsError::InvalidValue {
                    flag: "-dead_strip".into(),
                    value: "-r keeps every section (the next link strips); drop -dead_strip".into(),
                });
            }
            if opts.config.icf != pgr_core::icf::IcfMode::None {
                return Err(OptsError::InvalidValue {
                    flag: "-icf".into(),
                    value: "-r preserves relocations verbatim; drop -icf".into(),
                });
            }
            if opts.config.chain_word_format == FixupPointerFormat::Arm64e {
                return Err(OptsError::ChainFormatConflict {
                    verdict: "-r writes an input object: no fixups exist to shape".into(),
                    fix: "drop -fixup_chains_format".into(),
                });
            }
            if opts.init_offsets_flag == Some(true) {
                return Err(OptsError::InitOffsetsConflict {
                    verdict: "-init_offsets transforms initializer pointers into \
                              __init_offsets entries, but the -r output preserves input \
                              sections verbatim (nothing for the transform to own)"
                        .into(),
                    fix: "drop -init_offsets or link a final image".into(),
                });
            }
            if opts.incremental {
                return Err(OptsError::InvalidValue {
                    flag: "-incremental".into(),
                    value: "-r writes an input object, not an image: no link record exists; drop -incremental".into(),
                });
            }
            if opts.resident {
                return Err(OptsError::InvalidValue {
                    flag: "-resident".into(),
                    value: "-r has no resident shape; drop -resident".into(),
                });
            }
        }
    }
    // M10 rung 4, slice 5: an *explicitly named* chain word family must
    // survive the deployment floor. Below it the layout plans the classic
    // opcode streams (TDD §3.6 invariant 3 — the encoding flips, the
    // fixups do not; the floor is the documented fallback) — and a named
    // family no image will ever carry is a silently dropped knob, which
    // this surface refuses to do. The unnamed default keeps the silent
    // fallback. The decision reads the same consumer seam the encoding
    // query answers from (one table, three readers — never a
    // re-derivation); after the output-kind match so `-r` keeps its
    // tighter refusal wording.
    if opts.chain_word_format_explicit && opts.config.fixup_chains {
        let encoding =
            pgr_core::platform::FixupEncoding::for_target(opts.config.platform, opts.config.minos);
        if encoding == pgr_core::platform::FixupEncoding::ClassicOpcodes {
            let floor = pgr_core::platform::FixupEncoding::floor_for(opts.config.platform);
            let floor_text = crate::fmt_version_word(floor);
            let minos_text = crate::fmt_version_word(opts.config.minos);
            tracing::debug!(
                format = chain_format_text(opts.config.chain_word_format),
                platform = platform_display(opts.config.platform),
                minos = %minos_text,
                floor = %floor_text,
                "the -fixup_chains_format floor gate refused the explicit family"
            );
            return Err(OptsError::ChainFormatConflict {
                verdict: format!(
                    "explicit -fixup_chains_format {} rides chained fixups, and {} {} sits \
                     below the {} chained-fixups floor: the link plans the classic opcode \
                     streams and the named family never reaches the image",
                    chain_format_text(opts.config.chain_word_format),
                    platform_display(opts.config.platform),
                    minos_text,
                    floor_text,
                ),
                fix: format!(
                    "raise the deployment target above {floor_text} or drop \
                     -fixup_chains_format — the encoding flips, the fixups do not"
                ),
            });
        }
    }
    // M11: the map reports the placed image — the surfaces that do not
    // produce one (an input object, the patch tiers' in-place plan, the
    // daemon's wire) refuse the knob instead of dropping it.
    if opts.map_path.is_some() {
        if opts.config.filetype == pgr_core::layout::OutputType::Relocatable {
            return Err(OptsError::OrderFileConflict {
                verdict: "-r writes an input object: no segment layout exists for the map to \
                         report"
                    .into(),
                fix: "drop -map".into(),
            });
        }
        if opts.incremental {
            return Err(OptsError::OrderFileConflict {
                verdict: "-incremental's patch tiers plan inside the relink engine; the map \
                          reports the full emit's layout"
                    .into(),
                fix: "drop -map or -incremental".into(),
            });
        }
        if opts.resident {
            return Err(OptsError::OrderFileConflict {
                verdict: "the resident session links across the v6 wire and never returns the \
                          layout the map reports"
                    .into(),
                fix: "drop -map or -resident".into(),
            });
        }
    }
    // M11: the order file must be appliable where it was requested — a
    // refusal, never a silently dropped knob (the surface's contract).
    if opts.order_file.is_some() {
        if opts.config.filetype == pgr_core::layout::OutputType::Relocatable {
            return Err(OptsError::OrderFileConflict {
                verdict: "-r writes an input object: sections merge at their declared \
                         alignments and no segment layout exists to rank"
                    .into(),
                fix: "drop -order_file".into(),
            });
        }
        if opts.resident {
            return Err(OptsError::OrderFileConflict {
                verdict: "the resident session's reuse gates replay the v6 wire config, \
                          which does not carry the order-file rank table"
                    .into(),
                fix: "drop -resident or -order_file".into(),
            });
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

/// Parses the `-fixup_chains_format` chain word family (M10 rung 4,
/// slice 2): `offset64` is the M2 default, `arm64e` the rung-4 producer
/// family. The encoding query (`fixup_encoding_report`) answers the
/// *chained-vs-classic* half of the same decision — one flag each, no
/// re-derivation drift.
#[must_use]
pub fn parse_chain_format(v: &str) -> Option<FixupPointerFormat> {
    match v {
        "offset64" => Some(FixupPointerFormat::Offset64),
        "arm64e" => Some(FixupPointerFormat::Arm64e),
        _ => None,
    }
}

/// The `-fixup_chains_format` vocabulary a config rides (the flag's own
/// names, for refusal messages — M10 rung 4, slice 5).
#[must_use]
pub fn chain_format_text(format: FixupPointerFormat) -> &'static str {
    match format {
        FixupPointerFormat::Offset64 => "offset64",
        FixupPointerFormat::Arm64e => "arm64e",
    }
}

/// The `-platform_version` name a platform constant rides (the inverse
/// of `platform_const`, for refusal messages). A constant outside the
/// five linked platforms displays numerically — only a caller-built
/// `pgr_core::layout::LinkConfig` can produce one (the CLI refuses it at
/// parse time).
#[must_use]
pub fn platform_display(platform: u32) -> String {
    match platform {
        PLATFORM_MACOS => "macos".into(),
        PLATFORM_IOS => "ios".into(),
        PLATFORM_TVOS => "tvos".into(),
        PLATFORM_WATCHOS => "watchos".into(),
        PLATFORM_VISIONOS => "visionos".into(),
        other => format!("platform {other}"),
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
    fn platform_flags_shape_the_config_m10() {
        let cases = [
            ("macos", pgr_format::consts::PLATFORM_MACOS),
            ("ios", pgr_format::consts::PLATFORM_IOS),
            ("tvos", pgr_format::consts::PLATFORM_TVOS),
            ("watchos", pgr_format::consts::PLATFORM_WATCHOS),
            ("visionos", pgr_format::consts::PLATFORM_VISIONOS),
        ];
        for (name, platform) in cases {
            let o = parse(&args(&[
                "-o",
                "out",
                "-platform_version",
                name,
                "1.0",
                "1.0",
                "a.o",
            ]))
            .unwrap_or_else(|e| panic!("{name} must parse: {e}"));
            assert_eq!(o.config.platform, platform, "{name} must shape the config");
        }
    }

    #[test]
    fn an_unknown_platform_refuses_with_the_surface_in_the_hint() {
        let err = parse(&args(&[
            "-o",
            "out",
            "-platform_version",
            "linux",
            "1.0",
            "1.0",
            "a.o",
        ]))
        .unwrap_err();
        let msg = err.to_string();
        for name in ["macos", "ios", "tvos", "watchos", "visionos"] {
            assert!(msg.contains(name), "the refusal must name {name}: {msg}");
        }
    }

    #[test]
    fn an_sdk_older_than_the_deployment_target_refuses() {
        let err = parse(&args(&[
            "-o",
            "out",
            "-platform_version",
            "macos",
            "14.0",
            "12.0",
            "a.o",
        ]))
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SDK") && msg.contains("14.0") && msg.contains("12.0"),
            "the refusal must name both versions: {msg}"
        );
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
        // M11: `-order_file` left the later-milestone list — the rank
        // table rides the link (the acceptance is gated in
        // tests/m11_order_file.rs); the surface stores its path.
        let o = parse(&args(&["-o", "out", "-order_file", "f.txt", "a.o"])).unwrap();
        assert_eq!(o.order_file.as_deref(), Some("f.txt"));
        // M14: the weak/lazy dylib family left the list too (the
        // acceptance is gated in tests/m14_lazy_dylibs.rs) — the
        // umbrella/ObjC refusals remain the actionable surface.
        let err = parse(&args(&["-o", "out", "-sub_umbrella", "Foo", "a.o"])).unwrap_err();
        assert!(err.to_string().contains("umbrella"), "{err}");
        let err = parse(&args(&["-o", "out", "-ObjC", "a.o"])).unwrap_err();
        assert!(err.to_string().contains("ObjC"), "{err}");
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
    fn m14_lazy_weak_flags_shape_the_config() {
        // M14: the released weak/lazy family parses repeatable; the
        // path forms record their input indices for the driver's
        // per-input kind marking.
        let o = parse(&args(&[
            "-o",
            "hello",
            "a.o",
            "-lazy_library",
            "libgreet.tbd",
            "-weak_library",
            "libweak.tbd",
            "-weak_framework",
            "Foundation",
            "-weak_framework",
            "CoreFoundation",
            "-lazy_framework",
            "SwiftUI",
            "b.o",
        ]))
        .unwrap();
        // lazy_library/weak_library push the path as an input and
        // record its index.
        assert_eq!(o.inputs[1], "libgreet.tbd");
        assert_eq!(o.inputs[2], "libweak.tbd");
        assert_eq!(o.lazy_library_inputs, [1]);
        assert_eq!(o.weak_library_inputs, [2]);
        assert_eq!(o.weak_frameworks, ["Foundation", "CoreFoundation"]);
        assert_eq!(o.lazy_frameworks, ["SwiftUI"]);
        assert_eq!(o.inputs.len(), 4, "a.o, the two libraries, b.o");
    }

    #[test]
    fn m15_pagezero_flag_shapes_the_config() {
        // M15: the image base parses (decimal and 0x-hex) into the
        // validated seam value; the executable default is untouched.
        let o = parse(&args(&[
            "-o",
            "hello",
            "-pagezero_size",
            "0x40000000",
            "a.o",
        ]))
        .unwrap();
        assert_eq!(o.config.pagezero.vmsize(), 0x4000_0000);
        assert!(o.pagezero_explicit);
        let o = parse(&args(&[
            "-o",
            "hello",
            "-pagezero_size",
            "1073741824",
            "a.o",
        ]))
        .unwrap();
        assert_eq!(o.config.pagezero.vmsize(), 0x4000_0000);
        // The default spelling (the 4 GiB constant) parses too.
        let o = parse(&args(&[
            "-o",
            "hello",
            "-pagezero_size",
            "0x100000000",
            "a.o",
        ]))
        .unwrap();
        assert_eq!(o.config.pagezero.vmsize(), 0x1_0000_0000);
        // No flag: the seam default rides, nothing is explicit.
        let o = parse(&args(&["-o", "hello", "a.o"])).unwrap();
        assert_eq!(o.config.pagezero.vmsize(), 0x1_0000_0000);
        assert!(!o.pagezero_explicit);
    }

    #[test]
    fn m15_pagezero_refusals_name_the_grammar() {
        // Zero, misaligned and non-numeric values refuse with the
        // grammar in the help; the core seam's validation is the same
        // one the wire pays.
        for raw in ["0", "0x3000", "0x4001", "abc"] {
            let err = parse(&args(&["-o", "hello", "-pagezero_size", raw, "a.o"])).unwrap_err();
            assert!(
                matches!(err, OptsError::PageZeroValue { .. }),
                "{raw}: {err:?}"
            );
        }
        // The knob is executable-only: dylib and -r outputs refuse with
        // the conflict shape (a refusal, never a silently dropped flag).
        for kind_flag in [["-dylib"], ["-r"]] {
            let mut argv = vec!["-o", "x"];
            argv.extend_from_slice(&kind_flag);
            argv.extend_from_slice(&["-pagezero_size", "0x40000000", "a.o"]);
            let err = parse(&args(&argv)).unwrap_err();
            assert!(
                matches!(err, OptsError::PageZeroConflict { .. }),
                "{kind_flag:?}: {err:?}"
            );
        }
    }

    #[test]
    fn non_utf8_arguments_are_a_named_error() {
        // The weak "invalid value for <arg>" shape became a named
        // refusal: the message says what happened (not valid UTF-8) and
        // the help names the constraint.
        let raw =
            <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(vec![0xFF, 0xFE]);
        let err = parse(&[
            std::ffi::OsString::from("-o"),
            std::ffi::OsString::from("out"),
            raw,
        ])
        .unwrap_err();
        assert!(matches!(err, OptsError::NonUtf8Arg { .. }), "{err:?}");
        assert!(err.to_string().contains("not valid UTF-8"), "{err}");
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
        let outer = write_rf("pgr_opts_m7", "outer.rsp", &format!("a.o @{inner}"));
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

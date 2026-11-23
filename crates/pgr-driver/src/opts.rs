//! ld64-compatible option surface (TDD §5 Pass 0; grown milestone by
//! milestone: M2 library search, M3 dylibs/bundles, M5 archives and
//! frameworks, M6 caches, M7 `-syslibroot`, M8 `-resident`, M9
//! `-incremental`, M10 `-r` relocatable output and the platform surface).
//! Flags real builds use that have not landed yet (the `MH_DYLINKER`
//! output kind, make-undefined, bitcode) are
//! rejected with actionable messages rather than silently ignored — a
//! linker that pretends to understand a flag it drops is worse than one
//! that says "not yet". TLV thread-locals link since M37 (the input
//! sections the parse validates ride the atom map onto the output).
//! `-order_file` landed at M11 and `-sectorder` rides the same rank
//! seam since M90 (the rank-based subset TDD §12 scoped from the start;
//! the sources compose in command-line order).

use pgr_core::fixups::FixupPointerFormat;
use pgr_core::layout::{LinkConfig, UuidSource};
use pgr_format::consts::{
    PLATFORM_IOS, PLATFORM_MACOS, PLATFORM_TVOS, PLATFORM_VISIONOS, PLATFORM_WATCHOS,
};

/// One order-bearing flag instance, in command-line order (M90): ld64's
/// order files append into ONE global rank table as the flags parse —
/// the driver composes the sources in the order the flags appear, never
/// last-wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderSpec {
    /// `-order_file <path>` (M11): the global rank file.
    File {
        /// The file's path (read and parsed at link time — the M11
        /// convention; the read rides the M60 dependency record).
        path: String,
    },
    /// `-sectorder <segment> <section> <path>` (M90): ld64's
    /// per-section order flag. The pair names the face, never a layout
    /// scope ([`pgr_core::order::classify_section_order`]): an ordinary
    /// section's file appends its entries to the one rank table, the
    /// `__TEXT,__cstring` face orders the section's literals by
    /// escape-decoded content (M91's rung), and a `__TEXT,__literal*`
    /// section is the warned no-op whose file is never read.
    Section {
        /// The named segment (`__TEXT` carries the special faces).
        segment: String,
        /// The named section.
        section: String,
        /// The file's path (read at link time, when the face reads).
        path: String,
    },
}

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

/// One export-filter source, in command-line order (M100): the
/// singular flags carry their validated entry (the same pattern grammar
/// the list files widened to — an exact name, or a `*` glob), the list
/// files carry their path (read and parsed at link time, the M3/M14
/// convention, the read riding the M60 dependency record). The list
/// files keep their once-per-kind contract (the M3 surface pinned it;
/// the singular flags are the repeatable face).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportFilterSpec {
    /// `-exported_symbol <name>`: one exported-only entry.
    Exported {
        /// The validated pattern (exact or `*` glob).
        pattern: pgr_core::SymbolPattern,
    },
    /// `-unexported_symbol <name>`: one hide-and-mark-`N_PEXT` entry.
    Unexported {
        /// The validated pattern (exact or `*` glob).
        pattern: pgr_core::SymbolPattern,
    },
    /// `-exported_symbols_list <path>`: the file's lines join the
    /// only-list (once per kind).
    ExportedList {
        /// The file's path (read at link time).
        path: String,
    },
    /// `-unexported_symbols_list <path>`: the file's lines join the
    /// hide-list (once per kind).
    UnexportedList {
        /// The file's path (read at link time).
        path: String,
    },
}

/// One alias source, in command-line order (M101): the `-alias` flag
/// carries its validated pair (the M24 grammar, paid at the parse), the
/// `-alias_list` file carries its path (read and validated at link time,
/// the M11/M14 list-file convention — the read rides the M60 dependency
/// record). Every source composes into the ONE alias table in flag
/// order, the M90 pattern, and the composed table feeds the unchanged
/// [`pgr_core::alias`] seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasSource {
    /// `-alias <alias_name> <definition_name>`: one validated pair.
    Pair {
        /// The validated pair (the M24 seam's own type).
        alias: pgr_core::Alias,
    },
    /// `-alias_list <path>`: the file's pairs join the table (the file
    /// form of M24's `-alias`).
    ListFile {
        /// The file's path (read at link time).
        path: String,
    },
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
    /// `-bundle_loader <path>` (M25): the host executable a bundle
    /// binds its undefined references against. The path is scanned at
    /// link time (Pass 0 reads the host's export trie — the surface the
    /// linker itself emits) and lands on the config as the validated
    /// [`pgr_core::bundle_loader::BundleLoader`].
    pub bundle_loader: Option<String>,
    /// Minimum page size accepted for `-segalign` on arm64 (16 KiB default).
    pub segalign: u64,
    /// `-headerpad <n>` (the M29 header-region floor: the flag the
    /// surface carried as an advisory no-op since M1 is the decision
    /// the packing loop reads).
    pub headerpad: u64,
    /// `-L` library search directories, in command-line order.
    pub lib_dirs: Vec<String>,
    /// `-l` requested library basenames (`-lfoo` / `-l foo`), in order.
    pub libs: Vec<String>,
    /// M106 `-needed-l <name>` (repeatable, ld64's `-needed-l<name>`
    /// attached form accepted too): the `-l` basenames that carry the
    /// needed-dylib mark — the dylib really rides even when no symbol
    /// binds against it (the `-dead_strip_dylibs` survival opt-out).
    pub needed_libs: Vec<String>,
    /// M110 `-hidden-l <name>` (repeatable, ld64's `-hidden-l<name>`
    /// attached form accepted too): the `-l` basenames that carry the
    /// hidden-dylib mark — the dylib's exports resolve but its load
    /// command drops (the dyld-flat-ride seam).
    pub hidden_libs: Vec<String>,
    /// `-u <symbol>`: force the symbol to be treated as defined (must
    /// resolve; a plain liveness marker at M2).
    pub force_load: Vec<String>,
    /// Indices into `inputs` loaded weakly (`-weak_library`).
    pub weak_library_inputs: Vec<usize>,
    /// Indices into `inputs` loaded lazily (`-lazy_library`, M14:
    /// `LC_LAZY_LOAD_DYLIB`).
    pub lazy_library_inputs: Vec<usize>,
    /// Indices into `inputs` loaded upward (`-upward_library`, M45:
    /// `LC_LOAD_UPWARD_DYLIB` — ld64's umbrella-relationship mark).
    pub upward_library_inputs: Vec<usize>,
    /// M106 indices into `inputs` carrying the needed-dylib mark
    /// (`-needed_library`): the dylib really rides even when no symbol
    /// binds against it (the `-dead_strip_dylibs` survival opt-out —
    /// ld64's "needed" loads).
    pub needed_library_inputs: Vec<usize>,
    /// M110 indices into `inputs` loaded hidden (`-hidden_library`):
    /// the dylib's exports enter the resolve arena but its load
    /// command drops — a weak reference rides dyld's flat lookup, a
    /// strong one refuses the link (ld64's "hidden" loads).
    pub hidden_library_inputs: Vec<usize>,
    /// Indices into `inputs` loaded as `LC_REEXPORT_DYLIB`
    /// (`-reexport_library`, M3).
    pub reexport_library_inputs: Vec<usize>,
    /// The export-filter sources, in command-line order (M100): each
    /// `-exported_symbol <name>` / `-unexported_symbol <name>`
    /// occurrence appends one validated entry, and each
    /// `-exported_symbols_list <f>` / `-unexported_symbols_list <f>`
    /// records its file (read at link time, the M3 convention) — every
    /// source composes into the ONE filter table in flag order, the
    /// M90 pattern, and the composed table feeds the unchanged
    /// [`pgr_core::export_filter`] seam. Empty (the default) keeps
    /// every pre-knob link byte-identical.
    pub export_filter_specs: Vec<ExportFilterSpec>,
    /// The alias sources, in command-line order (M101): each `-alias`
    /// occurrence carries its validated pair, each `-alias_list <f>`
    /// records its file (the file form of M24's `-alias`, read at link
    /// time) — every source composes into the ONE alias table in flag
    /// order (the M90 pattern; the table rides the config to the
    /// unchanged M24 seam, the wire's v16 carriage and the ladder).
    /// Empty (the default) keeps every pre-knob link byte-identical.
    pub alias_sources: Vec<AliasSource>,
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
    /// M45 `-upward_framework <name>` (repeatable): the framework dylib
    /// loads as `LC_LOAD_UPWARD_DYLIB` (the umbrella-relationship mark —
    /// the sub-umbrella its umbrella loads upward).
    pub upward_frameworks: Vec<String>,
    /// M23 `-reexport_framework <name>` (repeatable): the framework
    /// dylib loads as `LC_REEXPORT_DYLIB` and its exports join this
    /// image's export trie as REEXPORT nodes (the M3 `-reexport_library`
    /// shape, resolved through the `-F` search).
    pub reexport_frameworks: Vec<String>,
    /// M106 `-needed_framework <name>` (repeatable): the framework dylib
    /// carries the needed mark — it really rides even when no symbol
    /// binds against it (the `-dead_strip_dylibs` survival opt-out),
    /// resolved through the `-F` search (the M23 pattern).
    pub needed_frameworks: Vec<String>,
    /// M110 `-hidden_framework <name>` (repeatable): the framework dylib
    /// carries the hidden mark — its exports resolve but its load
    /// command drops, resolved through the `-F` search (the M23/M106
    /// pattern; ld64's "hidden" loads).
    pub hidden_frameworks: Vec<String>,
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
    /// M44 `-final_output <path>`: the dylib-identity default — the
    /// install name a dylib link derives when `-install_name` is absent
    /// (the `ld` man page: "Specifies the install name of a dylib if
    /// `-install_name` is not used"; the multi-arch driver names it so
    /// every arch slice records the universal path, not its own `-o`
    /// path). An explicit `-install_name` wins; refused where an install
    /// name has nothing to ride (execute, bundle, relocatable).
    pub final_output: Option<String>,
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
    /// M73 `-verify`: after the pipeline produces the image, run the
    /// strict verifier on the produced bytes and refuse to ship a
    /// failing verdict — the gate sits before the write, so the output
    /// file is never created when the image fails it (the audit's rule,
    /// on the cold path). The verdict rides
    /// [`LinkOutcome::verify`](crate::LinkOutcome::verify). The relink
    /// ladder carries its own gate (`-incremental-verify`): the two
    /// refuse to compose, and `-r` (an object, not an image) refuses
    /// the knob outright. M76: beside `-resident` the flag serves —
    /// the request asks the session for its own strict pass (v43) and
    /// the client gates the write on the served verdict, one verifier
    /// pass per resident link; a resident attempt that stands down
    /// hands over to the one-shot link, whose own gate still runs.
    pub verify: bool,
    /// M77 `-verify-checks <families>`: the M12 selector the link's own
    /// verify gate narrows to — the same [`pgr_verify::CheckSet`] the
    /// verifier CLI's `--checks` parses, the same subtractive contract
    /// (fewer families against the same parsed image; the parse
    /// pre-pass and the stats ride regardless). `None` names the full
    /// pass, every pre-M77 link's shape. The selection only rides
    /// beside `-verify` — a gate the selection narrows is the only
    /// gate it means — and on the resident lane it crosses the wire
    /// (v44) so the session's served pass narrows to the same families.
    pub verify_checks: Option<pgr_verify::CheckSet>,
    /// M10 rung 4, slice 5: `-fixup_chains_format` was passed explicitly
    /// (either spelling). The default (`false`) keeps the documented
    /// below-floor fallback — the layout silently plans the classic
    /// opcode streams when no family was named — while an explicitly
    /// named family the floor cannot carry is a refused knob, never a
    /// silently dropped one (the surface's own contract).
    pub chain_word_format_explicit: bool,
    /// The order sources, in command-line order (M11/M90): ld64's
    /// order files append into ONE rank table as the flags parse —
    /// `-order_file`'s rows and every `-sectorder`'s rows rank in the
    /// order the flags appear, never last-wins. Empty (the default)
    /// packs the layout exactly as before. The driver reads, parses
    /// (typed, line-tagged refusals) and composes the table before
    /// Pass 3 — see [`pgr_core::order`]. The resident lane serves the
    /// composed table since M81 (wire v47 carries it in the config
    /// tail) — the session's own walk ranks the entries the client
    /// named, either lane, the same layout.
    pub order_specs: Vec<OrderSpec>,
    /// M11 `-map <path>`: write the link map (the placed image's
    /// segments/sections/symbols, rendered by [`pgr_core::map`]) next to
    /// the link. `None` (the default) writes no map. The resident lane
    /// serves the document since M80 (wire v46) — the session's own walk
    /// renders it, the client writes the file; the one-shot lane renders
    /// its own (either lane, the same face). The incremental ladder
    /// renders the map since M86 — the relink's walk runs the full
    /// Passes 1–3, so the document is the relink's own placed image at
    /// either exit (the patched one and the untouched one) — and the
    /// fusion lane serves it too since M87: the session's ladder renders
    /// its own walk's document, the v46 tail carrying it verbatim (an
    /// old server's refusal is the stand-down the in-process ladder
    /// answers).
    pub map_path: Option<String>,
    /// M56 `-why_export <symbol>` (repeatable): after a link, answer
    /// *why is this symbol exported?* — the definition the resolution
    /// installed and every reference site the M8-a reverse index
    /// recorded (`pgr_core::provenance`). The default (the empty list)
    /// queries nothing. The query reads the link's own Pass-2 product:
    /// the one-shot lane's, the resident session's since M79 (wire v45
    /// — the rendered answers cross the wire verbatim), and — since M84
    /// — the incremental ladder's own walk (the relink re-parses the
    /// inputs and runs the full Passes 1–3, so `result.resolution` is
    /// the walk's product; the answers serve from it either tier — the
    /// patched relink and the untouched one both walked). Since M88 the
    /// fusion ladder's replay walk serves them too: the session's
    /// relink runs the same Passes 1–3, so its own Pass-2 product
    /// renders the answers over the same v45 tail.
    pub why_export: Vec<String>,
    /// M57 `-why_load`: after a link, report why each archive member
    /// was loaded (the S7 pull's per-member decision) and — under
    /// `-dead_strip_dylibs` — every input dylib's carriage
    /// (`pgr_core::provenance::LoadReport`, carried on the link result).
    /// The default (`false`) reports nothing. The lane contract mirrors
    /// `-why_export`: the resident lane serves the report since M79
    /// (the pull's record is the session's own); the ladder's own walk
    /// serves it since M84 — the relink re-pulls, the report names the
    /// members the relink's pull rode — and the fusion ladder's replay
    /// walk serves it since M88 (the session's re-pull is the honest
    /// record either lane).
    pub why_load: bool,
    /// M92 `-why_live <symbol>` (repeatable): after a link, answer *why
    /// is this symbol live under `-dead_strip`?* — the M5 mark phase's
    /// own first-marker record, walked from the queried definition back
    /// to its root (`pgr_core::why_live`; the record rides
    /// `LinkResult::liveness` exactly when the strip ran). The default
    /// (the empty list) queries nothing. The query reads the walk's own
    /// product: the one-shot lane's and — the relink re-runs the full
    /// Passes 1–3 — the incremental ladder's. M93: the resident lanes
    /// serve it too (wire v48 carries the ask; the session's own walk
    /// carries the mark record, the chains ride the provenance tail) —
    /// the relocatable output refuses the flag at the surface (`-r`
    /// carries no strip, no chain exists to name).
    pub why_live: Vec<String>,
    /// M58 `--time`: after a one-shot link, print the per-pass wall
    /// report — the M54 observation seam's phase events collected into
    /// the TDD's instrumentation table (`pgr_core::time_report`). The
    /// default (`false`) prints nothing. The resident lane serves the
    /// same report from the session's own observed pipeline (wire v40,
    /// M59); the incremental lane rides since M65 — the §7.3 ladder's
    /// rungs joined the seam's vocabulary — and the fusion lane
    /// (`-resident -incremental`) serves the session's observed ladder
    /// since M66 (wire v42 in service).
    pub time: bool,
    /// M58 `--time-json`: the same measurement rendered as the compact
    /// JSON interchange line (`TimeReport::render_json` — the M55/M56
    /// escape rules). Composes with `--time`; both faces read the one
    /// observed run. The lane contract mirrors `--time`.
    pub time_json: bool,
    /// M61 `--trace <path>`: after a link, write the link's
    /// Chrome-trace timeline — the M54 observation seam's phase events
    /// collected into the Trace Event Format's object form
    /// (`pgr_core::trace`; the reader is the same seam), the file the
    /// `chrome://tracing` and Perfetto UIs open. The default (`None`)
    /// writes nothing. The resident lane serves the same timeline from
    /// the session's own observed pipeline (wire v41, M62 — the client
    /// writes the served document verbatim); the incremental lane rides
    /// since M65 — the §7.3 ladder's rungs joined the seam's vocabulary
    /// — and the fusion lane (`-resident -incremental`) serves the
    /// session's observed ladder since M66 (wire v42 in service).
    pub trace_path: Option<String>,
    /// M60 `-dependency_info <path>`: after a successful link, write the
    /// build-system dependency record — ld64's sidecar artifact, the
    /// binary file Xcode's incremental builds read (`pgr_core::dep_info`
    /// validates and renders it; the reader is the same seam). The
    /// default (`None`) writes nothing. The record is the link's read set
    /// — never plan-derived — so it rides every lane that actually reads
    /// the input files (the resident lane writes it client-side from the
    /// request's own list; the daemon never touches the filesystem) —
    /// and, since M85, the incremental ladder: the relink's Pass 0
    /// re-reads every input it maps (the re-parse is the digest source)
    /// and records the read set while the reads happen, so the sidecar
    /// the relink rewrites names the files the ladder actually read, not
    /// the previous link's list. Since M89 the fusion lane serves it too:
    /// the daemon reads no files at all (the §7.2 contract), so the
    /// cycle's reads are the client's own Pass 0 — the same document
    /// either lane.
    pub dependency_info: Option<String>,
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
    /// M124: `-seg1addr` was passed explicitly. The value is validated
    /// against the core seam's grammar at parse time; the output-kind
    /// conflict (bundles, `-r`) and the one-base-per-kind overlap
    /// (`-seg1addr` beside `-pagezero_size` or `-image_base`) are
    /// `finish`'s (it sees the whole surface).
    pub seg1addr_explicit: bool,
    /// M28: the `-sectalign` decisions staged in command order. `finish`
    /// inserts them into the config (the core seam validates the value
    /// and refuses a twice-named (segment, section)) after the
    /// relocatable conflict gate sees the whole surface — a `-sectalign`
    /// on `-r` is a refused conflict, never a silently dropped flag.
    pub sect_align_stage: Vec<pgr_core::sect_align::SectAlign>,
    /// M29: `-headerpad` was passed explicitly. The value is validated
    /// against the core seam's grammar at `finish` (zero names the
    /// absence of the knob, an unaligned value breaks the load-command
    /// alignment); the output-kind conflict is `finish`'s too.
    pub headerpad_explicit: bool,
    /// M114: which UUID-identity flags the argv named (`-random_uuid`,
    /// `-no_uuid`) — both write the ONE typed source field, so the pair
    /// is not detectable from the config alone; `finish` refuses the
    /// pair order-independently from the two seen bits (the M99 pair
    /// shape, whose sides ride two fields). Parse bookkeeping, never a
    /// surface knob — the `chain_word_format_explicit` pattern.
    pub uuid_flags_seen: [bool; 2],
}

impl Default for Options {
    fn default() -> Self {
        Self {
            bundle_loader: None,
            output: String::new(),
            inputs: Vec::new(),
            config: LinkConfig::default(),
            segalign: pgr_format::consts::PAGE_SIZE_16K,
            headerpad: 0,
            lib_dirs: Vec::new(),
            libs: Vec::new(),
            needed_libs: Vec::new(),
            hidden_libs: Vec::new(),
            force_load: Vec::new(),
            weak_library_inputs: Vec::new(),
            lazy_library_inputs: Vec::new(),
            upward_library_inputs: Vec::new(),
            needed_library_inputs: Vec::new(),
            hidden_library_inputs: Vec::new(),
            reexport_library_inputs: Vec::new(),
            export_filter_specs: Vec::new(),
            alias_sources: Vec::new(),
            all_load: false,
            force_load_archives: Vec::new(),
            filelists: Vec::new(),
            frameworks: Vec::new(),
            weak_frameworks: Vec::new(),
            lazy_frameworks: Vec::new(),
            upward_frameworks: Vec::new(),
            reexport_frameworks: Vec::new(),
            needed_frameworks: Vec::new(),
            hidden_frameworks: Vec::new(),
            framework_dirs: Vec::new(),
            sectcreate: Vec::new(),
            cache_dir: None,
            no_cache: false,
            cache_max: None,
            syslibroots: Vec::new(),
            resident: false,
            resident_socket: None,
            final_output: None,
            incremental: false,
            incremental_verify: false,
            verify: false,
            verify_checks: None,
            chain_word_format_explicit: false,
            order_specs: Vec::new(),
            map_path: None,
            why_export: Vec::new(),
            why_load: false,
            why_live: Vec::new(),
            time: false,
            time_json: false,
            trace_path: None,
            dependency_info: None,
            pagezero_explicit: false,
            init_offsets_flag: None,
            seg_prot_stage: Vec::new(),
            stack_size_explicit: false,
            image_base_explicit: false,
            seg1addr_explicit: false,
            sect_align_stage: Vec::new(),
            headerpad_explicit: false,
            uuid_flags_seen: [false; 2],
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
    /// A `-sectalign` decision the core seam refuses (M28): the
    /// grammar (a section-bearing segment, a name that survives the
    /// 16-byte `section_64` field, a power of two up to the 0x4000
    /// page). The verdict is the core seam's refusal (it names the
    /// fix); the help restates the grammar.
    #[error("-sectalign: {detail}")]
    #[diagnostic(help(
        "the alignment is decimal or 0x-hex and a power of two up to 0x4000; the \
         segment is one of __TEXT, __DATA_CONST, __DATA and the section name fits \
         the 16-byte section_64 field"
    ))]
    SectAlignValue {
        /// The core seam's refusal (grammar, unknown segment, ceiling).
        detail: String,
    },
    /// A `-sectalign` surface conflict (M28): the relocatable output
    /// plans no segments and carries its input sections verbatim —
    /// nothing for a floor to land on — or one (segment, section) pair
    /// is named twice. The verdict names the shape conflict; the help
    /// is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    SectAlignConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `--trace` value refusal (M61): an empty path writes the
    /// timeline nowhere — the same honest refusal `-dependency_info`
    /// pays (the file is the surface's whole point).
    #[error("--trace: the timeline's path is empty")]
    #[diagnostic(help("name the file the timeline writes to: --trace <path>"))]
    TraceValue {
        /// The refused value (the empty string, verbatim).
        value: String,
    },
    /// A `-dependency_info` value the grammar refuses (M60): an empty
    /// path — the record is a file the build system reads back.
    #[error("invalid value for -dependency_info: {value}")]
    #[diagnostic(help("the record's path — e.g. -dependency_info build/app.deps"))]
    DependencyInfoValue {
        /// The refused value as written.
        value: String,
    },
    /// A `-why_export` value the grammar refuses (M56): an empty symbol
    /// name — the query is the C symbol, underscore included.
    #[error("invalid value for -why_export: {value}")]
    #[diagnostic(help(
        "the name is the C symbol, the leading underscore included — e.g. -why_export _greet"
    ))]
    WhyExportValue {
        /// The refused value as written.
        value: String,
    },
    /// A `-why_live` value the grammar refuses (M92): an empty symbol
    /// name — the query is the C symbol, underscore included.
    #[error("invalid value for -why_live: {value}")]
    #[diagnostic(help(
        "the name is the C symbol, the leading underscore included — e.g. -why_live _greet"
    ))]
    WhyLiveValue {
        /// The refused value as written.
        value: String,
    },
    /// A `-why_live` surface conflict (M93; the resident refusal the
    /// variant carried at M92 retired when wire v48 carried the ask —
    /// the session's own walk serves the chains). The surviving premise:
    /// the relocatable output (`-r`) preserves input sections verbatim
    /// and refuses the strip, so no mark record exists to walk — the
    /// verdict names the premise; the help is the fix — the house
    /// convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    WhyLiveConflict {
        /// What conflicts with what.
        verdict: String,
        /// The fix.
        fix: String,
    },
    /// A `-headerpad` value the grammar refuses (M29): the floor is
    /// non-zero (zero names the absence of the knob), a multiple of 8
    /// (the load-command alignment) and within the 16 KiB first page.
    /// The core seam's refusal rides the help — the grammar the flag
    /// accepts, not just the verdict.
    #[error("invalid value for -headerpad: {value}")]
    #[diagnostic(help("{message}"))]
    HeaderPadValue {
        /// The refused value as written.
        value: String,
        /// The core seam's refusal (the fix).
        message: String,
    },
    /// A `-headerpad` surface conflict (M29): the relocatable output
    /// plans no segments and carries its input sections verbatim —
    /// nothing for a reserved header region to land on. The verdict
    /// names the shape conflict; the help is the fix — the house
    /// convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    HeaderPadConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-verify` surface conflict (M73): the gate is an image-output
    /// decision — `-r` produces an `MH_OBJECT` (the verifier's object
    /// face gates it as a tool, never a link gate), and the relink
    /// ladder carries its own gate (`-incremental-verify` — the §7.3
    /// audit, whose subject is the patch). The verdict names the shape
    /// conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    VerifyConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-verify-checks` value the selector refuses (M77): the M12
    /// selector's own error rides verbatim — the offending token and the
    /// canonical family names — so the fix is one line away.
    #[error("invalid value for -verify-checks: {0}")]
    #[diagnostic(help(
        "name the families the gate runs (comma-separated `--checks` tokens, \
         the canonical names `pgr-verify --list-checks` prints)"
    ))]
    VerifyChecksValue(#[from] pgr_verify::CheckSetError),
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
    /// A `-seg1addr` value the grammar refuses (M124): the base is a
    /// non-zero multiple of the 16 KiB arm64 page — the same validation
    /// the core seam pays — and the help names the grammar (the fix,
    /// not just the verdict).
    #[error("invalid value for -seg1addr: {value}")]
    #[diagnostic(help(
        "the first segment's base is a non-zero multiple of the 16 KiB arm64 page (0x4000), \
         decimal or 0x-hex — e.g. 0x40000000; the default is 0x100000000"
    ))]
    Seg1AddrValue {
        /// The refused value as written.
        value: String,
    },
    /// A `-seg1addr` surface conflict (M124): the knob names the first
    /// segment's base — a bundle's preferred load address is its
    /// loader's job (the host process maps the bundle where it
    /// chooses), the relocatable output carries no segments, and one
    /// base knob per output kind means `-seg1addr` beside
    /// `-pagezero_size` (an executable) or `-image_base` (a dylib)
    /// names the same floor twice. The verdict names the shape
    /// conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    Seg1AddrConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-force_cpusubtype_ALL` surface conflict (M125): the knob
    /// forces the output's `mach_header_64.cpusubtype` word to
    /// `CPU_SUBTYPE_ARM64_ALL` — the relocatable output's header is the
    /// input's, verbatim (the M10 rung-1 contract — the object is
    /// itself a link input, its cpusubtype word rides untouched), so
    /// the knob has no header word to patch on `-r`. Executable, dylib
    /// and bundle outputs accept the knob (the header word is the
    /// producer's to name). The verdict names the shape conflict; the
    /// help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    ForceCpuSubtypeConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-allow_subsections_via_symbols` surface conflict (M126): the
    /// knob ORs `MH_SUBSECTIONS_VIA_SYMBOLS` into the output's
    /// `mach_header_64.flags` word — the relocatable output's header is
    /// the input's, verbatim (the M10 rung-1 contract — the object is
    /// itself a link input, its flags word rides untouched), so the
    /// knob has no header word to patch on `-r`. The default (`false`)
    /// keeps every pre-M126 link byte-identical (the segmented path
    /// never set the bit). Executable, dylib and bundle outputs accept
    /// the knob (the header word is the producer's to name). The
    /// verdict names the shape conflict; the help is the fix — the
    /// house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    SubsectionsViaSymbolsConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-interposable` surface conflict (M127): the knob marks a
    /// dylib's exports as interposable — `MH_WEAK_DEFINES |
    /// MH_BINDS_TO_WEAK` OR into the output's `mach_header_64.flags`
    /// word. An executable's identity is `LC_MAIN` (the kernel loads
    /// it), a bundle dlopens without an export table to interpose, and
    /// the relocatable output's header is the input's, verbatim (the M10
    /// rung-1 contract — the object is itself a link input, its flags
    /// word rides untouched). The default (`false`) keeps every pre-M127
    /// link byte-identical. The verdict names the shape conflict; the
    /// help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    InterposableConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-application_extension` surface conflict (M128): the knob ORs
    /// `MH_APP_EXTENSION_SAFE` into the output's `mach_header_64.flags`
    /// word — the relocatable output's header is the input's, verbatim
    /// (the M10 rung-1 contract — the object is itself a link input, its
    /// flags word rides untouched), so the knob has no header word to
    /// patch on `-r`. The default (`false`) keeps every pre-M128 link
    /// byte-identical. Executable, dylib and bundle outputs accept the
    /// knob (the header word is the producer's to name). The verdict
    /// names the shape conflict; the help is the fix — the house
    /// convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    ApplicationExtensionConflict {
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
    /// A `-sub_client` name the core seam refuses (M21): non-empty,
    /// NUL-free, named once. The seam's refusal rides the help — the
    /// grammar the flag accepts, not just the verdict.
    #[error("invalid value for -sub_client: {raw}")]
    #[diagnostic(help("{message}"))]
    SubClientValue {
        /// The refused name as written.
        raw: String,
        /// The core seam's refusal (the fix).
        message: String,
    },
    /// A `-rename_section` value the core seam refuses (M53): every
    /// name within the Mach-O 16-byte field width, no synthetic source
    /// or target, a source named once. The seam's refusal rides the
    /// help — the grammar the flag accepts, not just the verdict.
    #[error("invalid value for -rename_section: {raw}")]
    #[diagnostic(help("{message}"))]
    RenameValue {
        /// The refused value as written (the four names).
        raw: String,
        /// The core seam's refusal (the fix).
        message: String,
    },
    /// A `-sub_client` surface conflict (M21): the client list is a
    /// dylib's identity block — an executable's identity is `LC_MAIN` +
    /// `LC_LOAD_DYLINKER`, a bundle dlopens without sub commands, and
    /// the relocatable output carries no identity commands at all. The
    /// verdict names the shape conflict; the help is the fix — the
    /// house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    SubClientConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-U` name the core seam refuses (M39): non-empty, NUL-free,
    /// named once. The seam's refusal rides the help — the grammar the
    /// flag accepts, not just the verdict.
    #[error("invalid value for -U: {raw}")]
    #[diagnostic(help("{message}"))]
    MakeUndefinedValue {
        /// The refused name as written.
        raw: String,
        /// The core seam's refusal (the fix).
        message: String,
    },
    /// A `-U` surface conflict (M39): the marks are a Pass-2 decision —
    /// the relocatable output opens its undefineds by design and carries
    /// its input symbol table verbatim, so a mark has nothing to strip.
    /// The verdict names the shape conflict; the help is the fix — the
    /// house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    MakeUndefinedConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-dyld_env` pair the core seam refuses (M22): the
    /// `DYLD_<var>=<value>` grammar (a `DYLD_`-prefixed non-empty
    /// variable, one `=`, NUL-free), named once. The seam's refusal
    /// rides the help — the grammar the flag accepts, not just the
    /// verdict.
    #[error("invalid value for -dyld_env: {raw}")]
    #[diagnostic(help("{message}"))]
    DyldEnvValue {
        /// The refused pair as written.
        raw: String,
        /// The core seam's refusal (the fix).
        message: String,
    },
    /// A `-dyld_env` surface conflict (M22): dyld reads
    /// `LC_DYLD_ENVIRONMENT` from the main executable only — a dylib, a
    /// bundle and the relocatable output carry no loader to export the
    /// variables through. The verdict names the shape conflict; the
    /// help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    DyldEnvConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-dylinker` path the core seam refuses (M26): non-empty,
    /// NUL-free and absolute (the kernel resolves the loader path from
    /// the process root at exec time). The seam's refusal rides the
    /// help — the grammar the flag accepts, not just the verdict.
    #[error("invalid value for -dylinker: {raw}")]
    #[diagnostic(help("{message}"))]
    DylinkerValue {
        /// The refused path as written.
        raw: String,
        /// The core seam's refusal (the fix).
        message: String,
    },
    /// A `-dylinker` surface conflict (M26): `LC_LOAD_DYLINKER` is the
    /// main-executable command (the §8.2 loader-configuration
    /// adjacency) — a dylib, a bundle and the relocatable output carry
    /// no loader command for the path to land on. The verdict names the
    /// shape conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    DylinkerConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-no_pie` surface conflict (M27): `MH_PIE` is an
    /// executable-only bit — the kernel loads a dylib or a bundle
    /// itself, and the relocatable output carries no loader semantics
    /// at all. The verdict names the shape conflict; the help is the
    /// fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    NoPieConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-pie` surface conflict (M122): the M27 `-no_pie` refusal
    /// mirrored exactly — `MH_PIE` is an executable-only bit, the
    /// kernel loads a dylib or a bundle itself, and the relocatable
    /// output carries no loader semantics at all. The verdict names
    /// the shape conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    PieConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// An `-allow_stack_execute` surface conflict (M51):
    /// `MH_ALLOW_STACK_EXECUTION` is an executable-only bit — the
    /// kernel loads a dylib or a bundle itself, and the relocatable
    /// output carries no loader semantics at all (the M27 PIE shape,
    /// one flag word over). The verdict names the shape conflict; the
    /// help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    StackExecConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-bind_at_load` surface conflict (M102): `MH_BINDATLOAD` is an
    /// executable-only bit — dyld binds the exec'd main executable's
    /// undefineds before `main` runs, a dylib's and a bundle's binds
    /// ride their own loads, and the relocatable output carries no
    /// loader semantics at all (the M27 PIE and M51 stack-execution
    /// shape, one flag word over). The verdict names the shape
    /// conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    BindAtLoadConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// An `-undefined warning|suppress` surface conflict (M103): the
    /// non-escalating policies are a load-time-bind decision — a
    /// relocatable object's undefineds stay open in its symbol table by
    /// design (`-r` resolves nothing and carries no load-time bind to
    /// warn or suppress). The verdict names the shape conflict; the
    /// help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    UndefinedPolicyConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-x` surface conflict (M104): the symtab-shaping decision's
    /// drop face is a final-image decision — the relocatable output's
    /// symtab is the input's, verbatim (an object carries its inputs'
    /// tables untouched; there is no locals subrange to shape). The
    /// verdict names the shape conflict; the help is the fix — the
    /// house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    LocalSymbolsConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-S` surface conflict (M105): the debug-section suppression is
    /// a final-image decision — the relocatable output's sections are
    /// the input's, verbatim (an object carries its inputs' sections
    /// untouched; there is no debug classification to apply). The
    /// verdict names the shape conflict; the help is the fix — the
    /// house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    StripDebugConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-commons` policy surface conflict (M107): the non-default
    /// common-symbol treatment cannot apply where it was requested. The
    /// verdict names the shape conflict; the help is the fix — the house
    /// convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    CommonsPolicyConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-multiply_defined` policy surface conflict (M108): the
    /// non-default duplicated-symbol treatment cannot apply where it was
    /// requested. The verdict names the shape conflict; the help is the
    /// fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    MultiplyDefinedPolicyConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-fatal_warnings` surface conflict (M109): the exit escalation
    /// cannot apply where it was requested. The verdict names the shape
    /// conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    FatalWarningsConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-w` surface conflict (M133): the advisory faces' print
    /// suppression cannot apply where it was requested. The verdict
    /// names the shape conflict; the help is the fix — the house
    /// convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    WarnSuppressConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-print_statistics` surface conflict (M112): the
    /// link-statistics report is a final-image decision — the relocatable
    /// output has no full-emit layout or fixup planning to report in the
    /// same way (its sections are the input's, verbatim; the object walk
    /// plans no segments, no fixup slots and emits no image the report's
    /// counts name). The verdict names the shape conflict; the help is
    /// the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    PrintStatisticsConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-t` surface conflict (M113): the reference trace is a
    /// resolve-shaping decision — the relocatable output's symtab is the
    /// input's, verbatim (its symbol table rides the inputs untouched;
    /// there is no Pass-2 trace to report). The verdict names the shape
    /// conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    TraceRefsConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-no_objc_category_merging` surface conflict (M115): the
    /// category-merge disable is a final-image decision — the
    /// relocatable output's sections are the input's, verbatim (its
    /// sections ride the inputs untouched; there is no registration to
    /// fold). The verdict names the shape conflict; the help is the fix
    /// — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    ObjcCategoryMergingConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-warn_commons` surface conflict (M116): the common-symbol
    /// advisory is a resolve-record decision — the relocatable output's
    /// symtab is the input's, verbatim (its symbol table rides the
    /// inputs untouched; there is no resolution landing to advise
    /// about). The verdict names the shape conflict; the help is the
    /// fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    WarnCommonsConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-no_inits` surface conflict (M117): the init/term section
    /// suppression is a final-image decision — the relocatable output's
    /// sections are the input's, verbatim (its sections ride the inputs
    /// untouched; there is no init classification to apply). The verdict
    /// names the shape conflict; the help is the fix — the house
    /// convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    NoInitsConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-dtrace` surface conflict (M118): the `DTrace` `DOF` section
    /// processing is a final-image decision — the relocatable output's
    /// sections are the input's, verbatim (its sections ride the inputs
    /// untouched; there is no `DOF` header to validate at emit, no
    /// assembly to link). The verdict names the shape conflict; the help
    /// is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    DtraceConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-single_module`/`-multi_module` surface conflict (M119): the
    /// dylib module contract is a final-image decision — the relocatable
    /// output's symtab is the input's, verbatim (its tables ride the
    /// inputs untouched; there is no `LC_DYSYMTAB` module table to shape,
    /// no single-module escalation to apply). The verdict names the shape
    /// conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    ModulePolicyConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// An `-executable` surface conflict (M120): the explicit filetype
    /// override forces an `MH_EXECUTE` output — `-r`'s `MH_OBJECT` is the
    /// input's filetype verbatim (the object preserves the input's shape),
    /// so the combination refuses whatever order the flags arrived in. The
    /// verdict names the shape conflict; the help is the fix — the house
    /// convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    ExecutableConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-warn_duplicate` surface conflict (M121): the duplicate-symbol
    /// advisory is a resolve-record decision — the relocatable output's
    /// symtab is the input's, verbatim (its symbol table rides the inputs
    /// untouched; there is no resolution landing to tally). The verdict
    /// names the shape conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    WarnDuplicateConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// An `-init` surface conflict (M48): the dylib initializer is a
    /// dylib-only command (ld64: "-init can only be used with
    /// -dynamiclib") — an executable's initializer surface is
    /// `LC_MAIN`, a bundle dlopens without one, and the relocatable
    /// output carries no load commands at all. The verdict names the
    /// shape conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    InitConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-term` surface conflict (M98): the dylib terminator is the
    /// sibling of the `-init` decision — dylib-only, riding the same
    /// `LC_ROUTINES_64`. An executable terminates through its runtime
    /// (no load command names the routine), a bundle dlopens without a
    /// dylib terminator, and the relocatable output carries no load
    /// commands at all. The verdict names the shape conflict; the help
    /// is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    TermConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-uuid` value the surface refuses (M99): the 8-4-4-4-12 hex
    /// form is the grammar the flag accepts — 36 characters, hyphens at
    /// 8/13/18/23, case-insensitive hex. The refusal rides the help
    /// (the grammar, not just the verdict — the house convention).
    #[error("invalid value for -uuid: {raw}")]
    #[diagnostic(help("{message}"))]
    UuidValue {
        /// The refused value as written.
        raw: String,
        /// The grammar the flag accepts (the fix).
        message: String,
    },
    /// A `-no_uuid` × `-uuid` conflict (M99): a suppression and a named
    /// value are two answers to one question — order-independent, the
    /// pair is the shape. The verdict names both flags; the help is the
    /// fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    UuidConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// An `-alias` pair the core seam refuses (M24): the
    /// `-alias <alias_name> <definition_name>` grammar (two non-empty,
    /// NUL-free, distinct names), named once. The seam's refusal rides
    /// the help — the grammar the flag accepts, not just the verdict.
    #[error("invalid value for -alias: {raw}")]
    #[diagnostic(help("{message}"))]
    AliasValue {
        /// The refused pair as written.
        raw: String,
        /// The core seam's refusal (the fix).
        message: String,
    },
    /// A `-bundle_loader` surface conflict (M25): only a bundle binds
    /// against a host — an executable is the host of its own bundles, a
    /// dylib binds its own dylibs, and the relocatable output opens its
    /// undefineds by design. The verdict names the shape conflict; the
    /// help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    BundleLoaderConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// An `-alias` surface conflict (M24): the relocatable output
    /// carries the input symtab verbatim — an alias is an image-surface
    /// decision with no symtab row to grow. The verdict names the shape
    /// conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    AliasConflict {
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
    /// A `-no_exported_symbols` surface conflict (M40): the export-trie
    /// suppression cannot apply (or survive) where it was requested. The
    /// verdict names the shape conflict; the help is the fix — the house
    /// convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    ExportedSymbolsConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-dead_strip_dylibs` surface conflict (M42): the unused-dylib
    /// drop cannot apply where it was requested. The verdict names the
    /// shape conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    DeadStripDylibsConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-needed_library`/`-needed_framework`/`-needed-l` surface
    /// conflict (M106): the needed-dylib mark cannot apply where it was
    /// requested. The verdict names the shape conflict; the help is the
    /// fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    NeededLibraryConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-hidden_library`/`-hidden_framework`/`-hidden-l` surface
    /// conflict (M110): the hidden-dylib mark cannot apply where it was
    /// requested (the relocatable output carries no load commands to
    /// drop). The verdict names the shape conflict; the help is the fix
    /// — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    HiddenLibraryConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-read_only_relocs <policy>` surface conflict (M111): the
    /// read-only-relocations policy cannot apply where it was requested
    /// (the relocatable output carries no segment mapping to price).
    /// The verdict names the shape conflict; the help is the fix — the
    /// house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    ReadOnlyRelocsConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-weak_reference_mismatches <policy>` surface conflict (M123):
    /// the weak-reference-mismatches policy cannot apply where it was
    /// requested (the relocatable output's references ride untouched —
    /// no resolve walk prices them). The verdict names the shape
    /// conflict; the help is the fix — the house convention (the M111
    /// refusal shape, mirrored exactly).
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    WeakReferenceMismatchesConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-final_output` surface conflict (M44): the dylib-identity
    /// default cannot apply where it was requested. The verdict names
    /// the shape conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    FinalOutputConflict {
        /// What conflicts with what.
        verdict: String,
        /// The imperative tail naming the flags to change.
        fix: String,
    },
    /// A `-export_dynamic` surface conflict (M46): the dead-strip root
    /// widening cannot apply where it was requested. The verdict names
    /// the shape conflict; the help is the fix — the house convention.
    #[error("{verdict}")]
    #[diagnostic(help("{fix}"))]
    ExportDynamicConflict {
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
    /// A `-exported_symbol`/`-unexported_symbol` value the pattern
    /// grammar refuses (M100): the same grammar the M14 list files pay
    /// — an empty value matches nothing, interior whitespace is not a
    /// Mach-O symbol name. The refusal rides the help (the fix, not
    /// just the verdict — the house convention).
    #[error("invalid value for {flag}: {raw}")]
    #[diagnostic(help("{message}"))]
    ExportSymbolValue {
        /// The refused flag (`-exported_symbol` or `-unexported_symbol`).
        flag: String,
        /// The refused value as written.
        raw: String,
        /// The pattern grammar's refusal (the fix).
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
/// (cstring/code dedup stays on — the arm64 default). M30 promoted
/// `-no_data_in_code` off this list (the data-in-code carriage reads
/// the decision), M31 promoted `-no_function_starts` (the
/// function-starts suppression reads it), M32 promoted `-no_uuid`
/// (the UUID suppression reads it), M33 promoted
/// `-keep_private_externs` (the private-extern decision reads it) and
/// M41 promoted `-no_deduplicate` (the D4 merge reads it).
const NOOP_FLAGS: [&str; 3] = ["-no_adhoc_extensions", "-demangle", "-no_demangle"];

/// Flags that arrive at a later milestone (rejected with the roadmap entry).
/// M14 released the weak/lazy dylib family (`-weak_framework`,
/// `-lazy_framework`, `-lazy_library`), M15 released `-pagezero_size`
/// (the image-base seam), M20 released the umbrella re-exports
/// (`-sub_umbrella`, `-sub_library`), M26 released the `MH_DYLINKER`
/// output kind (`-dylinker`), M39 released make-undefined (`-U`, the
/// Pass-2 mark) and M43 released the `ObjC` pull (`-ObjC`, the archive
/// liveness rule) — the list is empty and the mechanism stays for the
/// next later-milestone flag. (The `-dylinker` entry that outlived its
/// M26 release shadowed nothing — the explicit arm won the match first,
/// so the entry was dead weight and left with the M43 promotion.)
const LATER_FLAGS: [(&str, &str); 0] = [];

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

/// Validates the `-uuid` value's 8-4-4-4-12 hex form (36 chars, hyphens
/// at 8/13/18/23, case-insensitive hex) and parses it into the 16 bytes
/// the `LC_UUID` command carries. The refusal names the grammar (the
/// fix, not just the verdict — the house convention), so a typo reads
/// what the flag accepts.
fn parse_named_uuid(raw: &str) -> Result<[u8; 16], String> {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let is_hex =
        |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || (b'A'..=b'F').contains(&b);
    let malformed = |why: &str| {
        format!(
            "-uuid accepts the 8-4-4-4-12 hex form (36 characters, hyphens at \
             positions 8/13/18/23, case-insensitive hex digits) — {why}"
        )
    };
    let bytes = raw.as_bytes();
    if bytes.len() != 36 {
        return Err(malformed(&format!(
            "the value is {} characters long",
            bytes.len()
        )));
    }
    let mut out = [0u8; 16];
    let mut at = 0usize;
    let mut oi = 0usize;
    for (gi, group) in GROUPS.iter().enumerate() {
        if gi > 0 {
            if bytes[at] != b'-' {
                return Err(malformed(&format!("position {} must be a hyphen", at + 1)));
            }
            at += 1;
        }
        for k in 0..*group {
            let b = bytes[at + k];
            if !is_hex(b) {
                return Err(malformed(&format!(
                    "character {b:?} at position {} is not a hex digit",
                    at + k + 1
                )));
            }
        }
        let hex = &raw[at..at + *group];
        let value = u64::from_str_radix(hex, 16)
            .map_err(|_| malformed("the group does not parse as hex"))?;
        let group_bytes = group.div_ceil(2);
        let encoded = value.to_be_bytes();
        out[oi..oi + group_bytes].copy_from_slice(&encoded[8 - group_bytes..]);
        oi += group_bytes;
        at += *group;
    }
    Ok(out)
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
            // M29: the flag no longer rides as an advisory no-op — the
            // explicit marker lets `finish` refuse a `-headerpad 0`
            // (the absence of the knob, not a decision) and gate the
            // relocatable conflict on the whole surface.
            opts.headerpad_explicit = true;
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
                // M103: the two non-escalating faces — the references
                // ride the flat-lookup slot exactly like
                // `dynamic_lookup`; the exit policy differs (warning
                // prints the unresolved list and exits 0, suppress
                // prints nothing and exits 0). The relocatable
                // conflict is `finish`'s (it sees the whole surface).
                "warning" => pgr_core::resolve::UndefinedPolicy::Warning,
                "suppress" => pgr_core::resolve::UndefinedPolicy::Suppress,
                other => {
                    return Err(OptsError::InvalidValue {
                        flag: arg.into(),
                        value: format!("{other} (error | dynamic_lookup | warning | suppress)"),
                    });
                }
            };
        }
        // M107: the commons resolution policy — ld64's `-commons
        // <policy>` ("Specifies how commons (aka tentative definitions)
        // are resolved with respect to dylibs"). The typed alphabet
        // rides the config; the relocatable conflict is `finish`'s (it
        // sees the whole surface).
        "-commons" => {
            let v = next_value(args, i, arg)?;
            opts.config.commons = match v.as_str() {
                "use_dylibs" => pgr_core::resolve::CommonsPolicy::UseDylibs,
                "search_dylibs" => pgr_core::resolve::CommonsPolicy::SearchDylibs,
                "use_extern" => pgr_core::resolve::CommonsPolicy::UseExtern,
                "error" => pgr_core::resolve::CommonsPolicy::Error,
                other => {
                    return Err(OptsError::InvalidValue {
                        flag: arg.into(),
                        value: format!("{other} (use_dylibs | search_dylibs | use_extern | error)"),
                    });
                }
            };
        }
        "-read_only_relocs" => {
            // M111: the read-only-relocations policy — ld64's policy
            // for relocations in read-only segments (the W^X
            // contract's other half): `error` refuses the write dyld
            // cannot perform, `warning` prints the advisory face (the
            // reloc rides, exit 0), `suppress` rides silently.
            let v = next_value(args, i, arg)?;
            opts.config.read_only_relocs = match v.as_str() {
                "error" => pgr_core::resolve::ReadOnlyRelocsPolicy::Error,
                "warning" => pgr_core::resolve::ReadOnlyRelocsPolicy::Warning,
                "suppress" => pgr_core::resolve::ReadOnlyRelocsPolicy::Suppress,
                other => {
                    return Err(OptsError::InvalidValue {
                        flag: arg.into(),
                        value: format!("{other} (error | warning | suppress)"),
                    });
                }
            };
        }
        // M123: the weak-reference-mismatches policy — ld64's
        // `-weak_reference_mismatches <policy>` (the `N_WEAK_REF` bit
        // on a symbol's `n_desc` — the weak-import contract's
        // resolve-side cousin): `error` refuses a weak/strong
        // reference mix (the default — the collision named), `weak`
        // records the mismatch and exits 0 (the advisory face — the
        // bytes never move, the M109/M116 pattern), `non-weak` the
        // advisory twin (the M103/M108 pattern).
        "-weak_reference_mismatches" => {
            let v = next_value(args, i, arg)?;
            opts.config.weak_reference_mismatches = match v.as_str() {
                "error" => pgr_core::resolve::WeakReferenceMismatchesPolicy::Error,
                "weak" => pgr_core::resolve::WeakReferenceMismatchesPolicy::Weak,
                "non-weak" => pgr_core::resolve::WeakReferenceMismatchesPolicy::NonWeak,
                other => {
                    return Err(OptsError::InvalidValue {
                        flag: arg.into(),
                        value: format!("{other} (error | weak | non-weak)"),
                    });
                }
            };
        }
        // M108: the multiply-defined resolution policy — ld64's
        // `-multiply_defined <policy>` ("How to handle multiply defined
        // symbols"). The typed alphabet rides the config; the relocatable
        // conflict is `finish`'s (it sees the whole surface).
        "-multiply_defined" => {
            let v = next_value(args, i, arg)?;
            opts.config.multiply_defined = match v.as_str() {
                "error" => pgr_core::resolve::MultiplyDefinedPolicy::Error,
                "warning" => pgr_core::resolve::MultiplyDefinedPolicy::Warning,
                "suppress" => pgr_core::resolve::MultiplyDefinedPolicy::Suppress,
                "dynamic_lookup" => pgr_core::resolve::MultiplyDefinedPolicy::DynamicLookup,
                other => {
                    return Err(OptsError::InvalidValue {
                        flag: arg.into(),
                        value: format!("{other} (error | warning | suppress | dynamic_lookup)"),
                    });
                }
            };
        }
        // M109: the warnings-as-errors exit policy — ld64's
        // `-fatal_warnings` ("Make warnings into errors") and its explicit
        // mirror. The bool rides the config (the bytes never move — the
        // policy is the exit's, not the image's); the relocatable conflict
        // is `finish`'s.
        "-fatal_warnings" => {
            opts.config.fatal_warnings = true;
        }
        "-no_fatal_warnings" => {
            opts.config.fatal_warnings = false;
        }
        // M133: the advisory faces' print suppression — ld64's `-w`
        // ("Suppress warnings"). The bool rides the config (the bytes
        // never move — the decision is the print face's, not the
        // image's); the relocatable conflict is `finish`'s. ld64's `-w`
        // carries no mirror: the flag is idempotent, a second occurrence
        // is the same decision.
        "-w" => {
            opts.config.suppress_warnings = true;
        }
        // M134: the loaded-object inventory — ld64's `-whatsloaded`
        // ("Print the names of all object files loaded"). The bool rides
        // the config (the bytes never move — the face is a measurement,
        // not a layout product); the face applies to every output kind
        // (an `-r` object's inventory is its own inputs), so no
        // relocatable conflict exists.
        "-whatsloaded" => {
            opts.config.whats_loaded = true;
        }
        // M112: the link-statistics report — ld64's "Print statistics
        // about the linker's performance". The counts ride the run's own
        // passes (the M54 observation seam) and the product, rendered to
        // stderr at the end of the link. The relocatable conflict is
        // `finish`'s (the object path has no full-emit layout or fixup
        // planning to report in the same way — the M104/M105 pattern).
        "-print_statistics" => {
            opts.config.print_statistics = true;
        }
        // M113: the reference trace — ld64's `-t` ("Print a trace of all
        // symbol references"). Each symbol Pass 2's resolve visits prints
        // to stderr, the events riding the M54 observation seam's
        // `on_reference` face. The relocatable conflict is `finish`'s
        // (the object's symtab is the input's, verbatim — the
        // M104/M105/M112 pattern).
        "-t" => {
            opts.config.trace_refs = true;
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
        "-upward_library" => {
            // M45: the whole dylib loads as the umbrella relationship
            // (LC_LOAD_UPWARD_DYLIB) — the sub-umbrella its umbrella
            // loads upward; under chained fixups the command rides the
            // two-level ordinal space like a plain load.
            let v = next_value(args, i, arg)?;
            opts.inputs.push(v);
            opts.upward_library_inputs.push(opts.inputs.len() - 1);
        }
        "-needed_library" => {
            // M106: the needed-dylib mark — the dylib really rides even
            // when no symbol binds against it (the `-dead_strip_dylibs`
            // survival opt-out; ld64's "needed" loads). The command kind
            // stays a plain load: the mark composes with every kind.
            let v = next_value(args, i, arg)?;
            opts.inputs.push(v);
            opts.needed_library_inputs.push(opts.inputs.len() - 1);
        }
        "-hidden_library" => {
            // M110: the hidden-dylib mark — the dylib's exports enter
            // the resolve arena (the same scan path as
            // `-weak_library`/`-lazy_library`) but its load command
            // drops: a weak reference rides dyld's flat lookup, a
            // strong one refuses the link (ld64's "hidden" loads —
            // dyld cannot bind a strong reference without the load
            // command).
            let v = next_value(args, i, arg)?;
            opts.inputs.push(v);
            opts.hidden_library_inputs.push(opts.inputs.len() - 1);
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
        "-upward_framework" => {
            // M45: the framework dylib loads as the umbrella relationship
            // (LC_LOAD_UPWARD_DYLIB) — the -framework search with the
            // upward-load kind.
            let v = next_value(args, i, arg)?;
            opts.upward_frameworks.push(v);
        }
        "-reexport_framework" => {
            // M23: the framework dylib re-exports through this image's
            // trie (LC_REEXPORT_DYLIB, the M3 shape — the framework form
            // of `-reexport_library`).
            let v = next_value(args, i, arg)?;
            opts.reexport_frameworks.push(v);
        }
        "-needed_framework" => {
            // M106: the needed-framework mark — the framework dylib
            // really rides even when no symbol binds against it (the
            // `-dead_strip_dylibs` survival opt-out), resolved through
            // the `-F` search (the M23 pattern). The command kind stays
            // a plain load: the mark composes with every kind.
            let v = next_value(args, i, arg)?;
            opts.needed_frameworks.push(v);
        }
        "-hidden_framework" => {
            // M110: the hidden-framework mark — the framework dylib's
            // exports resolve but its load command drops, resolved
            // through the `-F` search (the M23/M106 pattern; ld64's
            // "hidden" loads).
            let v = next_value(args, i, arg)?;
            opts.hidden_frameworks.push(v);
        }
        "-needed-l" => {
            // M106: the `-l` form of the needed mark — the basename
            // rides the `-L` search carrying the survival opt-out
            // (ld64's `-needed-l<name>`; the detached form is the flag's
            // own spelling, the attached `-needed-l<name>` form is
            // matched below with the attached libraries). The name is a
            // library request like `-l`'s (the search is shared, the
            // mark rides the resolved dylib).
            let v = next_value(args, i, arg)?;
            opts.libs.push(v.clone());
            opts.needed_libs.push(v);
        }
        "-hidden-l" => {
            // M110: the `-l` form of the hidden mark — the basename
            // rides the `-L` search carrying the command drop (ld64's
            // `-hidden-l<name>`; the detached form is the flag's own
            // spelling, the attached `-hidden-l<name>` form is matched
            // below with the attached libraries). The name is a library
            // request like `-l`'s (the search is shared, the mark rides
            // the resolved dylib).
            let v = next_value(args, i, arg)?;
            opts.libs.push(v.clone());
            opts.hidden_libs.push(v);
        }
        "-dylib" => match opts.config.filetype {
            // A repeated kind is idempotent; only a kind *switch* is a
            // conflict (a duplicate used to be reported as the mutual-
            // exclusion error — a diagnosis about a conflict that never
            // happened).
            pgr_core::layout::OutputType::Dylib => {}
            pgr_core::layout::OutputType::Execute => {
                // M120: `-executable` wins over `-dylib` regardless of
                // order (the override holds — ld64's "force MH_EXECUTE");
                // a `-dylib` arriving after the override is advisory, never
                // a silent switch back to a dylib.
                if !opts.config.executable {
                    opts.config.filetype = pgr_core::layout::OutputType::Dylib;
                }
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
                // M120: `-executable` wins over `-bundle` regardless of
                // order (the override holds — ld64's "force MH_EXECUTE");
                // a `-bundle` arriving after the override is advisory.
                if !opts.config.executable {
                    opts.config.filetype = pgr_core::layout::OutputType::Bundle;
                }
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
        // M120: ld64's `-executable` — the explicit filetype override.
        // Forces `MH_EXECUTE` regardless of any `-dylib`/`-bundle`
        // inference earlier on the command line (or sets the default,
        // which is already `Execute` — every pre-M120 link byte-identical).
        // `-r` keeps its refusal: when `-r` is in force the filetype stays
        // `Relocatable` and `finish` refuses the combination (the
        // M104/M105/M117 pattern, order-independent). The relocatable
        // conflict is `finish`'s — it sees the whole surface.
        "-executable" => {
            opts.config.executable = true;
            if opts.config.filetype != pgr_core::layout::OutputType::Relocatable {
                opts.config.filetype = pgr_core::layout::OutputType::Execute;
            }
        }
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
        // M44: the dylib-identity default — the install name a dylib
        // link derives when -install_name is absent (the explicit
        // -install_name wins; the identity-block conflicts refuse in
        // finish: an executable's identity is LC_MAIN, a bundle dlopens
        // without a region, and the relocatable output carries no
        // identity commands).
        "-final_output" => {
            let v = next_value(args, i, arg)?;
            opts.final_output = Some(v);
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
            if opts
                .export_filter_specs
                .iter()
                .any(|s| matches!(s, ExportFilterSpec::ExportedList { .. }))
            {
                return Err(OptsError::Repeated {
                    message: "-exported_symbols_list given more than once".into(),
                });
            }
            opts.export_filter_specs
                .push(ExportFilterSpec::ExportedList { path: v });
        }
        "-unexported_symbols_list" => {
            let v = next_value(args, i, arg)?;
            if opts
                .export_filter_specs
                .iter()
                .any(|s| matches!(s, ExportFilterSpec::UnexportedList { .. }))
            {
                return Err(OptsError::Repeated {
                    message: "-unexported_symbols_list given more than once".into(),
                });
            }
            opts.export_filter_specs
                .push(ExportFilterSpec::UnexportedList { path: v });
        }
        // M100: the singular export filters — ld64's command-line
        // siblings of the list files. The same pattern grammar the
        // M14 lists widened to validates here (an exact name, or a `*`
        // glob), so a typo refuses at the parse with the fix named;
        // each occurrence appends one entry to the ONE composed filter
        // table in flag order (the M90 compose pattern).
        "-exported_symbol" => {
            let v = next_value(args, i, arg)?;
            let pattern = pgr_core::SymbolPattern::parse(v.as_bytes()).map_err(|e| {
                OptsError::ExportSymbolValue {
                    flag: "-exported_symbol".into(),
                    raw: v.clone(),
                    message: e.to_string(),
                }
            })?;
            opts.export_filter_specs
                .push(ExportFilterSpec::Exported { pattern });
        }
        "-unexported_symbol" => {
            let v = next_value(args, i, arg)?;
            let pattern = pgr_core::SymbolPattern::parse(v.as_bytes()).map_err(|e| {
                OptsError::ExportSymbolValue {
                    flag: "-unexported_symbol".into(),
                    raw: v.clone(),
                    message: e.to_string(),
                }
            })?;
            opts.export_filter_specs
                .push(ExportFilterSpec::Unexported { pattern });
        }
        "-mark_dead_strippable_dylib" => opts.config.dead_strippable = true,
        "-dead_strip" => opts.config.dead_strip = true,
        "-no_dead_strip" => opts.config.dead_strip = false,
        // M52: the dead-strip init/term roots — ld64's flag ("The linker
        // never dead strips initialization and termination routines").
        // A boolean knob with no output-kind conflict: without
        // `-dead_strip` the decision never fires, and the relocatable
        // output strips nothing (the M41/M43/M47 inert-for-relocatable
        // shape).
        "-no_dead_strip_inits_and_terms" => {
            opts.config.no_dead_strip_inits_and_terms = true;
        }
        // M53: the section rename — ld64's flag ("Renames section
        // orgSegment/orgSection to newSegment/newSection"). Four
        // arguments, the `-segprot` shape; the same validation the core
        // seam pays runs here (the 16-byte name field, the synthetic
        // targets, the doubled source), so the refusal names the grammar;
        // a rename outside the M1 bucket trio is the layout's (it sees
        // the classification).
        "-rename_section" => {
            let from_seg = next_value(args, i, arg)?;
            let from_sect = next_value(args, i, arg)?;
            let to_seg = next_value(args, i, arg)?;
            let to_sect = next_value(args, i, arg)?;
            let rename = pgr_core::rename::SectionRename::from_flag(
                &from_seg, &from_sect, &to_seg, &to_sect,
            )
            .map_err(|e| OptsError::RenameValue {
                raw: format!("{from_seg} {from_sect} {to_seg} {to_sect}"),
                message: e.to_string(),
            })?;
            opts.config
                .renames
                .push(rename)
                .map_err(|e| OptsError::RenameValue {
                    raw: format!("{from_seg} {from_sect} {to_seg} {to_sect}"),
                    message: e.to_string(),
                })?;
        }
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
        // M73: the cold link's own gate — the strict pass on the
        // produced bytes before the write.
        "-verify" => opts.verify = true,
        // M77: the verify gate's check selection — the M12 selector's
        // canonical tokens, comma-separated. The parse names the
        // offending token and the canonical spellings (the selector's
        // own error, the fix not just the verdict); a selection without
        // a gate refuses in `finish`'s conflict walk.
        "-verify-checks" => {
            let v = next_value(args, i, arg)?;
            opts.verify_checks =
                Some(pgr_verify::CheckSet::parse(&v).map_err(OptsError::VerifyChecksValue)?);
        }
        "-all_load" => opts.all_load = true,
        "-force_load" => {
            let v = next_value(args, i, arg)?;
            opts.force_load_archives.push(v);
        }
        // M43: the ObjC pull — members implementing an Objective-C class
        // or category ride the archive pull without a reference (the
        // runtime registers the metadata by section address, so no
        // static reference seeds the fixpoint). The decision rides the
        // config: the pull reads it in Pass 0's fixpoint, never a parse
        // blindfold.
        "-ObjC" => opts.config.objc = true,
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
        // M11/M90: the order sources are read (and their parse refusals
        // named) by the driver before Pass 3; the surface stores the
        // instances in command-line order — `-sectorder`'s pair names
        // the face (`pgr_core::order::classify_section_order`), the
        // rank-append files compose with `-order_file` into the one
        // table.
        "-order_file" => {
            let v = next_value(args, i, arg)?;
            opts.order_specs.push(OrderSpec::File { path: v });
        }
        "-sectorder" => {
            let segment = next_value(args, i, arg)?;
            let section = next_value(args, i, arg)?;
            let path = next_value(args, i, arg)?;
            opts.order_specs.push(OrderSpec::Section {
                segment,
                section,
                path,
            });
        }
        // M11: the link map is rendered from the finished plan (the same
        // layout the fused emit writes) and written after the link.
        "-map" => {
            let v = next_value(args, i, arg)?;
            opts.map_path = Some(v);
        }
        // M56: the symbol-reference provenance query. The names ride
        // verbatim (C symbols carry the leading underscore); an empty
        // name refuses here, the lane conflicts are `finish`'s.
        "-why_export" => {
            let v = next_value(args, i, arg)?;
            if v.is_empty() {
                return Err(OptsError::WhyExportValue { value: v });
            }
            opts.why_export.push(v);
        }
        // M57: the load-provenance report (the S7 pull's per-member
        // decision, the `-dead_strip_dylibs` carriage). The lane
        // conflicts are `finish`'s.
        "-why_load" => {
            opts.why_load = true;
        }
        // M92: the liveness-provenance query — the M5 mark phase's own
        // first-marker record, walked from the queried definition back
        // to its root. The names ride verbatim (C symbols carry the
        // leading underscore); an empty name refuses here, the resident
        // lane's refusal is `finish`'s (the wire has no liveness ask
        // shape yet).
        "-why_live" => {
            let v = next_value(args, i, arg)?;
            if v.is_empty() {
                return Err(OptsError::WhyLiveValue { value: v });
            }
            opts.why_live.push(v);
        }
        // M58: the per-pass time report (the M54 observation seam's
        // phase events, collected into the TDD's instrumentation table).
        // The lane conflicts are `finish`'s — both faces read the
        // one-shot pipeline's phases.
        "--time" => {
            opts.time = true;
        }
        "--time-json" => {
            opts.time_json = true;
        }
        // M61: the Chrome-trace timeline (the roadmap §9.4 toolbox's
        // `--trace`). The path rides verbatim — paths are free-form; an
        // empty one refuses here (a timeline with no name writes
        // nowhere), the lane conflicts are `finish`'s.
        "--trace" => {
            let v = next_value(args, i, arg)?;
            if v.is_empty() {
                return Err(OptsError::TraceValue { value: v });
            }
            opts.trace_path = Some(v);
        }
        // M60: the build-system dependency record (ld64's
        // `-dependency_info`). The path rides verbatim — paths are
        // free-form; an empty one refuses here (a record with no name
        // writes nowhere), the lane conflict is `finish`'s.
        "-dependency_info" => {
            let v = next_value(args, i, arg)?;
            if v.is_empty() {
                return Err(OptsError::DependencyInfoValue { value: v });
            }
            opts.dependency_info = Some(v);
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
        // M28: the section-alignment floor (the packing engine's
        // `-sectalign <seg> <sect> <align>` decision). The same
        // validation the core seam pays runs here, so the refusal names
        // the grammar; the relocatable conflict is `finish`'s (it sees
        // the whole surface). The value is decimal or `0x`-hex (the
        // `-stack_size` grammar) — a bare integer is decimal, so ld64's
        // bare-hex spelling refuses instead of silently re-reading.
        "-sectalign" => {
            let seg_raw = next_value(args, i, arg)?;
            let sect_raw = next_value(args, i, arg)?;
            let value_raw = next_value(args, i, arg)?;
            let value = parse_number(&value_raw).ok_or_else(|| OptsError::SectAlignValue {
                detail: format!(
                    "{value_raw} is not a number — the alignment is decimal or \
                         0x-hex (e.g. 4096 or 0x1000)"
                ),
            })?;
            let decision = pgr_core::sect_align::SectAlign::from_flag(&seg_raw, &sect_raw, value)
                .map_err(|e| OptsError::SectAlignValue {
                detail: e.to_string(),
            })?;
            opts.sect_align_stage.push(decision);
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
        // M124: the first segment's base address (ld64's `-seg1addr
        // <address>` — "Set the base address of the first segment"). The
        // same validation the core seam pays runs here, so the refusal
        // names the grammar; the output-kind conflict (bundles, `-r`)
        // and the one-base-per-kind overlap are `finish`'s (it sees the
        // whole surface).
        "-seg1addr" => {
            let v = next_value(args, i, arg)?;
            let n =
                parse_number(&v).ok_or_else(|| OptsError::Seg1AddrValue { value: v.clone() })?;
            opts.config.seg1addr = Some(
                pgr_core::Seg1Addr::from_override(n)
                    .map_err(|_| OptsError::Seg1AddrValue { value: v.clone() })?,
            );
            opts.seg1addr_explicit = true;
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
        // M39: the make-undefined marks. The same validation the core
        // seam pays runs here, so the refusal names the grammar; the
        // output-kind conflict is `finish`'s (it sees the whole
        // surface).
        "-U" => {
            let v = next_value(args, i, arg)?;
            let mark = pgr_core::MakeUndefinedName::from_flag(&v).map_err(|e| {
                OptsError::MakeUndefinedValue {
                    raw: v.clone(),
                    message: e.to_string(),
                }
            })?;
            opts.config
                .make_undefined
                .push(mark)
                .map_err(|e| OptsError::MakeUndefinedValue {
                    raw: v.clone(),
                    message: e.to_string(),
                })?;
        }
        // M21: the client list's entries. The same validation the core
        // seam pays runs here, so the refusal names the grammar; the
        // output-kind conflict is `finish`'s (it sees the whole
        // surface).
        "-sub_client" => {
            let v = next_value(args, i, arg)?;
            let client =
                pgr_core::SubClientEntry::from_flag(&v).map_err(|e| OptsError::SubClientValue {
                    raw: v.clone(),
                    message: e.to_string(),
                })?;
            opts.config
                .sub_clients
                .push(client)
                .map_err(|e| OptsError::SubClientValue {
                    raw: v.clone(),
                    message: e.to_string(),
                })?;
        }
        // M22: the dyld-environment pairs. The same validation the core
        // seam pays runs here, so the refusal names the grammar; the
        // output-kind conflict is `finish`'s (it sees the whole
        // surface).
        "-dyld_env" => {
            let v = next_value(args, i, arg)?;
            let env =
                pgr_core::DyldEnvEntry::from_flag(&v).map_err(|e| OptsError::DyldEnvValue {
                    raw: v.clone(),
                    message: e.to_string(),
                })?;
            opts.config
                .dyld_envs
                .push(env)
                .map_err(|e| OptsError::DyldEnvValue {
                    raw: v.clone(),
                    message: e.to_string(),
                })?;
        }
        // M26: the loader path. The same validation the core seam pays
        // runs here, so the refusal names the grammar; the output-kind
        // conflict is `finish`'s (it sees the whole surface). One
        // decision per link — the later flag replaces the earlier (the
        // `Option` the seam rides).
        "-dylinker" => {
            let v = next_value(args, i, arg)?;
            let loader =
                pgr_core::Dylinker::from_flag(&v).map_err(|e| OptsError::DylinkerValue {
                    raw: v.clone(),
                    message: e.to_string(),
                })?;
            opts.config.dylinker = Some(loader);
        }
        // M27: the PIE decision. A boolean knob — the default (unset)
        // keeps the executable's `MH_PIE`; the output-kind conflict is
        // `finish`'s (it sees the whole surface).
        "-no_pie" => {
            opts.config.no_pie = true;
        }
        // M122: the PIE positive-form twin — ld64's `-pie` ("Force the
        // creation of an MH_PIE file") is the explicit-decision mirror of
        // the M27 `-no_pie` knob (the M120 `-executable` pattern over the
        // PIE bit). A boolean knob — last-wins the `-no_pie` pair (the
        // M102 `-bind_at_load`/`-no_bind_at_load` shape: the emit reads
        // `cfg.pie || !cfg.no_pie`); the output-kind conflict is
        // `finish`'s (it sees the whole surface).
        "-pie" => {
            opts.config.pie = true;
        }
        // M125: the CPU subtype override. ld64's `-force_cpusubtype_ALL`
        // ("Force the cpusubtype to be CPU_SUBTYPE_ARM64_ALL") forces
        // the output's `mach_header_64.cpusubtype` word to
        // `CPU_SUBTYPE_ARM64_ALL` regardless of the input objects'
        // subtypes. A boolean knob — the default already carries ALL
        // (every pre-M125 link), so the knob is byte-identity (the M122
        // `-pie` pattern over the cpusubtype word); the `-r` conflict
        // is `finish`'s (it sees the whole surface).
        "-force_cpusubtype_ALL" => {
            opts.config.force_cpusubtype_all = true;
        }
        // M126: the output image's atomization decision. ld64's flags
        // `-allow_subsections_via_symbols`/`-no_allow_subsections_via_symbols`
        // ("Turn on/off the `MH_SUBSECTIONS_VIA_SYMBOLS` bit in the
        // output mach-O header") — a boolean pair, last-wins (the M102
        // `-bind_at_load`/`-no_bind_at_load` shape): the emit reads
        // `cfg.subsections_via_symbols`. The default (`false`) keeps
        // every pre-M126 link byte-identical (the segmented path never
        // set the bit); the `-r` conflict is `finish`'s (it sees the
        // whole surface).
        "-allow_subsections_via_symbols" => {
            opts.config.subsections_via_symbols = true;
        }
        "-no_allow_subsections_via_symbols" => {
            opts.config.subsections_via_symbols = false;
        }
        // M127: the dylib's export-interposability decision. ld64's
        // `-interposable` marks a dylib's exports as interposable — the
        // loader consults `MH_WEAK_DEFINES | MH_BINDS_TO_WEAK` on the
        // image's `mach_header_64.flags` word to treat every export as
        // overridable at runtime. A boolean knob — the default (`false`)
        // keeps every pre-M127 link byte-identical (the bits ride the
        // weak-define presence the M2 trie already priced); the
        // output-kind conflicts (executable, bundle, `-r`) are
        // `finish`'s (it sees the whole surface).
        "-interposable" => {
            opts.config.interposable = true;
        }
        // M128: the app-extension-safe decision. ld64's
        // `-application_extension` marks the image as
        // app-extension-safe — the loader consults
        // `MH_APP_EXTENSION_SAFE` on the image's
        // `mach_header_64.flags` word for the App Store's sandbox
        // compatibility contract. A boolean knob — the default (`false`)
        // keeps every pre-M128 link byte-identical (the segmented path
        // never set the bit); the `-r` conflict is `finish`'s (it sees
        // the whole surface).
        "-application_extension" => {
            opts.config.application_extension = true;
        }
        // M51: the stack-execution decision. ld64's flag ("Marks
        // executable so that all stacks in the task will be given stack
        // execution privilege") — a boolean knob like the M27 PIE
        // decision, one flag word over; the output-kind conflict is
        // `finish`'s (it sees the whole surface).
        "-allow_stack_execute" => {
            opts.config.allow_stack_execute = true;
        }
        // M102: the bind-at-load decision. ld64's flag pair —
        // `-bind_at_load` ("Bind all undefined symbols at load time,
        // before main runs") sets the executable's `MH_BINDATLOAD`
        // flag word, `-no_bind_at_load` drops it (ld64's own default —
        // the last flag wins, the bool carries whichever came last);
        // the output-kind conflict is `finish`'s (it sees the whole
        // surface).
        "-bind_at_load" => {
            opts.config.bind_at_load = true;
        }
        "-no_bind_at_load" => {
            opts.config.bind_at_load = false;
        }
        // M104: the symtab-shaping decision. ld64's pair —
        // `-keep_local_symbols` ("Keep local symbols in the symbol
        // table") names the keep face, `-x` ("Do not emit symbols for
        // internal symbols") the drop: the output symtab's plain
        // local-symbol subrange drops or rides on the decision (the
        // last flag wins, the bool carries whichever came last). The
        // default keeps the subrange (ld64's own default,
        // kLocalSymbolsAll — every pre-knob link byte-identical); the
        // relocatable-output conflict is `finish`'s (it sees the whole
        // surface).
        "-keep_local_symbols" => {
            opts.config.keep_local_symbols = true;
        }
        "-x" => {
            opts.config.keep_local_symbols = false;
        }
        // M105: the debug-section suppression. ld64's `-S` ("Strip
        // debug symbols") names the debug shapes — the `__DWARF`
        // segments the sweep always kept out, plus the `__debug_*` and
        // `S_ATTR_DEBUG` sections the segment-name rule misses — the
        // Pass-1 classification drops their bytes, the symtab's entries
        // into them drop with them, and the `LC_FUNCTION_STARTS` /
        // `LC_DATA_IN_CODE` commands drop (the M31/M30 suppression
        // pattern composed). The relocatable-output conflict is
        // `finish`'s (it sees the whole surface).
        "-S" => {
            opts.config.strip_debug = true;
        }
        // M30: the data-in-code suppression. The flag rode the surface
        // as an accepted no-op since M1; the carriage reads the
        // decision — the output's `LC_DATA_IN_CODE` command drops (no
        // `__LINKEDIT` slot rides either). A boolean knob, like the
        // M27 PIE decision; there is no output-kind conflict (every
        // segmented output can carry the stream, the suppression just
        // names it off).
        "-no_data_in_code" => {
            opts.config.data_in_code = false;
        }
        // M31: the function-starts suppression. The flag rode the
        // surface as an accepted no-op since M1; the header assembly
        // reads the decision — the output's `LC_FUNCTION_STARTS`
        // command drops (no `__LINKEDIT` slot, no stream). A boolean
        // knob with no output-kind conflict.
        "-no_function_starts" => {
            opts.config.function_starts = false;
        }
        // M32/M114: the UUID suppression — the typed source alphabet's
        // `none` face. The flag rode the surface as an accepted no-op
        // since M1; the header assembly reads the decision — the
        // output's `LC_UUID` command drops (no uuid field for the emit
        // two-pass derivation to patch). The pair conflicts
        // (`-no_uuid` × `-uuid`, `-no_uuid` × `-random_uuid`) are
        // `finish`'s — it sees the whole surface; both flags writing
        // the ONE source field rides the seen bits.
        "-no_uuid" => {
            opts.config.uuid_source = pgr_core::layout::UuidSource::None;
            opts.uuid_flags_seen[1] = true;
        }
        // M114: ld64's `-random_uuid` — the typed source alphabet's
        // `random` face: the emit draws the output's identity from the
        // system CSPRNG at emit time (a whole UUIDv4, fresh per emit —
        // the reproducible face stays `content`, the default). The
        // conflicts (`-random_uuid` × `-uuid`, `×` `-no_uuid`, the
        // relocatable output) are `finish`'s — it sees the whole
        // surface.
        "-random_uuid" => {
            opts.config.uuid_source = pgr_core::layout::UuidSource::Random;
            opts.uuid_flags_seen[0] = true;
        }
        // M115: ld64's `-no_objc_category_merging` — the ObjC
        // category-merging optimization's disable. The default merges
        // every category whose base class rides the link (the
        // registration section the metadata family names folds away);
        // the flag keeps every category's registration verbatim. The
        // relocatable conflict is `finish`'s — it sees the whole
        // surface.
        "-no_objc_category_merging" => {
            opts.config.objc_category_merging = false;
        }
        // M116: ld64's `-warn_commons` — the common-symbol advisory face.
        // The decision rides the M107 `CommonsPolicy` seam without
        // changing the resolution policy itself: where every input
        // common symbol's name resolved (a local definition or a linked
        // dylib's export), the resolver records the landing and the
        // exit policy prints it as a warning, still exiting 0. The
        // relocatable conflict is `finish`'s — it sees the whole
        // surface.
        "-warn_commons" => {
            opts.config.warn_commons = true;
        }
        // M117: ld64's init/term section suppression — the
        // `__mod_init_func`, `__mod_term_func` and `__init_offsets`
        // sections drop from the output entirely, overriding the M16
        // transform and the M52 dead-strip roots, and the `LC_ROUTINES_64`
        // command (M48 `-init` / M98 `-term`) drops from the header (no
        // init/term machinery remains). The relocatable conflict is
        // `finish`'s — it sees the whole surface.
        "-no_inits" => {
            opts.config.no_inits = true;
        }
        // M118: ld64's dtrace DOF section processing — a `__dtrace_dof`
        // (`S_DTRACE_DOF`) section is recognized as a dtrace payload
        // (Pass 1, distinct from the generic `S_ATTR_DEBUG` debug class)
        // and the emit validates its DOF header (the identification magic
        // and the bounds the DTrace consumer gates on) before the section
        // links into the output; the verifier backstops the contract
        // read-side on every `S_DTRACE_DOF` section. The relocatable
        // conflict is `finish`'s — it sees the whole surface.
        "-dtrace" => {
            opts.config.dtrace = true;
        }
        // M119: ld64's dylib module contract — `-single_module` forces the
        // dylib to be treated as a single module (the LC_DYSYMTAB module
        // table has one entry, and all undefineds must resolve at link time
        // or ride the flat/weak lookup — unresolved strong symbols refuse
        // the link with the symbol named); `-multi_module` is the default
        // (the legacy zero-module table peregrine always carried, every
        // pre-knob link byte-identical). The relocatable conflict is
        // `finish`'s — it sees the whole surface.
        "-single_module" => {
            opts.config.module_policy = pgr_core::resolve::ModulePolicy::SingleModule;
        }
        "-multi_module" => {
            opts.config.module_policy = pgr_core::resolve::ModulePolicy::MultiModule;
        }
        // M121: ld64's `-warn_duplicate` — the duplicate-symbol advisory
        // face. Distinct from `-multiply_defined warning` (which changes
        // the resolution policy to first-wins), the advisory tallies the
        // duplicate strong definitions found during Pass 2 resolve and the
        // exit policy prints them as warnings, still exiting 0 — the
        // resolution policy itself is unchanged (the default `error` still
        // applies unless overridden). The relocatable conflict is
        // `finish`'s — it sees the whole surface.
        "-warn_duplicate" => {
            opts.config.warn_duplicate = true;
        }
        // M99: the named output UUID — the other half of the M32
        // suppression. ld64's `-uuid <uuid>` names the image's identity:
        // the 8-4-4-4-12 hex form validates here (36 chars, hyphens at
        // 8/13/18/23, case-insensitive hex — malformed refuses with the
        // fix), the parsed 16 bytes ride the config, and the emit
        // two-pass patch writes them instead of deriving. The surface
        // conflicts (`-no_uuid` × `-uuid`, the relocatable output) are
        // `finish`'s — it sees the whole surface.
        "-uuid" => {
            let v = next_value(args, i, arg)?;
            let bytes = parse_named_uuid(&v).map_err(|message| OptsError::UuidValue {
                raw: v.clone(),
                message,
            })?;
            opts.config.named_uuid = Some(bytes);
        }
        // M33: the private-extern decision. The flag rode the surface
        // as an accepted no-op since M1; the symtab build reads it —
        // an input `N_PEXT` definition stays external (`N_EXT | N_SECT
        // | N_PEXT`, exported) instead of converting into a local. A
        // boolean knob with no output-kind conflict.
        "-keep_private_externs" => {
            opts.config.keep_private_externs = true;
        }
        // M36: the compact-unwind suppression. ld64's flag; the surface
        // refused it as unknown until now — the carriage reads the
        // decision, and the output's `__TEXT,__unwind_info` section
        // drops (the pre-M34 bytes exactly). The parse still validates
        // the table — the knob is a Pass-3 decision, never a parse
        // blindfold. A boolean knob with no output-kind conflict.
        // M38: the install-name auto-floor — the reserved header region
        // grows by every load command's room to the longest install
        // name; the floor composes with `-headerpad` (both minimums).
        "-headerpad_max_install_names" => {
            opts.config.header_pad_max_install_names = true;
        }
        "-no_compact_unwind" => {
            opts.config.compact_unwind = false;
        }
        // M40: the export-trie suppression. ld64's flag — the last
        // always-carried `__LINKEDIT` command the surface could not
        // name; the header assembly reads the decision — the output's
        // `LC_DYLD_EXPORTS_TRIE` command drops (no `__LINKEDIT` slot,
        // no trie bytes). A boolean knob; the knob is an executable
        // decision (a dylib's trie is its two-level contract, a
        // bundle's the dlopen surface), so the output-kind conflict is
        // `finish`'s — it sees the whole surface, the re-export
        // conflict included (REEXPORT nodes ride the trie).
        "-no_exported_symbols" => {
            opts.config.exported_symbols = false;
        }
        // M41: the dedup toggle. The flag rode the surface as an
        // accepted no-op since M7; the layout's piece builder reads the
        // decision — identical literals stop merging, every input
        // `__cstring` section rides verbatim (the pre-D4 shape). A
        // boolean knob with no output-kind conflict (the relocatable
        // output never engaged the merge).
        "-no_deduplicate" => {
            opts.config.deduplicate = false;
        }
        // M42: the unused-dylib drop. ld64's flag — previously unknown,
        // now the Pass-2 decision the resolve reads: every input dylib
        // no referenced name binds against leaves the header, the kept
        // list compacts the two-level ordinals. The surface conflicts
        // (the relocatable output, flat namespace) are `finish`'s — it
        // sees the whole surface.
        "-dead_strip_dylibs" => {
            opts.config.dead_strip_dylibs = true;
        }
        // M46: the export-dynamic roots — every global definition in a
        // main executable roots the dead-strip mark phase (the `dlsym`
        // surface). The surface conflicts (dylib, bundle, the relocatable
        // output) are `finish`'s — it sees the whole surface.
        "-export_dynamic" => {
            opts.config.export_dynamic = true;
        }
        // M47: the branch-island suppression — ld64's knob (`on` by
        // default) rides the Pass-3 fixed point: the layout stops
        // planning veneers, and an out-of-range branch the ±128 MiB
        // `imm26` window cannot reach refuses the link with the site
        // named. There is no output-kind conflict (the relocatable
        // output resolves no branches, so the decision is inert there —
        // the M41/M43 shape).
        "-no_branch_islands" => {
            opts.config.branch_islands = false;
        }
        // M48: the dylib initializer — ld64's `-init <symbol>` names
        // the load-time initializer dyld calls when the image loads
        // (the LC_ROUTINES_64 command; the name resolves like the
        // entry seam's). The output-kind conflicts (executable, bundle,
        // the relocatable output) are `finish`'s — it sees the whole
        // surface.
        "-init" => {
            let v = next_value(args, i, arg)?;
            opts.config.init_symbol = Some(v);
        }
        // M98: the dylib terminator — the sibling of the M48
        // initializer (`-term <symbol>` names the load-time terminator
        // dyld calls when the image unloads; the resolved address rides
        // the SAME LC_ROUTINES_64, one command two fields). The
        // output-kind conflicts (executable, bundle, the relocatable
        // output) are `finish`'s — it sees the whole surface.
        "-term" => {
            let v = next_value(args, i, arg)?;
            opts.config.term_symbol = Some(v);
        }
        // M50: the weak-import refusal — ld64's `-no_weak_imports`
        // turns the weak reference's runtime-lookup fallthrough into a
        // typed refusal (the resolve's undefined walk reads the
        // decision; a link-time resolution never refuses). The
        // relocatable output never reads it — its undefineds stay open.
        "-no_weak_imports" => {
            opts.config.no_weak_imports = true;
        }
        // M24: the symbol aliases, M101 the file form. The same
        // validation the core seam pays runs here, so the refusal names
        // the grammar; each occurrence records one ordered source (the
        // M101 compose list — pairs and files compose into the ONE
        // alias table in flag order at link time), and the output kind
        // conflict is `finish`'s (it sees the whole surface). A
        // repeated alias name across the flag occurrences refuses at
        // the parse (one decision per name, the M24 contract); a file
        // pair's duplicate is the link-time composition's (the file
        // content is not parse-known).
        "-alias" => {
            let alias = next_value(args, i, arg)?;
            let definition = next_value(args, i, arg)?;
            let a = pgr_core::Alias::from_parts(&alias, &definition).map_err(|e| {
                OptsError::AliasValue {
                    raw: format!("{alias} {definition}"),
                    message: e.to_string(),
                }
            })?;
            if opts
                .alias_sources
                .iter()
                .any(|s| matches!(s, AliasSource::Pair { alias: p } if p.alias() == a.alias()))
            {
                let raw = format!("{alias} {definition}");
                return Err(OptsError::AliasValue {
                    raw,
                    message: pgr_core::AliasError::Duplicate {
                        name: a.alias().to_string(),
                    }
                    .to_string(),
                });
            }
            opts.alias_sources.push(AliasSource::Pair { alias: a });
        }
        // M101: the alias list file — the file form of M24's `-alias`.
        // One `alias definition` pair per line (the house list-file
        // grammar: blank lines and `#` comments skip); the pairs ride
        // the ordered source list and compose beside the `-alias`
        // flags. The file is read (and its pairs validated) at link
        // time, the M11/M14 convention.
        "-alias_list" => {
            let v = next_value(args, i, arg)?;
            opts.alias_sources.push(AliasSource::ListFile { path: v });
        }
        // M25: the bundle's host. The path is scanned at link time (the
        // host's export trie is the surface the linker itself emits);
        // the output-kind conflict is `finish`'s (it sees the whole
        // surface).
        "-bundle_loader" => {
            let v = next_value(args, i, arg)?;
            opts.bundle_loader = Some(v);
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
        _ if arg.starts_with("-needed-l") && arg.len() > 9 => {
            // M106: the attached form of `-needed-l` (ld64's
            // `-needed-l<name>`) — the basename rides the `-L` search
            // carrying the needed-dylib mark (a library request like
            // `-l`'s, the mark rides the resolved dylib).
            let name = arg[9..].to_string();
            opts.libs.push(name.clone());
            opts.needed_libs.push(name);
        }
        _ if arg.starts_with("-hidden-l") && arg.len() > 9 => {
            // M110: the attached form of `-hidden-l` (ld64's
            // `-hidden-l<name>`) — the basename rides the `-L` search
            // carrying the hidden-dylib mark (a library request like
            // `-l`'s, the mark rides the resolved dylib).
            let name = arg[9..].to_string();
            opts.libs.push(name.clone());
            opts.hidden_libs.push(name);
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
    // M73: the verify gate is an image-output decision. `-r` produces an
    // `MH_OBJECT` — the verifier's object face gates it as a tool, never
    // a link gate — and the relink ladder carries its own gate (the §7.3
    // audit, `-incremental-verify`; its subject is the patch, the cold
    // gate's subject is the image). An explicitly named knob that cannot
    // apply is a refusal, never a silently dropped one.
    if opts.verify {
        if opts.config.filetype == pgr_core::layout::OutputType::Relocatable {
            return Err(OptsError::VerifyConflict {
                verdict: "-verify gates an image, but the relocatable output is an object".into(),
                fix: "drop -verify or link a segmented output (an executable, dylib or \
                      bundle); gate the object with pgr-verify itself"
                    .into(),
            });
        }
        if opts.incremental {
            return Err(OptsError::VerifyConflict {
                verdict: "-verify and -incremental name two gates for one image".into(),
                fix: "the relink ladder's gate is -incremental-verify (the §7.3 audit); \
                      use it, or drop -incremental for the cold link's gate"
                    .into(),
            });
        }
    }
    // M77: a selection without a gate is dead weight — the families
    // narrow the gate, never the link. The refusal names the gate the
    // selection means (the selection itself, rendered in the selector's
    // canonical order).
    if let Some(set) = opts.verify_checks {
        if !opts.verify {
            return Err(OptsError::VerifyConflict {
                verdict: format!("-verify-checks ({set}) names a selection but no gate to narrow"),
                fix: "pass -verify (the strict pass the families narrow); the \
                      selection rides beside the gate on the cold and resident \
                      lanes alike"
                    .into(),
            });
        }
    }
    // M10 rung 4, slice 2: the requested word family must be encodable
    // where it is requested — a refusal, never a silently dropped knob.
    // M82: the resident lane serves the family (the v6 wire byte has
    // mirrored it since M10; the session's warm pipeline plans it, the
    // record carries it, and the relink ladders admit through it — a
    // family flip relinks through the full link), so the only remaining
    // refusal is the classic opcode path's.
    if opts.config.chain_word_format == FixupPointerFormat::Arm64e && !opts.config.fixup_chains {
        return Err(OptsError::ChainFormatConflict {
            verdict: "the classic opcode streams have no chain words to shape".into(),
            fix: "drop -fixup_chains_format or re-enable chained fixups".into(),
        });
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
    // M28: the section-alignment floors are a packing-engine decision —
    // `-r` preserves input sections verbatim and plans no segments (the
    // M10 rung-1 contract), so a named floor has nothing to land on. An
    // explicitly named knob that cannot apply is a refusal, never a
    // silently dropped one; the staged decisions then insert into the
    // config, where the core seam refuses a twice-named pair.
    if !opts.sect_align_stage.is_empty()
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::SectAlignConflict {
            verdict: "-sectalign names a packing-engine alignment floor, but the \
                      relocatable output plans no segments and carries its input \
                      sections verbatim"
                .into(),
            fix: "drop -sectalign or link a segmented output (an executable, dylib or \
                  bundle)"
                .into(),
        });
    }
    for decision in opts.sect_align_stage.drain(..) {
        if let Err(err) = opts.config.sect_aligns.push(decision) {
            return Err(OptsError::SectAlignConflict {
                verdict: err.to_string(),
                fix: "one -sectalign per (segment, section)".into(),
            });
        }
    }
    // M29: the header-region floor is a segmented-output decision —
    // `-r` preserves input sections verbatim and plans no segments (the
    // M10 rung-1 contract), so a named floor has nothing to land on.
    // An explicitly named knob that cannot apply is a refusal, never a
    // silently dropped one; the flag the surface carried as an advisory
    // no-op since M1 now names the decision the packing loop reads.
    if opts.headerpad_explicit {
        if opts.config.filetype == pgr_core::layout::OutputType::Relocatable {
            return Err(OptsError::HeaderPadConflict {
                verdict: "-headerpad reserves the header region the load commands \
                          occupy, but the relocatable output plans no segments and \
                          carries its input sections verbatim"
                    .into(),
                fix: "drop -headerpad or link a segmented output (an executable, dylib \
                      or bundle)"
                    .into(),
            });
        }
        opts.config.header_pad = Some(
            pgr_core::header_pad::HeaderPad::from_override(opts.headerpad).map_err(|e| {
                OptsError::HeaderPadValue {
                    value: format!("{:#x}", opts.headerpad),
                    message: e.to_string(),
                }
            })?,
        );
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
    // M124: the first segment's base address is an executable/dylib
    // decision — a bundle's preferred load address is its loader's job
    // (the host process `dlopen`s the bundle and maps it where it
    // chooses), and the relocatable output carries no segments. One
    // base knob per output kind, never two: `-seg1addr` beside
    // `-pagezero_size` (an executable) or `-image_base` (a dylib) names
    // the same `__TEXT` floor twice. An explicitly named knob that
    // cannot apply — or that names a floor another knob already named
    // — is a refusal, never a silently dropped one (the library's
    // re-checks back this so no caller can plan the shape either).
    if opts.seg1addr_explicit {
        use pgr_core::layout::OutputType as Ot;
        match opts.config.filetype {
            Ot::Bundle => {
                return Err(OptsError::Seg1AddrConflict {
                    verdict: "-seg1addr names the first segment's base address, but \
                              a bundle's preferred load address is its loader's job"
                        .into(),
                    fix: "the host process dlopens the bundle and maps it where it \
                          chooses: link an executable or a dylib, or drop -seg1addr"
                        .into(),
                });
            }
            Ot::Relocatable => {
                return Err(OptsError::Seg1AddrConflict {
                    verdict: "-seg1addr names the first segment's base address, but \
                              the relocatable output carries no segments"
                        .into(),
                    fix: "drop -seg1addr or link an executable or a dylib".into(),
                });
            }
            Ot::Execute | Ot::Dylib => {}
        }
        if opts.pagezero_explicit && opts.config.filetype == Ot::Execute {
            return Err(OptsError::Seg1AddrConflict {
                verdict: "-seg1addr and -pagezero_size both name the executable's \
                          __TEXT base address"
                    .into(),
                fix: "one base knob per output kind: drop -pagezero_size or \
                      -seg1addr and relink"
                    .into(),
            });
        }
        if opts.image_base_explicit && opts.config.filetype == Ot::Dylib {
            return Err(OptsError::Seg1AddrConflict {
                verdict: "-seg1addr and -image_base both name the dylib's __TEXT \
                          base address"
                    .into(),
                fix: "one base knob per output kind: drop -image_base or -seg1addr \
                      and relink"
                    .into(),
            });
        }
    }
    // M125: the CPU subtype override is a segmented-output decision —
    // the `mach_header_64.cpusubtype` word is the producer's to name
    // (an executable, a dylib or a bundle all carry the header the
    // layout emits), but the relocatable output's header is the input's,
    // verbatim (the M10 rung-1 contract — the object is itself a link
    // input, its cpusubtype word rides untouched). An explicitly named
    // knob that cannot apply is a refusal, never a silently dropped one
    // (the library's re-checks back this so no caller can plan the
    // shape either — the M104/M105/M117 refusal shape, one header word
    // over). The knob is byte-identity on the segmented path (the
    // default already writes CPU_SUBTYPE_ARM64_ALL), so the `-r`
    // refusal is the only shape the knob can break.
    if opts.config.force_cpusubtype_all
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::ForceCpuSubtypeConflict {
            verdict: "-force_cpusubtype_ALL forces the output's cpusubtype to \
                      CPU_SUBTYPE_ARM64_ALL, but the relocatable output's header is \
                      the input's, verbatim"
                .into(),
            fix: "drop -force_cpusubtype_ALL or link a final image (an executable, \
                  a dylib or a bundle)"
                .into(),
        });
    }
    // M126: the output image's atomization decision — the
    // `MH_SUBSECTIONS_VIA_SYMBOLS` bit is the producer's to name (an
    // executable, a dylib or a bundle all carry the header the layout
    // emits), but the relocatable output's header is the input's,
    // verbatim (the M10 rung-1 contract — the object is itself a link
    // input, its flags word rides untouched). The default (`false`)
    // never refused before (the pre-M126 shape), so the refusal fires
    // only on the named `true` face (the M104/M105/M117 refusal shape,
    // one header word over, mirrored exactly so no library caller can
    // plan the shape either — the layout's re-check and `link_reloc`
    // back this).
    if opts.config.subsections_via_symbols
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::SubsectionsViaSymbolsConflict {
            verdict: "-allow_subsections_via_symbols sets the output's \
                      MH_SUBSECTIONS_VIA_SYMBOLS bit, but the relocatable output's \
                      header is the input's, verbatim"
                .into(),
            fix: "drop -allow_subsections_via_symbols or link a final image (an \
                  executable, a dylib or a bundle)"
                .into(),
        });
    }
    // M127: the dylib's export-interposability decision — the knob is a
    // dylib's decision (an executable's identity is `LC_MAIN` — the
    // kernel loads it; a bundle dlopens without an export table to
    // interpose; the relocatable output's header is the input's,
    // verbatim). The M104/M105/M117 refusal shape, mirrored exactly so
    // no library caller can plan the shape either. The default (`false`)
    // never refused before (the pre-M127 shape), so the refusal fires
    // only on the named `true` face.
    if opts.config.interposable && opts.config.filetype != pgr_core::layout::OutputType::Dylib {
        let (verdict, fix) = match opts.config.filetype {
            pgr_core::layout::OutputType::Execute => (
                "-interposable marks a dylib's exports as interposable, but \
                 this output is an executable"
                    .into(),
                "an executable's identity is LC_MAIN (the kernel loads it), \
                 not an export table to interpose: link a dylib (-dylib) or \
                 drop -interposable"
                    .into(),
            ),
            pgr_core::layout::OutputType::Bundle => (
                "-interposable marks a dylib's exports as interposable, but \
                 this output is a bundle"
                    .into(),
                "a bundle dlopens without an export table to interpose: link \
                 a dylib (-dylib) or drop -interposable"
                    .into(),
            ),
            _ => (
                "-interposable marks a dylib's exports as interposable, but \
                 the relocatable output's header is the input's, verbatim"
                    .into(),
                "drop -interposable or link a dylib".into(),
            ),
        };
        return Err(OptsError::InterposableConflict { verdict, fix });
    }
    // M128: the app-extension-safe decision — the
    // `MH_APP_EXTENSION_SAFE` bit is the producer's to name (an
    // executable, a dylib or a bundle all carry the header the layout
    // emits), but the relocatable output's header is the input's,
    // verbatim (the M10 rung-1 contract — the object is itself a link
    // input, its flags word rides untouched). The default (`false`)
    // never refused before (the pre-M128 shape), so the refusal fires
    // only on the named `true` face (the M104/M105/M117 refusal shape,
    // one header word over, mirrored exactly so no library caller can
    // plan the shape either — the layout's re-check and `link_reloc`
    // back this).
    if opts.config.application_extension
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::ApplicationExtensionConflict {
            verdict: "-application_extension sets the output's \
                      MH_APP_EXTENSION_SAFE bit, but the relocatable output's \
                      header is the input's, verbatim"
                .into(),
            fix: "drop -application_extension or link a final image (an \
                  executable, a dylib or a bundle)"
                .into(),
        });
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
    // M44: `-final_output` is a dylib's identity default — the same
    // refusal shape as the M20 region above: an explicitly named knob
    // that cannot apply is a refusal, never a silently dropped one.
    if opts.final_output.is_some() {
        use pgr_core::layout::OutputType as Ot;
        match opts.config.filetype {
            Ot::Execute => {
                return Err(OptsError::FinalOutputConflict {
                    verdict: "-final_output names a dylib's install-name default, \
                              but this output is an executable"
                        .into(),
                    fix: "the identity rides LC_MAIN: link a dylib (-dylib) or \
                          drop -final_output"
                        .into(),
                });
            }
            Ot::Bundle => {
                return Err(OptsError::FinalOutputConflict {
                    verdict: "-final_output names a dylib's install-name default, \
                              but this output is a bundle"
                        .into(),
                    fix: "bundles dlopen without an install-name identity: link a \
                          dylib (-dylib) or drop -final_output"
                        .into(),
                });
            }
            Ot::Relocatable => {
                return Err(OptsError::FinalOutputConflict {
                    verdict: "-final_output names a dylib's install-name default, \
                              but the relocatable output carries no identity commands"
                        .into(),
                    fix: "drop -final_output or link a dylib (-dylib)".into(),
                });
            }
            Ot::Dylib => {}
        }
    }
    // M21: the client list is a dylib's identity block — the same
    // refusal shape as the M20 region above: an explicitly named knob
    // that cannot apply is a refusal, never a silently dropped one.
    if !opts.config.sub_clients.is_empty() {
        use pgr_core::layout::OutputType as Ot;
        match opts.config.filetype {
            Ot::Execute => {
                return Err(OptsError::SubClientConflict {
                    verdict: "-sub_client names an identity-block dylib's allowed clients, \
                              but this output is an executable"
                        .into(),
                    fix: "the clients ride LC_ID_DYLIB's identity block: link a dylib \
                          (-dylib) or drop the flag"
                        .into(),
                });
            }
            Ot::Bundle => {
                return Err(OptsError::SubClientConflict {
                    verdict: "-sub_client names an identity-block dylib's allowed clients, \
                              but this output is a bundle"
                        .into(),
                    fix: "bundles dlopen without sub commands: link a dylib \
                          (-dylib) or drop the flag"
                        .into(),
                });
            }
            Ot::Relocatable => {
                return Err(OptsError::SubClientConflict {
                    verdict: "-sub_client names an identity-block dylib's allowed clients, \
                              but the relocatable output carries no identity commands"
                        .into(),
                    fix: "drop the flag or link a dylib (-dylib)".into(),
                });
            }
            Ot::Dylib => {}
        }
    }
    // M25: only a bundle binds against a host — the same refusal shape
    // as the M22/M24 conflicts above: an explicitly named knob that
    // cannot apply is a refusal, never a silently dropped one.
    if opts.bundle_loader.is_some() && opts.config.filetype != pgr_core::layout::OutputType::Bundle
    {
        let (verdict, fix) = match opts.config.filetype {
            pgr_core::layout::OutputType::Execute => (
                "-bundle_loader binds a bundle against its host process, but this \
                 output is an executable",
                "drop -bundle_loader (an executable is the host) or link a bundle",
            ),
            pgr_core::layout::OutputType::Dylib => (
                "-bundle_loader binds a bundle against its host process, but this \
                 output is a dylib",
                "drop -bundle_loader or link a bundle",
            ),
            pgr_core::layout::OutputType::Relocatable => (
                "-bundle_loader binds a bundle against its host process, but the \
                 relocatable output opens its undefineds by design",
                "drop -bundle_loader or link a bundle",
            ),
            pgr_core::layout::OutputType::Bundle => unreachable!("guarded above"),
        };
        return Err(OptsError::BundleLoaderConflict {
            verdict: verdict.into(),
            fix: fix.into(),
        });
    }
    // M24: an alias is an image-surface decision — the relocatable
    // output carries the input symtab verbatim, so a named pair has no
    // symtab row to grow — the same refusal shape as the M22
    // environment above: an explicitly named knob that cannot apply is
    // a refusal, never a silently dropped one. M101: the file form
    // rides the same contract (the source list, flag or file, is the
    // knob's presence).
    if !opts.alias_sources.is_empty()
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::AliasConflict {
            verdict: "-alias exports additional names through the image symtab, but the \
                      relocatable output carries the input symtab verbatim"
                .into(),
            fix: "drop -alias or link an image (executable, dylib, bundle)".into(),
        });
    }
    // M22: the dyld environment is an executable decision — dyld reads
    // `LC_DYLD_ENVIRONMENT` from the main executable only — the same
    // refusal shape as the M18 reserve above: an explicitly named knob
    // that cannot apply is a refusal, never a silently dropped one.
    if !opts.config.dyld_envs.is_empty() {
        use pgr_core::layout::OutputType as Ot;
        match opts.config.filetype {
            Ot::Dylib => {
                return Err(OptsError::DyldEnvConflict {
                    verdict: "-dyld_env exports DYLD_* variables through the loader, \
                              but this output is a dylib"
                        .into(),
                    fix: "dyld reads LC_DYLD_ENVIRONMENT from the main executable only: \
                          link an executable or drop the flag"
                        .into(),
                });
            }
            Ot::Bundle => {
                return Err(OptsError::DyldEnvConflict {
                    verdict: "-dyld_env exports DYLD_* variables through the loader, \
                              but this output is a bundle"
                        .into(),
                    fix: "dyld reads LC_DYLD_ENVIRONMENT from the main executable only: \
                          link an executable or drop the flag"
                        .into(),
                });
            }
            Ot::Relocatable => {
                return Err(OptsError::DyldEnvConflict {
                    verdict: "-dyld_env exports DYLD_* variables through the loader, but \
                              the relocatable output carries no loader commands"
                        .into(),
                    fix: "drop the flag or link an executable".into(),
                });
            }
            Ot::Execute => {}
        }
    }
    // M39: the make-undefined marks are a Pass-2 decision — the
    // relocatable output opens its undefineds by design and carries its
    // input symbol table verbatim, so a mark has nothing to strip. An
    // explicitly named knob that cannot apply is a refusal, never a
    // silently dropped one (the library's `link_reloc` re-checks so no
    // caller can plan the shape either).
    if !opts.config.make_undefined.is_empty()
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::MakeUndefinedConflict {
            verdict: "-U marks a defined symbol undefined, but the relocatable output \
                      opens its undefineds by design and carries its input symbol table \
                      verbatim"
                .into(),
            fix: "drop -U or link an image (an executable, dylib or bundle)".into(),
        });
    }
    // M26: the loader path is an executable decision —
    // `LC_LOAD_DYLINKER` is the main-executable command (the §8.2
    // loader-configuration adjacency), the same refusal shape as the
    // M22 environment above: an explicitly named knob that cannot
    // apply is a refusal, never a silently dropped one.
    if opts.config.dylinker.is_some() {
        use pgr_core::layout::OutputType as Ot;
        match opts.config.filetype {
            Ot::Dylib => {
                return Err(OptsError::DylinkerConflict {
                    verdict: "-dylinker names the loader LC_LOAD_DYLINKER execs, \
                              but this output is a dylib"
                        .into(),
                    fix: "the kernel loads a dylib itself — only the main executable \
                          carries LC_LOAD_DYLINKER: link an executable or drop the flag"
                        .into(),
                });
            }
            Ot::Bundle => {
                return Err(OptsError::DylinkerConflict {
                    verdict: "-dylinker names the loader LC_LOAD_DYLINKER execs, \
                              but this output is a bundle"
                        .into(),
                    fix: "the kernel loads a bundle itself — only the main executable \
                          carries LC_LOAD_DYLINKER: link an executable or drop the flag"
                        .into(),
                });
            }
            Ot::Relocatable => {
                return Err(OptsError::DylinkerConflict {
                    verdict: "-dylinker names the loader LC_LOAD_DYLINKER execs, but \
                              the relocatable output carries no loader commands"
                        .into(),
                    fix: "drop the flag or link an executable".into(),
                });
            }
            Ot::Execute => {}
        }
    }
    // M27: the PIE decision is an executable decision — `MH_PIE` is
    // the executable-only bit (the kernel loads a dylib or a bundle
    // itself), the same refusal shape as the M18 reserve above: an
    // explicitly named knob that cannot apply is a refusal, never a
    // silently dropped one.
    if opts.config.no_pie {
        use pgr_core::layout::OutputType as Ot;
        match opts.config.filetype {
            Ot::Dylib | Ot::Bundle | Ot::Relocatable => {
                return Err(OptsError::NoPieConflict {
                    verdict: "-no_pie clears the executable's MH_PIE flag, but this \
                              output is not an executable"
                        .into(),
                    fix: "MH_PIE is an executable-only bit — the kernel loads a dylib \
                          or a bundle itself: link an executable or drop the flag"
                        .into(),
                });
            }
            Ot::Execute => {}
        }
    }
    // M122: the PIE positive-form twin — the `-pie` knob is the
    // explicit-decision mirror of the M27 `-no_pie` pair, and the same
    // executable-only contract holds (the kernel loads a dylib or a
    // bundle itself, the relocatable output carries no loader
    // semantics). The refusal shape is the M27 refusal mirrored
    // exactly: an explicitly named knob that cannot apply is a refusal,
    // never a silently dropped one.
    if opts.config.pie {
        use pgr_core::layout::OutputType as Ot;
        match opts.config.filetype {
            Ot::Dylib | Ot::Bundle | Ot::Relocatable => {
                return Err(OptsError::PieConflict {
                    verdict: "-pie sets the executable's MH_PIE flag, but this \
                              output is not an executable"
                        .into(),
                    fix: "MH_PIE is an executable-only bit — the kernel loads a dylib \
                          or a bundle itself: link an executable or drop the flag"
                        .into(),
                });
            }
            Ot::Execute => {}
        }
    }
    // M51: the stack-execution decision is an executable decision —
    // `MH_ALLOW_STACK_EXECUTION` is the executable-only bit (the kernel
    // loads a dylib or a bundle itself), the same refusal shape as the
    // M27 PIE decision above: an explicitly named knob that cannot
    // apply is a refusal, never a silently dropped one.
    if opts.config.allow_stack_execute {
        use pgr_core::layout::OutputType as Ot;
        match opts.config.filetype {
            Ot::Dylib | Ot::Bundle | Ot::Relocatable => {
                return Err(OptsError::StackExecConflict {
                    verdict: "-allow_stack_execute sets the executable's \
                              MH_ALLOW_STACK_EXECUTION flag, but this output is \
                              not an executable"
                        .into(),
                    fix: "MH_ALLOW_STACK_EXECUTION is an executable-only bit — the \
                          kernel loads a dylib or a bundle itself: link an \
                          executable or drop the flag"
                        .into(),
                });
            }
            Ot::Execute => {}
        }
    }
    // M102: the bind-at-load decision is an executable decision —
    // `MH_BINDATLOAD` is the executable-only bit (dyld binds the exec'd
    // main executable's undefineds before `main` runs), the same refusal
    // shape as the M27 PIE and M51 stack-execution decisions above: an
    // explicitly named knob that cannot apply is a refusal, never a
    // silently dropped one.
    if opts.config.bind_at_load {
        use pgr_core::layout::OutputType as Ot;
        match opts.config.filetype {
            Ot::Dylib | Ot::Bundle | Ot::Relocatable => {
                return Err(OptsError::BindAtLoadConflict {
                    verdict: "-bind_at_load sets the executable's MH_BINDATLOAD flag, \
                              but this output is not an executable"
                        .into(),
                    fix: "MH_BINDATLOAD is an executable-only bit — dyld binds the \
                          exec'd main executable's undefineds before main runs: link an \
                          executable or drop the flag"
                        .into(),
                });
            }
            Ot::Execute => {}
        }
    }
    // M103: the non-escalating undefined policies are a load-time-bind
    // decision — the relocatable output's undefineds stay open in its
    // symbol table by design (an object carries no load-time bind to
    // warn or suppress), the same refusal shape as the M39 make-undefined
    // marks above: an explicitly named knob that cannot apply is a
    // refusal, never a silently dropped one.
    if matches!(
        opts.config.undefined_policy,
        pgr_core::resolve::UndefinedPolicy::Warning | pgr_core::resolve::UndefinedPolicy::Suppress
    ) && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::UndefinedPolicyConflict {
            verdict: "-undefined warning|suppress names the load-time bind's exit \
                      policy, but the relocatable output's undefineds stay open by \
                      design"
                .into(),
            fix: "an object has no load-time bind to warn or suppress: drop -undefined \
                  or link an image (an executable, dylib or bundle)"
                .into(),
        });
    }
    // M104: the symtab-shaping decision's drop face (`-x`) is a final
    // image decision — the relocatable output's symtab is the input's,
    // verbatim (an object carries its inputs' tables untouched), the
    // same refusal shape as the M103 policy faces above: an explicitly
    // named knob that cannot apply is a refusal, never a silently
    // dropped one. The keep face is the default's mirror and never
    // refuses.
    if !opts.config.keep_local_symbols
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::LocalSymbolsConflict {
            verdict: "-x drops the output's plain local symbols, but the relocatable \
                      output's symtab is the input's, verbatim"
                .into(),
            fix: "an object carries its inputs' symbol tables untouched — there is no \
                  locals subrange to shape: drop -x or link an image (an executable, \
                  dylib or bundle)"
                .into(),
        });
    }
    // M105: the debug-section suppression's `-S` face is a final image
    // decision — the relocatable output's sections are the input's,
    // verbatim (an object carries its inputs' sections untouched), the
    // same refusal shape as the M104 drop face above: an explicitly
    // named knob that cannot apply is a refusal, never a silently
    // dropped one.
    if opts.config.strip_debug && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::StripDebugConflict {
            verdict: "-S drops the output's debug sections, but the relocatable \
                      output's sections are the input's, verbatim"
                .into(),
            fix: "an object carries its inputs' sections untouched — there is no debug \
                  classification to apply: drop -S or link an image (an executable, \
                  dylib or bundle)"
                .into(),
        });
    }
    // M107: the non-default commons policies are a final-image decision
    // — the relocatable output's symtab is the input's, verbatim (an
    // object carries its inputs' tables untouched — there is no
    // tentative fate to decide). The default never refuses (the
    // pre-M107 shape). An explicitly named policy that cannot apply is
    // a refusal, never a silently dropped one (the library's re-checks
    // back this so no caller can plan the shape either).
    if opts.config.commons != pgr_core::resolve::CommonsPolicy::UseDylibs
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::CommonsPolicyConflict {
            verdict: format!(
                "-commons {} decides a tentative definition's fate against the linked \
                 dylibs, but the relocatable output's symtab is the input's, verbatim",
                opts.config.commons.flag_word()
            ),
            fix: "an object carries its inputs' symbol tables untouched — there is no \
                  tentative to decide about: drop -commons or link an image (an \
                  executable, dylib or bundle)"
                .into(),
        });
    }
    // M108: the non-default multiply-defined policies are a final-image
    // decision — the relocatable output's symtab is the input's, verbatim
    // (an object carries its inputs' tables untouched — there is no
    // winner to decide about). The default never refuses (the pre-M108
    // shape). An explicitly named policy that cannot apply is a refusal,
    // never a silently dropped one (the library's re-checks back this so
    // no caller can plan the shape either).
    if opts.config.multiply_defined != pgr_core::resolve::MultiplyDefinedPolicy::Error
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::MultiplyDefinedPolicyConflict {
            verdict: format!(
                "-multiply_defined {} decides which definition wins a duplicated name, \
                 but the relocatable output's symtab is the input's, verbatim",
                opts.config.multiply_defined.flag_word()
            ),
            fix: "an object carries its inputs' symbol tables untouched — there is no \
                  winner to decide about: drop -multiply_defined or link an image (an \
                  executable, dylib or bundle)"
                .into(),
        });
    }
    // M109: the warnings-as-errors exit decision is a final-image decision
    // — the relocatable output's shape is the input's, verbatim, and
    // every advisory face that would warn beside `-r` is already refused
    // there (the M103/M108 refusals: an object has no load-time bind to
    // warn about, no winner to decide about), so there is nothing left to
    // elevate. The default and its explicit mirror never refuse. An
    // explicitly named escalation that cannot apply is a refusal, never a
    // silently dropped one (the library's re-checks back this so no
    // caller can plan the shape either).
    if opts.config.fatal_warnings
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::FatalWarningsConflict {
            verdict: "-fatal_warnings elevates the advisory faces' warnings to a failed \
                      link, but the relocatable output's shape is the input's, verbatim"
                .into(),
            fix: "every advisory face is already refused beside -r — there is nothing \
                  left to elevate: drop -fatal_warnings or link an image (an executable, \
                  dylib or bundle)"
                .into(),
        });
    }
    // M133: the advisory faces' print-suppression surface conflict. The
    // knob is a print-face decision — the relocatable output's shape is
    // the input's, verbatim (every advisory face that would warn beside
    // -r is already refused there), so there is nothing left to
    // suppress. The default never refuses (the pre-M133 shape). An
    // explicitly named knob that cannot apply is a refusal, never a
    // silently dropped one (the library's re-checks back this so no
    // caller can plan the shape either).
    if opts.config.suppress_warnings
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::WarnSuppressConflict {
            verdict: "-w suppresses the advisory faces' warnings, but the relocatable \
                      output's shape is the input's, verbatim"
                .into(),
            fix: "every advisory face is already refused beside -r — there is nothing \
                  left to suppress: drop -w or link an image (an executable, dylib or \
                  bundle)"
                .into(),
        });
    }
    // M112: the link-statistics report is a final-image decision — the
    // relocatable output has no full-emit layout or fixup planning to
    // report in the same way (the object walk plans no segments, no
    // fixup slots and emits no image the report's counts name). The
    // default never refuses (the pre-M112 shape). An explicitly named
    // knob that cannot apply is a refusal, never a silently dropped one
    // (the library's re-checks back this so no caller can plan the shape
    // either).
    if opts.config.print_statistics
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::PrintStatisticsConflict {
            verdict: "-print_statistics reports the link's statistics, but the relocatable \
                      output has no full-emit layout or fixup planning to report in the \
                      same way"
                .into(),
            fix: "drop -print_statistics or link an image (an executable, dylib or \
                  bundle)"
                .into(),
        });
    }
    // M113: the reference trace's surface conflict. The knob is a
    // resolve-shaping decision — the relocatable output's symtab is the
    // input's, verbatim (its symbol table rides the inputs untouched;
    // there is no Pass-2 trace to report). An explicitly named knob that
    // cannot apply is a refusal, never a silently dropped one (the
    // library's re-checks back this so no caller can plan the shape
    // either).
    if opts.config.trace_refs && opts.config.filetype == pgr_core::layout::OutputType::Relocatable {
        return Err(OptsError::TraceRefsConflict {
            verdict: "-t traces the symbols Pass 2's resolve references, but the \
                      relocatable output's symtab is the input's, verbatim"
                .into(),
            fix: "drop -t or link an image (an executable, dylib or bundle)".into(),
        });
    }
    // M115: the category-merge disable's surface conflict — the
    // relocatable output's sections are the input's, verbatim (an
    // object carries its inputs' sections untouched; there is no
    // registration to fold). An explicitly named knob that cannot
    // apply is a refusal, never a silently dropped one (the library's
    // re-checks back this so no caller can plan the shape either).
    if !opts.config.objc_category_merging
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::ObjcCategoryMergingConflict {
            verdict: "-no_objc_category_merging keeps every category's registration \
                      verbatim, but the relocatable output's sections are the input's, \
                      verbatim already"
                .into(),
            fix: "drop -no_objc_category_merging or link an image (an executable, dylib \
                  or bundle)"
                .into(),
        });
    }
    // M116: the common-symbol advisory's surface conflict — the
    // relocatable output's symtab is the input's, verbatim (there is no
    // resolution landing to advise about). An explicitly named knob that
    // cannot apply is a refusal, never a silently dropped one (the
    // library's re-checks back this so no caller can plan the shape
    // either).
    if opts.config.warn_commons && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::WarnCommonsConflict {
            verdict: "-warn_commons advises where every tentative definition resolved, \
                      but the relocatable output's symtab is the input's, verbatim"
                .into(),
            fix: "drop -warn_commons or link an image (an executable, dylib or bundle)".into(),
        });
    }
    // M117: the init/term suppression's surface conflict — the
    // relocatable output's sections are the input's, verbatim (there is
    // no init classification to apply). An explicitly named knob that
    // cannot apply is a refusal, never a silently dropped one (the
    // library's re-checks back this so no caller can plan the shape
    // either).
    if opts.config.no_inits && opts.config.filetype == pgr_core::layout::OutputType::Relocatable {
        return Err(OptsError::NoInitsConflict {
            verdict: "-no_inits drops the output's init/term sections (the \
                      __mod_init_func, __mod_term_func and __init_offsets shapes), \
                      but the relocatable output's sections are the input's, verbatim"
                .into(),
            fix: "drop -no_inits or link an image (an executable, dylib or bundle)".into(),
        });
    }
    // M118: the dtrace DOF processing's surface conflict — the
    // relocatable output's sections are the input's, verbatim (there is
    // no DOF header to validate at emit, no assembly to link). An
    // explicitly named knob that cannot apply is a refusal, never a
    // silently dropped one (the library's re-checks back this so no
    // caller can plan the shape either).
    if opts.config.dtrace && opts.config.filetype == pgr_core::layout::OutputType::Relocatable {
        return Err(OptsError::DtraceConflict {
            verdict: "-dtrace validates the output's __dtrace_dof (DOF) section \
                      headers and links them into the image, but the relocatable \
                      output's sections are the input's, verbatim"
                .into(),
            fix: "drop -dtrace or link an image (an executable, dylib or bundle)".into(),
        });
    }
    // M119: the dylib module contract's surface conflict — the
    // relocatable output's symtab is the input's, verbatim (there is no
    // LC_DYSYMTAB module table to shape, no single-module escalation to
    // apply). An explicitly named knob that cannot apply is a refusal,
    // never a silently dropped one (the library's re-checks back this so
    // no caller can plan the shape either).
    if opts.config.module_policy.is_single()
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::ModulePolicyConflict {
            verdict: "-single_module shapes the output's LC_DYSYMTAB module table \
                      and escalates unresolved strong references, but the relocatable \
                      output's symtab is the input's, verbatim"
                .into(),
            fix: "drop -single_module or link an image (an executable, dylib or bundle)".into(),
        });
    }
    // M120: the explicit executable override's surface conflict — `-r`'s
    // `MH_OBJECT` is the input's filetype verbatim (the object preserves
    // the input's shape), so `-executable` beside `-r` refuses whatever
    // order the flags arrived in. An explicitly named knob that cannot
    // apply is a refusal, never a silently dropped one (the library's
    // re-checks back this so no caller can plan the shape either).
    if opts.config.executable && opts.config.filetype == pgr_core::layout::OutputType::Relocatable {
        return Err(OptsError::ExecutableConflict {
            verdict: "-executable forces an MH_EXECUTE output, but the relocatable \
                      output's filetype is the input's, verbatim"
                .into(),
            fix: "drop -executable or drop -r (link an image)".into(),
        });
    }
    // M121: the duplicate-symbol advisory's surface conflict — the
    // relocatable output's symtab is the input's, verbatim (its symbol
    // table rides the inputs untouched; there is no resolution landing to
    // tally). An explicitly named knob that cannot apply is a refusal,
    // never a silently dropped one (the library's re-checks back this so
    // no caller can plan the shape either).
    if opts.config.warn_duplicate
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::WarnDuplicateConflict {
            verdict: "-warn_duplicate tallies the duplicate strong definitions found \
                      during resolve, but the relocatable output's symtab is the \
                      input's, verbatim"
                .into(),
            fix: "drop -warn_duplicate or link an image (an executable, dylib or bundle)".into(),
        });
    }
    // M40: the export-trie suppression is an executable decision — a
    // main executable's trie is the dlsym/debugger surface (its dylib
    // partners bind into their own tries), while a dylib's trie IS the
    // two-level contract its clients bind through, a bundle's the
    // dlopen surface, and the relocatable output carries no __LINKEDIT
    // commands at all. An explicitly named knob that cannot apply is a
    // refusal, never a silently dropped one (the library's re-checks
    // back this so no caller can plan the shape either).
    if !opts.config.exported_symbols {
        use pgr_core::layout::OutputType as Ot;
        match opts.config.filetype {
            Ot::Dylib => {
                return Err(OptsError::ExportedSymbolsConflict {
                    verdict: "-no_exported_symbols drops the export trie, but this \
                              output is a dylib"
                        .into(),
                    fix: "a dylib's trie IS the two-level contract its clients bind \
                          through: link an executable or drop the flag"
                        .into(),
                });
            }
            Ot::Bundle => {
                return Err(OptsError::ExportedSymbolsConflict {
                    verdict: "-no_exported_symbols drops the export trie, but this \
                              output is a bundle"
                        .into(),
                    fix: "a bundle's trie is the dlopen/dlsym surface its host \
                          resolves against: link an executable or drop the flag"
                        .into(),
                });
            }
            Ot::Relocatable => {
                return Err(OptsError::ExportedSymbolsConflict {
                    verdict: "-no_exported_symbols drops the export trie, but the \
                              relocatable output carries no __LINKEDIT commands"
                        .into(),
                    fix: "drop the flag or link an executable".into(),
                });
            }
            Ot::Execute => {}
        }
        // The re-export conflict: the REEXPORT trie nodes ride the
        // export trie — suppressing the trie silently breaks the
        // re-export contract (a client walking the image's exports
        // would miss every re-exported name). The inputs resolve into
        // `config.dylibs` at scan time, so the parse-time surface is
        // the input lists.
        if !opts.reexport_library_inputs.is_empty() || !opts.reexport_frameworks.is_empty() {
            return Err(OptsError::ExportedSymbolsConflict {
                verdict: "-no_exported_symbols drops the export trie, but the link \
                          carries re-export dylibs whose REEXPORT nodes ride that trie"
                    .into(),
                fix: "drop the re-export dylibs or drop -no_exported_symbols".into(),
            });
        }
    }
    // M42: the unused-dylib drop's surface conflicts. The relocatable
    // output carries no load commands (its symbol table is the input's,
    // verbatim — nothing to strip), and under `-flat_namespace` every
    // bind rides the flat-lookup ordinal (the bind names no provider —
    // the drop cannot be proven safe). An explicitly named knob that
    // cannot apply is a refusal, never a silently dropped one (the
    // library's re-checks back this so no caller can plan the shape
    // either).
    if opts.config.dead_strip_dylibs {
        if opts.config.filetype == pgr_core::layout::OutputType::Relocatable {
            return Err(OptsError::DeadStripDylibsConflict {
                verdict: "-dead_strip_dylibs drops the load commands of unused dylibs, but \
                          the relocatable output opens its undefineds by design and \
                          carries no load commands"
                    .into(),
                fix: "drop the flag or link a segmented output (an executable, dylib or \
                      bundle)"
                    .into(),
            });
        }
        if opts.config.flat_namespace {
            return Err(OptsError::DeadStripDylibsConflict {
                verdict: "-dead_strip_dylibs drops the load commands of unused dylibs, but \
                          the flat-namespace bind rides the flat-lookup ordinal — it \
                          names no provider"
                    .into(),
                fix: "drop -dead_strip_dylibs (flat binds may reach any loaded image's \
                      exports) or link two-level (the default)"
                    .into(),
            });
        }
    }
    // M106: the needed-dylib mark's surface conflict. The mark shapes
    // the output's load-command list (the `-dead_strip_dylibs` survival
    // opt-out — a needed dylib rides the kept list), and the relocatable
    // output carries no load commands (its symtab is the input's,
    // verbatim — nothing for the mark to keep). An explicitly named knob
    // that cannot apply is a refusal, never a silently dropped one (the
    // library's re-check backs this so no caller can plan the shape
    // either).
    if opts.config.filetype == pgr_core::layout::OutputType::Relocatable
        && (!opts.needed_library_inputs.is_empty()
            || !opts.needed_frameworks.is_empty()
            || !opts.needed_libs.is_empty())
    {
        return Err(OptsError::NeededLibraryConflict {
            verdict: "-needed marks a dylib to really ride the load commands even when \
                      nothing binds against it, but the relocatable output opens its \
                      undefineds by design and carries no load commands"
                .into(),
            fix: "drop -needed_library/-needed_framework/-needed-l or link a segmented \
                  output (an executable, dylib or bundle)"
                .into(),
        });
    }
    // M110: the hidden-dylib mark's surface conflict. The mark drops a
    // load command from the output's header (a weak reference rides
    // dyld's flat lookup, a strong one refuses), and the relocatable
    // output carries no load commands (its symtab is the input's,
    // verbatim — nothing for the mark to drop). An explicitly named
    // knob that cannot apply is a refusal, never a silently dropped
    // one (the library's re-check backs this so no caller can plan the
    // shape either).
    if opts.config.filetype == pgr_core::layout::OutputType::Relocatable
        && (!opts.hidden_library_inputs.is_empty()
            || !opts.hidden_frameworks.is_empty()
            || !opts.hidden_libs.is_empty())
    {
        return Err(OptsError::HiddenLibraryConflict {
            verdict: "-hidden marks a dylib to ride without its load command, but the \
                      relocatable output opens its undefineds by design and carries no \
                      load commands to drop"
                .into(),
            fix: "drop -hidden_library/-hidden_framework/-hidden-l or link a segmented \
                  output (an executable, dylib or bundle)"
                .into(),
        });
    }
    // M111: the read-only-relocations policy's surface conflict. The
    // non-default faces decide what a write into a read-only segment
    // becomes (the W^X contract's other half), and the relocatable
    // output's sections are the input's, verbatim — its relocation
    // sites ride untouched and no segment mapping exists for the
    // policy to price. An explicitly named knob that cannot apply is a
    // refusal, never a silently dropped one (the library's re-checks
    // back this so no caller can plan the shape either).
    if opts.config.filetype == pgr_core::layout::OutputType::Relocatable
        && opts.config.read_only_relocs != pgr_core::resolve::ReadOnlyRelocsPolicy::Error
    {
        return Err(OptsError::ReadOnlyRelocsConflict {
            verdict: format!(
                "-read_only_relocs {} decides what a write into a read-only segment \
                 becomes, but the relocatable output's sections are the input's, \
                 verbatim",
                opts.config.read_only_relocs.flag_word()
            ),
            fix: "drop -read_only_relocs or link a segmented output (an executable, \
                  dylib or bundle)"
                .into(),
        });
    }
    // M123: the weak-reference-mismatches policy's surface conflict. The
    // non-default faces decide what a weak/strong reference mix becomes
    // (the `N_WEAK_REF` bit on a symbol's `n_desc` — the weak-import
    // contract's resolve-side cousin), and the relocatable output's
    // references ride untouched (no resolve walk prices them). An
    // explicitly named knob that cannot apply is a refusal, never a
    // silently dropped one (the library's re-checks back this so no
    // caller can plan the shape either — the M111 refusal shape,
    // mirrored exactly).
    if opts.config.filetype == pgr_core::layout::OutputType::Relocatable
        && opts.config.weak_reference_mismatches
            != pgr_core::resolve::WeakReferenceMismatchesPolicy::Error
    {
        return Err(OptsError::WeakReferenceMismatchesConflict {
            verdict: format!(
                "-weak_reference_mismatches {} records the weak/strong reference \
                 mismatch, but the relocatable output's references ride untouched — \
                 nothing to record",
                opts.config.weak_reference_mismatches.flag_word()
            ),
            fix: "drop -weak_reference_mismatches or link an image (an executable, \
                  dylib or bundle)"
                .into(),
        });
    }
    // M46: the export-dynamic roots' surface conflicts. The knob is an
    // executable decision — a dylib's and a bundle's strip already
    // roots every definition (the export surface is the contract), and
    // the relocatable output strips nothing (its symbol table is the
    // input's, verbatim). An explicitly named knob that cannot apply is
    // a refusal, never a silently dropped one (the library's re-checks
    // — the layout and `link_reloc` — back this so no caller can plan
    // the shape either).
    if opts.config.export_dynamic {
        match opts.config.filetype {
            pgr_core::layout::OutputType::Execute => {}
            pgr_core::layout::OutputType::Dylib => {
                return Err(OptsError::ExportDynamicConflict {
                    verdict: "-export_dynamic preserves global symbols during dead \
                              stripping, but this output is a dylib"
                        .into(),
                    fix: "every definition already roots a dylib's strip (the export \
                          surface is the contract): link an executable or drop the flag"
                        .into(),
                });
            }
            pgr_core::layout::OutputType::Bundle => {
                return Err(OptsError::ExportDynamicConflict {
                    verdict: "-export_dynamic preserves global symbols during dead \
                              stripping, but this output is a bundle"
                        .into(),
                    fix: "every definition already roots a bundle's strip (the dlopen \
                          surface is the contract): link an executable or drop the flag"
                        .into(),
                });
            }
            pgr_core::layout::OutputType::Relocatable => {
                return Err(OptsError::ExportDynamicConflict {
                    verdict: "-export_dynamic preserves global symbols during dead \
                              stripping, but the relocatable output strips nothing"
                        .into(),
                    fix: "the object's symbol table is the input's, verbatim: drop the \
                          flag or link an executable"
                        .into(),
                });
            }
        }
    }
    // M48: the dylib initializer's surface conflicts. The knob is a
    // dylib decision — ld64's own validation ("-init can only be used
    // with -dynamiclib"): an executable's initializer surface is
    // LC_MAIN (its entry), a bundle dlopens without a dylib
    // initializer, and the relocatable output carries no load commands
    // at all. An explicitly named knob that cannot apply is a refusal,
    // never a silently dropped one (the library's re-checks — the
    // layout and `link_reloc` — back this so no caller can plan the
    // shape either).
    if opts.config.init_symbol.is_some() {
        match opts.config.filetype {
            pgr_core::layout::OutputType::Dylib => {}
            pgr_core::layout::OutputType::Execute => {
                return Err(OptsError::InitConflict {
                    verdict: "-init names a load-time initializer dyld calls when the \
                              image loads, but this output is an executable"
                        .into(),
                    fix: "the executable's initializer surface is LC_MAIN (its entry): \
                          link a dylib (-dylib) or drop the flag"
                        .into(),
                });
            }
            pgr_core::layout::OutputType::Bundle => {
                return Err(OptsError::InitConflict {
                    verdict: "-init names a load-time initializer dyld calls when the \
                              image loads, but this output is a bundle"
                        .into(),
                    fix: "bundles dlopen without a dylib initializer: link a dylib \
                          (-dylib) or drop the flag"
                        .into(),
                });
            }
            pgr_core::layout::OutputType::Relocatable => {
                return Err(OptsError::InitConflict {
                    verdict: "-init names a load-time initializer dyld calls when the \
                              image loads, but the relocatable output carries no load \
                              commands"
                        .into(),
                    fix: "drop the flag or link a dylib".into(),
                });
            }
        }
    }
    // M98: the dylib terminator's surface conflicts. The knob is a
    // dylib decision like the M48 initializer — an executable
    // terminates through its runtime (no load command names the
    // routine), a bundle dlopens without a dylib terminator, and the
    // relocatable output carries no load commands at all. An explicitly
    // named knob that cannot apply is a refusal, never a silently
    // dropped one (the library's re-checks — the layout and
    // `link_reloc` — back this so no caller can plan the shape either).
    if opts.config.term_symbol.is_some() {
        match opts.config.filetype {
            pgr_core::layout::OutputType::Dylib => {}
            pgr_core::layout::OutputType::Execute => {
                return Err(OptsError::TermConflict {
                    verdict: "-term names a load-time terminator dyld calls when the \
                              image unloads, but this output is an executable"
                        .into(),
                    fix: "an executable terminates through its runtime (no load command \
                          names the routine): link a dylib (-dylib) or drop the flag"
                        .into(),
                });
            }
            pgr_core::layout::OutputType::Bundle => {
                return Err(OptsError::TermConflict {
                    verdict: "-term names a load-time terminator dyld calls when the \
                              image unloads, but this output is a bundle"
                        .into(),
                    fix: "bundles dlopen without a dylib terminator: link a dylib \
                          (-dylib) or drop the flag"
                        .into(),
                });
            }
            pgr_core::layout::OutputType::Relocatable => {
                return Err(OptsError::TermConflict {
                    verdict: "-term names a load-time terminator dyld calls when the \
                              image unloads, but the relocatable output carries no load \
                              commands"
                        .into(),
                    fix: "drop the flag or link a dylib".into(),
                });
            }
        }
    }
    // M99: the named output UUID's surface conflicts. A named value and
    // the M32 suppression are two answers to one question (the pair is
    // the shape, not the argv order), and the relocatable output
    // carries no LC_UUID command at all (the M32 shape) — a named value
    // has no field to land on. The library's re-checks (the layout and
    // `link_reloc`) back these so no caller can plan the shape either.
    if opts.config.named_uuid.is_some() && opts.config.uuid_source == UuidSource::None {
        return Err(OptsError::UuidConflict {
            verdict: "-no_uuid suppresses the output's LC_UUID command, but -uuid names \
                     one"
            .into(),
            fix: "a suppression and a named value are two answers to one question: keep \
                 the name and drop -no_uuid, or keep the suppression and drop -uuid"
                .into(),
        });
    }
    if opts.config.named_uuid.is_some()
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::UuidConflict {
            verdict: "-uuid names the output's LC_UUID identity, but the relocatable \
                     output carries no LC_UUID command at all"
                .into(),
            fix: "drop -uuid or link an executable/dylib/bundle".into(),
        });
    }
    // M114: the random source's surface conflicts. `-random_uuid` and
    // `-no_uuid` both write the ONE typed source field — the pair rides
    // the seen bits (order-independent, the M99 pair shape; neither
    // flag outlives the other in the config). `-random_uuid` × `-uuid`
    // are two answers to the identity question, and the relocatable
    // output carries no LC_UUID command at all — a draw has no field to
    // land on (the M99 relocatable refusal mirrored exactly). The
    // library's re-checks (the layout and `link_reloc`) back the
    // output-kind refusal so no caller can plan the shape either.
    if opts.uuid_flags_seen[0] && opts.uuid_flags_seen[1] {
        return Err(OptsError::UuidConflict {
            verdict: "-random_uuid draws the output's LC_UUID identity at emit time, but \
                     -no_uuid suppresses the command"
                .into(),
            fix: "a draw and a suppression are two answers to one question: keep the draw \
                 and drop -no_uuid, or keep the suppression and drop -random_uuid"
                .into(),
        });
    }
    if opts.config.uuid_source == UuidSource::Random && opts.config.named_uuid.is_some() {
        return Err(OptsError::UuidConflict {
            verdict: "-random_uuid draws the output's LC_UUID identity at emit time, but \
                     -uuid names one"
                .into(),
            fix: "a draw and a named value are two answers to one question: keep the name \
                 and drop -random_uuid, or keep the draw and drop -uuid"
                .into(),
        });
    }
    if opts.config.uuid_source == UuidSource::Random
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::UuidConflict {
            verdict: "-random_uuid generates the output's LC_UUID identity, but the \
                     relocatable output carries no LC_UUID command at all"
                .into(),
            fix: "drop -random_uuid or link an executable/dylib/bundle".into(),
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
            // M83: the resident lane serves the object shape (the
            // session's walk runs the object path over the raw blobs —
            // the reply carries the MH_OBJECT verbatim), so `-resident`
            // rides beside `-r` like every other lane that reads the
            // files.
        }
    }
    // M10 rung 4, slice 5: an *explicitly named* chain word family must
    // survive the deployment floor. Below it the layout plans the classic
    // opcode streams (TDD §3.6 invariant 3 — the encoding flips, the
    // fixups do not; the floor is the documented fallback) — and a named
    // family no image will ever carry is a silently dropped knob, which
    // this surface refuses to do. The unnamed default keeps the silent
    // fallback. The decision reads the same consumer seam the encoding
    // query answers from (one table, four readers since M16 — never a
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
    // produce one refuse the knob instead of dropping it. M80: the
    // resident lane serves the map (the session's own walk renders the
    // placed image's report — wire v46 carries the document verbatim).
    // M86: the ladder serves the map too — the relink is not a replay of
    // recorded bytes, its walk runs the full Passes 1–3
    // (`pgr_core::link_cached` inside `incremental_relink`), and
    // `LinkResult::layout` is the walk's own Pass-3 product: the map the
    // ladder writes names the placed image the relink just planned, the
    // same face the one-shot writes (either lane, one walk, one
    // document). M87: the fusion lane serves it as well — the session's
    // ladder renders its own walk's document over the same v46 tail (an
    // old server's refusal is the stand-down the in-process ladder
    // answers). The only remaining refusal is the relocatable output's
    // (an input object produces no segment layout).
    if opts.map_path.is_some() && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::OrderFileConflict {
            verdict: "-r writes an input object: no segment layout exists for the map to \
                     report"
                .into(),
            fix: "drop -map".into(),
        });
    }
    // M11: the order file must be appliable where it was requested — a
    // refusal, never a silently dropped knob (the surface's contract).
    // M81: the resident lane serves the rank table (wire v47 carries
    // it in the config tail — a resident ordered link ranks the
    // entries the client named, the ladder's replay beside the record
    // included), so the only remaining refusal is the relocatable
    // output's (no segment layout to rank). M90: the refusal covers
    // every order source — the `-sectorder` files rank the same table.
    if !opts.order_specs.is_empty()
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::OrderFileConflict {
            verdict: "-r writes an input object: sections merge at their declared \
                     alignments and no segment layout exists to rank"
                .into(),
            fix: "drop -order_file/-sectorder".into(),
        });
    }
    // M56/M57: the provenance queries read the link's own Pass-2 product.
    // M79: the resident lane serves both (the session's warm pipeline is
    // the walk — wire v45 carries the rendered answers). M84: the ladder
    // serves both too — the relink re-parses the inputs and runs the full
    // Passes 1–3 (`pgr_core::link_cached` inside `incremental_relink`),
    // so `result.resolution` and `result.loads` are the walk's products,
    // in the relink's own memory; the answers serve from them either tier
    // (a query-bearing relink that runs the fusion lane hands over to the
    // in-process ladder — the session's patch serves bytes, not answers).
    // No lane refuses the queries any more: every lane that links, walks.
    // M92: the liveness query's lane contract is the M56 shape — every
    // lane that carries `-dead_strip` answers it. M93: the served rung
    // retires the resident refusal (wire v48 carries the ask; the
    // session's own walk carries the mark record, the chains ride the
    // provenance tail) — the resident lanes serve the query like the
    // one-shot and the ladder do. M93 also closes the gap the served
    // rung surfaced: `-r` preserves input sections verbatim and refuses
    // the strip, so no mark record exists to walk and the query has no
    // honest answer there — the relocatable output refuses the premise
    // at the surface (the M83 replay-face rule: the driver never asks,
    // no wire caller can plan the shape either), instead of the
    // pre-M93 silent-ignore.
    if !opts.why_live.is_empty()
        && opts.config.filetype == pgr_core::layout::OutputType::Relocatable
    {
        return Err(OptsError::WhyLiveConflict {
            verdict: "-why_live asks the strip's own record, and the relocatable output \
                     (-r) preserves input sections verbatim — it carries no strip, so \
                     no liveness chain exists to name"
                .into(),
            fix: "drop -r (the image and relocatable-free lanes answer the query under \
                  -dead_strip)"
                .into(),
        });
    }
    // M60: the dependency record names the files the link read. The
    // one-shot, relocatable and resident lanes all read the files (the
    // resident client writes the record from its own request list; the
    // daemon never touches the filesystem). M85: the ladder rides too —
    // the relink's Pass 0 (`prepare_link`) re-reads every input it maps
    // (the re-parse is the digest source) and records the read set while
    // the reads happen (`PreparedLink::deps`), so the sidecar the relink
    // rewrites names the files the ladder actually read. A record-bearing
    // relink on the fusion lane hands over to the in-process ladder (the
    // session's reads live inside the daemon; the wire carries no read
    // set) — the run answers either way.
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
    use super::{ExportFilterSpec, OptsError, OrderSpec, parse, parse_number, parse_version};
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
        // tests/m11_order_file.rs); M90: the surface stores every
        // order source in command-line order (`-sectorder` beside it).
        let o = parse(&args(&["-o", "out", "-order_file", "f.txt", "a.o"])).unwrap();
        assert_eq!(
            o.order_specs,
            vec![OrderSpec::File {
                path: "f.txt".into()
            }]
        );
        let o = parse(&args(&[
            "-o",
            "out",
            "-sectorder",
            "__TEXT",
            "__text",
            "s.txt",
            "a.o",
        ]))
        .unwrap();
        assert_eq!(
            o.order_specs,
            vec![OrderSpec::Section {
                segment: "__TEXT".into(),
                section: "__text".into(),
                path: "s.txt".into(),
            }]
        );
        // M14: the weak/lazy dylib family left the list too (the
        // acceptance is gated in tests/m14_lazy_dylibs.rs); M43
        // released the ObjC pull and emptied the list — the umbrella
        // refusals remain the actionable surface and `-ObjC` parses
        // into its decision (the acceptance is gated in
        // tests/m43_objc.rs).
        let err = parse(&args(&["-o", "out", "-sub_umbrella", "Foo", "a.o"])).unwrap_err();
        assert!(err.to_string().contains("umbrella"), "{err}");
        let o = parse(&args(&["-o", "out", "-ObjC", "a.o"])).unwrap();
        assert!(o.config.objc, "the released flag names its decision");
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
        // M100: the list file rides the ordered spec list (the compose
        // source; the M90 shape).
        assert_eq!(
            o.export_filter_specs,
            vec![ExportFilterSpec::ExportedList {
                path: "/tmp/exports.txt".into()
            }]
        );
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
    fn m39_make_undefined_marks_shape_the_config() {
        let o = parse(&args(&[
            "-o",
            "out",
            "-U",
            "_override_me",
            "-U",
            "_also_gone",
            "-undefined",
            "dynamic_lookup",
            "a.o",
        ]))
        .unwrap();
        assert_eq!(
            o.config.make_undefined.names(),
            ["_override_me", "_also_gone"]
        );
    }

    #[test]
    fn m39_make_undefined_values_are_validated() {
        // The grammar (empty, NUL, repeated) refuses at parse time; the
        // verdict names the flag and the core seam's refusal rides the
        // miette help (the same split the M21 clients ride — the module
        // tests own the grammar wording).
        let err = parse(&args(&["-o", "out", "-U", "", "a.o"])).unwrap_err();
        assert!(err.to_string().contains("-U"), "{err}");
        assert!(parse(&args(&["-o", "out", "-U", "_bad\0name", "a.o"])).is_err());
        assert!(parse(&args(&["-o", "out", "-U", "_f", "-U", "_f", "a.o"])).is_err());
    }

    #[test]
    fn m39_the_relocatable_output_refuses_the_marks() {
        let err = parse(&args(&["-o", "out", "-r", "-U", "_f", "a.o"])).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("-U"), "{msg}");
        assert!(msg.contains("relocatable"), "{msg}");
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
        // doing exactly what it already does (no demangling): accepted,
        // no effect, value flags consume their value. `-no_deduplicate`
        // left this list at M41 (the D4 merge reads the decision).
        let o = parse(&args(&[
            "-o",
            "out",
            "-demangle",
            "a.o",
            "-object_path_lto",
            "/tmp/lto.o",
            "b.o",
        ]))
        .unwrap();
        assert_eq!(o.inputs, ["a.o", "b.o"]);
        let o2 = parse(&args(&["-o", "out", "-no_demangle", "a.o"])).unwrap();
        assert_eq!(o2.inputs, ["a.o"]);
        let o3 = parse(&args(&["-o", "out", "-no_deduplicate", "a.o"])).unwrap();
        assert!(
            !o3.config.deduplicate,
            "the promoted toggle reads the decision (M41)"
        );
    }
}

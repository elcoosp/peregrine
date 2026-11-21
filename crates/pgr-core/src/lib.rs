//! Peregrine core pipeline: input parsing, interning, resolution,
//! layout and fixup planning — TDD §5 Passes 1–3 and §6/§7 data structures.
//!
//! M1 scope ("static hello-world") grew through M3 (dynamic executables,
//! dylibs, bundles). M4 (architecture doc §10.3 row M4) makes the pipeline
//! **performance-shaped end to end**: Pass 1 parses LPT-scheduled in
//! parallel with giant-object splitting, the interner sorts on the pool,
//! Pass 3 materializes the D8 `resolved[]` de-indirection tables and the
//! copy-run coalescing the fused tile emit (pgr-emit, Pass 4 v2) consumes.
//!
//! Determinism policy (§4.3): every ordering input is total-ordered
//! (command-line file order, symbol order within a file, canonical output
//! section order); nothing reads hash iteration order. Parallel schedules
//! change who computes a result, never the result — gated in tests.
//!
//! The M8/M9 machinery rides the same passes: the reverse reference index,
//! the insertion-stable import table and the slack policy (`revindex`,
//! `stable_imports`, `slack`) anchor the §7.3 incremental relink's layout,
//! and `propagate`/`resolve_reuse` scope a relink's Pass 2 work to what
//! the recorded plan can vouch for — anything else re-runs in full.
//!
//! M10 rides the same seams at both ends: [`link_reloc`] stops after
//! Pass 2 for the `-r` relocatable output (the object is itself a link
//! input), and the layout's fixup-encoding gate is platform-aware —
//! [`layout::chained_fixups_min_minos`] names the per-platform
//! deployment floor (macOS 12.0, iOS 15.0, tvOS 15.0, watchOS 8.0,
//! visionOS 1.0) below which the classic `LC_DYLD_INFO_ONLY` opcodes
//! encode the same fixups. Rung 3 landed the floor as a consumer seam:
//! [`platform::FixupEncoding`] names the fixup-encoding decision for a
//! platform/target pair *before* the link runs, and the canonical
//! table it reads lives beside the platform constants
//! (`pgr_format::consts::chained_fixups_floor`) — one table, four
//! readers since M16: this layout, the seam, the verifier's
//! `fixups_floor` gate and the initializer-offsets decision
//! (`pgr_core::init_offsets` — whose driver surface, unlike the M10
//! query, names the form on the link command line itself).

pub mod alias;
pub mod bundle_loader;
pub mod cache;
pub mod deadstrip;
pub mod dep_info;
pub mod dyld_env;
pub mod dyld_info;
pub mod dylinker;
pub mod export_filter;
pub mod fixups;
pub mod header_pad;
pub mod icf;
pub mod ids;
pub mod image_base;
pub mod init_offsets;
pub mod interner;
pub mod layout;
pub mod link;
pub mod make_undefined;
pub mod map;
pub mod objc;
pub mod object;
pub mod observe;
pub mod order;
pub mod pagezero;
pub mod platform;
pub mod pool;
pub mod propagate;
pub mod provenance;
pub mod rename;
pub mod resolve;
pub mod resolve_reuse;
pub mod revindex;
pub mod sect_align;
pub mod segprot;
pub mod slack;
pub mod stable_imports;
pub mod stack_size;
pub mod statistics;
pub mod sub_client;
pub mod thunks;
pub mod time_report;
pub mod trace;
pub mod trie;
pub mod umbrella;
pub mod unwind;
pub mod why_live;

pub use alias::{Alias, AliasError, AliasTable};
pub use bundle_loader::{BundleLoader, BundleLoaderError};
pub use cache::PoiCache;
pub use deadstrip::{LiveRootKind, LivenessIndex};
pub use dep_info::{DepInfoError, DependencyEntry, DependencyRecord};
pub use dyld_env::{DyldEnv, DyldEnvEntry, DyldEnvError};
pub use dyld_info::DyldInfoPlan;
pub use dylinker::{Dylinker, DylinkerError};
pub use export_filter::{SymbolMatcher, SymbolPattern, SymbolPatternError, is_export_visible};
pub use fixups::{
    FixupKind, FixupPlan, FixupPointerFormat, MAX_CHAIN_STRIDE_BYTES, pack_page_strided,
};
pub use header_pad::HeaderPad;
pub use ids::{FileId, StringId};
pub use image_base::ImageBase;
pub use init_offsets::{InitOffsets, InitOffsetsError};
pub use interner::Interner;
pub use layout::{
    CopyRun, Layout, LinkConfig, OutputSymbol, OutputType, PatchOp, Piece, PlacedSection,
    ResolvedFile, SegmentPlan, UuidSource,
};
pub use link::{
    LinkArchive, LinkArchiveMember, LinkInput, LinkResult, Parallelism, RelocLink,
    check_load_symbols, link, link_cached, link_from_objects, link_from_objects_observed,
    link_observed, link_reloc, link_reloc_observed, link_with, split_symbols_for,
};
pub use make_undefined::{MakeUndefined, MakeUndefinedError, MakeUndefinedName};
pub use map::MapJsonError;
pub use objc::{
    OBJC_METADATA_PREFIXES, OBJC1_METADATA_PREFIXES, ObjcFamily, classify_objc_metadata,
    defines_objc_metadata,
};
pub use object::{DecodedReloc, InputObject, RelocKind, RelocTarget};
pub use observe::{
    LinkNote, LinkObserver, ObserverPair, Phase, PhaseDetail, PhaseEvent, ReferenceEvent,
    RefsCollector, TaskEvent, TracingObserver,
};
pub use pagezero::PageZero;
pub use platform::FixupEncoding;
pub use propagate::{PropagationScope, SectionDigest};
pub use provenance::{
    DefinitionSource, DylibExplanation, LoadDecision, LoadExplanation, LoadReport, ProvenanceError,
    RefExplanation, RefSiteReport, explain_export,
};
pub use rename::{RenameError, SectionRename, SectionRenames};
pub use resolve::{Def, Rank, Resolution};
pub use resolve_reuse::{ResolveReuseSeed, ReuseFallback, ReusePlan, install_reused, plan_reuse};
pub use revindex::{RefSite, ReverseIndex};
pub use sect_align::{SectAlign, SectAlignError, SectAlignTable};
pub use segprot::{SegName, SegProt, SegProtError, SegProts};
pub use slack::{LayoutFallback, SlackPolicy};
pub use stable_imports::{StableImport, StableImports};
pub use stack_size::StackSize;
pub use statistics::{LinkStatistics, StatsCollector};
pub use sub_client::{SubClient, SubClientEntry, SubClientError};
pub use time_report::{TimeCollector, TimeReport};
pub use trace::{TraceCollector, TraceJsonError, TraceLane, TraceReport, TraceTask};
pub use trie::{Export, ExportInfo};
pub use umbrella::{Umbrella, UmbrellaError, UmbrellaKind, UmbrellaMember};
pub use unwind::{
    MAX_COMMON_ENCODINGS, SynthesisError, UnwindEntry, UnwindInfo, UnwindShape, plan_shape,
    synthesize, synthesized_size, synthesized_size_shape,
};
pub use why_live::{LiveVerdict, LiveWhyStep, WhyLiveError, WhyLiveExplanation, explain_live};

/// A fatal link error (M1 surface: inputs, symbols, layout, encoding).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    /// An input file could not be parsed.
    #[error("{file}: {message}")]
    Parse {
        /// Input file name.
        file: String,
        /// What failed.
        message: String,
    },
    /// A symbol problem: undefined reference or duplicate strong definition.
    #[error("{message}")]
    Symbol {
        /// The offending symbol name.
        name: String,
        /// What failed and where.
        message: String,
    },
    /// An input construct the M1 pipeline does not support.
    #[error("{file}: {message}")]
    Unsupported {
        /// Input file name.
        file: String,
        /// What and why.
        message: String,
    },
    /// The requested layout violates a Mach-O contract (header page, range).
    #[error("{message}")]
    Layout {
        /// What failed.
        message: String,
    },
    /// An internal invariant failed (a bug, not user input).
    #[error("internal: {message}")]
    Internal {
        /// What invariant failed.
        message: String,
    },
}

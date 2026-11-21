//! The typed link-pipeline observation seam (M54): the pass structure
//! Passes 1–3 already name on the tracing seam becomes a nameable, typed
//! surface a library consumer can subscribe to. A link reports each
//! phase's completion — [`Phase`] in link order, the phase's own shape as
//! [`PhaseDetail`] (the counts the pass already had in hand), the wall
//! time it took — and the §7.3 ladder's silent-correct rungs (the
//! resolve-reuse fallback) as explicit [`LinkNote`]s. The observer is
//! read-only: subscribing never changes the plan (the parity gate lives in
//! `tests/m54_observer.rs`), and the trait's default methods keep an
//! observer that subscribes to nothing cost-free. The M63 rung adds the
//! intra-phase face: the parse pool's per-input parses ride the seam as
//! [`TaskEvent`]s, each naming the thread that ran it and its own arrival
//! clock — the facts the timeline's worker lanes read
//! (`tests/m63_task_spans.rs` gates the shape and the parity). The M65
//! rung adds the §7.3 relink ladder's own rungs: the integrity gate, the
//! patch plan, the clone-and-patch and the `-incremental-verify` audit
//! ride the seam as [`Phase`]s (`RelinkGate`, `RelinkPlan`, `RelinkPatch`,
//! `RelinkAudit` — the ladder's engine phases, named beside the pipeline's
//! passes), and the ladder's fallback rungs join [`LinkNote`]
//! (`RelinkFallback` — the full link the ladder handed over to, named the
//! way the resolve-reuse fallback already names itself).
//!
//! The M68 rung adds the emit half: Passes 4–5 stop being the caller's
//! opaque band and ride the seam as [`Phase`]s (`Emit` — the fused tile
//! emit's completion; `Flush` — the pooled atomic write's, the TDD §9.3
//! instrumentation spec's named rows beside the pipeline's passes) —
//! `pgr-emit`'s `build_image_fused_observed`/`write_image_observed` report
//! them to the caller's observer slot, and the driver's `--time`/`--trace`
//! faces collect them beside the Passes 1–3 rows (one collection per run).
//! The band face stays the library caller's: `TimeReport::emit`/`total`
//! remain the `Option`s a consumer fills.
//!
//! The seam follows the house observability convention: [`TracingObserver`]
//! bridges every event onto the `tracing` debug level, inert until a
//! subscriber installs — the binaries and the consumer examples install
//! one under their debug envs (`PGR_TRACING=1`), and a library consumer
//! keeps (or ships) its own. The typed surface is for the consumer that
//! wants the events *as data* — a build-system progress bar, a phase-time
//! report — without scraping formatted spans.
//!
//! The M78 rung grows the task seam's second pool: the flush pool's
//! writers (Pass 5, `pgr-emit`'s writer pool) carry their own
//! [`TaskEvent`]s — one per writer, the blocks the writer carried as its
//! label, the same channel convention the parse pool rides (the records
//! cross an mpsc channel that opens only when a subscriber rides; the
//! caller forwards them once the pool returns). The timeline's lane
//! registry names the second family beside the first (`pgr write pool N`
//! beside `pgr parse pool N`, `tests/m78_write_lanes.rs` gating the
//! naming and the round trip; `tests/m78_write_tasks.rs` gating the
//! spans and the parity).

use std::thread::ThreadId;
use std::time::{Duration, Instant};

/// The pipeline phases the observer sees, in link order (the same pass
/// structure the tracing spans name: `link_reloc`, `objc_pull`,
/// `resolve_reuse_plan`/`install`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    /// Pass 1: the inputs' Mach-O parse & atomize (POI-cache hits included —
    /// a cached parse is still a parse the consumer waited on).
    Parse,
    /// The S7 archive-pull fixpoint (M5): the members liveness added beyond
    /// the direct parse (zero when no archives ride the link).
    ArchivePull,
    /// The interner batch: object symbols, then dylib exports, then the
    /// header/alias names (the M2 two-level id order).
    Intern,
    /// Pass 2: symbol resolution — the full install or the resolve-reuse
    /// replay (the replay's refusal rides [`LinkNote::ResolveReuseFallback`]).
    Resolve,
    /// The D12 liveness fixpoint (M5): roots, mark, sweep (`active` names
    /// whether the strip engaged — without `-dead_strip` the set is live).
    Liveness,
    /// The ICF fold over the live text atoms (M6): the atoms folded onto a
    /// canonical copy.
    Fold,
    /// Pass 3: layout — synthesis, fixup planning, the segment/section plan.
    Layout,
    /// The `-r` relocatable shape's completion (Passes 1–2, no segment
    /// plan — the object bytes are `pgr-emit`'s `build_object_image`).
    Reloc,
    /// The §7.3 ladder's integrity gate (M65): the previous output hashed
    /// against the record's page-hash table (the sampled gate the in-place
    /// tier stands on — a mismatch falls back and names itself on
    /// [`LinkNote::RelinkFallback`]).
    RelinkGate,
    /// The §7.3 ladder's patch plan (M65): the span diff over the relinked
    /// layout, the dirty tiles it names (an empty set is the untouched
    /// relink — the ladder's job is done and the patch phase never runs).
    RelinkPlan,
    /// The §7.3 ladder's clone-and-patch (M65): the dirty tiles patched
    /// into the copy-on-write clone, re-signed at the (possibly moved)
    /// signature boundary.
    RelinkPatch,
    /// The §7.3 ladder's audit (M65): the `-incremental-verify` gate —
    /// byte-identity against the full fused emit of the same plan, then
    /// the strict verifier on the final bytes (a divergence is healed, a
    /// blocking issue never ships).
    RelinkAudit,
    /// Pass 4's completion (M68): the fused tile emit planned the image —
    /// copy, relocate, chain words, `__LINKEDIT` chunks and the page-hash
    /// table in one pass over the tiles. The event rides the emit's
    /// completion (never a per-tile stream — the M54 shape), reported by
    /// `pgr-emit`'s `build_image_fused_observed`.
    Emit,
    /// Pass 5's completion (M68): the pooled atomic write shipped the
    /// image — the temp file preallocated, the 8 MiB blocks `pwrite`d,
    /// fsynced, renamed. Reported by `pgr-emit`'s `write_image_observed`
    /// (the fast-path lanes keep their own shapes — the resident run
    /// patches in memory and the client writes unobserved).
    Flush,
}

impl Phase {
    /// The phase's stable token — the field name a subscriber records
    /// (`parse`, `archive_pull`, …), the same `snake_case` convention the
    /// tracing spans use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::ArchivePull => "archive_pull",
            Self::Intern => "intern",
            Self::Resolve => "resolve",
            Self::Liveness => "liveness",
            Self::Fold => "fold",
            Self::Layout => "layout",
            Self::Reloc => "reloc",
            Self::RelinkGate => "relink_gate",
            Self::RelinkPlan => "relink_plan",
            Self::RelinkPatch => "relink_patch",
            Self::RelinkAudit => "relink_audit",
            Self::Emit => "emit",
            Self::Flush => "flush",
        }
    }
}

/// The phase's own detail: the shape the pass already computed (the counts
/// ride for free — the seam never re-derives a number to observe it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhaseDetail {
    /// Pass 1: the parsed direct inputs (cache hits included).
    Objects {
        /// The input count the parse produced.
        inputs: usize,
    },
    /// The archive pull: members liveness pulled beyond the direct parse.
    Members {
        /// The pulled member count.
        pulled: usize,
    },
    /// The interner batch: the symbol names interned.
    Names {
        /// The interned name count.
        interned: usize,
    },
    /// Pass 2: the winners installed. `reused` names the path — the
    /// resolve-reuse replay (`true`) or the full walk (`false`).
    Winners {
        /// Whether the resolution rode the recorded replay.
        reused: bool,
    },
    /// The liveness fixpoint: whether the dead-strip engaged.
    Live {
        /// True when `-dead_strip` (or the M11 order file) ran the fixpoint.
        active: bool,
    },
    /// The ICF fold: the atoms folded onto a canonical copy.
    Folded {
        /// The folded-atom count.
        folded: usize,
    },
    /// Pass 3: the planned shape.
    Planned {
        /// The planned segment count.
        segments: usize,
        /// The planned section count.
        sections: usize,
    },
    /// The `-r` shape: the inputs the front half parsed.
    Reloc {
        /// The input count the object-shape run consumed.
        inputs: usize,
    },
    /// The ladder's integrity gate (M65): the record's page-hash table
    /// hashed against the previous output's bytes.
    Gate {
        /// The hashed page count (the record's own sample).
        pages: usize,
    },
    /// The ladder's patch plan (M65): the tiles the relink dirtied.
    Plan {
        /// The total tiles in the image.
        tiles: usize,
        /// The dirty tiles the plan names (zero = the untouched relink).
        dirty: usize,
    },
    /// The ladder's clone-and-patch (M65): the patch's measured effect.
    Patch {
        /// The bytes `pwrite`d into the clone (dirty tiles + page 0 +
        /// signature).
        bytes: u64,
        /// The dirty tiles actually emitted.
        tiles: usize,
    },
    /// The ladder's audit (M65): the `-incremental-verify` verdict.
    Audit {
        /// The patch diverged and was healed from the reference emit.
        healed: bool,
        /// The strict verifier's blocking-issue count (the audit refuses
        /// the ship when it is nonzero — the event rode anyway).
        issues: usize,
    },
    /// Pass 4's shape (M68): the fused tile emit's own plan-derived facts —
    /// the 16 KiB tiles the pass processed and the image bytes it produced.
    Emitted {
        /// The 16 KiB tiles the emit processed (`file_size` rounded up).
        tiles: usize,
        /// The image bytes the emit produced (the plan's file size).
        bytes: u64,
    },
    /// Pass 5's shape (M68): the pooled write's own facts — the 8 MiB
    /// blocks the file split into (zero for an empty image) and the pool
    /// threads that carried them (one on the single-writer path).
    Flushed {
        /// The 8 MiB blocks the write split into (`buf.len()` rounded up).
        blocks: usize,
        /// The writer threads that ran (the pool's four or the single
        /// small-output writer).
        writers: usize,
    },
}

/// One phase completion: the phase, its shape, the wall time it took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseEvent {
    /// The phase that completed.
    pub phase: Phase,
    /// The phase's own shape.
    pub detail: PhaseDetail,
    /// The wall time the phase took (measured at the seam — the sum is the
    /// link's Passes 1–3 wall time minus the seams' own overhead).
    pub elapsed: Duration,
}

/// One intra-phase task a worker thread carried (M63): the parse pool's
/// per-input parse, reported by the thread that ran it. The event rides
/// the same read-only contract as [`PhaseEvent`] — reporting never moves
/// a byte — and carries the two facts the phase event cannot: the thread
/// the task ran on (the timeline's lane registry keys on it — the worker
/// lanes the §9.4 toolbox reads) and the task's own arrival clock (the
/// collector reconstructs the span's start from it; a drain that forwards
/// the event after the phase completed must not re-stamp the arrival —
/// every worker's span would end at the drain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskEvent {
    /// The phase the task rode in (the parse pool's `Parse` — M63 — and
    /// the flush pool's `Flush` — M78; the two pools the pipeline runs).
    pub phase: Phase,
    /// The task's own label — the input's command-line name for a parse.
    pub label: String,
    /// The wall time the task took.
    pub elapsed: Duration,
    /// The task's completion instant, on the thread that ran it (the
    /// event's own clock — the collector's epoch math reads it).
    pub at: Instant,
    /// The thread that ran the task (the lane registry's key).
    pub thread: ThreadId,
}

/// A pipeline note: a rung the ladder answered on the consumer's behalf.
/// A note never changes the plan — it names the decision the "silent-correct,
/// not silent-blind" contract already made (the same wording the tracing
/// seam's debug events carry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkNote {
    /// The shape-guarded resolve-reuse replay refused (`reason` names the
    /// moved shape, the `ReuseFallback` render) and the full resolve ran —
    /// the ladder's bottom rung: always available, always correct.
    ResolveReuseFallback {
        /// The refusal's own wording.
        reason: String,
    },
    /// The §7.3 in-place ladder handed the link over to the full link
    /// (M65): `reason` names the rung that refused (no record, the
    /// integrity gate's mismatch, the planner's fallback — the
    /// [`crate::resolve_reuse`]-style always-available bottom rung). The
    /// full link follows and produces the outcome; a report that names the
    /// note names why the ladder's rungs stop where they do.
    RelinkFallback {
        /// The refusal's own wording (the fallback reason's render).
        reason: String,
    },
}

/// One symbol reference Pass 2 visited (M113): the resolver's trace face.
/// The event names the referenced symbol as the resolver saw it (the
/// interner's bytes, verbatim) and the input that carries the reference —
/// the two facts ld64's `-t` trace prints. The event rides the same
/// read-only contract as [`PhaseEvent`] — reporting never moves a byte —
/// and fires once per visit (a name referenced from two inputs rides
/// twice, in the walk's own order: the trace is the walk's record, not a
/// deduped set). Both resolve paths report it: the full install's walk
/// and the resolve-reuse replay's reference re-walk (the trace is the
/// run's own Pass-2 record — the M107/M108 config pattern).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceEvent {
    /// The referenced symbol's name (the interner's bytes, verbatim).
    pub name: String,
    /// The input that carries the reference (the command-line name).
    pub from: String,
}

impl ReferenceEvent {
    /// The face both lanes print: the reference and the input that
    /// carried it — the cold lane's stderr line and the served tail's
    /// client-printed line are this render (the wire carries the facts,
    /// the M62 convention; the face never re-shapes between lanes).
    #[must_use]
    pub fn render(&self) -> String {
        format!("{} (from {})", self.name, self.from)
    }
}

/// The reference trace's collector (M113): subscribes to the observation
/// seam's `on_reference` face and keeps every visit in walk order (the
/// trace face's `Vec` — the driver prints each; a library consumer reads
/// the events as data). Feed it to [`crate::link_observed`] /
/// [`crate::link_from_objects_observed`] /
/// [`crate::link_reloc_observed`], then [`RefsCollector::finish`] into
/// the ordered event list.
#[derive(Debug, Default)]
pub struct RefsCollector {
    events: Vec<ReferenceEvent>,
}

impl LinkObserver for RefsCollector {
    fn on_reference(&mut self, event: ReferenceEvent) {
        self.events.push(event);
    }
}

impl RefsCollector {
    /// Consumes the collection into the ordered event list (the walk's
    /// own order: file order, then symbol order — the replay's re-walk
    /// pushes the same order).
    #[must_use]
    pub fn finish(self) -> Vec<ReferenceEvent> {
        self.events
    }
}

/// The link-pipeline observer: subscribes to the passes a link runs. Both
/// methods default to subscribing to nothing — an observer opts into the
/// phases and notes it wants, and the pipeline pays nothing for the
/// silence (the observed and unobserved links plan identical layouts).
pub trait LinkObserver {
    /// A phase completed (`event.elapsed` names its wall time).
    fn on_phase(&mut self, _event: PhaseEvent) {}
    /// An intra-phase task completed on a worker thread (`task.elapsed`
    /// names its wall time, `task.thread` the lane that ran it) — the
    /// M63 task seam the parse pool reports through.
    fn on_task(&mut self, _task: TaskEvent) {}
    /// A pipeline note (a fallback the ladder answered itself).
    fn on_note(&mut self, _note: LinkNote) {}
    /// One symbol reference Pass 2 visited (M113 — `event.name` the
    /// referenced symbol, `event.from` the input that carries it): the
    /// trace face ld64's `-t` prints, reported once per visit in the
    /// walk's own order.
    fn on_reference(&mut self, _event: ReferenceEvent) {}
}

/// The tracing bridge: every event rides the house tracing seam (debug
/// level, inert until a subscriber installs). The bridge is the zero-config
/// observer — installing it keeps the library's own spans and events
/// exactly where they were, and adds the phase-level record a subscriber
/// can watch.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingObserver;

impl LinkObserver for TracingObserver {
    fn on_phase(&mut self, event: PhaseEvent) {
        tracing::debug!(
            phase = event.phase.as_str(),
            elapsed_us = event.elapsed.as_micros() as u64,
            "the link phase completed"
        );
    }

    fn on_task(&mut self, task: TaskEvent) {
        tracing::debug!(
            phase = task.phase.as_str(),
            label = %task.label,
            elapsed_us = task.elapsed.as_micros() as u64,
            "the phase task completed on its worker"
        );
    }

    fn on_note(&mut self, note: LinkNote) {
        // Each variant names its own event (an arm, not a skip): a new
        // `LinkNote` rung stops compiling here until the bridge speaks it.
        match note {
            LinkNote::ResolveReuseFallback { reason } => tracing::debug!(
                fallback = %reason,
                "the resolve-reuse replay fell back to the full resolve"
            ),
            LinkNote::RelinkFallback { reason } => tracing::debug!(
                fallback = %reason,
                "the in-place ladder fell back to the full link"
            ),
        }
    }

    fn on_reference(&mut self, event: ReferenceEvent) {
        tracing::debug!(
            symbol = %event.name,
            from = %event.from,
            "the resolve visited a symbol reference"
        );
    }
}

/// Two observers behind one subscription (M61): the one-shot `--time` +
/// `--trace` shape — both faces read the one observed run, so the seam
/// hands each event to both collectors (the first a clone, the second
/// the original; the event is a `Duration` and an enum, the copy is the
/// seam's own price). The pair borrows its subscribers, so the caller's
/// collectors stay where it put them.
pub struct ObserverPair<'a, 'b> {
    first: &'a mut dyn LinkObserver,
    second: &'b mut dyn LinkObserver,
}

impl<'a, 'b> ObserverPair<'a, 'b> {
    /// Pairs two subscribers behind one [`LinkObserver`].
    #[must_use]
    pub fn new(first: &'a mut dyn LinkObserver, second: &'b mut dyn LinkObserver) -> Self {
        Self { first, second }
    }
}

impl LinkObserver for ObserverPair<'_, '_> {
    fn on_phase(&mut self, event: PhaseEvent) {
        self.first.on_phase(event.clone());
        self.second.on_phase(event);
    }

    fn on_task(&mut self, task: TaskEvent) {
        self.first.on_task(task.clone());
        self.second.on_task(task);
    }

    fn on_note(&mut self, note: LinkNote) {
        self.first.on_note(note.clone());
        self.second.on_note(note);
    }

    fn on_reference(&mut self, event: ReferenceEvent) {
        self.first.on_reference(event.clone());
        self.second.on_reference(event);
    }
}

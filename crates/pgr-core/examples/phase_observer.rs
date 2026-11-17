//! The M54 observation seam's consumer cycle, runnable: a two-object link
//! whose every phase completion lands in a recording observer — the typed
//! face of what `PGR_TRACING=1` shows on the tracing seam. A build system
//! ships this observer when it wants the pass structure *as data* (a
//! progress bar, a phase-time report) instead of scraping formatted spans:
//! the phases arrive in link order, each carrying its own detail and its
//! wall time, and the ladder's silent-correct rungs (the resolve-reuse
//! fallback) arrive as notes.
//!
//! Set `PGR_TRACING=1` to also install a subscriber and watch
//! [`TracingObserver`] bridge the same events onto stderr (the house
//! convention — the subscriber makes the spans visible, it never changes
//! the plan).
//!
//! ```sh
//! cargo run -p pgr-core --example phase_observer
//! ```

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism, link_observed};
use pgr_core::observe::{LinkNote, LinkObserver, PhaseEvent};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// The consumer's recorder: events as data (a progress bar's face).
#[derive(Default)]
struct PhaseTable {
    rows: Vec<(String, String, std::time::Duration)>,
    notes: Vec<String>,
}

impl LinkObserver for PhaseTable {
    fn on_phase(&mut self, event: PhaseEvent) {
        let detail = match event.detail {
            pgr_core::observe::PhaseDetail::Objects { inputs }
            | pgr_core::observe::PhaseDetail::Reloc { inputs } => format!("{inputs} inputs"),
            pgr_core::observe::PhaseDetail::Members { pulled } => format!("{pulled} pulled"),
            pgr_core::observe::PhaseDetail::Names { interned } => format!("{interned} names"),
            pgr_core::observe::PhaseDetail::Winners { reused } => format!("reused={reused}"),
            pgr_core::observe::PhaseDetail::Live { active } => format!("active={active}"),
            pgr_core::observe::PhaseDetail::Folded { folded } => format!("{folded} folded"),
            pgr_core::observe::PhaseDetail::Planned { segments, sections } => {
                format!("{segments} segments, {sections} sections")
            }
        };
        self.rows
            .push((event.phase.as_str().to_string(), detail, event.elapsed));
    }

    fn on_note(&mut self, note: LinkNote) {
        let LinkNote::ResolveReuseFallback { reason } = note;
        self.notes.push(reason);
    }
}

/// One object: a two-instruction `__text`, a `__data` word, one definition.
fn object(name: &str, stem: &str, main: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_section(ObjectSection::data("__data", vec![0x41u8; 8], vec![]));
    let symbol = if main {
        "_main".to_string()
    } else {
        format!("_{stem}")
    };
    b.add_symbol(ObjectSymbol::Defined {
        name: symbol,
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn main() {
    // The bridge observer stays inert until a subscriber installs;
    // PGR_TRACING=1 turns the phase events into stderr lines (the binaries
    // do the same under their debug envs). Debug level: the phase events
    // and the fallback notes all log below info.
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let inputs = vec![
        LinkInput {
            name: "main.o".to_string(),
            bytes: object("main.o", "main", true),
        },
        LinkInput {
            name: "aux.o".to_string(),
            bytes: object("aux.o", "aux_fn", false),
        },
    ];

    // The typed face: every phase completion lands in the recorder. The
    // plan is byte-identical to the unobserved link (the parity gate is
    // the seam's contract — `tests/m54_observer.rs`).
    let mut observer = PhaseTable::default();
    let result = link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut observer,
    )
    .expect("the corpus links");
    println!(
        "observed link: {} segments, {} sections, file size {} bytes — the phases:",
        result.layout.segments.len(),
        result.layout.sections.len(),
        result.layout.file_size,
    );
    for (phase, detail, elapsed) in &observer.rows {
        println!("  {phase:<13} {detail:<28} {elapsed:?}");
    }
    println!(
        "notes: {} (the resolve-reuse fallback names itself when a relink's shape moved)",
        observer.notes.len(),
    );

    // The bridge face: the same events on the tracing seam. `PGR_TRACING=1`
    // shows `the link phase completed` lines with `phase`/`elapsed_us`
    // fields beside the spans the pipeline already emits.
    let mut bridge = pgr_core::observe::TracingObserver;
    let _ = link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut bridge,
    )
    .expect("the corpus links");
    println!("bridge link planned (identical shape — run with PGR_TRACING=1 to watch it)");
}

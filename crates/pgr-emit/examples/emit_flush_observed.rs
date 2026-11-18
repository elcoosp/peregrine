//! The M68 emit half's consumer cycle, runnable: the fused tile emit
//! (Pass 4) and the pooled atomic write (Pass 5) report their completions
//! through the M54 observation seam as the `emit`/`flush` phases — the
//! TDD §9.3 instrumentation spec's named rows beside the pipeline's
//! passes. The demo subscribes both faces the M61 way: a
//! [`pgr_core::TimeCollector`] (the per-pass wall report) paired with this
//! demo's own printing observer through [`pgr_core::ObserverPair`] — one
//! event stream, both faces — and prints the report showing the whole
//! pipeline, Passes 1–5.
//!
//! ```sh
//! cargo run -p pgr-emit --example emit_flush_observed
//! ```

use std::path::PathBuf;

use pgr_core::layout::{Layout, LinkConfig};
use pgr_core::link::{LinkInput, Parallelism, link_cached};
use pgr_core::observe::{LinkObserver, PhaseDetail, PhaseEvent};
use pgr_emit::{build_image_fused_observed, write_image_observed};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// The demo's own observer: every phase completion prints as it lands
/// (the live face a build system's progress bar would ride).
struct PrintObserver;

impl LinkObserver for PrintObserver {
    fn on_phase(&mut self, event: PhaseEvent) {
        let shape = match &event.detail {
            PhaseDetail::Objects { inputs } | PhaseDetail::Reloc { inputs } => {
                format!("{inputs} inputs")
            }
            PhaseDetail::Members { pulled } => format!("{pulled} pulled"),
            PhaseDetail::Names { interned } => format!("{interned} names"),
            PhaseDetail::Winners { reused } => format!("reused={reused}"),
            PhaseDetail::Live { active } => format!("active={active}"),
            PhaseDetail::Folded { folded } => format!("{folded} folded"),
            PhaseDetail::Planned { segments, sections } => {
                format!("{segments} segments, {sections} sections")
            }
            PhaseDetail::Gate { pages } => format!("{pages} pages hashed"),
            PhaseDetail::Plan { tiles, dirty } => format!("{tiles} tiles, {dirty} dirty"),
            PhaseDetail::Patch { bytes, tiles } => format!("{bytes} bytes, {tiles} tiles"),
            PhaseDetail::Audit { healed, issues } => {
                format!("healed={healed}, issues={issues}")
            }
            PhaseDetail::Emitted { tiles, bytes } => format!("tiles={tiles}, bytes={bytes}"),
            PhaseDetail::Flushed { blocks, writers } => {
                format!("blocks={blocks}, writers={writers}")
            }
        };
        println!(
            "  {:<12} {:>9} µs  {shape}",
            event.phase.as_str(),
            event.elapsed.as_micros()
        );
    }
}

/// hello.o: `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret; `_greet`
/// stays undefined (greet.o defines it).
fn hello() -> ObjectBuilder {
    let mut b = ObjectBuilder::new("hello.o");
    let words: Vec<u32> = vec![
        0x9000_0000, // adrp x0, _msg@page
        0x9100_0000, // add x0, x0, #_msg@pageoff
        0x9400_0000, // bl _greet
        0xD65F_03C0, // ret
    ];
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
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
    let msg = b.add_section(ObjectSection::cstring("hello, peregrine\n"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_msg".into(),
        section_index: msg,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b
}

/// greet.o: `_greet` body.
fn greet() -> ObjectBuilder {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b
}

/// The linked plan: the fixture pair through Passes 1–3.
fn linked() -> (Layout, Vec<pgr_core::InputObject>) {
    let inputs = vec![
        LinkInput {
            name: "hello.o".into(),
            bytes: hello().build().expect("the fixture builds"),
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet().build().expect("the fixture builds"),
        },
    ];
    let cfg = LinkConfig {
        ident: "emit-flush-observed".into(),
        ..LinkConfig::default()
    };
    let result =
        link_cached(&inputs, &[], &cfg, Parallelism::Auto, None).expect("the fixture pair links");
    (result.layout, result.objects)
}

fn workdir() -> PathBuf {
    let dir = std::env::temp_dir().join("pgr_emit_flush_observed");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn main() {
    let (layout, objects) = linked();
    let output = workdir().join("hello");

    // The demo runs unobserved by default; `PGR_TRACING=1` installs the
    // house tracing subscriber (the workspace convention — the demo
    // prints its own report either way).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt::init();
    }

    println!(
        "linking {} bytes of image (the plan's own file size):",
        layout.file_size
    );
    // The M61 pairing: one event stream, both faces — the report
    // collector and the demo's printer read the same emit half.
    let mut times = pgr_core::TimeCollector::default();
    let mut printing = PrintObserver;
    let mut pair = pgr_core::ObserverPair::new(&mut times, &mut printing);
    let image = build_image_fused_observed(&layout, &objects, &mut pair).expect("the image emits");
    // Pass 5: the pooled atomic write joins the same subscription (the
    // parity gate is the seam's own contract — observing never moves a
    // byte; `write_image_observed` ships `write_image`'s bytes exactly).
    write_image_observed(&image, &output, &mut pair).expect("the image ships");

    println!("\nthe per-pass wall report (the emit half included):");
    print!("{}", times.report().render());
    println!("\nthe image shipped to {}", output.display());
}

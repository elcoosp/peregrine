//! M68 — the observed emit half: [`pgr_emit::build_image_fused_observed`]
//! and [`pgr_emit::write_image_observed`] report their completions through
//! the M54 observation seam as the `emit`/`flush` phases, the TDD §9.3
//! instrumentation spec's named Pass-4/Pass-5 rows. The gate is the seam's
//! own contract: observing never moves a byte (the parity gate) and one
//! event per call rides (the M54 shape — the emit's completion is its own
//! phase, not a per-tile stream).
//!
//! Gate matrix:
//! * the emit parity — the observed fused emit plans the identical image
//!   and reports exactly one `Emitted` event (the tile count and the
//!   image bytes the plan already knew);
//! * the flush parity — the observed pooled write ships the identical
//!   bytes and reports exactly one `Flushed` event (the 8 MiB block count
//!   and the writer count, the single-writer path included);
//! * the lanes — the events ride the caller's observer slot, the same
//!   subscription the M54/M63 collectors read.

use std::path::PathBuf;

use pgr_core::layout::{Layout, LinkConfig};
use pgr_core::link::{LinkInput, Parallelism, link_cached};
use pgr_core::observe::{LinkObserver, Phase, PhaseDetail, PhaseEvent};
use pgr_emit::{build_image_fused, build_image_fused_observed, write_image, write_image_observed};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// The phase-event recorder: the test's own observer (the collectors the
/// driver subscribes, at the seam's smallest).
#[derive(Default)]
struct Recorder {
    phases: Vec<PhaseEvent>,
}

impl LinkObserver for Recorder {
    fn on_phase(&mut self, event: PhaseEvent) {
        self.phases.push(event);
    }
}

/// hello.o: `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret; `_msg` cstring
/// beside it; `_greet` stays undefined (greet.o defines it).
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

/// The linked plan: the shared fixture pair through Passes 1–3.
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
        ident: "emit-observed".into(),
        ..LinkConfig::default()
    };
    let result =
        link_cached(&inputs, &[], &cfg, Parallelism::Auto, None).expect("the fixture pair links");
    (result.layout, result.objects)
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_emit_observed_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

// ---- the emit parity ----------------------------------------------------------

#[test]
fn the_observed_fused_emit_plans_identical_bytes() {
    let (layout, objects) = linked();
    let expected_tiles =
        usize::try_from(layout.file_size.div_ceil(16 * 1024)).expect("the tile count fits");
    let quiet = build_image_fused(&layout, &objects).expect("the unobserved emit plans");
    let mut recorder = Recorder::default();
    let observed = build_image_fused_observed(&layout, &objects, &mut recorder)
        .expect("the observed emit plans");
    assert_eq!(
        observed, quiet,
        "the parity gate: observing never moves a byte"
    );
    assert_eq!(
        recorder.phases.len(),
        1,
        "one event per phase — the emit's completion, not a per-tile stream"
    );
    let event = &recorder.phases[0];
    assert_eq!(event.phase, Phase::Emit, "the fused tile emit's phase");
    assert_eq!(
        event.detail,
        PhaseDetail::Emitted {
            tiles: expected_tiles,
            bytes: layout.file_size,
        },
        "the detail names the plan's own shape"
    );
}

// ---- the flush parity ---------------------------------------------------------

#[test]
fn the_observed_flush_writes_identical_bytes_small_path() {
    let (layout, objects) = linked();
    let image = build_image_fused(&layout, &objects).expect("the image plans");
    let dir = scratch("small");
    let quiet_path = dir.join("quiet");
    let observed_path = dir.join("observed");
    write_image(&image, &quiet_path).expect("the unobserved write ships");
    let mut recorder = Recorder::default();
    write_image_observed(&image, &observed_path, &mut recorder).expect("the observed write ships");
    assert_eq!(
        std::fs::read(&observed_path).expect("the observed image reads"),
        std::fs::read(&quiet_path).expect("the quiet image reads"),
        "the parity gate: observing never moves a byte"
    );
    assert_eq!(recorder.phases.len(), 1, "one event for the write");
    assert_eq!(recorder.phases[0].phase, Phase::Flush, "the write's phase");
    assert_eq!(
        recorder.phases[0].detail,
        PhaseDetail::Flushed {
            blocks: 1,
            writers: 1,
        },
        "the single-writer path names its shape"
    );
}

#[test]
fn the_observed_flush_writes_identical_bytes_pooled_path() {
    // 25 MiB + 3 bytes: four full 8 MiB blocks plus a partial tail —
    // writer k takes blocks k, k+4, … so every pool thread rides. The
    // byte pattern cycles 0..=250 (the `i % 251` stream, cast-free).
    let len = 25 * 1024 * 1024 + 3;
    let image: Vec<u8> = (0..=250u8).cycle().take(len).collect();
    let dir = scratch("pooled");
    let quiet_path = dir.join("quiet");
    let observed_path = dir.join("observed");
    write_image(&image, &quiet_path).expect("the unobserved write ships");
    let mut recorder = Recorder::default();
    write_image_observed(&image, &observed_path, &mut recorder).expect("the observed write ships");
    assert_eq!(
        std::fs::read(&observed_path).expect("the observed image reads"),
        std::fs::read(&quiet_path).expect("the quiet image reads"),
        "the parity gate: the pooled write reproduces the byte stream"
    );
    assert_eq!(recorder.phases.len(), 1, "one event for the write");
    assert_eq!(
        recorder.phases[0].detail,
        PhaseDetail::Flushed {
            blocks: 4,
            writers: 4,
        },
        "the pool's shape rides the detail"
    );
}

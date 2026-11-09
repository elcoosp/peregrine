//! The M9 incremental engine's consumer cycle, runnable: **record → plan →
//! patch → re-record**, plus the bytes-level tile twin the §7.2 resident
//! transport ships (`TilePatch`). This is the whole §7.3 tier-1 loop the
//! driver drives through `-incremental`, at the engine's own API level —
//! the same cycle `pgr-emit`'s integration suite gates byte-for-byte.
//!
//! tracing spans ride the phases (inert until a subscriber installs, the
//! workspace convention: the demo prints its own report either way).
//!
//! ```sh
//! cargo run -p pgr-emit --example record_patch_tiles
//! ```

use std::path::PathBuf;

use pgr_core::layout::{Layout, LinkConfig};
use pgr_core::link::{LinkInput, Parallelism, link_cached};
use pgr_core::slack::{SlackAnchor, SlackPolicy};
use pgr_emit::incremental::{
    LinkRecord, PatchDecision, apply_patch, apply_tiles, diff_tiles, plan_patch,
};
use pgr_emit::{build_image_fused, write_image};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// hello.o with a `text_bytes`-sized `__text`: `_main` ADRP+ADD loads
/// `_msg`, BL `_greet`, ret; `body_flip` swaps a mov immediate and the
/// cstring at equal length (the "edit" the relink patches in place).
fn hello(text_bytes: usize, body_flip: bool) -> ObjectBuilder {
    let mut words: Vec<u32> = vec![
        0x9000_0000, // adrp x0, _msg@page
        0x9100_0000, // add x0, x0, #_msg@pageoff
        0x9400_0000, // bl _greet
        0x5280_0000, // mov w0, #0 (flipped: #1 — the edited body)
        0xD65F_03C0, // ret
    ];
    if body_flip {
        words[3] = 0x5280_0020;
    }
    words.resize(text_bytes / 4, 0xD503_201F);
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
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
    b.add_section(ObjectSection::cstring(if body_flip {
        "merci, peregrine\n"
    } else {
        "hello, peregrine\n"
    }));
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
    b
}

/// greet.o (never edited): `_greet` body.
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

fn inputs(hello: &ObjectBuilder) -> Vec<LinkInput> {
    vec![
        LinkInput {
            name: "hello.o".into(),
            bytes: hello.build().expect("fixture builds"),
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet().build().expect("fixture builds"),
        },
    ]
}

/// Anchors from a layout: every padded user section's reserved size (the
/// M8-c slack policy cross-link, the relink cycle's shape).
fn anchors_of(layout: &Layout) -> Vec<SlackAnchor> {
    layout
        .sections
        .iter()
        .filter(|s| SlackPolicy::is_padded_section(&s.seg_name, &s.name) && s.size > 0)
        .map(|s| SlackAnchor {
            seg: s.seg_name.clone(),
            name: s.name.clone(),
            padded: s.size,
        })
        .collect()
}

fn workdir() -> PathBuf {
    let dir = std::env::temp_dir().join("pgr_emit_record_patch_tiles");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn main() {
    let dir = workdir();
    let output = dir.join("hello");

    // 1. The cold link: a full fused emit, written as the previous output,
    //    and the emit plan recorded next to it (the driver writes the same
    //    record as `<output>.pgr-inc`).
    let phase = tracing::info_span!("record", output = %output.display()).entered();
    let cfg = LinkConfig {
        ident: "record-patch-tiles".into(),
        layout_slack: Some(SlackPolicy::default()),
        ..LinkConfig::default()
    };
    let (layout1, objects1) = {
        let result = link_cached(
            &inputs(&hello(1024, false)),
            &[],
            &cfg,
            Parallelism::Auto,
            None,
        )
        .expect("cold link");
        (result.layout, result.objects)
    };
    let image1 = build_image_fused(&layout1, &objects1).expect("fused emit");
    write_image(&image1, &output).expect("write previous output");
    let record = LinkRecord::record(&layout1, &objects1, &image1, None).expect("record");
    println!(
        "cold link: {} bytes, record v{}",
        image1.len(),
        record.format_version
    );
    println!("  sections anchored: {}", record.sections.len());
    drop(phase);

    // 2. The edit: one function body's immediates and the cstring change
    //    at equal length — the shape the ladder patches in place.
    let phase = tracing::info_span!("plan").entered();
    let cfg_relink = LinkConfig {
        slack_anchor: anchors_of(&layout1),
        sig_anchor: (layout1.linkedit.sig_off > 0).then_some(layout1.linkedit.sig_off),
        ..cfg.clone()
    };
    let (layout2, objects2) = {
        let result = link_cached(
            &inputs(&hello(1024, true)),
            &[],
            &cfg_relink,
            Parallelism::Auto,
            None,
        )
        .expect("relink pipeline");
        (result.layout, result.objects)
    };
    let image2_full = build_image_fused(&layout2, &objects2).expect("reference emit");
    let decision = plan_patch(
        &record,
        &layout2,
        &objects2,
        cfg_relink.layout_slack.as_ref(),
    )
    .expect("plan");
    let plan = match &decision {
        PatchDecision::InPlace(plan) => plan.clone(),
        PatchDecision::Fallback(reason) => {
            println!("the ladder fell back: {reason}");
            return;
        }
    };
    drop(phase);

    // 3. The patch: clone the previous output, `pwrite` the dirty tiles,
    //    rebuild page 0 with the fresh UUID, re-sign from the merged hash
    //    table, rename. Bytes written scale with the change, not the image.
    let phase = tracing::info_span!("patch").entered();
    let (outcome, next_record) =
        apply_patch(&output, &record, &plan, &layout2, &objects2, &output, None).expect("patch");
    let patched = std::fs::read(&output).expect("read patched output");
    println!(
        "patched: {}/{} tile(s), {} bytes written ({}% of the image)",
        outcome.dirty_tiles,
        outcome.total_tiles,
        outcome.bytes_patched,
        outcome.bytes_patched * 100 / (image1.len() as u64)
    );
    drop(phase);

    // The engine's contract, checked live: the patched file is
    // byte-identical to the full fused emit of the same plan.
    assert_eq!(
        patched, image2_full,
        "the patched output must be byte-identical to the full fused emit"
    );
    println!("byte identity: the patch equals the full emit of the same plan");

    // 4. The bytes-level twin (wire v5's transport shape): the changed-tile
    //    stream is all a warm resident relink crosses — diff, replay,
    //    hash-gate — instead of the whole image.
    let phase = tracing::info_span!("tiles").entered();
    let stream = diff_tiles(&image1, &patched);
    let replayed = apply_tiles(&image1, &stream);
    assert_eq!(replayed, patched, "the tile replay is lossless");
    println!(
        "tile stream: {} tile(s), {} wire bytes (the image is {} bytes), replay hash-gated",
        stream.tiles.len(),
        stream.wire_bytes(),
        image1.len()
    );
    drop(phase);

    // 5. The renewed record: the next cycle patches from this state (the
    //    driver stores it where the next `-incremental` link finds it).
    let redecoded = LinkRecord::decode(&next_record.encode()).expect("renewed record");
    println!(
        "re-recorded: v{} for the next cycle ({} section(s) anchored)",
        redecoded.format_version,
        redecoded.sections.len()
    );
}

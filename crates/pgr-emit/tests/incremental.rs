//! M9 integration gates (architecture doc §10.4 row M9, §7.3 Stage C
//! tier 1): the incremental relink engine end to end over real link plans.
//!
//! The central gate is the engine's correctness contract: a patched output
//! is **byte-identical to the full fused emit of the same plan** — the
//! patch path reuses recorded page hashes for clean tiles and recomputes
//! dirty ones, so any divergence would mean the span diff (the tile-reuse
//! decision) is wrong. Everything else pins the §7.3 behavior: growth
//! within slack stays in place, skeleton moves fall back through the
//! ladder, an unchanged relink touches nothing, and the integrity gate is
//! honest about what it checks.

use pgr_core::layout::{LinkConfig, Layout, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link_cached};
use pgr_core::slack::{SlackAnchor, SlackPolicy};
use pgr_emit::incremental::{
    FallbackReason, Integrity, LinkRecord, PatchDecision, apply_patch, check_output, plan_patch,
};
use pgr_emit::{build_image_fused, write_image};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::path::PathBuf;

/// hello.o with a `text_bytes`-sized `__text` (canonical prologue + `nop`
/// padding): `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret. The symbol
/// set is invariant under `text_bytes` and under `body_flip`.
fn hello(text_bytes: usize, body_flip: bool) -> ObjectBuilder {
    let mut words: Vec<u32> = vec![
        0x9000_0000, // adrp x0, _msg@page
        0x9100_0000, // add x0, x0, #_msg@pageoff
        0x9400_0000, // bl _greet
        0x5280_0000, // mov w0, #0 (flipped: #1 — the "edited function body")
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
        // Same length as "hello, peregrine\n" — a body edit must not
        // resize any section when the no-slack path is under test.
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

/// greet.o (never edited): `_greet` body + a `__data` pointer to `_greet`.
fn greet() -> ObjectBuilder {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.section_mut(data).relocs = vec![ObjectReloc::unsigned(0).at(0)];
    b
}

fn inputs(hello: ObjectBuilder) -> Vec<LinkInput> {
    vec![
        LinkInput {
            name: "hello.o".into(),
            bytes: hello.build().unwrap(),
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet().build().unwrap(),
        },
    ]
}

fn cfg(kind: OutputType, slack: bool, anchors: Vec<SlackAnchor>) -> LinkConfig {
    cfg_adhoc(kind, slack, anchors, true)
}

fn cfg_adhoc(
    kind: OutputType,
    slack: bool,
    anchors: Vec<SlackAnchor>,
    adhoc: bool,
) -> LinkConfig {
    LinkConfig {
        ident: "m9-incremental".into(),
        filetype: kind,
        install_name: matches!(kind, OutputType::Dylib).then(|| "@rpath/libhello.dylib".into()),
        layout_slack: slack.then(SlackPolicy::default),
        slack_anchor: anchors,
        adhoc,
        ..LinkConfig::default()
    }
}

fn link(inputs: &[LinkInput], cfg: &LinkConfig) -> (Layout, Vec<pgr_core::object::InputObject>) {
    let result = link_cached(inputs, &[], cfg, Parallelism::Auto, None).unwrap();
    (result.layout, result.objects)
}

/// Anchors from a layout: every padded user section's reserved size.
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

fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_emit_inc_{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The full §7.3 tier-1 loop over an edited corpus, asserting the engine's
/// byte-identity contract. Returns the patch outcome for the size gates.
fn patch_and_assert_identity(
    tag: &str,
    kind: OutputType,
    slack: bool,
    adhoc: bool,
    old: Vec<LinkInput>,
    new: Vec<LinkInput>,
) -> pgr_emit::incremental::PatchOutcome {
    let cfg_old = cfg_adhoc(kind, slack, Vec::new(), adhoc);
    let (layout1, objects1) = link(&old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();

    let dir = workdir(tag);
    let prev = dir.join("out");
    write_image(&image1, &prev).unwrap();

    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    let cfg_new = cfg_adhoc(kind, slack, anchors_of(&layout1), adhoc);
    let (layout2, objects2) = link(&new, &cfg_new);
    let image2_full = build_image_fused(&layout2, &objects2).unwrap();

    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    let plan = match &decision {
        PatchDecision::InPlace(p) => p.clone(),
        PatchDecision::Fallback(r) => panic!("expected in place, fell back: {r}"),
    };

    let (outcome, next_record) =
        apply_patch(&prev, &record, &plan, &layout2, &objects2, &prev).unwrap();
    assert!(!outcome.untouched);
    assert!(outcome.bytes_patched <= image1.len() as u64, "patch wrote more than the image");

    let patched = std::fs::read(&prev).unwrap();
    assert_eq!(
        patched, image2_full,
        "the patched output must be byte-identical to the full fused emit"
    );
    // The returned record describes the new state exactly.
    assert_eq!(next_record, LinkRecord::record(&layout2, &objects2, &image2_full).unwrap());
    // The next relink over the same inputs is a no-op.
    let decision3 = plan_patch(&next_record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    assert!(matches!(decision3, PatchDecision::InPlace(ref p) if p.is_untouched()));
    outcome
}

#[test]
fn body_edit_patches_in_place_and_matches_the_full_emit() {
    let outcome = patch_and_assert_identity(
        "body_edit",
        OutputType::Execute,
        true,
        true,
        inputs(hello(64, false)),
        inputs(hello(64, true)),
    );
    // A same-size body edit: the content tile(s) plus the UUID page — a
    // small fraction of the image.
    assert!(
        outcome.dirty_tiles <= 3,
        "a one-function edit patched {} tiles",
        outcome.dirty_tiles
    );
}

#[test]
fn growth_within_slack_patches_in_place_and_matches_the_full_emit() {
    // A 32 KiB `__text` grows by 1 KiB — inside the reserved slack. The
    // grown piece shifts the section's tail (2 text tiles dirty), the
    // function-starts stream gains a byte (LINKEDIT churn — chunk offsets
    // rearrange inside the frozen segment), and the UUID page rides along.
    // Everything else — the majority of the image — is reused.
    let outcome = patch_and_assert_identity(
        "growth",
        OutputType::Execute,
        true,
        true,
        inputs(hello(32 * 1024, false)),
        inputs(hello(33 * 1024, false)),
    );
    assert!(
        outcome.dirty_tiles < outcome.total_tiles,
        "growth within slack must stay in place ({} of {})",
        outcome.dirty_tiles,
        outcome.total_tiles
    );
    assert!(
        outcome.bytes_patched < u64::from(outcome.total_tiles - 1) * 16 * 1024,
        "the patch must write less than the whole image"
    );
}

#[test]
fn dylib_output_patches_in_place_and_matches_the_full_emit() {
    // The image-base-0 path: dylibs/bundles subtract nothing from vaddrs.
    patch_and_assert_identity(
        "dylib",
        OutputType::Dylib,
        true,
        true,
        inputs(hello(64, false)),
        inputs(hello(64, true)),
    );
}

#[test]
fn no_slack_corpus_still_patches_same_size_edits() {
    // Exact packing (the v1.0 default): a same-size edit keeps every size
    // and offset — the in-place tier still applies.
    patch_and_assert_identity(
        "no_slack",
        OutputType::Execute,
        false,
        true,
        inputs(hello(64, false)),
        inputs(hello(64, true)),
    );
}

#[test]
fn unchanged_relink_is_untouched() {
    let old = inputs(hello(64, false));
    let cfg_old = cfg(OutputType::Execute, true, Vec::new());
    let (layout1, objects1) = link(&old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    // Same inputs, anchored config: identical plan.
    let cfg_new = cfg(OutputType::Execute, true, anchors_of(&layout1));
    let (layout2, objects2) = link(&old, &cfg_new);
    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    match decision {
        PatchDecision::InPlace(plan) => {
            assert!(plan.is_untouched(), "identical inputs must dirty nothing");
            assert!(apply_patch(
                &std::env::temp_dir().join("pgr_emit_inc_noop_missing"),
                &record,
                &plan,
                &layout2,
                &objects2,
                &std::env::temp_dir().join("pgr_emit_inc_noop_missing_out"),
            )
            .is_err(), "an untouched plan is not an apply request");
        }
        PatchDecision::Fallback(r) => panic!("identical inputs fell back: {r}"),
    }
}

#[test]
fn symbol_count_change_falls_back_to_the_clean_link() {
    let old = inputs(hello(64, false));
    let cfg_old = cfg(OutputType::Execute, true, Vec::new());
    let (layout1, objects1) = link(&old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    // The edit adds a local symbol: the symtab grows, the `__LINKEDIT`
    // chunk plan moves — the frozen skeleton is gone.
    let mut b = hello(64, true);
    b.add_symbol(ObjectSymbol::Defined {
        name: "_new_local".into(),
        section_index: 0,
        value: 16,
        weak: false,
    });
    let new = inputs(b);
    let cfg_new = cfg(OutputType::Execute, true, anchors_of(&layout1));
    let (layout2, objects2) = link(&new, &cfg_new);
    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    match decision {
        PatchDecision::Fallback(FallbackReason::Skeleton { detail, .. }) => {
            assert!(!detail.is_empty());
        }
        other => panic!("expected a skeleton fallback, got {other:?}"),
    }
}

#[test]
fn growth_past_the_anchor_falls_back_through_the_ladder() {
    let old = inputs(hello(64, false));
    let cfg_old = cfg(OutputType::Execute, true, Vec::new());
    let (layout1, objects1) = link(&old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    // 64 KiB of new text blows way past the min-pad anchor: the section
    // resizes — the ladder classifies it (segment re-layout tier; the v1
    // engine escalates straight to the clean link).
    let new = inputs(hello(64 * 1024, false));
    let cfg_new = cfg(OutputType::Execute, true, anchors_of(&layout1));
    let (layout2, objects2) = link(&new, &cfg_new);
    let decision = plan_patch(
        &record,
        &layout2,
        &objects2,
        cfg_new.layout_slack.as_ref(),
    )
    .unwrap();
    match decision {
        PatchDecision::Fallback(FallbackReason::Skeleton {
            tier: Some(tier), ..
        }) => assert_ne!(tier, pgr_core::slack::LayoutFallback::InPlace),
        other => panic!("expected a ladder-classified fallback, got {other:?}"),
    }
}

#[test]
fn integrity_gate_checks_what_it_claims_and_no_more() {
    let old = inputs(hello(64, false));
    let cfg_old = cfg(OutputType::Execute, true, Vec::new());
    let (layout1, objects1) = link(&old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    let dir = workdir("integrity");
    let path = dir.join("out");
    std::fs::write(&path, &image1).unwrap();
    assert!(matches!(check_output(&path, &record).unwrap(), Integrity::Match));

    // Tamper page 0 (sampled): caught.
    let mut tampered = image1.clone();
    tampered[16] ^= 0xff;
    std::fs::write(&path, &tampered).unwrap();
    assert!(matches!(
        check_output(&path, &record).unwrap(),
        Integrity::Mismatch { .. }
    ));

    // Tamper the last hashed page (sampled): caught. The last hashed page
    // starts at (pages-1) * 4096 — a partial tail page when code_limit is
    // not 4 KiB-aligned.
    let last_page = ((record.hashed_pages() - 1) * 4096) as usize;
    let mut tampered = image1.clone();
    tampered[last_page + 5] ^= 0xff;
    std::fs::write(&path, &tampered).unwrap();
    assert!(matches!(
        check_output(&path, &record).unwrap(),
        Integrity::Mismatch { .. }
    ));

    // Resize: caught by the length gate.
    std::fs::write(&path, &image1[..image1.len() - 8]).unwrap();
    assert!(matches!(
        check_output(&path, &record).unwrap(),
        Integrity::Mismatch { .. }
    ));

    // Remove: an error (the caller falls back).
    std::fs::remove_file(&path).unwrap();
    assert!(check_output(&path, &record).is_err());

    // And the honest trust-model pin: corruption on an *unsampled* hashed
    // page is NOT caught here (the signature is the load-time gate; the
    // `-incremental-verify` audit catches it) — the patch proceeds and the
    // resulting image is still byte-identical to the clean link.
    let first_mid = 4096 * 2 + 3; // page 2: 0 % 64 != 0, not last
    let mut tampered = image1.clone();
    tampered[first_mid] ^= 0xff;
    std::fs::write(&path, &tampered).unwrap();
    assert!(matches!(check_output(&path, &record).unwrap(), Integrity::Match));
    let cfg_new = cfg(OutputType::Execute, true, anchors_of(&layout1));
    let (layout2, objects2) = link(&old, &cfg_new);
    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    let PatchDecision::InPlace(plan) = decision else {
        panic!("identical inputs fell back");
    };
    assert!(plan.is_untouched(), "tampering invisible to the record is a no-op");
}

#[test]
fn unsigned_output_patches_without_a_hash_table() {
    // `-no_adhoc`: no signature, no page hashes — the patch path runs the
    // same span diff with an empty hashed prefix.
    patch_and_assert_identity(
        "unsigned",
        OutputType::Execute,
        true,
        false,
        inputs(hello(64, false)),
        inputs(hello(64, true)),
    );
}

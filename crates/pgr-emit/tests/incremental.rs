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
//! honest about what it checks. Tier 2a adds the cross-link import table:
//! the record carries it (v2), the anchored relink keeps its ordinals, and
//! the byte-identity contract holds under import churn — including the
//! scaled-down randomized-edit gate (the M9 GA bar runs 10⁴ sequences on
//! the P0 rig; this suite runs a deterministic subset in CI).

use pgr_core::layout::{Layout, LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link_cached};
use pgr_core::resolve::Dylib;
use pgr_core::slack::{SlackAnchor, SlackPolicy};
use pgr_core::stable_imports::StableImport;
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

/// hello.o plus `locals` unreferenced local symbols pinned into `__text`:
/// the locals land in the output symtab and string pool (the tier-2a
/// symbol-count gate proves they do), so adding them grows the
/// `__LINKEDIT` chunk stream and removing it shrinks — the LINKEDIT-shrink
/// corpus. The text bytes and relocations are invariant under `locals`.
fn hello_with_locals(text_bytes: usize, body_flip: bool, locals: usize) -> ObjectBuilder {
    let mut b = hello(text_bytes, body_flip);
    for i in 0..locals {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_pgr_local_{i:04}"),
            section_index: 0,
            value: u64::try_from(i % 16).unwrap_or(0) * 4,
            weak: false,
        });
    }
    b
}

fn inputs(hello: &ObjectBuilder) -> Vec<LinkInput> {
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

fn cfg_adhoc(kind: OutputType, slack: bool, anchors: Vec<SlackAnchor>, adhoc: bool) -> LinkConfig {
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
    old: &[LinkInput],
    new: &[LinkInput],
) -> pgr_emit::incremental::PatchOutcome {
    let cfg_old = cfg_adhoc(kind, slack, Vec::new(), adhoc);
    let (layout1, objects1) = link(old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();

    let dir = workdir(tag);
    let prev = dir.join("out");
    write_image(&image1, &prev).unwrap();

    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    let mut cfg_new = cfg_adhoc(kind, slack, anchors_of(&layout1), adhoc);
    // The relink cycle anchors the signature boundary (the LINKEDIT tail
    // reservation's counterpart; the driver does the same from the record).
    cfg_new.sig_anchor = slack.then_some(layout1.linkedit.sig_off).filter(|&v| v > 0);
    let (layout2, objects2) = link(new, &cfg_new);
    let image2_full = build_image_fused(&layout2, &objects2).unwrap();

    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    let plan = match &decision {
        PatchDecision::InPlace(p) => p.clone(),
        PatchDecision::Fallback(r) => panic!("expected in place, fell back: {r}"),
    };

    let (outcome, next_record) =
        apply_patch(&prev, &record, &plan, &layout2, &objects2, &prev).unwrap();
    assert!(!outcome.untouched);
    assert!(
        outcome.bytes_patched <= image1.len() as u64,
        "patch wrote more than the image"
    );

    let patched = std::fs::read(&prev).unwrap();
    assert_eq!(
        patched, image2_full,
        "the patched output must be byte-identical to the full fused emit"
    );
    // The returned record describes the new state exactly.
    assert_eq!(
        next_record,
        LinkRecord::record(&layout2, &objects2, &image2_full).unwrap()
    );
    // The next relink over the same inputs is a no-op.
    let decision3 = plan_patch(
        &next_record,
        &layout2,
        &objects2,
        cfg_new.layout_slack.as_ref(),
    )
    .unwrap();
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
        &inputs(&hello(64, false)),
        &inputs(&hello(64, true)),
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
        &inputs(&hello(32 * 1024, false)),
        &inputs(&hello(33 * 1024, false)),
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
        &inputs(&hello(64, false)),
        &inputs(&hello(64, true)),
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
        &inputs(&hello(64, false)),
        &inputs(&hello(64, true)),
    );
}

#[test]
fn unchanged_relink_is_untouched() {
    let old = inputs(&hello(64, false));
    let cfg_old = cfg(OutputType::Execute, true, Vec::new());
    let (layout1, objects1) = link(&old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    // Same inputs, anchored config: identical plan.
    let mut cfg_new = cfg(OutputType::Execute, true, anchors_of(&layout1));
    cfg_new.sig_anchor = Some(layout1.linkedit.sig_off);
    let (layout2, objects2) = link(&old, &cfg_new);
    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    match decision {
        PatchDecision::InPlace(plan) => {
            assert!(plan.is_untouched(), "identical inputs must dirty nothing");
            assert!(
                apply_patch(
                    &std::env::temp_dir().join("pgr_emit_inc_noop_missing"),
                    &record,
                    &plan,
                    &layout2,
                    &objects2,
                    &std::env::temp_dir().join("pgr_emit_inc_noop_missing_out"),
                )
                .is_err(),
                "an untouched plan is not an apply request"
            );
        }
        PatchDecision::Fallback(r) => panic!("identical inputs fell back: {r}"),
    }
}

#[test]
fn symbol_count_change_patches_in_place_inside_the_linkedit_reservation() {
    // Tier 2a: the `__LINKEDIT` tail reservation (slack links) keeps the
    // signature boundary fixed while the chunk stream grows — one extra
    // symtab entry (16 B) plus its string now patches in place instead of
    // moving `sig_off` and falling back (the tier-1 behavior, pinned by
    // `ident_change_falls_back_to_the_clean_link` below).
    let old = inputs(&hello(64, false));
    let cfg_old = cfg(OutputType::Execute, true, Vec::new());
    let (layout1, objects1) = link(&old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    // The edit adds a local symbol: the symtab grows into the reservation.
    let mut b = hello(64, true);
    b.add_symbol(ObjectSymbol::Defined {
        name: "_new_local".into(),
        section_index: 0,
        value: 16,
        weak: false,
    });
    let new = inputs(&b);
    let mut cfg_new = cfg(OutputType::Execute, true, anchors_of(&layout1));
    cfg_new.sig_anchor = Some(layout1.linkedit.sig_off);
    let (layout2, objects2) = link(&new, &cfg_new);
    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    let plan = match decision {
        PatchDecision::InPlace(p) => p,
        PatchDecision::Fallback(reason) => panic!(
            "symtab growth within the reservation must patch in place, got Fallback({reason:?})"
        ),
    };
    let dir = workdir("symtab_growth");
    let prev = dir.join("out");
    write_image(&image1, &prev).unwrap();
    let (_outcome, next_record) =
        apply_patch(&prev, &record, &plan, &layout2, &objects2, &prev).unwrap();
    let full = build_image_fused(&layout2, &objects2).unwrap();
    assert_eq!(
        std::fs::read(&prev).unwrap(),
        full,
        "the symtab-growth patch must stay byte-identical to the full emit"
    );
    assert_eq!(
        next_record,
        LinkRecord::record(&layout2, &objects2, &full).unwrap()
    );
}

#[test]
fn linkedit_shrink_patches_through_segment_relayout() {
    // The §7.3 ladder's shrink rung (the tier-2 trigger's mirror): an
    // unsigned image has no signature boundary to anchor the chunk tail
    // (`adhoc = false` records `sig_off = 0`), so a symtab/string-pool
    // shrink — the locals block removed — moves the `__LINKEDIT` end down
    // and the image shrinks with it. The content skeleton is frozen end to
    // end, so the relayout tier must admit the shape: the clone is
    // truncated to the new size, the moved chunk tail is re-emitted, and
    // the byte-identity contract holds. (The signed counterpart never
    // shrinks — the sig anchor keeps the boundary — and stays tier-1.)
    let old = inputs(&hello_with_locals(64, false, 256));
    let cfg_old = cfg_adhoc(OutputType::Execute, true, Vec::new(), false);
    let (layout1, objects1) = link(&old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();
    assert_eq!(record.linkedit.sig_off, 0, "the corpus is unsigned");

    let new = inputs(&hello_with_locals(64, false, 0));
    let mut cfg_new = cfg_adhoc(OutputType::Execute, true, anchors_of(&layout1), false);
    cfg_new.sig_anchor = None;
    let (layout2, objects2) = link(&new, &cfg_new);
    assert!(
        layout2.file_size < layout1.file_size,
        "the chunk stream shrank the image ({} -> {})",
        layout1.file_size,
        layout2.file_size
    );
    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    let plan = match decision {
        PatchDecision::InPlace(plan) => plan,
        PatchDecision::Fallback(reason) => panic!(
            "a LINKEDIT shrink over a frozen content skeleton must patch (the shrink rung), got Fallback({reason:?})"
        ),
    };
    assert!(
        plan.relayout.is_some(),
        "the shrinking tail is a segment-relayout plan"
    );

    let dir = workdir("linkedit_shrink");
    let prev = dir.join("out");
    write_image(&image1, &prev).unwrap();
    let (outcome, next_record) =
        apply_patch(&prev, &record, &plan, &layout2, &objects2, &prev).unwrap();
    assert!(!outcome.untouched);
    assert!(
        outcome.bytes_patched < image1.len() as u64,
        "the shrink patch must not rewrite the whole image ({} of {})",
        outcome.bytes_patched,
        image1.len()
    );
    let full = build_image_fused(&layout2, &objects2).unwrap();
    assert_eq!(
        std::fs::read(&prev).unwrap(),
        full,
        "the shrink patch must stay byte-identical to the full fused emit"
    );
    assert_eq!(
        next_record,
        LinkRecord::record(&layout2, &objects2, &full).unwrap()
    );
    assert_eq!(next_record.file_size, layout2.file_size);

    // The shrunk state is the next relink's baseline: a same-size body edit
    // on top patches in place (tier 1), and the locals grow back through
    // the LINKEDIT-overflow trigger (tier 2, the pre-existing direction).
    let flipped = inputs(&hello_with_locals(64, true, 0));
    let (layout3, objects3) = link(&flipped, &cfg_new);
    let decision3 = plan_patch(
        &next_record,
        &layout3,
        &objects3,
        cfg_new.layout_slack.as_ref(),
    )
    .unwrap();
    let plan3 = match decision3 {
        PatchDecision::InPlace(plan) => plan,
        PatchDecision::Fallback(reason) => panic!(
            "a body edit on the shrunk baseline must patch in place, got Fallback({reason:?})"
        ),
    };
    let (outcome3, record3) =
        apply_patch(&prev, &next_record, &plan3, &layout3, &objects3, &prev).unwrap();
    let full3 = build_image_fused(&layout3, &objects3).unwrap();
    assert_eq!(std::fs::read(&prev).unwrap(), full3);
    assert_eq!(
        record3,
        LinkRecord::record(&layout3, &objects3, &full3).unwrap()
    );
    assert!(
        outcome3.bytes_patched < image1.len() as u64,
        "the tier-1 patch on the shrunk baseline stays small"
    );

    let regrown = inputs(&hello_with_locals(64, true, 256));
    let (layout4, objects4) = link(&regrown, &cfg_new);
    let decision4 =
        plan_patch(&record3, &layout4, &objects4, cfg_new.layout_slack.as_ref()).unwrap();
    let plan4 = match decision4 {
        PatchDecision::InPlace(plan) => plan,
        PatchDecision::Fallback(reason) => panic!(
            "the locals growing back is the LINKEDIT-overflow trigger, got Fallback({reason:?})"
        ),
    };
    let (_, _) = apply_patch(&prev, &record3, &plan4, &layout4, &objects4, &prev).unwrap();
    let full4 = build_image_fused(&layout4, &objects4).unwrap();
    assert_eq!(
        std::fs::read(&prev).unwrap(),
        full4,
        "the regrow patch must stay byte-identical to the full fused emit"
    );
}

#[test]
fn ident_change_falls_back_to_the_clean_link() {
    // The identity is frozen skeleton state: renaming the image is not a
    // bytes-only edit (the CodeDirectory's identifier changes size), so
    // the ladder re-runs the full link.
    let old = inputs(&hello(64, false));
    let cfg_old = cfg(OutputType::Execute, true, Vec::new());
    let (layout1, objects1) = link(&old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    let mut cfg_new = cfg(OutputType::Execute, true, anchors_of(&layout1));
    cfg_new.sig_anchor = Some(layout1.linkedit.sig_off);
    cfg_new.ident = "m9-incremental-renamed".into();
    let (layout2, objects2) = link(&old, &cfg_new);
    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    match decision {
        PatchDecision::Fallback(FallbackReason::Skeleton { detail, .. }) => {
            assert_ne!(detail, "");
        }
        other => panic!("expected a skeleton fallback, got {other:?}"),
    }
}

#[test]
fn overflow_past_the_anchor_patches_through_segment_relayout() {
    // §7.3 ladder tier 2: the edit overflows the reserved slack, the
    // section re-pads naturally, and everything behind it shifts — the
    // ladder's segment-relayout tier. The planner admits the shifted
    // skeleton as a patch plan (record v4 carries the output-section
    // digests the shift-exemption gate leans on), the patch rewrites the
    // moved suffix, and the byte-identity contract still holds.
    let old = inputs(&hello(32 * 1024, false));
    let cfg_old = cfg(OutputType::Execute, true, Vec::new());
    let (layout1, objects1) = link(&old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    // 64 KiB of new text blows way past the min-pad anchor: the section
    // resizes (growth within the ladder's segment-relayout bound).
    let new = inputs(&hello(96 * 1024, false));
    let mut cfg_new = cfg(OutputType::Execute, true, anchors_of(&layout1));
    cfg_new.sig_anchor = Some(layout1.linkedit.sig_off);
    let (layout2, objects2) = link(&new, &cfg_new);
    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    let plan = match decision {
        PatchDecision::InPlace(plan) => plan,
        PatchDecision::Fallback(reason) => panic!(
            "a slack overflow within the relayout bound must patch (tier 2), got Fallback({reason:?})"
        ),
    };
    assert!(
        plan.relayout.is_some(),
        "the shifted skeleton is a segment-relayout plan"
    );
    assert!(
        layout2.file_size > layout1.file_size,
        "the section grew: the image grows with it"
    );

    let dir = workdir("relayout");
    let prev = dir.join("out");
    write_image(&image1, &prev).unwrap();
    let (outcome, next_record) =
        apply_patch(&prev, &record, &plan, &layout2, &objects2, &prev).unwrap();
    assert!(!outcome.untouched);
    let full = build_image_fused(&layout2, &objects2).unwrap();
    assert_eq!(
        std::fs::read(&prev).unwrap(),
        full,
        "the relayout patch must stay byte-identical to the full fused emit"
    );
    assert_eq!(
        next_record,
        LinkRecord::record(&layout2, &objects2, &full).unwrap()
    );

    // The refreshed record is the next relink's baseline: a same-size body
    // edit on top patches in place (tier 1 again), and an unchanged relink
    // is a no-op.
    let decision3 = plan_patch(
        &next_record,
        &layout2,
        &objects2,
        cfg_new.layout_slack.as_ref(),
    )
    .unwrap();
    assert!(
        matches!(decision3, PatchDecision::InPlace(ref p) if p.is_untouched()),
        "the relayout state is a fixpoint"
    );
}

#[test]
fn oversized_growth_still_falls_back_to_the_clean_link() {
    // The ladder's top rung stays honest: growth beyond the policy's
    // max pad escalates to the clean link (always available, always
    // correct) — the relayout tier does not absorb arbitrary growth.
    let old = inputs(&hello(64, false));
    let cfg_old = cfg(OutputType::Execute, true, Vec::new());
    let (layout1, objects1) = link(&old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    let new = inputs(&hello(4 * 1024 * 1024, false));
    let mut cfg_new = cfg(OutputType::Execute, true, anchors_of(&layout1));
    cfg_new.sig_anchor = Some(layout1.linkedit.sig_off);
    let (layout2, objects2) = link(&new, &cfg_new);
    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    match decision {
        PatchDecision::Fallback(FallbackReason::Skeleton {
            tier: Some(tier), ..
        }) => assert_eq!(
            tier,
            pgr_core::slack::LayoutFallback::CleanLink,
            "multi-megabyte growth must escalate past the relayout tier"
        ),
        other => panic!("expected a clean-link fallback, got {other:?}"),
    }
}

/// The §7.3 tier-2 loop over an edited corpus (an overflow beyond the
/// anchor within the relayout bound), asserting the same contract as the
/// tier-1 helper: byte-identity, the refreshed record, the fixpoint.
fn relayout_and_assert_identity(
    tag: &str,
    kind: OutputType,
    adhoc: bool,
    old_text: usize,
    new_text: usize,
) {
    let cfg_old = cfg_adhoc(kind, true, Vec::new(), adhoc);
    let (layout1, objects1) = link(&inputs(&hello(old_text, false)), &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    let mut cfg_new = cfg_adhoc(kind, true, anchors_of(&layout1), adhoc);
    cfg_new.sig_anchor = Some(layout1.linkedit.sig_off);
    let (layout2, objects2) = link(&inputs(&hello(new_text, false)), &cfg_new);
    let image2_full = build_image_fused(&layout2, &objects2).unwrap();

    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    let plan = match &decision {
        PatchDecision::InPlace(p) => p.clone(),
        PatchDecision::Fallback(r) => panic!("expected a relayout plan, fell back: {r}"),
    };
    assert!(plan.relayout.is_some(), "the overflow must admit tier 2");

    let dir = workdir(tag);
    let prev = dir.join("out");
    write_image(&image1, &prev).unwrap();
    let (outcome, next_record) =
        apply_patch(&prev, &record, &plan, &layout2, &objects2, &prev).unwrap();
    assert!(!outcome.untouched);
    let patched = std::fs::read(&prev).unwrap();
    assert_eq!(
        patched, image2_full,
        "the relayout patch must be byte-identical to the full fused emit"
    );
    assert_eq!(
        next_record,
        LinkRecord::record(&layout2, &objects2, &image2_full).unwrap()
    );
    let decision3 = plan_patch(
        &next_record,
        &layout2,
        &objects2,
        cfg_new.layout_slack.as_ref(),
    )
    .unwrap();
    assert!(matches!(decision3, PatchDecision::InPlace(ref p) if p.is_untouched()));
}

#[test]
fn unsigned_output_relayout_matches_the_full_emit() {
    // `-no_adhoc`: the relayout tier without a signature — no hash table,
    // no CodeDirectory rebuild, the patch is the moved suffix alone. The
    // corpus keeps the moved suffix a minority of the image (the §7.3
    // economics gate declines a whole-image patch by design).
    relayout_and_assert_identity(
        "unsigned_relayout",
        OutputType::Execute,
        false,
        256 * 1024,
        256 * 1024 + 64 * 1024,
    );
}

#[test]
fn dylib_output_relayout_matches_the_full_emit() {
    // The image-base-0 path across a moved skeleton: downstream vaddrs
    // shift without an image base, the load commands and the CodeDirectory
    // (execSegLimit) ride the header diff.
    relayout_and_assert_identity(
        "dylib_relayout",
        OutputType::Dylib,
        true,
        256 * 1024,
        256 * 1024 + 64 * 1024,
    );
}

#[test]
fn linkedit_overflow_patches_through_segment_relayout() {
    // The second tier-2 trigger: the `__LINKEDIT` chunk stream outgrows
    // the signature-boundary reservation — `sig_off` moves with it. No
    // section resizes; the ladder's relayout tier still applies (the
    // moved LINKEDIT tail is the shifted suffix the patch rewrites).
    let mut b = hello(64 * 1024, false);
    for i in 0..300 {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_added_local_{i}"),
            section_index: 0,
            value: 64,
            weak: false,
        });
    }
    let old = inputs(&hello(64 * 1024, false));
    let cfg_old = cfg(OutputType::Execute, true, Vec::new());
    let (layout1, objects1) = link(&old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    let new = inputs(&b);
    let mut cfg_new = cfg(OutputType::Execute, true, anchors_of(&layout1));
    cfg_new.sig_anchor = Some(layout1.linkedit.sig_off);
    let (layout2, objects2) = link(&new, &cfg_new);
    assert_ne!(
        layout2.linkedit.sig_off, layout1.linkedit.sig_off,
        "the chunk stream outgrows the reservation: the boundary moves"
    );
    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    let plan = match decision {
        PatchDecision::InPlace(plan) => plan,
        PatchDecision::Fallback(reason) => panic!(
            "a LINKEDIT overflow within the relayout tier must patch, got Fallback({reason:?})"
        ),
    };
    assert!(plan.relayout.is_some());

    let dir = workdir("linkedit_overflow");
    let prev = dir.join("out");
    write_image(&image1, &prev).unwrap();
    let (_outcome, next_record) =
        apply_patch(&prev, &record, &plan, &layout2, &objects2, &prev).unwrap();
    let full = build_image_fused(&layout2, &objects2).unwrap();
    assert_eq!(
        std::fs::read(&prev).unwrap(),
        full,
        "the LINKEDIT-overflow patch must stay byte-identical to the full emit"
    );
    assert_eq!(
        next_record,
        LinkRecord::record(&layout2, &objects2, &full).unwrap()
    );
}

#[test]
fn integrity_gate_checks_what_it_claims_and_no_more() {
    let old = inputs(&hello(64, false));
    let cfg_old = cfg(OutputType::Execute, true, Vec::new());
    let (layout1, objects1) = link(&old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    let dir = workdir("integrity");
    let path = dir.join("out");
    std::fs::write(&path, &image1).unwrap();
    assert!(matches!(
        check_output(&path, &record).unwrap(),
        Integrity::Match
    ));

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
    assert!(matches!(
        check_output(&path, &record).unwrap(),
        Integrity::Match
    ));
    let mut cfg_new = cfg(OutputType::Execute, true, anchors_of(&layout1));
    cfg_new.sig_anchor = Some(layout1.linkedit.sig_off);
    let (layout2, objects2) = link(&old, &cfg_new);
    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    let PatchDecision::InPlace(plan) = decision else {
        panic!("identical inputs fell back");
    };
    assert!(
        plan.is_untouched(),
        "tampering invisible to the record is a no-op"
    );
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
        &inputs(&hello(64, false)),
        &inputs(&hello(64, true)),
    );
}

// ---------------------------------------------------------------------------
// Tier 2a — the cross-link import table (§7.3 step 5, D7 closed)
// ---------------------------------------------------------------------------

/// An object whose `__data` carries one external pointer per entry of
/// `binds` (undefined externs resolved by `cfg.dylibs`), plus `_main`.
fn pointer_main(text_bytes: usize, binds: &[&str]) -> ObjectBuilder {
    pointer_main_with_locals(text_bytes, binds, 0)
}

/// `pointer_main` plus `locals` unreferenced local symbols pinned into
/// `__text` (invariant text bytes; the symtab/string-pool churn rides the
/// `__LINKEDIT` chunk stream).
fn pointer_main_with_locals(text_bytes: usize, binds: &[&str], locals: usize) -> ObjectBuilder {
    let mut words: Vec<u32> = vec![0xD65F_03C0]; // ret
    words.resize(text_bytes / 4, 0xD503_201F);
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut b = ObjectBuilder::new("main.o");
    let text_idx = b.add_section(ObjectSection::text("__text", text, vec![]));
    let data_len = binds.len() * 8;
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; data_len], vec![]));
    for name in binds {
        b.add_symbol(ObjectSymbol::Undefined {
            name: (*name).into(),
            weak_ref: false,
        });
    }
    for i in 0..locals {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_pgr_local_{i:04}"),
            section_index: text_idx,
            value: u64::try_from(i % 16).unwrap_or(0) * 4,
            weak: false,
        });
    }
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text_idx,
        value: 0,
        weak: false,
    });
    for (i, _) in binds.iter().enumerate() {
        // The symtab groups locals/defs/undefs; `sym_index` maps the
        // declaration index onto the relocation's table index.
        let sym = b.sym_index(i);
        b.section_mut(data)
            .relocs
            .push(ObjectReloc::unsigned(sym).at((i * 8) as u32));
    }
    b
}

fn import_lib(exports: &[&str]) -> Dylib {
    Dylib {
        install_name: "/usr/lib/libInc.dylib".into(),
        current_version: (1 << 16) | (2 << 8),
        compatibility_version: 1 << 16,
        exports: exports.iter().map(|s| s.as_bytes().to_vec()).collect(),
        weak: false,
        reexport: false,
    }
}

fn stable_cfg(
    kind: OutputType,
    anchors: Vec<SlackAnchor>,
    imports: Option<Vec<StableImport>>,
    sig_anchor: Option<u64>,
) -> LinkConfig {
    LinkConfig {
        ident: "m9-import-churn".into(),
        filetype: kind,
        install_name: matches!(kind, OutputType::Dylib).then(|| "@rpath/libinc.dylib".into()),
        layout_slack: Some(SlackPolicy::default()),
        slack_anchor: anchors,
        stable_imports: imports,
        sig_anchor,
        dylibs: vec![import_lib(&["_log", "_warn", "_trace"])],
        ..LinkConfig::default()
    }
}

/// The record's import names, in table order.
fn record_import_names(record: &LinkRecord) -> Vec<String> {
    record
        .imports
        .iter()
        .map(|k| String::from_utf8_lossy(&k.name).into_owned())
        .collect()
}

#[test]
fn record_carries_the_import_table_and_roundtrips() {
    let old = inputs(&pointer_main(64, &["_log"]));
    let cfg1 = stable_cfg(OutputType::Execute, Vec::new(), None, None);
    let (layout1, objects1) = link(&old, &cfg1);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    assert_eq!(
        record_import_names(&record),
        ["_log"],
        "the record captures the link's import identities"
    );
    let back = LinkRecord::decode(&record.encode()).expect("v2 roundtrip");
    assert_eq!(
        back.imports, record.imports,
        "the codec is lossless over the table"
    );

    // An empty table roundtrips too (a corpus with no binds).
    let plain = inputs(&hello(64, false));
    let (plain_layout, plain_objects) = link(&plain, &cfg(OutputType::Execute, true, Vec::new()));
    let plain_image = build_image_fused(&plain_layout, &plain_objects).unwrap();
    let plain_record = LinkRecord::record(&plain_layout, &plain_objects, &plain_image).unwrap();
    assert_eq!(plain_record.imports, [] as [pgr_core::StableImport; 0]);
    let plain_back = LinkRecord::decode(&plain_record.encode()).expect("empty-table roundtrip");
    assert_eq!(plain_back.imports, [] as [pgr_core::StableImport; 0]);
}

#[test]
fn import_adding_edit_patches_byte_identically_with_stable_ordinals() {
    let kind = OutputType::Execute;
    let old = inputs(&pointer_main(32 * 1024, &["_log"]));
    let cfg1 = stable_cfg(kind, Vec::new(), None, None);
    let (layout1, objects1) = link(&old, &cfg1);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();

    let dir = workdir("import_churn");
    let prev = dir.join("out");
    write_image(&image1, &prev).unwrap();
    let record1 = LinkRecord::record(&layout1, &objects1, &image1).unwrap();
    assert_eq!(record_import_names(&record1), ["_log"]);

    // The edit re-points slot 0 at a NEW import and binds _log one slot
    // later: first-use renumbering would rewrite _log's word; the anchor
    // keeps the table [_log] and appends _warn.
    let new = inputs(&pointer_main(32 * 1024, &["_warn", "_log"]));
    let cfg2 = stable_cfg(
        kind,
        anchors_of(&layout1),
        Some(record1.imports.clone()),
        Some(layout1.linkedit.sig_off),
    );
    let (layout2, objects2) = link(&new, &cfg2);
    let image2_full = build_image_fused(&layout2, &objects2).unwrap();

    let decision = plan_patch(&record1, &layout2, &objects2, cfg2.layout_slack.as_ref()).unwrap();
    let plan = match &decision {
        PatchDecision::InPlace(p) => p.clone(),
        PatchDecision::Fallback(r) => panic!("expected in place, fell back: {r}"),
    };
    let (outcome, next_record) =
        apply_patch(&prev, &record1, &plan, &layout2, &objects2, &prev).unwrap();
    let patched = std::fs::read(&prev).unwrap();
    assert_eq!(
        patched, image2_full,
        "patched output byte-identical to the full emit under import churn"
    );
    assert_eq!(
        record_import_names(&next_record),
        ["_log", "_warn"],
        "the refreshed record anchors the next cycle"
    );
    assert!(outcome.dirty_tiles < outcome.total_tiles);
    // The next relink over the same inputs is a no-op (the anchored state
    // is a fixpoint — importing nothing new renumbers nothing).
    let decision3 = plan_patch(
        &next_record,
        &layout2,
        &objects2,
        cfg2.layout_slack.as_ref(),
    )
    .unwrap();
    assert!(matches!(decision3, PatchDecision::InPlace(ref p) if p.is_untouched()));
}

#[test]
fn randomized_edit_sequences_keep_the_patch_byte_identical() {
    // The scaled-down M9 GA randomized gate (roadmap: 10⁴ sequences on the
    // decision rig; CI runs this deterministic subset, and
    // `PGR_RANDOMIZED_STEPS` scales the sequence count — 2000 sequences
    // × 5 steps is the 10⁴ GA profile). A xorshift64* walk over edit
    // kinds — body growth, import add, import retarget, oversized growth,
    // symtab churn (grow past / shrink below the boundary reservation),
    // no-op — must land every step on either an in-place patch that is
    // byte-identical to the full emit, or an honest fallback that
    // re-records.
    let kind = OutputType::Execute;
    let exports = ["_log", "_warn", "_trace"];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };

    // Link 1: one object, one 8 KiB text, one bind. The seeded baseline.
    let cfg1 = stable_cfg(kind, Vec::new(), None, None);
    let (mut layout, objects) = link(&inputs(&pointer_main(8 * 1024, &["_log"])), &cfg1);
    let mut image = build_image_fused(&layout, &objects).unwrap();
    let mut record = LinkRecord::record(&layout, &objects, &image).unwrap();
    let mut binds: usize = 1;
    let mut shift: usize = 0;
    let mut locals: usize = 0;

    let dir = workdir("randomized");
    let prev = dir.join("out");
    write_image(&image, &prev).unwrap();

    let mut in_place_steps = 0u32;
    let mut fallback_steps = 0u32;
    let mut symtab_grow_steps = 0u32;
    let mut symtab_shrink_steps = 0u32;
    let sequences: usize = std::env::var("PGR_RANDOMIZED_STEPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(16);
    for _seq in 0..sequences {
        for _step in 0..5 {
            // Pick the edit from the generator.
            let roll = next() % 7;

            let (new_binds, new_shift, new_text, new_locals) = match roll {
                0 => {
                    // Body growth within slack (same import surface).
                    (
                        binds,
                        shift,
                        8 * 1024 + usize::try_from(next() % 2048).unwrap(),
                        locals,
                    )
                }
                1 => {
                    // Import add: an extra pointer to a (possibly new) export.
                    ((binds + 1).min(exports.len() + 2), shift, 8 * 1024, locals)
                }
                2 => {
                    // Import retarget: same size, different ordinals.
                    (binds.max(1), shift + 1, 8 * 1024, locals)
                }
                3 => {
                    // Big growth: blows the section's reservation — the
                    // ladder's honest exit (re-layout tier classification,
                    // the v1 engine re-runs the full link).
                    (binds, shift, 8 * 1024 + 24 * 1024, locals)
                }
                4 => {
                    // Symtab growth past the boundary reservation: the
                    // LINKEDIT-overflow trigger (tier 2's first shape).
                    (
                        binds,
                        shift,
                        8 * 1024,
                        usize::try_from(next() % 512).unwrap_or(0) + 256,
                    )
                }
                5 => {
                    // Symtab shrink: the chunk stream contracts under the
                    // anchored signature boundary (the tier-1 absorb; the
                    // unsigned shrink rung has its own deterministic gate).
                    (
                        binds,
                        shift,
                        8 * 1024,
                        usize::try_from(next() % 128).unwrap_or(0),
                    )
                }
                _ => {
                    // No-op: the untouched path must stay untouched.
                    (binds, shift, 8 * 1024, locals)
                }
            };
            binds = new_binds;
            shift = new_shift % exports.len();
            let text_bytes = new_text;
            if new_locals > locals {
                symtab_grow_steps += 1;
            } else if new_locals < locals {
                symtab_shrink_steps += 1;
            }
            locals = new_locals;
            let build_binds: Vec<&str> = (0..binds)
                .map(|i| exports[(i + shift) % exports.len()])
                .collect();
            let cfg_n = stable_cfg(
                kind,
                anchors_of(&layout),
                Some(record.imports.clone()),
                Some(layout.linkedit.sig_off),
            );
            let (l2, o2) = link(
                &inputs(&pointer_main_with_locals(text_bytes, &build_binds, locals)),
                &cfg_n,
            );
            let full = build_image_fused(&l2, &o2).unwrap();

            match plan_patch(&record, &l2, &o2, cfg_n.layout_slack.as_ref()).unwrap() {
                PatchDecision::InPlace(plan) => {
                    if plan.is_untouched() {
                        // Nothing changed: the record carries forward.
                        layout = l2;
                        continue;
                    }
                    let (outcome, next_record) =
                        apply_patch(&prev, &record, &plan, &l2, &o2, &prev).unwrap();
                    let patched = std::fs::read(&prev).unwrap();
                    assert_eq!(
                        patched, full,
                        "sequence step diverged: patched != full emit (edit roll {roll})"
                    );
                    assert_eq!(next_record, LinkRecord::record(&l2, &o2, &full).unwrap());
                    record = next_record;
                    layout = l2;
                    image = full;
                    assert!(outcome.bytes_patched <= image.len() as u64);
                    in_place_steps += 1;
                }
                PatchDecision::Fallback(reason) => {
                    // The ladder's honest exit: re-record from the full link.
                    fallback_steps += 1;
                    write_image(&full, &prev).unwrap();
                    record = LinkRecord::record(&l2, &o2, &full).unwrap();
                    layout = l2;
                    // The fallback ladder never produces an untouched plan
                    // for a changed corpus; record why for the report.
                    assert!(!matches!(
                        reason,
                        FallbackReason::RecordUnreadable | FallbackReason::Disabled
                    ));
                }
            }
        }
    }
    assert!(
        in_place_steps > 0 && fallback_steps > 0,
        "the walk must exercise both tiers (in place: {in_place_steps}, fallback: {fallback_steps})"
    );
    assert!(
        symtab_grow_steps > 0 && symtab_shrink_steps > 0,
        "the walk must exercise the symtab-churn dimension \
         (grow: {symtab_grow_steps}, shrink: {symtab_shrink_steps})"
    );
}

// ---------------------------------------------------------------------------
// Tier 2b — the per-symbol change-propagation planner (§7.3 step 3)
// ---------------------------------------------------------------------------

use pgr_core::propagate::section_digests;

/// greet.o with `_greet` at `value` inside an 8-byte `__text`
/// (`nop; ret`): moving `value` retargets hello.o's `BL _greet` without
/// resizing anything — the skeleton holds, the dependents retarget.
fn greet_at(value: u64) -> ObjectBuilder {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0x1F, 0x20, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6], // nop; ret
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value,
        weak: false,
    });
    b.section_mut(data).relocs = vec![ObjectReloc::unsigned(0).at(0)];
    b
}

fn hello_greet_inputs(greet_value: u64) -> Vec<LinkInput> {
    vec![
        LinkInput {
            name: "hello.o".into(),
            bytes: hello(64, false).build().unwrap(),
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet_at(greet_value).build().unwrap(),
        },
    ]
}

#[test]
fn record_v3_roundtrips_the_section_digests_and_rejects_v2() {
    let (layout, objects) = link(
        &inputs(&hello(64, false)),
        &cfg(OutputType::Execute, true, Vec::new()),
    );
    let image = build_image_fused(&layout, &objects).unwrap();
    let record = LinkRecord::record(&layout, &objects, &image).unwrap();

    assert_eq!(
        record.section_digests,
        section_digests(&objects),
        "the record captures the parse's section digests in parse order"
    );
    let back = LinkRecord::decode(&record.encode()).expect("v3 roundtrip");
    assert_eq!(
        back.section_digests, record.section_digests,
        "the codec is lossless over the digest table"
    );

    // A foreign version decodes to None — the relink re-records (the
    // documented fallback contract for pre-2b records).
    let mut downgraded = record.encode();
    downgraded[8..12].copy_from_slice(&2u32.to_le_bytes());
    assert!(
        LinkRecord::decode(&downgraded).is_none(),
        "v2 records must not decode under the v3 codec"
    );
}

#[test]
fn propagation_gate_accepts_a_predicted_dependent_retarget() {
    // `_greet` moves one instruction down (same section size): hello.o's
    // `BL _greet` word retargets. The scope predicts hello.o's text (the
    // dependent site) and greet.o's text (the seed), so the patch stays
    // in place and byte-identical — the gate must not false-fallback on a
    // genuine cross-file dependent change.
    let kind = OutputType::Execute;
    let cfg1 = cfg(kind, true, Vec::new());
    let (layout1, objects1) = link(&hello_greet_inputs(0), &cfg1);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();

    let dir = workdir("propagate_accept");
    let prev = dir.join("out");
    write_image(&image1, &prev).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    let mut cfg2 = cfg(kind, true, anchors_of(&layout1));
    cfg2.sig_anchor = Some(layout1.linkedit.sig_off);
    let (layout2, objects2) = link(&hello_greet_inputs(4), &cfg2);
    let image2_full = build_image_fused(&layout2, &objects2).unwrap();

    let decision = plan_patch(&record, &layout2, &objects2, cfg2.layout_slack.as_ref()).unwrap();
    let plan = match &decision {
        PatchDecision::InPlace(p) => p.clone(),
        PatchDecision::Fallback(r) => panic!("a predicted retarget fell back: {r}"),
    };
    let (outcome, next_record) =
        apply_patch(&prev, &record, &plan, &layout2, &objects2, &prev).unwrap();
    assert_eq!(
        std::fs::read(&prev).unwrap(),
        image2_full,
        "the patched output is byte-identical to the full emit"
    );
    assert_eq!(
        next_record.section_digests,
        section_digests(&objects2),
        "the refreshed record anchors the next cycle to the new parse"
    );
    assert!(outcome.dirty_tiles < outcome.total_tiles);
}

#[test]
fn propagation_gate_declines_an_unpredicted_content_change() {
    // The gate's tripwire: when the span diff dirties a content tile the
    // propagation scope cannot explain (here: a record whose digest table
    // claims a parse it did not see — the stale-record shape), the planner
    // falls back instead of trusting the diff. Fallback is always correct.
    let kind = OutputType::Execute;
    let cfg1 = cfg(kind, true, Vec::new());
    let (layout1, objects1) = link(&inputs(&hello(64, false)), &cfg1);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let mut record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    let mut cfg2 = cfg(kind, true, anchors_of(&layout1));
    cfg2.sig_anchor = Some(layout1.linkedit.sig_off);
    let (layout2, objects2) = link(&inputs(&hello(64, true)), &cfg2);

    // The lie: claim the record saw exactly this (edited) parse. The real
    // recorded spans disagree with what the digest table vouches for, and
    // the gate must catch the discrepancy instead of patching blind.
    record.section_digests = section_digests(&objects2);
    let decision = plan_patch(&record, &layout2, &objects2, cfg2.layout_slack.as_ref()).unwrap();
    match decision {
        PatchDecision::Fallback(FallbackReason::PropagationMismatch { detail }) => {
            assert!(
                detail.contains("tile"),
                "the reason names the tiles: {detail}"
            );
        }
        other => panic!("expected a propagation fallback, got {other:?}"),
    }
}

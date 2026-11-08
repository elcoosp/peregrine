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
fn growth_past_the_anchor_falls_back_through_the_ladder() {
    let old = inputs(&hello(64, false));
    let cfg_old = cfg(OutputType::Execute, true, Vec::new());
    let (layout1, objects1) = link(&old, &cfg_old);
    let image1 = build_image_fused(&layout1, &objects1).unwrap();
    let record = LinkRecord::record(&layout1, &objects1, &image1).unwrap();

    // 64 KiB of new text blows way past the min-pad anchor: the section
    // resizes — the ladder classifies it (segment re-layout tier; the v1
    // engine escalates straight to the clean link).
    let new = inputs(&hello(64 * 1024, false));
    let mut cfg_new = cfg(OutputType::Execute, true, anchors_of(&layout1));
    cfg_new.sig_anchor = Some(layout1.linkedit.sig_off);
    let (layout2, objects2) = link(&new, &cfg_new);
    let decision = plan_patch(&record, &layout2, &objects2, cfg_new.layout_slack.as_ref()).unwrap();
    match decision {
        PatchDecision::Fallback(FallbackReason::Skeleton {
            tier: Some(tier), ..
        }) => assert_ne!(tier, pgr_core::slack::LayoutFallback::InPlace),
        other => panic!("expected a ladder-classified fallback, got {other:?}"),
    }
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
    // decision rig; CI runs this deterministic subset). A xorshift64* walk
    // over edit kinds — body flip, import add, import retarget, no-op —
    // must land every step on either an in-place patch that is byte-
    // identical to the full emit, or an honest fallback that re-records.
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

    let dir = workdir("randomized");
    let prev = dir.join("out");
    write_image(&image, &prev).unwrap();

    let mut in_place_steps = 0u32;
    let mut fallback_steps = 0u32;
    for _seq in 0..16 {
        for _step in 0..5 {
            // Pick the edit from the generator.
            let roll = next() % 5;

            let (new_binds, new_shift, new_text) = match roll {
                0 => {
                    // Body growth within slack (same import surface).
                    (
                        binds,
                        shift,
                        8 * 1024 + usize::try_from(next() % 2048).unwrap(),
                    )
                }
                1 => {
                    // Import add: an extra pointer to a (possibly new) export.
                    ((binds + 1).min(exports.len() + 2), shift, 8 * 1024)
                }
                2 => {
                    // Import retarget: same size, different ordinals.
                    (binds.max(1), shift + 1, 8 * 1024)
                }
                3 => {
                    // Big growth: blows the section's reservation — the
                    // ladder's honest exit (re-layout tier classification,
                    // the v1 engine re-runs the full link).
                    (binds, shift, 8 * 1024 + 24 * 1024)
                }
                _ => {
                    // No-op: the untouched path must stay untouched.
                    (binds, shift, 8 * 1024)
                }
            };
            binds = new_binds;
            shift = new_shift % exports.len();
            let text_bytes = new_text;
            let build_binds: Vec<&str> = (0..binds)
                .map(|i| exports[(i + shift) % exports.len()])
                .collect();
            let cfg_n = stable_cfg(
                kind,
                anchors_of(&layout),
                Some(record.imports.clone()),
                Some(layout.linkedit.sig_off),
            );
            let (l2, o2) = link(&inputs(&pointer_main(text_bytes, &build_binds)), &cfg_n);
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
}

//! M116 — the `-warn_commons` advisory face: ld64's common-symbol
//! advisory ("Print a warning whenever a tentative definition in an
//! object file is found [and an external symbol by the same name is
//! also found]" — the `ld64` man page) rides the M107 `CommonsPolicy`
//! seam as an orthogonal warning decision on `LinkConfig`. The
//! decision never changes the resolution policy itself: a walk after
//! the commons policy derives, from the resolved state, where every
//! input common symbol landed — a local definition (the common's own
//! coalesced ride included) or a linked dylib's export — and the
//! driver's advisory face tallies the entries, prints them to stderr
//! and exits 0 (the M103/M108 warning-face pattern).
//!
//! Gate matrix:
//! * the local face — a common whose name a real definition lands on
//!   records `resolved to 'input <n>'` (the winner's file);
//! * the coalesce face — two commons' tentative rows land on one
//!   winner (the lowest file's), the entry dedupes onto the winner's
//!   provider;
//! * the dylib face — a common the `-commons` policy un-defined binds
//!   the exporting dylib, the entry names the install name;
//! * the silent shapes — `-U` stripped the common (no definition to
//!   name), the `use_extern` def dropped with nothing exporting (the
//!   flat ride is the intended shape, the M103 face pattern), and the
//!   default off decision records nothing;
//! * the parity lock — the advisory is a measurement, never a layout
//!   product: the header bytes the decision on/off plans are
//!   identical;
//! * the ladder's replay rides the decision (the M81 pattern — the
//!   decision is config, not a product): the resolve-reuse relink
//!   derives the same entries the full walk derives;
//! * the relocatable refusal — the object's symtab is the input's,
//!   verbatim (the layout re-check and `link_reloc` back the driver
//!   surface).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_cached, link_reloc};
use pgr_core::propagate::section_digests;
use pgr_core::resolve::{CommonsPolicy, Dylib, UndefinedPolicy};
use pgr_core::resolve_reuse::ResolveReuseSeed;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// An object: `_main` in the first, its own `_fn` otherwise; a plain
/// reference to each name in `refs`; an optional tentative definition
/// (`N_UNDF | N_EXT`, non-zero value — the common shape) for `common`.
fn fixture(name: &str, defines: &[&str], refs: &[&str], common: Option<&str>) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: if name == "a.o" {
            "_main".into()
        } else {
            format!("_{name}_fn")
        },
        section_index: text,
        value: 0,
        weak: false,
    });
    for d in defines {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*d).into(),
            section_index: text,
            value: 0,
            weak: false,
        });
    }
    let data = b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 8 * (refs.len() + usize::from(common.is_some()))],
        vec![],
    ));
    for (i, r) in refs.iter().enumerate() {
        let undef = b.add_symbol(ObjectSymbol::Undefined {
            name: (*r).into(),
            weak_ref: false,
        });
        b.section_mut(data)
            .relocs
            .push(ObjectReloc::unsigned(undef as u32).at((i * 8) as u32));
    }
    if let Some(c) = common {
        b.add_symbol(ObjectSymbol::Common {
            name: c.into(),
            size: 32,
            align_log2: 3,
        });
    }
    b
}

/// Links the fixtures under `tweak`; returns the full Pass 1–3 result.
fn plan(
    builders: &[ObjectBuilder],
    tweak: impl FnOnce(&mut LinkConfig),
) -> pgr_core::link::LinkResult {
    let inputs: Vec<LinkInput> = builders
        .iter()
        .map(|b| LinkInput {
            name: b.name().into(),
            bytes: b.build().expect("the fixture object builds"),
        })
        .collect();
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(&inputs, &[], &cfg).expect("the corpus links")
}

fn dylib(install_name: &str, exports: &[&str]) -> Dylib {
    Dylib {
        install_name: install_name.to_string(),
        current_version: 0,
        compatibility_version: 0,
        exports: exports.iter().map(|e| e.as_bytes().to_vec()).collect(),
        weak: false,
        lazy: false,
        upward: false,
        reexport: false,
        needed: false,
        hidden: false,
    }
}

/// The entries the resolver recorded (sorted, the `BTreeSet` order).
fn entries(result: &pgr_core::link::LinkResult) -> Vec<String> {
    result
        .resolution
        .warn_commons_open()
        .map(str::to_owned)
        .collect()
}

// ---- the gate matrix ---------------------------------------------------------

#[test]
fn the_local_face_names_the_input_the_definition_lands_on() {
    // a.o declares `_landing` tentative; b.o defines it for real — the
    // common's name resolved to a local definition, the entry names the
    // winner's input (the M108 entry convention's provider half).
    let result = plan(
        &[
            fixture("a.o", &[], &[], Some("_landing")),
            fixture("b.o", &["_landing"], &[], None),
        ],
        |c| c.warn_commons = true,
    );
    assert_eq!(
        entries(&result),
        vec!["'_landing' resolved to 'input 1'"],
        "the advisory names the definition the common resolved to (the plain \
         references and the real definitions never enter the walk)"
    );
}

#[test]
fn the_coalesce_face_dedupes_onto_the_winning_input() {
    // Two commons: the tentative rows coalesce onto the lowest file's
    // row (the TDD §5 tie-break); every input row's landing derives the
    // same provider, the deterministic set carries one entry.
    let result = plan(
        &[
            fixture("a.o", &[], &[], Some("_coalesced")),
            fixture("b.o", &[], &["_coalesced"], Some("_coalesced")),
        ],
        |c| c.warn_commons = true,
    );
    let got = entries(&result);
    assert!(
        got.contains(&"'_coalesced' resolved to 'input 0'".to_owned()),
        "the coalesced common names the winning input: {got:?}"
    );
    assert_eq!(
        got.iter().filter(|e| e.contains("coalesced")).count(),
        1,
        "the two rows' landings dedupe onto one entry (the winner's provider)"
    );
}

#[test]
fn the_dylib_face_names_the_install_name() {
    // `use_extern` un-defines the tentative; the exporting dylib serves
    // the name — the landing is the dylib, the entry names the install
    // name (the policy's decision rode first; the advisory walks the
    // post-policy state).
    let inputs: Vec<LinkInput> = vec![LinkInput {
        name: "a.o".into(),
        bytes: fixture("a.o", &[], &[], Some("_extern_c"))
            .build()
            .expect("the fixture object builds"),
    }];
    let cfg = LinkConfig {
        dylibs: vec![dylib("@rpath/libc.dylib", &["_extern_c"])],
        commons: CommonsPolicy::UseExtern,
        warn_commons: true,
        ..LinkConfig::default()
    };
    let result = link(&inputs, &[], &cfg).expect("the corpus links");
    assert_eq!(
        entries(&result),
        vec!["'_extern_c' resolved to '@rpath/libc.dylib'"],
        "the dropped tentative's landing is the dylib export"
    );
}

#[test]
fn the_dylib_match_under_the_default_names_the_local_landing() {
    // ld64's face: a tentative whose name a linked dylib also exports
    // — under the house default the in-image common beats the export
    // (the M107 rank order), so the landing is the local definition
    // and the entry names its input; the match still warns (the face
    // fires wherever a definition owns the name).
    let inputs: Vec<LinkInput> = vec![LinkInput {
        name: "a.o".into(),
        bytes: fixture("a.o", &[], &[], Some("_matched"))
            .build()
            .expect("the fixture object builds"),
    }];
    let cfg = LinkConfig {
        dylibs: vec![dylib("@rpath/libmatched.dylib", &["_matched"])],
        warn_commons: true,
        ..LinkConfig::default()
    };
    let result = link(&inputs, &[], &cfg).expect("the corpus links");
    let got = entries(&result);
    assert!(
        got.contains(&"'_matched' resolved to 'input 0'".to_owned()),
        "the matched common's landing is the local definition: {got:?}"
    );
}

#[test]
fn the_silent_shapes_record_nothing() {
    // The `-U` mark stripped the common before any definition existed
    // (no definition to name); a lone common under the default records
    // its own landing (the definition it became).
    let marked_bytes = fixture("a.o", &[], &[], Some("_marked"))
        .build()
        .expect("the fixture object builds");
    let cfg = LinkConfig {
        warn_commons: true,
        ..LinkConfig::default()
    };
    let mut make = pgr_core::make_undefined::MakeUndefined::new();
    make.push(pgr_core::MakeUndefinedName::from_flag("_marked").expect("the mark parses"))
        .expect("the mark table accepts the name");
    let cfg_marked = LinkConfig {
        make_undefined: make,
        ..cfg.clone()
    };
    let marked_inputs = vec![LinkInput {
        name: "a.o".into(),
        bytes: marked_bytes,
    }];
    let marked_result = link(&marked_inputs, &[], &cfg_marked).expect("the marked link runs");
    assert!(
        entries(&marked_result)
            .iter()
            .all(|e| !e.contains("_marked")),
        "the -U-stripped common has no definition to name: {:?}",
        entries(&marked_result)
    );

    let plain_inputs: Vec<LinkInput> = vec![LinkInput {
        name: "a.o".into(),
        bytes: fixture("a.o", &[], &[], Some("_lone"))
            .build()
            .expect("the fixture object builds"),
    }];
    let off = link(&plain_inputs, &[], &LinkConfig::default()).expect("the plain link runs");
    assert!(
        entries(&off).is_empty(),
        "the default records nothing (the decision is off): {:?}",
        entries(&off)
    );
}

#[test]
fn the_advisory_never_moves_the_bytes() {
    // The face is a measurement, never a layout product (the M109
    // pattern): the decision on/off plans identical header bytes over
    // a commons-bearing corpus.
    let inputs: Vec<LinkInput> = vec![
        LinkInput {
            name: "a.o".into(),
            bytes: fixture("a.o", &[], &[], Some("_c"))
                .build()
                .expect("builds"),
        },
        LinkInput {
            name: "b.o".into(),
            bytes: fixture("b.o", &[], &["_c"], None).build().expect("builds"),
        },
    ];
    let off = link(&inputs, &[], &LinkConfig::default()).expect("the off link plans");
    let on = link(
        &inputs,
        &[],
        &LinkConfig {
            warn_commons: true,
            ..LinkConfig::default()
        },
    )
    .expect("the on link plans");
    assert_eq!(
        off.layout.header_bytes, on.layout.header_bytes,
        "the advisory face never moves the bytes"
    );
}

#[test]
fn the_ladder_replay_rides_the_decision() {
    // The M81 pattern: the decision is config, not a product. The
    // recording link captures the Pass-2 snapshot; the resolve-reuse
    // relink derives the same advisory entries the full walk derives.
    let inputs: Vec<LinkInput> = vec![
        LinkInput {
            name: "a.o".into(),
            bytes: fixture("a.o", &[], &[], Some("_replayed"))
                .build()
                .expect("builds"),
        },
        LinkInput {
            name: "b.o".into(),
            bytes: fixture("b.o", &["_replayed"], &[], None)
                .build()
                .expect("builds"),
        },
    ];
    let recording_cfg = LinkConfig {
        record_resolution: true,
        warn_commons: true,
        ..LinkConfig::default()
    };
    let first = link_cached(&inputs, &[], &recording_cfg, Parallelism::Serial, None)
        .expect("the recording link runs");
    let snapshot = first
        .resolve_snapshot
        .clone()
        .expect("a recording link captures the snapshot");
    let seeded_cfg = LinkConfig {
        resolve_reuse: Some(ResolveReuseSeed {
            snapshot,
            digests: section_digests(&first.objects),
        }),
        warn_commons: true,
        ..LinkConfig::default()
    };
    let replayed = link_cached(&inputs, &[], &seeded_cfg, Parallelism::Serial, None)
        .expect("the seeded relink runs");
    assert_eq!(
        entries(&first),
        entries(&replayed),
        "the replay's advisory product matches the full walk's (the M81 parity)"
    );
    assert!(
        !entries(&replayed).is_empty(),
        "the corpus carries commons (the parity is not vacuous)"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob_in_link_reloc() {
    // The object's symtab is the input's, verbatim — there is no
    // resolution landing to advise about (the M104/M105/M112 pattern;
    // the layout re-check backs this in `layout`).
    let inputs: Vec<LinkInput> = vec![LinkInput {
        name: "a.o".into(),
        bytes: fixture("a.o", &[], &[], Some("_c"))
            .build()
            .expect("builds"),
    }];
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        warn_commons: true,
        ..LinkConfig::default()
    };
    let err = link_reloc(&inputs, &[], &cfg, Parallelism::Serial)
        .expect_err("the relocatable output refuses the knob");
    let text = err.to_string();
    assert!(
        text.contains("-warn_commons") && text.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {text}"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob_in_layout() {
    // The layout's own re-check: no library caller plans the shape
    // either (the M104/M105 refusal shape).
    let inputs: Vec<LinkInput> = vec![LinkInput {
        name: "a.o".into(),
        bytes: fixture("a.o", &[], &[], Some("_c"))
            .build()
            .expect("builds"),
    }];
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        warn_commons: true,
        ..LinkConfig::default()
    };
    let err = link(&inputs, &[], &cfg).expect_err("the layout re-check refuses");
    let text = err.to_string();
    assert!(
        text.contains("-warn_commons") && text.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {text}"
    );
}

#[test]
fn the_undefined_policy_face_composes_with_the_advisory() {
    // The advisory rides any `-undefined` face: under `warning` the
    // unresolved-open entries print through their own face and the
    // commons entries through theirs — one tally, two faces (the M109
    // composition).
    let inputs: Vec<LinkInput> = vec![LinkInput {
        name: "a.o".into(),
        bytes: fixture("a.o", &[], &["_hole"], Some("_c"))
            .build()
            .expect("builds"),
    }];
    let cfg = LinkConfig {
        undefined_policy: UndefinedPolicy::Warning,
        warn_commons: true,
        ..LinkConfig::default()
    };
    let result = link(&inputs, &[], &cfg).expect("the warning-policy link runs");
    assert!(
        result
            .resolution
            .unresolved_open()
            .any(|e| e.contains("_hole")),
        "the undefined face recorded its own product"
    );
    assert!(
        entries(&result).iter().any(|e| e.contains("'_c'")),
        "the commons face recorded its own product beside it"
    );
}

//! The `-r` relocatable-output consumer example (M10 rung 1): the
//! two-step cycle a build system drives when it wants a partially-linked
//! object instead of an image —
//!
//! 1. `link_reloc` + `build_object_image`: two fixture objects merge into
//!    one `MH_OBJECT` (sections merged at their declared alignments, the
//!    symbol table grouped locals/globals/undefineds, relocation entries
//!    re-pointed at the output symbol table, undefineds left open);
//! 2. the emitted object re-links — as an *input* — into a full
//!    executable, gated by the pipeline's own verifier both ways.
//!
//! Run: `cargo run -p pgr-driver --example relocatable_link`
//! (`PGR_TRACING=1` installs a subscriber so the `link_reloc`,
//! `object_layout`, `reloc_encode` and `object_emit` spans print).

use pgr_core::layout::LinkConfig;
use pgr_core::{LinkInput, Parallelism, link, link_reloc};
use pgr_emit::build_object_image;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

fn main() {
    // The spans stay inert until a subscriber installs — the workspace
    // convention (the binaries do it under their debug envs). The DEBUG
    // level surfaces the seams' field events (the split counts, the
    // encode totals); the span envelopes themselves are INFO.
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    // ---- the two inputs (deterministic fixture bytes) ------------------
    let main_object = {
        let mut b = ObjectBuilder::new("hello_main.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![
                0x90, 0x00, 0x00, 0x00, // adrp x0, _msg@page
                0x91, 0x00, 0x00, 0x00, // add x0, x0, #_msg@pageoff
                0x94, 0x00, 0x00, 0x00, // bl _greet
                0xC0, 0x03, 0x5F, 0xD6, // ret
            ],
            vec![
                ObjectReloc::addend(0).at(0),
                ObjectReloc::page21(1).at(0),
                ObjectReloc::addend(0).at(4),
                ObjectReloc::pageoff12(1).at(4),
                ObjectReloc::branch26(2).at(8),
            ],
        ));
        b.add_section(ObjectSection::cstring("hello, peregrine\n"));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text,
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
        b.build().unwrap()
    };
    let greet_object = {
        let mut b = ObjectBuilder::new("greet.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6], // ret
            vec![],
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_greet".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.build().unwrap()
    };
    let inputs = vec![
        LinkInput {
            name: "hello_main.o".into(),
            bytes: main_object,
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet_object,
        },
    ];

    // ---- step 1: the relocatable link (`pgr -r` at the API level) ------
    let cfg = LinkConfig {
        ident: "relocatable-link-example".into(),
        ..LinkConfig::default()
    };
    let linked = link_reloc(&inputs, &[], &cfg, Parallelism::Auto)
        .expect("pass 1-2: undefined _greet stays open");
    let object = build_object_image(&linked, &cfg).expect("the object emit");
    println!(
        "step 1: -r wrote {} bytes of MH_OBJECT \
         (sections merged, relocation entries re-pointed, _greet open)",
        object.len()
    );

    // ---- step 1b: the object is verifier-clean --------------------------
    let report = pgr_verify::verify(&object, &pgr_verify::Options::default());
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.severity == pgr_verify::Severity::Error),
        "the -r output must be verifier-clean: {:?}",
        report.issues
    );
    println!(
        "step 1b: pgr-verify clean ({} issues, none fatal)",
        report.issues.len()
    );

    // ---- step 2: the emitted object re-links into an executable ---------
    let linked = link(
        &[LinkInput {
            name: "out.o".into(),
            bytes: object,
        }],
        &[],
        &cfg,
    )
    .expect("pass 1-3 over the emitted object");
    let image =
        pgr_emit::build_image_fused(&linked.layout, &linked.objects).expect("the fused image emit");
    let report = pgr_verify::verify(&image, &pgr_verify::Options::default());
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.severity == pgr_verify::Severity::Error),
        "the re-linked executable must be verifier-clean: {:?}",
        report.issues
    );
    println!(
        "step 2: out.o re-linked into a {}-byte executable (entryoff {:#x}), verifier clean",
        image.len(),
        linked.layout.entryoff
    );
}

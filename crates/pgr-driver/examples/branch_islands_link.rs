//! The branch-islands consumer example (M47): the layout's veneer
//! fixed point plans one `adrp/add/br` trampoline per out-of-range
//! `B`/`BL` (M6); `-no_branch_islands` is ld64's suppression — the
//! fixed point stops planning veneers, and a branch the ±128 MiB
//! `imm26` window cannot reach refuses the link with the site named.
//! An in-range link plans byte-identical output under either decision;
//! the overflowing link shows both faces: the veneers under the
//! default, the typed refusal under the suppression.
//!
//! Run: `cargo run -p pgr-driver --example branch_islands_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_core::layout::{LinkConfig, SynthKind};
use pgr_core::link::{LinkInput, link};
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

const MIB: usize = 1 << 20;

/// An in-range corpus: every branch lands inside the `imm26` window.
fn small_object(name: &str, defs: &[(&str, bool)]) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6], // ret; ret
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    for (i, (n, def)) in defs.iter().enumerate() {
        if *def {
            b.add_symbol(ObjectSymbol::Defined {
                name: (*n).into(),
                section_index: if i == 0 { text } else { data },
                value: 0,
                weak: false,
            });
        }
    }
    b.build().expect("the fixture object builds")
}

/// The M6 giant-text corpus: a.o (64 MiB, branch to `_far`), b.o
/// (66 MiB, pure distance), c.o (2 MiB, `_far` + branch back) —
/// site→target distances land at ~130 MiB both ways.
fn giant_inputs() -> Vec<LinkInput> {
    let giant = |name: &str,
                 size: usize,
                 text_syms: &[(&str, bool)],
                 branch: bool,
                 branch_target: usize| {
        let mut b = ObjectBuilder::new(name);
        let mut relocs: Vec<ObjectReloc> = Vec::new();
        if branch {
            relocs.push(
                ObjectReloc::branch26(u32::try_from(branch_target).expect("index fits")).at(0),
            );
        }
        let text = b.add_section(ObjectSection::text("__text", vec![0u8; size], relocs));
        for (n, def) in text_syms {
            if *def {
                b.add_symbol(ObjectSymbol::Defined {
                    name: (*n).into(),
                    section_index: text,
                    value: 0,
                    weak: false,
                });
            } else {
                b.add_symbol(ObjectSymbol::Undefined {
                    name: (*n).into(),
                    weak_ref: false,
                });
            }
        }
        LinkInput {
            name: name.to_string(),
            bytes: b.build().expect("the fixture object builds"),
        }
    };
    vec![
        giant(
            "a.o",
            64 * MIB,
            &[("_main", true), ("_far", false)],
            true,
            1,
        ),
        giant("b.o", 66 * MIB, &[("_b", true)], false, 0),
        giant("c.o", 2 * MIB, &[("_far", true), ("_main", false)], true, 1),
    ]
}

/// The veneer pieces the layout planned.
fn veneer_count(layout: &pgr_core::layout::Layout) -> usize {
    layout
        .sections
        .iter()
        .flat_map(|s| &s.pieces)
        .filter(|p| {
            matches!(
                &p.synth,
                Some(s) if matches!(s.kind, SynthKind::Veneer { .. })
            )
        })
        .count()
}

/// Links the named inputs with the named extra flags through the
/// driver surface; returns the image bytes.
fn link_with(inputs: &[(&str, Vec<u8>)], extra: &[&str], tag: &str) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!("pgr_branch_islands_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut argv: Vec<std::ffi::OsString> = Vec::new();
    let out = dir.join(format!("out-{tag}"));
    argv.push(std::ffi::OsString::from("-o"));
    argv.push(std::ffi::OsString::from(out.to_str().unwrap()));
    for (name, bytes) in inputs {
        let path = dir.join(format!("{tag}-{name}"));
        std::fs::write(&path, bytes).unwrap();
        argv.push(std::ffi::OsString::from(path.to_str().unwrap()));
    }
    for a in extra {
        argv.push(std::ffi::OsString::from(*a));
    }
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(&out).expect("the image reads");
    assert!(
        verify(
            &image,
            &VerifyOptions {
                strict_warnings: true,
                skip_hash_recompute: false,
            },
        )
        .is_ok(&VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        }),
        "the {tag} image verifies strict"
    );
    image
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    // The in-range lane: both decisions plan identical bytes — the
    // suppression has nothing to refuse.
    let in_range = vec![
        (
            "m.o",
            small_object("m.o", &[("_main", true), ("_far", false)]),
        ),
        ("f.o", small_object("f.o", &[("_far", true)])),
    ];
    let plain = link_with(&in_range, &[], "plain");
    let suppressed = link_with(&in_range, &["-no_branch_islands"], "suppressed");
    assert_eq!(plain.len(), suppressed.len(), "the sizes hold");
    assert_eq!(
        plain, suppressed,
        "the in-range bytes hold under both decisions"
    );
    println!(
        "in-range: {} bytes — the suppression plans the same bytes (veneers: 0)",
        plain.len()
    );

    // The overflowing lane: the default plans one veneer per site (the
    // library seam's plan is what a build system audits before the
    // emit); the suppression refuses with the site named.
    let giant = giant_inputs();
    let planned = link(&giant, &[], &LinkConfig::default())
        .expect("the giant link plans with the veneer default")
        .layout;
    println!(
        "overflow: {} planned bytes — {} veneers keep every B/BL in range",
        planned.file_size,
        veneer_count(&planned)
    );
    let refused = link(
        &giant,
        &[],
        &LinkConfig {
            branch_islands: false,
            ..LinkConfig::default()
        },
    );
    match &refused {
        Ok(_) => panic!("the suppressed overflow must refuse"),
        Err(e) => println!("overflow: -no_branch_islands refuses — {e}"),
    }
    println!(
        "\nthe veneer set is a pure function of the placed addresses; \
         try PGR_TRACING=1 to watch the pipeline"
    );
}

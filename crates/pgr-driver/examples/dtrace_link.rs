//! M118 — the dtrace `DOF` section processing: `-dtrace` — a
//! `__dtrace_dof` (`S_DTRACE_DOF`) section is recognized as a dtrace
//! payload (Pass 1, distinct from the generic `S_ATTR_DEBUG` debug
//! class), the emit validates its `DOF` header (the identification magic
//! and the bounds the `DTrace` consumer gates on) before the section links
//! into the output, and the verifier backstops the contract read-side on
//! every `S_DTRACE_DOF` section. The default carries the section's bytes
//! verbatim (no emit validation; the read-side backstop still gates). The
//! relocatable output refuses the knob (the object's sections are the
//! input's, verbatim).
//!
//! Run: `cargo run -p pgr-driver --example dtrace_link`
//! (`PGR_TRACING=1` installs a tracing subscriber).

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::S_DTRACE_DOF;
use pgr_format::dof::DOF_MAGIC;
use pgr_format::{LoadCommandIter, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;

/// `main.o`: `_main` plus a `__dtrace_dof` (`S_DTRACE_DOF`) section
/// whose head carries the `DOF` identification magic — the payload the
/// decision recognizes and the emit validates.
fn corpus(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(4),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    // The DOF payload: 32 bytes, the identification magic at the head
    // (covers the DOF_ID_SIZE identification region).
    let mut dof = vec![0u8; 32];
    dof[..DOF_MAGIC.len()].copy_from_slice(&DOF_MAGIC);
    let dof_sect = b.add_section(ObjectSection::text("__dtrace_dof", dof, vec![]));
    b.section_mut(dof_sect).flags = S_DTRACE_DOF;
    let path = dir.join("main.o");
    std::fs::write(&path, b.build().expect("the fixture builds")).expect("main.o writes");
    vec![path]
}

/// The output section names the image's segment commands carry (the raw
/// load-command walk).
fn image_sections(image: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let Ok(hdr) = MachHeader64::parse(image) else {
        return names;
    };
    let Ok(mut it) = LoadCommandIter::new(image, MachHeader64::SIZE, hdr.ncmds, hdr.sizeofcmds)
    else {
        return names;
    };
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind != pgr_format::LoadCommandKind::Segment64 || cmd.bytes.len() < 72 {
            continue;
        }
        let nsects = u32::from_le_bytes(cmd.bytes[64..68].try_into().unwrap_or([0; 4]));
        for i in 0..nsects as usize {
            let base = 72 + i * 80;
            if base + 80 > cmd.bytes.len() {
                break;
            }
            let name = String::from_utf8_lossy(&cmd.bytes[base..base + 16]);
            names.push(name.trim_end_matches('\0').to_owned());
        }
    }
    names
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_dtrace_link_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the scratch dir creates");
    let objs = corpus(&dir);
    let inputs: Vec<LinkInput> = objs
        .iter()
        .map(|p| LinkInput {
            name: p
                .file_name()
                .expect("the name rides")
                .to_string_lossy()
                .into_owned(),
            bytes: std::fs::read(p).expect("the object reads"),
        })
        .collect();

    // Face 1 — the library seam: the default carries the `__dtrace_dof`
    // section verbatim; the decision carries it too (the classification
    // recognizes the payload, never drops it — the M105/M118 distinction;
    // the layout carries the echo the emit reads).
    let plan_for = |dtrace: bool| {
        link(
            &inputs,
            &[],
            &LinkConfig {
                dtrace,
                ..LinkConfig::default()
            },
        )
        .expect("the link plans")
    };
    let carried = plan_for(false);
    let validated = plan_for(true);
    assert!(
        carried
            .layout
            .sections
            .iter()
            .any(|s| s.name == "__dtrace_dof"),
        "the default carries the __dtrace_dof section"
    );
    assert!(
        validated
            .layout
            .sections
            .iter()
            .any(|s| s.name == "__dtrace_dof"),
        "the decision carries the __dtrace_dof section (validated at emit)"
    );
    assert!(
        validated.layout.dtrace,
        "the layout carries the dtrace decision (the echo the emit reads)"
    );
    println!(
        "face 1 (library seam): default {} bytes (dtrace section carried verbatim) — decided {} \
         bytes (the section rides, its DOF header validated at emit)",
        carried.layout.file_size, validated.layout.file_size
    );

    // Face 2 — the driver face: the `-dtrace` image carries the
    // `__dtrace_dof` section and verifies strict (the producer validated
    // the DOF header at emit; the read-side backstop passes on a
    // well-formed header).
    let mut argv: Vec<OsString> = vec![
        "-dtrace".into(),
        "-o".into(),
        dir.join("app").to_string_lossy().into_owned().into(),
    ];
    argv.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    let o = opts::parse(&argv).expect("the surface parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(dir.join("app")).expect("the image reads");
    let names = image_sections(&image);
    assert!(
        names.iter().any(|n| n.contains("__dtrace_dof")),
        "the -dtrace image carries the __dtrace_dof section: {names:?}"
    );
    let strict = VerifyOptions::default();
    assert!(
        verify(&image, &strict).is_ok(&strict),
        "the DOF-bearing image (a well-formed header) verifies strict"
    );
    println!(
        "face 2 (-dtrace): the image ships the __dtrace_dof section ({} bytes); the DOF header \
         validated at emit; verifies strict",
        outcome.file_size
    );

    // Face 3 — the relocatable refusal: the object's sections are the
    // input's, verbatim.
    let mut full: Vec<OsString> = vec![
        "-r".into(),
        "-o".into(),
        dir.join("o.o").to_string_lossy().into_owned().into(),
        "-dtrace".into(),
    ];
    full.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    match opts::parse(&full) {
        Ok(_) => panic!("the relocatable output must refuse the dtrace decision"),
        Err(err) => println!("face 3 (-r): refused — {:?}", miette::Report::new(err)),
    }

    println!("\ndtrace_link: ok");
}

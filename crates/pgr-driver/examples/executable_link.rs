//! M120 — the explicit filetype override: `-executable` — ld64's flag
//! ("Force the creation of an `MH_EXECUTE` file") forces `MH_EXECUTE`
//! regardless of any `-dylib`/`-bundle` inference earlier on the command
//! line (or sets the default, which is already `Execute`). The decision
//! rides the filetype the layout and emit already key on (`__PAGEZERO`,
//! `LC_MAIN` and the no-`LC_ID_DYLIB` contract all gate on
//! `OutputType::is_executable`), so forcing `Execute` makes the executable
//! shape fire unchanged. The relocatable output refuses the knob (the
//! object's filetype is the input's, verbatim).
//!
//! Run: `cargo run -p pgr-driver --example executable_link`
//! (`PGR_TRACING=1` installs a tracing subscriber).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::MH_EXECUTE;
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;

/// `main.o`: `_main` in a `__text` body — the minimal executable corpus
/// (the entry symbol the `LC_MAIN` command names).
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
    let path = dir.join("main.o");
    std::fs::write(&path, b.build().expect("the fixture builds")).expect("main.o writes");
    vec![path]
}

/// The executable contract the linked image carries: `MH_EXECUTE`,
/// `__PAGEZERO` first, `LC_MAIN` present, no `LC_ID_DYLIB`.
fn image_exec_shape(image: &[u8]) -> (u32, bool, bool, bool) {
    let hdr = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, hdr.ncmds, hdr.sizeofcmds)
        .expect("the load-command iter builds");
    let mut pagezero_first = false;
    let mut has_main = false;
    let mut has_id_dylib = false;
    let mut first_segment = true;
    while let Ok(Some(cmd)) = it.next_command() {
        match cmd.kind {
            LoadCommandKind::Segment64 => {
                if first_segment {
                    let name = cmd
                        .bytes
                        .get(8..24)
                        .map(|b| {
                            String::from_utf8_lossy(b)
                                .trim_end_matches('\0')
                                .to_string()
                        })
                        .unwrap_or_default();
                    pagezero_first = name == "__PAGEZERO";
                    first_segment = false;
                }
            }
            LoadCommandKind::Main => has_main = true,
            LoadCommandKind::IdDylib => has_id_dylib = true,
            _ => {}
        }
    }
    (hdr.filetype, pagezero_first, has_main, has_id_dylib)
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_executable_link_{}", std::process::id()));
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

    // Face 1 — the library seam: the default `Execute` filetype carries
    // the executable shape; the explicit `-executable` override forces
    // `OutputType::Execute` (the same shape — the decision never moves
    // the bytes, every pre-knob link byte-identical).
    let plan_for = |executable: bool| {
        link(
            &inputs,
            &[],
            &LinkConfig {
                filetype: OutputType::Execute,
                executable,
                ..LinkConfig::default()
            },
        )
        .expect("the link plans")
    };
    let default = plan_for(false);
    let explicit = plan_for(true);
    let (ft, pz, main, id) = image_exec_shape(&explicit.layout.header_bytes);
    assert_eq!(ft, MH_EXECUTE, "the override carries MH_EXECUTE");
    assert!(pz, "the override carries __PAGEZERO first");
    assert!(main, "the override carries LC_MAIN");
    assert!(
        !id,
        "the override carries no LC_ID_DYLIB (an executable's identity is LC_MAIN)"
    );
    assert_eq!(
        default.layout.header_bytes, explicit.layout.header_bytes,
        "the default and the override link byte-identical"
    );
    println!(
        "face 1 (library seam): default {} bytes (MH_EXECUTE, __PAGEZERO + LC_MAIN) — \
         -executable {} bytes (the same shape, the override never moves the bytes)",
        default.layout.file_size, explicit.layout.file_size
    );

    // Face 2 — the driver face: the `-executable` image carries the
    // executable contract and verifies strict (the read-side executable
    // gate passes on the well-formed shape).
    let mut argv: Vec<OsString> = vec![
        "-executable".into(),
        "-o".into(),
        dir.join("app").to_string_lossy().into_owned().into(),
    ];
    argv.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    let o = opts::parse(&argv).expect("the surface parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(dir.join("app")).expect("the image reads");
    let (ft, pz, main, id) = image_exec_shape(&image);
    assert_eq!(ft, MH_EXECUTE, "the -executable image is MH_EXECUTE");
    assert!(pz, "the -executable image carries __PAGEZERO first");
    assert!(main, "the -executable image carries LC_MAIN");
    assert!(!id, "the -executable image carries no LC_ID_DYLIB");
    let strict = VerifyOptions::default();
    assert!(
        verify(&image, &strict).is_ok(&strict),
        "the -executable image verifies strict"
    );
    println!(
        "face 2 (-executable): the image ships MH_EXECUTE with __PAGEZERO + LC_MAIN ({} bytes); \
         verifies strict",
        outcome.file_size
    );

    // Face 3 — the relocatable refusal: the object's filetype is the
    // input's, verbatim.
    let mut full: Vec<OsString> = vec![
        "-r".into(),
        "-o".into(),
        dir.join("o.o").to_string_lossy().into_owned().into(),
        "-executable".into(),
    ];
    full.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    match opts::parse(&full) {
        Ok(_) => panic!("the relocatable output must refuse the -executable override"),
        Err(err) => println!("face 3 (-r): refused — {:?}", miette::Report::new(err)),
    }

    println!("\nexecutable_link: ok");
}

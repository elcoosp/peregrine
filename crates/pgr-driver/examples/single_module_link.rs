//! M119 — the dylib module contract: `-single_module`/`-multi_module` —
//! ld64's dylib module-table shape. `-single_module` forces the dylib to
//! be treated as a single module: the `LC_DYSYMTAB` module table has one
//! entry (a `DylibModule64` whose subranges mirror the `LC_DYSYMTAB`'s
//! locals/extdefs, the whole image as one module), and all undefineds
//! must resolve at link time (or they ride the flat/weak lookup, the M103
//! pattern; unresolved strong symbols refuse the link with the symbol
//! named). The default `-multi_module` keeps the legacy zero-module table
//! peregrine always carried (every pre-knob link byte-identical). The
//! relocatable output refuses the knob (the object's symtab is the
//! input's, verbatim).
//!
//! Run: `cargo run -p pgr-driver --example single_module_link`
//! (`PGR_TRACING=1` installs a tracing subscriber).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::ModulePolicy;
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{DysymtabCommand, LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;

/// `main.o`: `_main` plus a defined `_fn` — the minimal dylib corpus.
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
    b.add_symbol(ObjectSymbol::Defined {
        name: "_fn".into(),
        section_index: text,
        value: 16,
        weak: false,
    });
    let path = dir.join("main.o");
    std::fs::write(&path, b.build().expect("the fixture builds")).expect("main.o writes");
    vec![path]
}

/// The `LC_DYSYMTAB` the linked image carries (the raw load-command walk).
fn image_dysymtab(image: &[u8]) -> DysymtabCommand {
    let hdr = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, hdr.ncmds, hdr.sizeofcmds)
        .expect("the load-command iter builds");
    while let Ok(Some(cmd)) = it.next_command() {
        if let LoadCommandKind::Dysymtab = cmd.kind {
            return DysymtabCommand::parse(cmd.bytes, 0).expect("the dysymtab parses");
        }
    }
    panic!("no LC_DYSYMTAB in the linked image");
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_single_module_link_{}", std::process::id()));
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

    // Face 1 — the library seam: the default `-multi_module` plans no
    // module table (the legacy zero-module shape); `-single_module` emits
    // one entry whose subranges mirror the `LC_DYSYMTAB` (the layout
    // carries the echo the emit reads).
    let plan_for = |policy: ModulePolicy| {
        link(
            &inputs,
            &[],
            &LinkConfig {
                filetype: OutputType::Dylib,
                install_name: Some("@rpath/libpgr.dylib".into()),
                module_policy: policy,
                ..LinkConfig::default()
            },
        )
        .expect("the link plans")
    };
    let multi = plan_for(ModulePolicy::MultiModule);
    let single = plan_for(ModulePolicy::SingleModule);
    let multi_dys = {
        let bytes = &multi.layout.header_bytes;
        let hdr = MachHeader64::parse(bytes).expect("the header parses");
        let mut it = LoadCommandIter::new(bytes, MachHeader64::SIZE, hdr.ncmds, hdr.sizeofcmds)
            .expect("the iter builds");
        let mut found = None;
        while let Ok(Some(cmd)) = it.next_command() {
            if let LoadCommandKind::Dysymtab = cmd.kind {
                found = Some(DysymtabCommand::parse(cmd.bytes, 0).expect("the dysymtab parses"));
            }
        }
        found.expect("the LC_DYSYMTAB rides the header")
    };
    let single_dys = {
        let bytes = &single.layout.header_bytes;
        let hdr = MachHeader64::parse(bytes).expect("the header parses");
        let mut it = LoadCommandIter::new(bytes, MachHeader64::SIZE, hdr.ncmds, hdr.sizeofcmds)
            .expect("the iter builds");
        let mut found = None;
        while let Ok(Some(cmd)) = it.next_command() {
            if let LoadCommandKind::Dysymtab = cmd.kind {
                found = Some(DysymtabCommand::parse(cmd.bytes, 0).expect("the dysymtab parses"));
            }
        }
        found.expect("the LC_DYSYMTAB rides the header")
    };
    assert_eq!(multi_dys.nmodtab, 0, "the default carries no module table");
    assert_eq!(
        single_dys.nmodtab, 1,
        "the decision carries one module-table entry"
    );
    assert!(
        single.layout.module_policy.is_single(),
        "the layout carries the single_module decision (the echo the emit reads)"
    );
    println!(
        "face 1 (library seam): multi_module {} bytes (nmodtab 0, the legacy shape) — \
         single_module {} bytes (nmodtab 1, the module table rides the LC_DYSYMTAB)",
        multi.layout.file_size, single.layout.file_size
    );

    // Face 2 — the driver face: the `-single_module` dylib carries one
    // `LC_DYSYMTAB` module-table entry and verifies strict (the producer
    // wrote a well-formed entry; the read-side backstop passes).
    let mut argv: Vec<OsString> = vec![
        "-single_module".into(),
        "-dylib".into(),
        "-o".into(),
        dir.join("libpgr.dylib")
            .to_string_lossy()
            .into_owned()
            .into(),
    ];
    argv.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    let o = opts::parse(&argv).expect("the surface parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(dir.join("libpgr.dylib")).expect("the image reads");
    let dys = image_dysymtab(&image);
    assert_eq!(
        dys.nmodtab, 1,
        "the -single_module dylib carries one module"
    );
    let strict = VerifyOptions::default();
    assert!(
        verify(&image, &strict).is_ok(&strict),
        "the single_module dylib (a well-formed module table) verifies strict"
    );
    println!(
        "face 2 (-single_module): the dylib ships one LC_DYSYMTAB module-table entry ({} bytes); \
         verifies strict",
        outcome.file_size
    );

    // Face 3 — the relocatable refusal: the object's symtab is the
    // input's, verbatim.
    let mut full: Vec<OsString> = vec![
        "-r".into(),
        "-o".into(),
        dir.join("o.o").to_string_lossy().into_owned().into(),
        "-single_module".into(),
    ];
    full.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    match opts::parse(&full) {
        Ok(_) => panic!("the relocatable output must refuse the single_module decision"),
        Err(err) => println!("face 3 (-r): refused — {:?}", miette::Report::new(err)),
    }

    println!("\nsingle_module_link: ok");
}

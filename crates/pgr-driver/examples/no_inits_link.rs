//! M117 — the init/term section suppression: `-no_inits` — the
//! `__mod_init_func`, `__mod_term_func` and `__init_offsets` sections
//! drop from the output entirely, overriding the M16 transform and the
//! M52 dead-strip roots, and the `LC_ROUTINES_64` command (M48 `-init`
//! / M98 `-term`) drops from the header — no init/term machinery
//! remains. The default keeps every pre-knob link byte-identical. The
//! relocatable output refuses the knob (the object's sections are the
//! input's, verbatim).
//!
//! Run: `cargo run -p pgr-driver --example no_inits_link`
//! (`PGR_TRACING=1` installs a tracing subscriber).

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{S_MOD_INIT_FUNC_POINTERS, S_MOD_TERM_FUNC_POINTERS};
use pgr_format::{LoadCommandIter, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;

/// `main.o`: `_main` plus initializer/terminator bodies, each targeted
/// by one 8-byte pointer in its `__mod_init_func`/`__mod_term_func`
/// section — the machinery the decision drops.
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
    let init_ptr = b.add_symbol(ObjectSymbol::Defined {
        name: "_init_ptr".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    let term_ptr = b.add_symbol(ObjectSymbol::Defined {
        name: "_term_ptr".into(),
        section_index: text,
        value: 8,
        weak: false,
    });
    let modinit = b.add_section(ObjectSection::data(
        "__mod_init_func",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(init_ptr as u32).at(0)],
    ));
    b.section_mut(modinit).flags = S_MOD_INIT_FUNC_POINTERS;
    let modterm = b.add_section(ObjectSection::data(
        "__mod_term_func",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(term_ptr as u32).at(0)],
    ));
    b.section_mut(modterm).flags = S_MOD_TERM_FUNC_POINTERS;
    let path = dir.join("main.o");
    std::fs::write(&path, b.build().expect("the fixture builds")).expect("main.o writes");
    vec![path]
}

/// The output section names the image's segment commands carry (the
/// raw load-command walk).
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

/// The `LC_ROUTINES_64` count the header carries.
fn routines_count(image: &[u8]) -> usize {
    let Ok(hdr) = MachHeader64::parse(image) else {
        return 0;
    };
    let Ok(mut it) = LoadCommandIter::new(image, MachHeader64::SIZE, hdr.ncmds, hdr.sizeofcmds)
    else {
        return 0;
    };
    let mut count = 0;
    while let Ok(Some(cmd)) = it.next_command() {
        if matches!(cmd.kind, pgr_format::LoadCommandKind::Routines) {
            count += 1;
        }
    }
    count
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_no_inits_link_{}", std::process::id()));
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

    // Face 1 — the library face: the default keeps the init/term
    // sections; the suppression drops them entirely (no bucket, no
    // placed bytes — the M52 roots never fire on sections that never
    // place).
    let plan_for = |no_inits: bool| {
        link(
            &inputs,
            &[],
            &LinkConfig {
                no_inits,
                ..LinkConfig::default()
            },
        )
        .expect("the link plans")
    };
    let carried = plan_for(false);
    let suppressed = plan_for(true);
    assert!(
        carried
            .layout
            .sections
            .iter()
            .any(|s| s.name == "__mod_init_func"),
        "the default keeps the initializer pointers"
    );
    let free_names: Vec<&str> = suppressed
        .layout
        .sections
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert!(
        !free_names
            .iter()
            .any(|n| n.contains("mod_init") || n.contains("mod_term")),
        "the suppressed plan carries no init/term sections: {free_names:?}"
    );
    println!(
        "face 1 (library seam): default {} bytes (init/term carried) — suppressed {} bytes \
         (no init/term section plans)",
        carried.layout.file_size, suppressed.layout.file_size
    );

    // Face 2 — the driver face: the suppressed image verifies strict
    // and carries no init/term section; the dylib's `-init`/`-term`
    // surface drops from the header beside the flag.
    let mut argv: Vec<OsString> = vec![
        "-dylib".into(),
        "-install_name".into(),
        "@rpath/lib.dylib".into(),
        "-init".into(),
        "_init_ptr".into(),
        "-term".into(),
        "_term_ptr".into(),
        "-no_inits".into(),
        "-o".into(),
        dir.join("free.dylib").to_string_lossy().into_owned().into(),
    ];
    argv.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    let o = opts::parse(&argv).expect("the surface parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(dir.join("free.dylib")).expect("the image reads");
    let names = image_sections(&image);
    assert!(
        !names
            .iter()
            .any(|n| n.contains("mod_init") || n.contains("mod_term")),
        "the suppressed image carries no init/term sections"
    );
    assert_eq!(
        routines_count(&image),
        0,
        "the LC_ROUTINES_64 command drops from the header"
    );
    let strict = VerifyOptions::default();
    assert!(
        verify(&image, &strict).is_ok(&strict),
        "the init-free image verifies strict"
    );
    println!(
        "face 2 (-no_inits): the dylib ships init-free ({} bytes); the `-init`/`-term` \
         command dropped from the header; verifies strict",
        outcome.file_size
    );

    // Face 3 — the relocatable refusal: the object's sections are the
    // input's, verbatim.
    let mut full: Vec<OsString> = vec![
        "-r".into(),
        "-o".into(),
        dir.join("o.o").to_string_lossy().into_owned().into(),
        "-no_inits".into(),
    ];
    full.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    match opts::parse(&full) {
        Ok(_) => panic!("the relocatable output must refuse the suppression"),
        Err(err) => println!("face 3 (-r): refused — {:?}", miette::Report::new(err)),
    }

    println!("\nno_inits_link: ok");
}

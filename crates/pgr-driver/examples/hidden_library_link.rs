//! M110 — the hidden-dylib mark: `-hidden_library`/`-hidden_framework`/
//! `-hidden-l` — ld64's "hidden" loads, the other half of the
//! load-command contract. The dylib's exports enter the resolve arena
//! (the same scan path as `-weak_library`/`-lazy_library`) but the load
//! command drops: a weak reference rides dyld's flat lookup (the M103
//! shape), a strong one refuses the link with the fix.
//!
//! Run: `cargo run -p pgr-driver --example hidden_library_link`
//! (`PGR_TRACING=1` installs a tracing subscriber).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::path::Path;

fn weak_hello() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let undef = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: true,
    });
    let slot = b.sym_index(undef);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    b.build().expect("the fixture object builds")
}

fn strong_hello() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let undef = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    let slot = b.sym_index(undef);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    b.build().expect("the fixture object builds")
}

fn lib_tbd(dir: &Path, name: &str) -> String {
    let path = dir.join(format!("lib{name}.tbd"));
    std::fs::write(
        &path,
        format!(
            "--- !tapi-tbd\n\
             tbd-version: 4\n\
             targets: [arm64-macos]\n\
             install-name: '@rpath/lib{name}.tbd'\n\
             exports:\n\
               - targets: [arm64-macos]\n\
                 symbols: ['_greet']\n\
             ...\n"
        ),
    )
    .expect("the stub writes");
    path.to_string_lossy().into_owned()
}

fn dylib_names(image: &[u8]) -> Vec<String> {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut out = Vec::new();
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind == pgr_format::LoadCommandKind::LoadDylib {
            if let Some(n) = pgr_format::DylibCommand::parse(cmd.bytes)
                .ok()
                .and_then(|c| c.name(cmd.bytes).ok())
            {
                out.push(
                    String::from_utf8_lossy(n)
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
        }
    }
    out
}

fn link(dir: &Path, out: &str, extra: &[&str], obj: &[u8]) -> Vec<u8> {
    let obj_path = dir.join("hello.o");
    std::fs::write(&obj_path, obj).expect("the object writes");
    let mut argv: Vec<OsString> = vec![
        "-o".into(),
        dir.join(out).to_string_lossy().into_owned().into(),
    ];
    for a in extra {
        argv.push((*a).into());
    }
    argv.push(obj_path.to_string_lossy().into_owned().into());
    let o = opts::parse(&argv).expect("the surface parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(dir.join(out)).expect("the image reads")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_hidden_library_link_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the scratch dir creates");
    let stub = lib_tbd(&dir, "greet");

    // Face 1 — the hidden default: the dylib's exports resolve, the
    // load command drops, the weak bind rides dyld's flat lookup.
    let image = link(
        &dir,
        "hello_hidden",
        &["-hidden_library", &stub],
        &weak_hello(),
    );
    println!(
        "face 1 (-hidden_library): dylib commands {:?}",
        dylib_names(&image)
    );
    let strict = VerifyOptions::default();
    assert!(
        verify(&image, &strict).is_ok(&strict),
        "the image verifies strict"
    );

    // Face 2 — the strong refusal: dyld cannot bind a strong reference
    // without the load command the mark drops.
    let obj_path = dir.join("hello.o");
    std::fs::write(&obj_path, strong_hello()).expect("the object writes");
    let argv: Vec<OsString> = vec![
        "-o".into(),
        dir.join("hello_strong")
            .to_string_lossy()
            .into_owned()
            .into(),
        "-hidden_library".into(),
        stub.clone().into(),
        obj_path.to_string_lossy().into_owned().into(),
    ];
    let outcome = match opts::parse(&argv) {
        Ok(o) => pgr_driver::run(&o).map(|_| ()).map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    match outcome {
        Ok(_) => panic!("the strong bind must refuse"),
        Err(err) => println!("face 2 (strong bind): refused — {err}"),
    }

    // Face 3 — the `-hidden-l` form: the basename rides the `-L` search
    // carrying the mark.
    let image = link(
        &dir,
        "hello_hidden_l",
        &["-L", &dir.to_string_lossy(), "-hidden-lgreet"],
        &weak_hello(),
    );
    println!(
        "face 3 (-hidden-l): dylib commands {:?}",
        dylib_names(&image)
    );

    // Face 4 — the relocatable refusal: the object carries no load
    // commands for the mark to drop.
    let argv: Vec<OsString> = vec![
        "-r".into(),
        "-o".into(),
        dir.join("o.o").to_string_lossy().into_owned().into(),
        "-hidden_library".into(),
        stub.into(),
        obj_path.to_string_lossy().into_owned().into(),
    ];
    match opts::parse(&argv) {
        Ok(_) => panic!("the relocatable output must refuse the mark"),
        Err(err) => println!("face 4 (-r): refused — {err}"),
    }

    println!("\nhidden_library_link: ok");
}

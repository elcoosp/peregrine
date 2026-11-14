//! The private-extern consumer example (M33): the same corpus — one
//! plain external, one private external (the compilers'
//! `.private_extern`, the input `N_PEXT` bit) — linked as a plain
//! executable twice: the default conversion (the private extern lands
//! in the locals range as `N_SECT | N_PEXT`, absent from the export
//! trie) and `-keep_private_externs` (the row stays external as
//! `N_EXT | N_SECT | N_PEXT`, exported like any other definition),
//! both run through the strict verifier and the rows read back from
//! the images.
//!
//! Run: `cargo run -p pgr-driver --example keep_private_externs_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans —
//! the same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::{N_EXT, N_PEXT, N_SECT};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SymtabCommand};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` plain, `_helper` private — the executable the
/// example links twice.
fn hello_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::DefinedPrivate {
        name: "_helper".into(),
        section_index: text,
        value: 4,
    });
    b.build().expect("the fixture object builds")
}

/// The output symtab row's `n_type` for `name` (walked through the
/// format reader).
fn sym_n_type(image: &[u8], name: &[u8]) -> Option<u8> {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    let mut st = None;
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::Symtab = cmd.kind {
            st = Some(SymtabCommand::parse(image, cmd.offset).expect("the symtab parses"));
        }
    }
    let st = st.expect("the symtab command rides the header");
    for i in 0..st.nsyms {
        let off = st.symoff as usize + i as usize * 16;
        let sym: pgr_format::Nlist64 =
            pgr_format::cursor::pod_read_unaligned_at(image, off).expect("the row parses");
        let at = st.stroff as usize + sym.n_strx as usize;
        let end = image[at..].iter().position(|&b| b == 0).expect("NUL") + at;
        if &image[at..end] == name {
            return Some(sym.n_type);
        }
    }
    None
}

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).expect("the image reads")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_keeppext_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The default conversion: the private extern lands in the
    //    locals range (the filter-hidden shape) and the image verifies
    //    strict like any other.
    let converted = link(&dir, "hello_conv", &[]);
    assert_eq!(
        sym_n_type(&converted, b"_helper"),
        Some(N_SECT | N_PEXT),
        "the conversion is the locals-range shape"
    );
    let report = verify(&converted, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the converted image verifies strict: {:?}",
        report.issues
    );

    // 2. The decision: `-keep_private_externs` holds the row external
    //    with `N_PEXT` set — exported like any other definition — and
    //    the image verifies strict like the converted one.
    let kept = link(&dir, "hello_keep", &["-keep_private_externs"]);
    assert_eq!(
        sym_n_type(&kept, b"_helper"),
        Some(N_EXT | N_SECT | N_PEXT),
        "the keep holds the row external with N_PEXT set"
    );
    let report = verify(&kept, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the kept image verifies strict: {:?}",
        report.issues
    );

    println!(
        "converted: _helper rides the locals range (N_SECT | N_PEXT, {} bytes of image)",
        converted.len()
    );
    println!(
        "kept: _helper rides the extdef range (N_EXT | N_SECT | N_PEXT, exported, \
         {} bytes of image)",
        kept.len()
    );

    println!("\nkeep_private_externs_link: ok");
}

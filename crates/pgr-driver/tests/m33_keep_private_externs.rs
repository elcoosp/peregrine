//! M33 — the `-keep_private_externs` driver surface: the flag the
//! surface carried as a no-op since M1 parses onto the core
//! private-extern decision. A corpus with a private-extern definition
//! links end-to-end with the row converted into a local (`N_SECT |
//! N_PEXT`, absent from the export trie — the default) and held
//! external (`N_EXT | N_SECT | N_PEXT`, exported), and both images
//! verify strict.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::{N_EXT, N_PEXT, N_SECT};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SymtabCommand};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m33_pext_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A corpus with one private-extern definition (`_helper`).
fn corpus(dir: &Path, tag: &str) -> PathBuf {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
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
    let path = dir.join(format!("main_{tag}.o"));
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// Links `obj` under `extra` argv; returns the image bytes.
fn link(dir: &Path, out: &str, obj: &Path, extra: &[&str]) -> Vec<u8> {
    let out_path = dir.join(out);
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string()];
    argv.push(obj.display().to_string());
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).unwrap()
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// The output symtab row for `name` (walked through the format reader).
fn sym_row(image: &[u8], name: &[u8]) -> Option<(u8, u16)> {
    let header = MachHeader64::parse(image).expect("the header parses");
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
            return Some((sym.n_type, sym.n_desc));
        }
    }
    None
}

// ---- the flag ------------------------------------------------------------------

#[test]
fn the_flag_names_the_decision() {
    let dir = scratch("flag");
    let obj = corpus(&dir, "flag");
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("out").display().to_string(),
        "-keep_private_externs".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = pgr_driver::opts::parse(&argv).expect("the flag parses");
    assert!(
        o.config.keep_private_externs,
        "the flag parses onto the keep decision"
    );
    let default_argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("out_default").display().to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    assert!(
        !pgr_driver::opts::parse(&default_argv)
            .expect("the default surface parses")
            .config
            .keep_private_externs,
        "the default converts"
    );
}

// ---- the end-to-end shapes -------------------------------------------------------

#[test]
fn the_converted_link_keeps_the_row_private_and_verifies_strict() {
    let dir = scratch("convert");
    let obj = corpus(&dir, "convert");
    let image = link(&dir, "hello_conv", &obj, &[]);
    let (n_type, _n_desc) = sym_row(&image, b"_helper").expect("the row rides the symtab");
    assert_eq!(
        n_type,
        N_SECT | N_PEXT,
        "the conversion is the locals-range shape"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the converted image verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_kept_link_holds_the_row_external_and_verifies_strict() {
    let dir = scratch("keep");
    let obj = corpus(&dir, "keep");
    let image = link(&dir, "hello_keep", &obj, &["-keep_private_externs"]);
    let (n_type, _n_desc) = sym_row(&image, b"_helper").expect("the row rides the symtab");
    assert_eq!(
        n_type,
        N_EXT | N_SECT | N_PEXT,
        "the keep holds the row external with N_PEXT set"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the kept image verifies strict: {:?}",
        report.issues
    );
}

//! M25 — the `-bundle_loader <path>` driver surface: the flag names the
//! host executable a bundle binds against, the driver scans the host's
//! export surface (the trie the linker itself emits), the bundle links
//! end-to-end with its loader binds riding the main-executable ordinal
//! (`0xFF`), and the pair gate cross-checks the two images (every
//! `0xFF` bind names an export the host's trie carries).

use pgr_fixtures::{
    ImageBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol, SectionSpec,
    SegmentSpec, SymbolSpec, filler,
};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::pair::verify_bundle_loader;
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m25_loader_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// The bundle body: `_bundle_main` calls `_host_fn` (BL against the
/// loader).
fn bundle_object(dir: &Path) -> PathBuf {
    let mut b = ObjectBuilder::new("bundle.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [
            0x9400_0000u32, // bl _host_fn
            0x5280_0000u32, // mov w0, #0
            0xD65F_03C0u32, // ret
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect(),
        vec![ObjectReloc::branch26(1).at(0)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_bundle_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_host_fn".into(),
        weak_ref: false,
    });
    let path = dir.join("bundle.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// The host executable image: a legal pgr-linked executable exporting
/// `_host_fn` (the bundle loader).
fn host_executable(dir: &Path) -> PathBuf {
    let mut b = ImageBuilder::executable("m25host");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0x5AA5, 96),
            relocs: Vec::new(),
        }],
    });
    b.set_entry(0);
    b.add_symbol(SymbolSpec::Defined {
        name: "_host_fn".into(),
        section_index: 0,
    });
    let path = dir.join("host");
    std::fs::write(&path, b.build().expect("the host fixture builds").bytes).unwrap();
    path
}

/// Links the bundle under `extra` argv; returns the image bytes.
fn link(dir: &Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let obj = bundle_object(dir);
    let out_path = dir.join(out);
    let mut argv: Vec<String> = vec![
        "-o".into(),
        out_path.display().to_string(),
        "-bundle".into(),
    ];
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

// ---- the surface ---------------------------------------------------------------

#[test]
fn the_flag_names_the_host_and_the_bundle_links_two_level() {
    let dir = scratch("parse");
    let host = host_executable(&dir);
    let image = link(
        &dir,
        "bundle.dylib",
        &["-bundle_loader", host.display().to_string().as_str()],
    );

    // The undefined external carries the main-executable ordinal.
    let hdr = pgr_format::MachHeader64::parse(&image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        &image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut st = None;
    while let Some(cmd) = it.next_command().expect("the chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::Symtab {
            st = Some(
                pgr_format::symtab::SymtabCommand::parse(cmd.bytes, 0).expect("the symtab parses"),
            );
        }
    }
    let st = st.expect("LC_SYMTAB present");
    let mut saw_loader_bind = false;
    for i in 0..st.nsyms {
        let off = st.symoff as usize + i as usize * 16;
        let sym: pgr_format::symtab::Nlist64 =
            pgr_format::cursor::pod_read_unaligned_at(&image, off).expect("the symbol reads");
        if sym.is_undefined()
            && sym.is_external()
            && sym.library_ordinal() == pgr_format::consts::BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE
        {
            saw_loader_bind = true;
        }
    }
    assert!(
        saw_loader_bind,
        "the loader bind rides the main-executable ordinal"
    );

    // The pair gate: every 0xFF bind names an export the host's trie
    // carries.
    let host_bytes = std::fs::read(&host).unwrap();
    let pair = verify_bundle_loader(&image, &host_bytes, &strict());
    assert!(
        pair.is_ok(&strict()),
        "the bundle + loader pair verifies: bundle {:?}, loader {:?}, pair {:?}",
        pair.bundle.issues,
        pair.loader.issues,
        pair.pair_issues
    );

    // The bundle verifies strict on its own, too.
    assert!(
        verify(&image, &strict()).is_ok(&strict()),
        "strict verifies"
    );
}

#[test]
fn the_knob_refuses_off_a_bundle() {
    let dir = scratch("conflict");
    let host = host_executable(&dir);
    let obj = bundle_object(&dir);
    for (kind, needle) in [
        (
            vec!["-dylib", "-install_name", "@rpath/libb.dylib"],
            "dylib",
        ),
        (vec!["-r"], "relocatable"),
    ] {
        let mut argv: Vec<String> = vec![
            "-o".into(),
            dir.join("out").display().to_string(),
            "-bundle_loader".into(),
            host.display().to_string(),
        ];
        argv.extend(kind.iter().map(std::string::ToString::to_string));
        argv.push(obj.display().to_string());
        let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
        let err = pgr_driver::opts::parse(&argv).expect_err("the shape refuses");
        let report = miette::Report::new(err);
        let msg = format!("{report:?}");
        assert!(
            msg.contains(needle),
            "the refusal names the output kind ({needle}): {msg}"
        );
    }
}

#[test]
fn a_missing_host_file_names_the_path() {
    let dir = scratch("missing");
    let obj = bundle_object(&dir);
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("out").display().to_string(),
        "-bundle".to_string(),
        "-bundle_loader".to_string(),
        dir.join("nowhere").display().to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    let err = pgr_driver::run(&o).expect_err("the missing host refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("nowhere"),
        "the refusal names the missing path: {msg}"
    );
}

#[test]
fn the_double_link_is_byte_identical() {
    let dir = scratch("det");
    let host = host_executable(&dir);
    let a = link(
        &dir,
        "a",
        &["-bundle_loader", host.display().to_string().as_str()],
    );
    let b = link(
        &dir,
        "b",
        &["-bundle_loader", host.display().to_string().as_str()],
    );
    assert_eq!(a, b, "the double link is byte-identical (TDD §4.3)");
}

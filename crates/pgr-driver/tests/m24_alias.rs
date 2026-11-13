//! M24 — the `-alias <alias_name> <definition_name>` driver surface:
//! the flag parses repeatable onto the validated core table, refuses on
//! the relocatable output (the object surface carries the input symtab
//! verbatim), and an aliased link lands end-to-end — the alias names
//! ride the symtab and the export trie at the definition's address, the
//! image verifies strict exactly like the plain one, and the double
//! link stays byte-identical (TDD §4.3).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m24_alias_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A two-function corpus (`_main`, `_lib_fn`) written to `dir`; the
/// `__data` pointer keeps a rebase slot in the image.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (i, sym) in ["_main", "_lib_fn"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let _ = data;
    let path = dir.join("main.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    vec![path]
}

/// Links the corpus under `kind` argv shapes; returns the image bytes.
fn link(dir: &Path, out: &str, kind: &[&str], extra: &[&str]) -> Vec<u8> {
    let objs = corpus(dir);
    let out_path = dir.join(out);
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string()];
    argv.extend(kind.iter().map(std::string::ToString::to_string));
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
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

/// The image's export trie, walked.
fn trie_exports(image: &[u8]) -> Vec<pgr_format::TrieExport> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut payload: Option<&[u8]> = None;
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if let pgr_format::LoadCommandKind::LinkeditData(op) = cmd.kind
            && op == pgr_format::consts::LC_DYLD_EXPORTS_TRIE
        {
            let (off, size) = (
                u32::from_le_bytes(cmd.bytes[8..12].try_into().expect("dataoff")),
                u32::from_le_bytes(cmd.bytes[12..16].try_into().expect("datasize")),
            );
            let at = off as usize;
            payload = Some(&image[at..at + size as usize]);
        }
    }
    let payload = payload.expect("LC_DYLD_EXPORTS_TRIE present");
    pgr_format::trie::exports(payload).expect("the trie walks")
}

// ---- the surface ---------------------------------------------------------------

#[test]
fn the_flag_parses_repeatable_in_flag_order() {
    let dir = scratch("parse");
    let objs = corpus(&dir);
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("out").display().to_string(),
        "-alias".to_string(),
        "_shim_a".to_string(),
        "_lib_fn".to_string(),
        "-alias".to_string(),
        "_shim_b".to_string(),
        "_main".to_string(),
        objs[0].display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    let aliases: Vec<(&str, &str)> = o
        .config
        .aliases
        .iter()
        .map(|a| (a.alias(), a.definition()))
        .collect();
    assert_eq!(
        aliases,
        [("_shim_a", "_lib_fn"), ("_shim_b", "_main")],
        "the aliases ride the config in flag order"
    );
}

#[test]
fn malformed_and_duplicate_aliases_refuse_with_the_fix() {
    let dir = scratch("bad");
    let objs = corpus(&dir);
    let base: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("out").display().to_string(),
        objs[0].display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    for (bad, needle) in [
        (vec!["-alias", "_a"], "value"),
        (vec!["-alias", "", "_lib_fn"], "non-empty"),
        (vec!["-alias", "_a", "_a"], "distinct"),
        (vec!["-alias", "_a\0x", "_lib_fn"], "NUL"),
    ] {
        let mut argv = base.clone();
        for a in bad {
            argv.push(std::ffi::OsString::from(a));
        }
        let err = pgr_driver::opts::parse(&argv).expect_err("the bad alias refuses");
        let report = miette::Report::new(err);
        let msg = format!("{report:?}");
        assert!(
            msg.contains(needle),
            "the refusal names the fix ({needle}): {msg}"
        );
    }
    // A repeated alias name: one decision per name.
    let mut argv = base.clone();
    for a in ["-alias", "_dup", "_lib_fn", "-alias", "_dup", "_main"] {
        argv.push(std::ffi::OsString::from(a));
    }
    let err = pgr_driver::opts::parse(&argv).expect_err("the duplicate refuses");
    let report = miette::Report::new(err);
    assert!(format!("{report:?}").contains("_dup"), "{report:?}");
}

#[test]
fn the_relocatable_output_refuses_the_knob() {
    let dir = scratch("reloc");
    let objs = corpus(&dir);
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("out.o").display().to_string(),
        "-r".to_string(),
        "-alias".to_string(),
        "_shim".to_string(),
        "_lib_fn".to_string(),
        objs[0].display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let err = pgr_driver::opts::parse(&argv).expect_err("the relocatable output refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("relocatable"),
        "the refusal names the output kind: {msg}"
    );
}

// ---- the end-to-end shape ------------------------------------------------------

#[test]
fn an_aliased_executable_links_and_verifies_strict() {
    let dir = scratch("exec");
    let img = link(&dir, "hello", &[], &["-alias", "_shim", "_lib_fn"]);
    let exports = trie_exports(&img);
    let shim = exports
        .iter()
        .find(|e| e.name == b"_shim")
        .expect("the alias exports");
    let target = exports
        .iter()
        .find(|e| e.name == b"_lib_fn")
        .expect("the definition exports");
    assert_eq!(
        shim.address, target.address,
        "the alias exports at the body"
    );
    assert!(verify(&img, &strict()).is_ok(&strict()), "strict verifies");

    // The double link is byte-identical (TDD §4.3).
    let again = link(&dir, "hello", &[], &["-alias", "_shim", "_lib_fn"]);
    assert_eq!(img, again, "the double link is byte-identical");
}

#[test]
fn an_aliased_dylib_ships_both_names() {
    let dir = scratch("dylib");
    let img = link(
        &dir,
        "libhello.dylib",
        &["-dylib", "-install_name", "@rpath/libhello.dylib"],
        &["-alias", "_shim", "_lib_fn"],
    );
    let exports = trie_exports(&img);
    let shim = exports
        .iter()
        .find(|e| e.name == b"_shim")
        .expect("the alias exports");
    let target = exports
        .iter()
        .find(|e| e.name == b"_lib_fn")
        .expect("the definition exports");
    assert_eq!(shim.address, target.address, "both names, one body");
    assert!(verify(&img, &strict()).is_ok(&strict()), "strict verifies");
}

#[test]
fn the_resident_cycle_carries_the_aliases() {
    // One-shot reference.
    let dir = scratch("resident_ref");
    let one_shot = link(&dir, "hello_ref", &[], &["-alias", "_shim", "_lib_fn"]);

    // The same link through the resident path: the daemon relinks with
    // the same config, so the named pairs crossed the wire (v16).
    let dir2 = scratch("resident");
    let sock = dir2.join("pgrd.sock");
    let owned = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(120));
    });
    std::thread::sleep(Duration::from_millis(50));

    let objs = corpus(&dir2);
    let out_path = dir2.join("hello");
    let mut argv = vec![
        "-o".to_string(),
        out_path.display().to_string(),
        "-alias".to_string(),
        "_shim".to_string(),
        "_lib_fn".to_string(),
        "-resident".to_string(),
        "-resident_socket".to_string(),
        sock.display().to_string(),
    ];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the resident argv parses");
    pgr_driver::run(&o).expect("the resident link runs");
    let resident = std::fs::read(&out_path).unwrap();
    assert_eq!(
        one_shot, resident,
        "the resident cycle plans the same bytes with the named aliases"
    );
}

#[test]
fn an_alias_of_a_missing_name_is_a_link_error() {
    let dir = scratch("missing");
    let objs = corpus(&dir);
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("out").display().to_string(),
        "-alias".to_string(),
        "_shim".to_string(),
        "_nowhere".to_string(),
        objs[0].display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    let err = pgr_driver::run(&o).expect_err("the missing definition refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("_nowhere"),
        "the refusal names the misspelling: {msg}"
    );
}

//! M40 — the export-trie driver surface: `-no_exported_symbols` links
//! an image whose header carries no `LC_DYLD_EXPORTS_TRIE` command and
//! still verifies strict, the default keeps every pre-M40 link
//! byte-identical, the output-kind refusals render as miette help text
//! (the fix, not just the verdict), and the re-export conflict refuses
//! at parse time (the library's `link()` re-checks — no caller can
//! plan the shape either).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m40_exports_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// `_main` (RET) with a second defined external — the trie carries
/// both, the suppression drops the command.
fn corpus(dir: &Path, tag: &str) -> PathBuf {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2), // ret; ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_f".into(),
        section_index: text,
        value: 4,
        weak: false,
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
    std::fs::read(&out_path).expect("the image reads")
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

fn carries_trie_command(image: &[u8]) -> bool {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if cmd.kind
            == pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_EXPORTS_TRIE)
        {
            return true;
        }
    }
    false
}

#[test]
fn m40_flag_shapes_the_config() {
    let dir = scratch("opts");
    let obj = corpus(&dir, "opts");
    let argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join("app").as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
        std::ffi::OsString::from("-no_exported_symbols"),
    ];
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    assert!(
        !o.config.exported_symbols,
        "the suppression names the decision"
    );
    let default = pgr_driver::opts::parse(&argv[..3]).expect("the argv parses");
    assert!(
        default.config.exported_symbols,
        "the default keeps every pre-M40 link byte-identical"
    );
}

#[test]
fn the_suppressed_link_drops_the_command_and_verifies_strict() {
    let dir = scratch("e2e");
    let obj = corpus(&dir, "sup");
    let image = link(&dir, "app_noexports", &obj, &["-no_exported_symbols"]);
    assert!(
        !carries_trie_command(&image),
        "LC_DYLD_EXPORTS_TRIE drops on the named decision"
    );
    let plain = link(&dir, "app_plain", &obj, &[]);
    assert!(carries_trie_command(&plain), "the default carries the trie");
    assert!(
        plain.len() - image.len() >= 16,
        "the file shrinks past the command slot (the signature blob tail re-sizes \
         with the LINKEDIT it covers)"
    );
    let report = verify(&image, &strict());
    assert!(
        report
            .issues
            .iter()
            .all(|i| i.severity != pgr_verify::Severity::Error),
        "the suppressed image verifies: {:?}",
        report.issues
    );
}

#[test]
fn the_output_kind_refusals_render_the_fix() {
    let dir = scratch("refuse");
    let obj = corpus(&dir, "ref");
    // A dylib: its trie IS the two-level contract its clients bind through.
    let dylib_argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join("libout.dylib").as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
        std::ffi::OsString::from("-dylib"),
        std::ffi::OsString::from("-install_name"),
        std::ffi::OsString::from("@rpath/libout.dylib"),
        std::ffi::OsString::from("-no_exported_symbols"),
    ];
    let err = pgr_driver::opts::parse(&dylib_argv).expect_err("a dylib refuses the knob");
    let rendered = format!("{:?}", miette::Report::new(err));
    assert!(
        rendered.contains("-no_exported_symbols"),
        "the help names the fix: {rendered}"
    );
    // A bundle: the dlopen/dlsym surface rides the trie.
    let bundle_argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join("plug").as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
        std::ffi::OsString::from("-bundle"),
        std::ffi::OsString::from("-no_exported_symbols"),
    ];
    assert!(
        pgr_driver::opts::parse(&bundle_argv).is_err(),
        "a bundle refuses the knob"
    );
    // The relocatable output: no __LINKEDIT commands at all.
    let reloc_argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join("out.o").as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
        std::ffi::OsString::from("-r"),
        std::ffi::OsString::from("-no_exported_symbols"),
    ];
    assert!(
        pgr_driver::opts::parse(&reloc_argv).is_err(),
        "the relocatable output refuses the knob"
    );
}

#[test]
fn the_reexport_conflict_refuses_at_parse() {
    let dir = scratch("reexport");
    let obj = corpus(&dir, "rex");
    // A re-export stub dylib the flag would silently break.
    let stub_path = dir.join("libre.tbd");
    std::fs::write(
        &stub_path,
        "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\n\
         install-name: @rpath/libre.dylib\ncurrent-version: 1.0.0\n\
         compatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n\
         \x20   symbols: [ _f ]\n...\n",
    )
    .expect("the stub writes");
    let argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join("app").as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
        std::ffi::OsString::from("-reexport_library"),
        stub_path.as_os_str().to_os_string(),
        std::ffi::OsString::from("-no_exported_symbols"),
    ];
    let err = pgr_driver::opts::parse(&argv)
        .expect_err("REEXPORT nodes ride the trie — the combination refuses");
    let rendered = format!("{:?}", miette::Report::new(err));
    assert!(
        rendered.contains("re-export") || rendered.contains("REEXPORT"),
        "the refusal names the contract: {rendered}"
    );
}

//! M42 — the unused-dylib drop, driver surface: `-dead_strip_dylibs`
//! links a two-dylib corpus into an image whose header carries only the
//! used dylib's `LC_LOAD_DYLIB` (and verifies strict), the default
//! keeps every input dylib byte-identical, the cached lane stays
//! byte-identical under the knob, and the surface conflicts refuse
//! (the relocatable output carries no load commands; the flat-namespace
//! bind names no provider).

use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::{DylibCommand, LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::PathBuf;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m42_dylibs_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// main.o: `_main` over two RET functions, one `__data` bind slot
/// against `_used` (the undefined reference the two-level bind names).
fn caller_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
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
        name: "_used".into(),
        weak_ref: false,
    });
    let slot = b.sym_index(undef);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    b.build().expect("the fixture object builds")
}

/// Two `.tbd` text stubs (the tapi-v4 YAML form): one exporting
/// `_used`, one exporting only `_unused`.
fn tbd(name: &str, export: &str) -> String {
    format!(
        "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: @rpath/{name}.dylib\n\
         current-version: 1.0.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _{export} ]\n...\n"
    )
}

/// Writes the corpus (one object, two text stubs); returns the paths in
/// command order.
fn corpus(dir: &std::path::Path, tag: &str) -> Vec<PathBuf> {
    let obj = dir.join(format!("{tag}_main.o"));
    std::fs::write(&obj, caller_object()).unwrap();
    let used = dir.join(format!("{tag}_libused.tbd"));
    std::fs::write(&used, tbd("libused", "used")).unwrap();
    let unused = dir.join(format!("{tag}_libunused.tbd"));
    std::fs::write(&unused, tbd("libunused", "unused")).unwrap();
    vec![obj, used, unused]
}

/// Links `inputs` under `extra` argv; returns the image bytes.
fn link(dir: &std::path::Path, out: &str, inputs: &[PathBuf], extra: &[&str]) -> Vec<u8> {
    let out_path = dir.join(out);
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string()];
    argv.extend(inputs.iter().map(|p| p.display().to_string()));
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

/// The dylib install names the header's load commands carry, in
/// command order.
fn header_dylibs(image: &[u8]) -> Vec<String> {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    let mut out = Vec::new();
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if matches!(
            cmd.kind,
            LoadCommandKind::LoadDylib | LoadCommandKind::ReexportDylib
        ) {
            let dylib_cmd = DylibCommand::parse(cmd.bytes).expect("the dylib command parses");
            let name = dylib_cmd.name(cmd.bytes).expect("the install name reads");
            out.push(String::from_utf8_lossy(name).into_owned());
        }
    }
    out
}

#[test]
fn m42_flag_shapes_the_config() {
    let dir = scratch("opts");
    let inputs = corpus(&dir, "opts");
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join("app").as_os_str().to_os_string(),
    ];
    argv.extend(inputs.iter().map(|p| p.as_os_str().to_os_string()));
    argv.push(std::ffi::OsString::from("-dead_strip_dylibs"));
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    assert!(o.config.dead_strip_dylibs, "the drop names the decision");
    let default = pgr_driver::opts::parse(&argv[..2 + inputs.len()]).expect("the argv parses");
    assert!(
        !default.config.dead_strip_dylibs,
        "the default keeps every pre-M42 link byte-identical"
    );
}

#[test]
fn the_unused_dylib_drops_and_verifies_strict() {
    let dir = scratch("e2e");
    let inputs = corpus(&dir, "e2e");
    let dropped = link(&dir, "app_dropped", &inputs, &["-dead_strip_dylibs"]);
    assert_eq!(
        header_dylibs(&dropped),
        vec!["@rpath/libused.dylib".to_string()],
        "the unused dylib's command leaves the header"
    );
    let report = verify(&dropped, &strict());
    assert!(
        report.is_ok(&strict()),
        "the dropped image verifies strict: {:?}",
        report.issues
    );

    // The default: both commands ride (ld64's shape) and the image
    // verifies strict.
    let carried = link(&dir, "app_carried", &inputs, &[]);
    assert_eq!(
        header_dylibs(&carried),
        vec![
            "@rpath/libused.dylib".to_string(),
            "@rpath/libunused.dylib".to_string(),
        ],
        "the default carries every input dylib"
    );
    let report = verify(&carried, &strict());
    assert!(
        report.is_ok(&strict()),
        "the carried image verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_cached_lane_stays_byte_identical_under_the_knob() {
    let dir = scratch("cache");
    let inputs = corpus(&dir, "cached");
    let plain = link(&dir, "app_plain", &inputs, &["-dead_strip_dylibs"]);
    let cached = link(
        &dir,
        "app_cached",
        &inputs,
        &[
            "-dead_strip_dylibs",
            "-cache",
            &dir.join("cache").display().to_string(),
        ],
    );
    assert_eq!(
        plain, cached,
        "the cold cached link is byte-identical (the cache carries parsed inputs, the knob rides the resolve)"
    );
    let warm = link(
        &dir,
        "app_warm",
        &inputs,
        &[
            "-dead_strip_dylibs",
            "-cache",
            &dir.join("cache").display().to_string(),
        ],
    );
    assert_eq!(plain, warm, "the warm cached link is byte-identical");
}

#[test]
fn the_surface_conflicts_refuse() {
    let dir = scratch("conflict");
    let inputs = corpus(&dir, "conflict");
    // The relocatable output carries no load commands.
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join("out_r").as_os_str().to_os_string(),
        std::ffi::OsString::from("-r"),
        std::ffi::OsString::from("-dead_strip_dylibs"),
    ];
    argv.extend(inputs.iter().map(|p| p.as_os_str().to_os_string()));
    let err = pgr_driver::opts::parse(&argv).expect_err("the relocatable conflict refuses");
    assert!(
        err.to_string().contains("-dead_strip_dylibs"),
        "the refusal names the knob: {err}"
    );
    // The flat-namespace bind names no provider.
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join("out_flat").as_os_str().to_os_string(),
        std::ffi::OsString::from("-flat_namespace"),
        std::ffi::OsString::from("-dead_strip_dylibs"),
    ];
    argv.extend(inputs.iter().map(|p| p.as_os_str().to_os_string()));
    let err = pgr_driver::opts::parse(&argv).expect_err("the flat-namespace conflict refuses");
    assert!(
        err.to_string().contains("flat"),
        "the refusal names the conflict: {err}"
    );
}

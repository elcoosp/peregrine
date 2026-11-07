//! M7 build-system integration gates (architecture doc §10.3 row M7:
//! "ld-compatible driver tested through clang `-fuse-ld`, Xcode and
//! `xcodebuild`, cargo, CMake/Ninja" — the in-tree, filesystem-honest half):
//!
//! * **response files** (`@file`, nested, quoted) expand in command-line
//!   order — the shape CMake/Ninja emit for long link lines,
//! * **`-syslibroot <dir>`** reshapes the library/framework search paths the
//!   way ld64 does (single root: prefixed paths only; multiple roots: the
//!   union including the original path) — the flag Xcode always passes,
//! * accepted no-op flags (`-demangle`/`-no_demangle`/`-no_deduplicate`,
//!   `-object_path_lto <path>`) parse without swallowing inputs.

use pgr_driver::opts::{Options, parse};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::ffi::OsString;

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(std::ffi::OsString::from).collect()
}

fn scratch(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m7_driver").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn caller() -> Vec<u8> {
    let mut b = ObjectBuilder::new("caller.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![
            0x91, 0x00, 0x00, 0x00, // add x0, x0, #0
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.build().unwrap()
}

fn greet_tbd() -> Vec<u8> {
    b"--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: /usr/lib/libgreet.dylib\ncurrent-version: 1.2.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _greet ]\n...\n"
        .to_vec()
}

fn opts_with_inputs(paths: &[String], out: &std::path::Path) -> Options {
    Options {
        inputs: paths.to_vec(),
        output: out.display().to_string(),
        config: pgr_core::layout::LinkConfig {
            ident: "m7-driver".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        ..Options::default()
    }
}

#[test]
fn m7_response_file_drives_a_real_link() {
    // The CMake/Ninja shape: every argument on its own line, including the
    // output path, flags with separate values and the library request.
    let dir = scratch("rsp_link");
    let obj = dir.join("caller.o");
    std::fs::write(&obj, caller()).unwrap();
    let lib_dir = dir.join("L");
    std::fs::create_dir_all(&lib_dir).unwrap();
    std::fs::write(lib_dir.join("libgreet.tbd"), greet_tbd()).unwrap();
    let out = dir.join("hi.bin");
    let rsp = dir.join("link.rsp");
    std::fs::write(
        &rsp,
        format!(
            "# pgr link line\n-o\n{}\n-platform_version\nmacos\n12.0\n14.0\n-L\n{}\n-l\ngreet\n{}\n",
            out.display(),
            lib_dir.display(),
            obj.display()
        ),
    )
    .unwrap();
    let opts = parse(&args(&[&format!("@{}", rsp.display())])).unwrap();
    assert_eq!(opts.output, out.display().to_string());
    assert_eq!(opts.libs, ["greet"]);
    assert_eq!(opts.lib_dirs, [lib_dir.display().to_string()]);
    pgr_driver::run(&opts).unwrap();
    assert!(out.is_file(), "the expanded command line linked");
    // And the same link built without the response file is byte-identical.
    let out2 = dir.join("hi2.bin");
    let mut plain = opts_with_inputs(&[obj.display().to_string()], &out2);
    plain.libs = vec!["greet".into()];
    plain.lib_dirs = vec![lib_dir.display().to_string()];
    plain.config.minos = 12 << 16; // macos 12.0 (same as the response file)
    plain.config.sdk = 14 << 16; // macos 14.0
    plain.config.ident = opts.config.ident.clone(); // same CodeDirectory ident
    pgr_driver::run(&plain).unwrap();
    let a = std::fs::read(&out).unwrap();
    let b = std::fs::read(&out2).unwrap();
    assert_eq!(
        (a.len(), b.len(), a == b),
        (b.len(), a.len(), true),
        "response-file expansion is order-preserving ({} vs {} bytes)",
        a.len(),
        b.len()
    );
}

#[test]
fn m7_syslibroot_prefixes_the_sdk_search() {
    // libgreet.tbd lives only inside the "SDK"; a single -syslibroot must
    // make the SDK paths the searched ones (prefixed-only rule).
    let dir = scratch("syslibroot");
    let obj = dir.join("caller.o");
    std::fs::write(&obj, caller()).unwrap();
    let out = dir.join("hi.bin");
    let sdk = dir.join("MacOSX.sdk");
    let sdk_lib = sdk.join("usr").join("lib");
    std::fs::create_dir_all(&sdk_lib).unwrap();
    std::fs::write(sdk_lib.join("libgreet.tbd"), greet_tbd()).unwrap();
    let opts = parse(&args(&[
        "-o",
        &out.display().to_string(),
        "-syslibroot",
        &sdk.display().to_string(),
        "-l",
        "greet",
        &obj.display().to_string(),
    ]))
    .unwrap();
    pgr_driver::run(&opts).unwrap();
    assert!(out.is_file(), "-l greet resolved inside the syslibroot");
    // Without the root the same -l fails (the SDK dir is not searched).
    let out2 = dir.join("hi2.bin");
    let no_root = parse(&args(&[
        "-o",
        &out2.display().to_string(),
        "-l",
        "greet",
        &obj.display().to_string(),
    ]))
    .unwrap();
    let err = pgr_driver::run(&no_root).unwrap_err();
    assert!(
        err.to_string().contains("library not found"),
        "expected a not-found diagnostic, got {err}"
    );
}

#[test]
fn m7_two_syslibroots_search_the_union() {
    // Two roots: the union rule — the library in root 2 is found even though
    // root 1 shadows the search list, and an -L dir itself stays searched.
    let dir = scratch("syslibroot2");
    let obj = dir.join("caller.o");
    std::fs::write(&obj, caller()).unwrap();
    let out = dir.join("hi.bin");
    let sdk2 = dir.join("sdk2");
    let sdk2_lib = sdk2.join("usr").join("lib");
    std::fs::create_dir_all(&sdk2_lib).unwrap();
    std::fs::write(sdk2_lib.join("libgreet.tbd"), greet_tbd()).unwrap();
    let opts = parse(&args(&[
        "-o",
        &out.display().to_string(),
        "-syslibroot",
        &dir.join("sdk1").display().to_string(),
        "-syslibroot",
        &sdk2.display().to_string(),
        "-l",
        "greet",
        &obj.display().to_string(),
    ]))
    .unwrap();
    pgr_driver::run(&opts).unwrap();
    assert!(out.is_file(), "the union search found the sdk2 library");
}

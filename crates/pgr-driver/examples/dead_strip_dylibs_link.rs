//! The dead-strip-dylibs consumer example (M42): a two-dylib corpus
//! linked under the default (every input dylib rides its
//! `LC_LOAD_DYLIB` command — ld64's shape) beside the same corpus under
//! `-dead_strip_dylibs` (the dylib nothing binds against leaves the
//! header, the kept list compacts the two-level ordinals), both run
//! through the strict verifier, and the dropped command printed — the
//! knob a build system names when its link line carries transitive
//! dylibs nothing binds against.
//!
//! Run: `cargo run -p pgr-driver --example dead_strip_dylibs_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans —
//! the same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::{DylibCommand, LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};

/// main.o: `_main` over two RET functions, one `__data` bind slot
/// against `_used`.
fn caller_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        Vec::new(),
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

/// A tapi-v4 text stub exporting one symbol.
fn tbd(name: &str, export: &str) -> String {
    format!(
        "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: @rpath/{name}.dylib\n\
         current-version: 1.0.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _{export} ]\n...\n"
    )
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

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
    ];
    let obj = dir.join("main.o");
    std::fs::write(&obj, caller_object()).unwrap();
    argv.push(obj.as_os_str().to_os_string());
    for (name, export) in [("libused", "used"), ("libunused", "unused")] {
        let tbd_path = dir.join(format!("{name}.tbd"));
        std::fs::write(&tbd_path, tbd(name, export)).unwrap();
        argv.push(tbd_path.as_os_str().to_os_string());
    }
    argv.extend(extra.iter().map(std::ffi::OsString::from));
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

    let dir = std::env::temp_dir().join(format!("pgr_dead_strip_dylibs_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The default: every input dylib rides its command (ld64's
    //    shape) and the image verifies strict like any other.
    let carried = link(&dir, "app_carried", &[]);
    let names = header_dylibs(&carried);
    assert_eq!(
        names,
        vec![
            "@rpath/libused.dylib".to_string(),
            "@rpath/libunused.dylib".to_string(),
        ],
        "the default carries every input dylib"
    );
    let report = verify(&carried, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the carried image verifies strict: {:?}",
        report.issues
    );

    // 2. The drop: the same corpus under `-dead_strip_dylibs` — the
    //    dylib nothing binds against leaves the header (the re-exports
    //    would ride: their REEXPORT nodes join the trie) and the image
    //    verifies strict.
    let dropped = link(&dir, "app_dropped", &["-dead_strip_dylibs"]);
    let names = header_dylibs(&dropped);
    assert_eq!(
        names,
        vec!["@rpath/libused.dylib".to_string()],
        "the unused dylib's command leaves the header"
    );
    let report = verify(&dropped, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the dropped image verifies strict: {:?}",
        report.issues
    );

    println!(
        "carried: {} LC_LOAD_DYLIB commands ({}), {} bytes of image",
        names_len(&carried),
        header_dylibs(&carried).join(", "),
        carried.len()
    );
    println!(
        "dropped: {} LC_LOAD_DYLIB commands ({}), {} bytes of image — \
         the kept list compacted the two-level ordinals onto itself",
        names_len(&dropped),
        header_dylibs(&dropped).join(", "),
        dropped.len()
    );
}

fn names_len(image: &[u8]) -> usize {
    header_dylibs(image).len()
}

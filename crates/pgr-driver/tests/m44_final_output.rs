//! M44 — `-final_output`: ld64's dylib-identity default ("Specifies
//! the install name of a dylib if `-install_name` is not used" — the `ld`
//! man page; the multi-arch driver names it so every arch slice records
//! the universal path, not its own `-o` path). On the surface the flag
//! supplies the default install name a dylib link derives when
//! `-install_name` is absent; an explicit `-install_name` wins (the
//! man-page rule), and the knob refuses where an install name has
//! nothing to ride (executables, bundles — the identity block is
//! `LC_MAIN`/dlopen — and the relocatable output, which carries no
//! identity commands at all). The default (flag absent) keeps every
//! pre-M44 link byte-identical: the derived install name stays the
//! `-o` path.
//!
//! Gate matrix:
//! * the default — a dylib without `-install_name` records its `-o`
//!   path (unchanged);
//! * the flag — `-final_output` supplies the recorded install name;
//! * the precedence — an explicit `-install_name` wins over the flag;
//! * the refusals — execute, bundle and relocatable outputs refuse
//!   with the identity-block help;
//! * the image — the flagged dylib verifies strict.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{DylibCommand, LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::PathBuf;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m44_final_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// lib.o: one exported definition over a RET body (the dylib's surface).
fn provider_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("lib.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn corpus(dir: &std::path::Path, tag: &str) -> Vec<PathBuf> {
    let obj = dir.join(format!("{tag}_lib.o"));
    std::fs::write(&obj, provider_object()).unwrap();
    vec![obj]
}

/// Links `inputs` (with `-dylib`) under `extra` argv; returns the image.
fn link(dir: &std::path::Path, out: &str, inputs: &[PathBuf], extra: &[&str]) -> Vec<u8> {
    let out_path = dir.join(out);
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string(), "-dylib".into()];
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

/// The `LC_ID_DYLIB` install name the image records.
fn id_install_name(image: &[u8]) -> String {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::IdDylib = cmd.kind {
            let dylib_cmd = DylibCommand::parse(cmd.bytes).expect("the dylib command parses");
            let name = dylib_cmd.name(cmd.bytes).expect("the install name reads");
            return String::from_utf8_lossy(name).into_owned();
        }
    }
    panic!("the dylib image carries LC_ID_DYLIB")
}

#[test]
fn m44_flag_shapes_the_default_install_name() {
    let dir = scratch("opts");
    let inputs = corpus(&dir, "opts");
    let base: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("libdylib.dylib").display().to_string(),
        "-dylib".to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .chain(inputs.iter().map(|p| p.as_os_str().to_os_string()))
    .collect();

    let o = pgr_driver::opts::parse(&base).expect("the argv parses");
    assert!(
        o.final_output.is_none(),
        "the default carries no final-output override"
    );

    let mut flagged = base.clone();
    flagged.push(std::ffi::OsString::from("-final_output"));
    flagged.push(std::ffi::OsString::from(
        "/usr/local/lib/libuniversal.dylib",
    ));
    let o = pgr_driver::opts::parse(&flagged).expect("the argv parses");
    assert_eq!(
        o.final_output.as_deref(),
        Some("/usr/local/lib/libuniversal.dylib"),
        "the flag names the identity default"
    );
}

#[test]
fn the_flag_supplies_the_recorded_install_name() {
    let dir = scratch("e2e");
    let inputs = corpus(&dir, "e2e");
    let default = link(&dir, "libdefault.dylib", &inputs, &[]);
    assert_eq!(
        id_install_name(&default),
        dir.join("libdefault.dylib").display().to_string(),
        "the default records the -o path (every pre-M44 link, unchanged)"
    );

    let flagged = link(
        &dir,
        "libflagged.dylib",
        &inputs,
        &["-final_output", "/usr/local/lib/libuniversal.dylib"],
    );
    assert_eq!(
        id_install_name(&flagged),
        "/usr/local/lib/libuniversal.dylib",
        "the flag supplies the recorded install name (the multi-arch \
         driver's universal path, not the slice's -o path)"
    );
    let report = verify(&flagged, &strict());
    assert!(
        report.is_ok(&strict()),
        "the flagged dylib verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_explicit_install_name_wins() {
    let dir = scratch("precedence");
    let inputs = corpus(&dir, "precedence");
    let image = link(
        &dir,
        "libboth.dylib",
        &inputs,
        &[
            "-final_output",
            "/usr/local/lib/libuniversal.dylib",
            "-install_name",
            "@rpath/libexplicit.dylib",
        ],
    );
    assert_eq!(
        id_install_name(&image),
        "@rpath/libexplicit.dylib",
        "an explicit -install_name wins over the flag (the man-page rule)"
    );
}

#[test]
fn the_identity_block_conflicts_refuse() {
    let dir = scratch("conflict");
    let inputs = corpus(&dir, "conflict");
    for (kind, flag) in [("", ""), ("-bundle", ""), ("-r", "")] {
        let _ = (kind, flag);
        let mut argv: Vec<std::ffi::OsString> = vec![
            std::ffi::OsString::from("-o"),
            dir.join("out").as_os_str().to_os_string(),
        ];
        if kind == "-bundle" {
            argv.push(std::ffi::OsString::from("-bundle"));
        }
        if kind == "-r" {
            argv.push(std::ffi::OsString::from("-r"));
        }
        argv.extend(inputs.iter().map(|p| p.as_os_str().to_os_string()));
        argv.push(std::ffi::OsString::from("-final_output"));
        argv.push(std::ffi::OsString::from(
            "/usr/local/lib/libuniversal.dylib",
        ));
        let err = pgr_driver::opts::parse(&argv)
            .expect_err("a non-dylib identity block refuses the flag");
        assert!(
            err.to_string().contains("-final_output"),
            "the refusal names the knob: {err}"
        );
        assert!(
            miette_help_renders(&err),
            "the refusal renders the fix help: {err}"
        );
    }
}

/// The miette diagnostic renders its help tail (the house convention:
/// the fix, not just the verdict).
fn miette_help_renders(err: &pgr_driver::opts::OptsError) -> bool {
    let rendered = format!("{:?}", miette::Report::new(err.clone()));
    rendered.contains("fix") || rendered.contains("drop") || rendered.contains("-dylib")
}

#[test]
fn the_usage_line_names_the_flag() {
    let usage = pgr_driver::usage();
    assert!(
        usage.contains("-final_output"),
        "the usage surface carries the flag: the flag is a decision, \
         not a hidden one"
    );
}

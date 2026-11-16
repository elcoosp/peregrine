//! M50 — the weak-import refusal, driver surface: the flag names the
//! decision on the CLI (`o.config.no_weak_imports`), an unresolvable
//! weak reference under the knob refuses with the symbol, the knob and
//! the fix named, the default ships the dyld lookup bind the flag
//! refuses, a link-time resolution plans identical bytes under both
//! decisions and verifies strict, and the usage line names the flag.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::PathBuf;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m50_weak_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// `weakref.o`: `_main` over two RET functions and an undefined
/// `name` — `weak` flips the reference's `N_WEAK_REF` bit.
fn weakref_object(name: &str, weak: bool, undef: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name);
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
    b.add_symbol(ObjectSymbol::Undefined {
        name: undef.into(),
        weak_ref: weak,
    });
    b.build().expect("the fixture object builds")
}

/// `provider.o`: defines `name` over one RET body.
fn provider_object(name: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new("provider.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: name.into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Writes the corpus files; returns the paths.
fn corpus(dir: &std::path::Path, tag: &str, resolved: bool) -> Vec<PathBuf> {
    let weakref = dir.join(format!("{tag}_weakref.o"));
    std::fs::write(&weakref, weakref_object("weakref.o", true, "_maybe"))
        .expect("the weakref object writes");
    let mut inputs = vec![weakref];
    if resolved {
        let provider = dir.join(format!("{tag}_provider.o"));
        std::fs::write(&provider, provider_object("_maybe")).expect("the provider writes");
        inputs.push(provider);
    }
    inputs
}

/// Links `inputs` under `extra` argv; `Ok(bytes)` on a built image,
/// `Err(message)` on a typed refusal.
fn link(
    dir: &std::path::Path,
    out: &str,
    inputs: &[PathBuf],
    extra: &[&str],
) -> Result<Vec<u8>, String> {
    let out_path = dir.join(out);
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string()];
    argv.extend(inputs.iter().map(|p| p.display().to_string()));
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    match pgr_driver::opts::parse(&argv) {
        Ok(o) => match pgr_driver::run(&o) {
            Ok(_outcome) => Ok(std::fs::read(&out_path).expect("the image reads")),
            Err(e) => Err(e.to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

#[test]
fn the_flag_shapes_the_config() {
    let dir = scratch("opts");
    let inputs = corpus(&dir, "opts", false);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join("app").as_os_str().to_os_string(),
    ];
    argv.extend(inputs.iter().map(|p| p.as_os_str().to_os_string()));
    argv.push(std::ffi::OsString::from("-no_weak_imports"));
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    assert!(
        o.config.no_weak_imports,
        "the flag names the refusal decision"
    );
    let default = pgr_driver::opts::parse(&argv[..2 + inputs.len()]).expect("the argv parses");
    assert!(
        !default.config.no_weak_imports,
        "the default keeps every pre-M50 runtime-lookup fallthrough"
    );
}

#[test]
fn the_unresolved_weak_import_refuses_with_the_fix() {
    let dir = scratch("refuse");
    let inputs = corpus(&dir, "refuse", false);
    // The default ships the dyld lookup bind (the pre-M50 shape).
    let image = link(&dir, "app_default", &inputs, &[]).expect("the default ships the lookup bind");
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the default image verifies strict: {:?}",
        report.issues
    );
    // The knob refuses the same link — the symbol, the knob and the fix
    // named (ld64's own refusal shape).
    let err = link(&dir, "app_refuse", &inputs, &["-no_weak_imports"])
        .expect_err("the runtime-lookup weak import refuses under the knob");
    assert!(
        err.contains("_maybe"),
        "the refusal names the symbol: {err}"
    );
    assert!(
        err.contains("-no_weak_imports"),
        "the refusal names the knob: {err}"
    );
}

#[test]
fn the_resolved_weak_bind_links_and_verifies_under_both() {
    let dir = scratch("resolved");
    let inputs = corpus(&dir, "resolved", true);
    let default = link(&dir, "app_default", &inputs, &[]).expect("the default links");
    let named = link(&dir, "app_named", &inputs, &["-no_weak_imports"])
        .expect("the link-time resolution never refuses");
    assert_eq!(
        default, named,
        "a link-time resolution plans identical bytes under both decisions"
    );
    let report = verify(&named, &strict());
    assert!(
        report.is_ok(&strict()),
        "the resolved image verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_usage_line_names_the_flag() {
    let usage = pgr_driver::usage();
    assert!(
        usage.contains("-no_weak_imports"),
        "the usage text names the weak-import refusal"
    );
}

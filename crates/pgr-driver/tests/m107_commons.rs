//! M107 — the `-commons <policy>` driver surface: ld64's common-symbol
//! treatment (the other half of the `N_UNDF | N_EXT` contract). The
//! typed alphabet parses (the four words; an unknown value refuses with
//! the alphabet in the hint), the `search_dylibs` face resolves the
//! end-to-end image against a `.tbd` dylib (the bind rides the dylib's
//! two-level ordinal, no `__common` definition lands), the relocatable
//! output refuses the non-default policies, and the image verifies
//! strict.

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m107_commons").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn args(items: &[&str]) -> Vec<OsString> {
    items.iter().map(|s| OsString::from(*s)).collect()
}

/// hello.o: `_main` references `_conflicted` (the tentative the policy
/// decides about) and defines `_main`.
fn common_object(dir: &Path) -> PathBuf {
    let mut b = ObjectBuilder::new("hello.o");
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
    b.add_symbol(ObjectSymbol::Common {
        name: "_conflicted".into(),
        size: 32,
        align_log2: 3,
    });
    let undef = b.add_symbol(ObjectSymbol::Undefined {
        name: "_conflicted".into(),
        weak_ref: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let slot = b.sym_index(undef);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    let path = dir.join("hello.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// A `libconflict.tbd` stub exporting `_conflicted`.
fn conflict_tbd(dir: &Path) -> PathBuf {
    let tbd = dir.join("libconflict.tbd");
    std::fs::write(
        &tbd,
        "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: @rpath/libconflict.tbd\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _conflicted ]\n...\n",
    )
    .unwrap();
    tbd
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

#[test]
fn the_alphabet_parses_and_the_unknown_value_refuses() {
    let dir = scratch("parse");
    let obj = common_object(&dir);
    let obj = obj.display().to_string();
    for word in ["use_dylibs", "search_dylibs", "use_extern", "error"] {
        let argv = args(&[
            "-commons",
            word,
            "-o",
            &dir.join("x").display().to_string(),
            &obj,
        ]);
        let o = opts::parse(&argv).expect("the alphabet parses");
        let want = match word {
            "use_dylibs" => pgr_core::resolve::CommonsPolicy::UseDylibs,
            "search_dylibs" => pgr_core::resolve::CommonsPolicy::SearchDylibs,
            "use_extern" => pgr_core::resolve::CommonsPolicy::UseExtern,
            _ => pgr_core::resolve::CommonsPolicy::Error,
        };
        assert_eq!(o.config.commons, want, "{word} carries its face");
    }
    let argv = args(&[
        "-commons",
        "ignore_dylibs",
        "-o",
        &dir.join("x").display().to_string(),
        &obj,
    ]);
    let err = opts::parse(&argv).expect_err("the unknown value refuses");
    assert!(
        err.to_string().contains("use_dylibs"),
        "the hint names the alphabet: {err}"
    );
}

#[test]
fn search_dylibs_resolves_the_end_to_end_image_against_the_dylib() {
    let dir = scratch("e2e");
    let obj = common_object(&dir);
    let _tbd = conflict_tbd(&dir);
    let argv = args(&[
        "-o",
        &dir.join("hello").display().to_string(),
        "-commons",
        "search_dylibs",
        "-L",
        &dir.display().to_string(),
        "-l",
        "conflict",
        &obj.display().to_string(),
    ]);
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(dir.join("hello")).unwrap();
    // The bind rides the dylib: LC_LOAD_DYLIB carries the stub's install
    // name (the definition the policy used to replace the tentative).
    let header = pgr_format::MachHeader64::parse(&image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        &image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut names = Vec::new();
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind == pgr_format::LoadCommandKind::LoadDylib {
            let d = pgr_format::DylibCommand::parse(cmd.bytes).expect("the command parses");
            let name = d.name(cmd.bytes).expect("the install name reads");
            names.push(
                String::from_utf8_lossy(name)
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
    }
    assert_eq!(
        names,
        vec!["@rpath/libconflict.tbd".to_string()],
        "the dylib's definition replaced the tentative — its command rides"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the search_dylibs image verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_error_policy_refuses_the_conflict_and_r_refuses_the_knob() {
    let dir = scratch("faces");
    let obj = common_object(&dir);
    let _tbd = conflict_tbd(&dir);
    // The error face: the conflict refuses with the symbol named.
    let argv = args(&[
        "-o",
        &dir.join("hello").display().to_string(),
        "-commons",
        "error",
        "-L",
        &dir.display().to_string(),
        "-l",
        "conflict",
        &obj.display().to_string(),
    ]);
    let o = opts::parse(&argv).expect("the argv parses");
    let err = pgr_driver::run(&o).expect_err("the conflict refuses");
    assert!(
        err.to_string().contains("_conflicted"),
        "the refusal names the symbol: {err}"
    );
    // The relocatable output refuses the non-default policies (the
    // object's symtab is the input's, verbatim).
    for word in ["search_dylibs", "use_extern", "error"] {
        let argv = args(&[
            "-o",
            &dir.join("hello.o.out").display().to_string(),
            "-r",
            "-commons",
            word,
            &obj.display().to_string(),
        ]);
        let err = opts::parse(&argv).expect_err("the relocatable output refuses");
        assert!(
            err.to_string().contains("-commons"),
            "the refusal names the knob: {err}"
        );
    }
    // The default rides the relocatable output (the pre-M107 shape).
    let argv = args(&[
        "-o",
        &dir.join("hello.o.out").display().to_string(),
        "-r",
        "-commons",
        "use_dylibs",
        &obj.display().to_string(),
    ]);
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the default rides the relocatable output");
}

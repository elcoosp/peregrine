//! M103 — the `-undefined warning` / `-undefined suppress` driver
//! surface: the policies parse onto the core decision, the relocatable
//! output refuses them (an object has no load-time bind to warn or
//! suppress), and the exit policy is the e2e contract — the default
//! `-undefined error` still refuses, `dynamic_lookup` stays the silent
//! intended shape, `warning` prints the unresolved list and exits 0,
//! `suppress` prints nothing and exits 0. The spawn gates run the real
//! binary (the exit face is stderr + exit code — the driver library
//! cannot assert its own stderr).

use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m103_undef_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A `_main` object whose `__text` also references `_hole` through a
/// GOT-form pointer pair — the reference no input resolves, the
/// policy's subject.
fn hole_object(dir: &Path) -> PathBuf {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(8),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let hole = b.add_symbol(ObjectSymbol::Undefined {
        name: "_hole".into(),
        weak_ref: false,
    });
    b.section_mut(text)
        .relocs
        .push(ObjectReloc::got_page21(hole as u32).at(4));
    b.section_mut(text)
        .relocs
        .push(ObjectReloc::got_pageoff12(hole as u32).at(8));
    let path = dir.join("main.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// Runs the real `pgr` binary over the argv; returns the exit code and
/// the stderr text.
fn spawn_pgr(argv: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_pgr"))
        .args(argv)
        .output()
        .expect("the pgr binary spawns");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn parse(extra: &[&str]) -> Result<pgr_driver::opts::Options, pgr_driver::opts::OptsError> {
    let argv: Vec<std::ffi::OsString> = extra.iter().map(std::ffi::OsString::from).collect();
    pgr_driver::opts::parse(&argv)
}

// ---- the surface ---------------------------------------------------------------

#[test]
fn the_policies_parse_onto_the_decision() {
    for (value, expected) in [
        ("warning", pgr_core::resolve::UndefinedPolicy::Warning),
        ("suppress", pgr_core::resolve::UndefinedPolicy::Suppress),
        (
            "dynamic_lookup",
            pgr_core::resolve::UndefinedPolicy::DynamicLookup,
        ),
        ("error", pgr_core::resolve::UndefinedPolicy::Error),
    ] {
        let o = parse(&["-o", "out", "-undefined", value, "main.o"]).expect("the argv parses");
        assert_eq!(
            o.config.undefined_policy, expected,
            "the {value} face rides the config"
        );
    }
}

#[test]
fn an_unknown_policy_value_names_the_alphabet() {
    let err = parse(&["-o", "out", "-undefined", "wat", "main.o"])
        .expect_err("the typo refuses at the parse");
    let report = miette::Report::new(err);
    let text = format!("{report:?}");
    assert!(
        text.contains("warning") && text.contains("suppress"),
        "the refusal names the widened alphabet: {text}"
    );
}

#[test]
fn the_relocatable_output_refuses_the_policies() {
    for value in ["warning", "suppress"] {
        let err = parse(&["-o", "out.o", "-r", "-undefined", value, "main.o"])
            .expect_err("the -r surface refuses the policies");
        let report = miette::Report::new(err);
        let text = format!("{report:?}");
        assert!(
            text.contains("load-time bind"),
            "the refusal names the missing bind ({value}): {text}"
        );
    }
}

#[test]
fn the_flat_namespace_host_validates_the_new_policies() {
    // The retired-conflict surface: the flat namespace is a valid host
    // for warning/suppress — the escalation was the conflict, never the
    // namespace (M2's `-flat_namespace` × `-undefined error` refusal
    // never rode this tree; the policies compose with the flat binds).
    for (value, expected) in [
        ("warning", pgr_core::resolve::UndefinedPolicy::Warning),
        ("suppress", pgr_core::resolve::UndefinedPolicy::Suppress),
    ] {
        let o = parse(&[
            "-o",
            "out",
            "-flat_namespace",
            "-undefined",
            value,
            "main.o",
        ])
        .expect("the flat namespace hosts the policy");
        assert_eq!(
            o.config.undefined_policy, expected,
            "the {value} policy rides beside the flat namespace"
        );
    }
}

// ---- the exit policy (the real binary) ------------------------------------------

#[test]
fn the_error_policy_still_refuses_end_to_end() {
    let dir = scratch("error");
    let obj = hole_object(&dir);
    let out = dir.join("app").display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, obj.display().to_string().as_str()]);
    assert_ne!(code, Some(0), "the default policy refuses");
    assert!(
        stderr.contains("undefined symbol") && stderr.contains("_hole"),
        "the refusal names the hole: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_warning_policy_prints_and_exits_zero() {
    let dir = scratch("warning");
    let obj = hole_object(&dir);
    let out = dir.join("app").display().to_string();
    let obj_str = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, "-undefined", "warning", &obj_str]);
    assert_eq!(code, Some(0), "the warning face exits 0");
    assert!(
        stderr.contains("pgr: warning: undefined symbol") && stderr.contains("_hole"),
        "the warning face names the hole: {stderr}"
    );
    assert!(
        std::path::Path::new(&out).exists(),
        "the image ships despite the warnings"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_suppress_policy_prints_nothing_and_exits_zero() {
    let dir = scratch("suppress");
    let obj = hole_object(&dir);
    let out = dir.join("app").display().to_string();
    let obj_str = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, "-undefined", "suppress", &obj_str]);
    assert_eq!(code, Some(0), "the suppress face exits 0");
    assert!(
        !stderr.contains("undefined symbol"),
        "the suppress face prints nothing: {stderr:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_non_escalating_policies_plan_identical_images() {
    // The policy is the exit's, never the image's: warning, suppress
    // and dynamic_lookup plan byte-identical outputs over the same
    // corpus (the flat-lookup bind words ride whatever the exit prints).
    let dir = scratch("parity");
    let obj = hole_object(&dir);
    let obj_str = obj.display().to_string();
    let mut images = Vec::new();
    for (name, value) in [
        ("lookup", "dynamic_lookup"),
        ("warn", "warning"),
        ("suppress", "suppress"),
    ] {
        let out = dir.join(name).display().to_string();
        let (code, _) = spawn_pgr(&["-o", &out, "-undefined", value, &obj_str]);
        assert_eq!(code, Some(0), "the {value} face links");
        images.push(std::fs::read(&out).expect("the image reads"));
    }
    assert_eq!(
        images[0], images[1],
        "warning plans the dynamic_lookup bytes"
    );
    assert_eq!(images[1], images[2], "suppress plans the warning bytes");
    let _ = std::fs::remove_dir_all(&dir);
}

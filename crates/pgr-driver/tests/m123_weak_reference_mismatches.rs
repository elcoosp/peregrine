//! M123 — the `-weak_reference_mismatches` driver surface: the flag
//! parses onto the core decision, refuses on `-r` (the object's
//! references ride untouched), and the advisory face records the
//! mismatch end-to-end (the resolution policy itself unchanged).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m123_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

fn ref_object(file: &str, weak: bool, is_main: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new(file);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: if is_main {
            "_main".into()
        } else {
            format!("_{}_fn", file.trim_end_matches(".o"))
        },
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_sym".into(),
        weak_ref: weak,
    });
    b.build().expect("the fixture object builds")
}

fn provider_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("provider.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_sym".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn parse(extra: &[&str]) -> Result<pgr_driver::opts::Options, pgr_driver::opts::OptsError> {
    let argv: Vec<std::ffi::OsString> = extra.iter().map(std::ffi::OsString::from).collect();
    pgr_driver::opts::parse(&argv)
}

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let objs = [
        dir.join("weakref.o"),
        dir.join("strongref.o"),
        dir.join("provider.o"),
    ];
    std::fs::write(&objs[0], ref_object("weakref.o", true, true)).unwrap();
    std::fs::write(&objs[1], ref_object("strongref.o", false, false)).unwrap();
    std::fs::write(&objs[2], provider_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string()];
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).unwrap()
}

#[test]
fn the_flag_names_the_decision() {
    for (word, expected) in [
        (
            "error",
            pgr_core::resolve::WeakReferenceMismatchesPolicy::Error,
        ),
        (
            "weak",
            pgr_core::resolve::WeakReferenceMismatchesPolicy::Weak,
        ),
        (
            "non-weak",
            pgr_core::resolve::WeakReferenceMismatchesPolicy::NonWeak,
        ),
    ] {
        let o = parse(&["-o", "out", "-weak_reference_mismatches", word, "a.o"]).expect("parses");
        assert_eq!(
            o.config.weak_reference_mismatches, expected,
            "the {word} face rides the config"
        );
    }
}

#[test]
fn the_invalid_value_names_the_alphabet() {
    let err =
        parse(&["-o", "out", "-weak_reference_mismatches", "bogus", "a.o"]).expect_err("refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("error | weak | non-weak"),
        "the refusal names the alphabet: {msg}"
    );
}

#[test]
fn the_relocatable_conflict_names_the_shape() {
    let err = parse(&[
        "-o",
        "out",
        "-r",
        "-weak_reference_mismatches",
        "weak",
        "a.o",
    ])
    .expect_err("refuses");
    let report = miette::Report::new(err);
    assert!(
        format!("{report:?}").contains("relocatable"),
        "the refusal names the relocatable shape: {report:?}"
    );
}

#[test]
fn the_error_face_refuses_a_mix_end_to_end() {
    let dir = scratch("error");
    let argv = ["-weak_reference_mismatches", "error"];
    let out = dir.join("hello");
    let objs = [
        dir.join("weakref.o"),
        dir.join("strongref.o"),
        dir.join("provider.o"),
    ];
    std::fs::write(&objs[0], ref_object("weakref.o", true, true)).unwrap();
    std::fs::write(&objs[1], ref_object("strongref.o", false, false)).unwrap();
    std::fs::write(&objs[2], provider_object()).unwrap();
    let mut a: Vec<String> = vec!["-o".into(), out.display().to_string()];
    a.extend(argv.iter().map(std::string::ToString::to_string));
    for o in &objs {
        a.push(o.display().to_string());
    }
    let argv: Vec<std::ffi::OsString> = a.iter().map(std::ffi::OsString::from).collect();
    let err = pgr_driver::run(&pgr_driver::opts::parse(&argv).expect("parses"))
        .expect_err("the mix refuses");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        err.to_string().contains("weakly") && err.to_string().contains("strongly"),
        "the refusal names the mix: {err}"
    );
}

#[test]
fn the_weak_face_links_end_to_end() {
    let dir = scratch("weak");
    let img = link(&dir, "hello", &["-weak_reference_mismatches", "weak"]);
    assert!(!img.is_empty(), "the advisory face emits the image");
    let _ = std::fs::remove_dir_all(&dir);
}

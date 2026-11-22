//! The weak-reference-mismatches consumer example (M123): a corpus
//! whose references mix weak and strong against the same name, linked
//! under the `weak` advisory face (the mismatch recorded, exit 0 — the
//! bytes never move), and the `-r` refusal rendered as miette help text
//! (the M111 refusal shape, mirrored exactly — the fix, not just the
//! verdict).
//!
//! Run: `cargo run -p pgr-driver --example weak_reference_mismatches_link`

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

fn ref_object(file: &str, weak: bool, is_main: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new(file);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        Vec::new(),
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
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_sym".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn main() {
    let dir = std::env::temp_dir().join(format!("pgr_wrm_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let weakref = dir.join("weakref.o");
    let strongref = dir.join("strongref.o");
    let provider = dir.join("provider.o");
    std::fs::write(&weakref, ref_object("weakref.o", true, true)).unwrap();
    std::fs::write(&strongref, ref_object("strongref.o", false, false)).unwrap();
    std::fs::write(&provider, provider_object()).unwrap();
    let out = dir.join("hello");

    // 1. The advisory face: `-weak_reference_mismatches weak` records the
    //    mismatch, the resolution policy itself unchanged, exit 0.
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        out.display().to_string(),
        "-weak_reference_mismatches".to_string(),
        "weak".to_string(),
        weakref.display().to_string(),
        strongref.display().to_string(),
        provider.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the advisory face links");
    println!("weak face: the mismatch recorded, the link exits 0");

    // 2. The default error face refuses the same mix.
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        out.display().to_string(),
        "-weak_reference_mismatches".to_string(),
        "error".to_string(),
        weakref.display().to_string(),
        strongref.display().to_string(),
        provider.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match pgr_driver::run(&opts::parse(&argv).expect("parses")) {
        Ok(_) => unreachable!("the error face refuses the mix"),
        Err(err) => eprintln!("\nthe refusal (verdict + fix):\n{}", err),
    }

    // 3. The -r refusal: the non-default face refuses on the
    //    relocatable output (the M111 refusal shape, mirrored exactly).
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        out.display().to_string(),
        "-r".to_string(),
        "-weak_reference_mismatches".to_string(),
        "weak".to_string(),
        weakref.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the -r conflict refuses"),
        Err(err) => {
            eprintln!("\nthe -r refusal (verdict + fix):");
            eprintln!("{:?}", miette::Report::new(err));
        }
    }

    println!("\nweak_reference_mismatches_link: ok");
}

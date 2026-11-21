//! The multiply-defined consumer example (`warning`) (M108): ld64's
//! `-multiply_defined warning` — the advisory face: the first definition
//! wins, the collision prints as a warning, the link still exits 0 (the
//! M103 advisory-face shape one policy over), the image verified strict
//! and the winner's bytes read back (the house consumer-example
//! convention).
//!
//! Run: `cargo run -p pgr-driver --example multiply_defined_warning_link`

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;

fn definer(name: &str, with_main: bool, fill: u8) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    if with_main {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
    }
    let data = b.add_section(ObjectSection::data("__data", vec![fill; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_dup".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_multiply_warning_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = dir.join("a.o");
    std::fs::write(&a, definer("a.o", true, 0xAA)).unwrap();
    let b = dir.join("b.o");
    std::fs::write(&b, definer("b.o", false, 0xBB)).unwrap();
    let objs = [a.display().to_string(), b.display().to_string()];

    let mut argv: Vec<String> = vec![
        "-o".into(),
        dir.join("hello").display().to_string(),
        "-multiply_defined".into(),
        "warning".into(),
    ];
    argv.extend(objs.iter().cloned());
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the warning face links (exit 0; the collision printed)");
    let image = std::fs::read(dir.join("hello")).expect("the image reads");
    assert!(
        image.windows(8).any(|w| w == [0xAA; 8]) && !image.windows(8).any(|w| w == [0xBB; 8]),
        "the first object's definition wins the tie"
    );
    let strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    assert!(
        verify(&image, &strict).is_ok(&strict),
        "the image verifies strict"
    );

    println!("\nmultiply_defined_warning_link: ok");
}

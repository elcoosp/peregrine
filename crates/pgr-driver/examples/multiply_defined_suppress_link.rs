//! The multiply-defined consumer example (`suppress`) (M108): ld64's
//! `-multiply_defined suppress` — the silent face: the same first-wins
//! product the warning face plans (the walk derives the collision, the
//! exit prints none of it), byte-identical to the warning face's image
//! over the same corpus (the M103 parity shape one policy over — the
//! house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example multiply_defined_suppress_link`

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::path::PathBuf;

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

fn link(dir: &std::path::Path, out: &str, face: &str, objs: &[PathBuf]) -> Vec<u8> {
    let mut argv: Vec<String> = vec!["-o".into(), dir.join(out).display().to_string()];
    argv.extend(["-multiply_defined".into(), face.into()]);
    argv.extend(objs.iter().map(|p| p.display().to_string()));
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the face links");
    std::fs::read(dir.join(out)).expect("the image reads")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_multiply_suppress_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = dir.join("a.o");
    std::fs::write(&a, definer("a.o", true, 0xAA)).unwrap();
    let b = dir.join("b.o");
    std::fs::write(&b, definer("b.o", false, 0xBB)).unwrap();

    // The silent face beside the advisory face: the same first-wins
    // product, byte for byte.
    let warned = link(&dir, "hello_warn", "warning", &[a.clone(), b.clone()]);
    let silent = link(&dir, "hello_quiet", "suppress", &[a, b]);
    assert_eq!(
        warned, silent,
        "suppress plans the warning bytes (the same first-wins product)"
    );
    let strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    assert!(
        verify(&silent, &strict).is_ok(&strict),
        "the image verifies strict"
    );

    println!("\nmultiply_defined_suppress_link: ok");
}

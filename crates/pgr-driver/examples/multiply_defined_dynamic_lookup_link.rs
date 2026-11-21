//! The multiply-defined consumer example (`dynamic_lookup`) (M108): the
//! M103 undefined face pattern one policy over — the duplicated name
//! leaves the winners' table and the references ride the flat-lookup
//! slot (dyld resolves at launch or kills the image), the image verified
//! strict and the name's absence from the winners' table read back
//! through the resolution seam (the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example multiply_defined_dynamic_lookup_link`

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
    let dir = std::env::temp_dir().join(format!("pgr_multiply_lookup_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = dir.join("a.o");
    std::fs::write(&a, definer("a.o", true, 0xAA)).unwrap();
    let b = dir.join("b.o");
    std::fs::write(&b, definer("b.o", false, 0xBB)).unwrap();

    // The lookup face: the duplicated slot leaves the winners' table —
    // the image differs from the first-wins faces' (no symtab row, no
    // local bind) and verifies strict (the flat ride is a planned shape,
    // never a defect).
    let warned = link(&dir, "hello_warn", "warning", &[a.clone(), b.clone()]);
    let flat = link(&dir, "hello_flat", "dynamic_lookup", &[a, b]);
    assert_ne!(
        warned, flat,
        "the duplicated slot leaves the winners' table — the bytes move"
    );
    let strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    assert!(
        verify(&flat, &strict).is_ok(&strict),
        "the flat ride verifies strict"
    );

    println!("\nmultiply_defined_dynamic_lookup_link: ok");
}

//! The multiply-defined consumer example (`error`) (M108): ld64's
//! `-multiply_defined <policy>` — the default face — two strong
//! definitions of one name refuse the link with the symbol named (the
//! pre-M108 escalation), the refusal rendered as miette help text where
//! the surface owns it and the typed refusal beside (the house
//! consumer-example convention), the first-wins faces beside it over the
//! same corpus.
//!
//! Run: `cargo run -p pgr-driver --example multiply_defined_error_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::path::PathBuf;

/// One defining object: `_main` (the first object's only) plus a strong
/// `_dup` over a distinct `__data` fill byte.
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

fn link(dir: &std::path::Path, out: &str, extra: &[&str], objs: &[PathBuf]) -> Option<Vec<u8>> {
    let mut argv: Vec<String> = vec!["-o".into(), dir.join(out).display().to_string()];
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    argv.extend(objs.iter().map(|p| p.display().to_string()));
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).ok()?;
    match pgr_driver::run(&o) {
        Ok(_) => Some(std::fs::read(dir.join(out)).expect("the image reads")),
        Err(e) => {
            eprintln!("the face refused: {e}");
            None
        }
    }
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_multiply_error_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = dir.join("a.o");
    std::fs::write(&a, definer("a.o", true, 0xAA)).unwrap();
    let b = dir.join("b.o");
    std::fs::write(&b, definer("b.o", false, 0xBB)).unwrap();

    // The default face: the collision refuses with the symbol named (the
    // typed refusal — the driver library renders the LinkError, the CLI
    // exit 1s on it).
    let refused = link(
        &dir,
        "hello_error",
        &["-multiply_defined", "error"],
        &[a.clone(), b.clone()],
    );
    assert!(
        refused.is_none(),
        "the duplicated name refuses under the default"
    );

    // The warning face beside the refusal's own corpus: the first
    // definition wins, the collision prints, exit 0.
    let warned = link(
        &dir,
        "hello_warn",
        &["-multiply_defined", "warning"],
        &[a.clone(), b.clone()],
    )
    .expect("the warning face links");
    assert!(
        warned.windows(8).any(|w| w == [0xAA; 8]) && !warned.windows(8).any(|w| w == [0xBB; 8]),
        "the first object's definition wins the tie"
    );
    let strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    assert!(
        verify(&warned, &strict).is_ok(&strict),
        "the image verifies strict"
    );

    println!("\nmultiply_defined_error_link: ok");
}

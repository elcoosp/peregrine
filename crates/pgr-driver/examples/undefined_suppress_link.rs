//! The undefined-suppress consumer example (M103): the same `main.o`
//! that references `_hole` — a symbol nothing resolves — linked under
//! `-undefined suppress`: the link succeeds, exits 0, and nothing
//! prints (ld64's most dangerous face — the holes ride to load time
//! unannounced at link time). The example walks the silence beside the
//! warning face's honesty and the relocatable refusal (an object has
//! no load-time bind to warn or suppress).
//!
//! Run: `cargo run -p pgr-driver --example undefined_suppress_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// main.o: `_main` over a small `__text`, plus one GOT-form reference
/// to `_hole` — the reference nothing resolves, the policy's subject.
fn hole_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(8),
        Vec::new(),
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
    b.build().expect("the fixture object builds")
}

fn run(dir: &std::path::Path, out: &str, extra: &[&str]) -> Result<Vec<u8>, String> {
    let obj = dir.join("main.o");
    std::fs::write(&obj, hole_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    let o = opts::parse(&argv).map_err(|e| e.to_string())?;
    match pgr_driver::run(&o) {
        Ok(_) => Ok(std::fs::read(&out_path).expect("the image reads")),
        Err(e) => Err(e.to_string()),
    }
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_undef_suppress_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // 1. The suppress face: `-undefined suppress` links, exits 0, and
    //    nothing prints — the image ships with the hole riding dyld's
    //    flat lookup (the stderr above this line stays silent; the
    //    warning face's example shows the honest variant).
    let suppress =
        run(&dir, "app_suppress", &["-undefined", "suppress"]).expect("the suppress face links");
    println!("`-undefined suppress`: the link exits 0, nothing prints");

    // 2. The image: the same bytes the warning face and
    //    `dynamic_lookup` plan — the policy is the exit's, never the
    //    image's.
    let lookup = run(&dir, "app_lookup", &["-undefined", "dynamic_lookup"])
        .expect("the dynamic_lookup face links");
    assert_eq!(
        suppress, lookup,
        "the suppress face plans the dynamic_lookup bytes"
    );

    // 3. The refusal: the relocatable output refuses the policies — an
    //    object has no load-time bind to warn or suppress (the
    //    miette-rendered parse refusal, the fix named).
    let obj = dir.join("main.o");
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("main_r.o").display().to_string(),
        "-r".to_string(),
        "-undefined".to_string(),
        "suppress".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the relocatable conflict refuses"),
        Err(err) => {
            eprintln!("\nthe refusal (verdict + fix):");
            eprintln!("{:?}", miette::Report::new(err));
        }
    }

    println!("\nundefined_suppress_link: ok");
}

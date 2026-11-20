//! The undefined-warning consumer example (M103): a `main.o` that
//! references `_hole` — a symbol nothing resolves — linked under the
//! default `-undefined error` (the refusal, the fix rendered), then
//! under `-undefined warning`: the link succeeds, exits 0, and the
//! unresolved list prints as warnings (ld64's advisory face — the
//! build sees the holes, the product ships), the image verified strict
//! like the default one's shape (the flat-lookup bind rides exactly
//! what `dynamic_lookup` always encoded).
//!
//! Run: `cargo run -p pgr-driver --example undefined_warning_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

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

    let dir = std::env::temp_dir().join(format!("pgr_undef_warning_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // 1. The default: `-undefined error` refuses the hole (the
    //    escalation, the fix in the message).
    let refused = run(&dir, "app_error", &[]);
    assert!(
        refused.is_err() && refused.err().unwrap_or_default().contains("_hole"),
        "the default policy escalates"
    );
    println!("default `-undefined error`: the link refuses, naming \"_hole\"");

    // 2. The advisory face: `-undefined warning` links, exits 0, and
    //    the unresolved list prints as warnings (the stderr above this
    //    line carries the `pgr: warning:` rows).
    let image =
        run(&dir, "app_warning", &["-undefined", "warning"]).expect("the warning face links");
    println!("`-undefined warning`: the link exits 0, the hole prints as a warning");

    // 3. The image: the flat-lookup bind rides exactly the shape
    //    `dynamic_lookup` plans — the policy is the exit's, never the
    //    image's — and the strict verifier reads the decision (the
    //    verifier gates the shape it can break, never the exit face).
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let lookup = run(&dir, "app_lookup", &["-undefined", "dynamic_lookup"])
        .expect("the dynamic_lookup face links");
    assert_eq!(
        image, lookup,
        "the warning face plans the dynamic_lookup bytes"
    );
    let report = verify(&image, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the warned image verifies strict: {:?}",
        report.issues
    );

    println!("\nundefined_warning_link: ok");
}

//! The dead-strip init/term-roots consumer example (M52): the same
//! corpus linked under `-dead_strip` plain (the pre-M52 shape — an
//! unreferenced terminator strips) and with
//! `-no_dead_strip_inits_and_terms` (the terminator rides) — the symtab
//! read back from both images, the strict verifier on both, and the
//! inert-shape check (off the strip the bytes do not move).
//!
//! Run: `cargo run -p pgr-driver --example no_dead_strip_inits_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// main.o: `_main` over a small `__text`.
fn main_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xD65F_03C0u32.to_le_bytes()].concat(),
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// routines.o: an unreferenced initializer and terminator, each with
/// its pointer-section slot.
fn routines_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("routines.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        Vec::new(),
    ));
    let init_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_init_fn".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let term_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_term_fn".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    let modinit = b.add_section(ObjectSection::data(
        "__mod_init_func",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(init_sym as u32).at(0)],
    ));
    b.section_mut(modinit).flags = pgr_format::consts::S_MOD_INIT_FUNC_POINTERS;
    let modterm = b.add_section(ObjectSection::data(
        "__mod_term_func",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(term_sym as u32).at(0)],
    ));
    b.section_mut(modterm).flags = pgr_format::consts::S_MOD_TERM_FUNC_POINTERS;
    b.build().expect("the fixture object builds")
}

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let main = dir.join("main.o");
    let routines = dir.join("routines.o");
    std::fs::write(&main, main_object()).unwrap();
    std::fs::write(&routines, routines_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        main.as_os_str().to_os_string(),
        routines.as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).expect("the image reads")
}

fn contains(image: &[u8], needle: &[u8]) -> bool {
    image.windows(needle.len()).any(|w| w == needle)
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_dead_strip_inits_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The pre-M52 shape: `-dead_strip` drops the unreferenced
    //    terminator and keeps the initializer (the M5 root).
    let plain = link(&dir, "hello_plain", &["-dead_strip"]);
    assert!(
        !contains(&plain, b"_term_fn"),
        "the unreferenced terminator strips"
    );
    assert!(
        contains(&plain, b"_init_fn"),
        "the initializer survives (the M5 root)"
    );
    let report = verify(&plain, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the term-strip default verifies strict"
    );

    // 2. The decision: `-no_dead_strip_inits_and_terms` roots the
    //    termination-pointer sections — the terminator rides — and the
    //    image verifies strict like the default one.
    let knobbed = link(
        &dir,
        "hello_rooted",
        &["-dead_strip", "-no_dead_strip_inits_and_terms"],
    );
    println!(
        "bytes: default {}, no_dead_strip_inits_and_terms {}",
        plain.len(),
        knobbed.len()
    );
    assert!(
        contains(&knobbed, b"_term_fn"),
        "the termination routine never strips under the knob"
    );
    let report = verify(&knobbed, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the rooted shape verifies strict like the default one"
    );

    // 3. The inert shape: off the strip the decision never fires — the
    //    bytes do not move.
    let inert = link(&dir, "hello_inert", &["-no_dead_strip_inits_and_terms"]);
    let plain_no_knob = link(&dir, "hello_bare", &[]);
    assert_eq!(
        inert, plain_no_knob,
        "off the strip the decision never fires"
    );

    println!("\nno_dead_strip_inits_link: ok");
}

//! The incremental ladder's provenance consumer example (M84): the
//! capture link records the state, one function's body changes, and the
//! relink answers the provenance questions from its own walk —
//! `-why_export` renders the definition and the reference sites the
//! relink's Pass-2 product carries, `-why_load` names the pulled member
//! the relink's own pull rode. The vacuous query (a misspelled name) is
//! rendered as the refusal it is — miette help text included, the fix
//! and not just the verdict (the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example incremental_provenance`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// `main.o`: `_main` over 16 KiB of `__text` (the tier-1 edit shape —
/// same-size edits patch a minority of the tiles), one 8-byte data
/// pointer at `__data` targeting `_greet` (the archive member's export).
/// The `flip` variant rewrites eight words mid-text: the edit the
/// relink patches.
fn main_object(flip: bool) -> Vec<u8> {
    let mut text = vec![0xD5u8, 0x03, 0x20, 0x1F]; // nop
    text.resize(16 * 1024, 0xD5);
    if flip {
        let base = 8 * 1024 + 16;
        for i in 0..8 {
            text[base + i * 4] = 0xAA;
        }
    }
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text_sect = b.add_section(ObjectSection::text("__text", text, vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text_sect,
        value: 0,
        weak: false,
    });
    let greet = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(greet as u32).at(0)],
    ));
    b.build().expect("the fixture object builds")
}

/// `greet.o`: `_greet` over a small `__text` — the archive member the
/// S7 pull rides in.
fn greet_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Links `argv` (the corpus paths appended) through the driver's own
/// parse + run pair; errors render as the refusal they are.
fn run(
    dir: &std::path::Path,
    out: &str,
    extra: &[&str],
) -> Result<pgr_driver::LinkOutcome, String> {
    let main = dir.join("main.o");
    let archive = dir.join("libgreet.a");
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join(out).as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    argv.push(main.as_os_str().to_os_string());
    argv.push(archive.as_os_str().to_os_string());
    let parsed = opts::parse(&argv).map_err(|e| format!("{:?}", miette::Report::new(e)))?;
    pgr_driver::run(&parsed).map_err(|e| e.to_string())
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_ladder_prov_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("main.o"), main_object(false)).unwrap();
    let mut archive = ArchiveBuilder::new("libgreet.a");
    archive.add_member("greet.o", greet_object());
    std::fs::write(dir.join("libgreet.a"), archive.build()).unwrap();

    // 1. The capture link: the ladder's first rung records the state
    //    beside the output (`<output>.pgr-inc`) — no queries, the plain
    //    recorded full link the relink patches from.
    println!("== the capture link (the record sidecar is written) ==");
    run(&dir, "hello", &["-incremental"]).expect("the capture link runs");

    // 2. The edit: the same object, eight words flipped mid-text — the
    //    tier-1 edit the anchored relink patches in place.
    std::fs::write(dir.join("main.o"), main_object(true)).unwrap();

    // 3. The queried relink: the ladder's own walk IS the Pass-2 product
    //    — the answers serve from it either tier, exactly the faces the
    //    one-shot prints. The patch report rides the outcome; the
    //    `-why_export` answer names `_greet`'s definition (the pulled
    //    member) and the reference site main.o carries; `-why_load`
    //    names the member the relink's own pull rode.
    println!("== the queried relink: -incremental -why_export _greet -why_load ==");
    let outcome = run(
        &dir,
        "hello",
        &["-incremental", "-why_export", "_greet", "-why_load"],
    )
    .expect("the queried relink runs");
    let patch = outcome.patch.expect("the relink reports its patch");
    println!(
        "outcome: {} of {} tiles patched ({} bytes, untouched={})",
        patch.dirty_tiles, patch.total_tiles, patch.bytes_patched, patch.untouched
    );

    // 4. The vacuous query: the relink refuses the run — the misspelling
    //    named, never silently empty (the one-shot's own refusal, the
    //    ladder's too).
    println!("== the vacuous query: -why_export _nope (the refusal) ==");
    let refused = run(&dir, "hello", &["-incremental", "-why_export", "_nope"]);
    match refused {
        Ok(_) => panic!("a vacuous query must refuse the run"),
        Err(rendered) => println!("{rendered}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

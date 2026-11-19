//! The incremental ladder's link-map consumer example (M86): the capture
//! link records the state, one function's body changes, and the relink
//! rewrites the build-system sidecar from its own walk — `-map` beside
//! `-incremental` renders [`pgr_core::map::build_link_map`] over the
//! relink's own Pass-3 layout (the walk runs the full Passes 1–3, so the
//! document names the placed image the relink just planned — never the
//! previous link's). The rendered segments and symbol rows print so the
//! run's own map is visible, not implied.
//!
//! Run: `cargo run -p pgr-driver --example incremental_map`

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// hello.o: `_main` over 16 KiB of `__text` (the tier-1 edit shape),
/// a BL `_greet` site — the link the ladder records and patches. The
/// `flip` variant rewrites eight words mid-text: the edit the relink
/// patches.
fn hello(flip: bool) -> Vec<u8> {
    let mut text = vec![0xD5u8, 0x03, 0x20, 0x1F]; // nop
    text.resize(16 * 1024, 0xD5);
    if flip {
        let base = 8 * 1024 + 16;
        for i in 0..8 {
            text[base + i * 4] = 0xAA;
        }
    }
    let mut b = ObjectBuilder::new("hello.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        text,
        vec![ObjectReloc::branch26(1).at(40)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.build().expect("the fixture object builds")
}

/// greet.o: `_greet` — the linked definition.
fn greet() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Links `argv` (the corpus paths appended) through the driver's own
/// parse + run pair.
fn run(
    dir: &std::path::Path,
    out: &str,
    extra: &[&str],
) -> Result<pgr_driver::LinkOutcome, String> {
    let hello_path = dir.join("hello.o");
    let greet_path = dir.join("greet.o");
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join(out).as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    argv.push(hello_path.as_os_str().to_os_string());
    argv.push(greet_path.as_os_str().to_os_string());
    let parsed = opts::parse(&argv).map_err(|e| format!("{:?}", miette::Report::new(e)))?;
    pgr_driver::run(&parsed).map_err(|e| e.to_string())
}

/// Prints the map's segment rows (the placed image's own report — the
/// text the ladder wrote, read back line by line).
fn print_map(path: &std::path::Path) {
    let text = std::fs::read_to_string(path).expect("the map exists");
    println!("-- {} --", path.display());
    let mut shown = 0;
    for line in text.lines() {
        // The segment header rows lead with their name in column one; the
        // section and symbol rows indent beneath them. Ten rows carry the
        // shape; the file holds the whole placed image.
        if shown < 10 && !line.starts_with(' ') {
            println!("   {line}");
            shown += 1;
        }
    }
    println!("   … ({} bytes of map)", text.len());
}

fn main() {
    let dir = std::env::temp_dir().join(format!("pgr_ladder_map_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("hello.o"), hello(false)).unwrap();
    std::fs::write(dir.join("greet.o"), greet()).unwrap();
    let map = dir.join("hello.map");
    let map_arg = map.display().to_string();

    // 1. The capture link: the ladder's first rung records the state
    //    beside the output and writes the map its full link laid out.
    println!("== the capture link (the map sidecar is written) ==");
    run(&dir, "hello", &["-incremental", "-map", &map_arg]).expect("the capture link runs");
    print_map(&map);

    // 2. The edit: the same object, eight words flipped mid-text — the
    //    tier-1 edit the anchored relink patches in place.
    std::fs::write(dir.join("hello.o"), hello(true)).unwrap();

    // 3. The map-bearing relink: the ladder's walk runs the full Passes
    //    1–3, so the map renders from the walk's own Pass-3 layout — the
    //    placed image this relink planned, at either exit (the patched
    //    one and the untouched one). Never the previous link's document.
    println!("== the map-bearing relink: -incremental -map ==");
    let outcome = run(&dir, "hello", &["-incremental", "-map", &map_arg])
        .expect("the map-bearing relink runs");
    let patch = outcome.patch.expect("the relink reports its patch");
    println!(
        "outcome: {} of {} tiles patched ({} bytes, untouched={})",
        patch.dirty_tiles, patch.total_tiles, patch.bytes_patched, patch.untouched
    );
    print_map(&map);

    let _ = std::fs::remove_dir_all(&dir);
}

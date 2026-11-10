//! M11 rung 2 — the `-map` driver surface: the flag writes the rendered
//! map beside the link, the map file describes the image that landed
//! (segment sizes match the file), and the surfaces that produce no
//! full-emit layout (`-r`, `-incremental`, `-resident`) refuse the knob
//! with the fix in the message.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m11_map").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn args(items: &[&str]) -> Vec<OsString> {
    items.iter().map(|s| OsString::from(*s)).collect()
}

/// hello.o with three functions and a cstring.
fn hello_o(dir: &std::path::Path) -> PathBuf {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    b.add_section(ObjectSection::cstring("hi\n"));
    for (i, name) in ["_main", "_second", "_third"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*name).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    let path = dir.join("hello.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

#[test]
fn the_map_flag_writes_the_placed_report() {
    let dir = scratch("m11");
    let obj = hello_o(&dir);
    let out = dir.join("hello");
    let map_path = dir.join("hello.map");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        obj.to_str().unwrap(),
        "-map",
        map_path.to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the argv parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    assert!(outcome.file_size > 0);

    let map_text = std::fs::read_to_string(&map_path).expect("the map file exists");
    assert!(map_text.starts_with("# Peregrine link map"), "{map_text}");
    assert!(map_text.contains("segment __TEXT"), "{map_text}");
    assert!(map_text.contains("section __text"), "{map_text}");
    assert!(map_text.contains("_main"), "{map_text}");
    // The report's file size line matches the image that landed.
    let declared: u64 = map_text
        .lines()
        .find_map(|l| l.strip_prefix("# file size: "))
        .map(|v| v.parse().expect("the size parses"))
        .expect("the map carries the file size");
    assert_eq!(declared, outcome.file_size, "the map describes this image");

    // And the image itself is unaffected by the report.
    let bytes = std::fs::read(&out).unwrap();
    let report = verify(
        &bytes,
        &VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    assert!(
        report.is_ok(&VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        }),
        "the mapped image verifies strict: {:#?}",
        report.issues
    );
}

#[test]
fn two_links_render_identical_maps() {
    // Determinism: the same inputs map byte-for-byte (the double-link
    // gate the repo holds everywhere, applied to the report).
    let mut maps = Vec::new();
    for i in 0..2 {
        let dir = scratch("m11det");
        let obj = hello_o(&dir);
        let out = dir.join(format!("hello{i}"));
        let map_path = dir.join(format!("hello{i}.map"));
        let argv = args(&[
            "-o",
            out.to_str().unwrap(),
            obj.to_str().unwrap(),
            "-map",
            map_path.to_str().unwrap(),
        ]);
        let o = opts::parse(&argv).expect("the argv parses");
        pgr_driver::run(&o).expect("the link runs");
        maps.push(std::fs::read_to_string(&map_path).unwrap());
    }
    assert_eq!(maps[0], maps[1], "the map render is deterministic");
}

#[test]
fn the_map_refuses_the_surfaces_without_a_full_emit_layout() {
    let dir = scratch("m11");
    let obj = hello_o(&dir);

    // `-r`: an input object, no segment layout.
    let argv = args(&[
        "-o",
        "out.o",
        "-r",
        obj.to_str().unwrap(),
        "-map",
        "out.map",
    ]);
    let err = opts::parse(&argv).unwrap_err();
    assert!(err.to_string().contains("no segment layout"), "{err}");

    // `-incremental`: the patch tiers plan inside the engine.
    let argv = args(&[
        "-o",
        "out",
        obj.to_str().unwrap(),
        "-map",
        "out.map",
        "-incremental",
    ]);
    let err = opts::parse(&argv).unwrap_err();
    assert!(err.to_string().contains("patch tiers"), "{err}");

    // `-resident`: the wire never returns the layout.
    let argv = args(&[
        "-o",
        "out",
        obj.to_str().unwrap(),
        "-map",
        "out.map",
        "-resident",
    ]);
    let err = opts::parse(&argv).unwrap_err();
    assert!(err.to_string().contains("v6 wire"), "{err}");
}

#[test]
fn an_unwritable_map_path_is_a_named_io_refusal() {
    let dir = scratch("m11");
    let obj = hello_o(&dir);
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        obj.to_str().unwrap(),
        "-map",
        dir.join("no-such-dir").join("hello.map").to_str().unwrap(),
    ]);
    let o = opts::parse(&argv).expect("the argv parses");
    let err = pgr_driver::run(&o).unwrap_err();
    assert!(
        err.to_string().contains("hello.map"),
        "the refusal names the map path: {err}"
    );
}

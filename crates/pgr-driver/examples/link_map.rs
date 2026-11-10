//! The link-map consumer example (M11 rung 2): the build-system loop
//! the seam serves — link once with `-map`, read the placed report the
//! same way a build system would (the `#`-prefixed header, the segment
//! blocks, the symbol rows), and re-derive one size claim from it. The
//! map is rendered from the plan the fused emit writes, so the report
//! and the bytes cannot disagree; the example cross-checks exactly that
//! (the map's file-size line against the image on disk).
//!
//! Run: `cargo run -p pgr-driver --example link_map`
//! (`PGR_TRACING=1` installs a subscriber so the layout's spans print —
//! the same inert-until-subscriber convention the binaries use).

use std::path::PathBuf;

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o with three functions (subsections split, so the map has real
/// symbol rows) and one cstring.
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

fn main() {
    // The spans stay inert until a subscriber installs; PGR_TRACING=1
    // turns them into stderr lines (the binaries do the same under their
    // debug envs).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_link_map_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let obj = hello_o(&dir);
    let out = dir.join("hello");
    let map_path = dir.join("hello.map");

    // 1. The link through the driver surface: the same `-map <path>` the
    //    CLI takes. The map is written beside the image.
    let argv: Vec<std::ffi::OsString> = [
        "-o".as_ref(),
        out.as_os_str(),
        obj.as_os_str(),
        "-map".as_ref(),
        map_path.as_os_str(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = opts::parse(&argv).expect("the argv parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    println!(
        "linked {} bytes, map at {}",
        outcome.file_size,
        map_path.display()
    );

    // 2. The report, read as a build system would: the header carries
    //    the file size, the segments carry their ranges.
    let map_text = std::fs::read_to_string(&map_path).expect("the map exists");
    println!("--- the map's head ---");
    for line in map_text.lines().take(8) {
        println!("{line}");
    }
    println!("---");

    // 3. The cross-check the seam promises: the map's file-size line is
    //    the image's actual size (the plan the report renders is the
    //    plan the emit wrote).
    let declared: u64 = map_text
        .lines()
        .find_map(|l| l.strip_prefix("# file size: "))
        .map(|v| v.parse().expect("the size parses"))
        .expect("the map carries the file size");
    let image = std::fs::read(&out).expect("the image exists");
    assert_eq!(declared, image.len() as u64, "the map describes this image");

    // 4. The image is a normal output: it verifies strict with or
    //    without the report.
    let report = verify(
        &image,
        &VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    println!(
        "strict verify: {}",
        if report.is_ok(&VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        }) {
            "clean"
        } else {
            "FAILED"
        }
    );
}

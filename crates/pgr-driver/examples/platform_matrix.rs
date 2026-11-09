//! The platform-matrix consumer example (M10 rung 2, roadmap §10.4 row
//! M10): the loop a cross-platform build system drives when it wants the
//! same corpus linked for every `-platform_version` platform —
//!
//! 1. link the fixture object once per platform (`macos`, `ios`, `tvos`,
//!    `watchos`, `visionos`) through the driver's `link_to_bytes`, with
//!    each platform at its chained-fixups deployment floor;
//! 2. read back the `LC_BUILD_VERSION` payload and the fixup encoding the
//!    layout chose (chained fixups at/above the floor, the classic
//!    `LC_DYLD_INFO_ONLY` opcode streams below it);
//! 3. gate every image with the pipeline's own verifier — strict, so the
//!    platform gate (`build platform … is not a known Mach-O platform`)
//!    and the SDK-ordering gate are exercised, not just the bytes.
//!
//! Run: `cargo run -p pgr-driver --example platform_matrix`
//! (`PGR_TRACING=1` installs a subscriber so the `-platform_version`
//! parse seam and the layout's fixup-shape span — platform and floor on
//! every event — print).

use pgr_driver::opts::parse;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{LC_BUILD_VERSION, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_INFO_ONLY};
use std::ffi::OsString;

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

/// main.o: `_main` plus a `__data` rebase slot — self-contained, so no
/// dylib is needed and the only per-platform variable is the platform.
fn main_with_rebase_slot() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.section_mut(data).relocs = vec![ObjectReloc::unsigned(0).at(0)];
    b.build().unwrap()
}

/// The rung's matrix: every linked platform at its chained-fixups floor
/// (`pgr_core::layout::chained_fixups_min_minos` names the table).
fn platform_matrix() -> Vec<(&'static str, u32, u32, u32)> {
    use pgr_format::consts::{
        PLATFORM_IOS, PLATFORM_MACOS, PLATFORM_TVOS, PLATFORM_VISIONOS, PLATFORM_WATCHOS,
    };
    vec![
        ("macos", PLATFORM_MACOS, 0x000C_0000, 0x000E_0000),
        ("ios", PLATFORM_IOS, 0x000F_0000, 0x0011_0000),
        ("tvos", PLATFORM_TVOS, 0x000F_0000, 0x0011_0000),
        ("watchos", PLATFORM_WATCHOS, 0x0008_0000, 0x000A_0000),
        ("visionos", PLATFORM_VISIONOS, 0x0001_0000, 0x0001_0000),
    ]
}

/// The little-endian u32 at `off`, `None` past the end.
fn word_at(bytes: &[u8], off: usize) -> Option<u32> {
    let b = bytes.get(off..off + 4)?;
    Some(u32::from_le_bytes(b.try_into().ok()?))
}

/// Payload words of the first load command with `opcode`
/// (`[platform, minos, sdk, ntools]` for `LC_BUILD_VERSION`).
fn cmd_words(bytes: &[u8], opcode: u32) -> Option<[u32; 4]> {
    let ncmds = word_at(bytes, 16)?;
    let mut off = 32usize;
    for _ in 0..ncmds {
        let cmd = word_at(bytes, off)?;
        let size = word_at(bytes, off + 4)? as usize;
        if cmd == opcode {
            return Some([
                word_at(bytes, off + 8)?,
                word_at(bytes, off + 12)?,
                word_at(bytes, off + 16)?,
                word_at(bytes, off + 20)?,
            ]);
        }
        off += size;
    }
    None
}

/// The packed `X.Y.Z` word as the pipeline displays it.
fn version_word(v: u32) -> String {
    format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)
}

fn main() {
    // The spans stay inert until a subscriber installs — the workspace
    // convention (the binaries do it under their debug envs). DEBUG
    // surfaces the `-platform_version` seam's parse event and the layout's
    // fixup-shape span (platform + chains_floor on every event).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join("pgr_example_platform_matrix");
    std::fs::create_dir_all(&dir).unwrap();
    let main = dir.join("main.o");
    std::fs::write(&main, main_with_rebase_slot()).unwrap();

    println!(
        "{:<9} {:>10} {:>10} {:<10} {:>10}  verifier (strict)",
        "platform", "minos", "sdk", "fixups", "image"
    );
    for (name, platform, minos, sdk) in platform_matrix() {
        let mut opts = parse(&args(&[
            "-o",
            dir.join("exe").to_str().unwrap(),
            "-platform_version",
            name,
            &version_word(minos),
            &version_word(sdk),
            main.to_str().unwrap(),
        ]))
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        opts.config.ident = format!("platform-matrix-{name}");
        let image = pgr_driver::link_to_bytes(&opts).unwrap();

        let bv = cmd_words(&image, LC_BUILD_VERSION).expect("LC_BUILD_VERSION present");
        debug_assert_eq!(
            bv[0], platform,
            "the declared platform must land in the image"
        );
        let encoding = if cmd_words(&image, LC_DYLD_CHAINED_FIXUPS).is_some() {
            "chained"
        } else {
            debug_assert!(
                cmd_words(&image, LC_DYLD_INFO_ONLY).is_some(),
                "below the floor the classic opcode streams must be present"
            );
            "legacy"
        };

        let report = pgr_verify::verify(
            &image,
            &pgr_verify::Options {
                strict_warnings: true,
                skip_hash_recompute: false,
            },
        );
        let verdict = if report.is_ok(&pgr_verify::Options {
            strict_warnings: true,
            skip_hash_recompute: false,
        }) {
            "clean"
        } else {
            "FAILED"
        };

        println!(
            "{:<9} {:>10} {:>10} {:<10} {:>10}  {verdict}",
            name,
            version_word(minos),
            version_word(sdk),
            encoding,
            image.len(),
        );
    }
    println!(
        "\nEvery platform at its chained-fixups floor: the encoding flips with the floor, \
         the pipeline does not."
    );
}

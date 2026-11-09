//! M10 rung 2 — the platform plumbing rung through the driver: the
//! `-platform_version` surface accepts the five linked platforms
//! (macos, ios, tvos, watchos, visionos), refuses unknown names with the
//! surface in the hint, refuses an SDK older than the deployment target,
//! and the end-to-end links carry the declared platform with the right
//! fixup encoding — verifier-strict on every platform.

use pgr_driver::opts::parse;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::ffi::OsString;

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

fn scratch(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m10_platform").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A self-contained main.o: `_main` plus one `__data` rebase slot — no
/// undefineds, so the link needs no libraries on any platform.
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

/// Payload words of every load command with `opcode`: `[a, b, c, d]` =
/// the four words after the 8-byte command header (platform, minos, sdk,
/// ntools for `LC_BUILD_VERSION`).
fn cmd_words(bytes: &[u8], opcode: u32) -> Vec<[u32; 4]> {
    let ncmds = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let mut off = 32usize;
    let mut out = Vec::new();
    for _ in 0..ncmds {
        let cmd = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let size = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmd == opcode {
            let w = |k: usize| u32::from_le_bytes(bytes[off + k..off + k + 4].try_into().unwrap());
            out.push([w(8), w(12), w(16), w(20)]);
        }
        off += size;
    }
    out
}

#[test]
fn platform_flags_shape_the_config() {
    let cases = [
        ("macos", pgr_format::consts::PLATFORM_MACOS),
        ("ios", pgr_format::consts::PLATFORM_IOS),
        ("tvos", pgr_format::consts::PLATFORM_TVOS),
        ("watchos", pgr_format::consts::PLATFORM_WATCHOS),
        ("visionos", pgr_format::consts::PLATFORM_VISIONOS),
    ];
    for (name, platform) in cases {
        let o = parse(&args(&[
            "-o",
            "out",
            "-platform_version",
            name,
            "1.0",
            "1.0",
            "a.o",
        ]))
        .unwrap_or_else(|e| panic!("{name} must parse: {e}"));
        assert_eq!(o.config.platform, platform, "{name} must shape the config");
    }
}

#[test]
fn unknown_platform_refuses_with_the_surface_in_the_hint() {
    let err = parse(&args(&[
        "-o",
        "out",
        "-platform_version",
        "linux",
        "1.0",
        "1.0",
        "a.o",
    ]))
    .unwrap_err();
    let msg = err.to_string();
    for name in ["macos", "ios", "tvos", "watchos", "visionos"] {
        assert!(msg.contains(name), "the refusal must name {name}: {msg}");
    }
}

#[test]
fn sdk_older_than_the_deployment_target_refuses() {
    let err = parse(&args(&[
        "-o",
        "out",
        "-platform_version",
        "macos",
        "14.0",
        "12.0",
        "a.o",
    ]))
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("SDK") && msg.contains("14.0") && msg.contains("12.0"),
        "the refusal must name both versions: {msg}"
    );
}

#[test]
fn visionos_link_verifies_strict_and_carries_chains() {
    let dir = scratch("visionos");
    let main = dir.join("main.o");
    std::fs::write(&main, main_with_rebase_slot()).unwrap();
    let mut opts = parse(&args(&[
        "-o",
        dir.join("exe").to_str().unwrap(),
        "-platform_version",
        "visionos",
        "1.0",
        "1.0",
        main.to_str().unwrap(),
    ]))
    .unwrap();
    opts.config.ident = "m10-visionos".into();
    let outcome = pgr_driver::run(&opts).unwrap();
    assert!(outcome.file_size > 0 && outcome.entryoff > 0);

    let bytes = std::fs::read(dir.join("exe")).unwrap();
    let bv = cmd_words(&bytes, pgr_format::consts::LC_BUILD_VERSION);
    assert_eq!(bv.len(), 1, "one LC_BUILD_VERSION");
    assert_eq!(bv[0][0], pgr_format::consts::PLATFORM_VISIONOS);
    assert_eq!(bv[0][1], 0x0001_0000, "minos 1.0.0");
    assert!(
        !cmd_words(&bytes, pgr_format::consts::LC_DYLD_INFO_ONLY).is_empty()
            || !cmd_words(&bytes, pgr_format::consts::LC_DYLD_CHAINED_FIXUPS).is_empty(),
        "one fixup encoding must be present"
    );
    assert!(
        cmd_words(&bytes, pgr_format::consts::LC_DYLD_CHAINED_FIXUPS).len() == 1,
        "visionos 1.0 is at its floor: chained fixups"
    );
    assert!(
        cmd_words(&bytes, pgr_format::consts::LC_DYLD_INFO_ONLY).is_empty(),
        "no legacy opcodes next to the chained payload"
    );

    let report = pgr_verify::verify(
        &bytes,
        &pgr_verify::Options {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    let errors: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.severity == pgr_verify::Severity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "visionos output must verify strict: {errors:?}"
    );
}

#[test]
fn ios_below_the_floor_falls_back_to_legacy_opcodes() {
    let dir = scratch("ios14");
    let main = dir.join("main.o");
    std::fs::write(&main, main_with_rebase_slot()).unwrap();
    let mut opts = parse(&args(&[
        "-o",
        dir.join("exe").to_str().unwrap(),
        "-platform_version",
        "ios",
        "14.0",
        "17.0",
        main.to_str().unwrap(),
    ]))
    .unwrap();
    opts.config.ident = "m10-ios14".into();
    pgr_driver::run(&opts).unwrap();

    let bytes = std::fs::read(dir.join("exe")).unwrap();
    assert_eq!(
        cmd_words(&bytes, pgr_format::consts::LC_BUILD_VERSION)[0][0],
        pgr_format::consts::PLATFORM_IOS,
    );
    assert!(
        !cmd_words(&bytes, pgr_format::consts::LC_DYLD_INFO_ONLY).is_empty(),
        "ios 14.0 is below its floor: the classic opcode streams"
    );
    assert!(
        cmd_words(&bytes, pgr_format::consts::LC_DYLD_CHAINED_FIXUPS).is_empty(),
        "no chained payload below the floor"
    );

    let report = pgr_verify::verify(
        &bytes,
        &pgr_verify::Options {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    let errors: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.severity == pgr_verify::Severity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "ios 14.0 output must verify strict: {errors:?}"
    );
}

#[test]
fn platform_links_are_deterministic() {
    let dir = scratch("determinism");
    let main = dir.join("main.o");
    std::fs::write(&main, main_with_rebase_slot()).unwrap();
    for out in ["one", "two"] {
        let mut opts = parse(&args(&[
            "-o",
            dir.join(format!("{out}.exe")).to_str().unwrap(),
            "-platform_version",
            "ios",
            "15.0",
            "17.0",
            main.to_str().unwrap(),
        ]))
        .unwrap();
        opts.config.ident = "m10-det".into();
        pgr_driver::run(&opts).unwrap();
    }
    assert_eq!(
        std::fs::read(dir.join("one.exe")).unwrap(),
        std::fs::read(dir.join("two.exe")).unwrap(),
        "double platform link is byte-identical"
    );
}

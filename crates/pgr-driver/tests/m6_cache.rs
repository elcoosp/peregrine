//! M6 Stage A cache gates (architecture doc §7.1): the POI cache and the
//! frozen-`.tbd` cache are pure accelerations —
//!
//! * cached vs uncached output is **byte-identical** (the roadmap gate),
//! * a corrupt entry is detected and silently re-parsed,
//! * `-no_cache` disables the feature entirely.

use pgr_driver::opts::Options;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

fn unique_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m6_cache").join(format!(
        "{}_{}_{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn hello_main() -> Vec<u8> {
    let text: Vec<u8> = [
        0x9000_0000u32, // adrp x0, _msg@page
        0x9100_0000u32, // add x0, x0, #_msg@pageoff
        0x9400_0000u32, // bl _greet
        0x5280_0000u32, // mov w0, #0
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let sect = b.add_section(ObjectSection::text(
        "__text",
        text,
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12(1).at(4),
            ObjectReloc::branch26(2).at(8),
        ],
    ));
    b.add_section(ObjectSection::cstring("hello, peregrine\n"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_msg".into(),
        section_index: 1,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.build().unwrap()
}

fn greet() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![
            0x91, 0x00, 0x00, 0x00, // add x0, x0, #0
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().unwrap()
}

fn opts_for(dir: &std::path::Path, cache_dir: Option<&std::path::Path>) -> Options {
    let main_p = dir.join("hello.o");
    std::fs::write(&main_p, hello_main()).unwrap();
    let greet_p = dir.join("greet.o");
    std::fs::write(&greet_p, greet()).unwrap();
    Options {
        inputs: vec![main_p.display().to_string(), greet_p.display().to_string()],
        output: dir.join("out.bin").display().to_string(),
        config: pgr_core::layout::LinkConfig {
            ident: "m6-cache".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        cache_dir: cache_dir.map(|c| c.display().to_string()),
        ..Options::default()
    }
}

const GREET_TBD: &str = "--- !tapi-tbd
tbd-version: 4
targets:         [ arm64-macos ]
install-name:    /usr/lib/libgreet.dylib
exports:
  - targets:         [ arm64-macos ]
    symbols:         [ _greet ]
...
";

/// The §7.1 gate: cached (warm) and uncached (cold) links are byte-identical,
/// and the second link actually hits the cache.
#[test]
fn m6_cached_and_uncached_outputs_are_byte_identical() {
    let cold_dir = unique_dir("cold");
    let warm_dir = unique_dir("warm");
    let cache_dir = unique_dir("cache");

    let cold = pgr_driver::link_to_bytes(&opts_for(&cold_dir, None)).unwrap();
    // First warm link populates the cache; second hits it.
    let warm1 = pgr_driver::link_to_bytes(&opts_for(&warm_dir, Some(&cache_dir))).unwrap();
    assert!(
        std::fs::read_dir(&cache_dir).unwrap().count() > 0,
        "the POI cache writes entries"
    );
    let warm2 = pgr_driver::link_to_bytes(&opts_for(&warm_dir, Some(&cache_dir))).unwrap();
    assert_eq!(cold, warm1, "cache population must not change the output");
    assert_eq!(cold, warm2, "a cache hit must be byte-identical (§7.1)");
}

/// A corrupted cache entry is detected (checksum) and silently re-parsed.
#[test]
fn m6_corrupt_cache_entries_are_silently_reparsed() {
    let dir = unique_dir("corrupt");
    let cache_dir = unique_dir("corrupt-cache");
    let warm = pgr_driver::link_to_bytes(&opts_for(&dir, Some(&cache_dir))).unwrap();
    // Corrupt every cache entry.
    for entry in std::fs::read_dir(&cache_dir).unwrap() {
        let path = entry.unwrap().path();
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&path, bytes).unwrap();
    }
    let again = pgr_driver::link_to_bytes(&opts_for(&dir, Some(&cache_dir))).unwrap();
    assert_eq!(warm, again, "corrupt entries must fall back to re-parse");
}

/// Frozen `.tbd`: the stub parse is cached; a dylib link through the cache
/// is byte-identical to the text-parsed link.
#[test]
fn m6_frozen_tbd_cache_hits_produce_identical_dylib_links() {
    let dir = unique_dir("tbd");
    let cache_dir = unique_dir("tbd-cache");
    let main_p = dir.join("hello.o");
    std::fs::write(&main_p, hello_main()).unwrap();
    let tbd_p = dir.join("libgreet.tbd");
    std::fs::write(&tbd_p, GREET_TBD).unwrap();

    let cold = Options {
        inputs: vec![main_p.display().to_string()],
        output: dir.join("cold.bin").display().to_string(),
        config: pgr_core::layout::LinkConfig {
            ident: "m6-tbd".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        lib_dirs: vec![dir.display().to_string()],
        libs: vec!["greet".into()],
        ..Options::default()
    };

    let mut warm = cold.clone();
    warm.cache_dir = Some(cache_dir.display().to_string());
    warm.output = dir.join("warm.bin").display().to_string();

    let cold_bytes = pgr_driver::link_to_bytes(&cold).unwrap();
    let warm1 = pgr_driver::link_to_bytes(&warm).unwrap();
    assert!(
        std::fs::read_dir(&cache_dir).unwrap().count() > 0,
        "the frozen-.tbd cache writes entries"
    );
    let warm2 = pgr_driver::link_to_bytes(&warm).unwrap();
    assert_eq!(cold_bytes, warm1);
    assert_eq!(cold_bytes, warm2, "frozen-.tbd hits are byte-identical");
    // And the bind still names _greet through the dylib ordinal.
    let report = pgr_verify::verify(
        &cold_bytes,
        &pgr_verify::Options {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    assert!(report.is_ok(&pgr_verify::Options::default()), "{report:?}");
}

/// `-no_cache` disables writes even when a directory is configured.
#[test]
fn m6_no_cache_disables_the_feature() {
    let dir = unique_dir("nocache");
    let cache_dir = unique_dir("nocache-cache");
    let mut opts = opts_for(&dir, Some(&cache_dir));
    opts.no_cache = true;
    pgr_driver::link_to_bytes(&opts).unwrap();
    assert_eq!(
        std::fs::read_dir(&cache_dir).unwrap().count(),
        0,
        "-no_cache must leave the cache directory empty"
    );
}

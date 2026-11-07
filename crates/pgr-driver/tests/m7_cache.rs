//! M7 versioned-cache-format gates (architecture doc §10.3 row M7:
//! "**versioned cache format**"; §7.1 marker/self-heal/LRU) — e2e through the
//! driver surface:
//!
//! * cached vs uncached output stays **byte-identical** on the v2 format
//!   (the §7.1 gate, re-asserted for the M7 frame),
//! * a cache directory written by another pgr format self-heals on open
//!   (marker mismatch → stale pgr-shaped files reclaimed, link proceeds),
//! * `-cache_max <bytes>` bounds the directory (oldest-mtime eviction),
//! * the frozen-`.tbd` path rides the same v2 framing.

use pgr_driver::opts::Options;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

fn unique_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m7_cache").join(format!(
        "{tag}_{}_{}",
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

fn write_inputs(tag: &str, objs: &[&[u8]]) -> (std::path::PathBuf, Vec<String>) {
    let dir = unique_dir(tag);
    let mut paths = Vec::new();
    for (i, bytes) in objs.iter().enumerate() {
        let p = dir.join(format!("{tag}_obj_{i}.o"));
        std::fs::write(&p, bytes).unwrap();
        paths.push(p.display().to_string());
    }
    (dir, paths)
}

fn opts_for(
    input_paths: &[String],
    out: &std::path::Path,
    cache_dir: Option<&std::path::Path>,
) -> Options {
    Options {
        inputs: input_paths.to_vec(),
        output: out.display().to_string(),
        config: pgr_core::layout::LinkConfig {
            ident: "m7-cache".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        cache_dir: cache_dir.map(|d| d.display().to_string()),
        ..Options::default()
    }
}

fn entry_files(dir: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.len() == 64 && name.bytes().all(|c| c.is_ascii_hexdigit()) {
            out.push(name);
        }
    }
    out.sort();
    out
}

#[test]
fn m7_cached_and_uncached_stay_byte_identical_on_v2() {
    let (_d, paths) = write_inputs("ident", &[&hello_main(), &greet()]);
    let out_dir = unique_dir("ident_out");
    let plain = out_dir.join("plain.bin");
    let warm = out_dir.join("warm.bin");
    let cache_dir = unique_dir("ident_cache");
    pgr_driver::run(&opts_for(&paths, &plain, None)).unwrap();
    pgr_driver::run(&opts_for(&paths, &warm, Some(&cache_dir))).unwrap();
    pgr_driver::run(&opts_for(&paths, &warm, Some(&cache_dir))).unwrap();
    let a = std::fs::read(&plain).unwrap();
    let b = std::fs::read(&warm).unwrap();
    assert_eq!(a, b, "v2 cache hits must stay byte-identical (§7.1)");
    assert!(!entry_files(&cache_dir).is_empty(), "entries were stored");
}

#[test]
fn m7_foreign_cache_dir_self_heals_and_the_link_proceeds() {
    let (_d, paths) = write_inputs("heal", &[&hello_main(), &greet()]);
    let out_dir = unique_dir("heal_out");
    let cache_dir = unique_dir("heal_cache");
    // A directory "written by another pgr": garbage marker + entry-shaped
    // stale files.
    std::fs::write(cache_dir.join("PGR_CACHE_FORMAT"), b" alien format ").unwrap();
    let stale = cache_dir.join("f".repeat(64));
    std::fs::write(&stale, b"stale bytes").unwrap();
    let plain = out_dir.join("plain.bin");
    let healed = out_dir.join("healed.bin");
    pgr_driver::run(&opts_for(&paths, &plain, None)).unwrap();
    pgr_driver::run(&opts_for(&paths, &healed, Some(&cache_dir))).unwrap();
    let a = std::fs::read(&plain).unwrap();
    let b = std::fs::read(&healed).unwrap();
    assert_eq!(a, b, "self-heal must not change the output");
    assert!(!stale.exists(), "stale entry reclaimed on open");
    let marker = std::fs::read(cache_dir.join("PGR_CACHE_FORMAT")).unwrap();
    assert_eq!(&marker[0..17], b"PGR-CACHE-FORMAT\0", "marker rewritten");
}

#[test]
fn m7_cache_max_bounds_the_directory() {
    let (_d, paths) = write_inputs("bound", &[&hello_main(), &greet()]);
    let out_dir = unique_dir("bound_out");
    let cache_dir = unique_dir("bound_cache");
    // A third, distinct object (defines its own symbol; no duplicates).
    let extra = out_dir.join("extra.o");
    let mut eb = ObjectBuilder::new("extra.o");
    let et = eb.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    eb.add_symbol(ObjectSymbol::Defined {
        name: "_extra".into(),
        section_index: et,
        value: 0,
        weak: false,
    });
    std::fs::write(&extra, eb.build().unwrap()).unwrap();
    let mut second = paths.clone();
    second.push(extra.display().to_string());
    // Cap at 1 KiB (each POI entry is ≈ 0.25 KiB, so the cap is real).
    let tiny_out = out_dir.join("t.bin");
    let mut opts = opts_for(&paths, &tiny_out, Some(&cache_dir));
    opts.cache_max = Some(1024);
    pgr_driver::run(&opts).unwrap();
    let mut opts2 = opts_for(&second, &tiny_out, Some(&cache_dir));
    opts2.cache_max = Some(1024);
    pgr_driver::run(&opts2).unwrap();
    // The eviction contract: the directory's entry bytes stay within the cap
    // plus one entry (the just-stored entry is never evicted).
    let mut sizes: Vec<u64> = Vec::new();
    for e in std::fs::read_dir(&cache_dir).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.len() == 64 && name.bytes().all(|c| c.is_ascii_hexdigit()) {
            sizes.push(e.metadata().unwrap().len());
        }
    }
    let total: u64 = sizes.iter().sum();
    let biggest = sizes.iter().copied().max().unwrap_or(0);
    assert!(!sizes.is_empty(), "entries were stored");
    assert!(
        total <= 1024 + biggest,
        "size bound respected (total {total}, biggest {biggest})"
    );
    // The unbounded default keeps everything: a fresh cache dir with the
    // same links stores all three distinct entries.
    let cache_dir2 = unique_dir("bound_cache_unlimited");
    let mut opts3 = opts_for(&paths, &tiny_out, Some(&cache_dir2));
    opts3.cache_max = Some(0);
    pgr_driver::run(&opts3).unwrap();
    let mut opts4 = opts_for(&second, &tiny_out, Some(&cache_dir2));
    opts4.cache_max = Some(0);
    pgr_driver::run(&opts4).unwrap();
    let n = entry_files(&cache_dir2).len();
    assert!(n >= 3, "cache_max 0 is unbounded (found {n} entries)");
}

#[test]
fn m7_frozen_tbd_roundtrips_through_v2() {
    // A dylib linked twice through one cache: the second link decodes the
    // frozen `.tbd` from the v2 frame and the bytes are identical.
    let tbd = b"--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: /usr/lib/libgreet.dylib\ncurrent-version: 1.2.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _greet ]\n...\n";
    let dir = unique_dir("tbd");
    let stub = dir.join("libgreet.tbd");
    std::fs::write(&stub, tbd).unwrap();
    let obj = dir.join("caller.o");
    let mut b = ObjectBuilder::new("caller.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0x91, 0x00, 0x00, 0x00, 0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    std::fs::write(&obj, b.build().unwrap()).unwrap();
    let cache_dir = unique_dir("tbd_cache");
    let out1 = dir.join("a.dylib");
    let out2 = dir.join("b.dylib");
    let mk = |out: &std::path::Path| Options {
        inputs: vec![obj.display().to_string(), stub.display().to_string()],
        output: out.display().to_string(),
        config: pgr_core::layout::LinkConfig {
            ident: "m7-tbd".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        cache_dir: Some(cache_dir.display().to_string()),
        ..Options::default()
    };
    pgr_driver::run(&mk(&out1)).unwrap();
    pgr_driver::run(&mk(&out2)).unwrap();
    assert_eq!(
        std::fs::read(&out1).unwrap(),
        std::fs::read(&out2).unwrap(),
        "frozen-`.tbd` v2 path stays byte-identical"
    );
    assert!(
        entry_files(&cache_dir).len() >= 2,
        "both the POI and the frozen stub were stored"
    );
}

#[test]
fn m7_lru_bound_survives_parallel_stores() {
    // Regression: Pass 1 stores entries concurrently from the parse pool.
    // Without serializing store+evict, two concurrent stores each spared
    // their own entry and evicted the other's — a tiny `-cache_max` could
    // wipe the directory. 30 bounded links over fresh dirs must always keep
    // the just-stored entry.
    for iter in 0..30 {
        let dir = unique_dir("lru_stress");
        let obj1 = dir.join("hello.o");
        let obj2 = dir.join("greet.o");
        std::fs::write(&obj1, hello_main()).unwrap();
        std::fs::write(&obj2, greet()).unwrap();
        let cache = dir.join("cache");
        let opts = Options {
            inputs: vec![obj1.display().to_string(), obj2.display().to_string()],
            output: dir.join("out.bin").display().to_string(),
            config: pgr_core::layout::LinkConfig {
                ident: "lru-stress".into(),
                ..pgr_core::layout::LinkConfig::default()
            },
            cache_dir: Some(cache.display().to_string()),
            cache_max: Some(256), // each entry is ≈ 250 B: the cap always binds
            ..Options::default()
        };
        pgr_driver::run(&opts).unwrap_or_else(|e| panic!("iter {iter}: link failed: {e}"));
        let entries = entry_files(&cache);
        assert!(
            !entries.is_empty(),
            "iter {iter}: the bounded cache lost every entry"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

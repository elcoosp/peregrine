//! The Stage A link-cache consumer example (M6/M7): the same corpus
//! linked through a cache directory — the cold lane stores the parsed
//! POIs, the warm lane hits them, a corrupted entry self-heals on open
//! (the stale bytes are detected and silently re-parsed) — every lane
//! byte-identical to the plain uncached link (the cached and uncached
//! output are byte-identical, gated here the way CI gates it), and the
//! cache directory's shape printed — the optimization a build system
//! opts into between relinks of an unchanged corpus.
//!
//! Run: `cargo run -p pgr-driver --example cache_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans —
//! the same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SegmentCommand64};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` over three RET functions and a `__cstring` (the
/// POIs the cache stores the parse of).
fn hello_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        Vec::new(),
    ));
    for (i, sym) in ["_main", "_fn_1", "_fn_2"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.add_section(ObjectSection::cstring("hello, peregrine\n"));
    b.build().expect("the fixture object builds")
}

/// The `__cstring` bytes the image carries (the cheapest full-image
/// fingerprint the example asserts across the lanes).
fn cstring_span(image: &[u8]) -> (u32, u32) {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg = SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            for s in seg
                .sections(cmd.bytes, SegmentCommand64::SIZE)
                .expect("the sections parse")
            {
                if s.segname.starts_with(b"__TEXT\0") && s.sectname.starts_with(b"__cstring\0") {
                    return (s.offset, s.size as u32);
                }
            }
        }
    }
    panic!("the corpus carries a cstring bucket")
}

fn link(dir: &std::path::Path, out: &str, cache: Option<&str>) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    if let Some(cache) = cache {
        argv.push(std::ffi::OsString::from("-cache"));
        argv.push(std::ffi::OsString::from(cache));
    }
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).expect("the image reads")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_cache_link_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cache_dir = dir.join("cache");
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The plain lane: no cache — the reference bytes every other
    //    lane must reproduce byte-for-byte.
    let plain = link(&dir, "app_plain", None);
    let report = verify(&plain, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the plain image verifies strict: {:?}",
        report.issues
    );

    // 2. The cold lane: the cache directory is created, the parse is
    //    stored, the image is byte-identical to the plain lane.
    let cold = link(&dir, "app_cold", Some(&cache_dir.display().to_string()));
    assert_eq!(plain, cold, "the cold cached link is byte-identical");
    let marker = cache_dir.join(pgr_core::cache::MARKER_NAME);
    assert!(
        marker.exists(),
        "the cache directory carries the format marker"
    );

    // 3. The warm lane: the same argv hits the stored entries —
    //    byte-identical again (the cache is an optimization only).
    let warm = link(&dir, "app_warm", Some(&cache_dir.display().to_string()));
    assert_eq!(plain, warm, "the warm cached link is byte-identical");

    // 4. The self-heal: corrupt one stored entry — the stale bytes are
    //    detected on open and silently re-parsed; the image stays
    //    byte-identical.
    let entries: Vec<_> = std::fs::read_dir(&cache_dir)
        .expect("the cache dir reads")
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_name() != pgr_core::cache::MARKER_NAME)
        .collect();
    assert!(!entries.is_empty(), "the cold lane stored an entry");
    let victim = &entries[0].path();
    let mut bytes = std::fs::read(victim).expect("the entry reads");
    let flip_at = bytes.len() / 2;
    bytes[flip_at] ^= 0xFF;
    std::fs::write(victim, &bytes).expect("the entry corrupts");
    let healed = link(&dir, "app_healed", Some(&cache_dir.display().to_string()));
    assert_eq!(
        plain, healed,
        "the corrupted entry self-heals byte-identically"
    );

    let (off, size) = cstring_span(&plain);
    println!(
        "plain: {} bytes of image, __cstring at file offset {:#x} ({} bytes)",
        plain.len(),
        off,
        size
    );
    println!(
        "cache: {} stored entries under {} (marker {}), cold/warm/healed lanes all \
         byte-identical to the plain lane; the corrupted entry self-healed",
        entries.len(),
        cache_dir.display(),
        pgr_core::cache::CACHE_FORMAT_VERSION
    );
}

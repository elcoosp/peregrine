//! The Stage-A POI cache's consumer cycle, runnable (M6, the library API):
//! a [`PoiCache`] opened on a scratch directory, a parsed object stored
//! under its content key, then two loads — a hit that skips the Mach-O
//! walk entirely and a miss on changed bytes (the content-addressed key
//! moved). This is the library face of the driver's `-cache <dir>` lane:
//! a build system driving [`pgr_core::link_cached`] directly holds the
//! cache handle, and every hit is equality-gated (a cache hit parses to
//! the identical object — the gate is `crate::cache`'s own tests and the
//! driver's M6 suite; corruption self-heals by re-parsing).
//!
//! ```sh
//! cargo run -p pgr-core --example cache_poi
//! ```

use std::path::Path;

use pgr_core::cache::PoiCache;
use pgr_core::ids::FileId;
use pgr_core::object::InputObject;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// One object: a two-instruction `__text`, a `__data` word, one definition.
fn object(stem: &str, flip: bool) -> Vec<u8> {
    let body = if flip {
        vec![0x1F, 0x20, 0x03, 0xD5, 0x00, 0x00, 0x00, 0x00] // nop; .word 0
    } else {
        vec![0x1F, 0x20, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6] // nop; ret
    };
    let mut b = ObjectBuilder::new(&format!("{stem}.o")).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text("__text", body, vec![]));
    b.add_section(ObjectSection::data("__data", vec![0x41u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_{stem}"),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn main() {
    // The cache is a directory: the driver's `-cache <dir>` opens (and
    // self-heals) the same shape; `open_limited` bounds it (the
    // `-cache_max` LRU). A scratch dir keeps the example side-effect-free.
    let dir = std::env::temp_dir().join("pgr-cache-poi-example");
    let cache = PoiCache::open(&dir).expect("the cache opens");

    // Pass 1's content key: the object bytes plus the parse flag (the
    // atom-split rides the key, an M11 order file changes it too).
    let bytes = object("hello", false);
    let split_symbols = false;
    let key = PoiCache::content_key(&bytes, split_symbols);

    // The cold parse: parse, then store. The store is a pure write — the
    // link never waits on it beyond the encode cost.
    let obj = InputObject::parse(FileId(0), "hello.o", bytes.clone()).expect("the object parses");
    cache.store(&key, &obj, split_symbols);
    println!(
        "stored hello.o under its content key ({} bytes)",
        bytes.len()
    );

    // The warm load: an identical body hits the cache and re-parses to
    // the identical object (the equality the gates pin).
    let hit = cache
        .load(&key, FileId(0), "hello.o", bytes.clone(), split_symbols)
        .expect("the warm load hits");
    println!(
        "hit:  hello.o re-parsed from the cache image ({} symbols)",
        hit.symbols.len()
    );

    // The changed body: different bytes, a different key — the miss is
    // the parse, never a stale image.
    let edited = object("hello", true);
    let miss = cache.load(
        &PoiCache::content_key(&edited, split_symbols),
        FileId(0),
        "hello.o",
        edited,
        split_symbols,
    );
    println!(
        "miss: the edited body carries a new key (loaded = {}), so Pass 1 runs",
        miss.is_some()
    );

    // The scratch dir: the example leaves no state behind.
    let _ = std::fs::remove_dir_all(Path::new(&dir));
    println!("cleaned the scratch cache dir");
}

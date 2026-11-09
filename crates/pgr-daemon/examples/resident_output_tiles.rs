//! The §7.2 output-residency rung, runnable (wire v5): the same cycle the
//! daemon serves `pgr -resident -incremental`, driven directly over a
//! [`ResidentSession`] — a cold full link whose served image becomes the
//! session's resident output state, an edit, then the warm relink whose
//! reply is the *changed-tile stream* instead of the image. The previous
//! output never re-crosses the wire (the session already holds it), the
//! untouched shape ships nothing, and the replay is hash-gated.
//!
//! ```sh
//! cargo run -p pgr-daemon --example resident_output_tiles
//! ```

use pgr_core::layout::LinkConfig;
use pgr_daemon::ResidentSession;
use pgr_daemon::protocol::{InputEntry, LinkRequest, content_hash};
use pgr_emit::incremental::{LinkRecord, apply_tiles};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// hello.o with a `text_bytes`-sized `__text`: `_main` ADRP+ADD loads
/// `_msg`, BL `_greet`, ret; `body_flip` swaps a mov immediate and the
/// cstring at equal length (the "edit" the relink patches).
fn hello(text_bytes: usize, body_flip: bool) -> ObjectBuilder {
    let mut words: Vec<u32> = vec![
        0x9000_0000, // adrp x0, _msg@page
        0x9100_0000, // add x0, x0, #_msg@pageoff
        0x9400_0000, // bl _greet
        0x5280_0000, // mov w0, #0 (flipped: #1 — the edited body)
        0xD65F_03C0, // ret
    ];
    if body_flip {
        words[3] = 0x5280_0020;
    }
    words.resize(text_bytes / 4, 0xD503_201F);
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut b = ObjectBuilder::new("hello.o");
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
    b.add_section(ObjectSection::cstring(if body_flip {
        "merci, peregrine\n"
    } else {
        "hello, peregrine\n"
    }));
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
    b
}

/// greet.o (never edited): `_greet` as a bare ret.
fn greet() -> ObjectBuilder {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b
}

fn request(hello_bytes: &[u8], greet_bytes: &[u8]) -> (LinkRequest, [u8; 32], [u8; 32]) {
    let req = LinkRequest {
        config: LinkConfig {
            ident: "resident-tiles-example".into(),
            // The in-place tier stands on slack anchors; `-incremental`
            // implies slack for the whole cycle (the driver does this).
            layout_slack: Some(pgr_core::SlackPolicy::default()),
            ..LinkConfig::default()
        },
        force_load: Vec::new(),
        inputs: vec![
            InputEntry {
                name: "hello.o".into(),
                hash: content_hash(hello_bytes),
            },
            InputEntry {
                name: "greet.o".into(),
                hash: content_hash(greet_bytes),
            },
        ],
        archives: Vec::new(),
        record: None,
        record_resolution: false,
        prev_output: None,
        audit: false,
        tiles: false,
    };
    (req, content_hash(hello_bytes), content_hash(greet_bytes))
}

fn main() {
    let hello_bytes = hello(32 * 1024, false).build().expect("hello.o builds");
    let greet_bytes = greet().build().expect("greet.o builds");

    // Cold link with record capture: the served image becomes the
    // session's resident output state — the next cycle's previous output
    // is already here (the client's BLOB negotiation finds the hash).
    let mut session = ResidentSession::default();
    let (mut req, hello_hash, greet_hash) = request(&hello_bytes, &greet_bytes);
    for (h, bytes) in [
        (hello_hash, hello_bytes.clone()),
        (greet_hash, greet_bytes.clone()),
    ] {
        session.store_blob(&h, bytes).expect("blob stored");
    }
    req.record_resolution = true;
    let cold = session.link(&req).expect("the cold link serves");
    let record_bytes = cold.record.clone().expect("the cold link captures");
    let prev_output = cold.image.clone();
    println!(
        "cold full link: {} bytes; resident output held = {}",
        prev_output.len(),
        session.has_blob(&content_hash(&prev_output))
    );

    // The edit + tiles relink: no prev-output upload (resident), and the
    // reply carries the changed 16 KiB tiles plus the patched image's
    // content hash — the client-side replay gate.
    let edited = hello(32 * 1024, true).build().expect("the edit builds");
    let (mut relink, hello_hash2, _) = request(&edited, &greet_bytes);
    relink.record = Some(record_bytes);
    relink.prev_output = Some(content_hash(&prev_output));
    relink.record_resolution = true;
    relink.tiles = true;
    session
        .store_blob(&hello_hash2, edited.clone())
        .expect("the edited input stored");
    let served = session.link(&relink).expect("the tiles relink serves");
    let patch = served.patch.expect("the ladder patches");
    let stream = served.tiles.expect("the tiles rung serves a stream");
    println!(
        "tiles relink: {} of {} tiles patched; the stream carried {} bytes of {} image bytes",
        patch.dirty_tiles,
        patch.total_tiles,
        stream.wire_bytes(),
        served.image.len()
    );

    // The client side of the rung: replay against the local previous
    // output, verify the replay gate, write. (The example asserts instead
    // of writing; the driver's file path is gated end to end in
    // `pgr-driver/tests/m9_resident_fusion.rs`.)
    let rebuilt = apply_tiles(&prev_output, &stream);
    assert_eq!(content_hash(&rebuilt), stream.image_hash, "replay gate");
    assert_eq!(rebuilt, served.image, "the replay is lossless");

    // Untouched: a relink with no edit ships zero bytes — the client's
    // file already is the output.
    let (mut again, _, _) = request(&edited, &greet_bytes);
    again.record = Some(
        LinkRecord::decode(served.record.as_ref().unwrap())
            .unwrap()
            .encode(),
    );
    again.prev_output = Some(content_hash(&served.image));
    again.tiles = true;
    let untouched = session.link(&again).expect("the untouched relink serves");
    let stream = untouched
        .tiles
        .expect("the untouched relink shapes a stream");
    println!(
        "untouched relink: {} tile bytes crossed (untouched = {})",
        stream.wire_bytes(),
        untouched.patch.as_ref().unwrap().untouched
    );
    assert_eq!(stream.wire_bytes(), 0, "nothing crossed the wire");
}

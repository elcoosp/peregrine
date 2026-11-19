//! The served liveness ask, runnable (wire v48, M93): the same session
//! the daemon serves `pgr -resident -dead_strip -why_live`, driven
//! directly over a [`ResidentSession`] — a cold full link under
//! `-dead_strip` asking two liveness questions, then the warm relink
//! whose edit flips one verdict: the cold walk drops `_orphan` (nothing
//! references it — the honest answer is the verdict that says so), the
//! edit adds the call, and the replay's own mark record answers *kept*
//! with the chain naming the new keeper. The reply's provenance tail
//! carries the rendered chains verbatim beside the M79 answers; the
//! renders are the cold lane's own face (`pgr_core::why_live`). An
//! unasked query never crosses: the same relink without the ask rides
//! no liveness answer.
//!
//! ```sh
//! cargo run -p pgr-daemon --example why_live_session
//! ```

use pgr_core::layout::LinkConfig;
use pgr_daemon::ResidentSession;
use pgr_daemon::protocol::{InputEntry, LinkRequest, content_hash};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// main.o: `_main` BL `_greet`, ret — plus a BL `_orphan` when
/// `calls_orphan` (the edit the relink patches: the added reference is
/// the chain's new root hop, and the strip's verdict flips with it).
fn main_object(calls_orphan: bool) -> ObjectBuilder {
    let mut words: Vec<u32> = vec![
        0x9400_0000, // bl _greet
    ];
    let mut relocs = vec![ObjectReloc::branch26(1).at(0)];
    let mut undefs = vec!["_greet"];
    if calls_orphan {
        words.push(0x9400_0000); // bl _orphan
        relocs.push(ObjectReloc::branch26(2).at(4));
        undefs.push("_orphan");
    }
    words.push(0xD65F_03C0); // ret
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    b.add_section(ObjectSection::text("__text", text, relocs));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    for (i, name) in undefs.iter().enumerate() {
        let _ = b.add_symbol(ObjectSymbol::Undefined {
            name: (*name).into(),
            weak_ref: false,
        });
        let _ = i;
    }
    b
}

/// A one-function object: `name` defined at the head of a bare-ret
/// `__text` (the definition the strip keeps or drops).
fn leaf_object(file: &str, symbol: &str) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(file).set_subsections_via_symbols(true);
    let sect = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: symbol.into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b
}

/// The request: a `-dead_strip` link over main.o, greet.o, orphan.o,
/// asking the named liveness queries (the wire's v48 tail).
fn request(
    main_bytes: &[u8],
    greet_bytes: &[u8],
    orphan_bytes: &[u8],
    queries: &[&str],
    record: Option<Vec<u8>>,
    prev_output: Option<[u8; 32]>,
) -> LinkRequest {
    LinkRequest {
        config: LinkConfig {
            ident: "why-live-session".into(),
            dead_strip: true,
            ..LinkConfig::default()
        },
        force_load: Vec::new(),
        inputs: vec![
            InputEntry {
                name: "main.o".into(),
                hash: content_hash(main_bytes),
            },
            InputEntry {
                name: "greet.o".into(),
                hash: content_hash(greet_bytes),
            },
            InputEntry {
                name: "orphan.o".into(),
                hash: content_hash(orphan_bytes),
            },
        ],
        archives: Vec::new(),
        record_resolution: true,
        prev_output,
        record,
        audit: false,
        tiles: false,
        time: false,
        trace: false,
        verify: false,
        verify_checks: None,
        why_export: Vec::new(),
        why_load: false,
        map: false,
        why_live: queries.iter().map(|s| (*s).to_string()).collect(),
    }
}

fn store(session: &mut ResidentSession, blobs: &[([u8; 32], Vec<u8>)]) {
    for (hash, bytes) in blobs {
        session
            .store_blob(hash, bytes.clone())
            .expect("the blob stores");
    }
}

fn main() {
    let greet_bytes = leaf_object("greet.o", "_greet")
        .build()
        .expect("greet.o builds");
    let orphan_bytes = leaf_object("orphan.o", "_orphan")
        .build()
        .expect("orphan.o builds");
    let main_bytes = main_object(false).build().expect("main.o builds");
    let edited_bytes = main_object(true).build().expect("the edit builds");

    // The cold link: the strip runs, the queries ride the v48 tail.
    let mut session = ResidentSession::default();
    let cold_req = request(
        &main_bytes,
        &greet_bytes,
        &orphan_bytes,
        &["_greet", "_orphan"],
        None,
        None,
    );
    let main_hash = content_hash(&main_bytes);
    store(
        &mut session,
        &[
            (main_hash, main_bytes.clone()),
            (content_hash(&greet_bytes), greet_bytes.clone()),
            (content_hash(&orphan_bytes), orphan_bytes.clone()),
        ],
    );
    let cold = session.link(&cold_req).expect("the cold link serves");
    let prov = cold.provenance.as_ref().expect("the asked query serves");
    println!("-- the cold link's served chains (wire v48) --");
    for live in &prov.lives {
        print!("{}", live.render);
    }
    assert!(
        prov.lives[0].render.contains("_greet: kept by the strip"),
        "the kept chain answers the query: {}",
        prov.lives[0].render
    );
    assert!(
        prov.lives[0]
            .render
            .contains("rooted at the entry point (-e)"),
        "the chain names the root decision: {}",
        prov.lives[0].render
    );
    assert!(
        prov.lives[1]
            .render
            .contains("_orphan: dropped by the strip"),
        "the dead answer states the verdict: {}",
        prov.lives[1].render
    );

    // The warm relink: the edit adds the call, the replay's own mark
    // record answers *kept* — the verdict flipped with the edit, and the
    // chain names the keeper the new reference introduced.
    let record_bytes = cold
        .record
        .clone()
        .expect("the cold link captures a record");
    let edited_hash = content_hash(&edited_bytes);
    let mut relink = request(
        &edited_bytes,
        &greet_bytes,
        &orphan_bytes,
        &["_orphan"],
        Some(record_bytes),
        Some(content_hash(&cold.image)),
    );
    relink.record_resolution = true;
    store(
        &mut session,
        &[
            (edited_hash, edited_bytes.clone()),
            (content_hash(&cold.image), cold.image.clone()),
        ],
    );
    let warm = session.link(&relink).expect("the warm relink serves");
    let warm_prov = warm.provenance.as_ref().expect("the asked query serves");
    println!("-- the warm relink's served chain (the edit flipped the verdict) --");
    for live in &warm_prov.lives {
        print!("{}", live.render);
    }
    assert!(
        warm_prov.lives[0]
            .render
            .contains("_orphan: kept by the strip"),
        "the replay's own record answers the flipped verdict: {}",
        warm_prov.lives[0].render
    );

    // An unasked query never crosses: the same relink without the ask
    // rides no liveness answer.
    let mut quiet = request(
        &edited_bytes,
        &greet_bytes,
        &orphan_bytes,
        &[],
        warm.record.clone(),
        Some(content_hash(&warm.image)),
    );
    quiet.record_resolution = true;
    let quiet_served = session.link(&quiet).expect("the quiet relink serves");
    assert!(
        quiet_served.provenance.is_none_or(|p| p.lives.is_empty()),
        "an unasked liveness query rides no answer"
    );
    println!("-- the unasked relink rides no liveness answer --");
}

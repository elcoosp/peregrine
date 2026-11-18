//! The served verify verdict, runnable (wire v43, M72): the same session
//! the daemon serves `pgr -resident`, driven directly over a
//! [`ResidentSession`] — a cold full link asking the strict verifier's
//! verdict on the final bytes, then the warm relink whose patched image
//! the session verifies in memory, then the untouched relink whose
//! subject is the resident previous output itself. The reply's IMAGE
//! tail carries the effective report in the M13 interchange form (the
//! `-no_adhoc` carve-out applied the audit's way — the missing-signature
//! shape is the config's own choice, never a defect the verdict names);
//! the verdict is a [`pgr_verify::Report`] on the client side, decoded
//! by the same strict reader the document's writer answers to. An
//! unasked verdict never crosses: the same relink without the flag rides
//! no tail.
//!
//! ```sh
//! cargo run -p pgr-daemon --example verify_session
//! ```

use pgr_core::layout::LinkConfig;
use pgr_daemon::ResidentSession;
use pgr_daemon::protocol::{InputEntry, LinkRequest, content_hash};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::report_json;

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

fn request(hello_bytes: &[u8], greet_bytes: &[u8], verify: bool) -> LinkRequest {
    LinkRequest {
        config: LinkConfig {
            ident: "served-verify-example".into(),
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
        time: false,
        trace: false,
        verify,
        verify_checks: None,
        why_export: Vec::new(),
        why_load: false,
    }
}

fn store(session: &mut ResidentSession, pairs: &[([u8; 32], Vec<u8>)]) {
    for (h, bytes) in pairs {
        session.store_blob(h, bytes.clone()).expect("blob stored");
    }
}

/// Prints the served verdict — the gate's own face, as the reply carried
/// it (the interchange document one line, the stats it describes).
fn print_verdict(label: &str, report: &pgr_verify::Report) {
    let stats = &report.stats;
    println!(
        "-- {label} -- {} issue(s), {} segment(s), {} fixup slot(s), {} hash page(s)",
        report.issues.len(),
        stats.segments,
        stats.fixup_slots,
        stats.hash_pages,
    );
    for issue in &report.issues {
        println!(
            "    {:?} [{}] {}",
            issue.severity,
            issue.code.as_str(),
            issue.message
        );
    }
    println!("    document: {}", report_json::to_json(report));
}

fn main() {
    // The demo runs unobserved by default; `PGR_TRACING=1` installs the
    // house tracing subscriber (the workspace convention — the demo
    // prints its own verdict either way).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt::init();
    }

    let hello_bytes = hello(16 * 1024, false).build().expect("hello.o builds");
    let greet_bytes = greet().build().expect("greet.o builds");

    // The cold full link asking the verdict: the session verifies its own
    // output — the strict pass on the bytes the reply is about to carry.
    let mut session = ResidentSession::default();
    let mut req = request(&hello_bytes, &greet_bytes, true);
    req.record_resolution = true;
    let hello_hash = content_hash(&hello_bytes);
    let greet_hash = content_hash(&greet_bytes);
    store(
        &mut session,
        &[
            (hello_hash, hello_bytes.clone()),
            (greet_hash, greet_bytes.clone()),
        ],
    );
    let cold = session.link(&req).expect("the cold link serves");
    let cold_verdict = cold
        .verify_report
        .as_ref()
        .expect("the served verdict rides the full link");
    print_verdict("the cold link's served verdict", cold_verdict);
    assert!(
        cold_verdict.is_ok(&pgr_verify::Options::default()),
        "the clean link verifies"
    );

    // The warm relink (record + previous output): the ladder patches in
    // memory over the session's POIs, and the verdict answers for the
    // patched bytes — the image the client is about to write.
    let record_bytes = cold
        .record
        .clone()
        .expect("the cold link captures a record");
    let edited = hello(16 * 1024, true).build().expect("the edit builds");
    let mut relink = request(&edited, &greet_bytes, true);
    relink.record = Some(record_bytes);
    relink.prev_output = Some(content_hash(&cold.image));
    let hello_hash2 = content_hash(&edited);
    store(
        &mut session,
        &[
            (hello_hash2, edited.clone()),
            (content_hash(&cold.image), cold.image.clone()),
        ],
    );
    let warm = session.link(&relink).expect("the warm relink serves");
    let warm_verdict = warm
        .verify_report
        .as_ref()
        .expect("the served verdict rides the patched relink");
    print_verdict("the warm relink's served verdict", warm_verdict);
    assert!(
        warm_verdict.is_ok(&pgr_verify::Options::default()),
        "the patched image verifies"
    );

    // The untouched relink asks too: nothing changed, the subject is the
    // resident previous output — the verdict says so again, without the
    // bytes ever re-crossing the wire. The renewed record rides (the
    // cycle's carrier), so the ladder recognizes the state.
    let mut quiet = request(&edited, &greet_bytes, true);
    quiet.record.clone_from(&warm.record);
    quiet.prev_output = Some(content_hash(&warm.image));
    let untouched = session.link(&quiet).expect("the untouched relink serves");
    assert!(
        untouched
            .patch
            .as_ref()
            .expect("the relink plans")
            .untouched,
        "an identical corpus relinks untouched"
    );
    let untouched_verdict = untouched
        .verify_report
        .as_ref()
        .expect("the untouched relink serves its verdict");
    print_verdict("the untouched relink's served verdict", untouched_verdict);

    // An unasked verdict never crosses: the same relink without the flag
    // rides no tail.
    let mut plain = request(&edited, &greet_bytes, false);
    plain.record.clone_from(&untouched.record);
    plain.prev_output = Some(content_hash(&untouched.image));
    let served = session.link(&plain).expect("the plain relink serves");
    assert!(served.verify_report.is_none());
    println!("-- the unasked relink rides no verdict tail --");
}

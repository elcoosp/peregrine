//! The served timing faces, runnable (wire v40/v41, M58–M62): the same
//! session the daemon serves `pgr -resident --time --trace`, driven
//! directly over a [`ResidentSession`] — a cold full link asking both
//! faces, then the warm relink whose served run names the phases the
//! session actually executed (no `Parse` row — the POIs are resident,
//! the parse was paid when the blobs arrived; the relink's Pass-4 half
//! is the in-memory patch, so its emit band rides absent). The reply's
//! IMAGE tail carries the collected report and the rendered timeline
//! verbatim; the strict reader (`pgr_core::trace::parse_trace_json`) is
//! the document's own face and runs here as the round-trip gate. An
//! unasked face never crosses: the same relink without the flags rides
//! no tail.
//!
//! ```sh
//! cargo run -p pgr-daemon --example served_timing_session
//! ```

use pgr_core::layout::LinkConfig;
use pgr_core::trace::parse_trace_json;
use pgr_daemon::ResidentSession;
use pgr_daemon::protocol::{InputEntry, LinkRequest, content_hash};
use pgr_emit::incremental::LinkRecord;
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

fn request(hello_bytes: &[u8], greet_bytes: &[u8], time: bool, trace: bool) -> LinkRequest {
    LinkRequest {
        config: LinkConfig {
            ident: "served-timing-example".into(),
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
        time,
        trace,
        verify: false,
    }
}

fn store(session: &mut ResidentSession, pairs: &[([u8; 32], Vec<u8>)]) {
    for (h, bytes) in pairs {
        session.store_blob(h, bytes.clone()).expect("blob stored");
    }
}

/// Prints the served report's phase rows (the token, the wall) — the
/// table `--time` renders, as the reply carried it.
fn print_report(label: &str, report: &pgr_core::time_report::TimeReport) {
    println!("-- {label} -- ({} phase rows)", report.phases.len());
    for phase in &report.phases {
        println!(
            "    {:<12} {:>8} µs",
            phase.phase.as_str(),
            phase.elapsed.as_micros()
        );
    }
    for note in &report.notes {
        println!("    note: {note}");
    }
}

fn main() {
    let hello_bytes = hello(16 * 1024, false).build().expect("hello.o builds");
    let greet_bytes = greet().build().expect("greet.o builds");

    // The cold full link asking both faces: the session observes its own
    // pipeline — every phase the run executed rides the reply's tails.
    let mut session = ResidentSession::default();
    let mut req = request(&hello_bytes, &greet_bytes, true, true);
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
    let report = cold.time_report.as_ref().expect("the time face rides");
    print_report("the cold link's served report", report);
    let timeline = cold.trace_json.as_deref().expect("the trace face rides");
    let parsed = parse_trace_json(timeline).expect("the served timeline parses");
    println!(
        "-- the cold link's served timeline -- ({} bytes, {} lanes: {})",
        timeline.len(),
        parsed.lanes.len(),
        parsed
            .lanes
            .iter()
            .map(|l| l.name.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    );

    // The warm relink (record + previous output): the ladder patches in
    // memory over the session's POIs — the served run names the phases
    // it actually executed, no Parse row, and the emit band rides absent
    // (the Pass-4 half is the in-memory patch).
    let record_bytes = cold
        .record
        .clone()
        .expect("the cold link captures a record");
    let record = LinkRecord::decode(&record_bytes).expect("the fresh record decodes");
    let edited = hello(16 * 1024, true).build().expect("the edit builds");
    let mut relink = request(&edited, &greet_bytes, true, true);
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
    let warm_report = warm.time_report.as_ref().expect("the warm time face rides");
    print_report("the warm relink's served report", warm_report);
    // M66 (v42 in service): the ladder's rungs ride the served report —
    // the gate, the plan and the patch beside the pipeline's rows (the
    // audit only beside an audited relink).
    for rung in ["relink_gate", "relink_plan", "relink_patch"] {
        assert!(
            warm_report.phases.iter().any(|p| p.phase.as_str() == rung),
            "the {rung} row rides the warm relink's served report"
        );
    }
    assert!(
        warm_report
            .phases
            .iter()
            .all(|p| p.phase.as_str() != "parse"),
        "the warm run's POIs are resident — no Parse row"
    );
    let warm_timeline = warm
        .trace_json
        .as_deref()
        .expect("the warm trace face rides");
    let warm_parsed = parse_trace_json(warm_timeline).expect("the served timeline parses");
    assert!(
        warm_parsed
            .spans
            .iter()
            .all(|s| s.phase.as_str() != "parse"),
        "the served timeline names the run's own phases"
    );

    // An unasked face never crosses: the same relink without the flags
    // rides no tail.
    let mut quiet = request(&edited, &greet_bytes, false, false);
    quiet.record = Some(record.encode());
    quiet.prev_output = Some(content_hash(&warm.image));
    let served = session.link(&quiet).expect("the quiet relink serves");
    assert!(served.time_report.is_none() && served.trace_json.is_none());
    println!("-- the unasked relink rides no tail (both faces absent) --");
}

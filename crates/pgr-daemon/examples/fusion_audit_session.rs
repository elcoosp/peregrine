//! The audited fusion cycle, runnable (M9 GA rung 2, wire v4): the same
//! §7.3 ladder the daemon serves `pgr -resident -incremental
//! -incremental-verify`, driven directly over a [`ResidentSession`] —
//! cold full link with record capture, an edit, then the audited warm
//! relink whose audit verdict (byte-identity + strict verify) crosses the
//! wire as an `AuditOutcome`.
//!
//! ```sh
//! cargo run -p pgr-daemon --example fusion_audit_session
//! ```

use pgr_core::layout::LinkConfig;
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

fn request(hello_bytes: &[u8], greet_bytes: &[u8]) -> (LinkRequest, [u8; 32], [u8; 32]) {
    let req = LinkRequest {
        config: LinkConfig {
            ident: "fusion-audit-example".into(),
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
    };
    (req, content_hash(hello_bytes), content_hash(greet_bytes))
}

fn store(session: &mut ResidentSession, pairs: &[([u8; 32], Vec<u8>)]) {
    for (h, bytes) in pairs {
        session.store_blob(h, bytes.clone()).expect("blob stored");
    }
}

fn main() {
    let hello_bytes = hello(16 * 1024, false).build().expect("hello.o builds");
    let greet_bytes = greet().build().expect("greet.o builds");

    // Cold link: a full link with record capture — the sidecar's birth
    // (the driver does this through the wire; the shape is identical).
    let mut session = ResidentSession::default();
    let (mut req, hello_hash, greet_hash) = request(&hello_bytes, &greet_bytes);
    store(
        &mut session,
        &[
            (hello_hash, hello_bytes.clone()),
            (greet_hash, greet_bytes.clone()),
        ],
    );
    req.record_resolution = true;
    let cold = session.link(&req).expect("the cold link serves");
    let record_bytes = cold.record.clone().expect("the cold link captures");
    let record = LinkRecord::decode(&record_bytes).expect("the fresh record decodes");
    println!(
        "cold full link: {} bytes recorded ({} sections, {} imports)",
        record.file_size,
        record.sections.len(),
        record.imports.len()
    );

    // The edit + audited relink: the §7.3 ladder patches in memory over
    // the session's POIs, audits its bytes against the reference emit and
    // hands the verdict across (wire v4 carries it; here the struct is
    // the same type the client decodes).
    let edited = hello(16 * 1024, true).build().expect("the edit builds");
    let (mut relink, hello_hash2, _) = request(&edited, &greet_bytes);
    relink.record = Some(record_bytes);
    relink.prev_output = Some(content_hash(&cold.image));
    relink.record_resolution = true;
    relink.audit = true;
    store(
        &mut session,
        &[
            (hello_hash2, edited),
            (content_hash(&cold.image), cold.image.clone()),
        ],
    );
    let served = session.link(&relink).expect("the audited relink serves");
    let patch = served.patch.expect("the ladder patches");
    let audit = served.audit.expect("the audit rides the reply");
    println!(
        "audited relink: {} of {} tiles patched ({} bytes), audit: identity_ok={} healed={} verify_ok={}",
        patch.dirty_tiles,
        patch.total_tiles,
        patch.bytes_patched,
        audit.identity_ok,
        audit.healed,
        audit.verify_blocking.is_empty()
    );

    // The example's own smoke gate: the audited bytes are the reference
    // emit of the same plan — the engine contract the audit twins.
    assert!(audit.identity_ok && audit.verify_blocking.is_empty());
    assert!(patch.bytes_patched < served.image.len() as u64);
}

//! M114 — the UUID source at the emit: `-random_uuid` — the emit
//! two-pass patch's random face. The decision is the plan's own echo
//! (`Layout::uuid_source`): `random` draws a fresh `UUIDv4` at emit time
//! (the identity is per-emit, never deterministic — that is the
//! decision's own contract; the `content` face keeps the reproducible
//! derivation), `none` leaves the image uuid-free (the M32 shape, the
//! absent sentinel), and the record (v9) carries the source so the
//! relink ladders admit through it — a source flip is the full link's
//! job, never an in-place identity renegotiation (the M99 pattern).

use pgr_core::layout::{LinkConfig, OutputType, UuidSource};
use pgr_core::link::{LinkInput, link};
use pgr_emit::incremental::{FallbackReason, LinkRecord};
use pgr_emit::tile::build_image_fused;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// hello.o: `_main` (`ret; ret` in `__text`) — the corpus the record
/// tests share.
fn hello() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn inputs() -> Vec<LinkInput> {
    vec![LinkInput {
        name: "hello.o".into(),
        bytes: hello(),
    }]
}

fn cfg(source: UuidSource) -> LinkConfig {
    LinkConfig {
        ident: "hello".into(),
        filetype: OutputType::Execute,
        uuid_source: source,
        ..LinkConfig::default()
    }
}

/// The image's `LC_UUID` slot when the command rides: the uuid field's
/// file offset and the 16 bytes it carries (the M99 read).
fn uuid_slot(image: &[u8]) -> Option<(usize, [u8; 16])> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if let pgr_format::LoadCommandKind::Uuid = cmd.kind {
            let st = pgr_format::UuidCommand::parse(cmd.bytes).expect("the lc parses");
            // The uuid field rides right after the 8-byte command header.
            let off = cmd.offset + 8;
            return Some((off, st.uuid));
        }
    }
    None
}

/// The image's pre-signature prefix with the identity field zeroed —
/// the shape comparison the random face's parity rides. The signature
/// blob is the rest of the file: its page hashes COVER the identity
/// bytes (the §9 content contract — the identity is signed content),
/// so the two emits' blobs differ by the draws' own hashes, a pure
/// function of the 16 identity bytes; the prefix is where the shape
/// lives.
fn identity_zeroed_prefix(image: &[u8], sig_off: u64) -> Vec<u8> {
    let mut copy = image[..sig_off as usize].to_vec();
    if let Some((off, _)) = uuid_slot(&copy) {
        copy[off..off + 16].fill(0);
    }
    copy
}

#[test]
fn the_random_identity_is_fresh_per_emit() {
    // Two emits over the SAME plan draw two different identities — the
    // source is the decision, the value is the emit's own (never a
    // deterministic derivation). Both draws are whole UUIDv4 values
    // (the version and variant bits set) and non-zero.
    let r = link(&inputs(), &[], &cfg(UuidSource::Random)).expect("the link plans");
    let image_a = build_image_fused(&r.layout, &r.objects).expect("the first image emits");
    let image_b = build_image_fused(&r.layout, &r.objects).expect("the second image emits");
    let (off_a, a) = uuid_slot(&image_a).expect("the first image carries the command");
    let (off_b, b) = uuid_slot(&image_b).expect("the second image carries the command");
    assert_ne!(a, b, "the random identity is fresh per emit");
    assert_ne!(a, [0u8; 16], "the draw never lands on the zero identity");
    assert_eq!(
        a[6] >> 4,
        4,
        "the version nibble names UUIDv4 (the RFC 4122 form)"
    );
    assert_eq!(
        a[8] >> 6,
        0b10,
        "the variant bits name the RFC 4122 reserved form"
    );
    assert_eq!(off_a, off_b, "the identity field's offset never moves");
    // Everything but the identity bytes is byte-identical: the decision
    // shapes the image's identity, never its layout. The signature blob
    // (beyond the prefix) carries the draws' own page hashes — the
    // identity is signed content, the blob a pure function of it.
    let sig_off = r.layout.linkedit.sig_off;
    assert_eq!(
        identity_zeroed_prefix(&image_a, sig_off),
        identity_zeroed_prefix(&image_b, sig_off),
        "the two random images differ only in the 16 identity bytes (the blob's hashes \
         are their own pure function)"
    );
    assert_eq!(image_a.len(), image_b.len(), "the file size never moves");
}

#[test]
fn the_content_face_stays_deterministic() {
    // The default's reproducible-builds contract rides unchanged (the
    // M32 pattern): the same corpus derives the same identity twice.
    let r1 = link(&inputs(), &[], &cfg(UuidSource::Content)).expect("the first links");
    let r2 = link(&inputs(), &[], &cfg(UuidSource::Content)).expect("the second links");
    let image_a = build_image_fused(&r1.layout, &r1.objects).expect("the first image emits");
    let image_b = build_image_fused(&r2.layout, &r2.objects).expect("the second image emits");
    assert_eq!(
        image_a, image_b,
        "the content face is deterministic (the reproducible-builds contract)"
    );
}

#[test]
fn the_none_face_emits_no_uuid_command() {
    // The M32 shape: the suppressed image carries no LC_UUID command at
    // all — the emit has no field to patch and the hashes hash the
    // bytes as they are.
    let r = link(&inputs(), &[], &cfg(UuidSource::None)).expect("the suppression plans");
    let image = build_image_fused(&r.layout, &r.objects).expect("the suppressed image emits");
    assert!(
        uuid_slot(&image).is_none(),
        "the suppressed image carries no LC_UUID command"
    );
    assert_eq!(
        r.layout.linkedit.uuid_at, 0,
        "the plan names the absent sentinel"
    );
}

#[test]
fn record_v9_carries_the_uuid_source() {
    // The record rides the plan's echo — one source, no re-derivation —
    // and the codec is lossless over the whole alphabet.
    for source in [UuidSource::Content, UuidSource::Random, UuidSource::None] {
        let r = link(&inputs(), &[], &cfg(source)).expect("the link plans");
        let image = build_image_fused(&r.layout, &r.objects).expect("the image emits");
        let record = LinkRecord::record(&r.layout, &r.objects, &image, None).unwrap();
        assert_eq!(
            record.uuid_source, source,
            "the record carries the decision the plan echoed ({source:?})"
        );
        let decoded = LinkRecord::decode(&record.encode()).expect("the v9 record decodes");
        assert_eq!(
            decoded.uuid_source, source,
            "the codec is lossless over the source ({source:?})"
        );
    }
}

#[test]
fn the_record_admits_its_own_source_and_refuses_a_flip() {
    // The relink ladder's source admission (the M99 named pattern): a
    // record admits the config whose source matches its own and refuses
    // a flip with the source fallback reason — the patch cannot
    // renegotiate the image's identity shape in place.
    let r_content = link(&inputs(), &[], &cfg(UuidSource::Content)).expect("the content plans");
    let image_content =
        build_image_fused(&r_content.layout, &r_content.objects).expect("the content image emits");
    let record =
        LinkRecord::record(&r_content.layout, &r_content.objects, &image_content, None).unwrap();
    assert!(
        record.admits(&cfg(UuidSource::Content)).is_ok(),
        "a config naming the record's own source is admitted"
    );
    for flipped in [UuidSource::Random, UuidSource::None] {
        let reason = record
            .admits(&cfg(flipped))
            .expect_err("a source flip refuses (the identity is the record's own shape)");
        assert!(
            matches!(reason, FallbackReason::UuidSource { .. }),
            "the refusal names the source move: {reason}"
        );
    }
}

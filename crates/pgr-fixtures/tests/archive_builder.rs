//! M5 archive-builder gates: `pgr_fixtures::ArchiveBuilder` emits
//! deterministic libtool-style archives that the `pgr-format` parser reads
//! back — members in order, name-sorted ranlib table, identical bytes on
//! every build.

use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectSection, ObjectSymbol};

/// a.o defines `_alpha`; b.o defines `_beta`. The archive carries both
/// members and a name-sorted index resolving each symbol to its member.
#[test]
fn archive_of_fixture_objects_round_trips() {
    let mut a = ObjectBuilder::new("a.o");
    let t = a.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    a.add_symbol(ObjectSymbol::Defined {
        name: "_alpha".into(),
        section_index: t,
        value: 0,
        weak: false,
    });
    let mut b = ObjectBuilder::new("b.o");
    let t2 = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_beta".into(),
        section_index: t2,
        value: 0,
        weak: false,
    });

    let mut arch = ArchiveBuilder::new("libfoo.a");
    arch.add_member("a.o", a.build().unwrap());
    arch.add_member("b.o", b.build().unwrap());
    let bytes = arch.build();

    let parsed = pgr_format::parse_archive(&bytes).unwrap();
    assert_eq!(
        parsed
            .members
            .iter()
            .map(|m| m.name.as_str())
            .collect::<Vec<_>>(),
        vec!["a.o", "b.o"]
    );
    assert_eq!(
        parsed.index,
        vec![
            pgr_format::ArchiveIndexEntry {
                name: "_alpha".into(),
                member: 0
            },
            pgr_format::ArchiveIndexEntry {
                name: "_beta".into(),
                member: 1
            },
        ]
    );

    // Determinism: the same build is byte-identical.
    let mut arch2 = ArchiveBuilder::new("libfoo.a");
    arch2.add_member("a.o", a.build().unwrap());
    arch2.add_member("b.o", b.build().unwrap());
    assert_eq!(bytes, arch2.build());
}

/// The index is name-sorted across members and covers every defined external
/// symbol per member (a member defining two symbols appears twice).
#[test]
fn index_is_sorted_and_covers_every_defined_symbol() {
    let mut z = ObjectBuilder::new("z.o");
    let t = z.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    z.add_symbol(ObjectSymbol::Defined {
        name: "_zeta".into(),
        section_index: t,
        value: 0,
        weak: false,
    });
    z.add_symbol(ObjectSymbol::Defined {
        name: "_apple".into(),
        section_index: t,
        value: 0,
        weak: false,
    });
    let mut b = ObjectBuilder::new("b.o");
    let t2 = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_beta".into(),
        section_index: t2,
        value: 0,
        weak: false,
    });
    // Undefined-only references never enter the index.
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_external_ref".into(),
        weak_ref: false,
    });

    let mut arch = ArchiveBuilder::new("libz.a");
    arch.add_member("z.o", z.build().unwrap());
    arch.add_member("b.o", b.build().unwrap());
    let parsed = pgr_format::parse_archive(&arch.build()).unwrap();

    let names: Vec<(&str, u32)> = parsed
        .index
        .iter()
        .map(|e| (e.name.as_str(), e.member))
        .collect();
    assert_eq!(names, vec![("_apple", 0), ("_beta", 1), ("_zeta", 0)]);
}

#[test]
fn empty_archive_builds_and_parses() {
    let arch = ArchiveBuilder::new("libempty.a");
    let parsed = pgr_format::parse_archive(&arch.build()).unwrap();
    assert_eq!(parsed.members, [] as [pgr_format::ArchiveMember; 0]);
    assert_eq!(parsed.index, [] as [pgr_format::ArchiveIndexEntry; 0]);
}

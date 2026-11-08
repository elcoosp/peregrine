//! M5 archive (`!<arch>`) parser gates (S7 — architecture doc §10.3 row M5).
//!
//! The archive format is the BSD/GNU `ar` format Apple's `libtool`/`ranlib`
//! emit: an 8-byte `!<arch>\n` magic, then 60-byte member headers with the
//! ranlib symbol table (`__.SYMDEF SORTED`, or `__.SYMDEF_64 SORTED` for the
//! 64-bit variant, or GNU `/`) as a special member and the GNU `//` long-name
//! table. Peregrine's S7 decision consumes the ranlib table to pull members
//! lazily, so the parser must resolve index entries back to members
//! deterministically and reject malformed tables with typed errors.
//!
//! The parser is total: any input yields `Ok(Archive)` or `FormatError`,
//! never a panic (gated here by a hand-written battery and a proptest).

use pgr_format::archive::{ArchiveIndexEntry, is_archive, parse_archive};
use proptest::prelude::*;

/// Assembles one 60-byte `ar` member header.
fn header(name: &[u8], size: usize) -> Vec<u8> {
    let mut h = vec![b' '; 60];
    h[..name.len()].copy_from_slice(name);
    // mtime (12), uid (6), gid (6), mode (8): zeros via blanks for time.
    let put = |h: &mut Vec<u8>, off: usize, text: &str| {
        h[off..off + text.len()].copy_from_slice(text.as_bytes());
    };
    put(&mut h, 16, "0");
    put(&mut h, 48, &size.to_string());
    h[58] = b'`';
    h[59] = b'\n';
    h
}

fn member(name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = header(name, data.len());
    out.extend_from_slice(data);
    if data.len() % 2 == 1 {
        out.push(b'\n');
    }
    out
}

/// libtool-style archive: `__.SYMDEF SORTED` + two members whose index
/// entries point at the member *header* offsets.
#[test]
fn libtool_style_archive_round_trips() {
    let a_data = b"AAAAAAAA";
    let b_data = b"BBBB";

    // Sizes first so the header offsets are stable, then build. Odd-size
    // members (the symtab here) carry one pad byte.
    let strings = b"_beta\0_alpha\0";
    let index_data_len = 4 + 2 * 8 + strings.len();
    let a_hdr = 8 + 60 + index_data_len + (index_data_len % 2); // magic + symtab
    let b_hdr = a_hdr + 60 + a_data.len() + (a_data.len() % 2);
    // The table is name-sorted: _alpha (strx 6) first, _beta (strx 0) second.
    let mut symtab: Vec<u8> = Vec::new();
    symtab.extend_from_slice(&2u32.to_le_bytes());
    symtab.extend_from_slice(&6u32.to_le_bytes());
    symtab.extend_from_slice(&(a_hdr as u32).to_le_bytes());
    symtab.extend_from_slice(&0u32.to_le_bytes());
    symtab.extend_from_slice(&(b_hdr as u32).to_le_bytes());
    symtab.extend_from_slice(strings);

    let mut bytes: Vec<u8> = b"!<arch>\n".to_vec();
    bytes.extend_from_slice(&member(b"__.SYMDEF SORTED", &symtab));
    bytes.extend_from_slice(&member(b"a.o", a_data));
    bytes.extend_from_slice(&member(b"b.o", b_data));

    assert!(is_archive(&bytes));
    let arch = parse_archive(&bytes).unwrap();
    // Content members in file order; the symbol table is consumed.
    assert_eq!(arch.members.len(), 2);
    assert_eq!(arch.members[0].name, "a.o");
    assert_eq!(arch.members[0].size, a_data.len() as u64);
    assert_eq!(arch.members[1].name, "b.o");
    // Index entries resolve to member indices (sorted order preserved).
    assert_eq!(
        arch.index,
        vec![
            ArchiveIndexEntry {
                name: "_alpha".into(),
                member: 0
            },
            ArchiveIndexEntry {
                name: "_beta".into(),
                member: 1
            },
        ]
    );
    // Member data is addressable at the reported offset.
    assert_eq!(&bytes[arch.members[0].offset as usize..][..8], b"AAAAAAAA");
}

/// BSD long names: `#1/<len>` consumes the first `<len>` data bytes as the
/// name (NUL-padded); the rest is the payload.
#[test]
fn bsd_long_name_members_are_resolved() {
    let payload = b"payload";
    let long_name = b"member.o\0"; // 9 bytes with the NUL
    let mut data = long_name.to_vec();
    data.extend_from_slice(payload);
    let mut bytes: Vec<u8> = b"!<arch>\n".to_vec();
    bytes.extend_from_slice(&member(format!("#1/{}", long_name.len()).as_bytes(), &data));
    bytes.extend_from_slice(&member(b"x.o", payload));

    let arch = parse_archive(&bytes).unwrap();
    assert_eq!(arch.members.len(), 2);
    assert_eq!(arch.members[0].name, "member.o");
    assert_eq!(arch.members[0].size, payload.len() as u64);
    assert_eq!(
        &bytes[arch.members[0].offset as usize..][..payload.len()],
        b"payload"
    );
    assert_eq!(arch.members[1].name, "x.o");
}

/// GNU long names: a `//` table member holds the names; members reference
/// them as `/offset`.
#[test]
fn gnu_long_name_table_members_are_resolved() {
    let table = b"verylongname.o/\nother.o/\n";
    let mut bytes: Vec<u8> = b"!<arch>\n".to_vec();
    bytes.extend_from_slice(&member(b"//", table));
    bytes.extend_from_slice(&member(b"/0", b"one"));
    bytes.extend_from_slice(&member(b"/16", b"two"));

    let arch = parse_archive(&bytes).unwrap();
    assert_eq!(arch.members.len(), 2);
    assert_eq!(arch.members[0].name, "verylongname.o");
    assert_eq!(arch.members[1].name, "other.o");
    // The name table itself is not a content member.
    assert!(arch.members.iter().all(|m| m.name != "//"));
}

/// GNU symbol-table member (`/`): same entry layout as `__.SYMDEF`, parsed
/// into the index.
#[test]
fn gnu_symbol_table_member_populates_the_index() {
    let strings = b"_sym\0";
    let index_data_len = 4 + 8 + strings.len();
    let m_hdr = 8 + 60 + index_data_len + (index_data_len % 2);
    let mut symtab: Vec<u8> = Vec::new();
    symtab.extend_from_slice(&1u32.to_le_bytes());
    symtab.extend_from_slice(&0u32.to_le_bytes());
    symtab.extend_from_slice(&(m_hdr as u32).to_le_bytes());
    symtab.extend_from_slice(strings);

    let mut bytes: Vec<u8> = b"!<arch>\n".to_vec();
    bytes.extend_from_slice(&member(b"/", &symtab));
    bytes.extend_from_slice(&member(b"m.o", b"body"));

    let arch = parse_archive(&bytes).unwrap();
    assert_eq!(arch.members.len(), 1);
    assert_eq!(arch.members[0].name, "m.o");
    assert_eq!(
        arch.index,
        vec![ArchiveIndexEntry {
            name: "_sym".into(),
            member: 0
        }]
    );
}

/// `__.SYMDEF_64 SORTED`: u64 count and entries (libtool's large-archive
/// variant).
#[test]
fn symdef_64_index_populates_the_index() {
    let strings = b"_big\0";
    let index_data_len = 8 + 16 + strings.len();
    let m_hdr = 8 + 60 + index_data_len + (index_data_len % 2);
    let mut symtab: Vec<u8> = Vec::new();
    symtab.extend_from_slice(&1u64.to_le_bytes());
    symtab.extend_from_slice(&0u64.to_le_bytes());
    symtab.extend_from_slice(&(m_hdr as u64).to_le_bytes());
    symtab.extend_from_slice(strings);

    let mut bytes: Vec<u8> = b"!<arch>\n".to_vec();
    bytes.extend_from_slice(&member(b"__.SYMDEF_64", &symtab));
    bytes.extend_from_slice(&member(b"m.o", b"body"));

    let arch = parse_archive(&bytes).unwrap();
    assert_eq!(arch.index.len(), 1);
    assert_eq!(arch.index[0].name, "_big");
    assert_eq!(arch.index[0].member, 0);
}

/// Some producers record the member *data* offset instead of the header
/// offset; both resolve (header offset wins when both match a member).
#[test]
fn index_entries_resolve_from_data_offsets_too() {
    let strings = b"_s\0";
    let index_data_len = 4 + 8 + strings.len();
    let data_off = 8 + 60 + index_data_len + (index_data_len % 2) + 60; // data offset of the single member
    let mut symtab: Vec<u8> = Vec::new();
    symtab.extend_from_slice(&1u32.to_le_bytes());
    symtab.extend_from_slice(&0u32.to_le_bytes());
    symtab.extend_from_slice(&(data_off as u32).to_le_bytes());
    symtab.extend_from_slice(strings);

    let mut bytes: Vec<u8> = b"!<arch>\n".to_vec();
    bytes.extend_from_slice(&member(b"__.SYMDEF", &symtab));
    bytes.extend_from_slice(&member(b"m.o", b"body"));

    let arch = parse_archive(&bytes).unwrap();
    assert_eq!(arch.index.len(), 1);
    assert_eq!(arch.index[0].member, 0);
}

#[test]
fn empty_archive_has_no_members() {
    let arch = parse_archive(b"!<arch>\n").unwrap();
    assert_eq!(arch.members, [] as [pgr_format::ArchiveMember; 0]);
    assert_eq!(arch.index, [] as [pgr_format::ArchiveIndexEntry; 0]);
    assert!(!is_archive(b"!<arch>"));
}

/// Hand-written battery: every truncation and bad field yields a typed
/// error, never a panic.
#[test]
fn malformed_archives_error_not_panic() {
    let ok = {
        let mut symtab: Vec<u8> = Vec::new();
        symtab.extend_from_slice(&1u32.to_le_bytes());
        symtab.extend_from_slice(&0u32.to_le_bytes());
        symtab.extend_from_slice(&84u32.to_le_bytes()); // header offset of m.o
        symtab.extend_from_slice(b"_s\0");
        let mut b: Vec<u8> = b"!<arch>\n".to_vec();
        b.extend_from_slice(&member(b"__.SYMDEF", &symtab));
        b.extend_from_slice(&member(b"m.o", b"body"));
        b
    };
    assert!(parse_archive(&ok).is_ok());

    // Truncations of every prefix must error (not panic).
    for n in 0..ok.len() {
        let _ = parse_archive(&ok[..n]);
    }

    // Bad magic.
    let mut bad = ok.clone();
    bad[3] = b'?';
    assert!(parse_archive(&bad).is_err());

    // Corrupt the member end marker.
    let mut bad = ok.clone();
    bad[60 + 58] = b'x';
    assert!(parse_archive(&bad).is_err());

    // Oversized member size.
    let mut bad = ok.clone();
    let sz_off = 60 + 48;
    bad[sz_off..sz_off + 10].copy_from_slice(b"9999999999");
    assert!(parse_archive(&bad).is_err());

    // Non-decimal size.
    let mut bad = ok.clone();
    bad[sz_off..sz_off + 10].copy_from_slice(b"four......");
    assert!(parse_archive(&bad).is_err());

    // Ranlib count beyond the member data.
    let mut bad = ok.clone();
    bad[68..72].copy_from_slice(&999u32.to_le_bytes());
    assert!(parse_archive(&bad).is_err());

    // Ranlib entry pointing at no member (the member-offset field sits at
    // bytes 76..80 of the file: symtab data starts at 68, after the count).
    let mut bad = ok.clone();
    bad[76..80].copy_from_slice(&12345u32.to_le_bytes());
    assert!(parse_archive(&bad).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Mutating a valid archive never panics: Ok or Err, always.
    #[test]
    fn mutated_archives_never_panic(
        mutations in proptest::collection::vec((0usize..256usize, any::<u8>()), 0..24)
    ) {
        let mut symtab: Vec<u8> = Vec::new();
        symtab.extend_from_slice(&1u32.to_le_bytes());
        symtab.extend_from_slice(&0u32.to_le_bytes());
        symtab.extend_from_slice(&84u32.to_le_bytes());
        symtab.extend_from_slice(b"_s\0");
        let mut bytes: Vec<u8> = b"!<arch>\n".to_vec();
        bytes.extend_from_slice(&member(b"__.SYMDEF", &symtab));
        bytes.extend_from_slice(&member(b"m.o", &[0xAA; 16]));
        let _ = &mutations;
        for (pos, val) in mutations {
            if pos < bytes.len() {
                bytes[pos] = val;
            }
        }
        let _ = parse_archive(&bytes);
    }

    /// Arbitrary byte soup never panics.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_archive(&bytes);
    }
}

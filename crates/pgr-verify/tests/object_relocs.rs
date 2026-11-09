//! M10 rung 1 — the verifier's relocatable-object gates: relocation
//! entries on `MH_OBJECT` are bounds-checked (against the section they
//! ride and the symbol table they name), chained fixups and classic dyld
//! info are refused on objects, and a well-formed object stays clean.

use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options, Severity, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

fn one_reloc_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("clean.o");
    b.add_section(ObjectSection::text(
        "__text",
        vec![0x94, 0x00, 0x00, 0x00], // bl _ext
        vec![ObjectReloc::branch26(1).at(0)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_ext".into(),
        weak_ref: false,
    });
    b.build().unwrap()
}

#[test]
fn a_well_formed_object_is_clean_under_strict() {
    let bytes = one_reloc_object();
    let report = verify(&bytes, &opts());
    assert!(
        report.issues.is_empty(),
        "fixtures-built objects carry the whole contract: {:?}",
        report.issues
    );
}

#[test]
fn an_extern_entry_past_the_symtab_is_named() {
    // Tamper the single relocation entry's r_symbolnum to 0xFFFF (the
    // symtab has 2 entries). The reloc table sits right after the
    // section-data blob: header (32 + 72 + 80*1 + 24 = 208) + blob (4).
    let mut bytes = one_reloc_object();
    let entry_at = 208 + 4;
    let word1_off = entry_at + 4;
    let mut info = u32::from_le_bytes(bytes[word1_off..word1_off + 4].try_into().unwrap());
    assert_eq!(info & 0xF, 2, "the tampered entry is the BRANCH26");
    info = (info & 0xFF00_0000) | 0x00FF_FFFF | 0x0600_0000; // keep pcrel+len+extern, symbolnum 0xFFFFFF
    bytes[word1_off..word1_off + 4].copy_from_slice(&info.to_le_bytes());
    let report = verify(&bytes, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.severity == Severity::Error && i.code.as_str() == "symbol_table"),
        "the out-of-range extern entry must be named: {:?}",
        report.issues
    );
}

#[test]
fn a_section_ordinal_past_the_section_table_is_named() {
    // !extern entries name 1-based section ordinals; this object has one
    // section, so ordinal 7 is out of range.
    let mut bytes = one_reloc_object();
    let entry_at = 208 + 4;
    let word1_off = entry_at + 4;
    let mut info = u32::from_le_bytes(bytes[word1_off..word1_off + 4].try_into().unwrap());
    info = (info & !0x0800_0000) | 0x0600_0000 | 7; // drop r_extern, ordinal 7
    bytes[word1_off..word1_off + 4].copy_from_slice(&info.to_le_bytes());
    let report = verify(&bytes, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.severity == Severity::Error && i.code.as_str() == "symbol_table"),
        "the out-of-range section ordinal must be named: {:?}",
        report.issues
    );
}

#[test]
fn chained_fixups_are_refused_on_an_object() {
    // Hand-assembled: header | LC_SEGMENT_64 (0 sections) |
    // LC_DYLD_CHAINED_FIXUPS (16-byte linkedit-data header). Objects never
    // carry fixups — dyld never loads them.
    let mut buf = vec![0u8; 32 + 72 + 16];
    let w32 = |buf: &mut Vec<u8>, at: usize, v: u32| {
        buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    };
    w32(&mut buf, 0, pgr_format::consts::MH_MAGIC_64);
    w32(&mut buf, 4, pgr_format::consts::CPU_TYPE_ARM64);
    w32(&mut buf, 8, pgr_format::consts::CPU_SUBTYPE_ARM64_ALL);
    w32(&mut buf, 12, pgr_format::consts::MH_OBJECT);
    w32(&mut buf, 16, 2); // ncmds
    w32(&mut buf, 20, 72 + 16); // sizeofcmds
    w32(&mut buf, 32, pgr_format::consts::LC_SEGMENT_64);
    w32(&mut buf, 36, 72);
    w32(&mut buf, 64, 0); // nsects
    w32(&mut buf, 104, pgr_format::consts::LC_DYLD_CHAINED_FIXUPS);
    w32(&mut buf, 108, 16);
    w32(&mut buf, 112, 0); // dataoff
    w32(&mut buf, 116, 0); // datasize
    let report = verify(&buf, &opts());
    assert!(
        report.issues.iter().any(|i| i.severity == Severity::Error),
        "chained fixups on MH_OBJECT must be refused: {:?}",
        report.issues
    );
}

//! M10 rung 4, slice 5 — the auth slots ride the import table: the
//! builder's fixup import table used to collect plain `SlotKind::Bind`
//! entries only, so an arm64e fixture whose `__got` carries an
//! authenticated bind refused with "bind name missing from import
//! table", and the indirect symbol table match predates the auth slot
//! kinds entirely. The gates: an auth-bind-only image builds, its
//! import table carries the bind (table addend 0 — the auth bind word
//! has no addend field), the payload re-parses through the format layer
//! with the ordinal in place, the words decode back through the arm64e
//! codec, and an auth-rebase-plus-auth-bind image keeps both shapes.

use pgr_fixtures::{
    ImageBuilder, PointerFormatKind, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    DYLD_CHAINED_IMPORT, DYLD_CHAINED_PTR_ARM64E, LC_DYLD_CHAINED_FIXUPS, PLATFORM_MACOS,
    S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_format::fixups::{parse_header, parse_imports, parse_starts_in_image, ChainWordArm64e};
use pgr_format::{LinkeditDataCommand, LoadCommandIter, LoadCommandKind, MachHeader64};

fn text_segment(bytes_len: usize) -> SegmentSpec {
    SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xA5A5, bytes_len),
            relocs: Vec::new(),
        }],
    }
}

fn data_const_segment() -> SegmentSpec {
    SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    }
}

/// An arm64e executable whose only fixup slot is an authenticated bind.
/// The pre-slice-5 builder refused this shape at `build()` — the import
/// table collected plain binds only.
fn auth_bind_only() -> pgr_fixtures::Image {
    let mut b = ImageBuilder::executable("auth-bind-only");
    b.add_segment(text_segment(96));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![SlotKind::AuthBind {
        sym_index: sym,
        diversity: 0x4321,
        addr_div: false,
        key: 0,
    }]);
    b.set_entry(0x40);
    b.set_pointer_format(PointerFormatKind::Arm64e);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    b.build().expect("the auth-bind-only fixture builds")
}

/// The fixup payload bytes of a built image (located through
/// `LC_DYLD_CHAINED_FIXUPS` by hand — the test rides the format layer,
/// not the builder's trust).
fn fixup_payload(image: &pgr_fixtures::Image) -> Vec<u8> {
    let bytes = &image.bytes;
    let header = MachHeader64::parse(bytes).expect("the fixture header parses");
    let mut it = LoadCommandIter::new(
        bytes,
        MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command walk holds") {
        if cmd.kind == LoadCommandKind::LinkeditData(LC_DYLD_CHAINED_FIXUPS) {
            let lc = LinkeditDataCommand::parse(cmd.bytes).expect("the payload command parses");
            let at = lc.dataoff as usize;
            return bytes[at..at + lc.datasize as usize].to_vec();
        }
    }
    panic!("the fixture carries LC_DYLD_CHAINED_FIXUPS");
}

#[test]
fn an_auth_bind_only_image_builds_and_registers_its_import() {
    let img = auth_bind_only();
    // The builder's recorded import table carries the auth bind.
    assert_eq!(img.map.imports.len(), 1, "the auth bind registers its import");
    assert_eq!(
        img.map.imports[0].lib_ordinal, 1,
        "the bind rides its dylib ordinal"
    );
    assert!(!img.map.imports[0].weak_import, "a plain undefined binds strong");
    assert_eq!(
        img.map.imports[0].addend, 0,
        "auth binds carry no table addend (the word has no addend field)"
    );

    // The payload re-parses through the format layer and agrees.
    let payload = fixup_payload(&img);
    let hdr = parse_header(&payload).expect("the payload header parses");
    assert_eq!(
        hdr.imports_format, DYLD_CHAINED_IMPORT,
        "the default import format rides Plain"
    );
    let imports = parse_imports(&payload, &hdr).expect("the import table parses");
    assert_eq!(imports.len(), 1, "one import entry");
    assert_eq!(imports[0].lib_ordinal, 1, "the ordinal lands in the payload");

    // The segment record names the arm64e family.
    let starts = parse_starts_in_image(&payload, hdr.starts_offset as usize)
        .expect("the starts-in-image record parses");
    let mut formats = Vec::new();
    for &off in &starts.seg_info_offset {
        if off == 0 {
            continue;
        }
        let rec_at = hdr.starts_offset as usize + off as usize;
        formats.push(u16::from_le_bytes(
            payload[rec_at + 6..rec_at + 8].try_into().unwrap(),
        ));
    }
    assert!(
        formats.contains(&DYLD_CHAINED_PTR_ARM64E),
        "the segment record names the arm64e family: {formats:?}"
    );

    // The slot word decodes as an auth bind with the recorded ordinal.
    let addr = img.map.got_slot_addrs[0];
    let at = (addr - 0x1_0000_0000) as usize;
    let raw = u64::from_le_bytes(img.bytes[at..at + 8].try_into().unwrap());
    let word = ChainWordArm64e::new(raw);
    assert!(word.is_bind() && word.is_auth(), "the slot is an auth bind");
    assert_eq!(word.bind_ordinal(), 0, "first-use ordinal 0");
    assert_eq!(word.auth_diversity(), 0x4321, "the PAC triple rides the word");
}

#[test]
fn an_auth_rebase_plus_auth_bind_image_keeps_both_shapes() {
    let mut b = ImageBuilder::executable("auth-mix");
    b.add_segment(text_segment(96));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![
        SlotKind::AuthRebase {
            offset: 0x40,
            diversity: 0x1234,
            addr_div: true,
            key: 2,
        },
        SlotKind::AuthBind {
            sym_index: sym,
            diversity: 0x4321,
            addr_div: false,
            key: 0,
        },
    ]);
    b.set_entry(0x40);
    b.set_pointer_format(PointerFormatKind::Arm64e);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    let img = b.build().expect("the mixed auth fixture builds");

    // Exactly one import (the bind; the rebase is not an import), and
    // both slot words decode back through the arm64e codec.
    assert_eq!(img.map.imports.len(), 1, "only the bind is an import");
    for (i, addr) in img.map.got_slot_addrs.iter().enumerate() {
        let at = (addr - 0x1_0000_0000) as usize;
        let raw = u64::from_le_bytes(img.bytes[at..at + 8].try_into().unwrap());
        let word = ChainWordArm64e::new(raw);
        match i {
            0 => assert!(!word.is_bind() && word.is_auth(), "slot 0 is the auth rebase"),
            1 => assert!(word.is_bind() && word.is_auth(), "slot 1 is the auth bind"),
            other => panic!("unexpected slot {other}"),
        }
    }
}

#[test]
fn a_plain_bind_image_is_unchanged() {
    // The regression guard: the plain-bind path (the M2 shape) keeps its
    // import-table behavior — inline addend, first-use ordinal.
    let mut b = ImageBuilder::executable("plain-bind");
    b.add_segment(text_segment(96));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![SlotKind::Bind {
        sym_index: sym,
        addend: 7,
    }]);
    b.set_entry(0x40);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    let img = b.build().expect("the plain-bind fixture builds");
    assert_eq!(img.map.imports.len(), 1, "the plain bind registers its import");
    assert_eq!(img.map.imports[0].addend, 0, "Plain keeps the addend inline");
    let payload = fixup_payload(&img);
    let hdr = parse_header(&payload).expect("the payload header parses");
    let imports = parse_imports(&payload, &hdr).expect("the import table parses");
    assert_eq!(imports.len(), 1, "one import entry");
}

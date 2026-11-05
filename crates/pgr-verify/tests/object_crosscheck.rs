//! Independent second-opinion parse: the `object` crate must see the same
//! image structure our format layer sees (TDD §11 three-opinion cross-check;
//! LLVM tools are the third opinion on macOS hardware, out of scope here).

use object::read::macho::MachOFile;
use object::{Endianness, Object, ObjectSection, ObjectSymbol};
use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler};
use pgr_format::consts::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};

#[test]
fn object_crate_agrees_with_our_parse() {
    let mut b = ImageBuilder::executable("crosscheck");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: pgr_format::consts::S_REGULAR | pgr_format::consts::S_ATTR_PURE_INSTRUCTIONS,
            data: filler(11, 64),
            relocs: Vec::new(),
        }],
    });
    b.add_segment(SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    });
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![SlotKind::Bind {
        sym_index: sym,
        addend: 0,
    }]);
    b.set_entry(0x40);
    let img = b.build().unwrap();

    let obj: MachOFile<object::macho::MachHeader64<Endianness>, &[u8]> =
        MachOFile::parse(&img.bytes[..]).expect("object crate must parse our fixture");

    // Header agreement.
    assert_eq!(obj.endianness(), Endianness::Little);
    assert_eq!(obj.architecture(), object::Architecture::Aarch64);

    // Sections agree (name and size) with the fixture map.
    let obj_sections: Vec<(String, u64)> = obj
        .sections()
        .filter_map(|s| {
            let name = s.name().ok()?.to_string();
            Some((name, s.size()))
        })
        .collect();
    for expected in &img.map.sections {
        let hit = obj_sections
            .iter()
            .any(|(name, size)| name == &expected.name && *size == expected.size);
        assert!(
            hit,
            "object crate must see section {expected:?} among {obj_sections:?}"
        );
    }

    // Symbols agree.
    let obj_syms: Vec<String> = obj
        .symbols()
        .filter_map(|s| s.name().ok().map(str::to_string))
        .collect();
    assert!(obj_syms.contains(&"_printf".to_string()), "{obj_syms:?}");
}

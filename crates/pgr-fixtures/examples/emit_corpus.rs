//! Emits deterministic valid Mach-O fixtures into a directory, used to seed
//! the cargo-fuzz corpus (see .github/workflows/fuzz.yml). M1 adds
//! relocatable-object seeds for the `link_object` target.
//!
//! Usage: `cargo run -p pgr-fixtures --example emit_corpus -- <dir>`

use std::path::PathBuf;

use pgr_fixtures::{
    ImageBuilder, ImportsFormat, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol,
    SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};

fn text_segment(seed: u64, kib: usize) -> SegmentSpec {
    SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(seed, kib * 1024),
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

fn main() {
    let dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("fuzz/corpus"));
    std::fs::create_dir_all(&dir).expect("corpus dir");

    let mut b = ImageBuilder::executable("fuzz-seed-exec");
    b.add_segment(text_segment(1, 4));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![
        SlotKind::Bind {
            sym_index: sym,
            addend: 0,
        },
        SlotKind::Rebase { target: 0x40 },
    ]);
    b.set_entry(0x40);
    let exec = b.build().expect("exec seed");
    std::fs::write(dir.join("exec_bind_rebase"), &exec.bytes).expect("write seed");

    let mut b = ImageBuilder::dylib("@rpath/libfuzzseed.dylib", "fuzz-seed-dylib");
    b.add_segment(text_segment(2, 2));
    b.add_symbol(SymbolSpec::Defined {
        name: "_fuzz_seed_init".into(),
        section_index: 0,
    });
    let dylib = b.build().expect("dylib seed");
    std::fs::write(dir.join("dylib_export"), &dylib.bytes).expect("write seed");

    let mut b = ImageBuilder::executable("fuzz-seed-fmt3");
    b.add_segment(text_segment(3, 2));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_putchar".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_imports_format(ImportsFormat::Addend64);
    b.set_got(vec![SlotKind::Bind {
        sym_index: sym,
        addend: 5,
    }]);
    let exec3 = b.build().expect("format-3 seed");
    std::fs::write(dir.join("exec_imports_addend64"), &exec3.bytes).expect("write seed");

    // M1: relocatable-object seeds for the link_object fuzz target — a
    // small hello-shaped pair exercising every supported relocation kind.
    let mut main_o = ObjectBuilder::new("seed_main.o");
    let text = main_o.add_section(ObjectSection::text(
        "__text",
        [
            0x9000_0000u32, // adrp x0, msg@page
            0x9100_0000u32, // add x0, x0, msg@pageoff
            0x9400_0000u32, // bl greet
            0x5280_0000u32, // mov w0, #0
            0xD65F_03C0u32, // ret
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect(),
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12(1).at(4),
            ObjectReloc::branch26(2).at(8),
        ],
    ));
    main_o.add_section(ObjectSection::cstring("hello\n"));
    main_o.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    main_o.add_symbol(ObjectSymbol::Defined {
        name: "_msg".into(),
        section_index: 1,
        value: 0,
        weak: false,
    });
    main_o.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    std::fs::write(dir.join("seed_main.o"), main_o.build().expect("main seed"))
        .expect("write seed");

    let mut greet_o = ObjectBuilder::new("seed_greet.o");
    let greet_text = greet_o.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        Vec::new(),
    ));
    let data = greet_o.add_section(ObjectSection::data("__data", vec![0u8; 8], Vec::new()));
    greet_o
        .section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(0).at(0));
    greet_o.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: greet_text,
        value: 0,
        weak: false,
    });
    std::fs::write(
        dir.join("seed_greet.o"),
        greet_o.build().expect("greet seed"),
    )
    .expect("write seed");

    println!(
        "wrote 3 seed images + 2 seed objects into {}",
        dir.display()
    );
}

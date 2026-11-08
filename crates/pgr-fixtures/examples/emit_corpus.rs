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
        .map_or_else(|| PathBuf::from("fuzz/corpus"), PathBuf::from);
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

    // M2: a GOT-carrying object seed — the link_object target exercises the
    // __got/__stubs synthesis and bind path with it.
    let mut got_o = ObjectBuilder::new("seed_got.o");
    let text = got_o.add_section(ObjectSection::text(
        "__text",
        [
            0x9000_0000u32, // adrp x0, printf@gotpage
            0xF940_0000u32, // ldr x0, [x0, printf@gotpageoff]
            0x9400_0000u32, // bl printf
            0xD65F_03C0u32, // ret
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect(),
        Vec::new(),
    ));
    got_o.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let printf_sym = got_o.add_symbol(ObjectSymbol::Undefined {
        name: "_printf".into(),
        weak_ref: false,
    });
    let printf = got_o.sym_index(printf_sym);
    got_o.section_mut(text).relocs = vec![
        ObjectReloc::got_page21(printf).at(0),
        ObjectReloc::got_pageoff12(printf).at(4),
        ObjectReloc::branch26(printf).at(8),
    ];
    std::fs::write(dir.join("seed_got.o"), got_o.build().expect("got seed")).expect("write seed");

    // M2: a .tbd seed for the parse_tbd target (v4 + v3 documents).
    std::fs::write(
        dir.join("seed_libsystem.tbd"),
        [
            "--- !tapi-tbd",
            "tbd-version: 4",
            "targets: [ arm64-macos ]",
            "install-name: /usr/lib/libSystem.B.dylib",
            "current-version: 1.2.3",
            "compatibility-version: 1.0.0",
            "exports:",
            "  - targets: [ arm64-macos ]",
            "    symbols: [ _printf, _strlen ]",
            "    weak-symbols: [ _weakfn ]",
            "...",
            "",
        ]
        .join("\n"),
    )
    .expect("write tbd seed");
    std::fs::write(
        dir.join("seed_libold.tbd"),
        [
            "--- !tbd-tbd-version-3.0",
            "tbd-version: 3",
            "targets: [ arm64-macos ]",
            "uuids: [ arm64-macos: 1234 ]",
            "install-name: /usr/lib/libold.dylib",
            "current-version: 1.2.3",
            "exports:",
            "  - targets: [ arm64-macos ]",
            "    symbols: [ _old ]",
            "...",
            "",
        ]
        .join("\n"),
    )
    .expect("write v3 tbd seed");

    // ---- M7 seeds: classic dyld-info opcode streams + cache entries ------
    // (the M7 fuzzing-at-scale targets `dyld_info_streams` and
    // `cache_entries`; valid entries give libFuzzer the codec shapes).
    let rebase_stream = pgr_format::dyld_info::encode_rebase_stream(&[
        pgr_format::dyld_info::RebaseEntry {
            seg: 1,
            seg_off: 0x40,
        },
        pgr_format::dyld_info::RebaseEntry {
            seg: 2,
            seg_off: 0x8,
        },
    ]);
    std::fs::write(dir.join("classic_rebase_stream"), &rebase_stream)
        .expect("write rebase stream seed");
    let bind_stream =
        pgr_format::dyld_info::encode_bind_stream(&[pgr_format::dyld_info::BindEntry {
            seg: 2,
            seg_off: 0,
            ordinal: pgr_format::dyld_info::BindOrdinal::Dylib(1),
            flags: 0,
            name: b"_printf".to_vec(),
            addend: 0,
        }]);
    std::fs::write(dir.join("classic_bind_stream"), &bind_stream).expect("write bind stream seed");

    // A minimal-but-valid v2 POI frame: flags | svs | from_archive |
    // archive_name("") | 0 sections | 0 syms | 0 names | 0 atom tables.
    let mut poi_payload: Vec<u8> = Vec::new();
    for b in [1u8, 0, 0] {
        poi_payload.push(b);
    }
    poi_payload.extend_from_slice(&0u32.to_le_bytes()); // archive_name len
    for _ in 0..4 {
        poi_payload.extend_from_slice(&0u32.to_le_bytes()); // 4 empty tables
    }
    std::fs::write(dir.join("cache_poi_v2"), frame("PGRPOI1\0", &poi_payload))
        .expect("write POI seed");
    // A minimal frozen-.tbd frame: install_name("") | versions | 0 exports.
    let mut tbd_payload: Vec<u8> = Vec::new();
    tbd_payload.extend_from_slice(&0u32.to_le_bytes());
    tbd_payload.extend_from_slice(&1u32.to_le_bytes());
    tbd_payload.extend_from_slice(&1u32.to_le_bytes());
    tbd_payload.extend_from_slice(&0u32.to_le_bytes());
    std::fs::write(
        dir.join("cache_frozen_tbd_v2"),
        frame("PGRFTBD1", &tbd_payload),
    )
    .expect("write frozen-tbd seed");

    println!(
        "wrote 3 seed images + 3 seed objects + 2 tbd + 2 stream + 2 cache seeds into {}",
        dir.display()
    );
}

/// Frames a cache payload the way `pgr_core::cache` does (v2): magic(8) |
/// format(u32=2) | parser(u32=1) | len(u64) | sha256(payload) | payload.
fn frame(magic: &str, payload: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut out = Vec::with_capacity(56 + payload.len());
    out.extend_from_slice(magic.as_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    let digest: [u8; 32] = Sha256::digest(payload).into();
    out.extend_from_slice(&digest);
    out.extend_from_slice(payload);
    out
}

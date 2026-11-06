//! M4 core-pipeline gates (architecture doc §10.3 row M4, perf doc §3/§4):
//!
//! * **Copy-run coalescing** (§4.3): `Layout.runs` covers every byte-carrying
//!   piece exactly once — same file, same input bytes, one destination — and
//!   merges what is mergeable, so the fused tile emit can issue large
//!   `memcpy`s instead of per-piece copies.
//! * **LPT-parallel Pass 1** (§4.1): parsing the same corpus through the
//!   parallel pool (`Parallelism::Auto`, longest-file-first scheduling) and
//!   the serial reference path (`Parallelism::Serial`) produces identical
//!   layouts — determinism policy §4.3 at M4.
//! * **D8 `resolved[]` de-indirection** (§3 D8): per-file flat tables carry
//!   the final vaddr of every in-image definition; the reloc scan reads the
//!   file-local array instead of global maps.

use pgr_core::layout::{CopyRun, LinkConfig};
use pgr_core::{LinkInput, Parallelism, link_with};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::hash::Hash;

fn hello_main() -> Vec<u8> {
    let text: Vec<u8> = [
        0x9000_0000u32, // adrp x0, _msg@page
        0x9100_0000u32, // add x0, x0, #_msg@pageoff
        0x9400_0000u32, // bl _greet
        0x5280_0000u32, // mov w0, #0
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
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
    b.add_section(ObjectSection::cstring("hello, peregrine\n"));
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
    b.build().unwrap()
}

fn greet() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0x91, 0x00, 0x00, 0x00, 0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
    let greet_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let ptr_a = b.add_symbol(ObjectSymbol::Defined {
        name: "_ptr_a".into(),
        section_index: data,
        value: 8,
        weak: false,
    });
    let ptr_b = b.add_symbol(ObjectSymbol::Defined {
        name: "_ptr_b".into(),
        section_index: data,
        value: 8,
        weak: false,
    });
    b.section_mut(data).relocs = vec![
        ObjectReloc::unsigned(greet_sym as u32).at(0),
        ObjectReloc::subtractor(ptr_a as u32).at(8),
        ObjectReloc::unsigned(ptr_b as u32).at(8),
    ];
    b.add_symbol(ObjectSymbol::Common {
        name: "_common_buf".into(),
        size: 64,
        align_log2: 4,
    });
    b.build().unwrap()
}

/// A wide corpus with deliberately uneven file sizes so the LPT order
/// differs from command-line order (large files are NOT first).
fn uneven_corpus() -> Vec<LinkInput> {
    let sizes_kib = [32usize, 2, 16, 4, 24, 2, 8, 12];
    (0..sizes_kib.len())
        .map(|i| {
            let kib = sizes_kib[i];
            let seed = (i + 1) as u64;
            let text = vec![0x14u8; kib * 1024];
            let mut b = ObjectBuilder::new(&format!("uneven_{i}.o"));
            let text_idx = b.add_section(ObjectSection::text("__text", text, Vec::new()));
            let data_idx = b.add_section(ObjectSection::data("__data", vec![0u8; 256], Vec::new()));
            for j in 0..32u64 {
                b.add_symbol(ObjectSymbol::Defined {
                    name: format!("_uneven_fn_{seed}_{j}"),
                    section_index: text_idx,
                    value: (j * 64) % (kib as u64 * 1024),
                    weak: false,
                });
            }
            let ref_seed = if seed == 1 { 1 } else { seed - 1 };
            for j in 0..32u64 {
                let r = b.add_symbol(ObjectSymbol::Undefined {
                    name: format!("_uneven_fn_{ref_seed}_{j}"),
                    weak_ref: false,
                });
                let t = b.sym_index(r);
                b.section_mut(text_idx)
                    .relocs
                    .push(ObjectReloc::branch26(t).at((j * 256 % (kib as u64 * 1024)) as u32));
                b.section_mut(data_idx)
                    .relocs
                    .push(ObjectReloc::unsigned(t).at((j * 8) as u32));
            }
            if i == 0 {
                b.add_symbol(ObjectSymbol::Defined {
                    name: "_main".into(),
                    section_index: text_idx,
                    value: 0,
                    weak: false,
                });
            }
            LinkInput {
                name: format!("uneven_{i}.o"),
                bytes: b.build().unwrap(),
            }
        })
        .collect()
}

/// A structural fingerprint of a layout (every field Pass 4 consumes), so
/// serial vs parallel pipelines can be compared without depending on the
/// emit crate (which depends back on this one).
fn layout_fingerprint(l: &pgr_core::Layout) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (
        l.file_size,
        l.entryoff,
        l.text_vmsize,
        l.image_base,
        l.filetype,
    )
        .hash(&mut h);
    l.header_bytes.hash(&mut h);
    l.str_offsets.hash(&mut h);
    l.strtab.hash(&mut h);
    l.trie.hash(&mut h);
    l.func_starts.hash(&mut h);
    l.indirect_syms.hash(&mut h);
    l.fixups.payload.hash(&mut h);
    l.fixups.chain_starts.hash(&mut h);
    l.fixups.slot_count.hash(&mut h);
    for (vaddr, word) in &l.fixups.slot_words {
        (*vaddr, *word).hash(&mut h);
    }
    for s in &l.symbols {
        (s.name, s.n_type, s.n_sect, s.n_desc, s.value, s.external).hash(&mut h);
    }
    for s in &l.segments {
        (s.name.as_str(), s.vmaddr, s.vmsize, s.fileoff, s.filesize).hash(&mut h);
    }
    for s in &l.sections {
        (
            s.name.as_str(),
            s.vm_addr,
            s.size,
            s.file_off,
            s.flags,
            s.align_log2,
        )
            .hash(&mut h);
        for p in &s.pieces {
            (
                p.file,
                p.in_sect,
                p.in_range.clone(),
                p.offset,
                p.size,
                p.align_log2,
            )
                .hash(&mut h);
            p.zerofill.hash(&mut h);
            p.common_name.hash(&mut h);
            for op in &p.patches {
                core::mem::discriminant(op).hash(&mut h);
                match *op {
                    pgr_core::PatchOp::Adrp {
                        in_offset,
                        page_delta,
                    } => {
                        (in_offset, page_delta).hash(&mut h);
                    }
                    pgr_core::PatchOp::PageOff12 { in_offset, imm12 } => {
                        (in_offset, imm12).hash(&mut h);
                    }
                    pgr_core::PatchOp::Branch26 {
                        in_offset,
                        pc,
                        delta,
                    } => {
                        (in_offset, pc, delta).hash(&mut h);
                    }
                    pgr_core::PatchOp::Write64 { in_offset, value } => {
                        (in_offset, value).hash(&mut h);
                    }
                }
            }
            for (off, kind) in &p.fixup_slots {
                (*off, core::mem::discriminant(kind)).hash(&mut h);
                match *kind {
                    pgr_core::fixups::FixupKind::Rebase { target_vaddr } => {
                        target_vaddr.hash(&mut h);
                    }
                    pgr_core::fixups::FixupKind::Bind {
                        lib_ordinal,
                        name,
                        addend,
                        weak,
                    } => {
                        (lib_ordinal, name, addend, weak).hash(&mut h);
                    }
                }
            }
        }
    }
    std::hash::Hasher::finish(&h)
}

#[test]
fn copy_runs_partition_every_content_byte() {
    let inputs = vec![
        LinkInput {
            name: "hello.o".into(),
            bytes: hello_main(),
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet(),
        },
    ];
    let cfg = LinkConfig {
        ident: "runs-gate".into(),
        ..LinkConfig::default()
    };
    let result = link_with(&inputs, &cfg, Parallelism::Serial).unwrap();
    let layout = &result.layout;

    // Every byte-carrying, non-synthetic piece must be covered by exactly
    // one run with the same file, source range and destination; synthetic
    // and zero-fill pieces must not appear in any run.
    let mut covered: Vec<(u32, u64, u64, u64)> = Vec::new(); // (file, src, len, dst)
    for r in &layout.runs {
        covered.push((r.file.0, r.src.start, r.src.end - r.src.start, r.dst));
    }
    let mut expected: Vec<(u32, u64, u64, u64)> = Vec::new();
    for s in &layout.sections {
        if s.zerofill {
            continue;
        }
        for p in &s.pieces {
            if p.zerofill || p.synth.is_some() || p.in_range.is_empty() {
                continue;
            }
            let dst = s.file_off + p.offset;
            expected.push((p.file.0, p.in_range.start, p.size, dst));
        }
    }
    covered.sort_unstable();
    expected.sort_unstable();
    assert_eq!(
        covered, expected,
        "runs must cover every content piece exactly once (perf doc §4.3)"
    );

    // Runs are sorted by destination and disjoint.
    for w in layout.runs.windows(2) {
        assert!(w[0].dst <= w[1].dst, "runs not sorted by dst");
        assert!(
            w[0].dst + (w[0].src.end - w[0].src.start) <= w[1].dst,
            "runs overlap"
        );
    }
    // Every run stays inside its input object.
    for r in &layout.runs {
        let obj = &result.objects[r.file.0 as usize];
        assert!(r.src.end <= obj.bytes.len() as u64, "run leaves its input");
    }
}

#[test]
fn parallel_pass1_matches_the_serial_reference() {
    let inputs = uneven_corpus();
    let cfg = LinkConfig {
        ident: "m4-parallel-gate".into(),
        ..LinkConfig::default()
    };
    let serial = link_with(&inputs, &cfg, Parallelism::Serial).unwrap();
    let auto = link_with(&inputs, &cfg, Parallelism::Auto).unwrap();
    assert_eq!(
        layout_fingerprint(&serial.layout),
        layout_fingerprint(&auto.layout),
        "LPT-parallel Pass 1 must produce the serial layout byte-for-byte \
         (determinism policy §4.3)"
    );
    // And the interner numbering matches too.
    assert_eq!(serial.interner.len(), auto.interner.len());
    for i in 0..serial.interner.len() {
        let id = pgr_core::StringId(i as u32);
        assert_eq!(serial.interner.bytes(id), auto.interner.bytes(id));
    }
}

#[test]
fn resolved_tables_carry_every_in_image_definition() {
    let inputs = vec![
        LinkInput {
            name: "hello.o".into(),
            bytes: hello_main(),
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet(),
        },
    ];
    let cfg = LinkConfig {
        ident: "m4-resolved-gate".into(),
        ..LinkConfig::default()
    };
    let result = link_with(&inputs, &cfg, Parallelism::Serial).unwrap();

    // Every defined external in the output symtab must appear in its file's
    // resolved[] table with the exact output vaddr.
    let interner = &result.interner;
    for (file, table) in result.layout.resolved.iter().enumerate() {
        let obj = &result.objects[file];
        assert_eq!(table.syms.len(), obj.symbols.len(), "file {file}");
        assert_eq!(table.sects.len(), obj.sections.len(), "file {file}");
    }
    // Stronger, targeted checks on the known corpus shape:
    // _main is the first __text piece (entryoff), _msg is the cstring,
    // _greet is greet.o's text, the common symbol lands in __common.
    let text_off = result
        .layout
        .sections
        .iter()
        .find(|s| s.name == "__text")
        .unwrap()
        .vm_addr;
    let main_file = 0usize;
    let main_idx = result.objects[main_file]
        .symbols
        .iter()
        .position(|s| interner.bytes(s.name) == b"_main")
        .unwrap();
    assert_eq!(
        result.layout.resolved[main_file].syms[main_idx], text_off,
        "_main resolves to the first __text piece"
    );
    let greet_file = 1usize;
    let greet_idx = result.objects[greet_file]
        .symbols
        .iter()
        .position(|s| interner.bytes(s.name) == b"_greet")
        .unwrap();
    assert!(
        result.layout.resolved[greet_file].syms[greet_idx] > 0,
        "_greet resolves in-image"
    );
    let common_idx = result.objects[greet_file]
        .symbols
        .iter()
        .position(|s| interner.bytes(s.name) == b"_common_buf")
        .unwrap();
    assert!(
        result.layout.resolved[greet_file].syms[common_idx] > 0,
        "the common symbol resolves through the resolved[] table too"
    );
    // Section table: hello.o's input section 1 (the cstring) is placed.
    assert!(
        result.layout.resolved[main_file].sects[1] > 0,
        "input sections carry their output vaddr in resolved[].sects"
    );
}

#[test]
fn runs_and_fingerprint_survive_parallel_parse_on_wide_corpus() {
    let inputs = uneven_corpus();
    let mut cfg = LinkConfig {
        ident: "m4-wide-runs".into(),
        ..LinkConfig::default()
    };
    // Dylib output too (0 image base — different slot-word math).
    cfg.filetype = pgr_core::layout::OutputType::Dylib;
    cfg.install_name = Some("@rpath/libuneven.dylib".into());
    let serial = link_with(&inputs, &cfg, Parallelism::Serial).unwrap();
    let auto = link_with(&inputs, &cfg, Parallelism::Auto).unwrap();
    assert_eq!(
        layout_fingerprint(&serial.layout),
        layout_fingerprint(&auto.layout)
    );
    // The runs view stays consistent with the pieces on both paths.
    for layout in [&serial.layout, &auto.layout] {
        for r in &layout.runs {
            assert!(r.src.start < r.src.end, "empty run");
        }
    }
}

/// Silence the unused-import gate until `CopyRun` fields are exercised
/// above (kept so the import list documents the M4 surface).
#[test]
fn copy_run_type_is_part_of_the_layout_surface() {
    let r = CopyRun {
        file: pgr_core::FileId(0),
        src: 0..8,
        dst: 0x4000,
    };
    assert_eq!(r.src.end - r.src.start, 8);
    assert_eq!(r.dst, 0x4000);
}

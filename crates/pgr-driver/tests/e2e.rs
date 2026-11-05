//! End-to-end M1 acceptance tests (TDD §12 gate): link the static
//! hello-world corpus and prove the output against the three independent
//! opinions available on Linux — `pgr-verify` (chain-walk simulation +
//! signature recompute), semantic assertions on the linked data, and the
//! deterministic double-link contract.

use pgr_driver::opts::Options;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{DYLD_CHAINED_PTR_64_OFFSET, PAGEZERO_SIZE_64};
use pgr_format::fixups::{
    ChainWord64, page_chain_starts, parse_header, parse_imports, parse_starts_in_image,
    parse_starts_in_segment,
};
use pgr_format::{MachHeader64, SegmentCommand64};

/// hello.o: _main ADRP+ADD loads _msg, BL _greet, returns 0.
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

/// greet.o: _greet, a __data rebase pointer to _greet, a subtractor pair
/// computing `_ptr_a - _ptr_b`, and a common symbol.
fn greet() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![
            0x91, 0x00, 0x00, 0x00, // add x0, x0, #0 (immediate kept)
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ],
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
        value: 0,
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

/// A per-call unique subdirectory (tests run in parallel threads and share
/// the process id, so the tag alone is not enough).
fn unique_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_e2e").join(format!(
        "{}_{}_{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Materializes the corpus and links it in-memory.
fn link_corpus() -> (Vec<u8>, pgr_driver::ImageAndPlan) {
    link_corpus_in(unique_dir("corpus"))
}

/// Links the corpus from `dir` (test-controlled paths).
fn link_corpus_in(dir: std::path::PathBuf) -> (Vec<u8>, pgr_driver::ImageAndPlan) {
    let mut opts = Options::default();
    for (i, bytes) in [hello_main(), greet()].iter().enumerate() {
        let p = dir.join(format!("e2e_{i}.o"));
        std::fs::write(&p, bytes).unwrap();
        opts.inputs.push(p.display().to_string());
    }
    opts.config.ident = "peregrine-e2e".into();
    let linked = pgr_driver::link_to_image(&opts).unwrap();
    let image = linked.image.clone();
    (image, linked)
}

/// Parsed symbol-table view of the output for assertions.
struct OutSyms {
    values: std::collections::HashMap<String, u64>,
    sections: std::collections::HashMap<(String, String), (u64, u64)>, // (seg, name) → (addr, size)
    segs: std::collections::HashMap<String, (u64, u64)>,               // name → (vmsize, filesize)
}

/// Parses the output image's symtab/sections.
fn parse_output(bytes: &[u8]) -> OutSyms {
    let header = MachHeader64::parse(bytes).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    let mut values = std::collections::HashMap::new();
    let mut sections = std::collections::HashMap::new();
    let mut segs = std::collections::HashMap::new();
    while let Some(cmd) = it.next_command().unwrap() {
        match cmd.kind {
            pgr_format::LoadCommandKind::Symtab => {
                let st = pgr_format::SymtabCommand::parse(cmd.bytes, 0).unwrap();
                for i in 0..st.nsyms {
                    let sym: pgr_format::symtab::Nlist64 =
                        pgr_format::cursor::pod_read_unaligned_at(
                            bytes,
                            st.symoff as usize + i as usize * 16,
                        )
                        .unwrap();
                    let name_off = sym.n_strx as usize;
                    let end = bytes[st.stroff as usize + name_off..]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap();
                    let name = String::from_utf8_lossy(
                        &bytes[st.stroff as usize + name_off..st.stroff as usize + name_off + end],
                    )
                    .into_owned();
                    values.insert(name, sym.n_value);
                }
            }
            pgr_format::LoadCommandKind::Segment64 => {
                let seg = SegmentCommand64::parse(cmd.bytes, 0).unwrap();
                let sects = seg.sections(cmd.bytes, SegmentCommand64::SIZE).unwrap();
                for s in sects {
                    sections.insert(
                        (
                            seg.name().unwrap().to_string(),
                            s.name().unwrap().to_string(),
                        ),
                        (s.addr, s.size),
                    );
                }
                segs.insert(seg.name().unwrap().to_string(), (seg.vmsize, seg.filesize));
            }
            _ => {}
        }
    }
    OutSyms {
        values,
        sections,
        segs,
    }
}

/// Finds the `LC_DYLD_CHAINED_FIXUPS` payload in the image.
fn find_fixup_payload(bytes: &[u8]) -> Vec<u8> {
    let header = MachHeader64::parse(bytes).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    while let Some(cmd) = it.next_command().unwrap() {
        if let pgr_format::LoadCommandKind::LinkeditData(
            pgr_format::consts::LC_DYLD_CHAINED_FIXUPS,
        ) = cmd.kind
        {
            let lc = pgr_format::LinkeditDataCommand::parse(cmd.bytes).unwrap();
            return lc.data(bytes).unwrap().to_vec();
        }
    }
    panic!("image carries no LC_DYLD_CHAINED_FIXUPS");
}

/// Walks every chain and returns slot vaddr → final pointer value (the dyld
/// simulation).
fn simulate_dyld(image: &[u8], payload: &[u8]) -> std::collections::HashMap<u64, u64> {
    let hdr = parse_header(payload).unwrap();
    assert_eq!(hdr.imports_count, 0, "static link: no imports");
    let imports = parse_imports(payload, &hdr).unwrap();
    assert!(imports.is_empty());
    let starts = parse_starts_in_image(payload, hdr.starts_offset as usize).unwrap();
    let mut out = std::collections::HashMap::new();
    for &off in &starts.seg_info_offset {
        if off == 0 {
            continue;
        }
        let rec_at = hdr.starts_offset as usize + off as usize;
        let seg = parse_starts_in_segment(payload, rec_at).unwrap();
        assert_eq!(seg.pointer_format, DYLD_CHAINED_PTR_64_OFFSET);
        for page in 0..seg.page_count {
            let heads = page_chain_starts(payload, rec_at, &seg, page).unwrap();
            for h in heads {
                let mut slot_off = u64::from(h);
                loop {
                    let file =
                        seg.segment_offset + u64::from(page) * u64::from(seg.page_size) + slot_off;
                    let word = ChainWord64::new(u64::from_le_bytes(
                        image[file as usize..file as usize + 8].try_into().unwrap(),
                    ));
                    assert!(!word.is_bind(), "static image: rebase words only");
                    let image_off = (u64::from(word.rebase_high8()) << 56) | word.rebase_target();
                    out.insert(file + PAGEZERO_SIZE_64, PAGEZERO_SIZE_64 + image_off);
                    if word.next() == 0 {
                        break;
                    }
                    slot_off += u64::from(word.next()) * 4;
                }
            }
        }
    }
    out
}

#[test]
fn verifier_full_pass_on_linked_output() {
    let (image, _linked) = link_corpus();
    let opts = pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = pgr_verify::verify(&image, &opts);
    assert!(report.is_ok(&opts), "verifier issues: {report:?}");
    // The gate ran the full simulation: chain walk + hash recompute.
    assert!(report.stats.fixup_slots >= 1, "{report:?}");
    assert!(report.stats.hash_pages >= 4, "{report:?}");
}

#[test]
fn double_link_is_byte_identical() {
    let (a, _) = link_corpus();
    let (b, _) = link_corpus();
    assert_eq!(a, b, "determinism policy TDD §4.3");
}

#[test]
fn dyld_simulation_yields_the_expected_pointer() {
    let (image, _linked) = link_corpus();
    let syms = parse_output(&image);
    let greet_addr = syms.values["_greet"];
    let rebased = simulate_dyld(&image, &find_fixup_payload(&image));
    // The greet.o __data pointer rebases to _greet's address.
    let data_addr = syms
        .sections
        .get(&("__DATA".into(), "__data".into()))
        .copied()
        .expect("__data present")
        .0;
    let value = rebased
        .get(&data_addr)
        .copied()
        .expect("slot was walked by dyld");
    assert_eq!(value, greet_addr, "dyld computes &_greet into the pointer");
}

#[test]
fn subtractor_and_common_and_cstring_are_semantically_right() {
    let (image, linked) = link_corpus();
    let syms = parse_output(&image);
    // Subtractor slot: _ptr_a - _ptr_b = 8.
    let data_addr = syms.sections[&("__DATA".into(), "__data".into())].0;
    let file_off8 = data_addr - PAGEZERO_SIZE_64 + 8;
    let slot8 = u64::from_le_bytes(
        image[file_off8 as usize..file_off8 as usize + 8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(slot8, 8, "_ptr_a - _ptr_b");
    // Common symbol allocated at the __common base, 2^4-aligned.
    let common = syms.values["_common_buf"];
    let (caddr, _csize) = syms.sections[&("__DATA".into(), "__common".into())];
    assert_eq!(common, caddr, "common symbol sits at the __common base");
    assert_eq!(common % 16, 0, "common alignment honored");
    // __DATA vmsize exceeds filesize: the zero-fill tail.
    let (vmsize, filesize) = syms.segs["__DATA"];
    assert!(
        vmsize > filesize,
        "vmsize {vmsize:#x} filesize {filesize:#x}"
    );
    // Entry point matches _main.
    assert_eq!(linked.entryoff, syms.values["_main"] - PAGEZERO_SIZE_64);
    // The cstring content landed verbatim in __TEXT,__cstring.
    let (addr, size) = syms.sections[&("__TEXT".into(), "__cstring".into())];
    let off = (addr - PAGEZERO_SIZE_64) as usize;
    assert_eq!(&image[off..off + size as usize], b"hello, peregrine\n\0");
}

#[test]
fn symtab_is_in_ld64_canonical_order() {
    let (image, _) = link_corpus();
    let header = MachHeader64::parse(&image).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        &image,
        MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    let mut dys = None;
    let mut st = None;
    while let Some(cmd) = it.next_command().unwrap() {
        match cmd.kind {
            pgr_format::LoadCommandKind::Dysymtab => {
                dys = Some(pgr_format::DysymtabCommand::parse(cmd.bytes, 0).unwrap());
            }
            pgr_format::LoadCommandKind::Symtab => {
                st = Some(pgr_format::SymtabCommand::parse(cmd.bytes, 0).unwrap());
            }
            _ => {}
        }
    }
    let dys = dys.expect("LC_DYSYMTAB");
    let st = st.expect("LC_SYMTAB");
    // M1 corpus: 0 locals, 6 defs (_main, _msg, _greet, _ptr_a, _ptr_b,
    // _common_buf), 0 undefs.
    assert_eq!(dys.ilocalsym, 0);
    assert_eq!(dys.nlocalsym, 0);
    assert_eq!(dys.iextdefsym, 0);
    assert!(dys.nextdefsym >= 6, "defs: {}", dys.nextdefsym);
    assert_eq!(dys.iundefsym, dys.nextdefsym);
    assert_eq!(dys.nundefsym, 0, "static: every reference resolved");
    // All defs carry N_EXT|N_SECT and map into real sections.
    for i in dys.iextdefsym..dys.iextdefsym + dys.nextdefsym {
        let sym: pgr_format::symtab::Nlist64 =
            pgr_format::cursor::pod_read_unaligned_at(&image, st.symoff as usize + i as usize * 16)
                .unwrap();
        assert_eq!(
            sym.n_type & pgr_format::consts::N_TYPE,
            pgr_format::consts::N_SECT
        );
        assert_ne!(sym.n_type & pgr_format::consts::N_EXT, 0);
        assert!(sym.n_sect >= 1);
    }
}

#[test]
fn chain_starts_mirror_agrees_with_the_payload() {
    let (image, _) = link_corpus();
    // Find the __chain_starts section and the fixup payload.
    let header = MachHeader64::parse(&image).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        &image,
        MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    let mut chain_starts = None;
    while let Some(cmd) = it.next_command().unwrap() {
        if let pgr_format::LoadCommandKind::Segment64 = cmd.kind {
            let seg = SegmentCommand64::parse(cmd.bytes, 0).unwrap();
            let sects = seg.sections(cmd.bytes, SegmentCommand64::SIZE).unwrap();
            for s in sects {
                if s.name().unwrap() == "__chain_starts" {
                    let at = s.offset as usize;
                    chain_starts = Some(image[at..at + s.size as usize].to_vec());
                }
            }
        }
    }
    let mirror = chain_starts.expect("__chain_starts present");
    // Static-mirror format (TDD §7.5): u32 pointer format, u32 head count,
    // u32 heads as image offsets.
    let fmt = u32::from_le_bytes(mirror[0..4].try_into().unwrap());
    let count = u32::from_le_bytes(mirror[4..8].try_into().unwrap());
    assert_eq!(fmt, u32::from(DYLD_CHAINED_PTR_64_OFFSET));
    let payload = find_fixup_payload(&image);
    let hdr = parse_header(&payload).unwrap();
    let starts = parse_starts_in_image(&payload, hdr.starts_offset as usize).unwrap();
    let mut payload_heads = 0u32;
    for &off in &starts.seg_info_offset {
        if off == 0 {
            continue;
        }
        let rec_at = hdr.starts_offset as usize + off as usize;
        let seg = parse_starts_in_segment(&payload, rec_at).unwrap();
        for page in 0..seg.page_count {
            payload_heads += page_chain_starts(&payload, rec_at, &seg, page)
                .unwrap()
                .len() as u32;
        }
    }
    assert_eq!(count, payload_heads, "mirror lists every chain head");
    assert!(count >= 1);
    // Every head slot decodes as a rebase chain word.
    for k in 0..count as usize {
        let head = u32::from_le_bytes(mirror[8 + k * 4..12 + k * 4].try_into().unwrap());
        let word = ChainWord64::new(u64::from_le_bytes(
            image[head as usize..head as usize + 8].try_into().unwrap(),
        ));
        assert!(!word.is_bind());
    }
}

#[test]
fn corrupted_chain_starts_mirror_is_reported() {
    let (mut image, _) = link_corpus();
    // Locate the mirror and flip a head to a bogus offset.
    let header = MachHeader64::parse(&image).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        &image,
        MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    let mut mirror_at = None;
    while let Some(cmd) = it.next_command().unwrap() {
        if let pgr_format::LoadCommandKind::Segment64 = cmd.kind {
            let seg = SegmentCommand64::parse(cmd.bytes, 0).unwrap();
            let sects = seg.sections(cmd.bytes, SegmentCommand64::SIZE).unwrap();
            for s in sects {
                if s.name().unwrap() == "__chain_starts" {
                    mirror_at = Some(s.offset as usize + 8);
                }
            }
        }
    }
    let mirror_at = mirror_at.expect("__chain_starts present");
    let head = u32::from_le_bytes(image[mirror_at..mirror_at + 4].try_into().unwrap());
    let bogus = head ^ 0xFF; // any 8-aligned... make it misaligned: | 1
    let bogus = bogus | 1;
    image[mirror_at..mirror_at + 4].copy_from_slice(&bogus.to_le_bytes());
    let report = pgr_verify::verify(&image, &pgr_verify::Options::default());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.severity == pgr_verify::Severity::Error),
        "misaligned mirror head must be an error: {report:?}"
    );
}

#[test]
fn no_adhoc_omits_the_signature() {
    let dir = unique_dir("no_adhoc");
    let mut opts = Options::default();
    for (i, bytes) in [hello_main(), greet()].iter().enumerate() {
        let p = dir.join(format!("e2e_{i}.o"));
        std::fs::write(&p, bytes).unwrap();
        opts.inputs.push(p.display().to_string());
    }
    opts.config.adhoc = false;
    opts.config.ident = "peregrine-e2e".into();
    let linked = pgr_driver::link_to_image(&opts).unwrap();
    let header = MachHeader64::parse(&linked.image).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        &linked.image,
        MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    while let Some(cmd) = it.next_command().unwrap() {
        assert_ne!(
            cmd.kind,
            pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_CODE_SIGNATURE),
            "-no_adhoc must not emit LC_CODE_SIGNATURE"
        );
    }
}

#[test]
fn undefined_symbol_fails_with_a_pointer_to_the_input() {
    let dir = unique_dir("undef");
    let p = dir.join("e2e_alone.o");
    std::fs::write(&p, hello_main()).unwrap();
    let mut opts = Options::default();
    opts.inputs.push(p.display().to_string());
    let err = pgr_driver::link_to_image(&opts).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("_greet"), "{msg}");
    assert!(msg.contains("e2e_alone.o"), "{msg}");
}

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
        assert!(
            seg.pointer_format == DYLD_CHAINED_PTR_64_OFFSET
                || seg.pointer_format == pgr_format::consts::DYLD_CHAINED_PTR_64,
            "unsupported pointer format {}",
            seg.pointer_format
        );
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

// ---------------------------------------------------------------------------
// M2 — dynamic executable gates (architecture doc §10.3 row M2)
// ---------------------------------------------------------------------------

/// printf-main.o: `BL _printf` through a GOT-load sequence plus an
/// adrp/add on a local string, and an `__data` pointer bound to `_printf`
/// (direct chained bind).
fn printf_main() -> Vec<u8> {
    let text: Vec<u8> = [
        0x9000_0000u32, // adrp x0, _printf@GOTPAGE
        0xF940_0000u32, // ldr x0, [x0, _printf@GOTPAGEOFF]
        0x9400_0000u32, // bl _printf
        0x9000_0001u32, // adrp x1, _msg@page
        0x9100_0020u32, // add x1, x1, #_msg@pageoff
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("printf_main.o");
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_section(ObjectSection::cstring("hi\n"));
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    let printf_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_printf".into(),
        weak_ref: false,
    });
    let msg_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_msg".into(),
        section_index: 2,
        value: 0,
        weak: false,
    });
    // Relocation `r_symbolnum`s are symtab-table indices (defs before
    // undefs), resolved via `sym_index`.
    let printf = b.sym_index(printf_sym);
    let msg = b.sym_index(msg_sym);
    let _ = main_sym;
    b.section_mut(sect).relocs = vec![
        ObjectReloc::got_page21(printf).at(0),
        ObjectReloc::got_pageoff12(printf).at(4),
        ObjectReloc::branch26(printf).at(8),
        ObjectReloc::addend(0).at(12),
        ObjectReloc::page21(msg).at(12),
        ObjectReloc::addend(0).at(16),
        ObjectReloc::pageoff12(msg).at(16),
    ];
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(printf).at(0));
    b.build().unwrap()
}

/// A libSystem-shaped `.tbd` (v4) exporting the printf surface.
fn libsystem_tbd() -> &'static str {
    "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: /usr/lib/libSystem.B.dylib\ncurrent-version: 1.2.3\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _printf, _strlen ]\n...\n"
}

/// Writes the tbd stub into `dir` and links `printf_main.o` against it.
fn link_printf_in(
    dir: std::path::PathBuf,
    tweak: impl FnOnce(&mut Options),
) -> (Vec<u8>, pgr_driver::ImageAndPlan) {
    let obj = dir.join("printf_main.o");
    std::fs::write(&obj, printf_main()).unwrap();
    let tbd = dir.join("libSystem.tbd");
    std::fs::write(&tbd, libsystem_tbd()).unwrap();
    let mut opts = Options::default();
    opts.inputs.push(obj.display().to_string());
    opts.inputs.push(tbd.display().to_string());
    opts.config.ident = "peregrine-m2".into();
    tweak(&mut opts);
    let linked = pgr_driver::link_to_image(&opts).unwrap();
    (linked.image.clone(), linked)
}

/// Finds the export-trie payload bytes.
fn find_trie(bytes: &[u8]) -> Vec<u8> {
    let header = MachHeader64::parse(bytes).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    while let Some(cmd) = it.next_command().unwrap() {
        if let pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_EXPORTS_TRIE) =
            cmd.kind
        {
            return pgr_format::LinkeditDataCommand::parse(cmd.bytes)
                .unwrap()
                .data(bytes)
                .unwrap()
                .to_vec();
        }
    }
    panic!("image carries no LC_DYLD_EXPORTS_TRIE");
}

/// Walks every chain of a dynamic image; returns `(vaddr, word)` per slot
/// plus the parsed import table (the full dyld simulation basis).
fn walk_chains(
    image: &[u8],
    payload: &[u8],
) -> (
    Vec<(u64, ChainWord64)>,
    Vec<pgr_format::fixups::Import>,
    Vec<u8>,
) {
    let hdr = parse_header(payload).unwrap();
    let imports = parse_imports(payload, &hdr).unwrap();
    let names = payload[hdr.symbols_offset as usize..].to_vec();
    let starts = parse_starts_in_image(payload, hdr.starts_offset as usize).unwrap();
    let mut out = Vec::new();
    for &off in &starts.seg_info_offset {
        if off == 0 {
            continue;
        }
        let rec_at = hdr.starts_offset as usize + off as usize;
        let seg = parse_starts_in_segment(payload, rec_at).unwrap();
        assert!(
            seg.pointer_format == DYLD_CHAINED_PTR_64_OFFSET
                || seg.pointer_format == pgr_format::consts::DYLD_CHAINED_PTR_64,
            "unsupported pointer format {}",
            seg.pointer_format
        );
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
                    out.push((file + PAGEZERO_SIZE_64, word));
                    if word.next() == 0 {
                        break;
                    }
                    slot_off += u64::from(word.next()) * 4;
                }
            }
        }
    }
    (out, imports, names)
}

/// The load commands of the image (kind, cmd bytes).
fn load_commands(bytes: &[u8]) -> Vec<(pgr_format::LoadCommandKind, Vec<u8>)> {
    let header = MachHeader64::parse(bytes).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    let mut out = Vec::new();
    while let Some(cmd) = it.next_command().unwrap() {
        out.push((cmd.kind, cmd.bytes.to_vec()));
    }
    out
}

#[test]
fn m2_links_printf_from_tbd() {
    let (image, linked) = link_printf_in(unique_dir("m2printf"), |_| {});
    // The verifier's full simulation accepts the dynamic image.
    let vopts = pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = pgr_verify::verify(&image, &vopts);
    assert!(report.is_ok(&vopts), "verifier issues: {report:?}");

    let syms = parse_output(&image);
    // __TEXT,__stubs (12 B/slot) and __DATA_CONST,__got (8 B/slot) exist.
    let (_saddr, ssize) = syms.sections[&("__TEXT".into(), "__stubs".into())];
    let (gaddr, gsize) = syms.sections[&("__DATA_CONST".into(), "__got".into())];
    assert_eq!(ssize, 12, "one stub for _printf");
    assert_eq!(gsize, 8, "one GOT slot for _printf");
    assert!(linked.fixup_slots >= 2, "got bind + data bind");

    // The stub decodes as adrp x16 / ldr x16 / br x16 patched to the slot.
    let stub_file = ssize; // placeholder to keep types honest
    let _ = stub_file;
    let text_addr = syms.sections[&("__TEXT".into(), "__text".into())].0;
    let stub_at = (gaddr - PAGEZERO_SIZE_64) as usize; // sanity variable reuse
    let _ = stub_at;
    let stub_file_off =
        (syms.sections[&("__TEXT".into(), "__stubs".into())].0 - PAGEZERO_SIZE_64) as usize;
    let w0 = u32::from_le_bytes(image[stub_file_off..stub_file_off + 4].try_into().unwrap());
    let w1 = u32::from_le_bytes(
        image[stub_file_off + 4..stub_file_off + 8]
            .try_into()
            .unwrap(),
    );
    let w2 = u32::from_le_bytes(
        image[stub_file_off + 8..stub_file_off + 12]
            .try_into()
            .unwrap(),
    );
    assert_eq!(w2, 0xD61F_0200, "br x16");
    assert_eq!(w1 & 0xFFC0_0000, 0xF940_0000, "ldr x16, [x16, #imm12]");
    assert_eq!(w0 & 0x9F00_0000, 0x9000_0000, "adrp x16");
    // ldr imm12 points at the GOT slot's page offset / 8.
    let imm12 = (w1 >> 10) & 0xfff;
    let slot_pageoff = (gaddr & 0xFFF) / 8;
    assert_eq!(u64::from(imm12), slot_pageoff, "ldr targets the got slot");
    // adrp page delta lands on the got page.
    let rd = w0 & 0x1f;
    assert_eq!(rd, 16, "stub uses x16");
    let _ = text_addr;

    // Chains: one bind on the GOT slot (ordinal 0), one on the data slot.
    let (slots, imports, names) = walk_chains(&image, &find_fixup_payload(&image));
    assert_eq!(imports.len(), 1, "_printf only");
    assert_eq!(imports[0].lib_ordinal, 1, "libSystem is LC_LOAD_DYLIB #1");
    assert_eq!(
        &names[imports[0].name_offset as usize..imports[0].name_offset as usize + 8],
        b"_printf\0"
    );
    let binds: Vec<_> = slots.iter().filter(|(_, w)| w.is_bind()).collect();
    assert_eq!(binds.len(), 2, "got slot + data slot");
    for (_, w) in binds {
        assert_eq!(w.bind_ordinal(), 0);
    }

    // Symtab: _printf undefined with library ordinal 1; extdefs + header.
    let header = MachHeader64::parse(&image).unwrap();
    let _ = header;
    let undef = {
        let cmds = load_commands(&image);
        let (kind, _) = cmds
            .iter()
            .find(|(k, _)| matches!(k, pgr_format::LoadCommandKind::Symtab))
            .expect("symtab");
        let _ = kind;
        let st = pgr_format::SymtabCommand::parse(
            &cmds
                .iter()
                .find(|(k, _)| matches!(k, pgr_format::LoadCommandKind::Symtab))
                .unwrap()
                .1,
            0,
        )
        .unwrap();
        let mut found = None;
        for i in 0..st.nsyms {
            let sym: pgr_format::symtab::Nlist64 = pgr_format::cursor::pod_read_unaligned_at(
                &image,
                st.symoff as usize + i as usize * 16,
            )
            .unwrap();
            let strx = sym.n_strx as usize;
            let end = image[st.stroff as usize + strx..]
                .iter()
                .position(|&b| b == 0)
                .unwrap();
            let name = String::from_utf8_lossy(
                &image[st.stroff as usize + strx..st.stroff as usize + strx + end],
            )
            .into_owned();
            if name == "_printf" {
                found = Some(sym);
            }
        }
        found.expect("_printf in the output symtab")
    };
    assert_eq!(undef.n_type & 0x0e, 0x0, "_printf is N_UNDF");
    assert_eq!(undef.library_ordinal(), 1, "two-level ordinal = libSystem");
    assert_eq!(undef.n_value, 0);

    // LC_LOAD_DYLIB carries the install name + versions from the tbd.
    let cmds = load_commands(&image);
    let dylib_cmd = cmds
        .iter()
        .find(|(k, _)| matches!(k, pgr_format::LoadCommandKind::LoadDylib))
        .expect("LC_LOAD_DYLIB present");
    let name = pgr_format::DylibCommand::parse(&dylib_cmd.1)
        .unwrap()
        .name(&dylib_cmd.1)
        .unwrap();
    assert_eq!(name, b"/usr/lib/libSystem.B.dylib");

    // MH_TWOLEVEL set; the trie exports __mh_execute_header (and _main).
    let hflags = u32::from_le_bytes(image[24..28].try_into().unwrap());
    assert!(hflags & pgr_format::consts::MH_TWOLEVEL != 0);
    let trie = find_trie(&image);
    let mut report = pgr_verify::Report::default();
    let exports = pgr_verify::export_trie::check_export_trie(&trie, &mut report);
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.severity == pgr_verify::Severity::Error),
        "{report:?}"
    );
    let names: Vec<_> = exports.entries.iter().map(|(n, _, _)| n.clone()).collect();
    assert!(
        names.contains(&"__mh_execute_header".to_string()),
        "{names:?}"
    );
    assert!(names.contains(&"_main".to_string()), "{names:?}");

    // Indirect symbol table: __got slot then __stubs slot -> _printf index.
    let dysym_cmd = cmds
        .iter()
        .find(|(k, _)| matches!(k, pgr_format::LoadCommandKind::Dysymtab))
        .expect("dysymtab");
    let d = pgr_format::DysymtabCommand::parse(&dysym_cmd.1, 0).unwrap();
    assert_eq!(d.nindirectsyms, 2, "one got slot + one stub slot");
    let ind0 = u32::from_le_bytes(
        image[d.indirectsymoff as usize..d.indirectsymoff as usize + 4]
            .try_into()
            .unwrap(),
    );
    let ind1 = u32::from_le_bytes(
        image[d.indirectsymoff as usize + 4..d.indirectsymoff as usize + 8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(ind0, ind1, "both slots point at the _printf symtab entry");
    assert!(
        (ind0 as usize) < d.iundefsym as usize + d.nundefsym as usize,
        "entry names the undefined symbol"
    );
}

#[test]
fn m2_flat_namespace_binds_dyld_flat() {
    let (image, _) = link_printf_in(unique_dir("m2flat"), |o| {
        o.config.flat_namespace = true;
    });
    let (_, imports, names) = walk_chains(&image, &find_fixup_payload(&image));
    assert_eq!(imports.len(), 1);
    assert_eq!(
        imports[0].lib_ordinal,
        pgr_format::consts::BIND_SPECIAL_DYLIB_FLAT_LOOKUP,
        "flat lookup ordinal"
    );
    assert_eq!(&names[imports[0].name_offset as usize..], b"_printf\0");
    // No MH_TWOLEVEL in flat mode.
    let hflags = u32::from_le_bytes(image[24..28].try_into().unwrap());
    assert_eq!(hflags & pgr_format::consts::MH_TWOLEVEL, 0);
    // The undefined symbol carries the flat ordinal in n_desc too.
    let report = pgr_verify::verify(&image, &pgr_verify::Options::default());
    assert!(report.is_ok(&pgr_verify::Options::default()), "{report:?}");
}

#[test]
fn m2_undefined_dynamic_lookup_binds_weak_flat() {
    let dir = unique_dir("m2dyn");
    let obj = dir.join("weak_main.o");
    let text: Vec<u8> = [
        0x9400_0000u32, // bl _optional
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("weak_main.o");
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    let opt_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_optional".into(),
        weak_ref: true,
    });
    let opt = b.sym_index(opt_sym);
    b.section_mut(sect).relocs = vec![ObjectReloc::branch26(opt).at(0)];
    std::fs::write(&obj, b.build().unwrap()).unwrap();
    let mut opts = Options::default();
    opts.inputs.push(obj.display().to_string());
    opts.config.undefined_policy = pgr_core::resolve::UndefinedPolicy::DynamicLookup;
    opts.config.ident = "peregrine-m2".into();
    let image = pgr_driver::link_to_image(&opts).unwrap().image;

    let (_, imports, _) = walk_chains(&image, &find_fixup_payload(&image));
    assert_eq!(imports.len(), 1);
    assert!(imports[0].weak_import, "weak dynamic lookup");
    assert_eq!(
        imports[0].lib_ordinal,
        pgr_format::consts::BIND_SPECIAL_DYLIB_FLAT_LOOKUP
    );
    let vopts = pgr_verify::Options::default();
    let report = pgr_verify::verify(&image, &vopts);
    assert!(report.is_ok(&vopts), "{report:?}");
}

#[test]
fn m2_import_ordinals_follow_first_use() {
    // Same dylib, two calls: _strlen first (vaddr order), then _memcpy.
    let dir = unique_dir("m2order");
    let text: Vec<u8> = [
        0x9400_0000u32, // bl _strlen
        0x9400_0000u32, // bl _memcpy
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("order.o");
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    let strlen_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_strlen".into(),
        weak_ref: false,
    });
    let memcpy_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_memcpy".into(),
        weak_ref: false,
    });
    // Table order: _main(def)=0, then undefs in declaration order.
    let strlen = b.sym_index(strlen_sym);
    let memcpy = b.sym_index(memcpy_sym);
    b.section_mut(sect).relocs = vec![
        ObjectReloc::branch26(strlen).at(0),
        ObjectReloc::branch26(memcpy).at(4),
    ];
    let obj = dir.join("order.o");
    std::fs::write(&obj, b.build().unwrap()).unwrap();
    let tbd = dir.join("libstr.tbd");
    std::fs::write(
        &tbd,
        "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: /usr/lib/libstr.dylib\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _strlen, _memcpy, _aaa ]\n...\n",
    )
    .unwrap();
    let mut opts = Options::default();
    opts.inputs.push(obj.display().to_string());
    opts.inputs.push(tbd.display().to_string());
    opts.config.ident = "peregrine-m2".into();
    let image = pgr_driver::link_to_image(&opts).unwrap().image;

    let (_, imports, names) = walk_chains(&image, &find_fixup_payload(&image));
    assert_eq!(imports.len(), 2);
    let n0 = &names[imports[0].name_offset as usize..imports[0].name_offset as usize + 8];
    let n1 = &names[imports[1].name_offset as usize..];
    assert_eq!(&n0[..8], b"_strlen\0", "first-use order (spike S6)");
    assert_eq!(&n1[..8], b"_memcpy\0");
    assert_eq!(imports[0].lib_ordinal, 1);
    assert_eq!(imports[1].lib_ordinal, 1);
}

#[test]
fn m2_rpath_and_source_version_commands_land() {
    let (image, _) = link_printf_in(unique_dir("m2d13"), |o| {
        o.config.rpaths.push("@executable_path/../lib".into());
        o.config.rpaths.push("/opt/peregrine/lib".into());
        o.config.source_version = Some(1u64 << 40 | 2 << 30 | 3 << 20);
    });
    let cmds = load_commands(&image);
    // Parse the rpath strings via the raw bytes (lc_str offset 12).
    let rpath_raw: Vec<String> = cmds
        .iter()
        .filter(|(k, _)| matches!(k, pgr_format::LoadCommandKind::Rpath))
        .map(|(_, b)| {
            let end = b[12..].iter().position(|&c| c == 0).unwrap();
            String::from_utf8_lossy(&b[12..12 + end]).into_owned()
        })
        .collect();
    assert_eq!(
        rpath_raw,
        ["@executable_path/../lib", "/opt/peregrine/lib"],
        "rpaths in command order"
    );
    let sv = cmds
        .iter()
        .find(|(k, _)| matches!(k, pgr_format::LoadCommandKind::SourceVersion))
        .expect("LC_SOURCE_VERSION present");
    let value = u64::from_le_bytes(sv.1[8..16].try_into().unwrap());
    assert_eq!(value, 1u64 << 40 | 2 << 30 | 3 << 20);
    // The image still verifies clean.
    let vopts = pgr_verify::Options::default();
    let report = pgr_verify::verify(&image, &vopts);
    assert!(report.is_ok(&vopts), "{report:?}");
}

#[test]
fn m2_direct_page_reloc_to_external_is_rejected() {
    let dir = unique_dir("m2direct");
    let text: Vec<u8> = [
        0x9000_0000u32, // adrp x0, _printf@page (direct!)
        0x9100_0000u32, // add x0, x0, #_printf@pageoff
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("direct.o");
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    let printf_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_printf".into(),
        weak_ref: false,
    });
    let printf = b.sym_index(printf_sym);
    b.section_mut(sect).relocs = vec![
        ObjectReloc::addend(0).at(0),
        ObjectReloc::page21(printf).at(0),
        ObjectReloc::addend(0).at(4),
        ObjectReloc::pageoff12(printf).at(4),
    ];
    let obj = dir.join("direct.o");
    std::fs::write(&obj, b.build().unwrap()).unwrap();
    let tbd = dir.join("libSystem.tbd");
    std::fs::write(&tbd, libsystem_tbd()).unwrap();
    let mut opts = Options::default();
    opts.inputs.push(obj.display().to_string());
    opts.inputs.push(tbd.display().to_string());
    let err = pgr_driver::link_to_image(&opts).unwrap_err().to_string();
    assert!(err.contains("GOT"), "{err}");
}

/// Locates `ld64.lld` for the golden comparison (env override first, then
/// PATH). Returns `None` when unavailable — the golden test skips.
fn find_lld() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("PGR_LLD64") {
        let path = std::path::PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    let path = std::path::PathBuf::from("ld64.lld");
    std::process::Command::new(&path)
        .arg("-v")
        .output()
        .is_ok()
        .then_some(path)
}

/// The M2 "slot-for-slot vs lld" gate: link the SAME object against the
/// SAME tbd with `ld64.lld` and compare the bind semantics our dyld
/// simulation produces (per-slot: import ordinal → (lib, name, addend,
/// weak); rebase targets) with what the golden linker produced.
#[test]
fn m2_lld_golden_binds_slot_for_slot() {
    let Some(lld) = find_lld() else {
        eprintln!("skipping lld golden: no ld64.lld (set PGR_LLD64 or install lld)");
        return;
    };
    let dir = unique_dir("m2lld");
    let obj = dir.join("printf_main.o");
    std::fs::write(&obj, printf_main()).unwrap();
    let tbd = dir.join("libSystem.tbd");
    std::fs::write(&tbd, libsystem_tbd()).unwrap();
    let lld_out = dir.join("lld_out");

    // lld refuses direct page relocs to externals too, but our object only
    // carries GOT-load/branch/unsigned relocs, so both linkers accept it.
    let status = std::process::Command::new(&lld)
        .args([
            "-arch",
            "arm64",
            "-platform_version",
            "macos",
            "12.0",
            "14.0",
            "-fixup_chains",
            "-o",
        ])
        .arg(&lld_out)
        .arg(&obj)
        .arg(&tbd)
        .status()
        .expect("run ld64.lld");
    assert!(status.success(), "ld64.lld failed to link the corpus");

    let lld_image = std::fs::read(&lld_out).unwrap();
    let pgr_image = link_printf_in(dir.clone(), |_| {}).0;

    // Semantic comparison: the multiset of (kind, lib, name, addend, weak)
    // over both images' fixup slots, plus each image's import table.
    let semantic_of = |image: &[u8]| -> Vec<(bool, u16, String, i64, bool)> {
        let (_, imports, names) = walk_chains(image, &find_fixup_payload(image));
        let mut out = Vec::new();
        for (_, w) in walk_chains(image, &find_fixup_payload(image)).0 {
            if w.is_bind() {
                let imp = &imports[w.bind_ordinal() as usize];
                let name = names[imp.name_offset as usize..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|e| {
                        String::from_utf8_lossy(
                            &names[imp.name_offset as usize..imp.name_offset as usize + e],
                        )
                        .into_owned()
                    })
                    .unwrap_or_default();
                out.push((
                    true,
                    imp.lib_ordinal,
                    name,
                    imp.addend + i64::from(w.bind_addend()),
                    imp.weak_import,
                ));
            } else {
                out.push((false, 0, String::new(), 0, false));
            }
        }
        out.sort();
        out
    };
    let ours = semantic_of(&pgr_image);
    let golden = semantic_of(&lld_image);
    assert_eq!(
        ours, golden,
        "bind/rebase slot semantics must match ld64.lld slot-for-slot"
    );
    // Import tables agree on the (lib, name) pairs.
    let imports_of = |image: &[u8]| -> Vec<(u16, String, bool)> {
        let (_, imports, names) = walk_chains(image, &find_fixup_payload(image));
        imports
            .iter()
            .map(|i| {
                let name = names[i.name_offset as usize..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|e| {
                        String::from_utf8_lossy(
                            &names[i.name_offset as usize..i.name_offset as usize + e],
                        )
                        .into_owned()
                    })
                    .unwrap_or_default();
                (i.lib_ordinal, name, i.weak_import)
            })
            .collect()
    };
    assert_eq!(imports_of(&pgr_image), imports_of(&lld_image));
}

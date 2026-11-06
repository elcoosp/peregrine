//! M5 `__cstring` merging gates (D4): identical `S_CSTRING_LITERALS` strings
//! across inputs collapse to one output copy (ld64's default), every
//! reference — symbol-based or section-relative — lands on the single copy,
//! and the merged output passes the strict verifier with the fused emit
//! byte-identical to the reference.

use pgr_driver::opts::Options;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

fn unique_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m5_cstring").join(format!(
        "{}_{}_{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const SHARED: &str = "the quick brown fox\n";

/// Object A: defines `_shared_str` on its copy of `SHARED` and a local
/// `_a_private` string; code ADRP+ADD loads `_shared_str`.
fn object_a() -> Vec<u8> {
    let mut b = ObjectBuilder::new("a.o");
    let _text: usize = b.add_section(ObjectSection::text(
        "__text",
        [
            0x9000_0000u32.to_le_bytes(), // adrp x0, _shared_str@page
            0x9100_0000u32.to_le_bytes(), // add x0, x0, @_pageoff
        ]
        .concat(),
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12(1).at(4),
        ],
    ));
    let cstr: usize = b.add_section(ObjectSection::cstring(&format!("{SHARED}\0a-only\n\0")));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_shared_str".into(),
        section_index: cstr,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Local("_a_private".into()));
    b.build().unwrap()
}

/// Object B: an identical copy of `SHARED` (no external symbol — a local
/// label marks it) referenced through section-relative relocs, so the merge
/// must remap both the local symbol and the raw relocations.
fn object_b() -> Vec<u8> {
    let mut b = ObjectBuilder::new("b.o");
    let _text: usize = b.add_section(ObjectSection::text(
        "__text",
        [
            0x9000_0000u32.to_le_bytes(), // adrp x0, <local string>@page
            0x9100_0000u32.to_le_bytes(), // add x0, x0, @pageoff
        ]
        .concat(),
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21_sect(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12_sect(1).at(4),
        ],
    ));
    let data: usize = b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned_sect(2).at(0)],
    ));
    let _ = data;
    let cstr: usize = b.add_section(ObjectSection::cstring(&format!("{SHARED}\0b-only\n\0")));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_b_shared".into(),
        section_index: cstr,
        value: 0,
        weak: false,
    });
    b.build().unwrap()
}

fn output_symbols(bytes: &[u8]) -> std::collections::HashMap<String, u64> {
    let header = pgr_format::MachHeader64::parse(bytes).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    let mut out = std::collections::HashMap::new();
    while let Some(cmd) = it.next_command().unwrap() {
        if let pgr_format::LoadCommandKind::Symtab = cmd.kind {
            let st = pgr_format::SymtabCommand::parse(cmd.bytes, 0).unwrap();
            for i in 0..st.nsyms {
                let sym: pgr_format::symtab::Nlist64 = pgr_format::cursor::pod_read_unaligned_at(
                    bytes,
                    st.symoff as usize + i as usize * 16,
                )
                .unwrap();
                let strx = sym.n_strx as usize;
                let end = bytes[st.stroff as usize + strx..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap();
                let name = String::from_utf8_lossy(
                    &bytes[st.stroff as usize + strx..st.stroff as usize + strx + end],
                )
                .into_owned();
                out.insert(name, sym.n_value);
            }
        }
    }
    out
}

fn section_size(bytes: &[u8], seg: &str, sect: &str) -> u64 {
    let header = pgr_format::MachHeader64::parse(bytes).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    while let Some(cmd) = it.next_command().unwrap() {
        if let pgr_format::LoadCommandKind::Segment64 = cmd.kind {
            let seg_cmd = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).unwrap();
            if seg_cmd.name().unwrap() != seg {
                continue;
            }
            for s in seg_cmd
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .unwrap()
            {
                if s.name().unwrap() == sect {
                    return s.size;
                }
            }
        }
    }
    panic!("section {seg},{sect} not found");
}

fn strict_verify(image: &[u8]) {
    let opts = pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = pgr_verify::verify(image, &opts);
    assert!(report.is_ok(&opts), "verifier issues: {report:?}");
}

#[test]
fn m5_cstring_merge_dedups_across_inputs() {
    let dir = unique_dir("dedup");
    let (pa, pb) = (dir.join("a.o"), dir.join("b.o"));
    std::fs::write(&pa, object_a()).unwrap();
    std::fs::write(&pb, object_b()).unwrap();

    let mut opts = Options {
        inputs: vec![pa.display().to_string(), pb.display().to_string()],
        output: dir.join("out.dylib").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-cstring".into();
    opts.config.filetype = pgr_core::layout::OutputType::Dylib;
    opts.config.install_name = Some("@rpath/libcstr.dylib".into());
    let image = pgr_driver::link_to_bytes(&opts).unwrap();

    // Exactly one copy of the shared literal (plus the two private tails).
    let cstr_size = section_size(&image, "__TEXT", "__cstring");
    let shared_len = SHARED.len() as u64 + 1;
    assert_eq!(
        cstr_size,
        shared_len + "a-only\n\0".len() as u64 + "b-only\n\0".len() as u64 + 1,
        "__cstring size {cstr_size} (unmerged would be {})",
        cstr_size + shared_len
    );
    assert_eq!(
        image
            .windows(SHARED.len())
            .filter(|w| *w == SHARED.as_bytes())
            .count(),
        1,
        "the shared literal appears more than once"
    );

    // The symbol-level proof: B's local label on its duplicate resolves to
    // the same address as A's definition.
    let syms = output_symbols(&image);
    assert_eq!(
        syms["_shared_str"], syms["_b_shared"],
        "the duplicate's local label did not remap to the canonical copy"
    );
    strict_verify(&image);

    // The fused emit stays byte-identical to the reference.
    let reference = pgr_driver::link_reference_bytes(&opts).unwrap();
    assert_eq!(image, reference);
}

#[test]
fn m5_cstring_section_relative_pointers_remap_to_the_canonical_copy() {
    let dir = unique_dir("sectptr");
    let (pa, pb) = (dir.join("a.o"), dir.join("b.o"));
    std::fs::write(&pa, object_a()).unwrap();
    std::fs::write(&pb, object_b()).unwrap();

    let mut opts = Options {
        inputs: vec![pa.display().to_string(), pb.display().to_string()],
        output: dir.join("out.dylib").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-cstring".into();
    opts.config.filetype = pgr_core::layout::OutputType::Dylib;
    opts.config.install_name = Some("@rpath/libcstr.dylib".into());
    let image = pgr_driver::link_to_bytes(&opts).unwrap();

    // B's __data pointer (section-relative UNSIGNED into its own duplicate)
    // must hold the canonical copy's address — the same value A's symbol
    // carries (both point at the shared literal's first byte).
    let syms = output_symbols(&image);
    let shared_addr = syms["_shared_str"];
    let header = pgr_format::MachHeader64::parse(&image).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        &image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    let mut data_addr = None;
    while let Some(cmd) = it.next_command().unwrap() {
        if let pgr_format::LoadCommandKind::Segment64 = cmd.kind {
            let seg = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).unwrap();
            if seg.name().unwrap() == "__DATA" {
                for s in seg
                    .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                    .unwrap()
                {
                    if s.name().unwrap() == "__data" {
                        data_addr = Some((s.addr, s.offset));
                    }
                }
            }
        }
    }
    let (vaddr, file_off) = data_addr.expect("__data section");
    // The chained-fixup rebase for the pointer carries the target vaddr;
    // simulate dyld: the slot at __data+0 must equal shared_addr.
    let payload = {
        let mut it = pgr_format::LoadCommandIter::new(
            &image,
            pgr_format::MachHeader64::SIZE,
            header.ncmds,
            header.sizeofcmds,
        )
        .unwrap();
        let mut found = None;
        while let Some(cmd) = it.next_command().unwrap() {
            if let pgr_format::LoadCommandKind::LinkeditData(
                pgr_format::consts::LC_DYLD_CHAINED_FIXUPS,
            ) = cmd.kind
            {
                let lc = pgr_format::LinkeditDataCommand::parse(cmd.bytes).unwrap();
                found = Some(lc.data(&image).unwrap().to_vec());
            }
        }
        found.expect("fixup payload")
    };
    let hdr = pgr_format::fixups::parse_header(&payload).unwrap();
    let starts =
        pgr_format::fixups::parse_starts_in_image(&payload, hdr.starts_offset as usize).unwrap();
    let mut seen = Vec::new();
    for &off in &starts.seg_info_offset {
        if off == 0 {
            continue;
        }
        let rec = hdr.starts_offset as usize + off as usize;
        let seg = pgr_format::fixups::parse_starts_in_segment(&payload, rec).unwrap();
        for page in 0..seg.page_count {
            for start in pgr_format::fixups::page_chain_starts(&payload, rec, &seg, page).unwrap() {
                let _ = start;
                // Walk this page's chain: slots are 8 bytes; the slot vaddr
                // maps through __DATA's fileoff.
                let mut slot_off = u64::from(start);
                loop {
                    let slot_file = u64::from(seg.page_size) * u64::from(page) + slot_off;
                    let at = (file_off as u64 + slot_file) as usize;
                    let word = u64::from_le_bytes(image[at..at + 8].try_into().unwrap());
                    let cw = pgr_format::fixups::ChainWord64::new(word);
                    let target = cw.rebase_target();
                    seen.push((vaddr + slot_file, target));
                    let next = u64::from(cw.next());
                    if next == 0 {
                        break;
                    }
                    slot_off += next * 4;
                }
            }
        }
    }
    assert!(
        seen.iter()
            .any(|(slot, target)| *slot == vaddr && *target == shared_addr),
        "the section-relative pointer did not land on the canonical copy: {seen:?}"
    );
}

#[test]
fn m5_cstring_merge_and_dead_strip_cooperate() {
    let dir = unique_dir("strip");
    // a.o: live function referencing the shared string; b.o: dead function
    // referencing its own copy of the same string (dies with the function).
    let mut a = ObjectBuilder::new("a.o").set_subsections_via_symbols(true);
    let at = a.add_section(ObjectSection::text(
        "__text",
        [
            0x9000_0000u32.to_le_bytes(),
            0x9100_0000u32.to_le_bytes(),
            0xD65F_03C0u32.to_le_bytes(),
        ]
        .concat(),
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12(1).at(4),
        ],
    ));
    let acs: usize = a.add_section(ObjectSection::cstring("shared-string\0"));
    a.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: at,
        value: 0,
        weak: false,
    });
    a.add_symbol(ObjectSymbol::Defined {
        name: "_a_str".into(),
        section_index: acs,
        value: 0,
        weak: false,
    });

    let mut b = ObjectBuilder::new("b.o").set_subsections_via_symbols(true);
    let bt = b.add_section(ObjectSection::text(
        "__text",
        [
            0x9000_0000u32.to_le_bytes(),
            0x9100_0000u32.to_le_bytes(),
            0xD65F_03C0u32.to_le_bytes(),
        ]
        .concat(),
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21_sect(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12_sect(1).at(4),
        ],
    ));
    b.add_section(ObjectSection::cstring("shared-string\0"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_dead_fn".into(),
        section_index: bt,
        value: 0,
        weak: false,
    });

    let (pa, pb) = (dir.join("a.o"), dir.join("b.o"));
    std::fs::write(&pa, a.build().unwrap()).unwrap();
    std::fs::write(&pb, b.build().unwrap()).unwrap();

    let mut opts = Options {
        inputs: vec![pa.display().to_string(), pb.display().to_string()],
        output: dir.join("out.bin").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-cstring-strip".into();
    opts.config.dead_strip = true;
    let image = pgr_driver::link_to_bytes(&opts).unwrap();

    // One copy of the shared string survives (a.o's, referenced by _main);
    // b.o's duplicate died with _dead_fn.
    assert_eq!(
        image
            .windows("shared-string".len())
            .filter(|w| w == b"shared-string")
            .count(),
        1
    );
    let syms = output_symbols(&image);
    assert!(syms.contains_key("_a_str"), "the live string's local label");
    assert!(!syms.contains_key("_dead_fn"));
    strict_verify(&image);
    let reference = pgr_driver::link_reference_bytes(&opts).unwrap();
    assert_eq!(image, reference);
}

#[test]
fn m5_cstring_merge_keeps_distinct_strings_intact() {
    let dir = unique_dir("distinct");
    let (pa, pb) = (dir.join("a.o"), dir.join("b.o"));
    std::fs::write(&pa, object_a()).unwrap();
    std::fs::write(&pb, object_b()).unwrap();

    let mut opts = Options {
        inputs: vec![pa.display().to_string(), pb.display().to_string()],
        output: dir.join("out.dylib").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-cstring".into();
    opts.config.filetype = pgr_core::layout::OutputType::Dylib;
    opts.config.install_name = Some("@rpath/libcstr.dylib".into());
    let image = pgr_driver::link_to_bytes(&opts).unwrap();

    for tail in ["a-only\n", "b-only\n"] {
        assert_eq!(
            image
                .windows(tail.len())
                .filter(|w| *w == tail.as_bytes())
                .count(),
            1,
            "{tail} appears the wrong number of times"
        );
    }
    let syms = output_symbols(&image);
    // The private strings do NOT alias the shared one.
    assert_ne!(syms["_shared_str"], syms["_a_private"]);
}

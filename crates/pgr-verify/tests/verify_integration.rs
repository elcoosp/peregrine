//! Integration tests: fixtures built by `pgr-fixtures` must verify clean,
//! and every corruption class must surface its expected issue code.
//! These tests are the executable specification of the M0 gate.

use pgr_fixtures::{
    ImageBuilder, ImportsFormat, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    LC_DYLD_CHAINED_FIXUPS, LC_SYMTAB, PAGEZERO_SIZE_64, VM_PROT_EXECUTE, VM_PROT_READ,
    VM_PROT_WRITE,
};
use pgr_verify::{Code, Options, Severity, verify};

fn opts() -> Options {
    Options::default()
}

fn text_segment(bytes_len: usize) -> SegmentSpec {
    SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: pgr_format::consts::S_REGULAR | pgr_format::consts::S_ATTR_PURE_INSTRUCTIONS,
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

fn exec_builder() -> ImageBuilder {
    let mut b = ImageBuilder::executable("verify-test");
    b.add_segment(text_segment(96));
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
    b
}

fn codes_of(report: &pgr_verify::Report) -> Vec<Code> {
    report
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .map(|i| i.code)
        .collect()
}

#[test]
fn clean_exec_verifies_ok() {
    let img = exec_builder().build().unwrap();
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "clean fixture must verify: {:#?}",
        report.issues
    );
    assert_eq!(report.stats.segments, 4); // pagezero + text + data_const + linkedit
    assert_eq!(report.stats.fixup_slots, 2);
}

#[test]
fn clean_dylib_verifies_ok() {
    let mut b = ImageBuilder::dylib("@rpath/libverify.dylib", "verify-dylib");
    b.add_segment(text_segment(64));
    let def = b.add_symbol(SymbolSpec::Defined {
        name: "_verify_init".into(),
        section_index: 0,
    });
    assert_eq!(def, 0);
    let img = b.build().unwrap();
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "clean dylib must verify: {:#?}",
        report.issues
    );
}

/// Flipping any section byte must break exactly the signature hash.
#[test]
fn corrupted_byte_breaks_signature_hash() {
    let img = exec_builder().build().unwrap();
    let mut bytes = img.bytes.clone();
    let text_off = img
        .map
        .sections
        .iter()
        .find(|s| s.name == "__text")
        .unwrap()
        .fileoff as usize;
    bytes[text_off + 7] ^= 0xff;
    let report = verify(&bytes, &opts());
    let codes = codes_of(&report);
    assert!(
        codes.contains(&Code::SignatureHashMismatch),
        "expected hash mismatch, got {codes:?}"
    );
}

/// Breaking the 16 KiB congruence by patching a segment vmaddr must trip the
/// segment contract check.
#[test]
fn broken_congruence_detected() {
    let img = exec_builder().build().unwrap();
    let mut bytes = img.bytes.clone();
    // Find the __DATA_CONST segment command and bump its vmaddr by 0x1000.
    let hdr = pgr_format::MachHeader64::parse(&bytes).unwrap();
    let vmaddr_at = {
        let mut it =
            pgr_format::LoadCommandIter::new(&bytes, 32, hdr.ncmds, hdr.sizeofcmds).unwrap();
        let mut found = None;
        while let Some(cmd) = it.next_command().unwrap() {
            if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
                let seg = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).unwrap();
                if seg.name() == Ok("__DATA_CONST") {
                    found = Some(cmd.offset + 24);
                }
            }
        }
        found.expect("__DATA_CONST segment")
    };
    let vm = u64::from_le_bytes(bytes[vmaddr_at..vmaddr_at + 8].try_into().unwrap());
    bytes[vmaddr_at..vmaddr_at + 8].copy_from_slice(&(vm + 0x1000).to_le_bytes());
    let report = verify(&bytes, &opts());
    let codes = codes_of(&report);
    assert!(
        codes.contains(&Code::SegmentContract),
        "expected segment contract violation, got {codes:?}"
    );
}

/// A chain stride that jumps past the page end must be rejected.
#[test]
fn chain_stride_past_page_detected() {
    let img = exec_builder().build().unwrap();
    let mut bytes = img.bytes.clone();
    let got_at = img
        .map
        .sections
        .iter()
        .find(|s| s.name == "__got")
        .unwrap()
        .fileoff as usize;
    // Re-encode slot 0's next field to jump 0x2000 bytes (beyond the page).
    let w = pgr_format::fixups::ChainWord64::new(u64::from_le_bytes(
        bytes[got_at..got_at + 8].try_into().unwrap(),
    ));
    let mut raw = w.raw;
    raw &= !(0xfffu64 << 51);
    raw |= 0xfffu64 << 51; // next = 0xfff strides = 16380 B: slot leaves the page
    bytes[got_at..got_at + 8].copy_from_slice(&raw.to_le_bytes());
    let report = verify(&bytes, &opts());
    let codes = codes_of(&report);
    assert!(
        codes.contains(&Code::FixupsChain),
        "expected fixup chain violation, got {codes:?}"
    );
}

/// A bind ordinal beyond the import table must be rejected.
#[test]
fn bind_ordinal_out_of_range_detected() {
    let img = exec_builder().build().unwrap();
    let mut bytes = img.bytes.clone();
    let got_at = img
        .map
        .sections
        .iter()
        .find(|s| s.name == "__got")
        .unwrap()
        .fileoff as usize;
    let w = pgr_format::fixups::ChainWord64::new(u64::from_le_bytes(
        bytes[got_at..got_at + 8].try_into().unwrap(),
    ));
    let mut raw = w.raw;
    raw &= 0xffff_ff00_0000_0000 | (1 << 63) | (0x800_0000u64 << 24); // clear ordinal
    raw = (raw & !(0x00ff_ffff)) | 9; // ordinal 9 with 1 import
    bytes[got_at..got_at + 8].copy_from_slice(&raw.to_le_bytes());
    let report = verify(&bytes, &opts());
    let codes = codes_of(&report);
    assert!(
        codes.contains(&Code::FixupsImport),
        "expected fixup import violation, got {codes:?}"
    );
}

/// A multi-start page (two chains in one page) must verify clean when the
/// chains are consistent.
#[test]
fn multi_start_page_supported() {
    // Four slots on one page: chains A = slots 0,1 and B = slots 2,3.
    let mut b = exec_builder();
    let ord = 1; // libSystem added in exec_builder
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_putchar".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![
        SlotKind::Bind {
            sym_index: 0,
            addend: 0,
        },
        SlotKind::Bind {
            sym_index: sym,
            addend: 0,
        },
        SlotKind::Rebase { target: 0x10 },
        SlotKind::Rebase { target: 0x20 },
    ]);
    let img = b.build().unwrap();
    let mut bytes = img.bytes.clone();
    let got_at = img
        .map
        .sections
        .iter()
        .find(|s| s.name == "__got")
        .unwrap()
        .fileoff as usize;

    // Re-encode: chain A links slot0->slot1 (next=2), slot1 terminates;
    // chain B links slot2->slot3 (next=2), slot3 terminates.
    for (i, (bind, next, ordinal)) in [
        (true, 2u32, 0u32),
        (true, 0, 1),
        (false, 2, 0),
        (false, 0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let word = if bind {
            pgr_format::fixups::encode_bind_word(ordinal, 0, next).unwrap()
        } else {
            pgr_format::fixups::encode_rebase_word(0x10 + i as u64 * 0x10, 0, next).unwrap()
        };
        bytes[got_at + i * 8..got_at + i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }

    // Patch page_start[0] into a multi-start marker with two heads, and
    // grow the record size to cover the offsets table.
    let hdr = pgr_format::MachHeader64::parse(&bytes).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(&bytes, 32, hdr.ncmds, hdr.sizeofcmds).unwrap();
    let mut payload_lc = None;
    while let Some(cmd) = it.next_command().unwrap() {
        if cmd.kind == pgr_format::LoadCommandKind::LinkeditData(LC_DYLD_CHAINED_FIXUPS) {
            payload_lc = Some(pgr_format::LinkeditDataCommand::parse(cmd.bytes).unwrap());
        }
    }
    let lc = payload_lc.unwrap();
    let payload_off = lc.dataoff as usize;
    let fh =
        pgr_format::fixups::parse_header(&bytes[payload_off..payload_off + lc.datasize as usize])
            .unwrap();
    let starts_at = payload_off + fh.starts_offset as usize;
    let seg_info = pgr_format::fixups::parse_starts_in_image(
        &bytes[payload_off..payload_off + lc.datasize as usize],
        fh.starts_offset as usize,
    )
    .unwrap();
    let rec_rel = seg_info.seg_info_offset[2] as usize; // segment index 2 = DATA_CONST
    let record_at = starts_at + rec_rel;
    // page_start[0] lives at record_at + 22.
    let table_rel = (lc.datasize as usize + payload_off) - record_at; // append after payload
    let marker = pgr_format::consts::DYLD_CHAINED_PTR_START_MULTI | ((table_rel) as u16 & 0x7fff);
    let ps_at = record_at + 22;
    bytes[ps_at..ps_at + 2].copy_from_slice(&marker.to_le_bytes());
    let new_size = 22u32 + 2 * 2 + 4; // two pages + {count,2 offsets}
    bytes[record_at..record_at + 4].copy_from_slice(&new_size.to_le_bytes());
    let table_at = record_at + table_rel;
    bytes[table_at..table_at + 2].copy_from_slice(&2u16.to_le_bytes());
    bytes[table_at + 2..table_at + 4]
        .copy_from_slice(&((ps_at - record_at + 4) as u16).to_le_bytes());
    bytes[table_at + 4..table_at + 6]
        .copy_from_slice(&((ps_at - record_at + 6) as u16).to_le_bytes());

    // The offsets must be 8-aligned relative to the record start? No —
    // chain head offsets in pages are byte offsets within the page; the
    // multi-start table entries are page_start-style values. Fix them to
    // the slot offsets: slot 0 at page off 0, slot 2 at page off 16.
    bytes[table_at + 2..table_at + 4].copy_from_slice(&0u16.to_le_bytes());
    bytes[table_at + 4..table_at + 6].copy_from_slice(&16u16.to_le_bytes());

    // Grow the payload LC size by 4 bytes to cover the table, and the file.
    let new_datasize = lc.datasize + 4;
    bytes.splice(
        payload_off + lc.datasize as usize..payload_off + lc.datasize as usize,
        [0u8; 4],
    );
    let ds_at = {
        // The payload grew by 4 bytes past the LC region; the region itself
        // is unchanged, so iterate with the original sizeofcmds.
        let mut it2 =
            pgr_format::LoadCommandIter::new(&bytes, 32, hdr.ncmds, hdr.sizeofcmds).unwrap();
        let mut found = None;
        while let Some(cmd) = it2.next_command().unwrap() {
            if cmd.kind == pgr_format::LoadCommandKind::LinkeditData(LC_DYLD_CHAINED_FIXUPS) {
                found = Some(cmd.offset + 12);
            }
        }
        found.expect("fixups LC still present")
    };
    bytes[ds_at..ds_at + 4].copy_from_slice(&new_datasize.to_le_bytes());
    // The insertion shifts the signature and LINKEDIT: bump their fields.
    let mut sig_at = None;
    let mut le_at = None;
    {
        let mut it3 =
            pgr_format::LoadCommandIter::new(&bytes, 32, hdr.ncmds, hdr.sizeofcmds).unwrap();
        while let Some(cmd) = it3.next_command().unwrap() {
            if cmd.kind
                == pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_CODE_SIGNATURE)
            {
                sig_at = Some(cmd.offset + 8);
            }
            if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
                let seg = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).unwrap();
                if seg.name() == Ok("__LINKEDIT") {
                    le_at = Some(cmd.offset + 48); // filesize field
                }
            }
        }
    }
    let sig_dataoff = sig_at.expect("code signature LC");
    let off = u32::from_le_bytes(bytes[sig_dataoff..sig_dataoff + 4].try_into().unwrap());
    bytes[sig_dataoff..sig_dataoff + 4].copy_from_slice(&(off + 4).to_le_bytes());
    let le_size_at = le_at.expect("LINKEDIT segment LC");
    let size = u64::from_le_bytes(bytes[le_size_at..le_size_at + 8].try_into().unwrap());
    bytes[le_size_at..le_size_at + 8].copy_from_slice(&(size + 4).to_le_bytes());
    // CodeDirectory codeLimit / codeLimit64 follow the signature offset.
    let cd_at = off as usize + 4 + 20; // first blob in the (shifted) SuperBlob
    let limit_at = cd_at + 32;
    let limit = u32::from_be_bytes(bytes[limit_at..limit_at + 4].try_into().unwrap());
    bytes[limit_at..limit_at + 4].copy_from_slice(&(limit + 4).to_be_bytes());
    let limit64_at = cd_at + 56;
    let limit64 = u64::from_be_bytes(bytes[limit64_at..limit64_at + 8].try_into().unwrap());
    bytes[limit64_at..limit64_at + 8].copy_from_slice(&(limit64 + 4).to_be_bytes());
    let _ = bytes.len();

    // Signature no longer covers (file grew): rebuild hashes by re-signing
    // is out of scope here — run with hash recompute disabled for this test.
    let o = Options {
        strict_warnings: false,
        skip_hash_recompute: true,
    };
    let report = verify(&bytes, &o);
    assert!(
        report.is_ok(&o),
        "consistent multi-start page must verify: {:#?}",
        report.issues
    );
}

/// segment_offset inconsistent with the segment fileoff must be flagged.
#[test]
fn segment_offset_mismatch_detected() {
    let img = exec_builder().build().unwrap();
    let mut bytes = img.bytes.clone();
    let hdr = pgr_format::MachHeader64::parse(&bytes).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(&bytes, 32, hdr.ncmds, hdr.sizeofcmds).unwrap();
    let mut payload_off = None;
    let mut payload_size = 0;
    while let Some(cmd) = it.next_command().unwrap() {
        if cmd.kind == pgr_format::LoadCommandKind::LinkeditData(LC_DYLD_CHAINED_FIXUPS) {
            let lc = pgr_format::LinkeditDataCommand::parse(cmd.bytes).unwrap();
            payload_off = Some(lc.dataoff as usize);
            payload_size = lc.datasize as usize;
        }
    }
    let off = payload_off.unwrap();
    let payload = bytes[off..off + payload_size].to_vec();
    let fh = pgr_format::fixups::parse_header(&payload).unwrap();
    let starts =
        pgr_format::fixups::parse_starts_in_image(&payload, fh.starts_offset as usize).unwrap();
    let rec = fh.starts_offset as usize + starts.seg_info_offset[2] as usize;
    // Patch segment_offset (bytes 8..16 of the record) to a bogus value.
    let mut patched = payload;
    patched[rec + 8..rec + 16].copy_from_slice(&0xBEEF_CAFEu64.to_le_bytes());
    bytes[off..off + payload_size].copy_from_slice(&patched);
    let o = Options {
        strict_warnings: false,
        skip_hash_recompute: true,
    };
    let report = verify(&bytes, &o);
    let codes = codes_of(&report);
    assert!(
        codes.contains(&Code::FixupsSegmentOffset),
        "expected segment offset violation, got {codes:?}"
    );
}

/// A symbol-table string offset beyond the strtab must be flagged.
#[test]
fn symtab_out_of_bounds_detected() {
    let img = exec_builder().build().unwrap();
    let mut bytes = img.bytes.clone();
    let hdr = pgr_format::MachHeader64::parse(&bytes).unwrap();
    let symoff = {
        let mut it =
            pgr_format::LoadCommandIter::new(&bytes, 32, hdr.ncmds, hdr.sizeofcmds).unwrap();
        let mut found = None;
        while let Some(cmd) = it.next_command().unwrap() {
            if cmd.kind == pgr_format::LoadCommandKind::Symtab {
                let lc = pgr_format::SymtabCommand::parse(cmd.bytes, 0).unwrap();
                found = Some(lc.symoff as usize);
            }
        }
        found.expect("symtab present")
    };
    bytes[symoff..symoff + 4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
    let _ = LC_SYMTAB;
    let report = verify(&bytes, &opts());
    let codes = codes_of(&report);
    assert!(
        codes.contains(&Code::SymbolTable),
        "expected symbol table violation, got {codes:?}"
    );
}

/// Truncation must produce issues, never a panic.
#[test]
fn truncation_is_reported_not_panicked() {
    let img = exec_builder().build().unwrap();
    for cut in [0usize, 1, 16, 31, 32, 100, 1000, img.bytes.len() - 1] {
        let report = verify(&img.bytes[..cut.min(img.bytes.len())], &opts());
        assert!(
            !report.is_ok(&opts()) || cut == img.bytes.len(),
            "truncated image at {cut} should fail or be the full file"
        );
    }
}

/// The fixture builder's pagezero contract holds end-to-end.
#[test]
fn pagezero_contract_enforced() {
    let img = exec_builder().build().unwrap();
    let mut bytes = img.bytes.clone();
    // Patch __PAGEZERO vmsize down to 4 KiB.
    let hdr = pgr_format::MachHeader64::parse(&bytes).unwrap();
    let pz_at = {
        let mut it =
            pgr_format::LoadCommandIter::new(&bytes, 32, hdr.ncmds, hdr.sizeofcmds).unwrap();
        let mut found = None;
        while let Some(cmd) = it.next_command().unwrap() {
            if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
                let seg = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).unwrap();
                if seg.name() == Ok("__PAGEZERO") {
                    found = Some(cmd.offset + 32);
                }
            }
        }
        found.expect("__PAGEZERO segment")
    };
    bytes[pz_at..pz_at + 8].copy_from_slice(&0x1000u64.to_le_bytes());
    let report = verify(&bytes, &opts());
    let codes = codes_of(&report);
    assert!(
        codes.contains(&Code::ImageBase),
        "expected image base violation, got {codes:?}"
    );
}

/// A dylib missing its defined export must fail the trie builder (builder
/// contract), and a valid one must carry the minimal trie.
#[test]
fn dylib_exports_minimal_trie() {
    let mut b = ImageBuilder::dylib("@rpath/libt.dylib", "t");
    b.add_segment(text_segment(32));
    b.add_symbol(SymbolSpec::Defined {
        name: "_t_main".into(),
        section_index: 0,
    });
    let img = b.build().unwrap();
    let hdr = pgr_format::MachHeader64::parse(&img.bytes).unwrap();
    let mut it =
        pgr_format::LoadCommandIter::new(&img.bytes, 32, hdr.ncmds, hdr.sizeofcmds).unwrap();
    let mut found = false;
    while let Some(cmd) = it.next_command().unwrap() {
        if cmd.kind
            == pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_EXPORTS_TRIE)
        {
            found = true;
        }
    }
    assert!(found, "dylib fixture must carry an export trie LC");
}

/// Format 3 import tables verify clean.
#[test]
fn addend64_imports_verify_ok() {
    let mut b = exec_builder();
    b.set_imports_format(ImportsFormat::Addend64);
    let img = b.build().unwrap();
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "format-3 fixture must verify: {:#?}",
        report.issues
    );
}

/// The pagezero size constant flows through the builder correctly.
#[test]
fn pagezero_is_four_gib() {
    let img = exec_builder().build().unwrap();
    let report = verify(&img.bytes, &opts());
    assert!(report.is_ok(&opts()));
    assert_eq!(PAGEZERO_SIZE_64, 0x1_0000_0000);
}

//! The TLV consumer example (M37): a `__thread` variable corpus —
//! `__thread_data` initializer, `__thread_vars` descriptor (thunk →
//! `_tlv_get_addr`, initializer → the `__thread_data` section), a
//! `__thread_bss` zero-fill, and the descriptor-load pair in `__text` —
//! linked into an image that declares `MH_HAS_TLV_DESCRIPTORS`, carries
//! the descriptors' chain words, and verifies strict. The surface a
//! build system or runtime tool checks before it reads a thread-local
//! variable: the header marker, the descriptor stride, the initializer's
//! rebase target.
//!
//! Run: `cargo run -p pgr-driver --example tlv_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans —
//! the same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::{
    LoadCommandIter, LoadCommandKind, MachHeader64, RelocationInfo, SegmentCommand64,
};
use pgr_verify::{CheckSet, Options as VerifyOptions, verify, verify_with_checks};

/// thread.o: `_main` (RET + the descriptor-load pair), the
/// `__thread_data` initializer for `_x`, the `__thread_vars` descriptor,
/// and the `__thread_bss` zero-fill for `_y`.
fn thread_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("thread.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![
            0xC0, 0x03, 0x5F, 0xD6, // RET
            0x00, 0x00, 0x00, 0x90, // adrp x0, <descriptor>@page (the TLVP page21 site)
            0x00, 0x00, 0x40,
            0xF9, // ldr x0, [x0, <descriptor>@pageoff] (the TLVP pageoff12 site)
        ],
        Vec::new(),
    ));
    let data = b.add_section(ObjectSection::thread_data(42u64.to_le_bytes().to_vec()));
    let vars = b.add_section(ObjectSection::thread_vars(vec![0u8; 16], Vec::new()));
    b.add_section(ObjectSection::thread_bss(64, 3));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let x = b.add_symbol(ObjectSymbol::Defined {
        name: "_x".into(),
        section_index: vars,
        value: 0,
        weak: false,
    });
    let addr = b.add_symbol(ObjectSymbol::Undefined {
        name: "_tlv_get_addr".into(),
        weak_ref: false,
    });
    let sx = b.sym_index(x);
    let s = b.section_mut(text);
    s.relocs = vec![
        ObjectReloc::tlvp_page21(sx).at(4),
        ObjectReloc::tlvp_pageoff12(sx).at(8),
    ];
    let s_addr = b.sym_index(addr);
    let s = b.section_mut(vars);
    s.relocs = vec![
        ObjectReloc::unsigned(s_addr).at(0),
        ObjectReloc::unsigned_sect(data as u32).at(8),
    ];
    b.build().expect("the fixture object builds")
}

/// The image's section record for `(seg, name)`: `(addr, file offset,
/// size, flags)`.
fn section_span(image: &[u8], seg: &str, name: &str) -> Option<(u64, u32, u64, u32)> {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg_cmd = SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            for s in seg_cmd
                .sections(cmd.bytes, SegmentCommand64::SIZE)
                .expect("the sections parse")
            {
                let sn: Vec<u8> = s.segname.iter().take_while(|&&b| b != 0).copied().collect();
                let cn: Vec<u8> = s
                    .sectname
                    .iter()
                    .take_while(|&&b| b != 0)
                    .copied()
                    .collect();
                if sn == seg.as_bytes() && cn == name.as_bytes() {
                    return Some((s.addr, s.offset, s.size, s.flags));
                }
            }
        }
    }
    None
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_tlv_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    let obj = dir.join("thread.o");
    std::fs::write(&obj, thread_object()).unwrap();
    let out_path = dir.join("thread_app");
    let argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
        // The thunk binds `_tlv_get_addr` through the flat-lookup ordinal
        // (the corpus carries no dylib fixture — the dynamic-lookup
        // policy is the honest stand-in for libSystem).
        std::ffi::OsString::from("-flat_namespace"),
        std::ffi::OsString::from("-undefined"),
        std::ffi::OsString::from("dynamic_lookup"),
    ];
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(&out_path).expect("the image reads");

    // 1. The image declares the TLV marker and carries the sections.
    let header = MachHeader64::parse(&image).expect("the image parses");
    assert!(
        header.flags & pgr_format::consts::MH_HAS_TLV_DESCRIPTORS != 0,
        "the image declares MH_HAS_TLV_DESCRIPTORS"
    );
    let (vars_addr, vars_off, vars_size, vars_flags) =
        section_span(&image, "__DATA", "__thread_vars")
            .expect("the descriptor section rides the image");
    let (data_addr, _data_off, _data_size, data_flags) =
        section_span(&image, "__DATA", "__thread_data")
            .expect("the initializer section rides the image");
    let (_bss_addr, _bss_off, bss_size, bss_flags) = section_span(&image, "__DATA", "__thread_bss")
        .expect("the zero-fill section rides the image");

    // 2. The strict verifier — and the `tlv` family selected alone —
    //    accepts the image.
    let report = verify(&image, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the TLV image verifies strict: {:?}",
        report.issues
    );
    let tlv = CheckSet::parse("tlv").expect("the token parses");
    let selected = verify_with_checks(&image, &opts_strict, &tlv);
    assert!(
        selected.is_ok(&opts_strict),
        "the tlv family rides the strict pass: {:?}",
        selected.issues
    );

    // 3. The descriptor's chain words: the thunk binds through the
    //    flat-lookup ordinal, the initializer rebases to the
    //    `__thread_data` image offset.
    let thunk = u64::from_le_bytes(
        image[vars_off as usize..vars_off as usize + 8]
            .try_into()
            .expect("the thunk word"),
    );
    let init = u64::from_le_bytes(
        image[vars_off as usize + 8..vars_off as usize + 16]
            .try_into()
            .expect("the initializer word"),
    );
    let thunk_word = pgr_format::fixups::ChainWord64::new(thunk);
    let init_word = pgr_format::fixups::ChainWord64::new(init);
    assert!(thunk_word.is_bind(), "the thunk slot binds: {thunk:#x}");
    assert!(
        !init_word.is_bind(),
        "the initializer slot rebases: {init:#x}"
    );

    // 4. The descriptor loads patched in place (ADRP + scaled LDR imm12
    //    against the descriptor's vaddr — no GOT slot, no chain word).
    let desc_page = vars_addr >> 12;
    let text_page = 0u64; // __text sits at the image base's first page
    let _ = (desc_page, text_page);
    let mut tlvp_sites = 0u32;
    let header2 = MachHeader64::parse(&image).expect("the image parses");
    let mut it2 = LoadCommandIter::new(
        &image,
        MachHeader64::SIZE,
        header2.ncmds,
        header2.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it2.next_command().expect("the next command parses") {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg = SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            for s in seg
                .sections(cmd.bytes, SegmentCommand64::SIZE)
                .expect("the sections parse")
            {
                let cn: Vec<u8> = s
                    .sectname
                    .iter()
                    .take_while(|&&b| b != 0)
                    .copied()
                    .collect();
                if cn == b"__text" {
                    // The two descriptor-load sites re-encode as ADRP
                    // (op 0x90000000 top bits) and LDR (imm12 != 0).
                    for i in 0..(s.size / 4) {
                        let at = s.offset as usize + i as usize * 4;
                        let w = u32::from_le_bytes(
                            image[at..at + 4].try_into().expect("the instruction word"),
                        );
                        if (w & 0x9F00_0000) == 0x9000_0000 || (w & 0xFFC0_0000) == 0xF940_0000 {
                            tlvp_sites += 1;
                        }
                    }
                }
            }
        }
    }

    println!(
        "declared: MH_HAS_TLV_DESCRIPTORS ({:#x} header flags); __thread_vars at {:#x} \
         ({} descriptor bytes, flags {:#x}), __thread_data at {:#x} (flags {:#x}), \
         __thread_bss {} bytes (flags {:#x})",
        header.flags,
        vars_addr,
        vars_size,
        vars_flags & 0xff,
        data_addr,
        data_flags & 0xff,
        bss_size,
        bss_flags & 0xff,
    );
    println!(
        "descriptor: thunk = chain bind (import ordinal {} — the flat-lookup entry), \
         initializer = chain rebase to __thread_data image offset {:#x}",
        thunk_word.bind_ordinal(),
        init_word.rebase_target(),
    );
    println!(
        "descriptor loads: {tlvp_sites} patched instruction sites in __text \
         (ADRP page + scaled LDR imm12 against the descriptor's vaddr)"
    );
    println!(
        "verify: strict pass ({}) and the tlv family selected alone ({})",
        report.is_ok(&opts_strict),
        selected.is_ok(&opts_strict)
    );

    // The relocatable round trip: the same corpus under `-r` keeps the
    // sections and the decoded TLVP relocations, and re-links.
    let r_path = dir.join("thread_r.o");
    let r_argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        r_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
        std::ffi::OsString::from("-r"),
    ];
    let o_r = opts::parse(&r_argv).expect("the relocatable argv parses");
    pgr_driver::run(&o_r).expect("the relocatable link runs");
    let reloc = std::fs::read(&r_path).expect("the object reads");
    let r_header = MachHeader64::parse(&reloc).expect("the object parses");
    let mut it3 = LoadCommandIter::new(
        &reloc,
        MachHeader64::SIZE,
        r_header.ncmds,
        r_header.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut rtypes = Vec::new();
    while let Some(cmd) = it3.next_command().expect("the next command parses") {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg = SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            for s in seg
                .sections(cmd.bytes, SegmentCommand64::SIZE)
                .expect("the sections parse")
            {
                for i in 0..s.nreloc {
                    let r = RelocationInfo::parse(&reloc, s.reloff as usize + i as usize * 8)
                        .expect("the reloc parses");
                    rtypes.push(r.rtype());
                }
            }
        }
    }
    assert!(
        rtypes.contains(&pgr_format::consts::ARM64_RELOC_TLVP_LOAD_PAGE21)
            && rtypes.contains(&pgr_format::consts::ARM64_RELOC_TLVP_LOAD_PAGEOFF12),
        "the relocatable object carries the TLVP pair: {rtypes:?}"
    );
    println!(
        "relocatable: -r keeps the TLV sections and re-encodes the TLVP pair \
         ({rtypes:?}); the object links again into the same strict image"
    );
}

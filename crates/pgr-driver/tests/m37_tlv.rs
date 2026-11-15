//! M37 — the TLV driver surface: a corpus carrying `__thread_data`
//! initializers, `__thread_vars` descriptors (thunk → `_tlv_get_addr`,
//! initializer → `_x.init`) and descriptor-load relocations links into
//! an image that verifies strict, declares `MH_HAS_TLV_DESCRIPTORS`,
//! carries the descriptors' chain words (the initializer rebase naming
//! the `__thread_data` address, the thunk bind riding the flat-lookup
//! ordinal), round-trips the relocatable output (the `-r` object keeps
//! the sections and the TLVP relocations and links again), and stays
//! byte-identical through the cached lane.

use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::{
    LoadCommandIter, LoadCommandKind, MachHeader64, RelocationInfo, SegmentCommand64,
};
use pgr_verify::{CheckSet, Options as VerifyOptions, verify, verify_with_checks};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m37_tlv_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// The M37 corpus on disk: `_main` (RET + descriptor-load pair), the
/// `__thread_data` initializer, the `__thread_vars` descriptor, the
/// `__thread_bss` zero-fill.
fn corpus(dir: &Path, tag: &str) -> PathBuf {
    let mut b = ObjectBuilder::new("tlv.o");
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
    // The thunk binds `_tlv_get_addr` (external); the initializer rebases
    // into the `__thread_data` section (section-relative — clang's
    // descriptor shape; r_extern entries must name external symbols).
    s.relocs = vec![
        ObjectReloc::unsigned(s_addr).at(0),
        ObjectReloc::unsigned_sect(data as u32).at(8),
    ];
    let path = dir.join(format!("tlv_{tag}.o"));
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// The dynamic-lookup argv every full link rides (the `_tlv_get_addr`
/// thunk bind resolves through the flat-lookup ordinal).
fn link(dir: &Path, out: &str, obj: &Path, extra: &[&str]) -> Vec<u8> {
    let out_path = dir.join(out);
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string()];
    argv.push(obj.display().to_string());
    argv.extend([
        "-flat_namespace".to_string(),
        "-undefined".to_string(),
        "dynamic_lookup".to_string(),
    ]);
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).expect("the image reads")
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// One output section's identity: `(segname, sectname, addr, file
/// offset, size, flags)`.
struct SectInfo {
    seg: String,
    name: String,
    addr: u64,
    offset: u32,
    flags: u32,
}

/// Walks the image's `LC_SEGMENT_64` section records.
fn sections_of(image: &[u8]) -> Vec<SectInfo> {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    let mut out = Vec::new();
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            for s in seg
                .sections(cmd.bytes, SegmentCommand64::SIZE)
                .expect("the sections parse")
            {
                out.push(SectInfo {
                    seg: cstr(&s.segname),
                    name: cstr(&s.sectname),
                    addr: s.addr,
                    offset: s.offset,
                    flags: s.flags,
                });
            }
        }
    }
    out
}

/// The image's preferred load address (the `__TEXT` segment's vmaddr) —
/// the base the `DYLD_CHAINED_PTR_64_OFFSET` rebase targets count from.
fn image_base(image: &[u8]) -> u64 {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            if cstr(&seg.segname) == "__TEXT" {
                return seg.vmaddr;
            }
        }
    }
    0
}

fn cstr(field: &[u8; 16]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn header_flags(image: &[u8]) -> u32 {
    MachHeader64::parse(image).expect("the image parses").flags
}

// ---- the end-to-end link ---------------------------------------------------

#[test]
fn the_tlv_corpus_links_and_verifies_strict() {
    let dir = scratch("e2e");
    let obj = corpus(&dir, "e2e");
    let image = link(&dir, "app", &obj, &[]);
    assert!(
        header_flags(&image) & pgr_format::consts::MH_HAS_TLV_DESCRIPTORS != 0,
        "the image declares MH_HAS_TLV_DESCRIPTORS"
    );
    let sects = sections_of(&image);
    let vars = sects
        .iter()
        .find(|s| s.seg == "__DATA" && s.name == "__thread_vars")
        .expect("the descriptor section rides the image");
    assert_eq!(
        vars.flags & 0xff,
        pgr_format::consts::S_THREAD_LOCAL_VARIABLES,
        "the descriptor section keeps its type"
    );
    let data = sects
        .iter()
        .find(|s| s.seg == "__DATA" && s.name == "__thread_data")
        .expect("the initializer section rides the image");
    assert_eq!(
        data.flags & 0xff,
        pgr_format::consts::S_THREAD_LOCAL_REGULAR,
        "the initializer section keeps its type"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the TLV image verifies strict: {:?}",
        report.issues
    );
    let tlv = CheckSet::parse("tlv").expect("the token parses");
    let selected = verify_with_checks(&image, &strict(), &tlv);
    assert!(
        selected.is_ok(&strict()),
        "the TLV family rides the strict pass: {:?}",
        selected.issues
    );
}

// ---- the descriptor chain words --------------------------------------------

#[test]
fn the_descriptor_slots_carry_the_chain_words() {
    let dir = scratch("slots");
    let obj = corpus(&dir, "slots");
    let image = link(&dir, "app_slots", &obj, &[]);
    let sects = sections_of(&image);
    let vars = sects
        .iter()
        .find(|s| s.seg == "__DATA" && s.name == "__thread_vars")
        .expect("the descriptor section rides the image");
    let data = sects
        .iter()
        .find(|s| s.seg == "__DATA" && s.name == "__thread_data")
        .expect("the initializer section rides the image");
    let at = vars.offset as usize;
    let thunk = u64::from_le_bytes(image[at..at + 8].try_into().expect("the thunk word"));
    let init = u64::from_le_bytes(
        image[at + 8..at + 16]
            .try_into()
            .expect("the initializer word"),
    );
    let thunk_word = pgr_format::fixups::ChainWord64::new(thunk);
    let init_word = pgr_format::fixups::ChainWord64::new(init);
    assert!(
        thunk_word.is_bind(),
        "the descriptor's thunk slot binds _tlv_get_addr: {thunk:#x}"
    );
    assert!(
        !init_word.is_bind(),
        "the descriptor's initializer slot rebases: {init:#x}"
    );
    assert_eq!(
        init_word.rebase_target(),
        data.addr - image_base(&image),
        "the initializer names the __thread_data image offset"
    );
    // The bind word's ordinal is an import-table index; the flat-lookup
    // contract rides the import entry the index names.
    let header = MachHeader64::parse(&image).expect("the image parses");
    let mut it = LoadCommandIter::new(&image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    let mut import = None;
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if matches!(
            cmd.kind,
            LoadCommandKind::LinkeditData(cmd_type) if cmd_type == pgr_format::consts::LC_DYLD_CHAINED_FIXUPS
        ) {
            let Ok(lc) = pgr_format::LinkeditDataCommand::parse(cmd.bytes) else {
                continue;
            };
            let Ok(payload) = lc.data(&image) else {
                continue;
            };
            let fh = pgr_format::fixups::parse_header(payload).expect("the fixup header parses");
            let imports =
                pgr_format::fixups::parse_imports(payload, &fh).expect("the imports parse");
            import = Some(imports[thunk_word.bind_ordinal() as usize]);
        }
    }
    let thunk_import = import.expect("the chained-fixups payload rides the image");
    assert_eq!(
        thunk_import.lib_ordinal,
        pgr_format::consts::BIND_SPECIAL_DYLIB_FLAT_LOOKUP,
        "the thunk bind resolves through the flat-lookup ordinal"
    );
}

// ---- the relocatable round trip --------------------------------------------

#[test]
fn the_relocatable_output_round_trips_the_tlv_surface() {
    let dir = scratch("reloc");
    let obj = corpus(&dir, "reloc_src");
    let reloc = link(&dir, "tlv_r.o", &obj, &["-r"]);
    // The relocatable object carries the TLV sections and the decoded
    // TLVP relocations (the pre-M37 parse refused the type outright).
    let sects = sections_of(&reloc);
    let vars = sects
        .iter()
        .find(|s| s.seg == "__DATA" && s.name == "__thread_vars")
        .expect("the descriptor section rides the relocatable object");
    assert_eq!(
        vars.flags & 0xff,
        pgr_format::consts::S_THREAD_LOCAL_VARIABLES,
        "the descriptor section keeps its type through -r"
    );
    let header = MachHeader64::parse(&reloc).expect("the object parses");
    let mut it = LoadCommandIter::new(&reloc, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    let mut rtypes = Vec::new();
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
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
        rtypes.contains(&pgr_format::consts::ARM64_RELOC_TLVP_LOAD_PAGE21),
        "the TLVP page21 reloc re-encodes: {rtypes:?}"
    );
    assert!(
        rtypes.contains(&pgr_format::consts::ARM64_RELOC_TLVP_LOAD_PAGEOFF12),
        "the TLVP pageoff12 reloc re-encodes: {rtypes:?}"
    );
    // Self-consumption: the relocatable object links again (the M10
    // two-step gate) into the same strict image.
    let again_path = dir.join("tlv_r.o");
    let image = link(&dir, "app_again", &again_path, &[]);
    assert!(
        header_flags(&image) & pgr_format::consts::MH_HAS_TLV_DESCRIPTORS != 0,
        "the self-consumed link declares the TLV markers"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the self-consumed image verifies strict: {:?}",
        report.issues
    );
}

// ---- the cached lane -------------------------------------------------------

#[test]
fn the_cached_lane_stays_byte_identical() {
    let dir = scratch("cache");
    let obj = corpus(&dir, "cached");
    let plain = link(&dir, "app_plain", &obj, &[]);
    let cache_dir = dir.join("pgr-cache");
    let cache = cache_dir.display().to_string();
    let cached = link(&dir, "app_cached", &obj, &["-cache", &cache]);
    assert_eq!(
        plain, cached,
        "the cached parse plans the same TLV carriage, byte for byte"
    );
}

//! M10 rung 5 — the golden pair rides the second CPU family. The M10
//! row's correctness gate names "**golden pairs per target**" (the
//! roadmap's §10.4 M10 row, gate column); the M2 harness
//! (`e2e.rs::m2_lld_golden_binds_slot_for_slot`) walks the arm64 pair,
//! and this file completes the pair for `x86_64`. The gate: link the
//! SAME `x86_64`-typed object against the SAME dual-target `.tbd` with
//! `ld64.lld` and with `pgr`, and compare the fixup-slot semantics
//! slot-for-slot — the multiset of (bind, lib ordinal, name, addend,
//! weak) over both images' chains plus each image's import table —
//! with both payloads declaring the family's `DYLD_CHAINED_PTR_64`
//! pointer format (rebase targets are VM addresses, TDD §15.9) and the
//! `pgr` image verifying strict.
//!
//! Skips when no `ld64.lld` is available (set `PGR_LLD64` or install
//! lld) — the M2 golden gate's own skip pattern.

use pgr_driver::opts::parse;
use pgr_fixtures::{CpuKind, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{DYLD_CHAINED_PTR_64, PAGEZERO_SIZE_64};
use pgr_format::fixups::{
    ChainWord64, page_chain_starts, parse_header, parse_imports, parse_starts_in_image,
    parse_starts_in_segment,
};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};
use std::ffi::OsString;

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("pgr-m10-x86e-golden-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Locates `ld64.lld` (env override first, then PATH) — the M2
/// harness's `find_lld`, verbatim.
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

/// A self-contained `x86_64` `main.o` (the `m10_x86_64.rs` fixture
/// shape): the GOT-indirect `_printf` bind the family emits natively
/// (no stub lane, TDD §15.9) beside one pure rebase slot in `__data`.
fn printf_main() -> Vec<u8> {
    let text: Vec<u8> = [
        &[0x48u8, 0x8B, 0x05, 0xFC, 0xFF, 0xFF, 0xFF][..], // movq _printf@GOTPCREL(%rip)
        &[0xC3],                                           // ret
    ]
    .concat();
    let mut b = ObjectBuilder::new("printf_main.o").set_cputype(CpuKind::X86_64);
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
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
    let main = b.sym_index(main_sym);
    let printf = b.sym_index(printf_sym);
    b.section_mut(sect)
        .relocs
        .push(ObjectReloc::x86_got_load(printf).at(3));
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::x86_unsigned(main).at(0));
    b.build().unwrap()
}

/// The libSystem-shaped `.tbd` (v4) the golden pair shares: the top
/// level keeps the `arm64-macos` target the read side requires (the
/// tbd gate) and adds the `x86_64-macos` target `ld64.lld` matches
/// under `-arch x86_64` — the export group carries both.
fn libsystem_tbd() -> &'static str {
    "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos, x86_64-macos ]\ninstall-name: /usr/lib/libSystem.B.dylib\ncurrent-version: 1.2.3\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos, x86_64-macos ]\n    symbols: [ _printf, _strlen ]\n...\n"
}

/// Finds the `LC_DYLD_CHAINED_FIXUPS` payload bytes.
fn find_fixup_payload(bytes: &[u8]) -> Vec<u8> {
    let header = MachHeader64::parse(bytes).unwrap();
    let mut it =
        LoadCommandIter::new(bytes, MachHeader64::SIZE, header.ncmds, header.sizeofcmds).unwrap();
    while let Some(cmd) = it.next_command().unwrap() {
        if let LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_CHAINED_FIXUPS) = cmd.kind
        {
            let lc = pgr_format::LinkeditDataCommand::parse(cmd.bytes).unwrap();
            return lc.data(bytes).unwrap().to_vec();
        }
    }
    panic!("image carries no LC_DYLD_CHAINED_FIXUPS");
}

/// Walks every chain of a dynamic image; returns `(vaddr, word)` per
/// slot plus the parsed import table (the M2 harness's walk, verbatim —
/// it admits both 64-family pointer formats).
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
            seg.pointer_format == DYLD_CHAINED_PTR_64
                || seg.pointer_format == pgr_format::consts::DYLD_CHAINED_PTR_64_OFFSET,
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

/// The NUL-terminated import name at `offset` in the names blob.
fn import_name(names: &[u8], offset: u32) -> String {
    let start = offset as usize;
    names[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|e| String::from_utf8_lossy(&names[start..start + e]).into_owned())
        .unwrap_or_default()
}

/// The pointer format the image's chain payload declares.
fn pointer_format_of(payload: &[u8]) -> u16 {
    let hdr = parse_header(payload).unwrap();
    let starts = parse_starts_in_image(payload, hdr.starts_offset as usize).unwrap();
    let off = *starts
        .seg_info_offset
        .iter()
        .find(|&&o| o != 0)
        .expect("the payload declares at least one segment");
    parse_starts_in_segment(payload, hdr.starts_offset as usize + off as usize)
        .unwrap()
        .pointer_format
}

#[test]
fn m10_x86_64_golden_binds_slot_for_slot() {
    let Some(lld) = find_lld() else {
        eprintln!("skipping lld golden: no ld64.lld (set PGR_LLD64 or install lld)");
        return;
    };
    let dir = scratch("pair");
    let obj = dir.join("printf_main.o");
    std::fs::write(&obj, printf_main()).unwrap();
    let tbd = dir.join("libSystem.tbd");
    std::fs::write(&tbd, libsystem_tbd()).unwrap();
    let lld_out = dir.join("lld_out");

    // The golden linker's side of the pair: the same object, the same
    // tbd, the family's chained-fixups form.
    let status = std::process::Command::new(&lld)
        .args([
            "-arch",
            "x86_64",
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

    // Our side of the pair: the driver surface names the family
    // (`-arch x86_64`), the pipeline produces the image.
    let out = dir.join("pgr_out");
    let argv: Vec<OsString> = [
        "-o",
        out.to_str().unwrap(),
        "-arch",
        "x86_64",
        "-platform_version",
        "macos",
        "12.0",
        "14.0",
        obj.to_str().unwrap(),
        tbd.to_str().unwrap(),
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let opts = parse(&argv).expect("the flag set parses");
    pgr_driver::run(&opts).expect("the link completes");
    let pgr_image = std::fs::read(&out).unwrap();
    let lld_image = std::fs::read(&lld_out).unwrap();

    // Both payloads declare the family's pointer format (rebase
    // targets are VM addresses under `DYLD_CHAINED_PTR_64`).
    let pgr_payload = find_fixup_payload(&pgr_image);
    let lld_payload = find_fixup_payload(&lld_image);
    assert_eq!(
        pointer_format_of(&pgr_payload),
        DYLD_CHAINED_PTR_64,
        "our x86_64 image declares the family's VM-address pointer format"
    );
    assert_eq!(
        pointer_format_of(&lld_payload),
        DYLD_CHAINED_PTR_64,
        "the golden x86_64 image declares the family's VM-address pointer format"
    );

    // Semantic comparison: the multiset of (kind, lib, name, addend,
    // weak) over both images' fixup slots, plus each image's import
    // table (the M2 harness's comparison, family-neutral).
    let semantic_of = |payload: &[u8], image: &[u8]| -> Vec<(bool, u16, String, i64, bool)> {
        let (_, imports, names) = walk_chains(image, payload);
        let mut out = Vec::new();
        for (_, w) in walk_chains(image, payload).0 {
            if w.is_bind() {
                let imp = &imports[w.bind_ordinal() as usize];
                out.push((
                    true,
                    imp.lib_ordinal,
                    import_name(&names, imp.name_offset),
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
    let ours = semantic_of(&pgr_payload, &pgr_image);
    let golden = semantic_of(&lld_payload, &lld_image);
    assert_eq!(
        ours, golden,
        "bind/rebase slot semantics must match ld64.lld slot-for-slot"
    );

    // Import tables agree on the (lib, name, weak) pairs.
    let imports_of = |payload: &[u8], image: &[u8]| -> Vec<(u16, String, bool)> {
        let (_, imports, names) = walk_chains(image, payload);
        imports
            .iter()
            .map(|i| {
                (
                    i.lib_ordinal,
                    import_name(&names, i.name_offset),
                    i.weak_import,
                )
            })
            .collect()
    };
    assert_eq!(
        imports_of(&pgr_payload, &pgr_image),
        imports_of(&lld_payload, &lld_image),
        "the import tables agree on the (lib, name) pairs"
    );

    // Our side verifies strict (the family's read-side contract).
    let vopts = pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = pgr_verify::verify(&pgr_image, &vopts);
    assert!(report.is_ok(&vopts), "verifier issues: {report:?}");
}

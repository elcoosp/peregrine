//! The compressed-unwind consumer example (M35): the entry-carrying
//! corpus linked as a plain executable — the input's
//! `__LD,__compact_unwind` table rides the atom map onto the output
//! `__TEXT,__unwind_info`, whose qualifying rows ride the compressed
//! second-level family (the density rung past the M34 regular pages)
//! — the image verifies strict, the synthesized section's shape
//! decodes from the bytes (the header's arrays, the common encodings
//! array, the index, the compressed page header's five fields and its
//! 4-byte entries), and the planning seam reads the same shape before
//! any link runs.
//!
//! Run: `cargo run -p pgr-driver --example compact_unwind_compressed_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans —
//! the same inert-until-subscriber convention the binaries use).

use std::fmt::Write as _;

use pgr_core::unwind::{
    MAX_COMMON_ENCODINGS, UnwindEntry, plan_shape, synthesize, synthesized_size,
    synthesized_size_shape,
};
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::{
    UNWIND_ARM64_MODE_FRAME, UNWIND_ARM64_MODE_FRAMELESS, UNWIND_SECOND_LEVEL_COMPRESSED,
};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SegmentCommand64};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` over three RET functions, one compact-unwind
/// entry per function (range start = the function's blob-relative
/// address — the input convention the carriage translates from). The
/// frameless word on `_main` and the frame word on the rest give the
/// table two distinct final words — the common encodings array's two
/// rows.
fn hello_object(entries: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        Vec::new(),
    ));
    for (i, sym) in ["_main", "_fn_1", "_fn_2"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    if entries {
        let table: Vec<pgr_format::CompactUnwindEntry> = (0..3)
            .map(|f| pgr_format::CompactUnwindEntry {
                range_start: (f * 4) as u64,
                range_length: 4,
                encoding: if f == 0 {
                    UNWIND_ARM64_MODE_FRAMELESS | (0x20 << 12)
                } else {
                    UNWIND_ARM64_MODE_FRAME
                },
                personality: 0,
                lsda: 0,
            })
            .collect();
        b.add_section(ObjectSection::compact_unwind(&table));
    }
    b.build().expect("the fixture object builds")
}

/// The `__TEXT,__unwind_info` section's file offset and size, when the
/// image carries the synthesized section.
fn unwind_info_span(image: &[u8]) -> Option<(u32, u32)> {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg = SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            for s in seg
                .sections(cmd.bytes, SegmentCommand64::SIZE)
                .expect("the sections parse")
            {
                if s.segname.starts_with(b"__TEXT\0") && s.sectname.starts_with(b"__unwind_info\0")
                {
                    return Some((s.offset, s.size as u32));
                }
            }
        }
    }
    None
}

/// Decodes the synthesized section's shape: the header's arrays, the
/// common encodings rows, the index, and the compressed page's
/// entries resolved through the two-tier decode (tier one — the
/// section-level common array; the page-local tier rides empty) —
/// the walk the verifier's `unwind` family runs, shown here so a
/// build system can read the same plan without linking.
fn decode_unwind_info(image: &[u8], at: u32, size: u32) -> String {
    let s = &image[at as usize..(at + size) as usize];
    let rd32 = |o: usize| u32::from_le_bytes([s[o], s[o + 1], s[o + 2], s[o + 3]]);
    let version = rd32(0);
    let common_off = rd32(4) as usize;
    let common_count = rd32(8);
    let pers_count = rd32(16);
    let index_off = rd32(20) as usize;
    let index_count = rd32(24) as usize;
    let mut out = format!(
        "version {version}, common encodings {common_count}, personalities \
         {pers_count}, index {index_count} entries"
    );
    for i in 0..common_count as usize {
        writeln!(
            out,
            "\n  common[{i}]: encoding {:#010x}",
            rd32(common_off + i * 4)
        )
        .expect("the report writes");
    }
    for i in 0..index_count {
        let base = index_off + i * 12;
        let func = rd32(base);
        let page = rd32(base + 4);
        writeln!(out, "\n  index[{i}]: function {func:#x}, page {page:#x}")
            .expect("the report writes");
        if page == 0 {
            out.push_str(" (terminator)");
            continue;
        }
        let page = page as usize;
        let kind = rd32(page);
        assert_eq!(
            kind, UNWIND_SECOND_LEVEL_COMPRESSED,
            "the qualifying rows ride the compressed family"
        );
        let entry_page = u16::from_le_bytes([s[page + 4], s[page + 5]]);
        let entry_count = u16::from_le_bytes([s[page + 6], s[page + 7]]);
        let local_at = u16::from_le_bytes([s[page + 8], s[page + 9]]);
        let local_count = u16::from_le_bytes([s[page + 10], s[page + 11]]);
        write!(
            out,
            ", kind {kind}, {entry_count} entries at +{entry_page}, page-local \
             encodings {local_count} at +{local_at}:"
        )
        .expect("the report writes");
        for e in 0..entry_count as usize {
            let at = page + entry_page as usize + e * 4;
            let word = rd32(at);
            let f = word & 0x00FF_FFFF;
            let idx = word >> 24;
            let resolved = if idx < common_count {
                format!(
                    "common[{idx}] = {:#010x}",
                    rd32(common_off + idx as usize * 4)
                )
            } else {
                format!(
                    "page-local[{}] = {:#010x}",
                    idx - common_count,
                    rd32(page + local_at as usize + (idx - common_count) as usize * 4)
                )
            };
            writeln!(out, "\n    entry[{e}]: function {f:#x} -> {resolved}")
                .expect("the report writes");
        }
    }
    out
}

/// The same table the object carries, on the output `__TEXT`-relative
/// offsets the planning seam reads (the offsets are the shape's only
/// input that matters here — the counts and page families are pure
/// functions of the rows).
fn planned_entries(text_base: u32) -> Vec<UnwindEntry> {
    (0..3)
        .map(|f| UnwindEntry {
            function_offset: text_base + (f * 4) as u32,
            range_length: 4,
            encoding: if f == 0 {
                UNWIND_ARM64_MODE_FRAMELESS | (0x20 << 12)
            } else {
                UNWIND_ARM64_MODE_FRAME
            },
            personality_offset: 0,
            lsda_offset: 0,
        })
        .collect()
}

fn link(dir: &std::path::Path, out: &str, entries: bool) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object(entries)).unwrap();
    let out_path = dir.join(out);
    let argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).expect("the image reads")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_unwind_m35_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The plain executable: the table rides and the qualifying
    //    rows compress — the output's `__TEXT,__unwind_info` names the
    //    common array, one compressed page, and the image verifies
    //    strict like any other.
    let carried = link(&dir, "hello_unwind", true);
    let span = unwind_info_span(&carried).expect("the carriage lands the section");
    let report = verify(&carried, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the carrying image verifies strict: {:?}",
        report.issues
    );

    // 2. The default: an entry-free corpus plans the pre-M34 bytes —
    //    no section.
    let plain = link(&dir, "hello_plain", false);
    assert!(
        unwind_info_span(&plain).is_none(),
        "the entry-free corpus synthesizes nothing"
    );

    // 3. The planning seam reads the same shape before any link: the
    //    exact planner and the linked image's bytes agree, the
    //    all-regular M34 shape names the size the density rung saved,
    //    and a table past the 24-bit mark plans zero compressed pages
    //    (the pre-M35 bytes). The table rides the output-relative
    //    offsets the carriage translates onto (the qualification and
    //    every count are pure functions of the rows).
    let entries = planned_entries(0);
    let shape = plan_shape(&entries).expect("the honest table plans");
    let exact = synthesize(&entries).expect("the honest table synthesizes");
    let m34_shape = synthesized_size(shape.entry_count, shape.personality_count, shape.lsda_count);
    let beyond = vec![UnwindEntry {
        function_offset: 0x0100_0000,
        range_length: 4,
        encoding: UNWIND_ARM64_MODE_FRAME,
        personality_offset: 0,
        lsda_offset: 0,
    }];
    let beyond_shape = plan_shape(&beyond).expect("the beyond table plans");

    assert_eq!(
        exact.bytes.len(),
        span.1 as usize,
        "the planner and the linked image agree on the section's size"
    );
    assert_eq!(
        shape.compressed_page_count, 1,
        "the linked table's rows all qualify"
    );
    assert_eq!(
        shape.common_encoding_count, 2,
        "the table's two distinct words ride the common array"
    );
    assert_eq!(
        beyond_shape.compressed_page_count, 0,
        "a table past the 24-bit mark plans the pre-M35 bytes"
    );
    assert!(shape.common_encoding_count <= MAX_COMMON_ENCODINGS);
    // The density at the size the rung exists for: 4096 rows over one
    // encoding — the M34 all-regular shape plans 8-byte rows, the
    // compressed rung halves them through the one-row common array.
    let dense: Vec<UnwindEntry> = (0..4096)
        .map(|f| UnwindEntry {
            function_offset: (f * 4) as u32,
            range_length: 4,
            encoding: UNWIND_ARM64_MODE_FRAME,
            personality_offset: 0,
            lsda_offset: 0,
        })
        .collect();
    let dense_shape = plan_shape(&dense).expect("the dense table plans");
    let dense_exact = synthesize(&dense).expect("the dense table synthesizes");
    let dense_m34 = synthesized_size(
        dense_shape.entry_count,
        dense_shape.personality_count,
        dense_shape.lsda_count,
    );
    assert_eq!(
        dense_exact.bytes.len(),
        synthesized_size_shape(&dense_shape),
        "the dense table's planner and builder agree"
    );

    println!(
        "carried: __TEXT,__unwind_info at file offset {:#x}, {} bytes of image \
         ({} section bytes)",
        span.0,
        carried.len(),
        span.1
    );
    println!(
        "density: the M34 all-regular shape plans {m34_shape} bytes for the same \
         counts; the compressed rung plans {} — the qualifying rows ride \
         4-byte entries through the common array",
        exact.bytes.len()
    );
    println!(
        "density at scale: 4096 rows over one encoding plan {dense_m34} bytes \
         all-regular and {} compressed ({}% of the M34 shape)",
        dense_exact.bytes.len(),
        100 * dense_exact.bytes.len() / dense_m34
    );
    println!(
        "suppressed: __unwind_info absent ({} bytes of image — the pre-M34 bytes)",
        plain.len()
    );
    println!(
        "\nthe synthesized section, decoded:\n{}",
        decode_unwind_info(&carried, span.0, span.1)
    );
}

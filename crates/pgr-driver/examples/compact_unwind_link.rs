//! The compact-unwind consumer example (M34): the entry-carrying
//! corpus linked as a plain executable — the input's
//! `__LD,__compact_unwind` table rides the atom map onto the output
//! `__TEXT,__unwind_info` (the section dyld's unwinder and every
//! backtrace reader walks) — the same corpus without the table
//! planning the pre-M34 bytes, both run through the strict verifier,
//! and the synthesized section's shape decoded from the image: the
//! header's arrays, the index, the regular pages and their entries.
//!
//! Run: `cargo run -p pgr-driver --example compact_unwind_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans —
//! the same inert-until-subscriber convention the binaries use).

use std::fmt::Write as _;

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::UNWIND_ARM64_MODE_FRAME;
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SegmentCommand64};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` over three RET functions, one compact-unwind entry
/// per function (range start = the function's blob-relative address —
/// the input convention the carriage translates from).
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
                encoding: UNWIND_ARM64_MODE_FRAME,
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
/// index, and each regular page's entry rows (the walk the verifier's
/// `unwind` family runs — shown here so a build system can read the
/// same plan without linking).
fn decode_unwind_info(image: &[u8], at: u32, size: u32) -> String {
    let s = &image[at as usize..(at + size) as usize];
    let rd32 = |o: usize| u32::from_le_bytes([s[o], s[o + 1], s[o + 2], s[o + 3]]);
    let version = rd32(0);
    let common_count = rd32(8);
    let personality_count = rd32(16);
    let index_off = rd32(20) as usize;
    let index_count = rd32(24) as usize;
    let mut out = format!(
        "version {version}, common encodings {common_count}, personalities \
         {personality_count}, index {index_count} entries"
    );
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
        let kind = rd32(page as usize);
        let entry_count = u16::from_le_bytes([s[page as usize + 6], s[page as usize + 7]]);
        write!(out, ", kind {kind}, {entry_count} regular entries:").expect("the report writes");
        let entries_at = page as usize + 8;
        for e in 0..entry_count as usize {
            let at = entries_at + e * 8;
            writeln!(
                out,
                "\n    entry[{e}]: function {:#x}, encoding {:#010x}",
                rd32(at),
                rd32(at + 4)
            )
            .expect("the report writes");
        }
    }
    out
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

    let dir = std::env::temp_dir().join(format!("pgr_unwind_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The plain executable: the table rides — the output's
    //    `__TEXT,__unwind_info` names one entry per live function and
    //    the image verifies strict like any other.
    let carried = link(&dir, "hello_unwind", true);
    let span = unwind_info_span(&carried).expect("the carriage lands the section");
    let report = verify(&carried, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the carrying image verifies strict: {:?}",
        report.issues
    );

    // 2. The default: an entry-free corpus plans the pre-M34 bytes —
    //    no section, byte-identical to the pre-M34 link.
    let plain = link(&dir, "hello_plain", false);
    assert!(
        unwind_info_span(&plain).is_none(),
        "the entry-free corpus synthesizes nothing"
    );
    let report = verify(&plain, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the pre-M34 shape verifies strict: {:?}",
        report.issues
    );

    println!(
        "carried: __TEXT,__unwind_info at file offset {:#x}, {} bytes of image",
        span.0,
        carried.len()
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

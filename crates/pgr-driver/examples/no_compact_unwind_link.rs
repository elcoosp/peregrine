//! The no-compact-unwind consumer example (M36): the entry-carrying
//! corpus linked under the default (the `__LD,__compact_unwind` table
//! rides the atom map onto the output `__TEXT,__unwind_info` — the M35
//! compressed shape) beside the same corpus under `-no_compact_unwind`
//! (the section drops — the pre-M34 bytes), both run through the
//! strict verifier, and the suppression's file-size delta printed —
//! the knob a build system names when its toolchain carries its own
//! unwinder data.
//!
//! Run: `cargo run -p pgr-driver --example no_compact_unwind_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans —
//! the same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::UNWIND_ARM64_MODE_FRAME;
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SegmentCommand64};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` over three RET functions, one compact-unwind entry
/// per function (range start = the function's blob-relative address —
/// the input convention the carriage translates from).
fn hello_object() -> Vec<u8> {
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

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    argv.extend(extra.iter().map(std::ffi::OsString::from));
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

    let dir = std::env::temp_dir().join(format!("pgr_no_unwind_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The default: the table rides — the output's
    //    `__TEXT,__unwind_info` carries the M35 compressed shape and
    //    the image verifies strict like any other.
    let carried = link(&dir, "hello_unwind", &[]);
    let span = unwind_info_span(&carried).expect("the carriage lands the section");
    let report = verify(&carried, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the carrying image verifies strict: {:?}",
        report.issues
    );

    // 2. The suppression: the same corpus under `-no_compact_unwind` —
    //    the section drops (the pre-M34 bytes) and the image verifies
    //    strict. The parse still validates the table — the knob is a
    //    Pass-3 decision, never a parse blindfold.
    let suppressed = link(&dir, "hello_suppressed", &["-no_compact_unwind"]);
    assert!(
        unwind_info_span(&suppressed).is_none(),
        "the suppression drops the section"
    );
    let report = verify(&suppressed, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the suppressed image verifies strict: {:?}",
        report.issues
    );

    println!(
        "carried: __TEXT,__unwind_info at file offset {:#x}, {} section bytes, \
         {} bytes of image",
        span.0,
        span.1,
        carried.len()
    );
    println!(
        "suppressed: __unwind_info absent ({} bytes of image — the pre-M34 bytes; \
         the file-size delta rides the 16 KiB segment congruence)",
        suppressed.len()
    );
}

//! The image-base consumer example (M15): the same `hello.o` linked
//! twice — once at the default 4 GiB base and once under
//! `-pagezero_size 0x40000000` — with the segment table read back from
//! both images, the strict verifier on both, and the misaligned-override
//! refusal rendered as miette help text (the fix, not just the verdict:
//! the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example pagezero_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use; the seam's
//! own decision event rides it).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` returns through a data pointer pair — two rebase
/// slots, so the fixup plan (whose `64_OFFSET` words encode
/// `target − base`) rides the example's base move.
fn hello_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6, 0xC0u8, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let helper_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_helper".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.section_mut(data).relocs = vec![
        ObjectReloc::unsigned(u32::try_from(main_sym).unwrap()).at(0),
        ObjectReloc::unsigned(u32::try_from(helper_sym).unwrap()).at(8),
    ];
    b.build().expect("the fixture object builds")
}

/// The image's segment table: `(name, vmaddr, vmsize, fileoff)`.
fn segment_rows(image: &[u8]) -> Vec<(String, u64, u64, u64)> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut rows = Vec::new();
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the command parses");
            rows.push((
                seg.name().unwrap_or("<non-utf8>").to_string(),
                seg.vmaddr,
                seg.vmsize,
                seg.fileoff,
            ));
        }
    }
    rows
}

fn link(dir: &std::path::Path, out: &str, pagezero: Option<&str>) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    if let Some(pz) = pagezero {
        argv.push(std::ffi::OsString::from("-pagezero_size"));
        argv.push(std::ffi::OsString::from(pz));
    }
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

    let dir = std::env::temp_dir().join(format!("pgr_pagezero_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // The two links: the Mach-O default (4 GiB) and a 1 GiB base.
    let default_image = link(&dir, "hello_default", None);
    let custom_image = link(&dir, "hello_1gib", Some("0x40000000"));
    for (label, image) in [
        ("default (4 GiB)", &default_image),
        ("custom (1 GiB)", &custom_image),
    ] {
        let report = verify(
            image,
            &VerifyOptions {
                strict_warnings: true,
                skip_hash_recompute: false,
            },
        );
        let opts = VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        };
        assert!(
            report.is_ok(&opts),
            "the {label} image verifies strict: {:#?}",
            report.issues
        );
        println!("{label} segments:");
        for (name, vmaddr, vmsize, fileoff) in segment_rows(image) {
            println!(
                "  {name:<14} vmaddr {vmaddr:#014x}  vmsize {vmsize:#010x}  fileoff {fileoff:#010x}"
            );
        }
        println!();
    }

    // The refusal: a misaligned override is refused at parse time, the
    // fix in the help text — the flag's grammar, not just a verdict.
    let argv: Vec<std::ffi::OsString> = [
        "-o".as_ref(),
        dir.join("hello_bad").as_os_str(),
        dir.join("hello.o").as_os_str(),
        "-pagezero_size".as_ref(),
        "0x3000".as_ref(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the misaligned override refuses"),
        Err(err) => {
            let report = miette::Report::new(err);
            println!("misaligned -pagezero_size refusal:");
            println!("  {report}");
            if let Some(help) = report.help() {
                println!("  fix: {help}");
            }
        }
    }

    println!(
        "\nimages: {} (strict-verified; try PGR_TRACING=1 to watch the base decision)",
        dir.display()
    );
}

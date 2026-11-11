//! The initializer-offsets consumer example (M16): the same `hello.o`
//! linked twice — once in the classic pointer form (the default) and
//! once under `-init_offsets` — with the initializer sections read back
//! from both images, the strict verifier on both, and the below-floor
//! refusal rendered as miette help text (the fix, not just the verdict:
//! the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example init_offsets_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use; the seam's
//! own decision event rides it).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{S_INIT_FUNC_OFFSETS, S_MOD_INIT_FUNC_POINTERS, SECTION_TYPE_MASK};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SegmentCommand64};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` plus two initializer functions, each targeted by one
/// 8-byte pointer in a `__mod_init_func` section — the shape the
/// transform consumes.
fn hello_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        Vec::new(),
    ));
    for (f, name) in ["_main", "_init_one", "_init_two"].into_iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: name.into(),
            section_index: text,
            value: (f * 4) as u64,
            weak: false,
        });
    }
    let modinit = b.add_section(ObjectSection::data(
        "__mod_init_func",
        vec![0u8; 16],
        vec![
            ObjectReloc::unsigned(1).at(0),
            ObjectReloc::unsigned(2).at(8),
        ],
    ));
    b.section_mut(modinit).flags = S_MOD_INIT_FUNC_POINTERS;
    b.build().expect("the fixture object builds")
}

/// A section record: `(seg, name, flags, size, file_off)`.
fn section_rows(image: &[u8]) -> Vec<(String, String, u32, u64, u64)> {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands walk");
    let mut rows = Vec::new();
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == LoadCommandKind::Segment64 {
            let seg = SegmentCommand64::parse(cmd.bytes, 0).expect("the command parses");
            let seg_name = seg.name().unwrap_or("<non-utf8>").to_string();
            let sects = seg
                .sections(cmd.bytes, SegmentCommand64::SIZE)
                .expect("the section array parses");
            for s in sects {
                rows.push((
                    seg_name.clone(),
                    s.name().unwrap_or("<non-utf8>").to_string(),
                    s.flags,
                    s.size,
                    u64::from(s.offset),
                ));
            }
        }
    }
    rows
}

fn link(dir: &std::path::Path, out: &str, init_offsets: bool) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    if init_offsets {
        argv.push(std::ffi::OsString::from("-init_offsets"));
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

    let dir = std::env::temp_dir().join(format!("pgr_init_offsets_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // The two links: the classic pointer form (the default) and the
    // `__init_offsets` transform.
    let classic = link(&dir, "hello_classic", false);
    let offsets = link(&dir, "hello_offsets", true);
    for (label, image) in [("classic (default)", &classic), ("init_offsets", &offsets)] {
        let opts = VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        };
        let report = verify(image, &opts);
        assert!(
            report.is_ok(&opts),
            "the {label} image verifies strict: {:#?}",
            report.issues
        );
        let rows = section_rows(image);
        println!("{label}:");
        let classic_ptr = rows
            .iter()
            .find(|(_, name, flags, _, _)| {
                *name == "__mod_init_func" && flags & SECTION_TYPE_MASK == S_MOD_INIT_FUNC_POINTERS
            })
            .map(|(_, _, _, size, _)| *size);
        let offsets_sect = rows
            .iter()
            .find(|(_, name, flags, _, _)| {
                *name == "__init_offsets" && flags & SECTION_TYPE_MASK == S_INIT_FUNC_OFFSETS
            })
            .map(|(_, _, _, size, off)| (*size, *off));
        if let Some(size) = classic_ptr {
            println!(
                "  __mod_init_func  {size:>4} B  (two 8-byte pointers, chained/classic rebase slots)"
            );
        }
        if let Some((size, off)) = offsets_sect {
            let entries: Vec<u32> = image[off as usize..(off + size) as usize]
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().expect("4-byte entry")))
                .collect();
            let text = rows
                .iter()
                .find(|(_, name, _, _, _)| name == "__text")
                .expect("__text");
            println!("  __init_offsets   {size:>4} B  (two u32 offsets from the load address)");
            for (i, e) in entries.iter().enumerate() {
                let at = text.4 + u64::from(*e);
                println!("    entry {i}: {e:#010x}  (__text at file offset {at:#x})");
            }
        }
        println!();
    }

    // The refusal: a target below the platform's chained-fixups floor
    // cannot consume `S_INIT_FUNC_OFFSETS` at all — refused at parse
    // time, the fix in the help text.
    let obj = dir.join("hello.o");
    let argv: Vec<std::ffi::OsString> = [
        "-o".as_ref(),
        dir.join("hello_floor").as_os_str(),
        "-platform_version".as_ref(),
        "ios".as_ref(),
        "14.0".as_ref(),
        "14.0".as_ref(),
        "-init_offsets".as_ref(),
        obj.as_os_str(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the below-floor form refuses"),
        Err(err) => {
            let report = miette::Report::new(err);
            println!("below-floor -init_offsets refusal:");
            println!("  {report}");
            if let Some(help) = report.help() {
                println!("  fix: {help}");
            }
        }
    }

    println!(
        "\nimages: {} (strict-verified; try PGR_TRACING=1 to watch the form decision)",
        dir.display()
    );
}

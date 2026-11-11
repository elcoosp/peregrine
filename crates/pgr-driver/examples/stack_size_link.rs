//! The stack-reserve consumer example (M18): the same `hello.o` linked
//! twice — once at the pre-M18 zero reserve and once under
//! `-stack_size 0x1000000` — with the `LC_MAIN` reserve read back from
//! both images, the strict verifier on both, and the misaligned-reserve
//! refusal rendered as miette help text (the fix, not just the verdict:
//! the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example stack_size_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use; the seam's
//! own decision event rides it).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` returns through a data pointer pair — two rebase
/// slots, so the example's link carries real fixup work under either
/// reserve.
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

/// The image's `LC_MAIN.stacksize` field.
fn stack_reserve(image: &[u8]) -> u64 {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::Main {
            let ep = pgr_format::EntryPointCommand::parse(cmd.bytes).expect("the command parses");
            return ep.stacksize;
        }
    }
    panic!("an executable carries LC_MAIN");
}

fn link(dir: &std::path::Path, out: &str, stack_size: Option<&str>) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    if let Some(reserve) = stack_size {
        argv.push(std::ffi::OsString::from("-stack_size"));
        argv.push(std::ffi::OsString::from(reserve));
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

    let dir = std::env::temp_dir().join(format!("pgr_stack_size_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // The two links: the zero reserve (dyld's own default) and a 16 MiB
    // reservation.
    let default_image = link(&dir, "hello_default", None);
    let custom_image = link(&dir, "hello_reserved", Some("0x1000000"));
    for (label, image) in [
        ("default (zero reserve)", &default_image),
        ("reserved (16 MiB)", &custom_image),
    ] {
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
        println!("{label}: LC_MAIN.stacksize = {:#x}", stack_reserve(image));
    }

    // The refusal: a misaligned reserve is refused at parse time, the
    // fix in the help text — the flag's grammar, not just a verdict.
    let argv: Vec<std::ffi::OsString> = [
        "-o".as_ref(),
        dir.join("hello_bad").as_os_str(),
        dir.join("hello.o").as_os_str(),
        "-stack_size".as_ref(),
        "0x3000".as_ref(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the misaligned reserve refuses"),
        Err(err) => {
            let report = miette::Report::new(err);
            println!("misaligned -stack_size refusal:");
            println!("  {report}");
            if let Some(help) = report.help() {
                println!("  fix: {help}");
            }
        }
    }

    println!(
        "\nimages: {} (strict-verified; try PGR_TRACING=1 to watch the reserve decision)",
        dir.display()
    );
}

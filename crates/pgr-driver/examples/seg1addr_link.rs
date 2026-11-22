//! The first-segment-base consumer example (M124): the same `hello.o`
//! linked twice as an executable — once at the default 4 GiB
//! constant-delta floor and once under `-seg1addr 0x40000000` — with
//! the `__PAGEZERO` vmsize and the `__TEXT` vmaddr read back from both
//! images (the override shifts both at once, the constant-delta
//! contract `vmaddr = fileoff + base`), the strict verifier on both,
//! and the bundle and `-r` refusals rendered as miette help text (the
//! fix, not just the verdict: the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example seg1addr_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use; the seam's
//! own decision event rides it).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` over a small `__text` — the executable the example
/// links twice.
fn hello_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// The `(name, vmaddr, vmsize)` row of the first two segments
/// (`__PAGEZERO`, `__TEXT`) — the two words the override shifts.
fn first_segments(image: &[u8]) -> Vec<(&'static str, u64, u64)> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut out = Vec::new();
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            if let Ok(name) = seg.name() {
                if name == "__PAGEZERO" || name == "__TEXT" {
                    out.push((
                        match name {
                            "__PAGEZERO" => "__PAGEZERO",
                            "__TEXT" => "__TEXT",
                            _ => unreachable!("guarded above"),
                        },
                        seg.vmaddr,
                        seg.vmsize,
                    ));
                }
            }
        }
        if out.len() == 2 {
            break;
        }
    }
    out
}

fn link(dir: &std::path::Path, out: &str, seg1addr: Option<&str>) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    if let Some(base) = seg1addr {
        argv.push(std::ffi::OsString::from("-seg1addr"));
        argv.push(std::ffi::OsString::from(base));
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

    let dir = std::env::temp_dir().join(format!("pgr_seg1addr_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // The two links: the default 4 GiB floor (the pre-M124 constant)
    // and a named 1 GiB first-segment base.
    let default_image = link(&dir, "hello_default", None);
    let custom_image = link(&dir, "hello_seg1addr", Some("0x40000000"));
    for (label, image, expected_base) in [
        ("default (4 GiB floor)", &default_image, 0x1_0000_0000u64),
        ("named (1 GiB base)", &custom_image, 0x4000_0000u64),
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
        let segs = first_segments(image);
        let (pz_vmaddr, pz_vmsize) = segs
            .iter()
            .find(|(n, _, _)| *n == "__PAGEZERO")
            .map(|(_, a, s)| (*a, *s))
            .expect("__PAGEZERO present");
        let (text_vmaddr, _) = segs
            .iter()
            .find(|(n, _, _)| *n == "__TEXT")
            .map(|(_, a, s)| (*a, *s))
            .expect("__TEXT present");
        assert_eq!(pz_vmaddr, 0, "__PAGEZERO.vmaddr is always 0");
        assert_eq!(
            pz_vmsize, expected_base,
            "__PAGEZERO.vmsize == the first segment base"
        );
        assert_eq!(
            text_vmaddr, expected_base,
            "__TEXT.vmaddr == the first segment base (the constant-delta contract)"
        );
        println!("{label}: __PAGEZERO.vmsize = {pz_vmsize:#x}, __TEXT.vmaddr = {text_vmaddr:#x}");
    }

    // The refusals: a bundle's preferred load address is its loader's
    // job, and the relocatable output carries no segments — the fix in
    // the help text.
    for (kind, label) in [("-bundle", "bundle"), ("-r", "relocatable")] {
        let argv: Vec<std::ffi::OsString> = [
            "-o".as_ref(),
            dir.join("refused").as_os_str(),
            kind.as_ref(),
            "-seg1addr".as_ref(),
            "0x40000000".as_ref(),
            dir.join("hello.o").as_os_str(),
        ]
        .iter()
        .map(std::ffi::OsString::from)
        .collect();
        match opts::parse(&argv) {
            Ok(_) => unreachable!("the {label} conflict refuses"),
            Err(err) => {
                let report = miette::Report::new(err);
                println!("-seg1addr on a {label} refusal:");
                println!("  {report}");
                if let Some(help) = report.help() {
                    println!("  fix: {help}");
                }
            }
        }
    }

    println!("both executables verify strict — the base is the constant-delta address arithmetic");
}

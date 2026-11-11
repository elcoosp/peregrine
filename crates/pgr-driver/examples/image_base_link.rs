//! The dylib/bundle image-base consumer example (M19): the same
//! `sdk.o` linked twice as a dylib — once at the M3 zero base and once
//! under `-image_base 0x80000` — with the `__TEXT` vmaddr read back
//! from both images, the strict verifier on both, and the
//! executable-conflict refusal rendered as miette help text (the fix,
//! not just the verdict: the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example image_base_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use; the seam's
//! own decision event rides it).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// sdk.o: an exported surface (`_sdk_init`, `_sdk_read`) over a small
/// `__text` — the dylib the example links twice.
fn sdk_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("sdk.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        Vec::new(),
    ));
    for (i, sym) in ["_sdk_init", "_sdk_read"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.build().expect("the fixture object builds")
}

/// The image's `__TEXT` `(vmaddr, fileoff)` row.
fn text_vmaddr(image: &[u8]) -> (u64, u64) {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            if seg.name() == Ok("__TEXT") {
                return (seg.vmaddr, seg.fileoff);
            }
        }
    }
    panic!("a dylib carries __TEXT");
}

fn link(dir: &std::path::Path, out: &str, image_base: Option<&str>) -> Vec<u8> {
    let obj = dir.join("sdk.o");
    std::fs::write(&obj, sdk_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        std::ffi::OsString::from("-dylib"),
        std::ffi::OsString::from("-install_name"),
        std::ffi::OsString::from("@rpath/libsdk.dylib"),
        obj.as_os_str().to_os_string(),
    ];
    if let Some(base) = image_base {
        argv.push(std::ffi::OsString::from("-image_base"));
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

    let dir = std::env::temp_dir().join(format!("pgr_image_base_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // The two links: the M3 zero base (the pre-M19 contract) and a
    // 512 KiB preferred load address.
    let default_image = link(&dir, "libdefault.dylib", None);
    let custom_image = link(&dir, "libcustom.dylib", Some("0x80000"));
    for (label, image) in [
        ("default (zero base)", &default_image),
        ("named (512 KiB base)", &custom_image),
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
        let (vmaddr, fileoff) = text_vmaddr(image);
        println!("{label}: __TEXT.vmaddr = {vmaddr:#x}, fileoff = {fileoff:#x}");
    }

    // The refusal: an image base on an executable refuses at parse
    // time (the executable's base is __PAGEZERO's job — M15 named
    // `-pagezero_size` for it), the fix in the help text.
    let argv: Vec<std::ffi::OsString> = [
        "-o".as_ref(),
        dir.join("hello").as_os_str(),
        dir.join("sdk.o").as_os_str(),
        "-image_base".as_ref(),
        "0x80000".as_ref(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the executable conflict refuses"),
        Err(err) => {
            let report = miette::Report::new(err);
            println!("-image_base on an executable refusal:");
            println!("  {report}");
            if let Some(help) = report.help() {
                println!("  fix: {help}");
            }
        }
    }

    println!("both dylibs verify strict — the base is the constant-delta address arithmetic");
}

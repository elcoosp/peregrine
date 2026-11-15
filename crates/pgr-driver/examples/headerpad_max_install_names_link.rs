//! The headerpad-max consumer example (M38): a main corpus binding two
//! stub dylibs whose install names differ in length — the natural link
//! beside the `-headerpad_max_install_names` link — both verified
//! strict, the reserved header region's growth printed (the room
//! `install_name_tool` needs to rewrite any install name in place).
//!
//! Run: `cargo run -p pgr-driver --example headerpad_max_install_names_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans —
//! the same inert-until-subscriber convention the binaries use).

use pgr_core::header_pad::install_names_growth;
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SegmentCommand64};
use pgr_verify::{Options as VerifyOptions, verify};

/// main.o: `_main` (RET) with one undefined `_fn_a` reference.
fn main_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_fn_a".into(),
        weak_ref: false,
    });
    b.build().expect("the fixture object builds")
}

/// The reserved header region: the first `__TEXT` section's file offset.
fn region_size(image: &[u8]) -> u64 {
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
                let seg_name: Vec<u8> =
                    s.segname.iter().take_while(|&&b| b != 0).copied().collect();
                let sect_name: Vec<u8> = s
                    .sectname
                    .iter()
                    .take_while(|&&b| b != 0)
                    .copied()
                    .collect();
                if seg_name == b"__TEXT" && sect_name == b"__text" {
                    return u64::from(s.offset);
                }
            }
        }
    }
    0
}

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let obj = dir.join("main.o");
    std::fs::write(&obj, main_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
        std::ffi::OsString::from("-flat_namespace"),
        std::ffi::OsString::from("-undefined"),
        std::ffi::OsString::from("dynamic_lookup"),
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
    let dir = std::env::temp_dir().join(format!("pgr_hpad_max_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // The install names the plan grows toward: one long, one short.
    let names = [
        "@rpath/lib_with_a_long_install_name.dylib",
        "@rpath/lib_a.dylib",
    ];
    let growth = install_names_growth(&names);

    // 1. The natural link: the region is the header's natural size, and
    //    the image verifies strict like any other.
    let natural_image = link(&dir, "app_natural", &[]);
    let natural = region_size(&natural_image);
    let report = verify(&natural_image, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the natural image verifies strict: {:?}",
        report.issues
    );

    // 2. The auto-floor: the same corpus under
    //    `-headerpad_max_install_names` — the region grows by the
    //    install names' growth (the flag rides the argv; the driver
    //    config composes with `-headerpad`).
    let floored_image = {
        let obj = dir.join("main.o");
        let out_path = dir.join("app_floored");
        let argv: Vec<std::ffi::OsString> = vec![
            std::ffi::OsString::from("-o"),
            out_path.as_os_str().to_os_string(),
            obj.as_os_str().to_os_string(),
            std::ffi::OsString::from("-flat_namespace"),
            std::ffi::OsString::from("-undefined"),
            std::ffi::OsString::from("dynamic_lookup"),
            std::ffi::OsString::from("-headerpad_max_install_names"),
        ];
        let o = opts::parse(&argv).expect("the argv parses");
        assert!(
            o.config.header_pad_max_install_names,
            "the auto-floor names the decision"
        );
        pgr_driver::run(&o).expect("the link runs");
        std::fs::read(&out_path).expect("the image reads")
    };
    let floored = region_size(&floored_image);
    let report = verify(&floored_image, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the floored image verifies strict: {:?}",
        report.issues
    );

    println!(
        "natural: header region {} bytes ({} bytes of image)",
        natural,
        natural_image.len()
    );
    println!(
        "auto-floor: header region {} bytes ({} bytes of image) — \
         the planned growth for two install names of {}/{} bytes is {} bytes \
         (each grown to the longest +1 NUL, 8-byte aligned)",
        floored,
        floored_image.len(),
        names[0].len(),
        names[1].len(),
        growth,
    );
    println!("verify: both images pass strict");
}

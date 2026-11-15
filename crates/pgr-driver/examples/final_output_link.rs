//! The final-output consumer example (M44): one dylib linked three
//! ways — the `-o`-path install-name default (every pre-M44 link), the
//! `-final_output` universal path (the multi-arch driver names the
//! universal path, every slice records it), and the explicit
//! `-install_name` winning over the flag (the man-page rule) — the
//! recorded `LC_ID_DYLIB` printed for each, all run through the strict
//! verifier.
//!
//! Run: `cargo run -p pgr-driver --example final_output_link`

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{DylibCommand, LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};

/// lib.o: one exported definition over a RET body (the dylib's surface).
fn provider_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("lib.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// The `LC_ID_DYLIB` install name the image records.
fn id_install_name(image: &[u8]) -> String {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::IdDylib = cmd.kind {
            let dylib_cmd = DylibCommand::parse(cmd.bytes).expect("the dylib command parses");
            let name = dylib_cmd.name(cmd.bytes).expect("the install name reads");
            return String::from_utf8_lossy(name).into_owned();
        }
    }
    panic!("the dylib image carries LC_ID_DYLIB")
}

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        std::ffi::OsString::from("-dylib"),
    ];
    let obj = dir.join("lib.o");
    std::fs::write(&obj, provider_object()).unwrap();
    argv.push(obj.as_os_str().to_os_string());
    argv.extend(extra.iter().map(std::ffi::OsString::from));
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).expect("the image reads")
}

fn main() {
    let dir = std::env::temp_dir().join(format!("pgr_final_output_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The default: the install name records the `-o` path (every
    //    pre-M44 link, unchanged) and the image verifies strict.
    let default = link(&dir, "libdefault.dylib", &[]);
    assert_eq!(
        id_install_name(&default),
        dir.join("libdefault.dylib").display().to_string(),
        "the default records the -o path"
    );
    let report = verify(&default, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the default dylib verifies strict: {:?}",
        report.issues
    );

    // 2. The flag: `-final_output` supplies the recorded install name —
    //    the universal path every arch slice records, whatever its own
    //    `-o` path is.
    let universal = "/usr/local/lib/libuniversal.dylib";
    let flagged = link(&dir, "libflagged.dylib", &["-final_output", universal]);
    assert_eq!(
        id_install_name(&flagged),
        universal,
        "the flag supplies the default"
    );
    let report = verify(&flagged, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the flagged dylib verifies strict: {:?}",
        report.issues
    );

    // 3. The precedence: an explicit `-install_name` wins over the flag
    //    (the man-page rule: the flag applies only when -install_name
    //    is not used).
    let explicit = link(
        &dir,
        "libboth.dylib",
        &[
            "-final_output",
            universal,
            "-install_name",
            "@rpath/libexplicit.dylib",
        ],
    );
    assert_eq!(
        id_install_name(&explicit),
        "@rpath/libexplicit.dylib",
        "the explicit -install_name wins"
    );

    println!("default:  {}", id_install_name(&default));
    println!("flagged:  {}", id_install_name(&flagged));
    println!(
        "explicit: {} (the -install_name wins over -final_output)",
        id_install_name(&explicit)
    );
}

//! The sub-client consumer example (M21): the same `sdk.o` linked as a
//! plain dylib and as an identity-block dylib naming
//! `-sub_client client.app` — the client command read back from the
//! image, the strict verifier on both, and the executable-conflict
//! refusal rendered as miette help text (the fix, not just the verdict:
//! the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example sub_client_link`
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

/// The image's `(opcode, name)` rows for the identity-block sub
/// commands (the M20 region and the M21 clients).
fn sub_rows(image: &[u8]) -> Vec<(u32, String)> {
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
        if matches!(
            cmd.kind,
            pgr_format::LoadCommandKind::SubUmbrella
                | pgr_format::LoadCommandKind::SubLibrary
                | pgr_format::LoadCommandKind::SubClient
        ) {
            let off = u32::from_le_bytes(cmd.bytes[8..12].try_into().expect("lc_str")) as usize;
            let name = String::from_utf8_lossy(&cmd.bytes[off..]).to_string();
            let name = name.trim_end_matches('\0').to_string();
            rows.push((cmd.hdr().0, name));
        }
    }
    rows
}

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
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
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
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

    let dir = std::env::temp_dir().join(format!("pgr_sub_client_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // 1. The plain dylib: the pre-M21 shape — no client commands.
    let plain = link(&dir, "libplain.dylib", &[]);
    assert!(
        sub_rows(&plain).is_empty(),
        "the default carries no sub commands"
    );
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&plain, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the plain dylib verifies strict"
    );

    // 2. The restricted dylib: the client command rides the identity
    // block (after any M20 region members), in flag order.
    let restricted = link(
        &dir,
        "librestricted.dylib",
        &["-sub_umbrella", "libsub.dylib", "-sub_client", "client.app"],
    );
    let rows = sub_rows(&restricted);
    println!("identity block:");
    for (opcode, name) in &rows {
        let kind = match *opcode {
            pgr_format::consts::LC_SUB_UMBRELLA => "LC_SUB_UMBRELLA",
            pgr_format::consts::LC_SUB_LIBRARY => "LC_SUB_LIBRARY",
            pgr_format::consts::LC_SUB_CLIENT => "LC_SUB_CLIENT",
            _ => unreachable!("only sub commands are collected"),
        };
        println!("  {opcode:#010x} {name} ({kind})");
    }
    assert_eq!(
        rows,
        vec![
            (
                pgr_format::consts::LC_SUB_UMBRELLA,
                "libsub.dylib".to_string()
            ),
            (pgr_format::consts::LC_SUB_CLIENT, "client.app".to_string()),
        ],
        "the region and the clients ride the identity block in order"
    );
    let report = verify(&restricted, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the restricted dylib verifies strict like the plain one"
    );

    // 3. The refusal: the clients off a dylib are a parse-time refusal —
    // rendered as miette help text (the fix, not just the verdict).
    let obj = dir.join("sdk.o");
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("exe").display().to_string(),
        "-sub_client".to_string(),
        "client.app".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the executable conflict refuses"),
        Err(err) => {
            eprintln!("\nthe refusal (verdict + fix):");
            eprintln!("{:?}", miette::Report::new(err));
        }
    }

    println!("\nsub_client_link: ok");
}

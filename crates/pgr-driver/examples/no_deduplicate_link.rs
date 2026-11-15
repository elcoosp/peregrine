//! The no-deduplicate consumer example (M41): a duplicate-literal
//! corpus linked under the default (the D4 merge collapses the shared
//! literals into one canonical copy per unique string, every reference
//! remapped) beside the same corpus under `-no_deduplicate` (every
//! input literal rides the output verbatim — the pre-D4 shape), both
//! run through the strict verifier, and the toggle's file-size delta
//! printed — the knob a build system names when it audits a size
//! delta, or a tool wants the literal pool exactly as the inputs
//! carried it.
//!
//! Run: `cargo run -p pgr-driver --example no_deduplicate_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans —
//! the same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SegmentCommand64};
use pgr_verify::{Options as VerifyOptions, verify};

/// The literal every object carries (the merge's input shape).
const SHARED: &str = "shared literal across the corpus";

/// One object: `_main` (first only) over two RET functions and a
/// `__cstring` carrying the shared literal plus a unique tail, named by
/// an external symbol.
fn object(name: &str, main: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: if main {
            "_main".into()
        } else {
            format!("_{name}_fn")
        },
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = format!("{SHARED}\0{name}-only tail\0");
    let cstr = b.add_section(ObjectSection::cstring(&data));
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_{name}_str"),
        section_index: cstr,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// The `__TEXT,__cstring` section's file offset and size.
fn cstring_span(image: &[u8]) -> (u32, u32) {
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
                if s.segname.starts_with(b"__TEXT\0") && s.sectname.starts_with(b"__cstring\0") {
                    return (s.offset, s.size as u32);
                }
            }
        }
    }
    panic!("the corpus carries a cstring bucket")
}

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
    ];
    for name in ["a.o", "b.o"] {
        let obj = dir.join(name);
        std::fs::write(&obj, object(name, name == "a.o")).unwrap();
        argv.push(obj.as_os_str().to_os_string());
    }
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

    let dir = std::env::temp_dir().join(format!("pgr_no_dedup_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The default: the shared literals merge — the output
    //    `__cstring` carries one copy of `SHARED` and the image
    //    verifies strict like any other.
    let merged = link(&dir, "hello_merged", &[]);
    let (merged_off, merged_size) = cstring_span(&merged);
    let pool = &merged[merged_off as usize..(merged_off + merged_size) as usize];
    let shared_count = pool
        .windows(SHARED.len())
        .filter(|w| *w == SHARED.as_bytes())
        .count();
    assert_eq!(shared_count, 1, "the merge carries one canonical copy");
    let report = verify(&merged, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the merged image verifies strict: {:?}",
        report.issues
    );

    // 2. The toggle: the same corpus under `-no_deduplicate` — every
    //    input literal rides verbatim (both copies of `SHARED`, both
    //    tails) and the image verifies strict.
    let verbatim = link(&dir, "hello_verbatim", &["-no_deduplicate"]);
    let (verb_off, verb_size) = cstring_span(&verbatim);
    let pool = &verbatim[verb_off as usize..(verb_off + verb_size) as usize];
    let shared_count = pool
        .windows(SHARED.len())
        .filter(|w| *w == SHARED.as_bytes())
        .count();
    assert_eq!(shared_count, 2, "the toggle keeps every input copy");
    let report = verify(&verbatim, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the verbatim image verifies strict: {:?}",
        report.issues
    );

    println!(
        "merged: __TEXT,__cstring at file offset {:#x}, {} section bytes, \
         one copy of the shared literal, {} bytes of image",
        merged_off,
        merged_size,
        merged.len()
    );
    println!(
        "verbatim: __cstring carries every input copy ({} section bytes, \
         {} bytes of image — the merge the D4 pass would have removed; \
         the file-size delta rides the 16 KiB segment congruence)",
        verb_size,
        verbatim.len()
    );
}

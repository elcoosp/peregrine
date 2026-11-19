//! The `-sectorder __TEXT __cstring` consumer example (M91): the
//! cstring face ld64 parses for the cstring pair — the file's lines are
//! escape-decoded literal *contents* (`\n`, `\t`, `\x41` hex, `\101`
//! octal; an unknown escape rides verbatim), and the decoded bytes rank
//! the `__cstring` sections' literals (the D4 canonical instances sort
//! by content rank, the duplicates resolving through the single output
//! copy). The walk: the plain link's `__cstring` order, the ranked
//! link's (the strict verifier gating both), the escape set in action,
//! and the advisory (an entry naming no placed literal warns — never an
//! error).
//!
//! Run: `cargo run -p pgr-driver --example cstring_order_link`

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` over a small `__text`, `__cstring` carrying the
/// named literals (one NUL-terminated atom each).
fn hello_object(literals: &[&str]) -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    let mut data = Vec::new();
    for literal in literals {
        data.extend_from_slice(literal.as_bytes());
        data.push(0);
    }
    b.add_section(ObjectSection {
        name: "__cstring".into(),
        segment: "__TEXT".into(),
        align_log2: 0,
        flags: pgr_format::consts::S_CSTRING_LITERALS,
        data,
        relocs: Vec::new(),
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(
        &obj,
        hello_object(&["alpha\n", "beta", "shared", "delta", "gamma"]),
    )
    .expect("the object writes");
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).expect("the image reads")
}

/// The placed `__cstring` bytes as the literal list (NUL-split).
fn placed_literals(bytes: &[u8]) -> Vec<String> {
    let hdr = pgr_format::MachHeader64::parse(bytes).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut sect = None;
    while let Some(cmd) = it.next_command().expect("the commands iterate") {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            for s in seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .expect("the sections walk")
            {
                if s.name() == Ok("__cstring") {
                    sect = Some((s.offset, s.size));
                }
            }
        }
    }
    let (off, size) = sect.expect("the cstring section places");
    let (off, size) = (
        usize::try_from(off).unwrap_or(0),
        usize::try_from(size).unwrap_or(0),
    );
    bytes[off..off + size]
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

fn main() {
    let dir = std::env::temp_dir().join("pgr_example_cstring_order_link");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");

    // 1. The plain link: the canonical first-use order (the D4 merge's
    //    own shape).
    let plain = link(&dir, "plain", &[]);
    println!("plain     __cstring order: {:?}", placed_literals(&plain));
    let opts = VerifyOptions::default();
    assert!(verify(&plain, &opts).is_ok(&opts));

    // 2. The ranked link: the escape-decoded contents rank the
    //    literals — `delta` then `be\tta` (the tab escape decoded to
    //    the byte the section carries) lead in rank order.
    let lit = dir.join("lit.txt");
    std::fs::write(&lit, "delta\nbe\\tta\n").expect("the rank file writes");
    let ranked = link(
        &dir,
        "ranked",
        &["-sectorder", "__TEXT", "__cstring", lit.to_str().unwrap()],
    );
    println!(
        "cstring   __cstring order: {:?} (the \\t escape decoded in `be\\tta`)",
        placed_literals(&ranked)
    );
    let report = verify(&ranked, &opts);
    assert!(report.is_ok(&opts), "{:#?}", report.issues);
    println!(
        "the ranked image verifies strict ({} issues)",
        report.issues.len()
    );

    // 3. The advisory: an entry naming no placed literal warns after
    //    the link (the M11 face, the literal's wording).
    let lit = dir.join("nomatch.txt");
    std::fs::write(&lit, "nomatch\ndelta\n").expect("the advisory file writes");
    let _ = link(
        &dir,
        "advised",
        &["-sectorder", "__TEXT", "__cstring", lit.to_str().unwrap()],
    );
    println!("the unmatched-literal advisory prints beside the link (stderr)");

    let _ = std::fs::remove_dir_all(&dir);
}

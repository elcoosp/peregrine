//! The literal-merge consumer example (M131, the D4 completion): the
//! fixed-width literal sections (`__literal4`/`__literal8`/`__literal16`)
//! the parser splits at their 4/8/16-byte widths now ride the D4 dedup the
//! cstrings have used since M5 — one canonical output copy per unique
//! value, every duplicate's symbol remapped onto the canonical address,
//! automatic (ld64's `-no_deduplicate` already named the whole D4 surface
//! at M41; the fixed-width literals inherit the decision — no new flag).
//! The walk: the plain link's `__literal4` pool (the duplicate value
//! collapsed into one canonical copy), the strict verifier gating it, and
//! the size-reduction signal (the deduped pool sits below the input's
//! verbatim footprint). Run: `cargo run -p pgr-driver --example literal_merge_link`

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::S_4BYTE_LITERALS;
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` over a small `__text`, `__literal4` carrying the
/// named 4-byte values (one atom each) — `alpha` rides twice so the
/// dedup has a real duplicate to collapse.
fn hello_object(values: &[u32]) -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let mut data = Vec::with_capacity(values.len() * 4);
    for v in values {
        data.extend_from_slice(&v.to_le_bytes());
    }
    b.add_section(ObjectSection {
        name: "__literal4".into(),
        segment: "__TEXT".into(),
        align_log2: 2,
        flags: S_4BYTE_LITERALS,
        data,
        relocs: Vec::new(),
    });
    b.build().expect("the fixture object builds")
}

/// Links hello.o (alpha twice, beta and gamma once) and returns the image.
fn link(dir: &std::path::Path, out: &str) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(
        &obj,
        hello_object(&[0x0102_0304, 0xAABB_CCDD, 0x0102_0304, 0x1122_3344]),
    )
    .expect("the object writes");
    let out_path = dir.join(out);
    let argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).expect("the image reads")
}

/// The placed `__literal4` bytes as the 4-byte value list (the deduped
/// pool — each unique value once).
fn placed_literals(bytes: &[u8]) -> Vec<u32> {
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
                if s.name() == Ok("__literal4") {
                    sect = Some((s.offset, s.size));
                }
            }
        }
    }
    let (off, size) = sect.expect("the literal4 section places");
    let (off, size) = (
        usize::try_from(off).unwrap_or(0),
        usize::try_from(size).unwrap_or(0),
    );
    bytes[off..off + size]
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap_or([0; 4])))
        .collect()
}

fn main() {
    let dir = std::env::temp_dir().join("pgr_example_literal_merge_link");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");

    let image = link(&dir, "merged");
    let pool = placed_literals(&image);
    println!(
        "merged    __literal4 pool: {:?}",
        pool.iter()
            .map(|v| format!("0x{v:08x}"))
            .collect::<Vec<_>>()
    );
    // The two alpha atoms collapsed into one canonical copy — 3 unique
    // values (alpha, beta, gamma), not the 4 input atoms.
    assert_eq!(
        pool.len(),
        3,
        "the duplicate alpha value merged into one canonical copy"
    );
    // The image verifies strict (the literal backstop passes on the
    // well-formed deduped pool).
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&image, &opts);
    assert!(
        report.is_ok(&opts),
        "the merged image verifies strict: {:#?}",
        report.issues
    );
    println!(
        "the merged image verifies strict ({} issues)",
        report.issues.len()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

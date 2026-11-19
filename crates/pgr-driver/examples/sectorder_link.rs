//! The `-sectorder` consumer example (M90): ld64's per-section order
//! flag riding the M11 rank seam. The same corpus linked plain (the
//! canonical input order), with `-sectorder __TEXT __text sect.txt`
//! (the file's rows lead `__text`, the strict verifier gates the image),
//! and composed — `-order_file` first, then `-sectorder`, the one rank
//! table in command-line order (ld64's append semantics). The faces the
//! pair can name walk beside it: the `__TEXT,__literal*` warned no-op
//! (ld64's wording, the file never read — a missing path links), and
//! The rank advisory closes the walk: an entry that ranks no placed
//! piece warns after the link, the M11 face. (The `__TEXT,__cstring`
//! literal face is M91's own rung — the `cstring_order_link` example
//! walks it.)
//!
//! Run: `cargo run -p pgr-driver --example sectorder_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o with `MH_SUBSECTIONS_VIA_SYMBOLS`: four functions (one ret
/// each) plus `_main`, so the order sources have real atoms to rank.
fn hello_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(4),
        Vec::new(),
    ));
    b.add_section(ObjectSection::cstring("hi\n"));
    for (i, name) in ["_main", "_second", "_third", "_tail"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*name).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.build().expect("the fixture object builds")
}

/// Links the object with `extra` args; returns the image bytes.
fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).expect("the object writes");
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

/// The `__text`-defined externals in placed (address) order — the rows
/// the rank table rearranged.
fn text_names(bytes: &[u8]) -> Vec<String> {
    let hdr = pgr_format::MachHeader64::parse(bytes).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut text_addr = 0u64;
    while let Some(cmd) = it.next_command().expect("the commands iterate") {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            for s in seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .expect("the sections walk")
            {
                if s.name() == Ok("__text") {
                    text_addr = s.addr;
                }
            }
        }
    }
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut externs: Vec<(u64, String)> = Vec::new();
    while let Some(cmd) = it.next_command().expect("the commands iterate") {
        if let pgr_format::LoadCommandKind::Symtab = cmd.kind {
            let st = pgr_format::SymtabCommand::parse(cmd.bytes, 0).expect("the symtab parses");
            let strtab = &bytes[st.stroff as usize..st.stroff as usize + st.strsize as usize];
            for i in 0..st.nsyms {
                let nl: pgr_format::symtab::Nlist64 = pgr_format::cursor::pod_read_unaligned_at(
                    bytes,
                    st.symoff as usize + i as usize * 16,
                )
                .expect("the symbol reads");
                if nl.n_type & pgr_format::consts::N_EXT != 0
                    && nl.n_type & pgr_format::consts::N_TYPE == pgr_format::consts::N_SECT
                    && nl.n_value >= text_addr
                {
                    let name = &strtab[nl.n_strx as usize..];
                    let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
                    externs.push((nl.n_value, String::from_utf8_lossy(name).into_owned()));
                }
            }
        }
    }
    externs.sort_by_key(|(value, _)| *value);
    externs.into_iter().map(|(_, name)| name).collect()
}

fn main() {
    let dir = std::env::temp_dir().join("pgr_example_sectorder_link");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");

    // 1. The plain link: the canonical input order — `_main` leads.
    let plain = link(&dir, "plain", &[]);
    println!("plain      __text order: {:?}", text_names(&plain));
    let opts = VerifyOptions::default();
    assert!(verify(&plain, &opts).is_ok(&opts));

    // 2. The sectorder link: the file's rows lead, in file order.
    let sect = dir.join("sect.txt");
    std::fs::write(&sect, "_tail\n_second\n").expect("the sectorder file writes");
    let ranked = link(
        &dir,
        "ranked",
        &["-sectorder", "__TEXT", "__text", sect.to_str().unwrap()],
    );
    println!("sectorder  __text order: {:?}", text_names(&ranked));
    let opts = VerifyOptions::default();
    let report = verify(&ranked, &opts);
    assert!(report.is_ok(&opts), "{:#?}", report.issues);
    println!(
        "the ranked image verifies strict ({} issues)",
        report.issues.len()
    );

    // 3. The composition: `-order_file` then `-sectorder`, one table in
    //    command-line order (the rows interleave in flag order).
    let first = dir.join("order.txt");
    std::fs::write(&first, "_third\n").expect("the order file writes");
    let composed = link(
        &dir,
        "composed",
        &[
            "-order_file",
            first.to_str().unwrap(),
            "-sectorder",
            "__TEXT",
            "__text",
            sect.to_str().unwrap(),
        ],
    );
    println!(
        "composed   __text order: {:?} (-order_file _third first, then the sectorder rows)",
        text_names(&composed)
    );

    // 4. The literal no-op face: the ld64 warning rides, the file is
    //    never read — a missing path links.
    let missing = dir.join("never.txt");
    let literal = link(
        &dir,
        "literal",
        &[
            "-sectorder",
            "__TEXT",
            "__literal4",
            missing.to_str().unwrap(),
        ],
    );
    println!(
        "literal    __text order: {:?} (the warned no-op — the missing file never read)",
        text_names(&literal)
    );

    // 5. The advisory: an entry that ranks no placed piece warns after
    //    the link (the M11 face, the composed table's rows included).
    let nowhere = dir.join("nowhere.txt");
    std::fs::write(&nowhere, "_main\n_not_a_symbol\n").expect("the advisory file writes");
    let _ = link(
        &dir,
        "advised",
        &["-sectorder", "__TEXT", "__text", nowhere.to_str().unwrap()],
    );
    println!("the unmatched-entry advisory prints beside the link (stderr)");

    let _ = std::fs::remove_dir_all(&dir);
}

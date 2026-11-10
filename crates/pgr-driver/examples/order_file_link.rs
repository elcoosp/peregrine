//! The order-file consumer example (M11 rung 1): a build that cares
//! about *where its code lands* — a startup-order file ranks the
//! functions of two objects, the link places the ranked atoms first
//! (the §8.4 stable sort), the output verifies strict, and the placed
//! order is read back from the image's own symtab. A rank that names
//! nothing renders as the miette advisory (the fix, not just the
//! verdict) — the house convention the platform/adu examples share.
//!
//! Run: `cargo run -p pgr-driver --example order_file_link`
//! (`PGR_TRACING=1` installs a subscriber so the layout's rank spans
//! print — the same inert-until-subscriber convention the binaries use).

use std::path::PathBuf;

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// The advisory: an order-file entry ranked nothing (a typo, a renamed
/// symbol) — the link is correct, the intent is not. The diagnostic
/// names the entry and the fix, per the house convention.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("order-file entry {symbol} ranked no placed piece")]
#[diagnostic(help(
    "check the spelling against the inputs' symbol table (order files match Mach-O names, leading underscore included)"
))]
struct Unranked {
    /// The entry that matched nothing, as written.
    symbol: String,
}

/// A subsection-split object: five functions, one atom each.
fn object(name: &str, stem: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(5),
        vec![],
    ));
    b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    for (i, fn_name) in ["main", "second", "third", "tail"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_{stem}_{fn_name}"),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_{stem}_init"),
        section_index: text,
        value: 16,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// The externs each image reads from its symtab: `(name, address)`.
fn externs(image: &[u8]) -> Vec<(String, u64)> {
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
        if let pgr_format::LoadCommandKind::Symtab = cmd.kind {
            let st = pgr_format::SymtabCommand::parse(cmd.bytes, 0).expect("the symtab parses");
            let strtab = &image[st.stroff as usize..st.stroff as usize + st.strsize as usize];
            for i in 0..st.nsyms {
                let nl: pgr_format::symtab::Nlist64 = pgr_format::cursor::pod_read_unaligned_at(
                    image,
                    st.symoff as usize + i as usize * 16,
                )
                .expect("the symbol reads");
                if nl.n_type & pgr_format::consts::N_EXT != 0
                    && nl.n_type & pgr_format::consts::N_TYPE == pgr_format::consts::N_SECT
                {
                    let name = &strtab[nl.n_strx as usize..];
                    let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
                    out.push((String::from_utf8_lossy(name).into_owned(), nl.n_value));
                }
            }
        }
    }
    out.sort_by_key(|(_, addr)| *addr);
    out
}

fn main() {
    // The spans stay inert until a subscriber installs; PGR_TRACING=1
    // turns them into stderr lines (the binaries do the same under their
    // debug envs).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_order_file_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = dir.join("a.o");
    let b = dir.join("b.o");
    std::fs::write(&a, object("a.o", "a")).unwrap();
    std::fs::write(&b, object("b.o", "b")).unwrap();

    // 1. The order file: startup order — each object's `_init` first,
    //    then the b.o body. (The Mach-O names carry the leading
    //    underscore; the object-scope form `a.o:_symbol` is the same
    //    seam's scoped half.)
    let order: PathBuf = dir.join("startup.order");
    std::fs::write(
        &order,
        "_a_init\n_b_init\n_b_second\n# comments and blank lines are fine\n",
    )
    .unwrap();

    // 2. The link through the driver surface: the same `-order_file` the
    //    CLI takes. The image verifies strict (the rank moves atoms, the
    //    fixups/signature follow the layout).
    let out = dir.join("startup");
    let argv: Vec<std::ffi::OsString> = [
        "-o".as_ref(),
        out.as_os_str(),
        a.as_os_str(),
        b.as_os_str(),
        "-e".as_ref(),
        "_a_main".as_ref(),
        "-order_file".as_ref(),
        order.as_os_str(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = opts::parse(&argv).expect("the ordered argv parses");
    let outcome = pgr_driver::run(&o).expect("the ordered link runs");
    println!(
        "linked {} bytes with -order_file {}",
        outcome.file_size,
        order.display()
    );

    let image = std::fs::read(&out).expect("the image exists");
    let report = verify(
        &image,
        &VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    println!(
        "strict verify: {}",
        if report.is_ok(&VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false
        }) {
            "clean"
        } else {
            "FAILED"
        }
    );

    // 3. The placed order, read back: the ranked symbols lead, the
    //    unranked keep their canonical file order behind them.
    println!("placed externs (address order):");
    for (name, addr) in externs(&image) {
        println!("  {addr:#x}  {name}");
    }

    // 4. The advisory: a rank that names nothing is a typo, not an
    //    error — the layout reports it, the advisory renders the fix
    //    (the miette seam the driver's refusals share).
    let typo_order: PathBuf = dir.join("typo.order");
    std::fs::write(&typo_order, "_a_init\n_init\n").unwrap();
    let file = pgr_core::order::OrderFile::parse("_a_init\n_init\n").expect("parses");
    let cfg = pgr_core::layout::LinkConfig {
        entry_symbol: "_a_main".into(),
        symbol_order: Some(pgr_core::order::SymbolOrder::build(&file)),
        ..pgr_core::layout::LinkConfig::default()
    };
    let inputs = vec![
        pgr_core::link::LinkInput {
            name: a.display().to_string(),
            bytes: std::fs::read(&a).unwrap(),
        },
        pgr_core::link::LinkInput {
            name: b.display().to_string(),
            bytes: std::fs::read(&b).unwrap(),
        },
    ];
    let result = pgr_core::link(&inputs, &[], &cfg).expect("the advisory link plans");
    for unmatched in &result.layout.order_unmatched {
        let symbol = String::from_utf8_lossy(unmatched).into_owned();
        println!("{:?}", miette::Report::new(Unranked { symbol }));
    }

    let _ = &dir;
}

//! M6 ICF end-to-end gates (architecture doc §10.3 row M6): `-icf=safe`
//! folds identical functions through the driver pipeline, every output
//! passes the strict verifier, determinism holds (TDD §4.3), and the
//! fold-off default is byte-identical to the M5 pipeline.

use pgr_driver::opts::{Options, parse_icf_level};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

fn unique_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m6_icf").join(format!(
        "{}_{}_{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One object defining `sym`: identical 12-byte body across all instances.
fn identical_fn(sym: &str, entry: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new(&format!("{sym}.o")).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![
            0x20, 0x00, 0x00, 0x8B, // add x0, x1, x0
            0x00, 0x00, 0x00, 0x8B, // add x0, x0, x0
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: if entry { "_main".into() } else { sym.into() },
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().unwrap()
}

fn opts_for(
    dir: &std::path::Path,
    icf: Option<&str>,
) -> Result<Options, pgr_driver::opts::OptsError> {
    let mut opts = Options::default();
    for (i, sym) in ["_f0", "_f1", "_f2"].iter().enumerate() {
        let p = dir.join(format!("{sym}.o"));
        std::fs::write(&p, identical_fn(sym, i == 0)).unwrap();
        opts.inputs.push(p.display().to_string());
    }
    opts.output = dir.join("out.bin").display().to_string();
    opts.config.ident = "m6-icf".into();
    if let Some(level) = icf {
        // Exercise the CLI surface: `-icf=<level>` (attached form).
        let mut args: Vec<std::ffi::OsString> = vec![format!("-icf={level}").into()];
        args.push("-o".into());
        args.push(opts.output.clone().into());
        for i in &opts.inputs {
            args.push(i.clone().into());
        }
        opts = pgr_driver::opts::parse(&args)?;
    }
    Ok(opts)
}

/// `__TEXT,__text` byte size (folds shrink it; page alignment hides that
/// in the total file size).
fn text_size(image: &[u8]) -> u64 {
    let header = pgr_format::MachHeader64::parse(image).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    let mut size = 0;
    while let Some(cmd) = it.next_command().unwrap() {
        if let pgr_format::LoadCommandKind::Segment64 = cmd.kind {
            let seg = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).unwrap();
            for sect in seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .unwrap()
            {
                if sect.name().unwrap() == "__text" {
                    size = sect.size;
                }
            }
        }
    }
    size
}

fn strict_verify(image: &[u8]) {
    let vopts = pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = pgr_verify::verify(image, &vopts);
    assert!(report.is_ok(&vopts), "verifier issues: {report:?}");
}

#[test]
fn m6_icf_level_parses_from_the_cli() {
    assert_eq!(parse_icf_level("none"), Some(pgr_core::icf::IcfMode::None));
    assert_eq!(parse_icf_level("safe"), Some(pgr_core::icf::IcfMode::Safe));
    assert_eq!(parse_icf_level("all"), Some(pgr_core::icf::IcfMode::All));
    assert_eq!(parse_icf_level("bogus"), None);
    // The attached form shapes the config.
    let dir = unique_dir("parse");
    let opts = opts_for(&dir, Some("safe")).unwrap();
    assert_eq!(opts.config.icf, pgr_core::icf::IcfMode::Safe);
}

/// `-icf=safe` folds the three identical functions: a smaller `__text`,
/// verifier-clean output, and deterministic bytes.
#[test]
fn m6_icf_e2e_folds_and_verifies() {
    let dir = unique_dir("e2e");
    let on = pgr_driver::link_to_bytes(&opts_for(&dir, Some("safe")).unwrap()).unwrap();
    let off = pgr_driver::link_to_bytes(&opts_for(&dir, None).unwrap()).unwrap();
    assert!(
        text_size(&on) < text_size(&off),
        "folded __text {} must be smaller than unfolded {}",
        text_size(&on),
        text_size(&off)
    );
    strict_verify(&on);
    strict_verify(&off);

    // Determinism (TDD §4.3): two folded links are byte-identical.
    let dir2 = unique_dir("e2e2");
    let again = pgr_driver::link_to_bytes(&opts_for(&dir2, Some("safe")).unwrap()).unwrap();
    assert_eq!(on, again, "double link must be byte-identical");
}

/// `-icf=all` also folds address-taken functions (superset of safe).
#[test]
fn m6_icf_all_folds_more_than_safe() {
    let dir = unique_dir("all");
    // A pointer to _f1 makes it address-taken: safe keeps it, all folds it.
    let mk = |name: &str, sym_name: &str, ptr: bool| {
        let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            vec![],
        ));
        let sym = b.add_symbol(ObjectSymbol::Defined {
            name: sym_name.into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        if ptr {
            let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
            let ptr_sym = b.add_symbol(ObjectSymbol::Defined {
                name: "_fn_ptr".into(),
                section_index: data,
                value: 0,
                weak: false,
            });
            b.section_mut(data).relocs =
                vec![pgr_fixtures::ObjectReloc::unsigned(sym as u32).at(0)];
            let _ = ptr_sym;
        }
        b.build().unwrap()
    };
    let mut opts = Options::default();
    let p0 = dir.join("a.o");
    std::fs::write(&p0, mk("a.o", "_main", false)).unwrap();
    let p1 = dir.join("b.o");
    std::fs::write(&p1, mk("b.o", "_fn1", true)).unwrap();
    opts.inputs = vec![p0.display().to_string(), p1.display().to_string()];
    opts.output = dir.join("out.bin").display().to_string();
    opts.config.ident = "m6-icf-all".into();

    let mut safe = opts.clone();
    safe.config.icf = pgr_core::icf::IcfMode::Safe;
    let mut all = opts.clone();
    all.config.icf = pgr_core::icf::IcfMode::All;
    let safe_bytes = pgr_driver::link_to_bytes(&safe).unwrap();
    let all_bytes = pgr_driver::link_to_bytes(&all).unwrap();
    assert!(
        text_size(&all_bytes) < text_size(&safe_bytes),
        "-icf=all folds the address-taken copy: {} vs {}",
        text_size(&all_bytes),
        text_size(&safe_bytes)
    );
    strict_verify(&safe_bytes);
    strict_verify(&all_bytes);
}

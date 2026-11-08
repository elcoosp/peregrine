//! M5 `-dead_strip` e2e gates (D12): the fused pipeline strips dead atoms,
//! stays byte-identical to the reference emit, passes the strict verifier,
//! and remains deterministic. Without `-dead_strip` the output matches the
//! M1–M4 shape exactly (whole-section pieces).

use pgr_driver::opts::Options;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

fn unique_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m5_deadstrip").join(format!(
        "{}_{}_{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// main.o (subsections): _main calls _live, returns.
fn main_object() -> Vec<u8> {
    let text: Vec<u8> = [
        0x9400_0000u32, // bl _live
        0x5280_0000u32, // mov w0, #0
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    b.add_section(ObjectSection::text(
        "__text",
        text,
        vec![ObjectReloc::branch26(1).at(0)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_live".into(),
        weak_ref: false,
    });
    b.build().unwrap()
}

/// lib.o (subsections): _live (4 bytes) then _`dead_fn` with a distinctive
/// 8-byte marker, then dead data with another marker.
fn lib_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("lib.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [
            vec![0xC0, 0x03, 0x5F, 0xD6],                         // _live: ret
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE], // _dead_fn
        ]
        .concat(),
        vec![],
    ));
    let data = b.add_section(ObjectSection::data(
        "__data",
        [0x5A, 0x5A, 0xDE, 0xC0, 0xDE, 0xC0, 0x5A, 0x5A].to_vec(),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_live".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_dead_fn".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_dead_data".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    b.build().unwrap()
}

fn write_corpus(dir: &std::path::Path) -> Vec<String> {
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).unwrap();
    let lib = dir.join("lib.o");
    std::fs::write(&lib, lib_object()).unwrap();
    vec![main.display().to_string(), lib.display().to_string()]
}

fn output_symbols(bytes: &[u8]) -> std::collections::HashMap<String, u64> {
    let header = pgr_format::MachHeader64::parse(bytes).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    let mut out = std::collections::HashMap::new();
    while let Some(cmd) = it.next_command().unwrap() {
        if let pgr_format::LoadCommandKind::Symtab = cmd.kind {
            let st = pgr_format::SymtabCommand::parse(cmd.bytes, 0).unwrap();
            for i in 0..st.nsyms {
                let sym: pgr_format::symtab::Nlist64 = pgr_format::cursor::pod_read_unaligned_at(
                    bytes,
                    st.symoff as usize + i as usize * 16,
                )
                .unwrap();
                let strx = sym.n_strx as usize;
                let end = bytes[st.stroff as usize + strx..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap();
                let name = String::from_utf8_lossy(
                    &bytes[st.stroff as usize + strx..st.stroff as usize + strx + end],
                )
                .into_owned();
                out.insert(name, sym.n_value);
            }
        }
    }
    out
}

fn strict_verify(image: &[u8]) {
    let opts = pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = pgr_verify::verify(image, &opts);
    assert!(report.is_ok(&opts), "verifier issues: {report:?}");
}

#[test]
fn m5_dead_strip_removes_dead_functions_and_data() {
    let dir = unique_dir("strip");
    let inputs = write_corpus(&dir);

    let mut off = Options {
        inputs: inputs.clone(),
        output: dir.join("off.bin").display().to_string(),
        ..Options::default()
    };
    off.config.ident = "m5-strip-off".into();
    let image_off = pgr_driver::link_to_bytes(&off).unwrap();

    let mut on = Options {
        inputs,
        output: dir.join("on.bin").display().to_string(),
        ..Options::default()
    };
    on.config.ident = "m5-strip-on".into();
    on.config.dead_strip = true;
    let image_on = pgr_driver::link_to_bytes(&on).unwrap();

    // Off: everything present (M1–M4 shape).
    let fn_marker = [0xDEu8, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let data_marker = [0x5Au8, 0x5A, 0xDE, 0xC0, 0xDE, 0xC0, 0x5A, 0x5A];
    assert!(image_off.windows(8).any(|w| w == fn_marker));
    assert!(image_off.windows(8).any(|w| w == data_marker));
    let syms_off = output_symbols(&image_off);
    assert!(syms_off.contains_key("_dead_fn"));
    assert!(syms_off.contains_key("_dead_data"));

    // On: dead code and data are gone, live code stays.
    assert!(
        !image_on.windows(8).any(|w| w == fn_marker),
        "dead function bytes survived -dead_strip"
    );
    assert!(
        !image_on.windows(8).any(|w| w == data_marker),
        "dead data bytes survived -dead_strip"
    );
    let syms_on = output_symbols(&image_on);
    assert!(syms_on.contains_key("_main"));
    assert!(syms_on.contains_key("_live"));
    assert!(!syms_on.contains_key("_dead_fn"), "dead symbol in symtab");
    assert!(!syms_on.contains_key("_dead_data"), "dead symbol in symtab");
    assert!(
        image_on.len() < image_off.len(),
        "stripped image is not smaller ({} vs {})",
        image_on.len(),
        image_off.len()
    );

    strict_verify(&image_on);
}

#[test]
fn m5_dead_strip_matches_the_reference_emit_and_determinism() {
    let dir = unique_dir("identity");
    let inputs = write_corpus(&dir);

    let mut opts = Options {
        inputs: inputs.clone(),
        output: dir.join("out.bin").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-strip-identity".into();
    opts.config.dead_strip = true;

    let fused = pgr_driver::link_to_bytes(&opts).unwrap();
    let reference = pgr_driver::link_reference_bytes(&opts).unwrap();
    assert_eq!(
        fused, reference,
        "fused emit diverged from the reference on a dead-stripped link"
    );
    let again = pgr_driver::link_to_bytes(&opts).unwrap();
    assert_eq!(fused, again, "double link must be byte-identical");
    strict_verify(&fused);
}

#[test]
fn m5_dead_strip_u_roots_survive() {
    let dir = unique_dir("uroots");
    let inputs = write_corpus(&dir);
    let mut opts = Options {
        inputs,
        output: dir.join("out.bin").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-strip-u".into();
    opts.config.dead_strip = true;
    opts.force_load = vec!["_dead_fn".into()];
    let image = pgr_driver::link_to_bytes(&opts).unwrap();
    let fn_marker = [0xDEu8, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    assert!(
        image.windows(8).any(|w| w == fn_marker),
        "-u _dead_fn must keep the atom alive"
    );
    let syms = output_symbols(&image);
    assert!(syms.contains_key("_dead_fn"));
    strict_verify(&image);
}

#[test]
fn m5_dead_strip_dylib_keeps_its_export_surface() {
    let dir = unique_dir("dylib");
    let lib = dir.join("lib.o");
    std::fs::write(&lib, lib_object()).unwrap();
    let mut opts = Options {
        inputs: vec![lib.display().to_string()],
        output: dir.join("libtest.dylib").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-strip-dylib".into();
    opts.config.filetype = pgr_core::layout::OutputType::Dylib;
    opts.config.dead_strip = true;
    let image = pgr_driver::link_to_bytes(&opts).unwrap();
    let syms = output_symbols(&image);
    for exported in ["_live", "_dead_fn", "_dead_data"] {
        assert!(
            syms.contains_key(exported),
            "{exported} must survive in a -dead_strip dylib"
        );
    }
    strict_verify(&image);
}

#[test]
fn m5_dead_strip_transitive_closure_across_an_archive() {
    // main → _chain_a (archive member a: calls _chain_b) → member b;
    // member c is never referenced.
    let dir = unique_dir("arch");
    let text: Vec<u8> = [
        0x9400_0000u32, // bl _chain_a
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut main = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    main.add_section(ObjectSection::text(
        "__text",
        text,
        vec![ObjectReloc::branch26(1).at(0)],
    ));
    main.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    main.add_symbol(ObjectSymbol::Undefined {
        name: "_chain_a".into(),
        weak_ref: false,
    });
    let main_p = dir.join("main.o");
    std::fs::write(&main_p, main.build().unwrap()).unwrap();

    let member = |name: &str, defined: &str, calls: Option<&str>, marker: u8| -> Vec<u8> {
        let mut body = vec![0xC0, 0x03, 0x5F, 0xD6]; // ret
        let mut relocs = Vec::new();
        if let Some(target) = calls {
            body = vec![0x94, 0x00, 0x00, 0x00, 0xC0, 0x03, 0x5F, 0xD6];
            relocs.push(ObjectReloc::branch26(1).at(4));
            let _ = target;
        }
        let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
        let t = b.add_section(ObjectSection::text(
            "__text",
            [vec![marker, marker, marker, marker], body].concat(),
            relocs,
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: defined.into(),
            section_index: t,
            value: 0,
            weak: false,
        });
        if let Some(target) = calls {
            b.add_symbol(ObjectSymbol::Undefined {
                name: target.into(),
                weak_ref: false,
            });
        }
        b.build().unwrap()
    };

    let mut arch = pgr_fixtures::ArchiveBuilder::new("libchain.a");
    arch.add_member("a.o", member("a.o", "_chain_a", Some("_chain_b"), 0x11));
    arch.add_member("b.o", member("b.o", "_chain_b", None, 0x22));
    arch.add_member("c.o", member("c.o", "_chain_c", None, 0x33));
    let archive = dir.join("libchain.a");
    std::fs::write(&archive, arch.build()).unwrap();

    let mut opts = Options {
        inputs: vec![main_p.display().to_string(), archive.display().to_string()],
        output: dir.join("out.bin").display().to_string(),
        ..Options::default()
    };
    opts.config.ident = "m5-strip-arch".into();
    opts.config.dead_strip = true;
    let image = pgr_driver::link_to_bytes(&opts).unwrap();

    assert!(
        image.windows(4).any(|w| w == [0x11; 4]),
        "a.o stripped wrongly"
    );
    assert!(
        image.windows(4).any(|w| w == [0x22; 4]),
        "transitively live b.o missing"
    );
    assert!(
        !image.windows(4).any(|w| w == [0x33; 4]),
        "unreferenced archive member's bytes survived"
    );
    let syms = output_symbols(&image);
    assert!(syms.contains_key("_chain_b"));
    assert!(!syms.contains_key("_chain_c"));
    strict_verify(&image);
}

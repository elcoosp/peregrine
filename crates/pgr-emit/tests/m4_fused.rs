//! M4 correctness gate (architecture doc §10.3 row M4): the fused tile emit
//! must be **byte-identical to the pre-fusion reference emit** on every
//! corpus shape. The reference (`build_image`, the M3 algorithm) stays in the
//! tree verbatim; every test here links a corpus through `pgr_core::link`,
//! emits it both ways, and asserts the bytes match.
//!
//! The corpora deliberately cover every layout shape the M3 surface can
//! produce: dynamic executables (GOT/stubs/binds/rebases/subtractor/common),
//! `-dylib`/`-bundle` outputs (0 image base, `LC_ID_DYLIB`, export trie),
//! re-exports, export filters, flat namespace, `-no_fixup_chains` and
//! `-no_adhoc` (no signature, so no page hashes at all).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::resolve::{Dylib, UndefinedPolicy};
use pgr_core::{LinkInput, link};
use pgr_emit::{build_image, build_image_fused};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// hello.o: _main ADRP+ADD loads _msg, BL _greet, returns 0.
fn hello_main() -> Vec<u8> {
    let text: Vec<u8> = [
        0x9000_0000u32, // adrp x0, _msg@page
        0x9100_0000u32, // add x0, x0, #_msg@pageoff
        0x9400_0000u32, // bl _greet
        0x5280_0000u32, // mov w0, #0
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("hello.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        text,
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12(1).at(4),
            ObjectReloc::branch26(2).at(8),
        ],
    ));
    b.add_section(ObjectSection::cstring("hello, peregrine\n"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_msg".into(),
        section_index: 1,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.build().unwrap()
}

/// greet.o: _greet, a __data rebase pointer to _greet, a subtractor pair
/// and a common symbol — the M1 semantic corpus.
fn greet() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![
            0x91, 0x00, 0x00, 0x00, // add x0, x0, #0
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ],
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
    let greet_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let ptr_a = b.add_symbol(ObjectSymbol::Defined {
        name: "_ptr_a".into(),
        section_index: data,
        value: 8,
        weak: false,
    });
    let ptr_b = b.add_symbol(ObjectSymbol::Defined {
        name: "_ptr_b".into(),
        section_index: data,
        value: 8,
        weak: false,
    });
    b.section_mut(data).relocs = vec![
        ObjectReloc::unsigned(greet_sym as u32).at(0),
        ObjectReloc::subtractor(ptr_a as u32).at(8),
        ObjectReloc::unsigned(ptr_b as u32).at(8),
    ];
    b.add_symbol(ObjectSymbol::Common {
        name: "_common_buf".into(),
        size: 64,
        align_log2: 4,
    });
    b.build().unwrap()
}

/// A dylib input built directly (the `.tbd` text parser is M2 surface and
/// not what these tests exercise).
fn bench_dylib(exports: &[&str]) -> Dylib {
    Dylib {
        install_name: "/usr/lib/libBench.dylib".into(),
        current_version: (1 << 16) | (2 << 8),
        compatibility_version: 1 << 16,
        exports: exports.iter().map(|s| s.as_bytes().to_vec()).collect(),
        weak: false,
        reexport: false,
    }
}

/// A caller object that branches through stubs and loads through GOT slots
/// against `exports` (M2 bind path).
fn dylib_caller(seed: usize, calls: usize) -> Vec<u8> {
    let text: Vec<u8> = (0..calls)
        .map(|i| match i % 4 {
            0 => 0x9000_0000u32, // adrp x0, @GOTPAGE
            1 => 0xF940_0000u32, // ldr x0, [x0, @GOTPAGEOFF]
            2 => 0xD63F_0000u32, // blr x0
            _ => 0xD65F_03C0u32, // ret
        })
        .flat_map(u32::to_le_bytes)
        .collect();
    let mut b = ObjectBuilder::new(&format!("caller_{seed}.o"));
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let mut refs = Vec::new();
    for i in 0..calls {
        refs.push(b.add_symbol(ObjectSymbol::Undefined {
            name: format!("_bench_dylib_fn_{}", i % 64),
            weak_ref: false,
        }));
    }
    if seed == 1 {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
    }
    for (i, r) in refs.iter().enumerate() {
        let t = b.sym_index(*r);
        let off = ((i * 4) % (calls * 4)) as u32;
        b.section_mut(sect)
            .relocs
            .push(ObjectReloc::branch26(t).at(off));
    }
    b.build().unwrap()
}

/// A wide static corpus (multi-tile `__text`, cross-object resolution,
/// rebase pointers in `__data`).
fn wide_corpus(objects: usize, text_kib: usize) -> Vec<LinkInput> {
    (1..=objects as u64)
        .map(|seed| {
            let text = vec![0xA9u8; text_kib * 1024];
            let mut b = ObjectBuilder::new(&format!("wide_{seed}.o"));
            let text_idx = b.add_section(ObjectSection::text("__text", text, Vec::new()));
            let data_idx = b.add_section(ObjectSection::data("__data", vec![0u8; 512], Vec::new()));
            for i in 0..64u64 {
                b.add_symbol(ObjectSymbol::Defined {
                    name: format!("_wide_fn_{seed}_{i}"),
                    section_index: text_idx,
                    value: (i * 32) % (text_kib as u64 * 1024),
                    weak: false,
                });
            }
            let ref_seed = if seed == 1 { 1 } else { seed - 1 };
            for i in 0..64u64 {
                let r = b.add_symbol(ObjectSymbol::Undefined {
                    name: format!("_wide_fn_{ref_seed}_{i}"),
                    weak_ref: false,
                });
                let t = b.sym_index(r);
                b.section_mut(text_idx).relocs.push(
                    ObjectReloc::branch26(t).at(((i * 128) % (text_kib as u64 * 1024)) as u32),
                );
                b.section_mut(data_idx)
                    .relocs
                    .push(ObjectReloc::unsigned(t).at((i * 8) as u32));
            }
            if seed == 1 {
                b.add_symbol(ObjectSymbol::Defined {
                    name: "_main".into(),
                    section_index: text_idx,
                    value: 0,
                    weak: false,
                });
            }
            LinkInput {
                name: format!("wide_{seed}.o"),
                bytes: b.build().unwrap(),
            }
        })
        .collect()
}

fn hello_greet() -> Vec<LinkInput> {
    vec![
        LinkInput {
            name: "hello.o".into(),
            bytes: hello_main(),
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet(),
        },
    ]
}

/// The M4 gate: fused bytes == reference bytes, for one config.
fn assert_fused_matches_reference(inputs: &[LinkInput], cfg: &LinkConfig) {
    let result = link(inputs, &[], cfg)
        .unwrap_or_else(|e| panic!("link failed for ident {:?}: {e:?}", cfg.ident));
    let reference = build_image(&result.layout, &result.objects)
        .unwrap_or_else(|e| panic!("reference emit failed: {e:?}"));
    let fused = build_image_fused(&result.layout, &result.objects)
        .unwrap_or_else(|e| panic!("fused emit failed: {e:?}"));
    assert_eq!(
        reference.len(),
        fused.len(),
        "ident {:?}: sizes diverge",
        cfg.ident
    );
    assert_eq!(
        reference, fused,
        "ident {:?}: fused emit diverged from the pre-fusion reference \
         (architecture doc §10.3 M4 correctness gate)",
        cfg.ident
    );
}

#[test]
fn m4_fused_matches_reference_dynamic_executable() {
    let cfg = LinkConfig {
        ident: "m4-exec".into(),
        ..LinkConfig::default()
    };
    assert_fused_matches_reference(&hello_greet(), &cfg);
}

#[test]
fn m4_fused_matches_reference_static_executable() {
    let cfg = LinkConfig {
        ident: "m4-static".into(),
        dynamic_linker: false,
        ..LinkConfig::default()
    };
    assert_fused_matches_reference(&hello_greet(), &cfg);
}

#[test]
fn m4_fused_matches_reference_bind_path_executable() {
    let exports: Vec<String> = (0..64).map(|i| format!("_bench_dylib_fn_{i}")).collect();
    let export_refs: Vec<&str> = exports.iter().map(String::as_str).collect();
    let mut cfg = LinkConfig {
        ident: "m4-bind".into(),
        ..LinkConfig::default()
    };
    cfg.dylibs.push(bench_dylib(&export_refs));
    let inputs = vec![LinkInput {
        name: "caller_1.o".into(),
        bytes: dylib_caller(1, 256),
    }];
    assert_fused_matches_reference(&inputs, &cfg);
}

#[test]
fn m4_fused_matches_reference_dylib_output() {
    let mut cfg = LinkConfig {
        ident: "m4-dylib".into(),
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libm4.dylib".into()),
        current_version: (1 << 16) | (2 << 8),
        compatibility_version: 1 << 16,
        ..LinkConfig::default()
    };
    cfg.dylibs.push(bench_dylib(&["_printf"]));
    assert_fused_matches_reference(&hello_greet(), &cfg);
}

#[test]
fn m4_fused_matches_reference_bundle_output() {
    let cfg = LinkConfig {
        ident: "m4-bundle".into(),
        filetype: OutputType::Bundle,
        ..LinkConfig::default()
    };
    assert_fused_matches_reference(&hello_greet(), &cfg);
}

#[test]
fn m4_fused_matches_reference_reexport() {
    let mut re = bench_dylib(&["_bar_api"]);
    re.reexport = true;
    let mut cfg = LinkConfig {
        ident: "m4-reexport".into(),
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libm4.dylib".into()),
        ..LinkConfig::default()
    };
    cfg.dylibs.push(re);
    assert_fused_matches_reference(&hello_greet(), &cfg);
}

#[test]
fn m4_fused_matches_reference_export_filters() {
    let mut cfg = LinkConfig {
        ident: "m4-filters".into(),
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libm4.dylib".into()),
        ..LinkConfig::default()
    };
    cfg.exported_only = Some(vec![b"_main".to_vec(), b"__mh_execute_header".to_vec()]);
    assert_fused_matches_reference(&hello_greet(), &cfg);

    let mut cfg2 = LinkConfig {
        ident: "m4-filters-unexport".into(),
        ..LinkConfig::default()
    };
    cfg2.unexported = vec![b"_msg".to_vec()];
    assert_fused_matches_reference(&hello_greet(), &cfg2);
}

#[test]
fn m4_fused_matches_reference_flat_namespace_and_dynamic_lookup() {
    let mut cfg = LinkConfig {
        ident: "m4-flat".into(),
        flat_namespace: true,
        undefined_policy: UndefinedPolicy::DynamicLookup,
        ..LinkConfig::default()
    };
    cfg.dylibs.push(bench_dylib(&["_greet"]));
    // hello.o defines _main/_msg and references _greet (a dylib export under
    // flat namespace); greet.o is dropped so the reference stays external.
    let inputs = vec![LinkInput {
        name: "hello.o".into(),
        bytes: hello_main(),
    }];
    assert_fused_matches_reference(&inputs, &cfg);
}

#[test]
fn m4_fused_matches_reference_no_fixup_chains_and_no_adhoc() {
    let cfg = LinkConfig {
        ident: "m4-nochains".into(),
        fixup_chains: false,
        ..LinkConfig::default()
    };
    assert_fused_matches_reference(&hello_greet(), &cfg);

    let cfg = LinkConfig {
        ident: "m4-noadhoc".into(),
        adhoc: false,
        ..LinkConfig::default()
    };
    assert_fused_matches_reference(&hello_greet(), &cfg);
}

#[test]
fn m4_fused_matches_reference_wide_multitile_corpus() {
    let inputs = wide_corpus(8, 24);
    let cfg = LinkConfig {
        ident: "m4-wide".into(),
        ..LinkConfig::default()
    };
    assert_fused_matches_reference(&inputs, &cfg);

    let mut cfg = LinkConfig {
        ident: "m4-wide-dylib".into(),
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libwide.dylib".into()),
        ..LinkConfig::default()
    };
    cfg.dylibs.push(bench_dylib(&["_printf"]));
    assert_fused_matches_reference(&inputs, &cfg);
}

//! The input-surface seam's consumer cycle, runnable (M10 rung 5,
//! slice 3): the same pointer-shaped content — a `__data` rebase slot
//! against `_main` and one GOT-indirect `_printf` bind — built twice,
//! once as an arm64-typed object and once as an x86_64-typed object,
//! linked under their own families, with both images' plans decoded and
//! printed side by side, and the crossed links refusing (the family
//! gate: an arm64 input under `-arch x86_64` refuses, and so does the
//! reverse — the relocation alphabets are per-family namespaces, the
//! `r_type` words collide).
//!
//! The consumer story: the CPU family on the *input* side changes what
//! Pass 1 reads (the arm64 pair forms — `ADDEND` leaders and page
//! relocs — versus the `x86_64` disp32 forms — in-situ `SIGNED`/`BRANCH`
//! fields and the subtractor pair naming the subtrahend first), never
//! what Pass 3 plans — same slots, same chained rebase, same GOT slot,
//! same import table; the payload declares the family's word format
//! (`64_OFFSET` vs `DYLD_CHAINED_PTR_64`) and the verifier's slice-1
//! walk reads both.
//!
//! Set `PGR_TRACING=1` to install a subscriber and watch the pipeline's
//! phase spans (inert without a subscriber, the workspace convention).
//!
//! ```sh
//! cargo run -p pgr-core --example x86_64_inputs_link
//! ```

use pgr_core::cpu::CpuFamily;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{CpuKind, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use pgr_format::fixups::ChainWord64;

/// The dylib the GOT bind resolves against (the tests' helper shape).
fn dylib() -> pgr_core::resolve::Dylib {
    pgr_core::resolve::Dylib {
        install_name: "/usr/lib/libSystem.B.dylib".into(),
        current_version: 0,
        compatibility_version: 0,
        exports: vec![b"_printf".to_vec()],
        weak: false,
        lazy: false,
        upward: false,
        reexport: false,
        needed: false,
        hidden: false,
    }
}

/// One pointer-shaped object family-typed: a `__data` rebase slot
/// against `_main` and the family's GOT-indirect `_printf` access in
/// `__text` — the call shape each family's clang emits natively.
fn pointer_object(cpu: CpuKind) -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_cputype(cpu);
    let (text, got_reloc) = match cpu {
        CpuKind::Arm64 => (
            [
                0x9000_0000u32, // adrp x0, _printf@GOTPAGE
                0xF940_0000u32, // ldr x0, [x0, _printf@GOTPAGEOFF]
                0xD65F_03C0u32, // ret
            ]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<u8>>(),
            vec![
                ObjectReloc::got_page21(0).at(0),
                ObjectReloc::got_pageoff12(0).at(4),
            ],
        ),
        CpuKind::X86_64 => (
            [
                &[0x48u8, 0x8B, 0x05, 0xFC, 0xFF, 0xFF, 0xFF][..], // movq _printf@GOTPCREL(%rip)
                &[0xC3],                                           // ret
            ]
            .concat(),
            vec![ObjectReloc::x86_got_load(0).at(3)],
        ),
    };
    let sect = b.add_section(ObjectSection::text("__text", text, got_reloc));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    let printf_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_printf".into(),
        weak_ref: false,
    });
    let main = b.sym_index(main_sym);
    let printf = b.sym_index(printf_sym);
    // The GOT relocs name `_printf` (declared first, index 0 above); the
    // slot names `_main`.
    if let CpuKind::Arm64 = cpu {
        b.section_mut(sect).relocs = vec![
            ObjectReloc::got_page21(printf).at(0),
            ObjectReloc::got_pageoff12(printf).at(4),
        ];
    } else {
        b.section_mut(sect)
            .relocs
            .push(ObjectReloc::x86_got_load(printf).at(3));
    }
    let slot = if let CpuKind::Arm64 = cpu {
        ObjectReloc::unsigned(main)
    } else {
        ObjectReloc::x86_unsigned(main)
    };
    b.section_mut(data).relocs.push(slot.at(0));
    b.build().expect("the fixture object builds")
}

/// One family's plan over its own corpus.
fn plan(bytes: Vec<u8>, cpu: CpuFamily) -> pgr_core::link::LinkResult {
    link(
        &[LinkInput {
            name: "main.o".to_string(),
            bytes,
        }],
        &[],
        &LinkConfig {
            cpu,
            filetype: OutputType::Execute,
            dylibs: vec![dylib()],
            ..LinkConfig::default()
        },
    )
    .expect("the family corpus plans")
}

fn main() {
    // The pipeline's phase spans stay inert until a subscriber installs;
    // PGR_TRACING=1 turns them into stderr lines (the binaries do the
    // same under their debug envs).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let arm64_bytes = pointer_object(CpuKind::Arm64);
    let x86e_bytes = pointer_object(CpuKind::X86_64);
    let arm64 = plan(arm64_bytes.clone(), CpuFamily::Arm64);
    let x86e = plan(x86e_bytes.clone(), CpuFamily::X86_64);

    println!("the same pointer-shaped content, two input alphabets");
    println!(
        "  input header cputype: arm64 = {CPU_TYPE_ARM64:#x}, x86_64 = {CPU_TYPE_X86_64:#x} \
         (the family gate reads it before any parse work)"
    );
    println!(
        "  payload pointer_format: arm64 = {}, x86_64 = {} (the family's own word family)",
        arm64.layout.fixups.chain_word_format.pointer_format(),
        x86e.layout.fixups.chain_word_format.pointer_format()
    );
    println!(
        "  import table: {} entry/entries each (the bind rides the slot in both families)",
        arm64.layout.fixups.imports.len()
    );

    // The slot's vaddr differs per family (the packing rides the family
    // page); the rebase under test is each plan's first non-bind slot
    // word (the __got bind slots ride the same payload).
    let first_rebase = |plan: &pgr_core::link::LinkResult| -> (u64, u64) {
        plan.layout
            .fixups
            .slot_words
            .iter()
            .find(|(_, w)| !ChainWord64::new(*w).is_bind())
            .copied()
            .expect("the rebase slot encodes")
    };
    let (a_v, a_word) = first_rebase(&arm64);
    let (x_v, x_word) = first_rebase(&x86e);
    let a = ChainWord64::new(a_word);
    let x = ChainWord64::new(x_word);
    println!("rebase slot (target _main): arm64 at {a_v:#x}, x86_64 at {x_v:#x}:");
    println!(
        "    arm64 (64_OFFSET): composed = {:#x} (image offset), next = {}",
        a.rebase_target(),
        a.next()
    );
    println!(
        "    x86_64 (Format64) : composed = {:#x} (VM address), next = {}",
        (u64::from(x.rebase_high8()) << 56) | x.rebase_target(),
        x.next()
    );

    // The crossed links refuse: the family gate names both families and
    // the `-arch` fix (the r_type namespaces collide — `0` is arm64
    // UNSIGNED and x86_64 UNSIGNED alike).
    for (input_family, link_family, label) in [
        (
            CpuFamily::Arm64,
            CpuFamily::X86_64,
            "arm64 input under -arch x86_64",
        ),
        (
            CpuFamily::X86_64,
            CpuFamily::Arm64,
            "x86_64 input under the arm64 default",
        ),
    ] {
        let bytes = match input_family {
            CpuFamily::Arm64 => arm64_bytes.clone(),
            CpuFamily::X86_64 => x86e_bytes.clone(),
        };
        let verdict = link(
            &[LinkInput {
                name: "main.o".to_string(),
                bytes,
            }],
            &[],
            &LinkConfig {
                cpu: link_family,
                filetype: OutputType::Execute,
                dylibs: vec![dylib()],
                ..LinkConfig::default()
            },
        );
        match verdict {
            Err(err) => println!("  {label}: refuses — {err}"),
            Ok(_) => println!("  {label}: (unexpectedly planned)"),
        }
    }
}

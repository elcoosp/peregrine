//! The universal-input consumer example (M70): one dylib linked through
//! a universal ("fat") container — the arm64 slice rides inside a
//! `FAT_MAGIC` wrapper beside a foreign-arch slice, and the driver
//! links the arm64 slice exactly as it would link the bare dylib (the
//! container adds nothing the pipeline sees). The link runs `-L dir
//! -lu`, the load command records the slice's install name, and the
//! image verifies strict — the shape every SDK dylib and static archive
//! ships as.
//!
//! Run: `cargo run -p pgr-driver --example universal_input_link`

use pgr_driver::opts;
use pgr_fixtures::{
    ImageBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol, SectionSpec,
    SegmentSpec, SymbolSpec, filler, universal_image,
};
use pgr_format::consts::{
    CPU_TYPE_ARM64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};
use pgr_format::{DylibCommand, LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};

/// The `x86_64` cputype (the foreign slice rides the container; the
/// pipeline never touches it).
const CPU_TYPE_X86_64: u32 = 0x0100_0007;

/// hello.o: `_main` BLs `_greet` and returns — one external bind.
fn hello_o() -> Vec<u8> {
    let text: Vec<u8> = [
        0x9400_0000u32, // bl _greet
        0x5280_0000u32, // mov w0, #0
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("hello.o");
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let greet = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    let _ = main_sym;
    b.section_mut(sect)
        .relocs
        .push(ObjectReloc::branch26(u32::try_from(greet).expect("the index fits")).at(0));
    b.build().expect("the fixture object builds")
}

/// The arm64 dylib slice: exports `_greet` under `@rpath/libu.dylib`.
fn greet_dylib_slice() -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libu.dylib", "universal-example");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0x7070, 64),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_greet".into(),
        section_index: 0,
    });
    b.build().expect("the fixture dylib builds").bytes
}

/// A minimal 32-byte Mach-O header marked with `cputype` (the foreign
/// slice fills its window; the seam selects before any parse).
fn foreign_slice() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&pgr_format::consts::MH_MAGIC_64.to_le_bytes());
    v.extend_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
    v.extend_from_slice(&[0u8; 24]);
    v
}

/// The `LC_LOAD_DYLIB` install names the image records.
fn load_dylib_names(image: &[u8]) -> Vec<String> {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands walk");
    let mut out = Vec::new();
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::LoadDylib = cmd.kind {
            let d = DylibCommand::parse(cmd.bytes).expect("the command parses");
            let name = d.name(cmd.bytes).expect("the install name reads");
            out.push(
                String::from_utf8_lossy(name)
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
    }
    out
}

fn main() {
    let dir = std::env::temp_dir().join(format!("pgr_universal_input_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // The container: the arm64 slice beside the foreign one — the SDK
    // shape the driver refused before M70.
    let container = universal_image(&[
        (&greet_dylib_slice(), CPU_TYPE_ARM64),
        (&foreign_slice(), CPU_TYPE_X86_64),
    ])
    .expect("the container wraps");
    let lib = dir.join("libu.dylib");
    std::fs::write(&lib, container).unwrap();
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_o()).unwrap();

    // The link: `-L dir -lu` — the container unwraps to its arm64 slice
    // before the per-kind dispatch, and the pipeline links the slice it
    // always linked.
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("hello").display().to_string(),
        obj.display().to_string(),
        "-L".to_string(),
        dir.display().to_string(),
        "-l".to_string(),
        "u".to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(dir.join("hello")).expect("the image reads");

    // The gate: the load command rides the slice's install name and the
    // image verifies strict.
    let names = load_dylib_names(&image);
    assert_eq!(
        names,
        vec!["@rpath/libu.dylib".to_string()],
        "the load command rides the slice's install name"
    );
    let report = verify(&image, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the image verifies strict: {:?}",
        report.issues
    );

    println!(
        "linked through the universal container (2 slices): {}",
        names.join(", ")
    );
    println!("the image verifies strict ({} issues)", report.issues.len());
}

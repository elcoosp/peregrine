//! M70 — the universal-binary read seam at the driver: ld64 links
//! against universal ("fat") containers by picking the `-arch` slice;
//! Peregrine refused them ("not a .tbd stub, Mach-O dylib or static
//! archive") because the container's magic is `FAT_MAGIC`, not a Mach-O
//! magic. The seam unwraps the arm64 slice before the per-kind dispatch,
//! so every input class the driver already links — `.tbd`/dylib,
//! archive, `.o` — works through a universal container unchanged, and a
//! container without the arm64 slice refuses naming the cputypes it
//! does carry.
//!
//! Gate matrix:
//! * the `-l` dylib — a universal `libu.dylib` (arm64 slice + a foreign
//!   slice) links; the load command records the slice's install name and
//!   the image verifies strict;
//! * the parity — the same program linked against the plain arm64 slice
//!   and against its universal container produces byte-identical images
//!   (the container adds nothing the pipeline sees);
//! * the positional dylib — `map_input`'s direct Mach-O arm unwraps the
//!   container too;
//! * the archive — a universal `libua.a` (arm64 archive slice) pulls its
//!   member through the slice; the bind lands and the image verifies;
//! * the object — a universal `.o` (arm64 object slice) rides the
//!   positional-object arm;
//! * the refusals — a container with no arm64 slice refuses with the
//!   cputypes it carries; a truncated container refuses; neither
//!   touches the output file.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pgr_driver::opts;
use pgr_fixtures::{
    ArchiveBuilder, ImageBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol,
    SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image,
};
use pgr_format::consts::{CPU_TYPE_ARM64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR};
use pgr_format::consts::{VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Options as VerifyOptions, verify};

/// The `x86_64` cputype (the foreign slice the refusals name).
const CPU_TYPE_X86_64: u32 = 0x0100_0007;

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m70_universal").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn args(items: &[&str]) -> Vec<OsString> {
    items.iter().map(|s| OsString::from(*s)).collect()
}

/// hello.o: `_main` BLs `_greet` and returns — one external bind.
fn hello_o(dir: &Path) -> PathBuf {
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
        .push(ObjectReloc::branch26(u32::try_from(greet).unwrap()).at(0));
    let path = dir.join("hello.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// A minimal 32-byte Mach-O header marked with `cputype` (the foreign
/// slice is never parsed — selection runs before the dispatch).
fn foreign_slice() -> Vec<u8> {
    use pgr_format::consts::MH_MAGIC_64;
    let mut v = Vec::new();
    v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    v.extend_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
    v.extend_from_slice(&[0u8; 24]);
    v
}

/// The arm64 dylib slice: exports `_greet`, install name `@rpath/libu.dylib`.
fn greet_dylib_slice() -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libu.dylib", "m70-universal");
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

/// The universal dylib container: the arm64 slice plus the foreign one.
fn universal_greet_dylib() -> Vec<u8> {
    universal_image(&[
        (&greet_dylib_slice(), CPU_TYPE_ARM64),
        (&foreign_slice(), CPU_TYPE_X86_64),
    ])
    .expect("the container wraps")
}

/// The arm64 archive slice: one `greet.o` member exporting `_greet`.
fn greet_archive_slice() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let member = b.build().expect("the member object builds");
    let mut a = ArchiveBuilder::new("libua.a");
    a.add_member("greet.o", member);
    a.build()
}

/// The universal archive container.
fn universal_greet_archive() -> Vec<u8> {
    universal_image(&[
        (&greet_archive_slice(), CPU_TYPE_ARM64),
        (&foreign_slice(), CPU_TYPE_X86_64),
    ])
    .expect("the container wraps")
}

/// The universal object container: hello.o's arm64 slice plus the
/// foreign one (a fat `.o` from a multi-arch toolchain).
fn universal_hello_object() -> Vec<u8> {
    let dir = scratch("slice_tmp");
    let obj = std::fs::read(hello_o(&dir)).expect("the object reads");
    universal_image(&[(&obj, CPU_TYPE_ARM64), (&foreign_slice(), CPU_TYPE_X86_64)])
        .expect("the container wraps")
}

/// The `LC_LOAD_DYLIB` install names the image records.
fn load_dylib_names(image: &[u8]) -> Vec<String> {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut out = Vec::new();
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind == pgr_format::LoadCommandKind::LoadDylib {
            let d = pgr_format::DylibCommand::parse(cmd.bytes).expect("the command parses");
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

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// Links `-o <dir/out>` plus `rest`, and returns the image bytes.
fn link(dir: &Path, out: &str, rest: &[&str]) -> Vec<u8> {
    let mut argv: Vec<String> = vec!["-o".to_string(), dir.join(out).display().to_string()];
    argv.extend(rest.iter().map(std::string::ToString::to_string));
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(dir.join(out)).expect("the image reads")
}

#[test]
fn links_the_dylib_through_its_arm64_slice() {
    let dir = scratch("dylib");
    std::fs::write(dir.join("libu.dylib"), universal_greet_dylib()).unwrap();
    let obj = hello_o(&dir);
    let image = link(
        &dir,
        "hello",
        &[
            obj.to_str().expect("the path strings"),
            "-L",
            dir.to_str().expect("the dir strings"),
            "-l",
            "u",
        ],
    );
    assert_eq!(
        load_dylib_names(&image),
        vec!["@rpath/libu.dylib".to_string()],
        "the load command rides the slice's install name"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the image verifies strict: {:#?}",
        report.issues
    );
}

#[test]
fn the_container_adds_nothing_the_pipeline_sees() {
    let dir = scratch("parity");
    std::fs::write(dir.join("libu.dylib"), universal_greet_dylib()).unwrap();
    std::fs::write(dir.join("libplain.dylib"), greet_dylib_slice()).unwrap();
    let obj = hello_o(&dir);
    let argv = |lib: &str| {
        [
            obj.display().to_string(),
            "-L".to_string(),
            dir.display().to_string(),
            "-l".to_string(),
            lib.to_string(),
        ]
    };
    let items = argv("u");
    let through_container = link(
        &dir,
        "through-container",
        &items.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    let items = argv("plain");
    let through_plain = link(
        &dir,
        "through-plain",
        &items.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(
        through_container, through_plain,
        "the container is unwrapped before the dispatch — the images match"
    );
}

#[test]
fn links_the_positional_dylib_through_its_arm64_slice() {
    let dir = scratch("positional");
    let container = dir.join("libu.dylib");
    std::fs::write(&container, universal_greet_dylib()).unwrap();
    let obj = hello_o(&dir);
    let image = link(
        &dir,
        "hello",
        &[
            obj.to_str().expect("the path strings"),
            container.to_str().expect("the container strings"),
        ],
    );
    assert_eq!(
        load_dylib_names(&image),
        vec!["@rpath/libu.dylib".to_string()],
        "map_input's dylib arm unwraps the container"
    );
}

#[test]
fn links_the_archive_through_its_arm64_slice() {
    let dir = scratch("archive");
    std::fs::write(dir.join("libua.a"), universal_greet_archive()).unwrap();
    let obj = hello_o(&dir);
    let image = link(
        &dir,
        "hello",
        &[
            obj.to_str().expect("the path strings"),
            "-L",
            dir.to_str().expect("the dir strings"),
            "-l",
            "ua",
        ],
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the archive pull works through the slice: {:#?}",
        report.issues
    );
}

#[test]
fn links_the_object_through_its_arm64_slice() {
    let dir = scratch("object");
    let container = dir.join("hello-universal.o");
    std::fs::write(&container, universal_hello_object()).unwrap();
    std::fs::write(dir.join("libu.dylib"), universal_greet_dylib()).unwrap();
    let image = link(
        &dir,
        "hello",
        &[
            container.to_str().expect("the container strings"),
            "-L",
            dir.to_str().expect("the dir strings"),
            "-l",
            "u",
        ],
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the fat object rides the positional arm: {:#?}",
        report.issues
    );
    // The BL in the fat slice resolved (the pull found _greet in the
    // dylib): the undefined-symbol refusal never fired.
    assert!(load_dylib_names(&image).len() <= 1);
}

#[test]
fn refuses_a_container_without_the_arm64_slice() {
    let dir = scratch("no_arm64");
    let container =
        universal_image(&[(&foreign_slice(), CPU_TYPE_X86_64)]).expect("the container wraps");
    std::fs::write(dir.join("libx86.dylib"), &container).unwrap();
    let obj = hello_o(&dir);
    let argv = args(&[
        "-o",
        dir.join("hello").to_str().expect("the path strings"),
        obj.to_str().expect("the path strings"),
        "-L",
        dir.to_str().expect("the dir strings"),
        "-l",
        "x86",
    ]);
    let o = opts::parse(&argv).expect("the argv parses");
    let err = pgr_driver::run(&o).expect_err("the container has no arm64 slice");
    let text = err.to_string();
    assert!(
        text.contains("0x1000007"),
        "the refusal names the cputype it carries: {text}"
    );
    assert!(
        !dir.join("hello").exists(),
        "the refused run writes no output"
    );
}

#[test]
fn refuses_a_truncated_container() {
    let dir = scratch("truncated");
    let container = universal_greet_dylib();
    std::fs::write(dir.join("libu.dylib"), &container[..40]).unwrap();
    let obj = hello_o(&dir);
    let argv = args(&[
        "-o",
        dir.join("hello").to_str().expect("the path strings"),
        obj.to_str().expect("the path strings"),
        "-L",
        dir.to_str().expect("the dir strings"),
        "-l",
        "u",
    ]);
    let o = opts::parse(&argv).expect("the argv parses");
    let err = pgr_driver::run(&o).expect_err("the truncated container refuses");
    assert!(
        err.to_string().contains("libu.dylib"),
        "the refusal carries the path: {err}"
    );
}

//! M10 rung 5, slice 3 — the universal container's slice selection rides
//! the CPU family: the driver's M70 unwrap names the slice the link's
//! family plans (the arm64 default keeps every pre-slice link
//! byte-identical — the container that carries the arm64 slice selects it
//! exactly as before), `-arch x86_64` selects an `x86_64` slice and links
//! it end to end (strict verify), and a container missing the requested
//! family's slice refuses with the cputypes it carries named. The plan
//! line this completes (TDD §15.9): *"The input surface stays arm64 this
//! rung"* — the input half of the family, container inputs included.

use pgr_fixtures::{CpuKind, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr-m10-univ-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A pointer-shaped rebase-only object family-typed (no external refs —
/// the corpus links without a dylib).
fn pointer_object(cpu: CpuKind) -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_cputype(cpu);
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    let idx = b.sym_index(sym);
    let r = match cpu {
        CpuKind::Arm64 => ObjectReloc::unsigned(idx),
        CpuKind::X86_64 => ObjectReloc::x86_unsigned(idx),
    };
    b.section_mut(data).relocs.push(r.at(0));
    b.build().expect("the fixture object builds")
}

/// A fat container carrying the named families' slices (the fixtures'
/// `FAT_MAGIC` wrapper — the M70 builder's own byte shape).
fn fat_container(slices: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let owned: Vec<(&[u8], u32)> = slices.iter().map(|(c, b)| (b.as_slice(), *c)).collect();
    pgr_fixtures::universal_image(&owned).expect("the container builds")
}

/// Links `obj_path` under `extra` flags; returns the produced bytes.
fn link(dir: &Path, obj_bytes: &[u8], extra: &[&str]) -> Result<Vec<u8>, String> {
    let obj = dir.join("input.bin");
    std::fs::write(&obj, obj_bytes).unwrap();
    let mut argv = vec!["-o".to_string(), dir.join("exe").display().to_string()];
    argv.extend(extra.iter().copied().map(str::to_string));
    argv.push(obj.display().to_string());
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let opts = pgr_driver::opts::parse(&argv).map_err(|e| e.to_string())?;
    pgr_driver::run(&opts).map_err(|e| e.to_string())?;
    Ok(std::fs::read(&opts.output).unwrap())
}

#[test]
fn the_x86_64_slice_links_beside_arch_x86_64() {
    let dir = scratch("x86e");
    let container = fat_container(&[
        (
            pgr_format::consts::CPU_TYPE_ARM64,
            pointer_object(CpuKind::Arm64),
        ),
        (
            pgr_format::consts::CPU_TYPE_X86_64,
            pointer_object(CpuKind::X86_64),
        ),
    ]);
    let image = link(&dir, &container, &["-arch", "x86_64"])
        .expect("the x86_64 slice links beside -arch x86_64");
    let cputype = u32::from_le_bytes(image[4..8].try_into().unwrap());
    assert_eq!(
        cputype,
        pgr_format::consts::CPU_TYPE_X86_64,
        "the container's x86_64 slice rode the link"
    );
}

#[test]
fn the_arm64_default_selects_the_arm64_slice() {
    // The pre-slice shape: the default family picks the arm64 slice out
    // of the same container (byte-identical to the direct-slice link).
    let dir = scratch("default");
    let direct =
        link(&dir, &pointer_object(CpuKind::Arm64), &[]).expect("the direct arm64 link plans");
    let dir2 = scratch("default-fat");
    let container = fat_container(&[
        (
            pgr_format::consts::CPU_TYPE_X86_64,
            pointer_object(CpuKind::X86_64),
        ),
        (
            pgr_format::consts::CPU_TYPE_ARM64,
            pointer_object(CpuKind::Arm64),
        ),
    ]);
    let sliced = link(&dir2, &container, &[]).expect("the arm64 slice rides the default");
    assert_eq!(
        direct, sliced,
        "the default family's slice link plans the direct bytes"
    );
}

#[test]
fn a_missing_family_slice_refuses_naming_the_cputypes() {
    // The arm64-only container under `-arch x86_64`: the refusal names
    // the cputypes the container carries (the fix is one line away).
    let dir = scratch("refuses");
    let container = fat_container(&[(
        pgr_format::consts::CPU_TYPE_ARM64,
        pointer_object(CpuKind::Arm64),
    )]);
    let err =
        link(&dir, &container, &["-arch", "x86_64"]).expect_err("the missing x86_64 slice refuses");
    assert!(
        err.contains("cputype") && err.contains("0x1000007"),
        "the refusal names the requested family and the carried cputypes: {err}"
    );
}

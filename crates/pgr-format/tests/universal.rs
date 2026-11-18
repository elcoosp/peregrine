//! M70 — the universal-binary read seam: ld64 links against universal
//! ("fat") containers daily — every SDK dylib and static archive ships
//! one — and Peregrine refused them as "not a .tbd stub, Mach-O dylib or
//! static archive" because `MachHeader64::parse` saw `FAT_MAGIC`
//! (`0xcafebabe`), not a Mach-O magic. The seam decodes the container
//! (the big-endian `fat_header` + slice table, both widths) and hands
//! the caller the slice windows — the driver picks the arm64 slice and
//! the per-kind dispatch runs on it unchanged.
//!
//! Gate matrix:
//! * the decode — a two-slice `FAT_MAGIC` container decodes to the same
//!   table it was written with (big-endian fields included);
//! * the widths — a `FAT_MAGIC_64` container decodes (64-bit offsets);
//! * the probe — `is_universal` is true for both magics and false for
//!   plain Mach-O/archive/empty bytes;
//! * the selection — the arm64 slice's window is exact (offset, size);
//!   a container without one refuses naming the cputypes it carries;
//! * the refusals — truncated header, truncated slice table, a count
//!   that lies, an out-of-bounds window, a sub-header slice, an
//!   overlapping table and a bad magic all refuse, offset-tagged, never
//!   panicking;
//! * the fixtures round trip — a `pgr-fixtures`-built container decodes
//!   to the slices it was built from.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, FAT_MAGIC, FAT_MAGIC_64, MH_MAGIC_64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR,
    VM_PROT_EXECUTE, VM_PROT_READ,
};
use pgr_format::universal::{FatArch, is_universal, parse_universal};

/// The `x86_64` cputype (the foreign slice the refusals name; the format
/// layer carries no constant for it — arm64 is the linked arch).
const CPU_TYPE_X86_64: u32 = 0x0100_0007;

/// A minimal 32-byte Mach-O header marked with `cputype` (the foreign
/// slices in the container are never parsed — selection runs before the
/// dispatch — so the bytes only have to fill a window).
fn foreign_slice(cputype: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    v.extend_from_slice(&cputype.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
    v.extend_from_slice(&0u32.to_le_bytes()); // filetype (parsed never)
    v.extend_from_slice(&0u32.to_le_bytes()); // ncmds
    v.extend_from_slice(&0u32.to_le_bytes()); // sizeofcmds
    v.extend_from_slice(&0u32.to_le_bytes()); // flags
    v.extend_from_slice(&0u32.to_le_bytes()); // reserved
    v
}

/// One small arm64 dylib slice (an export surface the driver can scan).
fn arm64_dylib_slice(install_name: &str) -> Vec<u8> {
    let mut b = ImageBuilder::dylib(install_name, "m70-format");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xA5A5, 64),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_greet".into(),
        section_index: 0,
    });
    b.build().expect("the fixture dylib builds").bytes
}

/// A two-slice container: the arm64 dylib slice plus the foreign one.
fn two_slice_container() -> (Vec<u8>, Vec<u8>) {
    let arm64 = arm64_dylib_slice("@rpath/libm70.dylib");
    let foreign = foreign_slice(CPU_TYPE_X86_64);
    let container = universal_image(&[(&arm64, CPU_TYPE_ARM64), (&foreign, CPU_TYPE_X86_64)])
        .expect("the container wraps");
    (container, arm64)
}

#[test]
fn decodes_the_written_table() {
    let (container, arm64) = two_slice_container();
    assert!(is_universal(&container), "the container probes universal");
    let u = parse_universal(&container).expect("the container decodes");
    assert_eq!(u.magic, FAT_MAGIC);
    assert_eq!(u.arches.len(), 2, "one entry per slice");
    assert_eq!(u.arches[0].cputype, CPU_TYPE_ARM64);
    assert_eq!(u.arches[1].cputype, CPU_TYPE_X86_64);
    // The arm64 window is exactly the slice the container was built
    // from (the fixtures builder writes offset-aligned windows).
    let slice = u
        .arm64(&container)
        .expect("the arm64 slice is in the table");
    assert_eq!(slice, &arm64[..], "the window is the slice's bytes");
}

#[test]
fn decodes_the_64_bit_width() {
    let arm64 = arm64_dylib_slice("@rpath/libm70.dylib");
    let foreign = foreign_slice(CPU_TYPE_X86_64);
    // The fixtures builder picks the width; both must decode. Build the
    // FAT_MAGIC_64 form by hand: header + two 32-byte entries, the
    // second slice past the first's window (the table cannot overlap).
    let mut v = Vec::new();
    v.extend_from_slice(&FAT_MAGIC_64.to_be_bytes());
    v.extend_from_slice(&2u32.to_be_bytes());
    let align_up = |x: u64| (x + 0xFFF) & !0xFFF;
    let offsets = [
        0x1000u64,
        align_up(0x1000 + u64::try_from(arm64.len()).expect("the slice fits u64")),
    ];
    for (i, (bytes, cputype)) in [(&arm64, CPU_TYPE_ARM64), (&foreign, CPU_TYPE_X86_64)]
        .into_iter()
        .enumerate()
    {
        v.extend_from_slice(&cputype.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        v.extend_from_slice(&offsets[i].to_be_bytes()); // offset
        v.extend_from_slice(
            &u64::try_from(bytes.len())
                .expect("the slice fits u64")
                .to_be_bytes(),
        ); // size
        v.extend_from_slice(&12u32.to_be_bytes()); // align (2^12)
        v.extend_from_slice(&0u32.to_be_bytes()); // reserved
    }
    let mut container = v;
    let tail = usize::try_from(offsets[1]).expect("the offset fits usize") + foreign.len();
    container.resize(tail, 0);
    let at0 = usize::try_from(offsets[0]).expect("the offset fits usize");
    container[at0..at0 + arm64.len()].copy_from_slice(&arm64);
    let at1 = usize::try_from(offsets[1]).expect("the offset fits usize");
    container[at1..at1 + foreign.len()].copy_from_slice(&foreign);
    let u = parse_universal(&container).expect("the 64-bit container decodes");
    assert_eq!(u.magic, FAT_MAGIC_64);
    assert_eq!(u.arches[0].offset, 0x1000);
    let slice = u.arm64(&container).expect("the arm64 slice selects");
    assert_eq!(slice, &arm64[..]);
}

#[test]
fn probe_rejects_plain_images() {
    let (container, _) = two_slice_container();
    assert!(is_universal(&container));
    assert!(!is_universal(&arm64_dylib_slice("@rpath/libplain.dylib")));
    assert!(!is_universal(b"!<arch>\n"));
    assert!(!is_universal(b""));
}

#[test]
fn selection_miss_names_the_cputypes() {
    let arm64 = arm64_dylib_slice("@rpath/libm70.dylib");
    let foreign = foreign_slice(CPU_TYPE_X86_64);
    let container = universal_image(&[(&foreign, CPU_TYPE_X86_64), (&arm64, 0x0100_000d)])
        .expect("the container wraps");
    let u = parse_universal(&container).expect("the container decodes");
    let err = u.arm64(&container).expect_err("no arm64 slice rides");
    let text = err.to_string();
    assert!(
        text.contains("arm64"),
        "the refusal names the missing arch: {text}"
    );
    assert!(
        text.contains("0x1000007") && text.contains("0x100000d"),
        "the refusal names the cputypes it carries: {text}"
    );
}

#[test]
fn truncated_header_refuses() {
    let (container, _) = two_slice_container();
    for len in 0..8usize {
        let err = parse_universal(&container[..len]).expect_err("a short header refuses");
        let anchored = if len < 4 { "offset 0" } else { "offset 4" };
        assert!(
            err.to_string().contains(anchored),
            "the refusal anchors at the field it needed: {err}"
        );
    }
}

#[test]
fn truncated_table_refuses() {
    let (container, _) = two_slice_container();
    // 8-byte header + 2 * 20-byte entries: every cut inside the table
    // refuses (the header's count still claims two slices).
    for len in 8..48usize {
        assert!(
            parse_universal(&container[..len]).is_err(),
            "a short table refuses at {len} bytes"
        );
    }
}

#[test]
fn lying_count_refuses() {
    // A header that claims two entries over a file that carries one
    // 20-byte entry and nothing else — the table's own extent refuses.
    let mut v = Vec::new();
    v.extend_from_slice(&FAT_MAGIC.to_be_bytes());
    v.extend_from_slice(&2u32.to_be_bytes());
    v.extend_from_slice(&[0u8; 20]); // one entry, zeros
    let err = parse_universal(&v).expect_err("the count refuses to lie");
    assert!(
        err.to_string().contains("offset 8"),
        "the refusal anchors at the table: {err}"
    );
}

#[test]
fn out_of_bounds_window_refuses() {
    let arm64 = arm64_dylib_slice("@rpath/libm70.dylib");
    let mut container = universal_image(&[(&arm64, CPU_TYPE_ARM64)]).expect("the container wraps");
    // Rewrite the slice's size past its end — the window claims bytes
    // the file does not carry. (Entry 0: cputype@8, subtype@12,
    // offset@16, size@20, align@24.)
    let size_at = 20;
    let big = u32::try_from(container.len() - size_at + 64).expect("the size fits u32");
    container[size_at..size_at + 4].copy_from_slice(&big.to_be_bytes());
    let err = parse_universal(&container).expect_err("the window refuses to overrun");
    assert!(
        err.to_string().contains("overruns"),
        "the refusal is the overrun shape: {err}"
    );
}

#[test]
fn sub_header_slice_refuses() {
    let arm64 = arm64_dylib_slice("@rpath/libm70.dylib");
    let mut container = universal_image(&[(&arm64, CPU_TYPE_ARM64)]).expect("the container wraps");
    // A 16-byte window cannot carry a Mach-O header.
    let size_at = 20;
    container[size_at..size_at + 4].copy_from_slice(&16u32.to_be_bytes());
    let err = parse_universal(&container).expect_err("a sub-header slice refuses");
    assert!(
        err.to_string().contains("slice"),
        "the refusal names the undersized slice: {err}"
    );
}

#[test]
fn overlapping_table_refuses() {
    let arm64 = arm64_dylib_slice("@rpath/libm70.dylib");
    let foreign = foreign_slice(CPU_TYPE_X86_64);
    let mut container = universal_image(&[(&arm64, CPU_TYPE_ARM64), (&foreign, CPU_TYPE_X86_64)])
        .expect("the container wraps");
    // Drag the second slice's offset onto the first's — the table must
    // refuse windows that share bytes. (Entry 1: offset@36.)
    let offset_at = 36;
    container[offset_at..offset_at + 4].copy_from_slice(&0x1000u32.to_be_bytes());
    let err = parse_universal(&container).expect_err("overlapping windows refuse");
    assert!(
        err.to_string().contains("overlap"),
        "the refusal names the overlap: {err}"
    );
}

#[test]
fn bad_magic_refuses_offset_tagged() {
    let arm64 = arm64_dylib_slice("@rpath/libm70.dylib");
    let mut container = universal_image(&[(&arm64, CPU_TYPE_ARM64)]).expect("the container wraps");
    container[0..4].copy_from_slice(&0xdead_f00du32.to_be_bytes());
    assert!(!is_universal(&container), "the magic no longer probes");
    let err = parse_universal(&container).expect_err("a bad magic refuses");
    assert!(
        err.to_string().contains("0xdeadf00d"),
        "the refusal names the magic it saw: {err}"
    );
}

#[test]
fn fixtures_round_trip_all_slices() {
    let arm64 = arm64_dylib_slice("@rpath/libm70.dylib");
    let foreign = foreign_slice(CPU_TYPE_X86_64);
    let slices = [
        (&arm64[..], CPU_TYPE_ARM64),
        (&foreign[..], CPU_TYPE_X86_64),
    ];
    let container = universal_image(&slices).expect("the container wraps");
    let u = parse_universal(&container).expect("the container decodes");
    for (arch, (bytes, cputype)) in u.arches.iter().zip(slices.iter()) {
        assert_eq!(arch.cputype, *cputype);
        let window = u
            .slice(&container, arch)
            .expect("every declared slice reads back");
        assert_eq!(window, *bytes, "slice for cputype {cputype:#x} round trips");
    }
    assert_eq!(
        u.arches[0].align_log2, 12,
        "the fixtures builder aligns 2^12"
    );
}

/// The `FatArch` row is a plain data carrier (the container's own
/// on-disk fields, widened where the 64-bit form is wider).
#[test]
fn fat_arch_is_a_data_carrier() {
    let a = FatArch {
        cputype: CPU_TYPE_ARM64,
        cpusubtype: 0,
        offset: 0x1000,
        size: 0x40,
        align_log2: 12,
    };
    assert_eq!(a.cputype, CPU_TYPE_ARM64);
    assert_eq!(a.offset, 0x1000);
}

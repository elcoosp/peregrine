//! M10 rung 2 — platform plumbing (roadmap §10.4 row M10): the linker
//! links every `-platform_version` platform it names, and the
//! chained-fixups deployment floor is *per platform* (dyld learned
//! chained fixups on macOS 12.0, iOS 15.0, tvOS 15.0, watchOS 8.0 and
//! visionOS 1.0). Below the floor the link falls back to the classic
//! `LC_DYLD_INFO_ONLY` opcode streams — the M6 legacy path, now
//! platform-aware; the fallback changes the encoding, never the fixups.

use pgr_core::layout::LinkConfig;
use pgr_core::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// main.o: a `_main` body plus a `__data` pointer to it — one chained
/// rebase slot, so the fixup planner has work on every platform.
fn main_with_rebase_slot() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.section_mut(data).relocs = vec![ObjectReloc::unsigned(0).at(0)];
    b.build().unwrap()
}

fn link_for(platform: u32, minos: u32) -> pgr_core::layout::Layout {
    let cfg = LinkConfig {
        platform,
        minos,
        ..LinkConfig::default()
    };
    let input = LinkInput {
        name: "main.o".into(),
        bytes: main_with_rebase_slot(),
    };
    link(&[input], &[], &cfg).unwrap().layout
}

const PLATFORM_MACOS: u32 = pgr_format::consts::PLATFORM_MACOS;
const PLATFORM_IOS: u32 = pgr_format::consts::PLATFORM_IOS;
const PLATFORM_TVOS: u32 = pgr_format::consts::PLATFORM_TVOS;
const PLATFORM_WATCHOS: u32 = pgr_format::consts::PLATFORM_WATCHOS;
const PLATFORM_VISIONOS: u32 = pgr_format::consts::PLATFORM_VISIONOS;

#[test]
fn below_the_floor_falls_back_to_legacy_opcodes_per_platform() {
    // macOS keeps its M6 floor (12.0.0) — the pre-rung behavior, pinned.
    let macos11 = link_for(PLATFORM_MACOS, 0x000B_0000);
    assert!(
        macos11.dyld_info.is_some() && macos11.linkedit.fixup_payload_off == 0,
        "macos 11.0 must fall back to the classic opcode streams"
    );
    // iOS and tvOS learn chained fixups at 15.0.0: 14.x must fall back
    // (before the rung this link planned chains against the macOS floor).
    for (name, platform) in [("ios", PLATFORM_IOS), ("tvos", PLATFORM_TVOS)] {
        let below = link_for(platform, 0x000E_0000); // 14.0.0
        assert!(
            below.dyld_info.is_some() && below.linkedit.fixup_payload_off == 0,
            "{name} 14.0 must fall back to the classic opcode streams"
        );
    }
    // watchOS learns them at 8.0.0: 7.x falls back.
    let watchos7 = link_for(PLATFORM_WATCHOS, 0x0007_0000);
    assert!(
        watchos7.dyld_info.is_some() && watchos7.linkedit.fixup_payload_off == 0,
        "watchos 7.0 must fall back to the classic opcode streams"
    );
}

#[test]
fn at_the_floor_and_above_runs_chained_fixups_per_platform() {
    let cases: [(&str, u32, u32); 5] = [
        ("macos", PLATFORM_MACOS, 0x000C_0000),       // 12.0.0
        ("ios", PLATFORM_IOS, 0x000F_0000),           // 15.0.0
        ("tvos", PLATFORM_TVOS, 0x000F_0000),         // 15.0.0
        ("watchos", PLATFORM_WATCHOS, 0x0008_0000),   // 8.0.0
        ("visionos", PLATFORM_VISIONOS, 0x0001_0000), // 1.0.0
    ];
    for (name, platform, minos) in cases {
        let layout = link_for(platform, minos);
        assert!(
            layout.dyld_info.is_none() && layout.linkedit.fixup_payload_off != 0,
            "{name} at its floor must plan chained fixups"
        );
    }
}

#[test]
fn the_build_version_command_carries_the_declared_platform() {
    // The layout already plumbed `LinkConfig.platform` into the emitted
    // `LC_BUILD_VERSION`; the rung's regression guard: the declared
    // platform word survives a non-macos link end to end.
    let layout = link_for(PLATFORM_VISIONOS, 0x0001_0000);
    let hb = &layout.header_bytes;
    let ncmds = u32::from_le_bytes(hb[16..20].try_into().unwrap());
    let mut off = 32usize;
    let mut found = false;
    for _ in 0..ncmds {
        let cmd = u32::from_le_bytes(hb[off..off + 4].try_into().unwrap());
        let size = u32::from_le_bytes(hb[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmd == pgr_format::consts::LC_BUILD_VERSION {
            let platform = u32::from_le_bytes(hb[off + 8..off + 12].try_into().unwrap());
            let minos = u32::from_le_bytes(hb[off + 12..off + 16].try_into().unwrap());
            assert_eq!(platform, PLATFORM_VISIONOS, "platform word must survive");
            assert_eq!(minos, 0x0001_0000, "deployment target must survive");
            found = true;
        }
        off += size;
    }
    assert!(found, "LC_BUILD_VERSION must be present");
}

#[test]
fn the_floor_table_matches_the_dyld_availability_rungs() {
    use pgr_core::layout::chained_fixups_min_minos;
    assert_eq!(chained_fixups_min_minos(PLATFORM_MACOS), 0x000C_0000);
    assert_eq!(chained_fixups_min_minos(PLATFORM_IOS), 0x000F_0000);
    assert_eq!(chained_fixups_min_minos(PLATFORM_TVOS), 0x000F_0000);
    assert_eq!(chained_fixups_min_minos(PLATFORM_WATCHOS), 0x0008_0000);
    assert_eq!(chained_fixups_min_minos(PLATFORM_VISIONOS), 0x0001_0000);
    // An unknown platform keeps the macOS floor — the conservative
    // default for a platform the pipeline does not model.
    assert_eq!(chained_fixups_min_minos(42), 0x000C_0000);
}

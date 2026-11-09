//! M10 rung 3, slice 1 — the platform floor becomes a nameable consumer
//! seam: `pgr_core::platform::FixupEncoding` answers "chained fixups or
//! the classic `LC_DYLD_INFO_ONLY` opcode streams?" for a
//! (`-platform_version` platform, deployment target) pair *before* the
//! link runs, reading the same per-platform floor table
//! [`pgr_core::layout::chained_fixups_min_minos`] names (rung 2) instead
//! of letting every consumer re-derive it — the duplication the
//! constants crosscheck closed for `PLATFORM_VISIONOS` stays closed for
//! the encoding decision too.

use pgr_core::layout::chained_fixups_min_minos;
use pgr_core::platform::FixupEncoding;
use pgr_format::consts::{
    PLATFORM_IOS, PLATFORM_MACOS, PLATFORM_TVOS, PLATFORM_VISIONOS, PLATFORM_WATCHOS,
};

/// The five linked platforms with the deployment word at their chained
/// fixups floor (`X.Y.Z` packed: major << 16).
const FLOORS: [(&str, u32, u32); 5] = [
    ("macos", PLATFORM_MACOS, 0x000C_0000),       // 12.0.0
    ("ios", PLATFORM_IOS, 0x000F_0000),           // 15.0.0
    ("tvos", PLATFORM_TVOS, 0x000F_0000),         // 15.0.0
    ("watchos", PLATFORM_WATCHOS, 0x0008_0000),   // 8.0.0
    ("visionos", PLATFORM_VISIONOS, 0x0001_0000), // 1.0.0
];

#[test]
fn at_the_floor_the_encoding_names_chains() {
    for (name, platform, floor) in FLOORS {
        assert_eq!(
            FixupEncoding::for_target(platform, floor),
            FixupEncoding::ChainedFixups,
            "{name} at its floor ({floor:#010x}) must plan chained fixups"
        );
    }
}

#[test]
fn below_the_floor_the_encoding_names_the_classic_streams() {
    for (name, platform, floor) in FLOORS {
        // One major version down: 12.0 → 11.0, 15.0 → 14.0, 8.0 → 7.0,
        // 1.0 → the zero word.
        assert_eq!(
            FixupEncoding::for_target(platform, floor - 0x0001_0000),
            FixupEncoding::ClassicOpcodes,
            "{name} a major below its floor must plan the classic opcode streams"
        );
    }
}

#[test]
fn minor_and_patch_words_keep_the_decision() {
    // 12.0.1 and 12.4.0 ride the same side of the macOS floor as 12.0.0;
    // 11.255.255 is still below it.
    assert_eq!(
        FixupEncoding::for_target(PLATFORM_MACOS, 0x000C_0001),
        FixupEncoding::ChainedFixups
    );
    assert_eq!(
        FixupEncoding::for_target(PLATFORM_MACOS, 0x000C_0400),
        FixupEncoding::ChainedFixups
    );
    assert_eq!(
        FixupEncoding::for_target(PLATFORM_MACOS, 0x000B_FFFF),
        FixupEncoding::ClassicOpcodes
    );
}

#[test]
fn the_floor_table_is_the_layout_table() {
    // One table, two readers: the seam's floor is the layout's floor,
    // platform for platform — a second table here is exactly the drift
    // the rung closes.
    for (name, platform, floor) in FLOORS {
        assert_eq!(
            FixupEncoding::floor_for(platform),
            floor,
            "{name}'s floor matches the rung-2 table"
        );
        assert_eq!(
            FixupEncoding::floor_for(platform),
            chained_fixups_min_minos(platform),
            "{name}'s floor is the layout's floor"
        );
    }
}

#[test]
fn an_unknown_platform_keeps_the_conservative_macos_floor() {
    // The layout's rule for a platform the pipeline does not model: the
    // macOS floor, the conservative default — the seam inherits it
    // verbatim instead of inventing a second policy.
    assert_eq!(chained_fixups_min_minos(0x0099_0099), 0x000C_0000);
    assert_eq!(FixupEncoding::floor_for(0x0099_0099), 0x000C_0000);
    assert_eq!(
        FixupEncoding::for_target(0x0099_0099, 0x000B_0000),
        FixupEncoding::ClassicOpcodes
    );
    assert_eq!(
        FixupEncoding::for_target(0x0099_0099, 0x000C_0000),
        FixupEncoding::ChainedFixups
    );
}

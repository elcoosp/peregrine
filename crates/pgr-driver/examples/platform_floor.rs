//! The platform-floor consumer example (M10 rung 3, slice 1): the check
//! a build system runs *before* the link — given a `-platform_version`
//! platform and a deployment target, which fixup encoding will Pass 3
//! plan? `pgr_core::platform::FixupEncoding::for_target` answers from
//! the same per-platform floor table the layout consumes
//! (`chained_fixups_min_minos`), so tooling predicts the encoding,
//! warns below the floor, and never re-derives the table.
//!
//! The below-floor rows render as miette advisories with help text —
//! the fix, not just the verdict — the same convention the driver's
//! option refusals use.
//!
//! Run: `cargo run -p pgr-driver --example platform_floor`
//! (`PGR_TRACING=1` installs a subscriber so the seam's decision event
//! prints — the same inert-until-subscriber convention the binaries
//! use).

use pgr_core::platform::FixupEncoding;
use pgr_format::consts::{
    PLATFORM_IOS, PLATFORM_MACOS, PLATFORM_TVOS, PLATFORM_VISIONOS, PLATFORM_WATCHOS,
};

/// One matrix row: the `-platform_version` name, its `LC_BUILD_VERSION`
/// constant, and the deployment target a cross-platform build might ask
/// for.
struct Row {
    /// The `-platform_version` name as written.
    name: &'static str,
    /// The platform constant (`pgr_format::consts`).
    platform: u32,
    /// The deployment target (the packed `X.Y.Z` word).
    target: u32,
}

/// One row, the field order pinned.
fn row(name: &'static str, platform: u32, target: u32) -> Row {
    Row {
        name,
        platform,
        target,
    }
}

/// The demo matrix: every linked platform asked once below and once at
/// its chained-fixups floor (`pgr_core::layout::chained_fixups_min_minos`
/// names the table).
fn rows() -> Vec<Row> {
    vec![
        row("macos", PLATFORM_MACOS, 0x000B_0000),       // 11.0.0: below
        row("macos", PLATFORM_MACOS, 0x000C_0000),       // 12.0.0: at the floor
        row("ios", PLATFORM_IOS, 0x000E_0000),           // 14.0.0: below
        row("ios", PLATFORM_IOS, 0x000F_0000),           // 15.0.0: at the floor
        row("tvos", PLATFORM_TVOS, 0x000E_0000),         // 14.0.0: below
        row("tvos", PLATFORM_TVOS, 0x000F_0000),         // 15.0.0: at the floor
        row("watchos", PLATFORM_WATCHOS, 0x0007_0000),   // 7.0.0: below
        row("watchos", PLATFORM_WATCHOS, 0x0008_0000),   // 8.0.0: at the floor
        row("visionos", PLATFORM_VISIONOS, 0x0001_0000), // 1.0.0: at the floor
    ]
}

/// The below-floor advisory: the target links, but through the classic
/// `LC_DYLD_INFO_ONLY` opcode streams — the diagnostic names the floor
/// (the fix, not just the verdict), the house miette convention.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("{name} {target} links the classic opcode streams: chained fixups start at {floor}")]
#[diagnostic(help(
    "raise the deployment target to {floor} or plan for the classic `LC_DYLD_INFO_ONLY` streams — the encoding flips, the fixups do not"
))]
struct BelowFloor {
    /// The `-platform_version` name as written.
    name: String,
    /// The deployment target, displayed.
    target: String,
    /// The platform's chained-fixups floor, displayed.
    floor: String,
}

/// The packed `X.Y.Z` word as the pipeline displays it (the driver's
/// `-platform_version` grammar).
fn version_word(v: u32) -> String {
    format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)
}

fn main() {
    // The spans stay inert until a subscriber installs — the workspace
    // convention (the binaries do it under their debug envs). DEBUG
    // surfaces the seam's decision event: platform, minos, floor and the
    // named encoding on every call.
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    println!("{:<9} {:>8}  {}", "platform", "target", "encoding (Pass 3 plans)");
    for r in rows() {
        let encoding = FixupEncoding::for_target(r.platform, r.target);
        println!("{:<9} {:>8}  {:?}", r.name, version_word(r.target), encoding);
        if encoding == FixupEncoding::ClassicOpcodes {
            let advisory = BelowFloor {
                name: r.name.to_string(),
                target: version_word(r.target),
                floor: version_word(FixupEncoding::floor_for(r.platform)),
            };
            println!("{:?}", miette::Report::new(advisory));
        }
    }
    println!(
        "\nThe decision rides the per-platform floor the layout itself reads — \
         predicted before the link, never re-derived."
    );
}

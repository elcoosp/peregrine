//! The M95 container SARIF face, runnable: build a deterministic
//! two-slice universal ("fat") container — one honest dylib slice, one
//! wearing the hand-broken initializer/TLV surface — verify it through
//! the M71 container face, and render the M95 SARIF document: one run
//! per declared slice, the anchors container-absolute, the exact shape
//! a CI triage gate reads beside the CLI's `pgr-verify <fat> --sarif`.
//!
//! ```sh
//! cargo run -p pgr-verify --example universal_sarif
//! ```
//!
//! `PGR_TRACING=1` installs a subscriber so the container walk's
//! `debug` event shows (the workspace's inert-until-subscriber
//! convention):
//!
//! ```sh
//! PGR_TRACING=1 cargo run -p pgr-verify --example universal_sarif
//! ```

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, MH_HAS_TLV_DESCRIPTORS, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE,
    VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{Options, verify_universal};

/// One arm64 dylib slice; `flagged` wears the broken initializer/TLV
/// surface (the marker without thread-local data, a `__thread_vars`
/// section off the 16-byte stride, a `__mod_init_func` section off the
/// 8-byte stride).
fn slice(seed: u64, flagged: bool) -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libm95.dylib", "universal-sarif-example");
    let mut text_sects = vec![SectionSpec {
        name: "__text".into(),
        align_log2: 2,
        flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
        data: filler(seed, 128),
        relocs: Vec::new(),
    }];
    if flagged {
        text_sects.push(SectionSpec {
            name: "__thread_vars".into(),
            align_log2: 3,
            flags: pgr_format::consts::S_THREAD_LOCAL_VARIABLES,
            data: vec![0u8; 10],
            relocs: Vec::new(),
        });
        b.set_mh_flags(MH_HAS_TLV_DESCRIPTORS);
    }
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: text_sects,
    });
    if flagged {
        b.add_segment(SegmentSpec {
            name: "__DATA_CONST".into(),
            maxprot: VM_PROT_READ | VM_PROT_WRITE,
            initprot: VM_PROT_READ | VM_PROT_WRITE,
            sections: vec![SectionSpec {
                name: "__mod_init_func".into(),
                align_log2: 3,
                flags: pgr_format::consts::S_MOD_INIT_FUNC_POINTERS,
                data: vec![0u8; 12],
                relocs: Vec::new(),
            }],
        });
    }
    b.add_symbol(SymbolSpec::Defined {
        name: "_greet".into(),
        section_index: 0,
    });
    b.build().expect("the deterministic fixture builds").bytes
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let opts = Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    let container = universal_image(&[
        (slice(0x95E1, false).as_slice(), CPU_TYPE_ARM64),
        (slice(0x95E2, true).as_slice(), CPU_TYPE_ARM64),
    ])
    .expect("the container wraps");

    let report = verify_universal(&container, &opts).expect("the container decodes");
    println!(
        "== the container's verdict: {} slices, ok: {} ==",
        report.slices.len(),
        report.is_ok(&opts)
    );
    for (i, s) in report.slices.iter().enumerate() {
        println!(
            "  slice {i} @ {:#x}: {} issue(s)",
            s.arch.offset,
            s.report.issues.len()
        );
    }

    println!("\n== the M95 SARIF document (one run per slice, container-absolute anchors) ==");
    let doc = pgr_verify::sarif::render_universal(&report, "fat.dylib");
    println!("{doc}");

    println!("\n== the same verdict through the CLI's own face ==");
    println!("  pgr-verify fat.dylib --sarif   (exit code keeps the whole-verdict gate)");
}

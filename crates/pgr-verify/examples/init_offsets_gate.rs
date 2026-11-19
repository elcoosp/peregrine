//! The M94 initializer-surface gate, runnable: build a deterministic
//! executable wearing each initializer shape the verifier walks — the
//! honest `__TEXT,__init_offsets` u32-offset section, the honest classic
//! `__mod_init_func` pointer section, and the same offsets section with
//! one hand-broken entry — and run the whole-image pass beside the
//! `init_offsets` selection, the exact shape a build gate uses to price
//! the initializer contract alone on every relink.
//!
//! ```sh
//! cargo run -p pgr-verify --example init_offsets_gate
//! ```
//!
//! `PGR_TRACING=1` installs a subscriber so the pass's `debug` events
//! show (the workspace's inert-until-subscriber convention):
//!
//! ```sh
//! PGR_TRACING=1 cargo run -p pgr-verify --example init_offsets_gate
//! ```

use pgr_fixtures::{Image, ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_format::consts::{
    PLATFORM_MACOS, S_ATTR_PURE_INSTRUCTIONS, S_INIT_FUNC_OFFSETS, S_MOD_INIT_FUNC_POINTERS,
    S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{CheckSet, Options, verify_with_checks};

/// The macOS chained-fixups floor (12.0.0) — the at-floor deployment
/// target the offsets form rides.
const MINOS_AT_FLOOR: u32 = 0x000C_0000;

/// One at-floor executable: honest `__text` inside the executable
/// `__TEXT`, the named initializer surface, the deployment target
/// pinned at the floor.
fn exec_with(offsets: Option<Vec<u8>>, mod_init: Option<Vec<u8>>) -> Image {
    let mut b = ImageBuilder::executable("init-offsets-gate-example");
    let mut text_sects = vec![SectionSpec {
        name: "__text".into(),
        align_log2: 2,
        flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
        data: filler(0x94E1, 64),
        relocs: Vec::new(),
    }];
    if let Some(bytes) = offsets {
        text_sects.push(SectionSpec {
            name: "__init_offsets".into(),
            align_log2: 2,
            flags: S_INIT_FUNC_OFFSETS,
            data: bytes,
            relocs: Vec::new(),
        });
    }
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: text_sects,
    });
    if let Some(bytes) = mod_init {
        b.add_segment(SegmentSpec {
            name: "__DATA_CONST".into(),
            maxprot: VM_PROT_READ | VM_PROT_WRITE,
            initprot: VM_PROT_READ | VM_PROT_WRITE,
            sections: vec![SectionSpec {
                name: "__mod_init_func".into(),
                align_log2: 3,
                flags: S_MOD_INIT_FUNC_POINTERS,
                data: bytes,
                relocs: Vec::new(),
            }],
        });
    }
    b.set_build_version(PLATFORM_MACOS, MINOS_AT_FLOOR, 0x000E_0000);
    b.set_entry(0);
    b.build().expect("the deterministic fixture builds")
}

/// The honest u32-offset section: two entries naming the image base
/// (the load address, inside the executable `__TEXT`), stride whole.
fn honest_offsets() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&16u32.to_le_bytes());
    out
}

/// The broken shape: the honest entries plus one entry outside every
/// segment the image maps — the finding path.
fn broken_offsets() -> Vec<u8> {
    let mut out = honest_offsets();
    out.extend_from_slice(&0x7fff_f000u32.to_le_bytes());
    out
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let opts = Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    let honest = exec_with(Some(honest_offsets()), None);
    let pointers = exec_with(None, Some(vec![0u8; 16]));
    let broken = exec_with(Some(broken_offsets()), None);

    println!("== the honest __init_offsets section, whole-image pass ==");
    let report = verify_with_checks(&honest.bytes, &opts, &CheckSet::all());
    println!("{} issues — {:?}", report.issues.len(), report.is_ok(&opts));

    println!("\n== the honest classic __mod_init_func pointer form ==");
    let report = verify_with_checks(&pointers.bytes, &opts, &CheckSet::all());
    println!("{} issues — {:?}", report.issues.len(), report.is_ok(&opts));

    println!("\n== one hand-broken entry, whole-image pass ==");
    let report = verify_with_checks(&broken.bytes, &opts, &CheckSet::all());
    for issue in &report.issues {
        println!(
            "  [{severity:?}] {code} @ {offset:?}: {message}",
            severity = issue.severity,
            code = issue.code.as_str(),
            offset = issue.offset,
            message = issue.message,
        );
    }

    println!("\n== the same shape under the init_offsets selection alone ==");
    let set = CheckSet::parse("init_offsets").expect("the canonical token parses");
    let report = verify_with_checks(&broken.bytes, &opts, &set);
    println!(
        "{} issues — the selection gates the initializer contract without paying the other families",
        report.issues.len()
    );
}

//! The M132 terminator-surface gate, runnable: build a deterministic
//! executable wearing each terminator shape the verifier walks — the
//! honest `__DATA_CONST,__mod_term_func` pointer section (whole 8-byte
//! slots), and the same section with a hand-broken stride — and run the
//! whole-image pass beside the `mod_term` selection, the exact shape a
//! build gate uses to price the terminator contract alone on every
//! relink.
//!
//! ```sh
//! cargo run -p pgr-verify --example mod_term_gate
//! ```
//!
//! `PGR_TRACING=1` installs a subscriber so the pass's `debug` events
//! show (the workspace's inert-until-subscriber convention):
//!
//! ```sh
//! PGR_TRACING=1 cargo run -p pgr-verify --example mod_term_gate
//! ```

use pgr_fixtures::{Image, ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_format::consts::{
    PLATFORM_MACOS, S_ATTR_PURE_INSTRUCTIONS, S_MOD_TERM_FUNC_POINTERS, S_REGULAR, VM_PROT_EXECUTE,
    VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{CheckSet, Options, verify_with_checks};

/// The macOS chained-fixups floor (12.0.0) — the at-floor deployment
/// target the terminator surface rides.
const MINOS_AT_FLOOR: u32 = 0x000C_0000;

/// One at-floor executable: honest `__text` inside the executable
/// `__TEXT`, the named terminator surface, the deployment target pinned
/// at the floor.
fn exec_with(mod_term: Option<Vec<u8>>) -> Image {
    let mut b = ImageBuilder::executable("mod-term-gate-example");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0x94E1, 64),
            relocs: Vec::new(),
        }],
    });
    if let Some(bytes) = mod_term {
        b.add_segment(SegmentSpec {
            name: "__DATA_CONST".into(),
            maxprot: VM_PROT_READ | VM_PROT_WRITE,
            initprot: VM_PROT_READ | VM_PROT_WRITE,
            sections: vec![SectionSpec {
                name: "__mod_term_func".into(),
                align_log2: 3,
                flags: S_MOD_TERM_FUNC_POINTERS,
                data: bytes,
                relocs: Vec::new(),
            }],
        });
    }
    b.set_build_version(PLATFORM_MACOS, MINOS_AT_FLOOR, 0x000E_0000);
    b.set_entry(0);
    b.build().expect("the deterministic fixture builds")
}

/// The honest pointer section: two whole 8-byte slots.
fn honest_mod_term() -> Vec<u8> {
    vec![0u8; 16]
}

/// The broken shape: the honest slots plus four trailing bytes — off the
/// 8-byte stride, the finding path.
fn broken_mod_term() -> Vec<u8> {
    let mut out = honest_mod_term();
    out.extend_from_slice(&[0u8; 4]);
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

    let honest = exec_with(Some(honest_mod_term()));
    let broken = exec_with(Some(broken_mod_term()));

    println!("== the honest __mod_term_func section, whole-image pass ==");
    let report = verify_with_checks(&honest.bytes, &opts, &CheckSet::all());
    println!("{} issues — {:?}", report.issues.len(), report.is_ok(&opts));

    println!("\n== the hand-broken stride, whole-image pass ==");
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

    println!("\n== the same shape under the mod_term selection alone ==");
    let set = CheckSet::parse("mod_term").expect("the canonical token parses");
    let report = verify_with_checks(&broken.bytes, &opts, &set);
    println!(
        "{} issues — the selection gates the terminator contract without paying the other families",
        report.issues.len()
    );
}

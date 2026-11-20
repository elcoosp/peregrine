//! The M97 SARIF `baselineState` face, runnable: the baseline gate's
//! whole-verdict document, stated. A corrupted image records the
//! tolerated history once; the relink twins show the three states the
//! gate speaks — the same image rides `unchanged` (the gate passes), the
//! clean relink's cleared finding rides `absent` with its code still
//! named in the rule table, and a fresh corruption rides `new` (the gate
//! fails). SARIF 2.1.0's own property carries the M13 delta, which is
//! what retires the M75 refusal's premise — a triage tool reads the
//! baseline diff natively.
//!
//! ```sh
//! cargo run -p pgr-verify --example sarif_baseline
//! ```

use pgr_fixtures::{
    ImageBuilder, ImportsFormat, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{BaselineDelta, OffsetIdentity, Options, sarif};

/// A small chained-fixup executable with one bind and one rebase slot.
fn exec_bytes(seed: u8) -> Vec<u8> {
    let mut b = ImageBuilder::executable("sarif-baseline-example");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(u64::from(seed), 96),
            relocs: Vec::new(),
        }],
    });
    b.add_segment(SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    });
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![SlotKind::Bind {
        sym_index: sym,
        addend: 0,
    }]);
    b.set_entry(0x40);
    b.set_imports_format(ImportsFormat::Plain);
    b.build().expect("the fixture builds").bytes
}

/// The corrupted twin: one flipped body byte rides a stale page hash.
fn corrupted(image: &[u8]) -> Vec<u8> {
    let mut bytes = image.to_vec();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    bytes
}

/// Renders the stated document for one relink twin and prints the states
/// it rides, beside the gate's verdict.
fn gate(name: &str, twin: &[u8], prev: &[pgr_verify::Issue], opts: Options) {
    let report = pgr_verify::verify(twin, &opts);
    let delta = BaselineDelta::between(prev, &report.issues, &OffsetIdentity);
    let doc = sarif::render_with_baseline(&report, &delta, &OffsetIdentity, "app");
    let clean = delta.is_clean();
    println!(
        "{name}: {}, {} new / {} resolved / {} surviving",
        if clean { "ships" } else { "refused" },
        delta.introduced.len(),
        delta.resolved.len(),
        delta.surviving,
    );
    for state in ["unchanged", "new", "absent"] {
        let count = doc
            .matches(&format!("\"baselineState\":\"{state}\""))
            .count();
        if count > 0 {
            println!("    {state}: {count} result(s)");
        }
    }
}

fn main() {
    if std::env::var("PGR_TRACING").as_deref() == Ok("1") {
        let _ = tracing_subscriber::fmt().try_init();
    }
    let opts = Options::default();

    // The corrupted run records the tolerated history (the baseline's
    // issues are the M13 report's own shape — what `--json` writes).
    let clean = exec_bytes(0x97);
    let broken = corrupted(&clean);
    let prev = pgr_verify::verify(&broken, &opts).issues;
    println!("recorded: {} issue(s) in the baseline\n", prev.len());

    gate("the same corrupted relink", &broken, &prev, opts);
    gate("the clean relink", &clean, &prev, opts);

    // A fresh corruption at a different site: a new finding the baseline
    // does not vouch for — the gate refuses and the document says `new`.
    let mut twice = clean.clone();
    let quarter = twice.len() / 4;
    twice[quarter] ^= 0xFF;
    gate("a fresh corruption", &twice, &prev, opts);
}

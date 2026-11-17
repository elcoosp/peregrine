//! The M67 consumer-side check seam, runnable: a project policy (no
//! stack-exec bit on an executable) verifies beside the built-in
//! families under its own `Code::Custom` token — same run shape, same
//! sorted report, same JSON round trip as the registry's own families.
//!
//! ```sh
//! cargo run -p pgr-verify --example custom_check
//! ```
//!
//! `PGR_TRACING=1` installs a subscriber so the selection's `debug`
//! event shows (the workspace's inert-until-subscriber convention):
//!
//! ```sh
//! PGR_TRACING=1 cargo run -p pgr-verify --example custom_check
//! ```

use pgr_fixtures::{Image, ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_format::consts::{
    MH_ALLOW_STACK_EXECUTION, MH_EXECUTE, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE,
    VM_PROT_READ,
};
use pgr_verify::{
    CheckContext, CheckSet, Code, CustomCheck, Issue, Options, parse_report_json, to_json,
    verify_with_extra_checks,
};

/// The project policy: an executable never rides the stack-exec bit
/// (the M51 decision read from the consumer side, under its own code).
/// Executable-only policy — the self-gate is a no-op on everything else.
struct NoStackExecute;

impl CustomCheck for NoStackExecute {
    fn name(&self) -> &'static str {
        "no_stack_execute"
    }
    fn summary(&self) -> &'static str {
        "project policy: no MH_ALLOW_STACK_EXECUTION on an executable"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::Custom("no_stack_execute")]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        if ctx.parsed.header.filetype == MH_EXECUTE
            && ctx.parsed.header.flags & MH_ALLOW_STACK_EXECUTION != 0
        {
            ctx.report.issues.push(Issue::error(
                Code::Custom("no_stack_execute"),
                "the image rides MH_ALLOW_STACK_EXECUTION — the fix is dropping the flag",
                None,
            ));
        }
    }
}

/// A minimal legal executable fixture with the stack-exec bit on or
/// off — the same shape the m51 gate pins, now the policy's target.
fn fixture_image(stack_exec: bool) -> Image {
    let mut b = ImageBuilder::executable("custom-check-example");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xC0_FFEE, 64),
            relocs: Vec::new(),
        }],
    });
    b.set_entry(0);
    if stack_exec {
        b.set_mh_flags(MH_ALLOW_STACK_EXECUTION);
    }
    b.build().expect("the deterministic fixture builds")
}

/// Runs the full pass beside the policy and prints its verdict line.
fn run(label: &str, bytes: &[u8], opts: Options, extra: &[&dyn CustomCheck]) -> bool {
    let report = verify_with_extra_checks(bytes, &opts, &CheckSet::all(), extra);
    for issue in &report.issues {
        let severity = match issue.severity {
            pgr_verify::Severity::Error => "error",
            pgr_verify::Severity::Warning => "warning",
        };
        println!("  {severity} [{}] {}", issue.code.as_str(), issue.message);
    }
    println!("{label:<24} ok={}", report.is_ok(&opts));
    report.is_ok(&opts)
}

fn main() {
    // The extension names itself on the tracing seam — inert until a
    // subscriber installs (the binaries do it under their debug envs).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let flagged = fixture_image(true);
    let clean = fixture_image(false);
    let check = NoStackExecute;
    let extra: [&dyn CustomCheck; 1] = [&check];
    let opts = Options::default();

    // The policy rides beside every family: the flagged image is
    // refused under the custom code, the control passes.
    println!("== the flagged image (the policy fires) ==");
    let flagged_ok = run("full+policy", &flagged.bytes, opts, &extra);
    assert!(!flagged_ok, "the policy refuses the stack-exec executable");

    println!("== the control (the policy is silent) ==");
    let clean_ok = run("full+policy", &clean.bytes, opts, &extra);
    assert!(clean_ok, "the control passes the policy");

    // The custom code rides the report JSON both ways (one writer, one
    // reader — the M13 round-trip contract extended to M67's tokens).
    let report = verify_with_extra_checks(&flagged.bytes, &opts, &CheckSet::all(), &extra);
    let parsed = parse_report_json(&to_json(&report)).expect("the report parses back");
    assert!(
        parsed
            .issues
            .iter()
            .any(|i| i.code.as_str() == "no_stack_execute"),
        "the custom code survives the round trip"
    );
    println!("== the custom code survives the round trip: no_stack_execute ==");
}

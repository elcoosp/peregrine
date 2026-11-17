//! M67 — the verifier's check registry opens to consumer-side checks: a
//! project policy slots into the same run shape the built-in families use
//! (`CustomCheck` beside `ImageCheck`), pushes issues carrying its own
//! `Code::Custom` token into the same sorted report, and rides every
//! downstream consumer unchanged — the JSON round trip, the baseline
//! delta, the strict gate, the stats contract.
//!
//! Gate matrix:
//! - the registry runs the custom check beside the families;
//! - the empty extension is the unchanged pass (bit-for-bit parity);
//! - the custom check self-gates on the image type (the family contract);
//! - a custom error zeroes the fixup-slot count like a family error;
//! - the custom code rides the report JSON both ways (round trip);
//! - a malformed custom token is refused with the fix named;
//! - the custom findings ride the baseline delta;
//! - strict warnings gate the custom warnings;
//! - names are metadata: two same-named checks both run.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler};
use pgr_format::consts::{
    MH_ALLOW_STACK_EXECUTION, MH_EXECUTE, PLATFORM_MACOS, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR,
    VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{
    BaselineDelta, CheckContext, CheckSet, Code, CustomCheck, Issue, OffsetIdentity, Options,
    Severity, parse_report_json, to_json, verify, verify_with_checks, verify_with_extra_checks,
};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

fn lenient() -> Options {
    Options {
        strict_warnings: false,
        skip_hash_recompute: false,
    }
}

/// A minimal legal executable fixture with the stack-exec bit on or off.
fn exec_builder(stack_exec: bool) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m67exec");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0x5AA5, 96),
            relocs: Vec::new(),
        }],
    });
    b.set_entry(0);
    if stack_exec {
        b.set_mh_flags(MH_ALLOW_STACK_EXECUTION);
    }
    b
}

/// A minimal legal dylib fixture (the shape the self-gate turns off on).
fn dylib_builder(stack_exec: bool) -> ImageBuilder {
    let mut b = ImageBuilder::dylib("@rpath/libm67.dylib", "m67");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xA5A5, 96),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_m67_fn".into(),
        section_index: 0,
    });
    if stack_exec {
        b.set_mh_flags(MH_ALLOW_STACK_EXECUTION);
    }
    b
}

/// A chained-fixup executable born at the macOS floor — the shape whose
/// parse carries fixup slots (the stats contract's nonzero side).
fn chained_exec() -> Vec<u8> {
    let mut b = ImageBuilder::executable("m67chained");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xA5A5, 96),
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
    b.set_got(vec![
        pgr_fixtures::SlotKind::Bind {
            sym_index: sym,
            addend: 0,
        },
        pgr_fixtures::SlotKind::Rebase { target: 0x40 },
    ]);
    b.set_entry(0x40);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    b.build().expect("the chained fixture builds").bytes
}

/// The project-policy check: no stack-exec bit, under its own code.
/// Executable-only policy (the M51 domain note: the privilege is an
/// exec'd main executable's, never a loaded image's) — the self-gate
/// is a no-op on everything else.
struct NoStackExecute;

impl CustomCheck for NoStackExecute {
    fn name(&self) -> &'static str {
        "no_stack_execute"
    }
    fn summary(&self) -> &'static str {
        "project policy: the image must not ride MH_ALLOW_STACK_EXECUTION"
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

/// A check that always fires one error at a fixed offset (the marker).
struct Marker {
    offset: u64,
}

impl CustomCheck for Marker {
    fn name(&self) -> &'static str {
        "policy_marker"
    }
    fn summary(&self) -> &'static str {
        "project policy: one marker issue at a known offset"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::Custom("policy_marker")]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        ctx.report.issues.push(Issue::error(
            Code::Custom("policy_marker"),
            "the marker rode",
            Some(self.offset),
        ));
    }
}

/// A custom warning (the strict-gate probe).
struct PolicyHint;

impl CustomCheck for PolicyHint {
    fn name(&self) -> &'static str {
        "policy_hint"
    }
    fn summary(&self) -> &'static str {
        "project policy: a tolerated but visible hint"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::Custom("policy_hint")]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        ctx.report.issues.push(Issue::warning(
            Code::Custom("policy_hint"),
            "the hint rode",
            None,
        ));
    }
}

/// Two checks sharing a name (names are metadata, not a registry key).
struct SameName(u8);

impl CustomCheck for SameName {
    fn name(&self) -> &'static str {
        "same_name"
    }
    fn summary(&self) -> &'static str {
        "project policy: names are metadata"
    }
    fn codes(&self) -> &'static [Code] {
        &[Code::Custom("same_name")]
    }
    fn run(&self, ctx: &mut CheckContext<'_>) {
        ctx.report.issues.push(Issue::error(
            Code::Custom("same_name"),
            format!("the {} same-named check rode", self.0),
            None,
        ));
    }
}

// ---- the invariant -----------------------------------------------------------

#[test]
fn the_registry_runs_the_custom_check_beside_the_families() {
    let bytes = exec_builder(false)
        .build()
        .expect("the fixture builds")
        .bytes;
    let marker = Marker { offset: 0x40 };
    let extra: [&dyn CustomCheck; 1] = [&marker];

    let plain = verify(&bytes, &opts());
    assert!(
        plain
            .issues
            .iter()
            .all(|i| i.code.as_str() != "policy_marker"),
        "the built-in registry alone names no custom code: {:?}",
        plain.issues
    );

    let report = verify_with_extra_checks(&bytes, &opts(), &CheckSet::all(), &extra);
    let marks: Vec<&Issue> = report
        .issues
        .iter()
        .filter(|i| i.code.as_str() == "policy_marker")
        .collect();
    assert_eq!(
        marks.len(),
        1,
        "the custom check ran once: {:?}",
        report.issues
    );
    assert_eq!(marks[0].offset, Some(0x40), "the marker kept its anchor");
    assert_eq!(marks[0].severity, Severity::Error, "the marker is an error");
    // The families still ran: the custom issue landed in the same sorted
    // report, not a side channel.
    assert!(
        report
            .issues
            .windows(2)
            .all(|w| w[0].offset.unwrap_or(u64::MAX) <= w[1].offset.unwrap_or(u64::MAX)),
        "the report stays sorted: {:?}",
        report.issues
    );
}

#[test]
fn the_empty_extension_is_the_unchanged_pass() {
    let bytes = chained_exec();
    let sets = [
        CheckSet::all(),
        CheckSet::parse("segments,fixups").expect("names"),
    ];
    for set in sets {
        let plain = verify_with_checks(&bytes, &opts(), &set);
        let extended = verify_with_extra_checks(&bytes, &opts(), &set, &[]);
        assert_eq!(plain, extended, "an empty extension is the same pass");
    }
}

#[test]
fn the_custom_check_self_gates_on_the_image_type() {
    let exec = exec_builder(true).build().expect("the exec builds").bytes;
    let dylib = dylib_builder(true).build().expect("the dylib builds").bytes;
    let check = NoStackExecute;
    let extra: [&dyn CustomCheck; 1] = [&check];

    let on_exec = verify_with_extra_checks(&exec, &opts(), &CheckSet::empty(), &extra);
    assert!(
        on_exec
            .issues
            .iter()
            .any(|i| i.code.as_str() == "no_stack_execute"),
        "the policy check fires on the executable: {:?}",
        on_exec.issues
    );

    let on_dylib = verify_with_extra_checks(&dylib, &opts(), &CheckSet::empty(), &extra);
    assert!(
        !on_dylib
            .issues
            .iter()
            .any(|i| i.code.as_str() == "no_stack_execute"),
        "the policy check self-gates off the dylib: {:?}",
        on_dylib.issues
    );
}

#[test]
fn a_custom_error_zeroes_the_fixup_slot_count_like_the_families() {
    let bytes = chained_exec();
    let marker = Marker { offset: 0x40 };
    let extra: [&dyn CustomCheck; 1] = [&marker];

    let base = verify_with_checks(&bytes, &opts(), &CheckSet::empty());
    assert!(
        base.stats.fixup_slots > 0,
        "the chained fixture carries fixup slots: {:?}",
        base.stats
    );
    assert!(
        !base.issues.iter().any(|i| i.severity == Severity::Error),
        "the fixture has no family errors: {:?}",
        base.issues
    );

    let refused = verify_with_extra_checks(&bytes, &opts(), &CheckSet::all(), &extra);
    assert_eq!(
        refused.stats.fixup_slots, 0,
        "a custom error zeroes the count like a family error"
    );
}

#[test]
fn the_custom_code_rides_the_report_json_round_trip() {
    let bytes = exec_builder(false)
        .build()
        .expect("the fixture builds")
        .bytes;
    let marker = Marker { offset: 0x40 };
    let extra: [&dyn CustomCheck; 1] = [&marker];
    let report = verify_with_extra_checks(&bytes, &opts(), &CheckSet::empty(), &extra);

    let json = to_json(&report);
    let parsed = parse_report_json(&json).expect("the report parses back");
    let before = report
        .issues
        .iter()
        .find(|i| i.code.as_str() == "policy_marker")
        .expect("the marker rode");
    let after = parsed
        .issues
        .iter()
        .find(|i| i.code.as_str() == "policy_marker")
        .expect("the custom code survives the round trip");
    assert_eq!(before.code, after.code, "the token restores verbatim");
    assert_eq!(before.message, after.message);
    assert_eq!(before.offset, after.offset);
}

#[test]
fn a_malformed_custom_token_is_refused_with_the_fix_named() {
    let err = parse_report_json(
        r#"{"issues":[{"severity":"error","code":"Policy Marker!","message":"x","offset":null}]}"#,
    )
    .expect_err("a malformed custom token is refused");
    let rendered = err.to_string();
    assert!(
        rendered.contains("Policy Marker!"),
        "the refusal names the token: {rendered}"
    );
    assert!(
        rendered.contains("snake_case"),
        "the refusal names the fix: {rendered}"
    );
}

#[test]
fn the_custom_findings_ride_the_baseline_delta() {
    let stack_exec = exec_builder(true).build().expect("builds").bytes;
    let clean = exec_builder(false).build().expect("builds").bytes;
    let check = NoStackExecute;
    let extra: [&dyn CustomCheck; 1] = [&check];

    let prev = verify_with_extra_checks(&stack_exec, &opts(), &CheckSet::empty(), &extra);
    assert_eq!(prev.issues.len(), 1, "the baseline carries the finding");

    let fresh_clean = verify_with_extra_checks(&clean, &opts(), &CheckSet::empty(), &extra);
    let delta = BaselineDelta::between(&prev.issues, &fresh_clean.issues, &OffsetIdentity);
    assert!(
        delta.is_clean(),
        "the finding resolved under the offset policy: {delta:?}"
    );
    assert_eq!(delta.resolved.len(), 1, "the custom finding was resolved");

    let fresh_again = verify_with_extra_checks(&stack_exec, &opts(), &CheckSet::empty(), &extra);
    let reintroduced =
        BaselineDelta::between(&fresh_clean.issues, &fresh_again.issues, &OffsetIdentity);
    assert_eq!(
        reintroduced.introduced.len(),
        1,
        "the custom finding is named when it returns"
    );
}

#[test]
fn strict_warnings_gate_the_custom_warnings() {
    let bytes = exec_builder(false).build().expect("builds").bytes;
    let check = PolicyHint;
    let extra: [&dyn CustomCheck; 1] = [&check];

    let lenient_report = verify_with_extra_checks(&bytes, &lenient(), &CheckSet::empty(), &extra);
    assert!(
        lenient_report.is_ok(&lenient()),
        "a custom warning passes the lenient gate"
    );
    let strict_report = verify_with_extra_checks(&bytes, &opts(), &CheckSet::empty(), &extra);
    assert!(
        !strict_report.is_ok(&opts()),
        "a custom warning fails the strict gate"
    );
}

#[test]
fn names_are_metadata_two_same_named_checks_both_run() {
    let bytes = exec_builder(false).build().expect("builds").bytes;
    let first = SameName(1);
    let second = SameName(2);
    let extra: [&dyn CustomCheck; 2] = [&first, &second];

    let report = verify_with_extra_checks(&bytes, &opts(), &CheckSet::empty(), &extra);
    let messages: Vec<&str> = report
        .issues
        .iter()
        .filter(|i| i.code.as_str() == "same_name")
        .map(|i| i.message.as_str())
        .collect();
    assert_eq!(
        messages,
        vec!["the 1 same-named check rode", "the 2 same-named check rode"],
        "caller order is the run order: {messages:?}"
    );
}

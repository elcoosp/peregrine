//! M119 — the `-single_module`/`-multi_module` dylib module contract:
//! ld64's dylib module-table shape. `-single_module` forces the dylib to
//! be treated as a single module: the `LC_DYSYMTAB` module table has one
//! entry (a `DylibModule64` whose subranges mirror the `LC_DYSYMTAB`'s
//! locals/extdefs, the whole image as one module), and all undefineds
//! must resolve at link time (or they ride the flat/weak lookup, the M103
//! pattern; unresolved strong symbols refuse the link with the symbol
//! named). The default `-multi_module` keeps the legacy zero-module table
//! peregrine always carried (every pre-knob link byte-identical).
//!
//! Gate matrix:
//! * the default keeps the pre-M119 shape (no module table, `nmodtab = 0`);
//! * `-single_module` dylib emits one `LC_DYSYMTAB` module-table entry
//!   (`nmodtab = 1`, `modtaboff > 0`, the 56-byte entry whose subranges
//!   mirror the `LC_DYSYMTAB`);
//! * the decision threads to the layout (the echo the emit reads);
//! * the escalation — under `-single_module` an unresolved strong,
//!   two-level reference refuses even under `-undefined dynamic_lookup`
//!   (the M103 `Error` shape forced); weak refs ride (the `is_weak_ref`
//!   gate); flat-namespace refs ride (the whole image is flat);
//! * the byte-identity lock — a dylib corpus links byte-identical under
//!   the default and an explicit `-multi_module`;
//! * the ladder replay rides the decision (the M81 pattern — config, not
//!   a product);
//! * the relocatable refusal — the object's symtab is the input's,
//!   verbatim (the layout re-check and `link_reloc` back the driver
//!   surface).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_cached, link_reloc};
use pgr_core::propagate::section_digests;
use pgr_core::resolve::{ModulePolicy, UndefinedPolicy};
use pgr_core::resolve_reuse::ResolveReuseSeed;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::{DysymtabCommand, LoadCommandIter, LoadCommandKind, MachHeader64};

/// One object: `_main` in a `__text` body, plus a defined `_fn` — the
/// minimal dylib corpus (two external definitions, one local-free shape).
fn dylib_corpus(name: &str) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(4),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_fn".into(),
        section_index: text,
        value: 16,
        weak: false,
    });
    b
}

/// One object whose `__text` references an unresolved external (`_hole`)
/// through a GOT-form pointer pair — the strong reference no input and no
/// dylib resolves, the escalation's subject. `weak` names the weak-ref
/// face the gate lets ride.
fn hole_corpus(name: &str, weak: bool) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(4),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let hole = b.add_symbol(ObjectSymbol::Undefined {
        name: "_hole".into(),
        weak_ref: weak,
    });
    b.section_mut(text)
        .relocs
        .push(ObjectReloc::got_page21(hole as u32).at(4));
    b.section_mut(text)
        .relocs
        .push(ObjectReloc::got_pageoff12(hole as u32).at(8));
    b
}

fn inputs(builders: &[ObjectBuilder]) -> Vec<LinkInput> {
    builders
        .iter()
        .map(|b| LinkInput {
            name: b.name().into(),
            bytes: b.build().expect("the fixture object builds"),
        })
        .collect()
}

fn dylib_cfg(tweak: impl FnOnce(&mut LinkConfig)) -> LinkConfig {
    let mut c = LinkConfig {
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libpgr.dylib".into()),
        ..LinkConfig::default()
    };
    tweak(&mut c);
    c
}

/// Parses the `LC_DYSYMTAB` from the layout's header bytes (the command
/// rides the header — the module-table shape is observable without the
/// full emit).
fn dysymtab(layout: &pgr_core::Layout) -> DysymtabCommand {
    let bytes = &layout.header_bytes;
    let hdr = MachHeader64::parse(bytes).expect("the header parses");
    let mut it = LoadCommandIter::new(bytes, MachHeader64::SIZE, hdr.ncmds, hdr.sizeofcmds)
        .expect("the load-command iter builds");
    while let Ok(Some(cmd)) = it.next_command() {
        if let LoadCommandKind::Dysymtab = cmd.kind {
            return DysymtabCommand::parse(cmd.bytes, 0).expect("the dysymtab parses");
        }
    }
    panic!("no LC_DYSYMTAB in the linked header");
}

#[test]
fn the_default_keeps_the_pre_m119_shape() {
    // The pre-M119 shape: the default `-multi_module` plans no module
    // table (the legacy zero-module table peregrine always carried —
    // `nmodtab = 0`, no `modtab_off`, every pre-knob link byte-identical).
    let builders = vec![dylib_corpus("a.o")];
    let layout = link(&inputs(&builders), &[], &dylib_cfg(|_| ()))
        .expect("the default dylib links")
        .layout;
    let dys = dysymtab(&layout);
    assert_eq!(dys.nmodtab, 0, "the default carries no module table");
    assert_eq!(dys.modtaboff, 0, "the default carries no modtaboff");
    assert!(
        layout.module_table.is_empty(),
        "the default carries no module-table bytes"
    );
    assert!(
        !layout.module_policy.is_single(),
        "the default is multi_module"
    );
}

#[test]
fn the_single_module_decision_emits_one_module_table_entry() {
    // `-single_module` dylib: the `LC_DYSYMTAB` carries one module-table
    // entry (`nmodtab = 1`, `modtaboff > 0`) — the 56-byte `DylibModule64`
    // the whole image as one module rides.
    let builders = vec![dylib_corpus("a.o")];
    let layout = link(
        &inputs(&builders),
        &[],
        &dylib_cfg(|c| c.module_policy = ModulePolicy::SingleModule),
    )
    .expect("the single_module dylib links")
    .layout;
    let dys = dysymtab(&layout);
    assert_eq!(dys.nmodtab, 1, "the single_module dylib carries one module");
    assert!(dys.modtaboff > 0, "the module table rides a real offset");
    assert_eq!(
        layout.module_table.len(),
        core::mem::size_of::<pgr_format::DylibModule64>(),
        "the module table is one 56-byte entry"
    );
    assert_eq!(
        layout.linkedit.modtab_off as u32, dys.modtaboff,
        "the layout's modtab_off matches the LC_DYSYMTAB"
    );
}

#[test]
fn the_module_table_subranges_mirror_the_dysymtab() {
    // The single module's `ilocalsym`/`nlocalsym`/`iextdefsym`/
    // `nextdefsym` mirror the `LC_DYSYMTAB`'s (the whole image is one
    // module — the entry's subranges ARE the command's).
    let builders = vec![dylib_corpus("a.o")];
    let layout = link(
        &inputs(&builders),
        &[],
        &dylib_cfg(|c| c.module_policy = ModulePolicy::SingleModule),
    )
    .expect("the single_module dylib links")
    .layout;
    let dys = dysymtab(&layout);
    assert_eq!(dys.nmodtab, 1, "the module table rides one entry");
    // The 56-byte `DylibModule64` field order (Apple `<mach-o/loader.h>`):
    // module_name(0), iextdefsym(4), nextdefsym(8), irefsym(12), nrefsym(16),
    // ilocalsym(20), nlocalsym(24), ... the trailing legacy fields zero.
    let mt = &layout.module_table;
    let r32 = |at: usize| u32::from_le_bytes(mt[at..at + 4].try_into().unwrap());
    assert_eq!(r32(0), 0, "the single module carries no name (module_name)");
    assert_eq!(r32(4), dys.iextdefsym, "iextdefsym mirrors the command");
    assert_eq!(r32(8), dys.nextdefsym, "nextdefsym mirrors the command");
    assert_eq!(r32(20), dys.ilocalsym, "ilocalsym mirrors the command");
    assert_eq!(r32(24), dys.nlocalsym, "nlocalsym mirrors the command");
}

#[test]
fn the_single_module_decision_threads_to_the_layout() {
    // The echo the emit reads — the decision crosses to the layout so
    // the producer-side gate fires regardless of which caller plans.
    let builders = vec![dylib_corpus("a.o")];
    let layout = link(
        &inputs(&builders),
        &[],
        &dylib_cfg(|c| c.module_policy = ModulePolicy::SingleModule),
    )
    .expect("the single_module dylib links")
    .layout;
    assert!(
        layout.module_policy.is_single(),
        "the layout carries the single_module decision"
    );
}

#[test]
fn the_single_module_escalation_refuses_strong_unresolved() {
    // Under `-single_module` an unresolved strong, two-level reference
    // refuses even under `-undefined dynamic_lookup` (the M103 `Error`
    // shape forced — the escalation is the rebinding the resolver reads).
    let builders = vec![hole_corpus("a.o", false)];
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        undefined_policy: UndefinedPolicy::DynamicLookup,
        module_policy: ModulePolicy::SingleModule,
        ..LinkConfig::default()
    };
    let err = link(&inputs(&builders), &[], &cfg).expect_err("the strong hole refuses");
    let text = err.to_string();
    assert!(
        text.contains("_hole") && text.contains("undefined"),
        "the refusal names the hole and the undefined contract: {text}"
    );
    // The default `-multi_module` lets the same hole ride (the M103
    // dynamic-lookup shape — the policy is the exit's, never the image's).
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        undefined_policy: UndefinedPolicy::DynamicLookup,
        module_policy: ModulePolicy::MultiModule,
        ..LinkConfig::default()
    };
    link(&inputs(&builders), &[], &cfg).expect("the multi_module face lets the hole ride");
}

#[test]
fn the_single_module_escalation_lets_weak_refs_ride() {
    // A weak reference rides the dynamic-lookup slot under `-single_module`
    // (the `is_weak_ref` gate — dyld resolves it at launch or kills the
    // image, the M103 pattern).
    let builders = vec![hole_corpus("a.o", true)];
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        undefined_policy: UndefinedPolicy::DynamicLookup,
        module_policy: ModulePolicy::SingleModule,
        ..LinkConfig::default()
    };
    link(&inputs(&builders), &[], &cfg).expect("the weak reference rides the dynamic-lookup slot");
}

#[test]
fn the_single_module_escalation_is_inert_under_flat_namespace() {
    // Under `-flat_namespace` the whole image is flat — no two-level
    // strong references exist, so `-single_module` is inert (the hole
    // rides the flat lookup the way `-undefined dynamic_lookup` always
    // encoded it).
    let builders = vec![hole_corpus("a.o", false)];
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        undefined_policy: UndefinedPolicy::DynamicLookup,
        flat_namespace: true,
        module_policy: ModulePolicy::SingleModule,
        ..LinkConfig::default()
    };
    link(&inputs(&builders), &[], &cfg)
        .expect("the flat namespace rides the hole (single_module inert)");
}

#[test]
fn the_byte_identity_lock() {
    // A dylib corpus links byte-identical under the default and an
    // explicit `-multi_module` (the default IS multi_module — every
    // pre-knob link byte-identical).
    let builders = vec![dylib_corpus("a.o")];
    let default =
        link(&inputs(&builders), &[], &dylib_cfg(|_| ())).expect("the default dylib links");
    let explicit = link(
        &inputs(&builders),
        &[],
        &dylib_cfg(|c| c.module_policy = ModulePolicy::MultiModule),
    )
    .expect("the explicit multi_module dylib links");
    assert_eq!(
        default.layout.header_bytes, explicit.layout.header_bytes,
        "the default and explicit multi_module link byte-identical"
    );
}

#[test]
fn the_ladder_replay_rides_the_decision() {
    // The M81 pattern: the decision is config, not a product — the
    // resolve-reuse relink re-plans the same single-module shape the cold
    // walk plans (the resolver reads the config, both lanes reach it).
    let builders = vec![dylib_corpus("a.o")];
    let ins = inputs(&builders);
    let recording = link_cached(
        &ins,
        &[],
        &dylib_cfg(|c| {
            c.record_resolution = true;
            c.module_policy = ModulePolicy::SingleModule;
        }),
        Parallelism::Serial,
        None,
    )
    .expect("the recording link runs");
    let snapshot = recording
        .resolve_snapshot
        .clone()
        .expect("a recording link captures the snapshot");
    let replayed = link_cached(
        &ins,
        &[],
        &dylib_cfg(|c| {
            c.resolve_reuse = Some(ResolveReuseSeed {
                snapshot,
                digests: section_digests(&recording.objects),
            });
            c.module_policy = ModulePolicy::SingleModule;
        }),
        Parallelism::Serial,
        None,
    )
    .expect("the seeded relink runs");
    assert_eq!(
        recording.layout.module_table.len(),
        replayed.layout.module_table.len(),
        "the replay plans the same module-table shape (the M81 parity)"
    );
    let cold = dysymtab(&recording.layout);
    let replay = dysymtab(&replayed.layout);
    assert_eq!(
        cold.nmodtab, replay.nmodtab,
        "the replay carries the same nmodtab"
    );
    assert_eq!(
        cold.modtaboff, replay.modtaboff,
        "the replay carries the same modtaboff"
    );
    assert!(
        replayed.layout.module_policy.is_single(),
        "the replay carries the single_module decision (config, not a product)"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob_in_link_reloc() {
    // The object's symtab is the input's, verbatim — there is no
    // LC_DYSYMTAB module table to shape, no escalation to apply (the
    // M104/M105/M117 pattern; the layout re-check backs this in `layout`).
    let builders = vec![dylib_corpus("a.o")];
    let cfg = {
        let mut c = dylib_cfg(|c| c.module_policy = ModulePolicy::SingleModule);
        c.filetype = OutputType::Relocatable;
        c
    };
    let err = link_reloc(&inputs(&builders), &[], &cfg, Parallelism::Serial)
        .expect_err("the relocatable output refuses the knob");
    let text = err.to_string();
    assert!(
        text.contains("-single_module") && text.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {text}"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob_in_layout() {
    // The layout's own re-check: no library caller plans the shape
    // either (the M104/M105/M117 refusal shape).
    let builders = vec![dylib_corpus("a.o")];
    let cfg = {
        let mut c = dylib_cfg(|c| c.module_policy = ModulePolicy::SingleModule);
        c.filetype = OutputType::Relocatable;
        c
    };
    let err = link(&inputs(&builders), &[], &cfg).expect_err("the layout re-check refuses");
    let text = err.to_string();
    assert!(
        text.contains("-single_module") && text.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {text}"
    );
}

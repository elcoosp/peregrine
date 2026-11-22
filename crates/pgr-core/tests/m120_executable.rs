//! M120 — the `-executable` explicit filetype override: ld64's flag
//! ("Force the creation of an `MH_EXECUTE` file") forces `MH_EXECUTE`
//! regardless of any `-dylib`/`-bundle` inference earlier on the command
//! line (or sets the default, which is already `Execute`). The decision
//! rides the filetype the layout and emit already key on (`__PAGEZERO`,
//! `LC_MAIN`, `LC_LOAD_DYLINKER` and the no-`LC_ID_DYLIB` contract all
//! gate on `OutputType::is_executable`), so forcing `Execute` makes the
//! executable shape fire unchanged.
//!
//! Gate matrix:
//! * the default keeps the pre-M120 shape (`MH_EXECUTE`, `__PAGEZERO`
//!   first, `LC_MAIN` present, no `LC_ID_DYLIB`);
//! * the explicit `-executable` decision carries the same executable
//!   shape (the byte-identity lock — the decision never moves the bytes,
//!   every pre-knob link byte-identical);
//! * the layout re-check refuses an `LC_ID_DYLIB` install name beside the
//!   override (an executable's identity is `LC_MAIN`, never an install
//!   name — the contract the verifier's read-side executable gate mirrors);
//! * the relocatable refusal — the object's filetype is the input's,
//!   verbatim (the layout re-check and `link_reloc` back the driver
//!   surface);
//! * the ladder replay rides the decision (the M81 pattern — config, not
//!   a product).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_cached, link_reloc};
use pgr_core::propagate::section_digests;
use pgr_core::resolve_reuse::ResolveReuseSeed;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::MH_EXECUTE;
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};

/// One object: `_main` in a `__text` body — the minimal executable corpus
/// (the entry symbol the `LC_MAIN` command names).
fn exec_corpus(name: &str) -> ObjectBuilder {
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

fn exec_cfg(tweak: impl FnOnce(&mut LinkConfig)) -> LinkConfig {
    let mut c = LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    tweak(&mut c);
    c
}

/// The executable contract the layout carries: `MH_EXECUTE`, `__PAGEZERO`
/// first, `LC_MAIN` present, no `LC_ID_DYLIB` (the read-side shape the
/// verifier's executable gate mirrors).
struct ExecShape {
    filetype: u32,
    pagezero_first: bool,
    has_main: bool,
    has_id_dylib: bool,
}

fn exec_shape(layout: &pgr_core::Layout) -> ExecShape {
    let bytes = &layout.header_bytes;
    let hdr = MachHeader64::parse(bytes).expect("the header parses");
    let mut it = LoadCommandIter::new(bytes, MachHeader64::SIZE, hdr.ncmds, hdr.sizeofcmds)
        .expect("the load-command iter builds");
    let mut pagezero_first = false;
    let mut has_main = false;
    let mut has_id_dylib = false;
    let mut first_segment = true;
    while let Ok(Some(cmd)) = it.next_command() {
        match cmd.kind {
            LoadCommandKind::Segment64 => {
                if first_segment {
                    // segment_command_64: segname at offset 8 (16 bytes,
                    // null-terminated).
                    let name = cmd
                        .bytes
                        .get(8..24)
                        .map(|b| {
                            String::from_utf8_lossy(b)
                                .trim_end_matches('\0')
                                .to_string()
                        })
                        .unwrap_or_default();
                    pagezero_first = name == "__PAGEZERO";
                    first_segment = false;
                }
            }
            LoadCommandKind::Main => has_main = true,
            LoadCommandKind::IdDylib => has_id_dylib = true,
            _ => {}
        }
    }
    ExecShape {
        filetype: hdr.filetype,
        pagezero_first,
        has_main,
        has_id_dylib,
    }
}

#[test]
fn the_default_keeps_the_pre_m120_shape() {
    // The pre-M120 shape: the default `Execute` filetype carries the
    // executable contract — `MH_EXECUTE`, `__PAGEZERO` first, `LC_MAIN`
    // present, no `LC_ID_DYLIB` (every pre-knob link byte-identical).
    let builders = vec![exec_corpus("a.o")];
    let layout = link(&inputs(&builders), &[], &exec_cfg(|_| ()))
        .expect("the default executable links")
        .layout;
    let shape = exec_shape(&layout);
    assert_eq!(shape.filetype, MH_EXECUTE, "the default is MH_EXECUTE");
    assert!(shape.pagezero_first, "the default carries __PAGEZERO first");
    assert!(shape.has_main, "the default carries LC_MAIN");
    assert!(
        !shape.has_id_dylib,
        "the default carries no LC_ID_DYLIB (an executable's identity is LC_MAIN)"
    );
}

#[test]
fn the_executable_decision_carries_the_same_shape() {
    // The explicit `-executable` decision carries the same executable
    // shape the default carries — the decision never moves the bytes
    // (the override forces `OutputType::Execute`, which is the default;
    // every pre-knob link byte-identical).
    let builders = vec![exec_corpus("a.o")];
    let explicit = link(&inputs(&builders), &[], &exec_cfg(|c| c.executable = true))
        .expect("the explicit executable links")
        .layout;
    let shape = exec_shape(&explicit);
    assert_eq!(shape.filetype, MH_EXECUTE, "the override is MH_EXECUTE");
    assert!(
        shape.pagezero_first,
        "the override carries __PAGEZERO first"
    );
    assert!(shape.has_main, "the override carries LC_MAIN");
    assert!(!shape.has_id_dylib, "the override carries no LC_ID_DYLIB");
}

#[test]
fn the_byte_identity_lock() {
    // An executable corpus links byte-identical under the default and an
    // explicit `-executable` (the decision is the explicit override, never
    // a shape change — the filetype byte at the head carries `Execute`
    // either way, every pre-knob link byte-identical).
    let builders = vec![exec_corpus("a.o")];
    let default =
        link(&inputs(&builders), &[], &exec_cfg(|_| ())).expect("the default executable links");
    let explicit = link(&inputs(&builders), &[], &exec_cfg(|c| c.executable = true))
        .expect("the explicit executable links");
    assert_eq!(
        default.layout.header_bytes, explicit.layout.header_bytes,
        "the default and explicit -executable link byte-identical"
    );
}

#[test]
fn the_executable_decision_refuses_an_install_name() {
    // An executable's identity is `LC_MAIN`, never `LC_ID_DYLIB` — the
    // emit never writes the command for a non-dylib, and the layout
    // re-check refuses an explicit `-install_name` beside the override so
    // the conflict names itself rather than silently dropping the install
    // name (the M48 dylib-only re-check shape, one filetype over).
    let builders = vec![exec_corpus("a.o")];
    let err = link(
        &inputs(&builders),
        &[],
        &exec_cfg(|c| {
            c.executable = true;
            c.install_name = Some("@rpath/libpgr.dylib".into());
        }),
    )
    .expect_err("the install name refuses beside the override");
    let text = err.to_string();
    assert!(
        text.contains("-executable") && text.contains("LC_ID_DYLIB"),
        "the refusal names the override and the LC_ID_DYLIB contract: {text}"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob_in_link_reloc() {
    // The object's filetype is the input's, verbatim — `-executable`
    // forces an `MH_EXECUTE` output but `link_reloc` is the `-r` path
    // whose `MH_OBJECT` preserves the input's shape (the M104/M105/M117
    // pattern; the layout re-check backs this in `layout`).
    let builders = vec![exec_corpus("a.o")];
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        executable: true,
        ..LinkConfig::default()
    };
    let err = link_reloc(&inputs(&builders), &[], &cfg, Parallelism::Serial)
        .expect_err("the relocatable output refuses the override");
    let text = err.to_string();
    assert!(
        text.contains("-executable") && text.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {text}"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob_in_layout() {
    // The layout's own re-check: no library caller plans the shape either
    // (the M104/M105/M117 refusal shape).
    let builders = vec![exec_corpus("a.o")];
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        executable: true,
        ..LinkConfig::default()
    };
    let err = link(&inputs(&builders), &[], &cfg).expect_err("the layout re-check refuses");
    let text = err.to_string();
    assert!(
        text.contains("-executable") && text.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {text}"
    );
}

#[test]
fn the_ladder_replay_rides_the_decision() {
    // The M81 pattern: the decision is config, not a product — the
    // resolve-reuse relink re-plans the same executable shape the cold
    // walk plans (the layout reads the filetype, both lanes reach it).
    let builders = vec![exec_corpus("a.o")];
    let ins = inputs(&builders);
    let recording = link_cached(
        &ins,
        &[],
        &exec_cfg(|c| {
            c.record_resolution = true;
            c.executable = true;
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
        &exec_cfg(|c| {
            c.resolve_reuse = Some(ResolveReuseSeed {
                snapshot,
                digests: section_digests(&recording.objects),
            });
            c.executable = true;
        }),
        Parallelism::Serial,
        None,
    )
    .expect("the seeded relink runs");
    assert_eq!(
        recording.layout.header_bytes, replayed.layout.header_bytes,
        "the replay plans the same executable shape (the M81 parity)"
    );
    let replay_shape = exec_shape(&replayed.layout);
    assert_eq!(
        replay_shape.filetype, MH_EXECUTE,
        "the replay carries the MH_EXECUTE shape (config, not a product)"
    );
    assert!(
        replay_shape.has_main && !replay_shape.has_id_dylib,
        "the replay carries the executable contract"
    );
}

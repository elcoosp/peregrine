//! The driver-side pipeline: Pass 0 (inputs) → Pass 1 (parse & intern) →
//! Pass 2 (resolve) → Pass 3 (layout). The returned [`Layout`] is the plan
//! Pass 4/5 (`pgr-emit`) turn into bytes.
//!
//! M4 (architecture doc §10.3 row M4): Pass 1 parses in parallel —
//! **LPT-scheduled** (longest input first, perf doc §4.1) on the shared
//! compute pool ([`crate::pool`]) — with giant objects split across threads
//! (symbol decode runs in deterministic index chunks). [`Parallelism::Serial`]
//! forces the M1–M3 single-threaded shape; both paths produce identical
//! layouts (determinism policy §4.3) and the equality is gated in tests.

use crate::LinkError;
use crate::ids::{FileId, StringId};
use crate::interner::Interner;
use crate::layout::{Layout, LinkConfig, layout};
use crate::object::InputObject;
use crate::pool;
use crate::resolve::Resolution;
use rayon::prelude::*;

/// Pass 1 scheduling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Parallelism {
    /// Use the shared compute pool: LPT-ordered parse, giant objects split
    /// across threads, parallel interner sort (the M4 default).
    #[default]
    Auto,
    /// Force the M1–M3 single-threaded pass bodies (reference path for the
    /// determinism gates and benches).
    Serial,
}

impl Parallelism {
    /// True when the parallel pass bodies should run.
    #[must_use]
    pub const fn is_parallel(self) -> bool {
        matches!(self, Self::Auto)
    }
}

/// One link input: a file name and its bytes (Pass 0 mapped them).
#[derive(Debug, Clone)]
pub struct LinkInput {
    /// File name (diagnostics only).
    pub name: String,
    /// Raw bytes of a relocatable arm64 object.
    pub bytes: Vec<u8>,
}

/// The full Pass 1–3 product: the emit plan plus the parsed input arena
/// (Pass 4 needs the input bytes for the section copies).
#[derive(Debug)]
pub struct LinkResult {
    /// The layout plan (Pass 3).
    pub layout: Layout,
    /// Parsed input objects (Pass 1 arenas; Pass 4 copies from these).
    pub objects: Vec<InputObject>,
    /// The interner (name diagnostics for driver-side checks).
    pub interner: Interner,
}

/// Runs Passes 1–3 over the inputs, producing the emit plan (M4 default:
/// parallel Pass 1 — see [`link_with`] for the serial reference path).
///
/// # Errors
/// [`LinkError`] on malformed inputs, unresolvable/duplicate symbols, or
/// layout contract violations.
pub fn link(inputs: &[LinkInput], cfg: &LinkConfig) -> Result<LinkResult, LinkError> {
    link_with(inputs, cfg, Parallelism::Auto)
}

/// Runs Passes 1–3 with an explicit scheduling policy.
///
/// # Errors
/// [`LinkError`] on malformed inputs, unresolvable/duplicate symbols, or
/// layout contract violations.
pub fn link_with(
    inputs: &[LinkInput],
    cfg: &LinkConfig,
    parallel: Parallelism,
) -> Result<LinkResult, LinkError> {
    // ---- Pass 1: parse & collect names for the interner --------------------
    let mut objects = parse_inputs(inputs, parallel)?;
    let mut names: Vec<Vec<u8>> = Vec::new();
    for obj in &mut objects {
        names.append(&mut obj.take_symbol_names());
    }
    // Dylib export names join the interner batch *after* the object symbol
    // stream, so the object id slices stay stable (M2 two-level namespace).
    let dylib_export_count: usize = cfg.dylibs.iter().map(|d| d.exports.len()).sum();
    let mut export_names: Vec<Vec<u8>> = Vec::with_capacity(dylib_export_count);
    for d in &cfg.dylibs {
        export_names.extend(d.exports.iter().cloned());
    }
    names.extend(export_names.iter().cloned());
    // `__mh_execute_header` is always interned so the layout pass can emit
    // the executable's header symbol (ld64/lld convention).
    names.push(b"__mh_execute_header".to_vec());
    let header_symbol_slot = 1usize;

    let (interner, ids) = Interner::build_with(&names, parallel.is_parallel());
    let mut cursor = 0usize;
    for obj in &mut objects {
        let take = obj.symbols.len();
        if cursor + take > ids.len() {
            return Err(LinkError::Internal {
                message: "interner table shorter than the symbol stream".into(),
            });
        }
        obj.finish(&ids[cursor..cursor + take])?;
        cursor += take;
    }
    let export_ids: Vec<StringId> = ids[cursor..cursor + dylib_export_count].to_vec();
    let _ = header_symbol_slot;

    // ---- Pass 2: resolution --------------------------------------------------
    let mut res = Resolution::default();
    res.install(&objects)?;
    res.install_dylibs(&cfg.dylibs, &export_ids);
    res.require_all_resolved(&interner, &objects, cfg.undefined_policy)?;

    // ---- Pass 3: layout -------------------------------------------------------
    let layout = layout(&objects, &res, &interner, cfg)?;
    Ok(LinkResult {
        layout,
        objects,
        interner,
    })
}

/// Pass 1 over the input files. `Auto` schedules **LPT** (longest input
/// first — perf doc §4.1) on the shared pool; the results land at their
/// command-line indices either way, and errors surface in command-line
/// order, so the schedule never changes the outcome.
fn parse_inputs(
    inputs: &[LinkInput],
    parallel: Parallelism,
) -> Result<Vec<InputObject>, LinkError> {
    let mut objects: Vec<Option<InputObject>> = (0..inputs.len()).map(|_| None).collect();
    if parallel.is_parallel() && inputs.len() > 1 {
        // LPT: biggest file first so the pool tail is filled by small files.
        let mut order: Vec<usize> = (0..inputs.len()).collect();
        order.sort_by(|&a, &b| {
            inputs[b]
                .bytes
                .len()
                .cmp(&inputs[a].bytes.len())
                .then(a.cmp(&b))
        });
        let parsed: Vec<Result<InputObject, LinkError>> = pool::compute_pool().install(|| {
            order
                .par_iter()
                .map(|&i| {
                    InputObject::parse(FileId(i as u32), &inputs[i].name, inputs[i].bytes.clone())
                })
                .collect()
        });
        for (slot, obj) in order.iter().zip(parsed) {
            objects[*slot] = Some(obj?);
        }
    } else {
        for (i, input) in inputs.iter().enumerate() {
            objects[i] = Some(InputObject::parse(
                FileId(i as u32),
                &input.name,
                input.bytes.clone(),
            )?);
        }
    }
    Ok(objects.into_iter().map(Option::unwrap).collect())
}

#[cfg(test)]
mod tests {
    use super::{LinkConfig, LinkInput, link};
    use crate::LinkError;
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

    /// hello.o: _main calls _greet (BL), references _msg (ADRP+ADD).
    fn hello_main() -> ObjectBuilder {
        // adrp x0, _msg@page
        let mut text: Vec<u8> = 0x9000_0000u32.to_le_bytes().to_vec();
        text.extend_from_slice(&0x9100_0000u32.to_le_bytes()); // add x0, x0, #msg@pageoff
        text.extend_from_slice(&0x9400_0000u32.to_le_bytes()); // bl _greet
        text.extend_from_slice(&0x5280_0000u32.to_le_bytes()); // mov w0, #0
        text.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // ret
        let mut b = ObjectBuilder::new("hello.o");
        let sect = b.add_section(ObjectSection::text(
            "__text",
            text,
            vec![
                ObjectReloc::addend(0).at(0),
                ObjectReloc::page21(1).at(0),
                ObjectReloc::addend(0).at(4),
                ObjectReloc::pageoff12(1).at(4),
                ObjectReloc::branch26(2).at(8),
            ],
        ));
        b.add_section(ObjectSection::cstring("hello, peregrine\n"));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Defined {
            name: "_msg".into(),
            section_index: 1,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_greet".into(),
            weak_ref: false,
        });
        b
    }

    /// greet.o: _greet body + __data pointer to _main (chained rebase).
    fn greet() -> ObjectBuilder {
        let mut b = ObjectBuilder::new("greet.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![
                0x91, 0x00, 0x00, 0x00, // add x0, x0, #0 (placeholder imm12)
                0xC0, 0x03, 0x5F, 0xD6, // ret
            ],
            vec![],
        ));
        let data = b.add_section(ObjectSection::data(
            "__data",
            vec![0u8; 8],
            vec![ObjectReloc::unsigned(0).at(0)],
        ));
        let _ = data;
        b.add_symbol(ObjectSymbol::Defined {
            name: "_greet".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main_ptr".into(),
            section_index: 1,
            value: 0,
            weak: false,
        });
        b
    }

    #[test]
    fn hello_world_layout_converges() {
        let main = hello_main().build().unwrap();
        let greet = greet().build().unwrap();
        let cfg = LinkConfig {
            ident: "hello".into(),
            ..LinkConfig::default()
        };
        let layout = link(
            &[
                LinkInput {
                    name: "hello.o".into(),
                    bytes: main,
                },
                LinkInput {
                    name: "greet.o".into(),
                    bytes: greet,
                },
            ],
            &cfg,
        );
        let layout = match layout {
            Ok(l) => l.layout,
            Err(e) => panic!("link failed: {e:?}"),
        };

        // Segments: five, canonical order, constant delta.
        assert_eq!(layout.segments.len(), 5);
        let names: Vec<&str> = layout.segments.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "__PAGEZERO",
                "__TEXT",
                "__DATA_CONST",
                "__DATA",
                "__LINKEDIT"
            ]
        );
        for seg in &layout.segments[1..] {
            assert_eq!(seg.vmaddr - seg.fileoff, 0x1_0000_0000, "{}", seg.name);
            assert_eq!(seg.fileoff % 0x4000, 0, "{} fileoff", seg.name);
            assert_eq!(seg.vmaddr % 0x4000, 0, "{} vmaddr", seg.name);
        }
        // Entry at _main (first piece of __text): entryoff == the __text
        // file offset (right after the header page region).
        let text_file_off = layout
            .sections
            .iter()
            .find(|s| s.name == "__text")
            .map(|s| s.file_off)
            .unwrap_or(u64::MAX);
        assert_eq!(layout.entryoff, text_file_off);
        // One fixup slot: greet.o's __data pointer to _main.
        assert_eq!(layout.fixups.slot_count, 1);
        // __chain_starts mirror: one head.
        assert_eq!(layout.fixups.chain_starts.len(), 12);
        // File size: signature last.
        assert_eq!(
            layout.linkedit.sig_off + layout.linkedit.sig_size,
            layout.file_size
        );
    }

    /// hello.o alone: _greet is never defined.
    fn hello_main_only() -> ObjectBuilder {
        let text: Vec<u8> = [
            0x9000_0000u32, // adrp x0, _msg@page
            0x9100_0000u32, // add x0, x0, #msg@pageoff
            0x9400_0000u32, // bl _greet
            0x5280_0000u32, // mov w0, #0
            0xD65F_03C0u32, // ret
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
        let mut b = ObjectBuilder::new("hello.o");
        let sect = b.add_section(ObjectSection::text(
            "__text",
            text,
            vec![ObjectReloc::branch26(1).at(8)],
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_greet".into(),
            weak_ref: false,
        });
        b
    }

    #[test]
    fn undefined_symbol_errors() {
        let main = hello_main_only().build().unwrap();
        let cfg = LinkConfig::default();
        let err = link(
            &[LinkInput {
                name: "hello.o".into(),
                bytes: main,
            }],
            &cfg,
        )
        .unwrap_err();
        assert!(matches!(err, LinkError::Symbol { .. }));
        assert!(err.to_string().contains("_greet"), "{err}");
    }

    #[test]
    fn missing_entry_errors() {
        let bytes = greet().build().unwrap();
        let cfg = LinkConfig::default();
        let err = link(
            &[LinkInput {
                name: "greet.o".into(),
                bytes,
            }],
            &cfg,
        )
        .unwrap_err();
        assert!(err.to_string().contains("_main"), "{err}");
    }
}

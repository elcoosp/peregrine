//! The M1 driver-side pipeline: Pass 0 (inputs) → Pass 1 (parse & intern) →
//! Pass 2 (resolve) → Pass 3 (layout). The returned [`Layout`] is the plan
//! Pass 4/5 (`pgr-emit`) turn into bytes.
//!
//! Single-threaded at M1 by design ("passes 0–5 minimal", TDD §12); the
//! per-pass structures are shaped so the M4 parallel bodies swap in without
//! changing the plan types.

use crate::LinkError;
use crate::ids::FileId;
use crate::interner::Interner;
use crate::layout::{Layout, LinkConfig, layout};
use crate::object::InputObject;
use crate::resolve::Resolution;

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
}

/// Runs Passes 1–3 over the inputs, producing the emit plan.
///
/// # Errors
/// [`LinkError`] on malformed inputs, unresolvable/duplicate symbols, or
/// layout contract violations.
pub fn link(inputs: &[LinkInput], cfg: &LinkConfig) -> Result<LinkResult, LinkError> {
    // ---- Pass 1: parse & collect names for the interner --------------------
    let mut objects: Vec<InputObject> = Vec::with_capacity(inputs.len());
    let mut names: Vec<Vec<u8>> = Vec::new();
    for (i, input) in inputs.iter().enumerate() {
        let mut obj = InputObject::parse(FileId(i as u32), &input.name, input.bytes.clone())?;
        names.append(&mut obj.take_symbol_names());
        objects.push(obj);
    }
    let (interner, ids) = Interner::build(&names);
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

    // ---- Pass 2: resolution --------------------------------------------------
    let mut res = Resolution::default();
    res.install(&objects)?;
    res.require_all_resolved(&interner, &objects)?;

    // ---- Pass 3: layout -------------------------------------------------------
    let layout = layout(&objects, &res, &interner, cfg)?;
    Ok(LinkResult { layout, objects })
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

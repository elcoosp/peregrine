//! The link map (M11 rung 2): a structured, human-readable report of the
//! placed image — segments, their sections, and the symbols each section
//! carries. The data is the layout plan's own (`Layout::segments`,
//! `Layout::sections`, `Layout::symbols`) re-grouped for consumption; the
//! builder is a pure function of the plan, and the render is
//! deterministic (segments in plan order, symbols by address then name —
//! no hash iteration order reaches the text).
//!
//! The map is the build-system-facing seam ld64's `-map` serves: "what
//! landed where, and why is my binary this size". It reads the *plan* —
//! the same plan the fused emit writes — so the report and the bytes
//! cannot disagree.

use crate::interner::Interner;
use crate::layout::Layout;

/// One symbol row in the map: its name, output address, and visibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSymbol {
    /// The symbol name.
    pub name: String,
    /// Output vaddr (the `n_value` the symtab carries).
    pub value: u64,
    /// True when the symbol is exported (the dysymtab extdef surface).
    pub external: bool,
}

/// One section row: the placed section and the symbols that landed in it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MapSection {
    /// Output section name (`__text`...).
    pub name: String,
    /// Owning output segment name.
    pub seg_name: String,
    /// Absolute vaddr of the section start.
    pub vm_addr: u64,
    /// Section size in bytes.
    pub size: u64,
    /// File offset (0 for zero-fill sections).
    pub file_off: u64,
    /// True when the section is zero-fill (no file bytes).
    pub zerofill: bool,
    /// The section's symbols, by address then name.
    pub symbols: Vec<MapSymbol>,
}

/// One segment row: the `LC_SEGMENT_64` summary and its sections.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MapSegment {
    /// Segment name.
    pub name: String,
    /// vaddr start.
    pub vmaddr: u64,
    /// Virtual size (covers zero-fill tails).
    pub vmsize: u64,
    /// File offset.
    pub fileoff: u64,
    /// File-backed size.
    pub filesize: u64,
    /// The segment's sections, in plan order.
    pub sections: Vec<MapSection>,
}

/// The placed image's map: segments → sections → symbols. Build with
/// [`build_link_map`], render with [`LinkMap::render`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkMap {
    /// The signature identifier the image carries.
    pub ident: String,
    /// The Mach-O file type word (`MH_EXECUTE`/`MH_DYLIB`/`MH_BUNDLE`).
    pub filetype: u32,
    /// Total file size.
    pub file_size: u64,
    /// The segments, in plan order.
    pub segments: Vec<MapSegment>,
}

/// Builds the link map from a finished plan. Pure: the same layout and
/// interner render the same map, byte for byte.
#[must_use]
pub fn build_link_map(layout: &Layout, interner: &Interner) -> LinkMap {
    // Section rows in plan order; `n_sect` indexes this vec (1-based).
    let mut sections: Vec<MapSection> = layout
        .sections
        .iter()
        .map(|s| MapSection {
            name: s.name.clone(),
            seg_name: s.seg_name.clone(),
            vm_addr: s.vm_addr,
            size: s.size,
            file_off: s.file_off,
            zerofill: s.zerofill,
            symbols: Vec::new(),
        })
        .collect();
    for sym in &layout.symbols {
        if sym.n_sect == 0 {
            // Absolute symbols name no section; the map is a placement
            // report, so they ride no row (the symtab still carries them).
            continue;
        }
        let Some(row) = sections.get_mut(usize::from(sym.n_sect - 1)) else {
            continue;
        };
        row.symbols.push(MapSymbol {
            name: interner.name(sym.name),
            value: sym.value,
            external: sym.external,
        });
    }
    for row in &mut sections {
        // Deterministic rows: by address, then name (the plan's own order
        // is canonical already; the explicit sort keeps the render stable
        // against future symtab-order changes).
        row.symbols
            .sort_by(|a, b| a.value.cmp(&b.value).then_with(|| a.name.cmp(&b.name)));
    }
    let segments = layout
        .segments
        .iter()
        .map(|seg| MapSegment {
            name: seg.name.clone(),
            vmaddr: seg.vmaddr,
            vmsize: seg.vmsize,
            fileoff: seg.fileoff,
            filesize: seg.filesize,
            sections: seg
                .sections
                .iter()
                .filter_map(|si| sections.get(*si).cloned())
                .collect(),
        })
        .collect();
    LinkMap {
        ident: layout.ident.clone(),
        filetype: layout.filetype,
        file_size: layout.file_size,
        segments,
    }
}

impl LinkMap {
    /// Renders the map as deterministic text: one segment per block, one
    /// section per line, symbols indented under their section. The
    /// format is ld64-map-shaped (`#`-prefixed header, columns) — a
    /// build system can diff two maps line by line.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(4096);
        s.push_str("# Peregrine link map\n");
        let _ = writeln!(s, "# ident: {}", self.ident);
        let _ = writeln!(s, "# filetype: {:#x}", self.filetype);
        let _ = writeln!(s, "# file size: {}", self.file_size);
        for seg in &self.segments {
            let _ = writeln!(
                s,
                "segment {:<16} vm 0x{:08x}..0x{:08x}  file 0x{:08x}..0x{:08x}",
                seg.name,
                seg.vmaddr,
                seg.vmaddr + seg.vmsize,
                seg.fileoff,
                seg.fileoff + seg.filesize,
            );
            for sect in &seg.sections {
                let _ = writeln!(
                    s,
                    "  section {:<12} vm 0x{:08x}  size 0x{:x}  file 0x{:x}{}",
                    sect.name,
                    sect.vm_addr,
                    sect.size,
                    sect.file_off,
                    if sect.zerofill { " (zerofill)" } else { "" },
                );
                for sym in &sect.symbols {
                    let _ = writeln!(
                        s,
                        "    0x{:08x}  {}{}",
                        sym.value,
                        sym.name,
                        if sym.external { "" } else { "  [local]" },
                    );
                }
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixups::FixupPlan;
    use crate::interner::Interner;
    use crate::layout::{LinkeditPlan, OutputSymbol, PlacedSection, SegmentPlan};

    /// A tiny hand-built plan: one segment, two sections, three symbols.
    fn tiny_layout() -> Layout {
        // The symbol names are interned with the same name table the
        // test's builder uses (id order: `_gamma` then `_alpha`).
        let (_, ids) = Interner::build(&[b"_gamma".to_vec(), b"_alpha".to_vec()]);
        let sect = PlacedSection {
            name: "__text".into(),
            seg_name: "__TEXT".into(),
            flags: 0,
            align_log2: 2,
            vm_addr: 0x1000,
            size: 16,
            file_off: 0x1000,
            zerofill: false,
            pieces: Vec::new(),
        };
        let data = PlacedSection {
            name: "__data".into(),
            seg_name: "__DATA".into(),
            flags: 0,
            align_log2: 3,
            vm_addr: 0x2000,
            size: 8,
            file_off: 0x2000,
            zerofill: false,
            pieces: Vec::new(),
        };
        Layout {
            ident: "tiny".into(),
            filetype: 2,
            order_unmatched: Vec::new(),
            image_base: 0,
            segments: vec![SegmentPlan {
                name: "__TEXT".into(),
                vmaddr: 0x1000,
                vmsize: 16,
                fileoff: 0x1000,
                filesize: 16,
                maxprot: 5,
                initprot: 5,
                sections: vec![0],
            }],
            sections: vec![sect, data],
            linkedit: LinkeditPlan::default(),
            header_bytes: Vec::new(),
            entryoff_at: 0,
            file_size: 0x2010,
            entryoff: 0,
            text_vmsize: 16,
            symbols: vec![
                OutputSymbol {
                    name: ids[1],
                    n_type: 0x0f,
                    n_sect: 1,
                    n_desc: 0,
                    value: 0x1004,
                    external: true,
                },
                OutputSymbol {
                    name: ids[0],
                    n_type: 0x0f,
                    n_sect: 1,
                    n_desc: 0,
                    value: 0x1000,
                    external: true,
                },
            ],
            trie: Vec::new(),
            func_starts: Vec::new(),
            strtab: Vec::new(),
            str_offsets: Vec::new(),
            indirect_syms: Vec::new(),
            fixups: FixupPlan {
                payload: Vec::new(),
                payload_off: 0,
                slot_words: Vec::new(),
                chain_starts: Vec::new(),
                slot_count: 0,
                imports: Vec::new(),
                import_names: Vec::new(),
                has_weak_binds: false,
                stable_keys: Vec::new(),
            },
            dyld_info: None,
            runs: Vec::new(),
            resolved: Vec::new(),
        }
    }

    #[test]
    fn the_map_groups_symbols_by_address_then_name() {
        let layout = tiny_layout();
        let (interner, _) = Interner::build(&[b"_gamma".to_vec(), b"_alpha".to_vec()]);
        let map = build_link_map(&layout, &interner);
        let text = &map.segments[0].sections[0];
        let names: Vec<&str> = text.symbols.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            ["_gamma", "_alpha"],
            "address order, not table order"
        );
    }

    #[test]
    fn the_render_is_deterministic_and_ld64_shaped() {
        let layout = tiny_layout();
        let (interner, _) = Interner::build(&[b"_gamma".to_vec(), b"_alpha".to_vec()]);
        let a = build_link_map(&layout, &interner).render();
        let b = build_link_map(&layout, &interner).render();
        assert_eq!(a, b, "the same plan renders byte-identical maps");
        assert!(a.starts_with("# Peregrine link map"));
        assert!(a.contains("segment __TEXT"));
        assert!(a.contains("section __text"));
        assert!(a.contains("0x00001000  _gamma"));
        assert!(a.contains("0x00001004  _alpha"));
    }
}

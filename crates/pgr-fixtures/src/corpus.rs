//! The parameterized corpus generator (the `pgr_fixtures::corpus` seam).
//!
//! The benchmark corpora the plan names (the performance architecture doc
//! §9.2 "Baselines to run on every rig … commit the harness") are mostly
//! inputs nobody can commit — ripgrep, a Chromium-class debug link. What a
//! benchmark rig *can* commit is the **shape**: object counts, payload
//! sizes, symbol counts, archive-member counts. This module turns those
//! axes into deterministic byte-identical corpora — the "parameterized
//! corpus generator behind an `xtask` for nightly shape sweeps" the
//! benchmarks ledger names as a follow-up ([`docs/BENCHMARKS.md`]).
//!
//! The presets name the §9.2 corpus-table rows the tree can synthesize:
//!
//! | Preset | §9.2 row | Defaults |
//! |---|---|---|
//! | [`CorpusPreset::ManyTiny`] | "`hello` and a 50-link 'many tiny links' script" | 50 objects × 4 KiB × 8 syms |
//! | [`CorpusPreset::LargeDebug`] | the parse-heavy large-debug shape | 16 objects × 4 KiB × 4 096 syms |
//! | [`CorpusPreset::ArchiveHeavy`] | "Archive-heavy (hundreds of static libs, most members unused)" | 8 direct objects + 300 unreferenced members |
//! | [`CorpusPreset::SingleGiant`] | "Single giant object (unity/LTO-style)" | 1 object × 4 MiB × 64 syms |
//! | [`CorpusPreset::ByteTouching`] | the parse-rate caveat's byte-touching shape | 1 object × 16 MiB × 2 syms |
//!
//! Every object carries one cross-object `BRANCH26` (except the
//! one-object presets, where no cross-object work exists to express) and
//! its own filler payload (distinct per index — no accidental ICF
//! folding), so a generated corpus exercises the same Pass 0–3 work the
//! recorded corpora do. The generation is pure and deterministic: the
//! same spec builds identical bytes every run (the BENCHMARKS corpora
//! contract), and [`write_corpus`] — the face the `xtask` corpus command
//! drives — writes them under zero-padded, command-line-ordered names.
//!
//! [`docs/BENCHMARKS.md`]: https://github.com/elcoosp/peregrine/blob/main/docs/BENCHMARKS.md

use std::fmt::Write as _;
use std::path::Path;

use crate::BuildError;
use crate::archive::ArchiveBuilder;
use crate::filler;
use crate::object::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// The corpus-table shape a preset names, with the knobs the parameters
/// override — the effective numbers [`CorpusSpec::resolved`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    /// Direct objects the corpus writes (`obj_NNNN.o`).
    pub objects: usize,
    /// `__text` payload per object, in KiB.
    pub text_kib: usize,
    /// Extra defined symbols per object (besides the entry definition and
    /// the cross-object reference).
    pub symbols_per_object: usize,
    /// Archive members the one `libcorpus.a` carries (0 = no archive).
    pub archive_members: usize,
    /// `__text` payload per archive member, in KiB.
    pub member_text_kib: usize,
}

/// The corpus shape each preset synthesizes (the §9.2 rows).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CorpusPreset {
    /// "`hello` and a 50-link 'many tiny links' script" — many small
    /// objects, one cross-object branch each.
    #[default]
    ManyTiny,
    /// The parse-heavy large-debug shape — the BENCHMARKS recorded corpus
    /// (16 objects × 4 096 symbols × 4 KiB).
    LargeDebug,
    /// "Archive-heavy (hundreds of static libs, most members unused)" — a
    /// member archive the direct inputs do not reference.
    ArchiveHeavy,
    /// "Single giant object (unity/LTO-style)" — one object whose payload
    /// carries the file.
    SingleGiant,
    /// The parse-rate caveat's byte-touching shape (docs/BENCHMARKS.md,
    /// "Conditions & harness": "`summarize` walks _metadata tables_, not
    /// section payload — these are metadata-walk rates, not DRAM
    /// streaming") — one object whose section payload carries the file,
    /// the corpus the byte-touching parse bench prices.
    ByteTouching,
}

impl CorpusPreset {
    /// The preset's default shape, as the `cargo xtask corpus` help prints it.
    #[must_use]
    pub fn shape(self) -> Shape {
        match self {
            Self::ManyTiny => Shape {
                objects: 50,
                text_kib: 4,
                symbols_per_object: 8,
                archive_members: 0,
                member_text_kib: 4,
            },
            Self::LargeDebug => Shape {
                objects: 16,
                text_kib: 4,
                symbols_per_object: 4_096,
                archive_members: 0,
                member_text_kib: 4,
            },
            Self::ArchiveHeavy => Shape {
                objects: 8,
                text_kib: 4,
                symbols_per_object: 8,
                archive_members: 300,
                member_text_kib: 4,
            },
            Self::SingleGiant => Shape {
                objects: 1,
                text_kib: 4_096,
                symbols_per_object: 64,
                archive_members: 0,
                member_text_kib: 4,
            },
            Self::ByteTouching => Shape {
                objects: 1,
                text_kib: 16 * 1024,
                symbols_per_object: 2,
                archive_members: 0,
                member_text_kib: 4,
            },
        }
    }

    /// The preset's kebab-case name — the `--preset` value the `xtask`
    /// corpus command reads.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::ManyTiny => "many-tiny",
            Self::LargeDebug => "large-debug",
            Self::ArchiveHeavy => "archive-heavy",
            Self::SingleGiant => "single-giant",
            Self::ByteTouching => "byte-touching",
        }
    }

    /// Parses a `--preset` value (the kebab-case [`CorpusPreset::name`]).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "many-tiny" => Some(Self::ManyTiny),
            "large-debug" => Some(Self::LargeDebug),
            "archive-heavy" => Some(Self::ArchiveHeavy),
            "single-giant" => Some(Self::SingleGiant),
            "byte-touching" => Some(Self::ByteTouching),
            _ => None,
        }
    }
}

/// One generated corpus file, as the manifest lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusFileInfo {
    /// The file's name inside the corpus directory (`obj_0001.o`,
    /// `libcorpus.a`).
    pub name: String,
    /// The file's size in bytes.
    pub bytes: u64,
}

impl CorpusManifest {
    /// Renders the manifest as the deterministic text the `xtask` corpus
    /// command prints: one line per file (name, bytes) in write order,
    /// then the totals. Integer arithmetic only — no float rounding rides
    /// the report.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for f in &self.files {
            let _ = writeln!(out, "{:>16}  {}", f.name, f.bytes);
        }
        let _ = writeln!(
            out,
            "{:>16}  {} objects, {} archive members, {} symbols",
            "totals", self.objects, self.archive_members, self.symbols
        );
        let _ = writeln!(
            out,
            "{:>16}  {} payload bytes, {} metadata bytes, {} file bytes",
            "", self.payload_bytes, self.metadata_bytes, self.file_bytes
        );
        out
    }
}

/// The totals one generated corpus carries — the numbers a shape sweep
/// records beside its measurements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusManifest {
    /// Direct objects the corpus carries.
    pub objects: usize,
    /// Archive members the one `libcorpus.a` carries (0 = no archive).
    pub archive_members: usize,
    /// Symbol-table entries across every object (direct objects and
    /// members).
    pub symbols: usize,
    /// Section payload bytes the corpus carries (the `__text` fill).
    pub payload_bytes: u64,
    /// Metadata bytes the corpus carries (headers, load commands, symbol
    /// tables, relocations, archive bookkeeping).
    pub metadata_bytes: u64,
    /// Total bytes the corpus writes (`payload + metadata`).
    pub file_bytes: u64,
    /// The generated files, in write order (objects in command-line
    /// order, the archive last).
    pub files: Vec<CorpusFileInfo>,
}

/// A generated corpus: the files (name + bytes, in write order) and the
/// totals they sum to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusContents {
    /// The generated files, in write order.
    pub files: Vec<(String, Vec<u8>)>,
    /// The totals the files sum to.
    pub manifest: CorpusManifest,
}

/// A parameterized corpus: a [`CorpusPreset`] shape plus per-axis
/// overrides (`None` keeps the preset's default). Building one is pure
/// and deterministic — the same spec builds identical bytes every run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusSpec {
    /// The shape the corpus names (the §9.2 row).
    pub preset: CorpusPreset,
    /// Direct objects (overrides the preset's count).
    pub objects: Option<usize>,
    /// `__text` payload per object, in KiB (overrides the preset's).
    pub text_kib: Option<usize>,
    /// Extra defined symbols per object (overrides the preset's).
    pub symbols_per_object: Option<usize>,
    /// Archive members (overrides the preset's; 0 writes no archive).
    pub archive_members: Option<usize>,
    /// `__text` payload per archive member, in KiB (overrides the
    /// preset's).
    pub member_text_kib: Option<usize>,
}

impl CorpusSpec {
    /// The preset's shape, unoverridden.
    #[must_use]
    pub fn new(preset: CorpusPreset) -> Self {
        Self {
            preset,
            objects: None,
            text_kib: None,
            symbols_per_object: None,
            archive_members: None,
            member_text_kib: None,
        }
    }

    /// The effective shape: the preset's defaults with the overrides
    /// applied — the shape the generator actually builds.
    #[must_use]
    pub fn resolved(&self) -> Shape {
        let base = self.preset.shape();
        Shape {
            objects: self.objects.unwrap_or(base.objects),
            text_kib: self.text_kib.unwrap_or(base.text_kib),
            symbols_per_object: self.symbols_per_object.unwrap_or(base.symbols_per_object),
            archive_members: self.archive_members.unwrap_or(base.archive_members),
            member_text_kib: self.member_text_kib.unwrap_or(base.member_text_kib),
        }
    }
}

/// One synthetic corpus object: `_main` (the first object) or `_fn_<i>`
/// defined over the filler `__text`, the shape's extra defined symbols,
/// and (multi-object corpora) one `BRANCH26` to the next object's
/// definition — the cross-object resolution the pipeline's Passes 2–3
/// price.
fn corpus_object(index: usize, shape: &Shape, total_objects: usize) -> Result<Vec<u8>, BuildError> {
    let name = format!("obj_{:04}.o", index + 1);
    let mut b = ObjectBuilder::new(&name);
    let text_len = shape.text_kib * 1024;
    let text = b.add_section(ObjectSection::text(
        "__text",
        // Distinct fill per object: no two objects share bytes, so no
        // accidental ICF folding rides the corpus.
        filler(index as u64 + 1, text_len),
        Vec::new(),
    ));
    let entry_sym = if index == 0 {
        "_main".to_string()
    } else {
        format!("_fn_{index}")
    };
    b.add_symbol(ObjectSymbol::Defined {
        name: entry_sym,
        section_index: text,
        value: 0,
        weak: false,
    });
    for j in 0..shape.symbols_per_object {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_sym_{index}_{j}"),
            section_index: text,
            value: ((j * 4) % text_len.max(1)) as u64,
            weak: false,
        });
    }
    if total_objects > 1 {
        // One cross-object reference per object: the next object's
        // definition (the last object's wraps to the entry, keeping every
        // undefined resolvable regardless of the count the sweep picks).
        let next = (index + 1) % total_objects;
        let next_name = if next == 0 {
            "_main".to_string()
        } else {
            format!("_fn_{next}")
        };
        let undef = b.add_symbol(ObjectSymbol::Undefined {
            name: next_name,
            weak_ref: false,
        });
        // The builder refuses counts past the Mach-O symbol limit, so the
        // index fits the reloc's `r_symbolnum` word.
        b.section_mut(text)
            .relocs
            .push(ObjectReloc::branch26(undef as u32).at(0));
    }
    b.build()
}

/// One synthetic archive member: `_mem_<j>` defined over its own filler
/// `__text`, nothing else — most members stay unreferenced (the §9.2
/// archive-heavy shape).
fn corpus_member(index: usize, shape: &Shape) -> Result<Vec<u8>, BuildError> {
    let mut b = ObjectBuilder::new(&format!("mem_{:04}.o", index + 1));
    let text = b.add_section(ObjectSection::text(
        "__text",
        filler(10_000 + index as u64 + 1, shape.member_text_kib * 1024),
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_mem_{index}"),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build()
}

/// Builds the corpus the spec names: the direct objects in
/// command-line order, the member archive (when the shape carries one)
/// after them. Pure and deterministic — no clocks, no entropy, no I/O.
///
/// # Errors
/// A [`BuildError`] when a spec exceeds the object builder's limits
/// (section/symbol counts) — the sweep's own guardrail.
pub fn build_corpus(spec: &CorpusSpec) -> Result<CorpusContents, BuildError> {
    let shape = spec.resolved();
    let mut files: Vec<(String, Vec<u8>)> = Vec::with_capacity(shape.objects + 1);
    let mut symbols = 0usize;
    let mut payload_bytes = 0u64;
    for i in 0..shape.objects {
        let bytes = corpus_object(i, &shape, shape.objects)?;
        // Entry definition + extras, plus the cross-object reference in a
        // multi-object corpus.
        symbols += shape.symbols_per_object + if shape.objects > 1 { 2 } else { 1 };
        payload_bytes += shape.text_kib as u64 * 1024;
        files.push((format!("obj_{:04}.o", i + 1), bytes));
    }
    if shape.archive_members > 0 {
        let mut arch = ArchiveBuilder::new("libcorpus.a");
        for j in 0..shape.archive_members {
            arch.add_member(&format!("mem_{:04}.o", j + 1), corpus_member(j, &shape)?);
            symbols += 1;
            payload_bytes += shape.member_text_kib as u64 * 1024;
        }
        files.push(("libcorpus.a".to_string(), arch.build()));
    }
    let file_infos: Vec<CorpusFileInfo> = files
        .iter()
        .map(|(name, bytes)| CorpusFileInfo {
            name: name.clone(),
            bytes: bytes.len() as u64,
        })
        .collect();
    let file_bytes: u64 = file_infos.iter().map(|f| f.bytes).sum();
    let metadata_bytes = file_bytes.saturating_sub(payload_bytes);
    let manifest = CorpusManifest {
        objects: shape.objects,
        archive_members: shape.archive_members,
        symbols,
        payload_bytes,
        metadata_bytes,
        file_bytes,
        files: file_infos,
    };
    Ok(CorpusContents { files, manifest })
}

/// Anything the corpus write face refuses.
#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    /// The generator refused the spec (the object builder's limits).
    #[error(transparent)]
    Build(#[from] BuildError),
    /// The corpus directory could not be created or written.
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Writes the corpus the spec names into `dir` (created when missing) —
/// the face the `xtask` corpus command drives. Returns the manifest the
/// command prints.
///
/// # Errors
/// A [`CorpusError::Build`] when the generator refuses the spec, an
/// [`CorpusError::Io`] when the directory or a file cannot be written.
pub fn write_corpus(spec: &CorpusSpec, dir: &Path) -> Result<CorpusManifest, CorpusError> {
    let contents = build_corpus(spec)?;
    std::fs::create_dir_all(dir)?;
    for (name, bytes) in &contents.files {
        std::fs::write(dir.join(name), bytes)?;
    }
    Ok(contents.manifest)
}

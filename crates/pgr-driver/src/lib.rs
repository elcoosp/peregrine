//! The `pgr` driver library (TDD §5 Pass 0 + the driver loop): option
//! parsing, input mapping, and the Pass 1–5 orchestration.
//!
//! The M1 loop is deliberately boring: map inputs → parse/intern/resolve/
//! layout (`pgr-core`) → emit bytes (`pgr-emit`) → flush. Determinism is an
//! end-to-end property (§4.3): linking the same corpus twice in separate
//! calls produces byte-identical images, asserted in the integration tests.

pub mod opts;

use pgr_core::LinkInput;
use pgr_emit::write_image;
use std::path::Path;

/// The driver outcome: bytes written, plus the plan for diagnostics.
#[derive(Debug)]
pub struct LinkOutcome {
    /// The output file path.
    pub output: String,
    /// Total image size in bytes.
    pub file_size: u64,
    /// Entry offset within `__TEXT`.
    pub entryoff: u64,
    /// Chained-fixup slots packed.
    pub fixup_slots: usize,
}

/// A driver failure: options, I/O, or link errors.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// Command-line problems (exit code 2).
    #[error(transparent)]
    Opts(#[from] opts::OptsError),
    /// Link pipeline failures (exit code 1).
    #[error(transparent)]
    Link(#[from] pgr_core::LinkError),
    /// Emit/flush failures (exit code 1).
    #[error(transparent)]
    Emit(#[from] pgr_emit::EmitError),
    /// An input file could not be read.
    #[error("reading {path}: {source}")]
    Io {
        /// The failing path.
        path: String,
        /// The OS error.
        source: std::io::Error,
    },
}

/// The in-memory link product: image bytes plus the plan facts.
#[derive(Debug)]
pub struct ImageAndPlan {
    /// The complete output image.
    pub image: Vec<u8>,
    /// Entry offset within `__TEXT`.
    pub entryoff: u64,
    /// Chained-fixup slots packed.
    pub fixup_slots: usize,
}

/// Links the option inputs into image bytes (no filesystem). Exposed for
/// tests, benchmarks and the verifier pipeline.
///
/// # Errors
/// [`DriverError`] on option, link or emit failures.
pub fn link_to_image(opts: &opts::Options) -> Result<ImageAndPlan, DriverError> {
    let mut inputs = Vec::with_capacity(opts.inputs.len());
    for (i, path) in opts.inputs.iter().enumerate() {
        let bytes = std::fs::read(path).map_err(|source| DriverError::Io {
            path: path.clone(),
            source,
        })?;
        inputs.push(LinkInput {
            name: format!("{path} (input {i})"),
            bytes,
        });
    }
    let result = pgr_core::link(&inputs, &opts.config)?;
    let image = pgr_emit::build_image(&result.layout, &result.objects)?;
    Ok(ImageAndPlan {
        entryoff: result.layout.entryoff,
        fixup_slots: result.layout.fixups.slot_count,
        image,
    })
}

/// Links `inputs` into image bytes (no filesystem). Kept for callers that
/// only need the bytes.
///
/// # Errors
/// [`DriverError`] on option, link or emit failures.
pub fn link_to_bytes(opts: &opts::Options) -> Result<Vec<u8>, DriverError> {
    Ok(link_to_image(opts)?.image)
}

/// Runs the full driver: link and write the output file.
///
/// # Errors
/// [`DriverError`] on option, link, emit or filesystem failures.
pub fn run(opts: &opts::Options) -> Result<LinkOutcome, DriverError> {
    let linked = link_to_image(opts)?;
    write_image(&linked.image, Path::new(&opts.output))?;
    Ok(LinkOutcome {
        output: opts.output.clone(),
        file_size: linked.image.len() as u64,
        entryoff: linked.entryoff,
        fixup_slots: linked.fixup_slots,
    })
}

/// The one-line version banner.
#[must_use]
pub fn version_line() -> String {
    format!("pgr (Peregrine) {}", env!("CARGO_PKG_VERSION"))
}

/// The `--help` text (the M1 flag surface).
#[must_use]
pub fn usage() -> String {
    let mut s = String::with_capacity(1024);
    s.push_str(&version_line());
    s.push_str("\n\nPeregrine: ultra-fast Mach-O linker for arm64-apple-darwin.\n\n");
    s.push_str("M1 — static hello-world: direct .o inputs, -static semantics,\n");
    s.push_str("LC_MAIN/LC_SYMTAB/LC_DYSYMTAB, rebase-only chained fixups,\n");
    s.push_str("__chain_starts, ad-hoc signature, deterministic layout.\n\n");
    s.push_str("Usage: pgr [options] <object files>\n\n");
    s.push_str("Options:\n");
    s.push_str("  -o <path>                    output file (required)\n");
    s.push_str("  -arch arm64                  target architecture (M1: arm64 only)\n");
    s.push_str("  -platform_version <p> <min> <sdk>   build version (macos only)\n");
    s.push_str("  -e <symbol>                  entry symbol (default _main)\n");
    s.push_str("  -static                      static semantics (M1 default)\n");
    s.push_str("  -fixup_chains | -no_fixup_chains    chained fixups (default on)\n");
    s.push_str("  -adhoc | -no_adhoc           ad-hoc code signature (default on)\n");
    s.push_str("  -headerpad <n>               reserve header space (advisory at M1)\n");
    s.push_str("  -segalign <n>                0x1000 or 0x4000 (default 0x4000)\n");
    s.push_str("  -help, -h                    this text\n");
    s.push_str("  -version, -V                 version banner\n\n");
    s.push_str("Dylibs (-dylib), archives, .tbd inputs and -dead_strip arrive at\n");
    s.push_str("M2/M3/M5 (TDD §12 roadmap).\n");
    s
}

#[cfg(test)]
mod tests {
    use super::{link_to_bytes, usage, version_line};
    use crate::opts::Options;
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

    /// hello.o: _main ADRP+ADD loads _msg, BL _greet, returns 0.
    fn hello_main() -> Vec<u8> {
        let text: Vec<u8> = [
            0x9000_0000u32, // adrp x0, _msg@page
            0x9100_0000u32, // add x0, x0, #_msg@pageoff
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
        b.build().unwrap()
    }

    /// greet.o: _greet + a __data pointer to _main + a subtractor pair +
    /// a common symbol.
    fn greet() -> Vec<u8> {
        let mut b = ObjectBuilder::new("greet.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![
                0x91, 0x00, 0x00, 0x00, // add x0, x0, #0 (immediate kept)
                0xC0, 0x03, 0x5F, 0xD6, // ret
            ],
            vec![],
        ));
        // __data: [ptr to _greet][subtractor result ptr_a - ptr_b]
        let _data = b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
        let greet_sym = b.add_symbol(ObjectSymbol::Defined {
            name: "_greet".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        let ptr_a = b.add_symbol(ObjectSymbol::Defined {
            name: "_ptr_a".into(),
            section_index: _data,
            value: 8,
            weak: false,
        });
        let ptr_b = b.add_symbol(ObjectSymbol::Defined {
            name: "_ptr_b".into(),
            section_index: _data,
            value: 8,
            weak: false,
        });
        b.section_mut(_data).relocs = vec![
            ObjectReloc::unsigned(greet_sym as u32).at(0),
            ObjectReloc::subtractor(ptr_a as u32).at(8),
            ObjectReloc::unsigned(ptr_b as u32).at(8),
        ];
        b.add_symbol(ObjectSymbol::Common {
            name: "_common_buf".into(),
            size: 64,
            align_log2: 4,
        });
        b.build().unwrap()
    }

    fn opts_for(files: &[(&str, &[u8])]) -> (Options, Vec<std::path::PathBuf>) {
        let dir = std::env::temp_dir().join("pgr_driver_tests");
        std::fs::create_dir_all(&dir).unwrap();
        let mut opts = Options::default();
        let mut paths = Vec::new();
        for (i, (name, bytes)) in files.iter().enumerate() {
            let p = dir.join(format!("obj_{i}_{name}"));
            std::fs::write(&p, bytes).unwrap();
            paths.push(p.clone());
            opts.inputs.push(p.display().to_string());
        }
        opts.output = dir.join("out.bin").display().to_string();
        opts.config.ident = "peregrine-test".into();
        (opts, paths)
    }

    #[test]
    fn link_is_deterministic() {
        let (o1, _) = opts_for(&[("hello.o", &hello_main()), ("greet.o", &greet())]);
        let (o2, _) = opts_for(&[("hello.o", &hello_main()), ("greet.o", &greet())]);
        let a = link_to_bytes(&o1).unwrap();
        let b = link_to_bytes(&o2).unwrap();
        assert_eq!(a, b, "double link must be byte-identical (TDD §4.3)");
        // At least one 16 KiB __TEXT page plus __LINKEDIT.
        assert!(a.len() > 0x4000, "image size {}", a.len());
    }

    #[test]
    fn banner_and_usage_are_shaped() {
        assert!(version_line().starts_with("pgr (Peregrine)"));
        assert!(usage().contains("-o <path>"));
        assert!(usage().contains("M1"));
    }
}

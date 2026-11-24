//! The parameterized corpus generator's consumer example: builds every
//! preset (the §9.2 corpus-table shapes) into a temp directory, prints
//! the manifest the shape sweeps record, and walks one generated object
//! back through the structural parser.
//!
//! Usage: `cargo run -p pgr-fixtures --example corpus_shapes`

use std::path::PathBuf;

use pgr_fixtures::{CorpusPreset, CorpusSpec, build_corpus, write_corpus};

fn main() {
    let dir = std::env::temp_dir().join("pgr-corpus-shapes");
    let _ = std::fs::remove_dir_all(&dir);

    for preset in [
        CorpusPreset::ManyTiny,
        CorpusPreset::LargeDebug,
        CorpusPreset::ArchiveHeavy,
        CorpusPreset::SingleGiant,
    ] {
        // The parameterized face: each preset's shape with one knob moved
        // (the sweep's own move) — the many-tiny preset doubles its object
        // count so the manifest shows the parameters riding.
        let mut spec = CorpusSpec::new(preset);
        if preset == CorpusPreset::ManyTiny {
            spec.objects = Some(8);
        }
        let out = dir.join(preset.name());
        let manifest =
            write_corpus(&spec, &out).unwrap_or_else(|e| panic!("{} writes: {e}", preset.name()));
        print!(
            "== {} ({}) ==\n{}",
            preset.name(),
            out.display(),
            manifest.render()
        );

        // The same shape built in memory: the bytes the sweeps consume.
        let contents = build_corpus(&spec).expect("the corpus builds");
        let (name, bytes) = &contents.files[0];
        let summary =
            pgr_format::summarize(bytes).unwrap_or_else(|e| panic!("{name} summarizes: {e}"));
        println!(
            "{name}: {} sections, {} symbols, {} relocs, {} bytes",
            summary.sections, summary.symbols, summary.relocations, summary.file_size
        );
    }

    let _ = std::fs::remove_dir_all(PathBuf::from(&dir));
    println!(
        "(the corpora lived under std::env::temp_dir — fixture bytes never ride the repo tree)"
    );
}

//! The byte-touching parse's consumer example: builds the byte-touching
//! corpus object (one object whose section payload carries the file —
//! the shape the parse-rate caveat names), walks it through the
//! structural parser, and prints the shape the `parse_bytes` bench
//! prices beside the metadata control.
//!
//! Usage: `cargo run -p pgr-format --example byte_touch_parse`

use pgr_fixtures::{CorpusPreset, CorpusSpec, build_corpus};

fn main() {
    let byte_touching = CorpusSpec::new(CorpusPreset::ByteTouching);
    let contents = build_corpus(&byte_touching).expect("the byte-touching corpus builds");
    let (name, bytes) = &contents.files[0];
    let summary = pgr_format::summarize(bytes).expect("the object summarizes");
    println!("== {name} (the byte-touching shape) ==");
    println!(
        "file {} bytes: {} sections, {} symbols, {} relocations — payload {} bytes ({}% of the file)",
        summary.file_size,
        summary.sections,
        summary.symbols,
        summary.relocations,
        contents.manifest.payload_bytes,
        contents.manifest.payload_bytes * 100 / contents.manifest.file_bytes
    );
    println!(
        "the metadata tables the parser walks: {} bytes",
        contents.manifest.metadata_bytes
    );
    println!(
        "docs/BENCHMARKS.md: \"summarize walks metadata tables, not section payload — these are \
         metadata-walk rates, not DRAM streaming. The byte-touching parse starts well below \
         them.\" The parse_bytes bench prices that rate; the corpus the generator produces is \
         the payload-dominated shape the Throughput::Bytes denominates by."
    );

    let control = CorpusSpec {
        objects: Some(1),
        ..CorpusSpec::new(CorpusPreset::ManyTiny)
    };
    let control = build_corpus(&control).expect("the control corpus builds");
    let (name, bytes) = &control.files[0];
    let summary = pgr_format::summarize(bytes).expect("the object summarizes");
    println!("== {name} (the metadata control) ==");
    println!(
        "file {} bytes: {} sections, {} symbols, {} relocations — payload {} bytes",
        summary.file_size,
        summary.sections,
        summary.symbols,
        summary.relocations,
        control.manifest.payload_bytes
    );
}

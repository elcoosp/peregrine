//! The M13 record inspector, runnable — and `pgr-emit`'s first consumer
//! example: link a small image, record it (the `-incremental` sidecar's
//! exact bytes), then read the sidecar back as a summary. The shape a
//! build system uses to answer "what did the last incremental link
//! record, and will the next relink patch?" without relinking.
//!
//! ```sh
//! cargo run -p pgr-emit --example record_summary
//! ```
//!
//! `PGR_TRACING=1` installs a subscriber so the read refusal's `debug`
//! event shows when the probe bytes are deliberately corrupted (the
//! workspace's inert-until-subscriber convention):
//!
//! ```sh
//! PGR_TRACING=1 cargo run -p pgr-emit --example record_summary
//! ```

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link_cached};
use pgr_emit::build_image_fused;
use pgr_emit::incremental::{LinkRecord, RecordSummary, read_summary};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// hello.o: `_main` returns, a `__cstring`, no imports — a static
/// executable the pipeline links clean with no library inputs.
fn hello_o() -> ObjectBuilder {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0x00u8, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_section(ObjectSection::cstring("hello, record\n"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b
}

fn main() {
    // The read refusals name their layer on the tracing seam — inert
    // until a subscriber installs (the binaries do it under their
    // debug envs).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    // The link: a full pass, then the record (what `pgr -incremental`
    // writes next to the output on every link).
    let cfg = LinkConfig {
        ident: "record-summary-example".into(),
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let inputs = vec![LinkInput {
        name: "hello.o".into(),
        bytes: hello_o().build().expect("the fixture builds"),
    }];
    let result = link_cached(&inputs, &[], &cfg, Parallelism::Auto, None)
        .expect("the static link links clean");
    let image = build_image_fused(&result.layout, &result.objects).expect("the image emits");
    let record = LinkRecord::record(&result.layout, &result.objects, &image, None)
        .expect("the finished image records");

    // The sidecar's exact bytes, in a scratch dir.
    let dir = std::env::temp_dir().join("pgr_emit_record_example");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir creates");
    let sidecar = dir.join("app.pgr-inc");
    std::fs::write(&sidecar, record.encode()).expect("the sidecar writes");
    println!(
        "sidecar: {} ({} bytes)\n",
        sidecar.display(),
        record.encode().len()
    );

    // The read surface: the summary names the record's shape.
    let summary = read_summary(&sidecar).expect("the sidecar reads");
    print!("{}", summary.render());

    // The in-memory path renders the same text (one shape, one writer).
    assert_eq!(
        RecordSummary::of(&record).render(),
        summary.render(),
        "the disk read and the in-memory record agree"
    );

    // A corrupt sidecar is a diagnosis, never a panic: flip a payload
    // byte and the checksum layer names it (the fix rides the message).
    let mut corrupt = record.encode();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    let corrupt_path = dir.join("corrupt.pgr-inc");
    std::fs::write(&corrupt_path, &corrupt).expect("the probe writes");
    match read_summary(&corrupt_path) {
        Ok(_) => unreachable!("the corrupt sidecar cannot read"),
        Err(e) => println!("\ncorrupt probe: {e}"),
    }
}

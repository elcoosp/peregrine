//! The trace consumer example (M61): one small executable link —
//! `main.o` binding `_greet` from `libgreet.a` — asked *when did each
//! pass run, and where did the idle gaps fall?* The M54 observation
//! seam's phase events are collected into the Chrome-trace timeline
//! (the roadmap §9.4 toolbox's face) and written beside the link under
//! `--trace`; the file is read back through the core seam's strict
//! reader (`pgr_core::trace::parse_trace_json`) to show the round trip,
//! and the observed link plans the identical layout the unobserved one
//! does (the parity gate is the seam's own contract).
//!
//! Run: `cargo run -p pgr-driver --example trace_timeline`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use; the written
//! `trace.json` opens in `chrome://tracing` or the Perfetto UI).

use pgr_driver::opts;
use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// `main.o`: `_main` + a data pointer at `_greet`.
fn main_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let greet = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(greet as u32).at(0)],
    ));
    b.build().expect("the fixture object builds")
}

/// `greet.o`: `_greet` — the pulled member.
fn greet_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Writes the corpus and links it through the driver's own parse + run
/// pair with `extra` argv.
fn run(dir: &std::path::Path, out: &str, extra: &[&str]) {
    std::fs::write(dir.join("main.o"), main_object()).unwrap();
    let mut a = ArchiveBuilder::new("libgreet.a");
    a.add_member("greet.o", greet_object());
    std::fs::write(dir.join("libgreet.a"), a.build()).unwrap();
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join(out).as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    argv.push(dir.join("main.o").as_os_str().to_os_string());
    argv.push(dir.join("libgreet.a").as_os_str().to_os_string());
    let parsed = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&parsed).expect("the link runs");
}

/// Links the corpus through the library face with the collector
/// subscribed (the build-system consumer that wants the events *as
/// data*), writes the timeline, reads it back through the strict reader
/// and prints the span table — the same run the driver's `--trace`
/// writes, minus the driver.
fn library_face(dir: &std::path::Path) {
    use pgr_core::layout::LinkConfig;
    use pgr_core::link::link_observed;

    let archive_bytes =
        pgr_format::parse_archive(&std::fs::read(dir.join("libgreet.a")).expect("reads"))
            .expect("the archive parses");
    let archives = vec![pgr_core::link::LinkArchive {
        name: dir.join("libgreet.a").display().to_string(),
        bytes: std::fs::read(dir.join("libgreet.a")).expect("reads"),
        index: archive_bytes
            .index
            .iter()
            .map(|e| (e.name.clone().into_bytes(), e.member))
            .collect(),
        members: archive_bytes
            .members
            .iter()
            .map(|m| pgr_core::link::LinkArchiveMember {
                name: m.name.clone(),
                offset: m.offset,
                size: m.size,
            })
            .collect(),
        all_load: false,
    }];
    let inputs = vec![pgr_core::link::LinkInput {
        name: "main.o".to_string(),
        bytes: std::fs::read(dir.join("main.o")).expect("reads"),
    }];
    let mut collector = pgr_core::trace::TraceCollector::new();
    let result = link_observed(
        &inputs,
        &archives,
        &LinkConfig::default(),
        pgr_core::Parallelism::Auto,
        None,
        &mut collector,
    )
    .expect("the corpus links");
    let image =
        pgr_emit::build_image_fused(&result.layout, &result.objects).expect("the plan emits");
    let timeline = collector.finish();
    let json = timeline.render();
    let trace_path = dir.join("trace.json");
    std::fs::write(&trace_path, &json).expect("the timeline writes");
    println!(
        "== the library face: the timeline ({} bytes planned) ==",
        image.len()
    );
    let parsed = pgr_core::trace::parse_trace_json(&json).expect("the timeline round-trips");
    assert_eq!(parsed, timeline, "the reader restored the writer's data");
    println!(
        "-- {} -- ({}, {} lanes)",
        trace_path.display(),
        json.len(),
        parsed.lanes.len(),
    );
    for span in &parsed.spans {
        println!(
            "  {:<12} ts={:>6} µs dur={:>6} µs",
            span.phase.as_str(),
            span.start_us,
            span.dur_us,
        );
    }
    for note in &parsed.notes {
        println!(
            "  {:<12} ts={:>6} µs — {}",
            note.kind, note.at_us, note.reason,
        );
    }
    println!("(the file opens in chrome://tracing or the Perfetto UI)");
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_trace_timeline_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // 1. The driver face: `--trace` writes the timeline beside the link
    //    (the same face the CLI ships); the file reads back through the
    //    strict reader — the round trip the parity gate rides.
    println!("== the driver face: --trace ==");
    let driver_trace_path = dir.join("driver_trace.json");
    let driver_trace_arg = driver_trace_path.display().to_string();
    run(&dir, "hello_traced", &["--trace", &driver_trace_arg]);
    let driver_trace = std::fs::read_to_string(&driver_trace_path).expect("reads");
    println!(
        "-- {} -- ({} bytes, parses: {})",
        driver_trace_path.display(),
        driver_trace.len(),
        pgr_core::trace::parse_trace_json(&driver_trace).is_ok(),
    );

    // 2. The library face: the collector subscribes to the observed
    //    pipeline, the timeline renders, the strict reader restores it.
    library_face(&dir);
}

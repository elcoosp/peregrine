//! The time-report consumer example (M58): one small executable link —
//! `main.o` binding `_greet` from `libgreet.a` — asked *how long did each
//! pass take?* The M54 observation seam's phase events are collected into
//! the per-pass wall table (the TDD's instrumentation face) and the JSON
//! interchange line (the M55/M56/M57 escape rules) — both faces read the
//! one observed run, and the observed link plans the identical layout the
//! unobserved one does (the parity gate is the seam's own contract).
//!
//! Run: `cargo run -p pgr-driver --example time_report`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

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
fn run(dir: &std::path::Path, out: &str, extra: &[&str]) -> pgr_driver::LinkOutcome {
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
    pgr_driver::run(&parsed).expect("the link runs")
}

/// Links the corpus through the library face with the collector
/// subscribed (the build-system consumer that wants the events *as
/// data*), then renders both faces over the one observed run — the
/// same link the driver's `--time` prints, minus the driver.
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
    let started = std::time::Instant::now();
    let mut collector = pgr_core::TimeCollector::default();
    let result = link_observed(
        &inputs,
        &archives,
        &LinkConfig::default(),
        pgr_core::Parallelism::Auto,
        None,
        &mut collector,
    )
    .expect("the corpus links");
    let emit_started = std::time::Instant::now();
    let image =
        pgr_emit::build_image_fused(&result.layout, &result.objects).expect("the plan emits");
    let emit = Some(emit_started.elapsed());
    let total = Some(started.elapsed());
    println!(
        "== the library face: TimeReport ({} bytes planned) ==",
        image.len()
    );
    let mut report = collector.report();
    report.emit = emit;
    report.total = total;
    print!("{}", report.render());
    println!("-- the interchange line --");
    println!("{}", report.render_json());
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_time_report_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // 1. The driver face: `--time` prints the table beside the link
    //    (the same face the CLI ships).
    println!("== the driver face: --time ==");
    run(&dir, "hello_timed", &["--time"]);

    // 2. The interchange face: `--time-json` prints the one-line JSON
    //    (the build-system face).
    println!("== the driver face: --time-json ==");
    run(&dir, "hello_timed_json", &["--time-json"]);

    // 3. The library face: the collector subscribes to the observed
    //    pipeline and the report renders both faces over the one run.
    library_face(&dir);
}

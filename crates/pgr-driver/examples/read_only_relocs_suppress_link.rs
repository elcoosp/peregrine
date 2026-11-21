//! M111 — the read-only-relocations policy face `suppress`:
//! `-read_only_relocs suppress` — the reloc rides silently — the identical image the warning face plans, nothing printed.
//! The target rides the `-segprot` decision the example makes: `__DATA`
//! mapped `rx`/`rx` drops `VM_PROT_WRITE` from the initial mapping.
//!
//! Run: `cargo run -p pgr-driver --example read_only_relocs_suppress_link`

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::ffi::OsString;

fn pointer_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let def = b.add_symbol(ObjectSymbol::Defined {
        name: "_table".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    let slot = b.sym_index(def);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    b.build().expect("the fixture object builds")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!(
        "pgr_read_only_relocs_suppress_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("the scratch dir creates");
    let obj_path = dir.join("hello.o");
    std::fs::write(&obj_path, pointer_object()).expect("the object writes");
    let argv: Vec<OsString> = vec![
        "-o".into(),
        dir.join("hello").to_string_lossy().into_owned().into(),
        "-read_only_relocs".into(),
        "suppress".into(),
        "-segprot".into(),
        "__DATA".into(),
        "rx".into(),
        "rx".into(),
        obj_path.to_string_lossy().into_owned().into(),
    ];
    let outcome = match opts::parse(&argv) {
        Ok(o) => pgr_driver::run(&o).map(|_| ()).map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    match outcome {
        Ok(()) => println!("face (suppress): linked — silent ride"),
        Err(err) => panic!("the suppress face must not refuse: {err}"),
    }

    println!("\nread_only_relocs_suppress_link: ok");
}

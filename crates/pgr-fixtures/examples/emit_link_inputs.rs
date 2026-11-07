//! Emits the link inputs the runtime-validation workflow (and humans) need:
//! a relocatable `hello_main.o` (ADRP/ADD → `_msg`, `BL _greet`, `ret`) and
//! a libSystem-shaped `.tbd` stub exporting `_printf`/`_strlen`, plus a
//! `greet.o` for dylib outputs. Deterministic bytes.
//!
//! Usage: `cargo run -p pgr-fixtures --example emit_link_inputs -- <dir>`

use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

fn main() {
    let dir = std::env::args()
        .nth(1)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("link-inputs"));
    std::fs::create_dir_all(&dir).expect("output dir");

    // hello_main.o
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
    let mut b = ObjectBuilder::new("hello_main.o");
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
    std::fs::write(dir.join("hello_main.o"), b.build().unwrap()).expect("write hello_main.o");

    // greet.o (defines _greet; used for the dylib half of the pair)
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0x91, 0x00, 0x00, 0x00, 0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    std::fs::write(dir.join("greet.o"), b.build().unwrap()).expect("write greet.o");

    // libSystem-shaped stub (for the dylib half's load command) and a
    // libgreet stub the executable binds `_greet` through.
    std::fs::write(
        dir.join("libSystem.tbd"),
        "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: /usr/lib/libSystem.B.dylib\ncurrent-version: 1.2.3\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _printf, _strlen ]\n...\n",
    )
    .expect("write libSystem.tbd");
    std::fs::write(
        dir.join("libgreet.tbd"),
        "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: /usr/lib/libgreet.dylib\ncurrent-version: 1.2.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _greet ]\n...\n",
    )
    .expect("write libgreet.tbd");

    println!(
        "wrote hello_main.o, greet.o, libSystem.tbd, libgreet.tbd into {}",
        dir.display()
    );
}

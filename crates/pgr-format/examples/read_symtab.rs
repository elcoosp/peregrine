//! A consumer's tour of `pgr-format`'s symbol table, runnable: parse a
//! Mach-O object and walk its `LC_SYMTAB` the way nm-like tooling would —
//! the [`pgr_format::SymtabCommand`] locating the nlist array, one
//! [`pgr_format::Nlist64`] per row (bounds-checked, typed errors), the
//! string table naming each symbol. Undefined rows are the references
//! the link resolves; defined external rows are the exports the trie and
//! symtab carry; stabs are the debug rows a symbol walk skips. The
//! format layer carries the raw format structs — the offsets are the
//! consumer's to honor, and every parse returns a typed, offset-tagged
//! [`pgr_format::FormatError`] instead of a panic.
//!
//! ```sh
//! cargo run -p pgr-format --example read_symtab -- path/to/object.o   # any 64-bit Mach-O
//! cargo run -p pgr-format --example read_symtab                       # builds one in-memory
//! ```

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, Nlist64, SymtabCommand};

/// The NUL-terminated name at `n_strx` (the offset the string table
/// names), or `None` when the row names nothing in bounds.
fn name_at(bytes: &[u8], st: &SymtabCommand, n_strx: u32) -> Option<String> {
    let start = st.stroff as usize + n_strx as usize;
    let end = st.stroff as usize + st.strsize as usize;
    let tail = bytes.get(start..end)?;
    let stop = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    std::str::from_utf8(&tail[..stop])
        .ok()
        .map(std::string::ToString::to_string)
}

fn main() {
    // The object under inspection: an argv path, or a fixture built in
    // memory (the same builder the test suite and the fuzz corpus use) —
    // `_main` references `_greet` and defines `_msg`, the shape a link
    // resolves: one undefined row, two defined rows.
    let bytes = if let Some(path) = std::env::args().nth(1) {
        std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
    } else {
        let mut b = ObjectBuilder::new("hello.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6], // ret
            vec![],
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Defined {
            name: "_msg".into(),
            section_index: text,
            value: 4,
            weak: false,
        });
        let _ = b.add_symbol(ObjectSymbol::Undefined {
            name: "_greet".into(),
            weak_ref: false,
        });
        b.build().expect("the fixture builds")
    };

    // The header locates the load-command walk; the symtab command rides
    // it. An image without symbols refuses the walk honestly — there is
    // nothing to name.
    let header = MachHeader64::parse(&bytes).expect("a 64-bit Mach-O");
    let mut it = LoadCommandIter::new(&bytes, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load-command region is well-formed");
    let st = loop {
        let Some(cmd) = it.next_command().expect("the next command parses") else {
            panic!("the image carries no LC_SYMTAB — nothing to walk");
        };
        if cmd.kind == LoadCommandKind::Symtab {
            break SymtabCommand::parse(cmd.bytes, 0).expect("the symtab command parses");
        }
    };
    println!(
        "{} symbols, {} bytes of string table at {:#x}",
        st.nsyms, st.strsize, st.stroff
    );

    // The nlist array: one bounds-checked parse per row (the format
    // layer's own contract — a truncated image refuses with the offset
    // named, it never panics), the string table naming each row.
    let mut undefined = 0usize;
    let mut defined = 0usize;
    for i in 0..st.nsyms {
        let off = st.symoff as usize + i as usize * 16;
        let sym: Nlist64 = pgr_format::cursor::pod_read_unaligned_at(&bytes, off)
            .unwrap_or_else(|e| panic!("symbol {i}: {e}"));
        let name = name_at(&bytes, &st, sym.n_strx).unwrap_or_default();
        let kind = if sym.is_stab() {
            "stab"
        } else if sym.is_undefined() {
            undefined += 1;
            "undefined"
        } else if sym.is_external() {
            defined += 1;
            "external"
        } else {
            "local"
        };
        println!(
            "  {kind:>9}  {name}  (n_type {:#04x}, n_sect {}, value {:#x})",
            sym.n_type, sym.n_sect, sym.n_value
        );
    }
    println!("{defined} defined, {undefined} undefined");
}

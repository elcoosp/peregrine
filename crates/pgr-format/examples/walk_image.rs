//! A consumer's tour of `pgr-format`, runnable: parse a Mach-O image and
//! walk it the way tooling would — header, load commands, segments and
//! sections, then the format-level summary ([`pgr_format::summarize`]).
//! Every parse is bounds-checked and returns a typed, offset-tagged
//! [`pgr_format::FormatError`] — parsers never panic on malformed input.
//!
//! ```sh
//! cargo run -p pgr-format --example walk_image -- path/to/image        # a linked image
//! cargo run -p pgr-format --example walk_image                          # builds one in-memory
//! ```

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SegmentCommand64, summarize};

fn main() {
    // The image under inspection: an argv path, or a fixture object built
    // in memory (the same builder the test suite and the fuzz corpus use).
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
            name: "_hello".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.build().expect("the fixture builds")
    };

    // The header: magic, and the load-command extent the walk consumes.
    // `parse` refuses anything that is not a 64-bit Mach-O.
    let header = MachHeader64::parse(&bytes).expect("a 64-bit Mach-O");
    println!(
        "magic {:#x}  ncmds {}  sizeofcmds {} bytes",
        header.magic, header.ncmds, header.sizeofcmds
    );

    // The load-command walk (zero-copy: every command borrows the image).
    let mut it = LoadCommandIter::new(&bytes, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load-command region is well-formed");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if cmd.kind == LoadCommandKind::Segment64 {
            let seg = SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            let nsects = match seg.sections(cmd.bytes, SegmentCommand64::SIZE) {
                Ok(sects) => sects.len(),
                Err(_) => 0,
            };
            println!(
                "LC_SEGMENT_64 {:<16} vmaddr {:#x} vmsize {:#x} {nsects} section(s)",
                seg.name().unwrap_or("?"),
                seg.vmaddr,
                seg.vmsize
            );
        } else {
            println!("{:?}", cmd.kind);
        }
    }

    // The format-level summary: the counts and payload flags tooling gates on.
    let summary = summarize(&bytes).expect("the image summarizes");
    println!(
        "summary: {} segment(s), {} section(s), {} symbol(s) ({} external), \
         {} reloc(s), chained fixups: {} ({} slot(s))",
        summary.segments,
        summary.sections,
        summary.symbols,
        summary.external_symbols,
        summary.relocations,
        summary.has_chained_fixups,
        summary.fixup_slots
    );
}

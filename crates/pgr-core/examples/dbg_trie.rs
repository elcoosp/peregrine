//! Debug example: build a tiny trie and parse it back.
use pgr_core::trie::{Export, ExportInfo, build};

fn reg(name: &'static str, address: u64) -> Export<'static> {
    Export {
        name: name.as_bytes(),
        info: ExportInfo::Regular { flags: 0, address },
    }
}

fn main() {
    let out = build(&mut vec![reg("_a", 1), reg("_b", 2), reg("_c", 3)], 0).unwrap();
    println!("built {} bytes", out.len());
    match pgr_format::trie::exports(&out) {
        Ok(v) => {
            for e in v {
                println!("{e:?}");
            }
        }
        Err(e) => println!("parse err: {e}"),
    }
}

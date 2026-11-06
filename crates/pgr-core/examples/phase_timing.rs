//! Phase-timing harness for the trie pipeline (sort vs build vs serialize).
use pgr_core::trie::{Export, ExportInfo};
use std::time::Instant;

fn main() {
    let n = 100_000usize;
    let owned: Vec<String> = (0..n)
        .map(|i| {
            if i % 4 == 0 {
                format!("_OBJC_CLASS_$_Peregrine{i:06}")
            } else {
                format!("_pgr_fn_{i:06}_body")
            }
        })
        .collect();
    for round in 0..3 {
        let exports: Vec<Export> = owned
            .iter()
            .map(|nm| Export {
                name: nm.as_bytes(),
                info: ExportInfo::Regular {
                    flags: 0,
                    address: 0,
                },
            })
            .collect();
        let t0 = Instant::now();
        let mut v = exports;
        let _ = pgr_core::trie::build(&mut v, 0).unwrap();
        let t1 = Instant::now();
        if round >= 1 {
            println!("build (sort+trie+serialize): {:?} for {n} exports", t1 - t0);
        }
    }
    // Sort alone (stable, borrowed names).
    let names: Vec<&str> = owned.iter().map(String::as_str).collect();
    for round in 0..3 {
        let mut v = names.clone();
        let t0 = Instant::now();
        v.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let t1 = Instant::now();
        if round >= 1 {
            println!("stable sort alone:            {:?}", t1 - t0);
        }
    }
    for round in 0..3 {
        let mut v: Vec<(u32, &str)> = names
            .iter()
            .enumerate()
            .map(|(i, s)| (i as u32, *s))
            .collect();
        let t0 = Instant::now();
        v.sort_unstable_by(|a, b| a.1.as_bytes().cmp(b.1.as_bytes()).then(a.0.cmp(&b.0)));
        let t1 = Instant::now();
        if round >= 1 {
            println!("unstable sort alone:          {:?}", t1 - t0);
        }
    }
}

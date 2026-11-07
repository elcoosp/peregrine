//! The `pgrd` binary end-to-end gates (M8): a real daemon process over the
//! real wire, exercised the way `pgr -resident` uses it.
//!
//! * start → handshake → link → **strict verifier pass** on the resident
//!   bytes → shutdown → clean exit;
//! * restart transparency: kill the daemon between links; the next link
//!   (fresh process, fresh session) still produces the identical bytes;
//! * link errors surface and the daemon keeps serving;
//! * the daemon idles out when no client arrives (§7.2).

use pgr_daemon::{DaemonClient, LinkJob};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn hello_main() -> Vec<u8> {
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
    let mut b = ObjectBuilder::new("hello.o");
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
    b.build().unwrap()
}

fn greet() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.section_mut(data).relocs = vec![ObjectReloc::unsigned(0).at(0)];
    b.build().unwrap()
}

fn job() -> LinkJob {
    let cfg = pgr_core::layout::LinkConfig {
        ident: "m8-pgrd-binary".into(),
        ..pgr_core::layout::LinkConfig::default()
    };
    LinkJob::build(
        &cfg,
        &[],
        &[
            pgr_core::LinkInput {
                name: "hello.o".into(),
                bytes: hello_main(),
            },
            pgr_core::LinkInput {
                name: "greet.o".into(),
                bytes: greet(),
            },
        ],
        &[],
    )
}

/// Spawns `pgrd --socket <sock> --idle-secs <n>` and waits for the socket.
/// Panics (and reaps the child) when the socket never opens.
fn spawn_daemon(sock: &std::path::Path, idle_secs: u64) -> Child {
    let child = Command::new(env!("CARGO_BIN_EXE_pgrd"))
        .arg("--socket")
        .arg(sock)
        .arg("--idle-secs")
        .arg(idle_secs.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn pgrd");
    for _ in 0..500 {
        if UnixStream::connect(sock).is_ok() {
            return child;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
    panic!("pgrd never opened {}", sock.display());
}

fn wait_socket_gone(sock: &std::path::Path) {
    for _ in 0..500 {
        if !sock.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn pgrd_serves_strict_verifiable_images_and_exits_cleanly() {
    let sock: PathBuf =
        std::env::temp_dir().join(format!("pgr-m8-pgrd-{}.sock", std::process::id()));
    let mut child = spawn_daemon(&sock, 30);

    let mut client = DaemonClient::connect(&sock).unwrap();
    let banner = client.hello().unwrap();
    assert!(!banner.is_empty(), "version banner: {banner}");
    let job = job();
    let image = client.link(&job).unwrap();
    assert!(!image.image.is_empty());

    // The §10.4 M8 gate's verifier half: the resident bytes pass the
    // strict checker.
    let report = pgr_verify::verify(
        &image.image,
        &pgr_verify::Options {
            strict_warnings: true,
            ..pgr_verify::Options::default()
        },
    );
    assert!(
        report.issues.is_empty(),
        "resident output failed strict verify: {:?}",
        report
            .issues
            .iter()
            .map(|i| i.code.as_str())
            .collect::<Vec<_>>()
    );

    // Warm relink: identical bytes, POI hits reported.
    let warm = client.link(&job).unwrap();
    assert_eq!(warm.image, image.image);
    assert!(warm.poi_hits >= 2, "warm link must report POI hits");

    // Shutdown semantics through the protocol.
    client.shutdown().unwrap();
    let _ = child.wait();
    wait_socket_gone(&sock);
    assert!(!sock.exists(), "pgrd must unlink its socket when it exits");
}

#[test]
fn a_killed_daemon_never_corrupts_a_relink() {
    let sock: PathBuf =
        std::env::temp_dir().join(format!("pgr-m8-kill-{}.sock", std::process::id()));
    let mut child = spawn_daemon(&sock, 30);
    let job = job();

    let mut client = DaemonClient::connect(&sock).unwrap();
    client.hello().unwrap();
    let first = client.link(&job).unwrap();
    drop(client);

    // SIGKILL mid-life: the client's next link sees a dead socket.
    child.kill().unwrap();
    let _ = child.wait();
    wait_socket_gone(&sock);

    // Fresh daemon (the driver's auto-start would spawn exactly this).
    let mut child2 = spawn_daemon(&sock, 30);
    let mut client2 = DaemonClient::connect(&sock).unwrap();
    client2.hello().unwrap();
    let second = client2.link(&job).unwrap();
    assert_eq!(
        second.image, first.image,
        "a daemon restart must not change a single output byte"
    );
    // The rebuilt session starts cold: nothing cached yet.
    assert_eq!(second.poi_hits, 0, "fresh session has nothing cached");
    client2.shutdown().unwrap();
    let _ = child2.wait();
}

#[test]
fn pgrd_reports_link_errors_and_keeps_serving() {
    let sock: PathBuf =
        std::env::temp_dir().join(format!("pgr-m8-err-{}.sock", std::process::id()));
    let mut child = spawn_daemon(&sock, 30);

    // A corpus with an unresolvable symbol: the daemon answers ERROR and
    // stays alive for the next client.
    let mut bad = ObjectBuilder::new("bad.o");
    let t = bad.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    bad.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: t,
        value: 0,
        weak: false,
    });
    bad.add_symbol(ObjectSymbol::Undefined {
        name: "_nowhere".into(),
        weak_ref: false,
    });
    let cfg = pgr_core::layout::LinkConfig {
        ident: "m8-pgrd-err".into(),
        ..pgr_core::layout::LinkConfig::default()
    };
    let bad_job = LinkJob::build(
        &cfg,
        &[],
        &[pgr_core::LinkInput {
            name: "bad.o".into(),
            bytes: bad.build().unwrap(),
        }],
        &[],
    );

    let mut client = DaemonClient::connect(&sock).unwrap();
    client.hello().unwrap();
    let err = client.link(&bad_job).unwrap_err();
    assert!(
        err.to_string().contains("_nowhere"),
        "the daemon must surface the link error: {err}"
    );

    // Still serving: a good link succeeds on the same daemon.
    let good = client.link(&job()).unwrap();
    assert!(!good.image.is_empty());
    client.shutdown().unwrap();
    let _ = child.wait();
}

#[test]
fn pgrd_idles_out_without_clients() {
    let sock: PathBuf =
        std::env::temp_dir().join(format!("pgr-m8-idle-{}.sock", std::process::id()));
    let mut child = spawn_daemon(&sock, 1);
    // No clients: the daemon exits after ~1 s of quiet and removes the
    // socket (§7.2 "It idles out after a timeout").
    std::thread::sleep(Duration::from_millis(1800));
    let exited = matches!(child.try_wait(), Ok(Some(_)));
    assert!(exited, "pgrd must exit when it idles out");
    wait_socket_gone(&sock);
    assert!(!sock.exists());
    assert!(
        UnixStream::connect(&sock).is_err(),
        "no daemon should answer after idle exit"
    );
}

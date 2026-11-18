//! Pass 5 — flush (TDD §5, §8.3): the finalized buffer reaches the file
//! through chunked page-granular writes into a fresh temporary file that is
//! atomically renamed over the output path.
//!
//! The macOS vnode-taint trap (TDD §2.1.3, risk R1) forbids mmap-ing the
//! output; writes are the only path. The M4 speed pass (spike S1, perf doc
//! §4.5) activates the pool: the output is preallocated to its final size
//! (`ftruncate` — the extent never grows during the writes), then **4
//! writer threads** `pwrite` disjoint 8 MiB blocks in ascending file order
//! per writer (writer *k* takes blocks *k, k+4, k+8, …*), the file is
//! fsynced once and renamed. Position-independent writes need no
//! synchronization, so the pool needs no locks, no channel and no `unsafe`
//! (`FileExt::write_at` is safe std); the M1–M3 contract — fresh vnode, no
//! partial file ever visible under the output path, page-granular chunks —
//! is unchanged. Small outputs (one block or fewer) keep the simple
//! single-writer path.
//!
//! The M78 observation face: under a subscriber the pool's writers report
//! their own spans through the M63 task seam (one
//! [`pgr_core::observe::TaskEvent`] per writer — the blocks it carried,
//! its wall time, its thread and its own arrival clock), so the §9.4
//! timeline renders the write workers' lanes beside the parse pool's.
//! The channel opens only when a subscriber rides; the unobserved write
//! keeps its no-channel shape (the doc paragraph above, unchanged).

use crate::EmitError;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::Path;

/// Writer-thread count (perf doc §4.5: "4 writers, 8 MiB blocks").
const WRITERS: usize = 4;
/// Write-block size (spike S1's measured default).
const BLOCK: usize = 8 << 20;

/// Writes `buf` to `path` atomically: a sibling temporary file is
/// preallocated to the final size, receives the bytes through the writer
/// pool (`pwrite` over disjoint 8 MiB blocks), is fsynced, then renamed.
///
/// # Errors
/// [`EmitError::Io`] on any filesystem failure; no partial output is left
/// behind (the temp file is removed on failure).
pub fn write_image(buf: &[u8], path: &Path) -> Result<(), EmitError> {
    write_image_inner(buf, path, None)
}

/// [`write_image`] under an observer (M68): the same atomic write — the
/// parity gate is the seam's own contract, `tests/emit_observed.rs` — with
/// Pass 5's completion reported as the `flush` phase (the M68 emit half of
/// the M54 observation seam: the 8 MiB blocks the file split into and the
/// writer threads that carried them, the single-writer path included). One
/// event per write — the completion; a refused write reports nothing (the
/// phase did not complete). The zero-config consumer installs
/// [`pgr_core::TracingObserver`].
///
/// M78 extends the report to the intra-phase face the M63 seam named: the
/// pool's writers carry their own spans — one [`pgr_core::observe::TaskEvent`]
/// per writer (the blocks the writer carried, its wall time, its thread
/// and its own arrival clock), the same shape the parse pool's per-input
/// tasks ride. The pool's threads cannot borrow the caller's observer
/// slot, so the records cross an mpsc channel that opens only when a
/// subscriber rides (the inert-until-subscriber convention — the
/// unsubscribed write allocates nothing) and the caller forwards them
/// once the pool returns; a single-block write reports its task on the
/// calling thread (the serial path — the timeline's pipeline lane).
///
/// # Errors
/// [`EmitError::Io`] on any filesystem failure; no partial output is left
/// behind (the temp file is removed on failure).
pub fn write_image_observed(
    buf: &[u8],
    path: &Path,
    observer: &mut dyn pgr_core::LinkObserver,
) -> Result<(), EmitError> {
    write_image_inner(buf, path, Some(observer))
}

/// The flush body both entries share; `observer` carries the M68 phase
/// report and the M78 writer spans (`None` = the unobserved write, the
/// shape every pre-M68 caller keeps).
fn write_image_inner(
    buf: &[u8],
    path: &Path,
    mut observer: Option<&mut dyn pgr_core::LinkObserver>,
) -> Result<(), EmitError> {
    let blocks = buf.len().div_ceil(BLOCK);
    // M78: the writers report through a channel only when a subscriber
    // rides (the M63 convention — the pool's closures run on other
    // threads and cannot borrow the caller's observer slot).
    let (task_tx, task_rx) = if observer.is_some() {
        let (tx, rx) = std::sync::mpsc::channel::<pgr_core::observe::TaskEvent>();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let started = std::time::Instant::now();
    write_image_body(buf, path, task_tx.as_ref())?;
    if let Some(rx) = task_rx {
        drop(task_tx);
        for task in rx {
            if let Some(observer) = observer.as_deref_mut() {
                observer.on_task(task);
            }
        }
    }
    if let Some(observer) = observer {
        observer.on_phase(pgr_core::PhaseEvent {
            phase: pgr_core::Phase::Flush,
            detail: pgr_core::PhaseDetail::Flushed {
                blocks,
                writers: WRITERS.min(blocks).max(1),
            },
            elapsed: started.elapsed(),
        });
    }
    Ok(())
}

/// The writer task's label: the 1-based blocks the writer carried
/// (`blocks 1,5 of 5` — writer *k* takes blocks *k, k+W, k+2W, …*).
fn writer_label(writer: usize, blocks: usize) -> String {
    let mine: Vec<String> = (writer..blocks)
        .step_by(WRITERS)
        .map(|b| u64::try_from(b + 1).unwrap_or(u64::MAX).to_string())
        .collect();
    format!("blocks {} of {blocks}", mine.join(","))
}

/// The atomic write itself (the M4 writer pool over the preallocated
/// sibling temp file, fsync, rename); `task_tx` carries the M78 writer
/// spans when a subscriber rides.
fn write_image_body(
    buf: &[u8],
    path: &Path,
    task_tx: Option<&std::sync::mpsc::Sender<pgr_core::observe::TaskEvent>>,
) -> Result<(), EmitError> {
    let tmp_path = path.with_extension("pgr.tmp");
    // A fresh vnode avoids stale-signature state on macOS hosts (§8.3).
    let mut file = std::fs::File::create(&tmp_path).map_err(|e| EmitError::Io {
        path: tmp_path.display().to_string(),
        source: e,
    })?;
    let result = (|| -> std::io::Result<()> {
        // S1: preallocate the extent (the Linux/macOS-safe `ftruncate`
        // analogue of `fcntl(F_PREALLOCATE)`); every later write lands
        // inside the existing extent.
        file.set_len(buf.len() as u64)?;
        if buf.len() > BLOCK {
            let blocks = buf.len().div_ceil(BLOCK);
            std::thread::scope(|scope| -> std::io::Result<()> {
                let mut handles = Vec::with_capacity(WRITERS);
                for writer in 0..WRITERS.min(blocks) {
                    let file = &file;
                    handles.push(scope.spawn(move || -> std::io::Result<()> {
                        let started = std::time::Instant::now();
                        let mut block = writer;
                        while block < blocks {
                            let start = block * BLOCK;
                            let end = (start + BLOCK).min(buf.len());
                            file.write_all_at(&buf[start..end], start as u64)?;
                            block += WRITERS;
                        }
                        // M78: the writer reports its own span — the
                        // blocks it carried and its own arrival clock
                        // (the drain must not re-stamp: the collector's
                        // start reconstruction reads the event's clock).
                        if let Some(tx) = task_tx {
                            let _ = tx.send(pgr_core::observe::TaskEvent {
                                phase: pgr_core::Phase::Flush,
                                label: writer_label(writer, blocks),
                                elapsed: started.elapsed(),
                                at: std::time::Instant::now(),
                                thread: std::thread::current().id(),
                            });
                        }
                        Ok(())
                    }));
                }
                for handle in handles {
                    handle.join().map_err(|payload| {
                        // The panic payload *is* the cause: name it (the
                        // house convention — a refusal carries its cause,
                        // not just its class).
                        let cause = payload
                            .downcast_ref::<&str>()
                            .map(|s| (*s).to_string())
                            .or_else(|| payload.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "non-string panic payload".to_string());
                        std::io::Error::other(format!("writer thread panicked: {cause}"))
                    })??;
                }
                Ok(())
            })?;
        } else {
            // The single-writer path: the write runs on the calling
            // thread, so its task is the timeline's pipeline lane (the
            // M64 serial-path rule the parse path rides too).
            let started = std::time::Instant::now();
            file.write_all(buf)?;
            if let Some(tx) = task_tx {
                let _ = tx.send(pgr_core::observe::TaskEvent {
                    phase: pgr_core::Phase::Flush,
                    label: "blocks 1 of 1".to_string(),
                    elapsed: started.elapsed(),
                    at: std::time::Instant::now(),
                    thread: std::thread::current().id(),
                });
            }
        }
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    })();
    if let Err(source) = result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(EmitError::Io {
            path: path.display().to_string(),
            source,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::write_image;
    use std::path::PathBuf;

    #[test]
    fn atomic_write_produces_exact_bytes() {
        let dir = std::env::temp_dir().join("pgr_emit_writer_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path: PathBuf = dir.join("out.bin");
        let buf: Vec<u8> = (0..40_000u32).map(|i| (i % 256) as u8).collect();
        write_image(&buf, &path).unwrap();
        let read = std::fs::read(&path).unwrap();
        assert_eq!(read, buf);
        // No temp file remains.
        assert!(!path.with_extension("pgr.tmp").exists());
        std::fs::remove_file(&path).ok();
    }

    /// The pooled path (multiple 8 MiB blocks, interleaved writers) must
    /// reproduce the byte stream exactly — including the tail block.
    #[test]
    fn pooled_write_reproduces_bytes_across_block_boundaries() {
        let dir = std::env::temp_dir().join("pgr_emit_writer_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path: PathBuf = dir.join("big.bin");
        // 19 MiB + 3 bytes: three full blocks plus a partial tail.
        let len = 19 * 1024 * 1024 + 3;
        let buf: Vec<u8> = (0..len as u64).map(|i| (i % 251) as u8).collect();
        write_image(&buf, &path).unwrap();
        let read = std::fs::read(&path).unwrap();
        assert_eq!(read, buf);
        assert!(!path.with_extension("pgr.tmp").exists());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_output_still_renames_atomically() {
        let dir = std::env::temp_dir().join("pgr_emit_writer_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path: PathBuf = dir.join("empty.bin");
        write_image(&[], &path).unwrap();
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap().len(), 0);
        std::fs::remove_file(&path).ok();
    }
}

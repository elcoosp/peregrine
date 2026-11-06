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
                        let mut block = writer;
                        while block < blocks {
                            let start = block * BLOCK;
                            let end = (start + BLOCK).min(buf.len());
                            file.write_all_at(&buf[start..end], start as u64)?;
                            block += WRITERS;
                        }
                        Ok(())
                    }));
                }
                for handle in handles {
                    handle
                        .join()
                        .map_err(|_| std::io::Error::other("writer thread panicked"))??;
                }
                Ok(())
            })?;
        } else {
            file.write_all(buf)?;
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

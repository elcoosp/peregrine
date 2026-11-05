//! Pass 5 — flush (TDD §5, §8.3): the finalized buffer reaches the file
//! through chunked page-granular writes into a fresh temporary file that is
//! atomically renamed over the output path.
//!
//! The macOS vnode-taint trap (TDD §2.1.3, risk R1) forbids mmap-ing the
//! output; writes are the only path. The 4-writer `pwrite` pool and
//! `fallocate` preallocation are the M4 speed pass — M1 keeps the *contract*
//! (fresh vnode, no partial file ever visible, page-granular chunks) with a
//! single writer.

use crate::EmitError;
use pgr_format::consts::PAGE_SIZE_16K;
use std::io::Write;
use std::path::Path;

/// Writes `buf` to `path` atomically: a sibling temporary file receives the
/// bytes in 16 KiB page-granular chunks, is fsynced, then renamed.
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
        for (i, chunk) in buf.chunks(PAGE_SIZE_16K as usize).enumerate() {
            file.write_all(chunk)?;
            let _ = i; // chunks are page-granular by construction
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
}

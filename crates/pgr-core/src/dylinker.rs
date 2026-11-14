//! The loader-path seam as a nameable decision (M26): the
//! `LC_LOAD_DYLINKER` string stops being the layout's hard-coded
//! `/usr/lib/dyld` and becomes a validated decision on
//! [`crate::layout::LinkConfig`] — the `-dylinker <path>` flag ld64
//! names the dynamic loader with. The kernel execs whatever the
//! command names instead of the default loader, so the decision is
//! *validated, not defaulted*: the path must be non-empty (an empty
//! name is the *absence* of the knob, not a decision), NUL-free (the
//! `lc_str` is a C string — an interior NUL would silently truncate
//! the name to a different loader) and **absolute** (the kernel
//! resolves the loader path from the process root at exec time — a
//! relative name is a shape exec refuses before dyld ever runs). The
//! default is `None` — every pre-M26 link names `/usr/lib/dyld`
//! byte-for-byte, and naming that default explicitly plans the same
//! bytes (the knob names a *different* loader, never a re-spelling of
//! the default one).
//!
//! The knob refuses where it cannot land: `LC_LOAD_DYLINKER` is a
//! main-executable command (the §8.2 loader-configuration adjacency —
//! the same contract M22's environment commands ride), so a dylib, a
//! bundle and the relocatable output have no field to land on. The
//! layout re-checks so no library caller can plan the shape either;
//! the driver surface refuses earlier and renders the refusal as
//! miette help text.

/// The `LC_LOAD_DYLINKER` path an executable link plans with: the
/// validated `-dylinker` override. Dylibs, bundles and relocatable
/// outputs carry no loader command (the M3 contract) — the knob
/// refuses there (the layout's re-check; the driver surface refuses
/// earlier).
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dylinker {
    path: String,
}

impl Dylinker {
    /// Validates a `-dylinker <path>` decision: non-empty, NUL-free,
    /// absolute. The refusal names the fix (the house error
    /// convention) — the driver renders it as miette help text, the
    /// wire maps it to a malformed frame.
    ///
    /// # Errors
    /// [`DylinkerError::Empty`] on an empty path,
    /// [`DylinkerError::Nul`] on an interior NUL,
    /// [`DylinkerError::Relative`] on a non-absolute path.
    pub fn from_flag(raw: &str) -> Result<Self, DylinkerError> {
        if raw.is_empty() {
            return Err(DylinkerError::Empty);
        }
        if raw.contains('\0') {
            return Err(DylinkerError::Nul { raw: raw.into() });
        }
        if !raw.starts_with('/') {
            return Err(DylinkerError::Relative { raw: raw.into() });
        }
        tracing::debug!(path = raw, "the loader seam names the exec'd dyld");
        Ok(Self {
            path: raw.to_string(),
        })
    }

    /// The loader path the command names (the `lc_str` payload).
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The exact `LC_LOAD_DYLINKER` command size for the named path —
    /// the 12-byte-fixed part, the path inline with its NUL, 8-byte
    /// aligned (the `LC_RPATH` grammar; dyld reads this command
    /// through the `dylinker_command` struct).
    #[must_use]
    pub fn cmd_size(&self) -> usize {
        Self::size_for(&self.path)
    }

    /// The command size for a path (the layout's sizing formula — one
    /// shape for the default and the override).
    pub(crate) fn size_for(path: &str) -> usize {
        (12 + path.len() + 1).div_ceil(8) * 8
    }
}

/// A `-dylinker` refusal: the message names the fix (the grammar the
/// flag accepts), never just the verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DylinkerError {
    /// An empty path names no loader — the default *is* the absence of
    /// the knob, so an empty `-dylinker` is a typo; drop the flag (or
    /// name the loader you meant).
    #[error(
        "invalid dylinker: the path is empty — the default loader is the absence of \
         -dylinker; drop the flag or name an absolute path (e.g. /usr/lib/dyld)"
    )]
    Empty,
    /// The `lc_str` is a C string: an interior NUL would silently
    /// truncate the name to a different loader.
    #[error(
        "invalid dylinker {raw:?}: the path must be free of NUL bytes — \
         the command carries C strings"
    )]
    Nul {
        /// The refused path as written.
        raw: String,
    },
    /// The kernel resolves the loader path from the process root at
    /// exec time — a relative name is a shape exec refuses before dyld
    /// ever runs. Name the absolute path.
    #[error(
        "invalid dylinker {raw:?}: the loader path must be absolute — the kernel \
         resolves it from the process root at exec time (use /usr/lib/dyld or an \
         absolute path to your own loader)"
    )]
    Relative {
        /// The refused path as written.
        raw: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_validate_and_keep_the_shape() {
        let d = Dylinker::from_flag("/usr/local/bin/mydyld").expect("ok");
        assert_eq!(d.path(), "/usr/local/bin/mydyld");
        assert_eq!(
            d.cmd_size(),
            (12 + "/usr/local/bin/mydyld".len() + 1).div_ceil(8) * 8
        );
        // The default spelling validates and sizes like the hard-coded
        // string always did (32 bytes — the pre-M26 command).
        assert_eq!(
            Dylinker::from_flag("/usr/lib/dyld").expect("ok").cmd_size(),
            32
        );
    }

    #[test]
    fn refusals_name_the_fix() {
        let err = Dylinker::from_flag("").expect_err("empty refuses");
        assert!(err.to_string().contains("empty"), "{err}");
        let err = Dylinker::from_flag("/usr/bin/dy\0ld").expect_err("NUL refuses");
        assert!(err.to_string().contains("NUL"), "{err}");
        let err = Dylinker::from_flag("bin/dyld").expect_err("relative refuses");
        assert!(err.to_string().contains("absolute"), "{err}");
        assert!(err.to_string().contains("bin/dyld"), "{err}");
    }
}

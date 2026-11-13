//! The bundle-loader seam as a nameable decision (M25): the
//! `-bundle_loader <path>` host stops being an unnameable input shape
//! and becomes a validated provider on [`crate::layout::LinkConfig`] —
//! the main executable a bundle binds against (ld64's bundle story: the
//! bundle carries undefined references the *host* resolves at load
//! time, so the linker plans those binds against the host's export
//! surface). The binds ride the main-executable ordinal
//! (`BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE`, `0xFF`) — the two-level
//! namespace's named slot for "the program itself" — in both the symtab
//! and the chained-fixups import table; no `LC_LOAD_DYLIB` command is
//! emitted (the host is not a dylib the image loads, it is the image's
//! own process).
//!
//! The decision is *validated, not defaulted*: the loader path must be
//! non-empty and NUL-free (the diagnostics carry it into every
//! refusal), every export must be non-empty and NUL-free (the symtab
//! strings are C strings — an interior NUL would silently truncate the
//! name to a different one), and a name enters the surface once (a
//! duplicate export is a scan bug, not a surface — the second row would
//! silently shadow). The default is `None` — every pre-M25 link is
//! byte-identical.
//!
//! The knob refuses where it cannot land: only a bundle binds against
//! a host (an executable is the host of its own bundles; a dylib binds
//! its own dylibs; the relocatable output opens its undefineds by
//! design). The driver surface refuses at parse time; the layout
//! re-checks so no library caller can plan the shape either.

/// The bundle's host: the named executable and the export surface its
/// scan produced (the driver reads the host's export trie — the same
/// surface the linker itself emits; see `pgr_driver`'s loader scan).
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleLoader {
    name: String,
    exports: Vec<Vec<u8>>,
}

impl BundleLoader {
    /// Validates one `-bundle_loader` host: a non-empty, NUL-free path
    /// and a non-empty, NUL-free, once-only export surface. The refusal
    /// names the fix (the house error convention) — the driver renders
    /// it as miette help text, the wire maps it to a malformed frame.
    ///
    /// # Errors
    /// [`BundleLoaderError::Malformed`] on an empty name or export,
    /// [`BundleLoaderError::Nul`] on an interior NUL,
    /// [`BundleLoaderError::Duplicate`] on a repeated export name.
    pub fn new(name: &str, exports: Vec<Vec<u8>>) -> Result<Self, BundleLoaderError> {
        if name.contains('\0') {
            return Err(BundleLoaderError::Nul {
                raw: name.to_string(),
                which: "path".to_string(),
            });
        }
        if name.is_empty() {
            return Err(BundleLoaderError::Malformed {
                raw: name.to_string(),
            });
        }
        let mut seen: std::collections::BTreeSet<&[u8]> = std::collections::BTreeSet::new();
        for export in &exports {
            if export.contains(&0) {
                return Err(BundleLoaderError::Nul {
                    raw: name.to_string(),
                    which: "export name".to_string(),
                });
            }
            if export.is_empty() {
                return Err(BundleLoaderError::Malformed {
                    raw: name.to_string(),
                });
            }
            if !seen.insert(export) {
                return Err(BundleLoaderError::Duplicate {
                    raw: name.to_string(),
                    name: String::from_utf8_lossy(export).into_owned(),
                });
            }
        }
        tracing::debug!(
            loader = name,
            exports = exports.len(),
            "the bundle-loader seam names a host"
        );
        Ok(Self {
            name: name.to_string(),
            exports,
        })
    }

    /// The host's path (diagnostics — the `-bundle_loader` value).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The host's exported symbol names (with the C underscore), in
    /// scan order.
    #[must_use]
    pub fn exports(&self) -> &[Vec<u8>] {
        &self.exports
    }
}

/// A bundle-loader refusal: the message names the fix (the shape the
/// flag accepts), never just the verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleLoaderError {
    /// A path or export that names nothing: an empty `-bundle_loader`
    /// value or an empty export name — shapes dyld could not resolve,
    /// so emitting them would be a silently dropped decision.
    #[error(
        "invalid bundle_loader {raw:?}: the host path and every export must be \
         non-empty — the grammar is -bundle_loader <executable>"
    )]
    Malformed {
        /// The refused path as written.
        raw: String,
    },
    /// The symtab strings are C strings: an interior NUL would silently
    /// truncate the name to a different one.
    #[error(
        "invalid bundle_loader {raw:?}: the {which} must be free of NUL bytes — \
         the symtab carries C strings"
    )]
    Nul {
        /// The refused path as written.
        raw: String,
        /// Which half carried the NUL (`path` or `export name`).
        which: String,
    },
    /// The seam exports a name once; a repeat is a scan bug — the
    /// second row would silently shadow.
    #[error(
        "invalid bundle_loader {raw:?}: duplicate export name {name:?} — \
         one row per name"
    )]
    Duplicate {
        /// The refused path as written.
        raw: String,
        /// The refused export name.
        name: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_loader_validates_and_carries_its_surface() {
        let l = BundleLoader::new("/bin/host", vec![b"_host_fn".to_vec()]).expect("ok");
        assert_eq!(l.name(), "/bin/host");
        assert_eq!(l.exports(), [b"_host_fn".to_vec()]);
        // An empty surface is legal: the host exports nothing the
        // bundle could bind against (the pair gate names the miss).
        let empty = BundleLoader::new("/bin/host", Vec::new()).expect("an empty surface validates");
        assert_eq!(empty.exports().len(), 0);
    }

    #[test]
    fn refusals_and_duplicates_name_the_fix() {
        assert!(BundleLoader::new("", Vec::new()).is_err());
        assert!(BundleLoader::new("/bin/h\0ost", Vec::new()).is_err());
        assert!(BundleLoader::new("/bin/host", vec![Vec::new()]).is_err());
        assert!(BundleLoader::new("/bin/host", vec![b"_f\0".to_vec()]).is_err());
        let err = BundleLoader::new("/bin/host", vec![b"_f".to_vec(), b"_f".to_vec()])
            .expect_err("duplicate refuses");
        assert!(err.to_string().contains("_f"), "{err}");
    }
}

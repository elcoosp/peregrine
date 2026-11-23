//! The CPU family the producer plans for (M10 rung 5, slice 2 — the
//! producer half of the `x86_64` rung; the read side named the family
//! since slice 1). One decision, three readers: the header's
//! `cputype`/`cpusubtype` words, the segment packing's page constant
//! (the "4 KiB constants, same tree" the M10 row names), and the chain
//! word family the fixup planner encodes (`DYLD_CHAINED_PTR_64` under
//! `x86_64` — the walk's dispatch key, TDD §15.8). The default
//! [`CpuFamily::Arm64`] is every pre-slice link: the seam is invisible
//! unless asked for.
//!
//! The family shapes the *image contract* — the header words, the page
//! congruence, the word family — the way the fixtures' [`CpuKind`]
//! (`pgr_fixtures`) already does for the read-side test images. The
//! input surface stays arm64 this rung (slice 1's honesty: the link
//! surface names the family, the input parse names no second one yet).

use pgr_format::consts::{
    CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_X86_64_ALL, CPU_TYPE_ARM64, CPU_TYPE_X86_64,
};

/// The CPU family an image is produced for: Apple Silicon
/// (`CPU_TYPE_ARM64`, the historical default) or Intel Mac
/// (`CPU_TYPE_X86_64`, the M10 row's second target).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CpuFamily {
    /// Apple Silicon (`CPU_TYPE_ARM64`; every pre-slice link).
    #[default]
    Arm64,
    /// Intel Mac (`CPU_TYPE_X86_64`; 4 KiB pages, format-2 chains).
    X86_64,
}

impl CpuFamily {
    /// The family a `mach_header_64.cputype` word names (`None` when
    /// the word is outside the carried families — the input decode
    /// refuses it rather than guessing, M10 rung 5 slice 3).
    #[must_use]
    pub const fn of_cputype(word: u32) -> Option<Self> {
        match word {
            pgr_format::consts::CPU_TYPE_ARM64 => Some(Self::Arm64),
            pgr_format::consts::CPU_TYPE_X86_64 => Some(Self::X86_64),
            _ => None,
        }
    }

    /// The family's `mach_header_64.cputype` value.
    #[must_use]
    pub const fn cputype(self) -> u32 {
        match self {
            Self::Arm64 => CPU_TYPE_ARM64,
            Self::X86_64 => CPU_TYPE_X86_64,
        }
    }

    /// The family's "all CPUs" subtype word
    /// (`CPU_SUBTYPE_ARM64_ALL` / `CPU_SUBTYPE_X86_64_ALL`).
    #[must_use]
    pub const fn subtype_all(self) -> u32 {
        match self {
            Self::Arm64 => CPU_SUBTYPE_ARM64_ALL,
            Self::X86_64 => CPU_SUBTYPE_X86_64_ALL,
        }
    }

    /// The family's segment page size
    /// ([`pgr_format::consts::page_size`] — one table, four readers
    /// since M16; the packing and the header-fit gate join the
    /// verifier's page-contract gates here).
    #[must_use]
    pub const fn page_size(self) -> u64 {
        pgr_format::consts::page_size(self.cputype())
    }

    /// The family's chain word family: `x86_64` encodes the format-2
    /// `DYLD_CHAINED_PTR_64` words (VM-address rebases, the slice-1
    /// walk's translation), arm64 keeps the configured family (the
    /// `-fixup_chains_format` seam — `Offset64` the default, `Arm64e`
    /// the rung-4 family).
    #[must_use]
    pub const fn chain_word_format(
        self,
        configured: crate::fixups::FixupPointerFormat,
    ) -> crate::fixups::FixupPointerFormat {
        match self {
            Self::Arm64 => configured,
            Self::X86_64 => crate::fixups::FixupPointerFormat::Format64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CPU_SUBTYPE_X86_64_ALL, CPU_TYPE_ARM64, CPU_TYPE_X86_64, CpuFamily};
    use pgr_format::consts::{PAGE_SIZE_4K, PAGE_SIZE_16K};

    #[test]
    fn the_default_is_arm64() {
        assert_eq!(CpuFamily::default(), CpuFamily::Arm64);
        assert_eq!(CpuFamily::default().cputype(), CPU_TYPE_ARM64);
        assert_eq!(CpuFamily::default().page_size(), PAGE_SIZE_16K);
    }

    #[test]
    fn the_x86_64_family_reads_the_4_kib_page() {
        let cpu = CpuFamily::X86_64;
        assert_eq!(cpu.cputype(), CPU_TYPE_X86_64);
        assert_eq!(cpu.subtype_all(), CPU_SUBTYPE_X86_64_ALL);
        assert_eq!(cpu.page_size(), PAGE_SIZE_4K);
    }

    #[test]
    fn the_chain_word_family_dispatches_on_the_cpu() {
        use crate::fixups::FixupPointerFormat;
        let arm64 = CpuFamily::Arm64.chain_word_format(FixupPointerFormat::Arm64e);
        assert_eq!(
            arm64,
            FixupPointerFormat::Arm64e,
            "arm64 keeps the configured family"
        );
        let x86e = CpuFamily::X86_64.chain_word_format(FixupPointerFormat::Arm64e);
        assert_eq!(
            x86e,
            FixupPointerFormat::Format64,
            "x86_64 encodes the format-2 family regardless of the arm64 word"
        );
    }
}

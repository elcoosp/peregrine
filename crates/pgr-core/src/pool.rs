//! The shared compute pool (M4, perf doc §3 D9 + §6).
//!
//! Apple Silicon rule (D9): the pool is sized to the **P-core count**
//! (`hw.perflevel0.logicalcpu`) — E-cores join barrier-synchronized passes
//! only as stragglers, and the Pass 5 writer threads are the intended
//! E-core work. Linux hosts (the cross-linking dev path) have no E/P split;
//! the pool falls back to [`std::thread::available_parallelism`].
//!
//! `PGR_JOBS` overrides the size explicitly (benches, CI sweeps, debugging);
//! an invalid value is ignored so a mistyped environment can never change
//! link results — pool size affects scheduling only, never bytes.
//!
//! The pool is a process-wide singleton ([`std::sync::OnceLock`]): rayon
//! pools are expensive to build, and the TDD's pass structure keeps one
//! barrier per pass, so every pass borrows the same pool.

use std::sync::OnceLock;

/// Environment override for the compute-pool size (`PGR_JOBS`).
const JOBS_ENV: &str = "PGR_JOBS";

/// Minimum pool size (a link always makes progress on one thread).
const MIN_JOBS: usize = 1;

/// The configured worker count: `PGR_JOBS` when it parses to a nonzero
/// value, otherwise the platform parallelism (the P-core count on macOS
/// hosts per D9 — the fallback here is `available_parallelism`).
#[must_use]
pub fn worker_count() -> usize {
    if let Ok(raw) = std::env::var(JOBS_ENV) {
        if let Ok(n) = raw.trim().parse::<usize>() {
            return n.max(MIN_JOBS);
        }
    }
    std::thread::available_parallelism().map_or(MIN_JOBS, std::num::NonZero::get)
}

/// The shared compute pool (D9). Every parallel pass installs itself into
/// this pool so the process carries exactly one set of worker threads.
#[must_use]
///
/// # Panics
/// Panics only if rayon cannot spawn the configured worker count (a
/// zero/negative `PGR_JOBS` value is clamped by [`worker_count`], so the
/// practical trigger is resource exhaustion at first-link time).
pub fn compute_pool() -> &'static rayon::ThreadPool {
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(worker_count())
            // D9: workers are link-compute threads; nothing else borrows the
            // pool, so the default breadth-first work sharing is fine. The
            // Pass 5 writers get their own plain threads (pgr-emit::writer).
            .build()
            .expect("rayon thread pool configuration is valid")
    })
}

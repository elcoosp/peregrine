//! M78 — the flush pool's writer spans ride the task seam: the M63 face
//! the parse pool carries (one [`pgr_core::observe::TaskEvent`] per
//! intra-phase task) extends to Pass 5's writer pool — the four writer
//! threads the §5 flush runs did the actual `pwrite` work invisibly, the
//! aggregate `Flushed` phase event the only fact a consumer had. Each
//! writer reports its own span now (the blocks it carried, its wall time,
//! its thread and its own arrival clock — the facts the timeline's lane
//! registry reads), through the M63 channel convention: the pool's
//! threads cannot borrow the caller's observer slot, so the channel opens
//! only when a subscriber rides and the caller forwards the records once
//! the pool returns.
//!
//! Gate matrix:
//! * the pooled write reports one task per writer — the labels name the
//!   blocks each writer carried (the 1-based block numbers, `k, k+W,
//!   k+2W, …`), the threads are the workers' own, and the block sets
//!   partition the write exactly once;
//! * the single-writer path reports its task on the calling thread (the
//!   M64 serial-path rule — the pipeline lane, not a worker);
//! * the parity — the task-carrying write ships the identical bytes (the
//!   observation never moves a byte), and the aggregate `Flushed` phase
//!   event rides beside the tasks;
//! * a refused write reports nothing (the phase did not complete; the
//!   tasks did not run to completion).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Instant;

use pgr_core::observe::{LinkObserver, Phase, PhaseDetail, PhaseEvent, TaskEvent};
use pgr_emit::{write_image, write_image_observed};

/// The task-and-phase recorder: the test's own observer.
#[derive(Default)]
struct Recorder {
    phases: Vec<PhaseEvent>,
    tasks: Vec<TaskEvent>,
}

impl LinkObserver for Recorder {
    fn on_phase(&mut self, event: PhaseEvent) {
        self.phases.push(event);
    }
    fn on_task(&mut self, task: TaskEvent) {
        self.tasks.push(task);
    }
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m78_{}_{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// The label's block numbers: `blocks 1,5 of 7` → `[1, 5]`, total 7.
fn label_blocks(label: &str) -> (Vec<u64>, u64) {
    let rest = label
        .strip_prefix("blocks ")
        .unwrap_or_else(|| panic!("the label names the blocks: {label}"));
    let (list, total) = rest
        .split_once(" of ")
        .unwrap_or_else(|| panic!("the label names the total: {label}"));
    let nums: Vec<u64> = list
        .split(',')
        .map(|n| n.parse().expect("the label's blocks parse"))
        .collect();
    (nums, total.parse().expect("the label's total parses"))
}

#[test]
fn the_pooled_write_reports_one_task_per_writer() {
    let dir = scratch("pooled");
    let path = dir.join("big.bin");
    // 33 MiB + 3 bytes: four full blocks plus a partial tail — five
    // blocks, so all four writers carry work.
    let len = 33 * 1024 * 1024 + 3;
    let buf: Vec<u8> = (0..len as u64).map(|i| (i % 251) as u8).collect();
    let blocks = buf.len().div_ceil(8 << 20);
    assert_eq!(blocks, 5, "the corpus splits into five blocks");

    let mut rec = Recorder::default();
    write_image_observed(&buf, &path, &mut rec).expect("the pooled write ships");
    let main_thread = std::thread::current().id();

    assert_eq!(rec.tasks.len(), 4, "one task per writer, not per block");
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for task in &rec.tasks {
        assert_eq!(task.phase, Phase::Flush, "the tasks ride the flush phase");
        assert_ne!(
            task.thread, main_thread,
            "a writer's task carries the worker's own thread"
        );
        assert!(task.elapsed.as_nanos() > 0, "the writer measured its wall");
        assert!(
            task.at <= Instant::now(),
            "the arrival clock is the worker's"
        );
        let (nums, total) = label_blocks(&task.label);
        assert_eq!(
            total, blocks as u64,
            "the label names the write's block count"
        );
        assert!(!nums.is_empty(), "every writer carried at least one block");
        for n in &nums {
            assert!(
                seen.insert(*n),
                "the writers' block sets partition the write (block {n} twice)"
            );
        }
    }
    let expected: BTreeSet<u64> = (1..=blocks as u64).collect();
    assert_eq!(seen, expected, "every block rode exactly one writer's span");

    // The aggregate phase event rides beside the tasks (the M68 shape).
    assert_eq!(rec.phases.len(), 1, "one completion event per write");
    let event = &rec.phases[0];
    assert_eq!(event.phase, Phase::Flush);
    assert!(
        matches!(
            &event.detail,
            PhaseDetail::Flushed {
                blocks: 5,
                writers: 4
            }
        ),
        "the Flushed detail keeps the M68 shape, got {:?}",
        event.detail
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_single_write_reports_its_task_on_the_calling_thread() {
    let dir = scratch("single");
    let path = dir.join("small.bin");
    let buf: Vec<u8> = (0..4096u32).map(|i| (i % 253) as u8).collect();

    let mut rec = Recorder::default();
    write_image_observed(&buf, &path, &mut rec).expect("the single write ships");

    assert_eq!(rec.tasks.len(), 1, "the simple path reports one task");
    let task = &rec.tasks[0];
    assert_eq!(task.phase, Phase::Flush);
    assert_eq!(task.label, "blocks 1 of 1");
    assert_eq!(
        task.thread,
        std::thread::current().id(),
        "the serial-path task is the pipeline lane's (M64's rule)"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_task_carrying_write_ships_identical_bytes() {
    let dir = scratch("parity");
    let observed = dir.join("observed.bin");
    let plain = dir.join("plain.bin");
    let len = 9 * 1024 * 1024; // two blocks: the pooled path
    let buf: Vec<u8> = (0..len as u64).map(|i| (i % 249) as u8).collect();

    let mut rec = Recorder::default();
    write_image_observed(&buf, &observed, &mut rec).expect("the observed write ships");
    write_image(&buf, &plain).expect("the plain write ships");

    assert_eq!(
        std::fs::read(&observed).expect("the observed bytes read"),
        buf,
        "the observed write ships the exact bytes"
    );
    assert_eq!(
        std::fs::read(&plain).expect("the plain bytes read"),
        buf,
        "the parity: observing never moves a byte"
    );
    assert!(!observed.with_extension("pgr.tmp").exists());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_refused_write_reports_no_task() {
    let dir = scratch("refused");
    // A path whose parent does not exist: the create refuses before any
    // writer runs.
    let path = dir.join("missing-dir").join("out.bin");
    let buf = vec![0u8; 64];

    let mut rec = Recorder::default();
    let result = write_image_observed(&buf, &path, &mut rec);
    assert!(result.is_err(), "the write refuses");
    assert!(
        rec.tasks.is_empty() && rec.phases.is_empty(),
        "a refused write reports nothing (the phase did not complete)"
    );
    std::fs::remove_dir_all(&dir).ok();
}

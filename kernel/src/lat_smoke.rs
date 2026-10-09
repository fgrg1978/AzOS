// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Worst-case wake-up latency under load (`lat-smoke`): the shape of
//! cyclictest / timerlat, as a kernel task.
//!
//! A priority-[`RT_PRIO`] task pinned to [`HART`] sleeps to an absolute
//! deadline every [`PERIOD_US`] for [`PERIODS`] periods and records how late
//! it ran: `now() - deadline` right after its block returns. That is timer
//! interrupt delay (masked windows) + the interrupt path + the wake + the
//! reschedule + the switch, end to end, the number an RTOS claim is about.
//!
//! Load on the same hart while it runs, all below it in priority:
//!   * `lat-spam` prints a ~100-byte console line every [`SPAM_EVERY`]
//!     periods (the console writer masks interrupts while it copies to the
//!     UART);
//!   * `lat-disk` reads [`DISK_SECTORS`] sectors from the block device every
//!     period, rotating the offset (virtio-blk request + its completion
//!     interrupt);
//!   * `lat-hog` computes and never blocks, so the hart is never idle while
//!     the measurement runs (a CPU-bound background, the case an RTOS is
//!     for — and the one where an idle hart's timer re-arm does not help);
//!   * whatever else the boot runs on hart 0 (boot daemons; the rows boot the
//!     ipctest image, whose autorun shares the hart at `-smp 1`).
//!
//! Spam and disk are paced by `lat-rt` itself (it kicks them by TID after
//! each sample), not by timers of their own (wave 13). A load task asleep on
//! a timer made the tick handler program the comparator for ITS deadline,
//! and a tick taken while `lat-rt` was already blocked again then programmed
//! `lat-rt`'s deadline too: the measured wake was on time whatever the
//! block-time arm did. Whether a load timer covered every period depended on
//! where the virtio-blk completions landed, which follows the host thread —
//! so the `oneshot-canary` row (no block-time arm) passed 9 boots of 20 on
//! riscv64 (max 17.8-21.9 us, the fixed kernel's number) and failed 11
//! (6.5-9.96 ms). Paced: 2 of 20 passed (max 8.1 us), 18 failed; aarch64's
//! canary failed 20 of 20. The residual is the boot's own timer sleepers on
//! hart 0 at `-smp 1` (rt-motor sleeps 1 ms), which this smoke does not
//! own: the riscv64 canary still cannot be read alone, its row is evidence
//! only with its failures counted over several boots.
//!
//! The rows boot under `-icount shift=0,sleep=off`: virtual time advances one
//! nanosecond per guest instruction, so the numbers are instruction counts of
//! the guest, not host wall-clock. Not bit-exact across runs: the virtio-blk
//! completion arrives from a host thread, so where it lands in the guest's
//! instruction stream moves with host timing (see the rows' notes).
//!
//! Verdict: `[LAT] PASS` when the maximum is at most [`BOUND_NS`] for this
//! ISA, `[LAT] FAIL` otherwise (a line only that path prints). With
//! `lat-trace` the run also ends with the tracer's per-hart maxima and the
//! five worst sites (`[LATTRACE] run ...`) and the `/proc/irqsoff` read-back;
//! the plain row builds without it, so its number is the kernel's alone.
//!
//! `lat-canary` (implies `lat-trace`): one more task on the hart masks
//! interrupts for [`CANARY_MASK_US`] [`CANARY_SHOTS`] times during the run,
//! announcing its site. The tracer must name that site as the worst, and the
//! verdict must be FAIL.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use alloc::vec::Vec;
use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_sched::{task_block_outcome, BlockOutcome, WaitReason};

/// Above everything a boot creates (rt-motor is 8; 0 is left free).
const RT_PRIO: u32 = 1;
/// Load priorities: below every boot daemon that matters, above idle.
const SPAM_PRIO: u32 = 20;
const DISK_PRIO: u32 = 22;
const HOG_PRIO: u32 = 23;
#[cfg(feature = "lat-canary")]
const CANARY_PRIO: u32 = 21;
/// Every task of this smoke runs on hart 0, the one every `-smp` has —
/// except riscv64's `oneshot-canary`, which runs on hart 1 under `-smp 2`
/// (its gate row boots so): on riscv64 every timer interrupt programs the
/// nearest sleeper, and hart 0 carries the boot's 1 kHz sleepers (rt-motor,
/// net-poll), whose interrupts reprogrammed `lat-rt`'s deadline and hid the
/// missing block-time arm in 2-3 boots of 5 even with the hog alone (05-10).
const HART: i8 = if cfg!(all(feature = "oneshot-canary", target_arch = "riscv64")) { 1 } else { 0 };

const PERIOD_US: u64 = 1_000;
const PERIODS: usize = 2_000;
/// Let the boot reach its steady state (autorun started) before measuring.
const SETTLE_MS: u64 = 1_500;
/// Spam every this many periods (2 ms at 1 ms, as when it slept 2 ms).
const SPAM_EVERY: usize = 2;
#[cfg(not(feature = "lat-fat"))]
const DISK_SECTORS: u32 = 8;

/// Upper bound on the worst wake-up latency, in nanoseconds of
/// `-icount shift=0` virtual time (= guest instructions), both ISAs.
///
/// Wave 13, load paced by `lat-rt` (20 runs per ISA): riscv64 max
/// 4.4-15.8 us, aarch64 3.6-7.3 us. Measured (wave 11 ONESHOT, `-smp 1`,
/// the timer-paced load, three runs per ISA):
/// riscv64 max 17.9-18.4 us, p99 8.4-9.9 us (Sstc `stimecmp`); aarch64 max
/// 11.5-12.8 us, p99 5.4-6.2 us. Before the one-shot change the worst case
/// was the scheduler tick: a task that blocked on a timer deadline on a hart
/// that then ran another task left the next tick programmed, so it woke up to
/// one `SCHED_HZ` period (10 ms) late (riscv64 max 8.3 ms, aarch64 9.7 ms with
/// ~1800 of 2000 periods late); the bound was 12 ms. Now `block_current`
/// programs the comparator for an earlier deadline and both tick handlers
/// program the nearest sleeper. The bound is 100 us: five times the worst
/// measured, so the virtio-blk completion landing on a deadline does not fail
/// it, and two orders of magnitude under the tick, so a return of the tick
/// (`oneshot-canary`) or a masked window of 0.1 ms does.
const BOUND_NS: u64 = 100_000;

#[cfg(feature = "lat-canary")]
const CANARY_MASK_US: u64 = 20_000;
#[cfg(feature = "lat-canary")]
const CANARY_SHOTS: u32 = 3;

static RUNNING: AtomicBool = AtomicBool::new(false);
static DONE: AtomicBool = AtomicBool::new(false);
static SPAM_LINES: AtomicU32 = AtomicU32::new(0);
static DISK_READS: AtomicU32 = AtomicU32::new(0);
static DISK_ERRORS: AtomicU32 = AtomicU32::new(0);
static HOG_ROUNDS: AtomicU32 = AtomicU32::new(0);
static SAMPLES: [AtomicU64; PERIODS] = [const { AtomicU64::new(0) }; PERIODS];
/// TIDs of the paced load tasks, for `lat-rt`'s kicks.
static SPAM_TID: AtomicU32 = AtomicU32::new(0);
static DISK_TID: AtomicU32 = AtomicU32::new(0);

/// A paced load task's wait for its kick: blocked on a timer that never
/// expires, so no deadline of its own reaches the comparator. Returns on
/// the kick (or a stray wake; the caller re-checks `DONE` either way).
fn wait_kick() {
    let _ = task_block_outcome(WaitReason::Timer(u64::MAX));
}

/// Kick a paced load task (the K-C9 stamp covers a kick that lands before
/// its block).
fn kick(tid: &AtomicU32) {
    let t = tid.load(Ordering::Acquire);
    if t != 0 {
        let _ = azos_sched::scheduler::wake_task_by_tid(
            t, &|r| matches!(r, WaitReason::Timer(u64::MAX)));
    }
}

fn isa() -> &'static str {
    if cfg!(target_arch = "riscv64") { "riscv64" } else { "aarch64" }
}

/// `oneshot-canary` only: half a microsecond added to each period, so over
/// [`PERIODS`] periods `lat-rt`'s deadline sweeps a whole millisecond of phase
/// against the boot's other 1 ms sleepers on this hart (rt-motor). With an
/// exact 1 ms period the phase stayed put, and when rt-motor's wake fell
/// between `lat-rt`'s block and its deadline, the tick it took programmed
/// that deadline every period: wave 14's canary saw 0 late periods of 2000
/// (gates 203, 204) where wave 13's saw 4 to 24. The measured row keeps 1 ms,
/// the period its Linux counterpart uses.
fn canary_phase_slip() -> u64 {
    if cfg!(feature = "oneshot-canary") { (TIMER_FREQ / 2_000_000).max(1) } else { 0 }
}

fn us_to_ticks(us: u64) -> u64 {
    TIMER_FREQ.saturating_mul(us) / 1_000_000
}

fn ticks_to_ns(t: u64) -> u64 {
    ((t as u128) * 1_000_000_000u128 / TIMER_FREQ.max(1) as u128) as u64
}

/// Block until the counter reaches `deadline` — `sys_sleep_until`'s loop.
fn block_until(deadline: u64) {
    while now() < deadline {
        if task_block_outcome(WaitReason::Timer(deadline)) == BlockOutcome::Refused {
            while now() < deadline {
                core::hint::spin_loop();
            }
        }
    }
}

fn sleep_us(us: u64) {
    block_until(now().saturating_add(us_to_ticks(us)));
}

/// Create the measuring task and its load on [`HART`].
pub fn spawn(num_cpus: usize) {
    azos_sched::task_create_affinity("lat-rt", rt_task, num_cpus, RT_PRIO, HART);
    // `oneshot-canary`: the CPU hog only. The paced spam and disk load raise a
    // console or virtio-blk interrupt after every sample, and any interrupt
    // that lands between `lat-rt`'s block and its deadline reprograms the
    // comparator for that deadline — it hid the missing block-time arm in 3
    // boots of 5 (05-10). With only the hog nothing but the boot's own timer
    // sleepers can rescue a period, and [`canary_phase_slip`] walks the
    // deadline past those. The measured row keeps its full load.
    if !cfg!(feature = "oneshot-canary") {
        azos_sched::task_create_affinity("lat-spam", spam_task, 0, SPAM_PRIO, HART);
        azos_sched::task_create_affinity("lat-disk", disk_task, 0, DISK_PRIO, HART);
    }
    azos_sched::task_create_affinity("lat-hog", hog_task, 0, HOG_PRIO, HART);
    #[cfg(feature = "lat-canary")]
    azos_sched::task_create_affinity("lat-canary", canary_task, 0, CANARY_PRIO, HART);
    kprintln!("[LAT] created lat-rt (prio {}) + load on hart {}", RT_PRIO, HART);
}

fn spam_task(_: usize) {
    SPAM_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    let mut n = 0u32;
    while !DONE.load(Ordering::Acquire) {
        if RUNNING.load(Ordering::Acquire) {
            kprintln!("[LATLOAD] {:06} the quick brown fox jumps over the lazy dog 0123456789 abcdefghijklmnopqrstuvwxyz", n);
            n = n.wrapping_add(1);
            SPAM_LINES.store(n, Ordering::Relaxed);
        }
        wait_kick();
    }
}

/// `lat-fat`: the disk load writes through FAT32 instead of reading raw
/// sectors. Each round rewrites [`FAT_PATH`] whole ([`FAT_BYTES`], a few
/// clusters on every image the rows boot): the VFS flush allocates a new
/// chain, frees the old one and crosses the journal's device barriers — the
/// shape of a CRASH.LOG append on the control hart.
///
/// Not paced by `lat-rt`'s kicks: a write that starts right after a sample
/// has a whole period before the next deadline, so a preempt-off window
/// shorter than the period never met one (the `SpinLock` canary measured
/// 0.83 ms windows on aarch64 and still passed at 85 us, paced). The writer
/// sleeps [`FAT_GAP_US`] between rounds instead — not a multiple of the
/// period, so the rounds sweep its phase and the hog below it still runs.
#[cfg(feature = "lat-fat")]
const FAT_PATH: &[u8] = b"/fat/LATFAT.BIN";
#[cfg(feature = "lat-fat")]
const FAT_BYTES: usize = 6 * 1024;
#[cfg(feature = "lat-fat")]
const FAT_GAP_US: u64 = 1_370;

#[cfg(feature = "lat-fat")]
fn disk_task(_: usize) {
    use azos_fs::vfs::{O_CREAT, O_TRUNC, O_WRONLY};
    let mut data = alloc::vec![0u8; FAT_BYTES];
    let mut fds = azos_fs::ScratchFds::new();
    azos_fs::fat32::fat32_pi_io_watch(azos_sched::current_task_tid());
    let mut n = 0u8;
    while !DONE.load(Ordering::Acquire) {
        sleep_us(if RUNNING.load(Ordering::Acquire) { FAT_GAP_US } else { 10_000 });
        if !RUNNING.load(Ordering::Acquire) {
            continue;
        }
        n = n.wrapping_add(1);
        data.iter_mut().for_each(|b| *b = n);
        let fd = azos_fs::vfs::vfs_open(&mut fds, FAT_PATH, O_WRONLY | O_CREAT | O_TRUNC);
        let ok = fd >= 0 && {
            let w = azos_fs::vfs::vfs_write(&mut fds, fd, data.as_ptr(), data.len());
            // Closed whatever the write did: the close is the flush.
            azos_fs::vfs::vfs_close(&mut fds, fd) == 0 && w == data.len() as i32
        };
        if ok {
            DISK_READS.fetch_add(1, Ordering::Relaxed);
        } else {
            DISK_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(not(feature = "lat-fat"))]
fn disk_task(_: usize) {
    DISK_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    let mut buf = [0u8; 512 * DISK_SECTORS as usize];
    let cap = azos_drv_block::blkdev::capacity_sectors();
    let mut sector = 0u64;
    while !DONE.load(Ordering::Acquire) {
        if !RUNNING.load(Ordering::Acquire) || cap < DISK_SECTORS as u64 {
            wait_kick();
            continue;
        }
        match azos_drv_block::blkdev::read(sector, DISK_SECTORS, &mut buf) {
            Ok(()) => { DISK_READS.fetch_add(1, Ordering::Relaxed); }
            Err(()) => { DISK_ERRORS.fetch_add(1, Ordering::Relaxed); }
        }
        sector = (sector + DISK_SECTORS as u64 * 17) % (cap - DISK_SECTORS as u64);
        wait_kick();
    }
}

fn hog_task(_: usize) {
    while !RUNNING.load(Ordering::Acquire) {
        if DONE.load(Ordering::Acquire) {
            return;
        }
        sleep_us(10_000);
    }
    let mut x = 0x9E37_79B9u32;
    while !DONE.load(Ordering::Acquire) {
        for _ in 0..1_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
        }
        core::hint::black_box(x);
        HOG_ROUNDS.store(HOG_ROUNDS.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed);
    }
}

#[cfg(feature = "lat-canary")]
fn canary_task(_: usize) {
    use azos_arch::{Interrupts, ARCH};
    while !RUNNING.load(Ordering::Acquire) {
        sleep_us(10_000);
    }
    for _ in 0..CANARY_SHOTS {
        sleep_us(400_000);
        if DONE.load(Ordering::Acquire) {
            return;
        }
        // One line, so the announced site is the line `disable_all` reports.
        let (site, prev) = (core::panic::Location::caller(), ARCH.disable_all());
        let end = now() + us_to_ticks(CANARY_MASK_US);
        while now() < end {
            core::hint::spin_loop();
        }
        ARCH.restore(prev);
        kprintln!("[LATCANARY] masked {} us at site={}:{}", CANARY_MASK_US, site.file(), site.line());
    }
}

fn rt_task(num_cpus: usize) {
    sleep_us(SETTLE_MS * 1_000);
    #[cfg(feature = "lat-trace")]
    {
        crate::lat_trace::print_summary("boot", 5);
        azos_arch::lat_hook::lat::reset();
    }
    let period = us_to_ticks(PERIOD_US) + canary_phase_slip();
    RUNNING.store(true, Ordering::Release);
    let t0 = now() + period;
    let mut overruns = 0u32;
    let mut max = 0u64;
    let mut worst = 0usize;
    for (k, slot) in SAMPLES.iter().enumerate() {
        let deadline = t0 + (k as u64) * period;
        if now() >= deadline {
            overruns += 1;
        }
        block_until(deadline);
        let late = now().saturating_sub(deadline);
        slot.store(late, Ordering::Relaxed);
        if late > max {
            max = late;
            worst = k;
        }
        // The load's pace (see the module doc), after the sample.
        kick(&DISK_TID);
        if k % SPAM_EVERY == 0 {
            kick(&SPAM_TID);
        }
    }
    RUNNING.store(false, Ordering::Release);
    DONE.store(true, Ordering::Release);
    kick(&DISK_TID);
    kick(&SPAM_TID);

    let mut v: Vec<u64> = SAMPLES.iter().map(|s| s.load(Ordering::Relaxed)).collect();
    v.sort_unstable();
    let pct = |p: usize| v[(v.len() * p).div_ceil(100).saturating_sub(1)];
    let (max_ns, p99_ns, p50_ns, min_ns) =
        (ticks_to_ns(max), ticks_to_ns(pct(99)), ticks_to_ns(pct(50)), ticks_to_ns(v[0]));
    kprintln!("[LAT] isa={} harts={} hart={} period_us={} periods={} max_ns={} p99_ns={} p50_ns={} min_ns={} worst_period={} overruns={} timer_hz={}",
              isa(), num_cpus, HART, PERIOD_US, PERIODS, max_ns, p99_ns, p50_ns, min_ns,
              worst, overruns, TIMER_FREQ);
    kprintln!("[LAT] load spam_lines={} disk_reads={} disk_errors={} hog_rounds={}",
              SPAM_LINES.load(Ordering::Relaxed), DISK_READS.load(Ordering::Relaxed),
              DISK_ERRORS.load(Ordering::Relaxed), HOG_ROUNDS.load(Ordering::Relaxed));
    // F1: FAT device I/O issued under a held PiMutex — by the FAT writer below
    // (must be 0: it holds none itself, so any is FAT32's), and by any task
    // (information: other subsystems' locks).
    #[cfg(feature = "lat-fat")]
    {
        let (mine, all) = azos_fs::fat32::fat32_pi_io_counts();
        kprintln!("[LAT] fat pi_io={} pi_io_all={}", mine, all);
    }
    #[cfg(feature = "lat-trace")]
    {
        crate::lat_trace::print_summary("run", 5);
        let mut buf = [0u8; 512];
        let n = azos_fs::procfs_read(b"/proc/irqsoff", &mut buf);
        for line in core::str::from_utf8(&buf[..n]).unwrap_or("?").lines() {
            kprintln!("[LATTRACE] proc irqsoff | {}", line);
        }
    }
    if max_ns <= BOUND_NS {
        kprintln!("[LAT] PASS {} max_ns={} <= bound_ns={}", isa(), max_ns, BOUND_NS);
    } else {
        kprintln!("[LAT] FAIL {} max_ns={} > bound_ns={}", isa(), max_ns, BOUND_NS);
    }
}

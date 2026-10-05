// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! pifast-smoke: priority inversion through fast IPC (RFC-0052 row R4).
//!
//! Three kernel tasks pinned to [`HART`]:
//!   * `pifast-cli` at [`CLIENT_PRIO`] (13) calls the server through
//!     `SYS_IPC_FAST_CALL_EP` (582) once per [`PERIOD_US`], on an absolute
//!     deadline, and times each call with `timebase::now()`;
//!   * `pifast-srv` at [`SERVER_PRIO`] (24) serves the named endpoint through
//!     `SYS_IPC_FAST_ACCEPT` / `SYS_IPC_FAST_REPLY_ACCEPT`, doing
//!     [`SERVER_WORK`] rounds of arithmetic per request;
//!   * `pifast-hog` at [`HOG_PRIO`] (18), between the two, computes for
//!     [`HOG_BURST_US`] and sleeps for [`HOG_REST_US`], over and over.
//!
//! The calls go through `syscall_dispatch_out`, the same arms ring 3 reaches
//! through `ecall`/`svc`: endpoint resolution, slot, hand-off, retry loop.
//!
//! Two phases. `quiet`: [`CALLS_QUIET`] calls with the hog parked — the
//! round trip and whatever else the boot runs on the hart. `loaded`:
//! [`CALLS_LOADED`] calls with the hog running. When a call lands during a
//! burst, the server (24) is woken behind the hog (18) on a hart with strict
//! priority dispatch, so without priority inheritance the client (13) waits
//! for the rest of the burst: the inversion. With the caller's priority
//! donated to the server for the span of the call, the server runs ahead of
//! the hog and the call costs what it costs in the quiet phase.
//!
//! Verdict: `[PIFAST] PASS` when the loaded maximum is at most [`BOUND_NS`]
//! AND the server was seen serving at the client's priority (the donation,
//! not some other reason, kept the bound); `[PIFAST] FAIL` otherwise (a line
//! only that path prints). `pifast-donation-canary` builds the call without
//! the donation: the row must fail. The rows boot
//! under `-smp 1 -icount shift=0,sleep=off` (the LAT rows' setup): one
//! nanosecond of virtual time per guest instruction.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use alloc::vec::Vec;
use azos_abi::syscall_nr::{SYS_IPC_FAST_ACCEPT, SYS_IPC_FAST_CALL_EP, SYS_IPC_FAST_REPLY_ACCEPT};
use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_ipc::cap::CapPerms;
use azos_sched::{task_block_outcome, BlockOutcome, WaitReason};
use azos_syscall::SyscallOut;

/// Client above the hog above the server. All three are outside the RT band
/// (`RT_PRIORITY_THRESHOLD` = 12), where ring-3 tasks live. 13, not 14: the
/// boot's `behavior` task runs at 14 (`BEHAVIOR_PRIORITY`) and computes for
/// ~1.5 s once (its one-shot bench sweep); at -smp 1 it shares this hart, and
/// a client in its bucket would be time-sliced against it whatever the
/// server's priority.
const CLIENT_PRIO: u32 = 13;
const HOG_PRIO: u32 = 18;
const SERVER_PRIO: u32 = 24;
/// Every task of this smoke runs on hart 0, the one every `-smp` has.
const HART: i8 = 0;

const ENDPOINT: &[u8] = b"pifast-smoke";
/// Let the boot reach its steady state (autorun started) before measuring.
const SETTLE_MS: u64 = 1_500;
/// Client period: not a divisor of the hog's cycle, so call instants sweep
/// the whole burst/rest cycle.
const PERIOD_US: u64 = 1_300;
const CALLS_QUIET: usize = 200;
const CALLS_LOADED: usize = 1_000;
const HOG_BURST_US: u64 = 2_000;
const HOG_REST_US: u64 = 1_000;
/// Arithmetic rounds per request: a few microseconds of service, so a hog
/// waking during the service can matter too.
const SERVER_WORK: u32 = 400;

/// Upper bound on the worst loaded call, in nanoseconds of `-icount shift=0`
/// virtual time, both ISAs: the LAT rows' 100 us. The unloaded round trip is
/// a few microseconds; an inverted call waits for up to one hog burst
/// ([`HOG_BURST_US`] = 2 ms), twenty times the bound.
const BOUND_NS: u64 = 100_000;

static SERVER_TID: AtomicU32 = AtomicU32::new(0);
static SERVING: AtomicBool = AtomicBool::new(false);
static HOG_ON: AtomicBool = AtomicBool::new(false);
static DONE: AtomicBool = AtomicBool::new(false);
static HOG_BURSTS: AtomicU32 = AtomicU32::new(0);
static SERVED: AtomicU32 = AtomicU32::new(0);
/// Worst priority the server was seen running at while serving (telemetry:
/// shows whether a donation reached it).
static SERVER_BEST_PRIO: AtomicU64 = AtomicU64::new(u64::MAX);

fn isa() -> &'static str {
    if cfg!(target_arch = "riscv64") { "riscv64" } else { "aarch64" }
}

fn us_to_ticks(us: u64) -> u64 {
    TIMER_FREQ.saturating_mul(us) / 1_000_000
}

fn ticks_to_ns(t: u64) -> u64 {
    ((t as u128) * 1_000_000_000u128 / TIMER_FREQ.max(1) as u128) as u64
}

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

fn dispatch(num: u64, a: [u64; 6], out: &mut SyscallOut) -> i64 {
    let regs = azos_sched::UserRegs::default();
    azos_syscall::syscall_dispatch_out(num, a[0], a[1], a[2], a[3], a[4], a[5], 0, 0, &regs, out)
}

/// Create the three tasks on [`HART`].
pub fn spawn() {
    azos_sched::task_create_affinity("pifast-srv", server_task, 0, SERVER_PRIO, HART);
    azos_sched::task_create_affinity("pifast-hog", hog_task, 0, HOG_PRIO, HART);
    azos_sched::task_create_affinity("pifast-cli", client_task, 0, CLIENT_PRIO, HART);
    kprintln!("[PIFAST] created client {} / hog {} / server {} on hart {}",
              CLIENT_PRIO, HOG_PRIO, SERVER_PRIO, HART);
}

fn server_task(_: usize) {
    let me = azos_sched::current_task_tid();
    if azos_ipc::endpoint::endpoint_named_cap(me, CapPerms::READ, ENDPOINT).is_none() {
        kprintln!("[PIFAST] FAIL setup: the server could not claim the endpoint");
        return;
    }
    SERVER_TID.store(me, Ordering::Release);
    SERVING.store(true, Ordering::Release);
    let mut out = SyscallOut::new();
    let mut h = dispatch(SYS_IPC_FAST_ACCEPT, [0; 6], &mut out);
    let mut x = 0x2545_F491u32;
    loop {
        if h < 0 {
            if DONE.load(Ordering::Acquire) {
                return;
            }
            h = dispatch(SYS_IPC_FAST_ACCEPT, [0; 6], &mut out);
            continue;
        }
        let w0 = out.regs[1];
        for _ in 0..SERVER_WORK {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
        }
        core::hint::black_box(x);
        if let Some(p) = azos_sched::task_priority(me) {
            SERVER_BEST_PRIO.fetch_min(p as u64, Ordering::Relaxed);
        }
        SERVED.fetch_add(1, Ordering::Relaxed);
        // a0 = handle, a1 unread, a2..a5 = reply words (the arm's convention).
        h = dispatch(SYS_IPC_FAST_REPLY_ACCEPT, [h as u64, 0, w0 ^ 0x5A5A, 0, 0, 0], &mut out);
    }
}

fn hog_task(_: usize) {
    let mut x = 0x9E37_79B9u32;
    while !DONE.load(Ordering::Acquire) {
        if !HOG_ON.load(Ordering::Acquire) {
            sleep_us(10_000);
            continue;
        }
        let end = now().saturating_add(us_to_ticks(HOG_BURST_US));
        while now() < end {
            for _ in 0..64 {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
            }
            core::hint::black_box(x);
        }
        HOG_BURSTS.fetch_add(1, Ordering::Relaxed);
        sleep_us(HOG_REST_US);
    }
}

/// `calls` timed calls, one per [`PERIOD_US`]; `None` on a wrong reply.
fn run_phase(cap: u64, calls: usize, seq0: u64) -> Option<Vec<u64>> {
    let mut out = SyscallOut::new();
    let mut lat = Vec::with_capacity(calls);
    let mut deadline = now();
    for i in 0..calls {
        deadline = deadline.saturating_add(us_to_ticks(PERIOD_US));
        block_until(deadline);
        let seq = seq0 + i as u64;
        let t0 = now();
        let rc = dispatch(SYS_IPC_FAST_CALL_EP, [cap, seq, 0, 0, 0, 0], &mut out);
        let t1 = now();
        if rc as u64 != seq ^ 0x5A5A {
            kprintln!("[PIFAST] FAIL reply: call {} answered {} (expected {})", seq, rc, seq ^ 0x5A5A);
            return None;
        }
        lat.push(ticks_to_ns(t1.saturating_sub(t0)));
    }
    Some(lat)
}

/// `(max, p99)` in ns.
fn stats(v: &mut Vec<u64>) -> (u64, u64) {
    v.sort_unstable();
    let n = v.len();
    if n == 0 {
        return (0, 0);
    }
    (v[n - 1], v[(n * 99 / 100).min(n - 1)])
}

fn client_task(_: usize) {
    let me = azos_sched::current_task_tid();
    sleep_us(SETTLE_MS * 1_000);
    while !SERVING.load(Ordering::Acquire) {
        sleep_us(10_000);
    }
    let srv = SERVER_TID.load(Ordering::Acquire);
    // Read live, not assumed: the row is about one hart.
    let harts = (
        azos_sched::task_cpu_affinity(me).unwrap_or(-1),
        azos_sched::task_cpu_affinity(srv).unwrap_or(-1),
    );
    if harts.0 != HART || harts.1 != HART {
        kprintln!("[PIFAST] FAIL setup: client on {} server on {}, need both on {}",
                  harts.0, harts.1, HART);
        return;
    }
    let cap = match azos_ipc::endpoint::endpoint_named_cap(me, CapPerms::WRITE, ENDPOINT) {
        Some(c) => c.raw().0 as u64,
        None => {
            kprintln!("[PIFAST] FAIL setup: the client got no capability to the endpoint");
            return;
        }
    };

    let Some(mut quiet) = run_phase(cap, CALLS_QUIET, 1) else { DONE.store(true, Ordering::Release); return };
    let (q_max, q_p99) = stats(&mut quiet);
    kprintln!("[PIFAST] isa={} quiet calls={} max_ns={} p99_ns={}", isa(), CALLS_QUIET, q_max, q_p99);

    SERVER_BEST_PRIO.store(u64::MAX, Ordering::Relaxed);
    HOG_ON.store(true, Ordering::Release);
    // Let the hog start its first burst.
    sleep_us(HOG_REST_US);
    let Some(mut loaded) = run_phase(cap, CALLS_LOADED, 1 + CALLS_QUIET as u64) else {
        DONE.store(true, Ordering::Release);
        return;
    };
    HOG_ON.store(false, Ordering::Release);
    DONE.store(true, Ordering::Release);
    let over = loaded.iter().filter(|&&n| n > BOUND_NS).count();
    let worst_at = loaded.iter().enumerate().max_by_key(|&(_, &n)| n).map(|(i, _)| i).unwrap_or(0);
    let (l_max, l_p99) = stats(&mut loaded);
    let n = loaded.len();
    kprintln!("[PIFAST] isa={} loaded worst call={} next_ns={} {} {}", isa(), worst_at,
              loaded[n.saturating_sub(2)], loaded[n.saturating_sub(3)], loaded[n.saturating_sub(4)]);
    let bursts = HOG_BURSTS.load(Ordering::Relaxed);
    let best = SERVER_BEST_PRIO.load(Ordering::Relaxed);
    kprintln!("[PIFAST] isa={} loaded calls={} max_ns={} p99_ns={} over_bound={} hog_bursts={} server_prio_seen={} served={}",
              isa(), CALLS_LOADED, l_max, l_p99, over, bursts, best, SERVED.load(Ordering::Relaxed));
    if bursts == 0 {
        kprintln!("[PIFAST] FAIL hog never ran");
    } else if l_max <= BOUND_NS && best == CLIENT_PRIO as u64 {
        kprintln!("[PIFAST] PASS loaded max_ns={} <= bound_ns={}", l_max, BOUND_NS);
    } else {
        kprintln!("[PIFAST] FAIL loaded max_ns={} bound_ns={} ({} of {} calls over) server_prio_seen={} client_prio={}",
                  l_max, BOUND_NS, over, CALLS_LOADED, best, CLIENT_PRIO);
    }
}

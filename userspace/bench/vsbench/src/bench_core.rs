// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Shared measurement core for the Azos-vs-Linux comparison.
//!
//! **The whole point of this file is that there is only one of it.** The two
//! builds differ *only* in the `Abi` implementation they link against — same
//! loop bodies, same iteration counts, same arithmetic, same clock. Writing two
//! programs would compare two programmers; this compares two kernels.
//!
//! # The clock, and why `rdtime`
//!
//! Both sides read the RISC-V `time` CSR from user mode. Linux enables
//! `scounteren.TM` and so does this kernel (`latbench` already reads it from
//! ring 3), so it is the one clock available to both without going through a
//! syscall — which matters, because on Linux the obvious alternative
//! (`clock_gettime`) is served by the vDSO and would silently measure a
//! *different* mechanism on each side.
//!
//! # What these numbers mean, and what they do not
//!
//! Under QEMU TCG absolute nanoseconds are close to meaningless: emulation
//! taxes traps and atomics far more than arithmetic, and the two kernels do not
//! use them in the same proportion. **Ratios within a single run transfer;
//! nanoseconds across runs do not.** Every report therefore prints the raw
//! ticks and the per-op cost *relative to the syscall floor measured in that
//! same run*, which is the number worth comparing between the two sides.

#![allow(dead_code)]

/// Iterations per batch. Large enough that the 100 ns tick granularity is
/// noise against the total, small enough to finish under TCG.
pub const N: u64 = 2000;

/// Fewer iterations for batches whose per-op cost is orders of magnitude
/// higher (anything that touches a device or forks).
pub const N_SLOW: u64 = 64;

/// `time` CSR frequency on QEMU virt, both sides (RISC-V; see `scale_ticks`
/// for aarch64).
pub const TIMER_HZ: u64 = 10_000_000;

/// Counter ticks → nanoseconds, integer-only: `ticks * 1e9 / hz / iters`.
///
/// **The frequency is per ISA, and on aarch64 it is read, not assumed.** The
/// `TIMER_HZ` constant is RISC-V's `time` CSR on QEMU virt. aarch64's
/// `cntvct_el0` runs at whatever `CNTFRQ_EL0` says — 1 GHz under QEMU
/// `-cpu max` — and dividing it by RISC-V's 10 MHz made every aarch64 lane
/// read 100x too high (a 41,300-"instruction" syscall floor on 2026-09-22).
/// `CNTFRQ_EL0` is readable at EL0 whenever `cntvct_el0` is, which this
/// binary already relies on. RISC-V keeps its original expression unchanged.
#[inline(always)]
fn scale_ticks(ticks: u64, iters: u64) -> u64 {
    #[cfg(not(target_arch = "aarch64"))]
    { ticks * (1_000_000_000 / TIMER_HZ) / iters }
    #[cfg(target_arch = "aarch64")]
    {
        let hz: u64;
        unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) hz, options(nomem, nostack)) };
        // u128: at 1 GHz, `ticks * 1e9` overflows u64 after ~18 s of ticks.
        (ticks as u128 * 1_000_000_000 / hz.max(1) as u128 / iters.max(1) as u128) as u64
    }
}

#[inline(always)]
pub fn rdtime() -> u64 {
    let t: u64;
    // `nomem`/`nostack`: reads a CSR (RISC-V) or the generic timer's virtual
    // counter (aarch64 — `cntvct_el0`; see `crates/core/libsys/src/lib.rs`'s
    // `read_time_csr` for the same pairing), touches neither.
    #[cfg(target_arch = "riscv64")]
    unsafe { core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack)) };
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) t, options(nomem, nostack)) };
    t
}

/// Everything the core needs from the host kernel. One impl per side; nothing
/// else in this file is allowed to know which kernel it is running on.
pub trait Abi {
    /// The cheapest syscall that still crosses the ring boundary. This is the
    /// floor every other number is quoted against.
    /// `(voluntary, involuntary)` context switches this task has performed,
    /// or `None` if the kernel cannot say.
    ///
    /// **The unit is SWITCHES, not calls, on both sides**, and that is the
    /// whole reason this exists. `switch-loaded` divides a wall-clock total by
    /// a yield count and calls the result the cost of a context switch — which
    /// is only true if each yield switched. Linux answers from `getrusage`'s
    /// `ru_nvcsw`; AzOS from `SYS_TASKINFO`, which counts at the one place a
    /// task actually loses the CPU. A yield that found nothing better to run
    /// is in neither number, on either system.
    fn ctx_switches(&self) -> Option<(u64, u64)>;

    /// The hart (CPU) this task is running on, or `None` if the kernel cannot
    /// say. Linux answers from `getcpu`; AzOS from slot 4 of `SYS_TASKINFO`.
    /// Only ever read outside a measured batch.
    fn current_cpu(&self) -> Option<u64>;

    fn null_syscall(&self);
    /// Give up the CPU voluntarily.
    fn yield_now(&self);
    /// Write bytes to the console/stderr. Never called inside a measured
    /// batch — see the module doc.
    fn write(&self, bytes: &[u8]);
    /// The lane filter this run was given ([`Lanes`]); all lanes by default.
    fn lanes(&self) -> Lanes { Lanes::all() }
}

/// The lane filter (`VSBENCH_LANES`, wave 15): a comma list of section keys
/// that runs only those sections, on both sides, so one change can be
/// measured without the whole suite. Empty (the default) runs everything,
/// exactly as before. The floor, the unloaded yield and the closing floor
/// always run: every other number is quoted against them.
///
/// Keys: `ipc` (ipc-roundtrip and the ring/drv/frame lanes on its peer),
/// `mem`, `proc`, `thread`, `vdso`, `ioring`, `shell`, `timer`, `net`
/// (nic-egress, udp-roundtrip), `switch` (switch-loaded, yield-switch),
/// `disk` (file-write, file-wr+fsync; wave 15).
/// AzOS reads it from `/fat/VSBLANES.TXT`, Linux from its environment;
/// `tools/vsbench_compare.sh` puts it in both.
pub struct Lanes {
    buf: [u8; LANES_MAX],
    len: usize,
}

/// Longest `VSBENCH_LANES` value read; the script refuses a longer one.
pub const LANES_MAX: usize = 128;

impl Lanes {
    pub const fn all() -> Self { Lanes { buf: [0; LANES_MAX], len: 0 } }

    pub fn from_bytes(src: &[u8]) -> Self {
        let mut l = Lanes::all();
        for &b in src.iter().take(LANES_MAX) {
            if b == 0 || b == b'\n' || b == b'\r' { break; }
            if b == b' ' { continue; }
            l.buf[l.len] = b;
            l.len += 1;
        }
        l
    }

    /// Is the section `key` selected?
    pub fn on(&self, key: &[u8]) -> bool {
        if self.len == 0 { return true; }
        self.buf[..self.len].split(|&b| b == b',').any(|k| k == key)
    }

    pub fn is_all(&self) -> bool { self.len == 0 }
}

/// One measured batch: `iters` calls of `body`, returning elapsed ticks.
///
/// `#[inline(never)]` on purpose: the two builds must run the same shape of
/// loop, and letting the optimiser fold a trivial `body` into the timing
/// brackets on one side only would produce a difference that is an artefact of
/// inlining, not of the kernel.
#[inline(never)]
pub fn batch<F: FnMut()>(iters: u64, mut body: F) -> u64 {
    let t0 = rdtime();
    let mut i = 0u64;
    while i < iters {
        body();
        i += 1;
    }
    rdtime() - t0
}

/// Nanoseconds per operation, integer-only (neither build has an FPU).
pub fn ns_per_op(ticks: u64, iters: u64) -> u64 {
    // Ordered to avoid overflow and keep integer precision.
    scale_ticks(ticks, iters)
}

/// Cost relative to the syscall floor, in hundredths (so 250 = 2.50x).
/// This is the figure that survives the emulator.
pub fn rel_x100(ticks: u64, iters: u64, floor_ns: u64) -> u64 {
    if floor_ns == 0 { return 0; }
    ns_per_op(ticks, iters) * 100 / floor_ns
}

// ── IPC round trip ─────────────────────────────────────────────────────────
//
// The unit is one **request/response round trip between two tasks**, measured
// from the client. Not "one syscall": the two kernels do not spend the same
// number of syscalls per round trip, and that difference is the result rather
// than a flaw in the comparison. Azos merges request, block and
// reply-receive into a single `SYS_IPC_FAST_CALL`; a Linux pipe pair costs the
// client a `write` and a `read`. Quoting round trips against each side's own
// syscall floor is what makes those two shapes comparable.

/// Measured round trips.
pub const N_IPC: u64 = 500;

/// Round trips executed and thrown away before the measured batch.
///
/// Two jobs. **The startup race**: the parent can reach its first call before
/// the forked child has reached its first accept, and a client that gives up
/// returns failure — a measured batch that silently absorbed those would be
/// reporting failed calls as fast ones. **Warm-up**: in every run of this
/// harness so far the second floor measurement came out below the first, which
/// points at icache warm-up rather than random noise; a brand-new code path
/// deserves the same courtesy.
pub const N_IPC_WARM: u64 = 50;

/// Request word that tells the server to stop and exit.
///
/// **Why a sentinel rather than a shared count.** A shared count was the first
/// design and it is wrong here: the client's rendezvous retries mean the
/// number of round trips that actually reach the server is not known in
/// advance, so client and server would disagree and the last call would block
/// on a peer that had already exited. The sentinel makes termination an
/// explicit part of the protocol instead of something both sides infer.
/// **Defined in `serve.rs` and re-exported here**, not declared twice. The
/// server half runs in a different binary (`VSSRV.ELF`) that pulls that file
/// with `#[path]`; two declarations of the same protocol constant is exactly
/// how the two halves would drift apart.
pub use crate::ipc_proto::IPC_SENTINEL;

/// Safety bound on how many round trips the server will serve before giving
/// up and exiting on its own.
///
/// Belt and braces: the sentinel is what normally stops it, and this only
/// matters if the sentinel is lost — in which case the server exits instead of
/// spinning forever inside a benchmark run.
pub const N_IPC_TOTAL: u64 = (N_IPC_WARM + N_IPC) * 4;

/// How many times the client retries its first call while the freshly forked
/// child works its way to its first `accept`.
///
/// **This is a real race, not a hypothetical.** The parent returns from
/// `fork()` and can reach its first call before the child has been scheduled
/// at all; the kernel's fast-path call gives up rather than blocking forever
/// on a server that is not accepting yet. Retrying with a yield in between is
/// the rendezvous. It happens strictly **before** the measured batch — inside
/// it, a failure stays fatal.
pub const IPC_RENDEZVOUS_TRIES: u64 = 20_000;

/// Which side of the fork this process ended up on.
pub enum Role {
    /// Parent. Carries whatever the client needs to address the server —
    /// a TID on Azos, unused on Linux where the pipes are inherited fds.
    Client(u64),
    /// Child.
    Server,
}

/// The second half of the ABI: everything that needs a peer process.
///
/// Split from [`Abi`] so the single-task measurements stay usable on their own
/// — if the fork fails, floor and yield are still valid numbers.
pub trait Ipc {
    /// Fork. `Some(Role::Client)` in the parent, `Some(Role::Server)` in the
    /// child, `None` if the fork itself failed.
    ///
    /// Any shared state the two sides need (Linux's pipe fds) must be
    /// established **before** the fork returns: after it, the two address
    /// spaces are copy-on-write and neither can see the other's writes.
    fn spawn_peer(&self) -> Option<Role>;

    /// One round trip. `Err(code)` carries the kernel's own error so a
    /// failure can be diagnosed instead of guessed — never a substituted
    /// value, because a failed call is *fast* and would flatter the result.
    fn round_trip(&self, peer: u64, val: u64) -> Result<u64, i64>;

    /// Serve round trips until a request whose first word is [`IPC_SENTINEL`]
    /// arrives, then exit. `bound` caps the loop so a lost sentinel cannot
    /// hang the run. Never returns.
    fn serve(&self, bound: u64) -> !;
}

// ── Memory ─────────────────────────────────────────────────────────────────
//
// Two measurements, and they are deliberately different questions.
//
// **`mmap+munmap`** is bookkeeping: the kernel's cost to create and destroy an
// anonymous mapping, with no page ever touched. **`page-fault`** is the demand
// path: a region mapped once, then one byte written per page, so every
// iteration is a fault the kernel has to resolve by allocating and installing
// a frame.
//
// They are comparable across the two kernels because both demand-page
// anonymous memory rather than populating it at map time — Azos routes
// `mmap` through its `demand` module, Linux does the same for
// `MAP_ANONYMOUS`. If either side ever populated eagerly, the fault lane would
// be measuring nothing on that side and the two numbers would be unrelated.

/// Page size on both sides.
pub const PAGE: u64 = 4096;

/// `mmap`+`munmap` pairs per measured batch. Lower than [`N`] because each
/// iteration is two syscalls and real page-table work.
pub const N_MEM: u64 = 200;

/// Pages touched in the demand-fault batch. 512 pages = 2 MiB, comfortably
/// under any per-process cap on either side.
pub const N_FAULT_PAGES: u64 = 512;

/// Anonymous memory mapping, the half of the ABI that needs no peer.
pub trait Mem {
    /// Map `len` bytes of anonymous, readable, writable memory.
    fn map(&self, len: u64) -> Result<u64, i64>;
    /// Unmap what [`Mem::map`] returned.
    fn unmap(&self, base: u64, len: u64) -> Result<(), i64>;
}

/// How many times the client retries one round trip before giving up.
///
/// A failed fast call on Azos is not "IPC unavailable": it is the K-C10
/// spurious-wake backstop in `crates/core/syscall/src/dispatch.rs` returning -1
/// after `MAX_SPURIOUS_WAKES` turns, with the server still alive and still
/// willing to answer. Retrying is what a real caller does, so the measurement
/// does it too — and counts it, because a number that hides its own spin is
/// not a measurement.
pub const IPC_RETRY_BUDGET: u64 = 64;

/// Map-and-touch rounds. Each round maps [`N_FAULT_PAGES`] pages, writes one
/// byte in each, and unmaps; the report divides by the total pages.
pub const N_MEM_ROUNDS: u64 = 8;

// ── Tail latency ───────────────────────────────────────────────────────────
//
// **Why the mean is the wrong number for a robot.** Every lane above reports
// total ticks divided by iterations. That is the right way to compare
// mechanisms, and it is useless for the question a control loop actually asks:
// *what is the worst this can take?* A 40 Hz loop with a 25 ms budget does not
// care that the average syscall costs 2 us; it cares that one in a thousand
// costs 30 ms, because that one misses the deadline.
//
// This harness has already been bitten by exactly that. The spurious `-1` from
// fast-IPC happened on roughly 1 call in 30 and was **invisible in the mean** —
// it was found by hand, from a failing assertion, after hours. A tail
// measurement reports it on the first run.
//
// **Method.** Each operation is bracketed by `rdtime` and its delta is filed
// into a log2 histogram: bucket `k` holds deltas in `[2^k, 2^(k+1))` ticks. No
// allocation, 32 counters, and the resolution is coarse but the *shape* is
// what matters — a bimodal distribution or a decade-wide tail shows up
// unmistakably.
//
// **The overhead is real and deliberately symmetric.** Two `rdtime` reads per
// operation cost something (under TCG they are a helper call, not a CSR read),
// so these numbers are NOT comparable with the mean lanes above. They are
// comparable with the *same* lane on the other kernel, which is the whole
// point.

/// Number of octaves tracked. 32 octaves of timer ticks is far more range
/// than any syscall will ever need; anything above saturates into the top
/// bucket and is reported by `max` anyway.
const TAIL_OCTAVES: usize = 32;
/// Linear sub-buckets inside each octave.
///
/// **Why not plain log2.** The first version used one bucket per octave, and
/// on a tight distribution it reported `p50 == p99` for every lane — true, and
/// useless: it only said "99 % of samples are within a factor of two of the
/// median". Four sub-buckets bring the resolution to ~19 %, which is enough to
/// separate "predictable" from "has a shoulder".
const TAIL_SUB: usize = 4;
const TAIL_BUCKETS: usize = TAIL_OCTAVES * TAIL_SUB;

/// Histogram of per-operation latencies, in timer ticks.
pub struct Tail {
    /// Bucket `e * TAIL_SUB + m` holds deltas whose leading bit is `e` and
    /// whose next two bits are `m` — i.e. `[2^e * (4+m)/4, 2^e * (5+m)/4)`.
    pub buckets: [u32; TAIL_BUCKETS],
    pub min: u64,
    pub max: u64,
    pub n: u64,
}

impl Tail {
    pub const fn new() -> Self {
        Tail { buckets: [0; TAIL_BUCKETS], min: u64::MAX, max: 0, n: 0 }
    }

    fn bucket_of(d: u64) -> usize {
        if d < 4 { return d as usize; }
        let e = 63 - d.leading_zeros() as usize;       // floor(log2 d)
        // The two bits just below the leading one: d >> (e-2) is in [4,8).
        let m = ((d >> (e - 2)) & 3) as usize;
        (e * TAIL_SUB + m).min(TAIL_BUCKETS - 1)
    }

    /// Lower edge of bucket `k`, in ticks.
    fn edge_of(k: usize) -> u64 {
        if k < 4 { return k as u64; }
        let e = k / TAIL_SUB;
        let m = (k % TAIL_SUB) as u64;
        (1u64 << e) * (4 + m) / 4
    }

    fn record(&mut self, d: u64) {
        self.n += 1;
        if d < self.min { self.min = d; }
        if d > self.max { self.max = d; }
        self.buckets[Self::bucket_of(d)] += 1;
    }

    /// Lower edge of the bucket holding the `q`-th permille sample, in ticks.
    ///
    /// A *lower bound* on the true quantile, by construction: the bucket's
    /// lower edge, never its midpoint. Reporting the optimistic end of the
    /// bucket keeps this from ever overstating a tail.
    pub fn quantile_ticks(&self, permille: u64) -> u64 {
        if self.n == 0 { return 0; }
        let target = self.n * permille / 1000;
        let mut seen = 0u64;
        for (k, c) in self.buckets.iter().enumerate() {
            seen += *c as u64;
            if seen >= target { return Self::edge_of(k); }
        }
        self.max
    }
}

/// Run `body` `iters` times, timing each call individually.
///
/// `#[inline(never)]` for the same reason as [`batch`]: the compiler must not
/// hoist the measured work out of the loop.
#[inline(never)]
pub fn batch_tail<F: FnMut()>(iters: u64, mut body: F) -> Tail {
    let mut t = Tail::new();
    for _ in 0..iters {
        let a = rdtime();
        body();
        let b = rdtime();
        t.record(b.wrapping_sub(a));
    }
    t
}

/// Ticks → ns, for a single sample rather than a batch average.
pub fn ticks_to_ns(ticks: u64) -> u64 {
    #[cfg(not(target_arch = "aarch64"))]
    { ticks * 1_000_000_000 / TIMER_HZ }
    #[cfg(target_arch = "aarch64")]
    { scale_ticks(ticks, 1) }
}

// ── Heap growth and process creation ───────────────────────────────────────

/// `brk` steps per batch. Each grows the heap by one page.
pub const N_BRK: u64 = 200;

/// fork + immediate child exit + parent reap, per batch. Low because process
/// creation is the most expensive thing either kernel does here.
pub const N_PROC: u64 = 40;

/// The two lanes that were used but never measured.
///
/// `fork` in particular: the IPC lane has been forking a peer since the first
/// version and throwing the cost away. Creating and destroying a process is
/// among the most expensive operations either kernel offers, it is directly
/// comparable, and it was invisible.
pub trait Proc {
    /// Move the program break by `delta` bytes. `Err` on refusal.
    ///
    /// Measured as *growth*, never shrink-and-regrow: a kernel that keeps the
    /// pages on shrink would answer the second `brk` for free and the lane
    /// would be timing bookkeeping instead of allocation.
    fn brk_grow(&self, delta: u64) -> Result<u64, i64>;

    /// Fork a peer. `Some(true)` in the child, `Some(false)` in the parent,
    /// `None` if the fork failed. Unlike [`Ipc::spawn_peer`], the child
    /// **returns** to do its own work rather than being handed a role.
    fn spawn_peer_raw(&self) -> Option<bool>;

    /// Terminate the child process. Never returns.
    fn exit_child(&self) -> !;

    /// Fork; the child exits immediately; the parent waits for THAT child
    /// and reaps it before returning. The full cycle: fork, the child's
    /// exit (its teardown included), the reap.
    ///
    /// **The child's exit is inside the caller's timed window by
    /// construction (wave 14).** This returns `Ok` only once a targeted,
    /// non-blocking reap of the child it just made has answered with that
    /// child's id, i.e. after the kernel finished the child's exit; anything
    /// else is an `Err`, and a failed lane reports no number. Until wave 14
    /// it polled ONCE for any finished child and returned: the child it had
    /// just made usually ran after the parent's poll, and on a kernel whose
    /// scheduler kept the parent running (the gate's `bench-minimal` build)
    /// the children ran after the timed batch, so the lane read ~68k
    /// instructions of fork without any exit in it, while the same lane on
    /// the default build carried most exits. Not a number to compare.
    ///
    /// It is the same operation as [`fork_exit_wait`](Proc::fork_exit_wait)
    /// (each side's own targeted `WNOHANG` poll with a yield between looks,
    /// for the reasons given there), and implemented by it. The two lanes
    /// are kept as a repeat of each other: their difference is run-to-run
    /// noise, nothing else.
    fn fork_exit(&self) -> Result<(), i64>;

    /// Fork; the child exits; **the parent reaps it**. The full life cycle.
    ///
    /// # The comparison this lane has to earn
    ///
    /// The easy version would be `wait4` on Linux against `wait` on Azos,
    /// and it would be a false comparison of exactly the shape the vDSO lane
    /// below refuses: Linux's `wait4` BLOCKS by default and Azos's `wait` is
    /// `WNOHANG` and cannot block at all. Timing one against the other pits a
    /// sleep against a spin and produces a spectacular, meaningless number.
    ///
    /// So both sides poll with `WNOHANG` and yield between attempts. That is
    /// the same operation on both, and it is the operation Azos actually
    /// offers.
    ///
    /// # What the number contains, stated because it is not only syscall cost
    ///
    /// The poll loop runs until the child has actually died and been reaped,
    /// so this measures fork + the scheduler getting round to the child + exit
    /// + reap. It is scheduler-dependent on BOTH sides. Since wave 14
    /// [`fork_exit`](Proc::fork_exit) is this same operation (it used to stop
    /// before the child's exit, see there).
    ///
    /// # Sentinels differ, and conflating them would hide a failure
    ///
    /// "No child has finished yet" is `0` from Linux's `wait4(WNOHANG)` and
    /// `-1` from Azos's `wait`. A shared "not positive means keep waiting"
    /// test would also swallow Linux's `-1` (a real error, e.g. no children at
    /// all) as if it were "not yet", and the lane would spin to its bound and
    /// report a large number instead of a failure. Each implementation checks
    /// its own sentinel.
    fn fork_exit_wait(&self) -> Result<(), i64>;
}

// ── vDSO ───────────────────────────────────────────────────────────────────
//
// **The only lane that measures what it costs NOT to enter the kernel.**
// Everything else here times traps. Both systems offer the same idea — a
// read-only page the kernel publishes and the program reads without an
// `ecall` — and until now the harness was blind to it.
//
// **The honest comparison, and the trap it avoids.** The easy route would have
// been to call `clock_gettime` as a syscall on the Linux side. That would pit
// our page read against their **trap**, and produce a spectacular, false
// number. `__vdso_clock_gettime` has to be resolved for real, which without
// libc means reading the auxiliary vector and parsing the vDSO ELF by hand.
//
// **An asymmetry worth stating**: the Linux vDSO returns a `timespec`
// (seconds + nanoseconds), so it does the conversion arithmetic. Ours now does
// the same via `vdso_now_ns`, so the two deliver the same product — that was
// not true of the first version, which served a value with 10 ms granularity.

/// vDSO clock reads per measured batch.
pub const N_VDSO: u64 = 2000;

/// Spawns per `spawn+wait` batch: as [`N_PROC`], process start is the
/// expensive end of what either kernel does here.
pub const N_SPAWN: u64 = 40;
/// The sleep between two reap polls of `spawn+wait`, both sides. A sleep,
/// not a yield: AzOS starts the child at its own row's priority (TOOLBOX.ELF
/// is `best_effort`, 26) below the bench's 16, and a yield never hands the
/// hart down (measured: the first version, polling with yields, never saw
/// the child finish on `-smp 1`). Linux sleeps the same way so both reaps
/// are one operation.
pub const SPAWN_NAP_NS: u64 = 50_000;
/// Write-then-read round trips per `pipe-rw` batch.
pub const N_PIPE: u64 = 2000;
/// Create-and-close pairs per `pipe+close` batch.
pub const N_PIPE_OPEN: u64 = 400;
/// Bytes per `pipe-rw` round trip: one small message, under both kernels'
/// atomic-write bound (AzOS `PIPE_ATOMIC`, Linux `PIPE_BUF`).
pub const PIPE_MSG: usize = 64;

/// Wave 12: the user shell's two primitives — starting a program by path,
/// and the pipe between two of them — on both kernels.
///
/// **Process start is posix_spawn's shape on both sides**, not fork's: no
/// copy of the caller's address space. AzOS: `SYS_SPAWN_EX` (608) of
/// `TOOLBOX.ELF` as `true` (argv[0]), which reads, hashes (the seccomp
/// digest binding) and loads the image. Linux: `clone(CLONE_VM |
/// CLONE_VFORK)` + `execve` of this binary with `--exit` — glibc's
/// `posix_spawn`. Both reap with WNOHANG polls and a [`SPAWN_NAP_NS`] sleep
/// between them. The images differ (Linux has no toolbox):
/// read the two numbers with their sizes beside them.
///
/// **The pipe** is used within one task (write, then read the same bytes
/// back), so the lane prices the two syscalls and the copy, not a wake-up.
/// Threads of one process (wave 13): the primitives the thread lanes are
/// built from, the same operations on both sides. AzOS: `SYS_THREAD_CREATE`
/// / `SYS_THREAD_EXIT` / `SYS_FUTEX_WAIT` / `SYS_FUTEX_WAKE`. Linux: raw
/// `clone(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
/// CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID)`, `exit`, and
/// private `futex` — what musl's `pthread_create`/`pthread_join` reduce to.
/// Associated functions, not methods: the thread bodies call them with no
/// handle on the ABI value.
pub trait Threads {
    /// Start `entry` as a thread of this process on the stack whose 16-byte
    /// aligned top is `stack_top`. `ctid` holds a non-zero value until the
    /// thread's exit clears it (and wakes it). Its TID, or a negative error.
    fn thread_spawn(entry: extern "C" fn() -> !, stack_top: usize, ctid: &'static core::sync::atomic::AtomicU32) -> i64;
    /// End the calling thread only.
    fn thread_exit() -> !;
    /// Wait while `*w == val` (no timeout).
    fn futex_wait(w: &core::sync::atomic::AtomicU32, val: u32) -> i64;
    /// Wake at most `n` waiters on `w`.
    fn futex_wake(w: &core::sync::atomic::AtomicU32, n: u32) -> i64;
    /// Wait while a thread's clear-tid word `w` holds `val`: the word its exit
    /// clears and wakes. Linux wakes it with a SHARED futex wake, which a
    /// private waiter does not see (the keys differ), so the join waits
    /// shared there; AzOS has one kind.
    fn join_wait(w: &core::sync::atomic::AtomicU32, val: u32) -> i64;
}

/// Iterations of the thread lanes.
pub const N_THR: u64 = 200;

pub trait Shell {
    /// Start the side's exit-at-once program and reap it. `Err` carries the
    /// errno, or a `-200x` code from the reap loop.
    fn spawn_wait(&self) -> Result<(), i64>;
    /// A new pipe: `(read end, write end)`.
    fn pipe_open(&self) -> Result<(u64, u64), i64>;
    /// Write `buf` into `w`, then read the same number of bytes from `r`.
    fn pipe_rw(&self, r: u64, w: u64, buf: &mut [u8]) -> Result<(), i64>;
    /// Close both ends.
    fn pipe_close(&self, r: u64, w: u64);
    /// One `read` on a descriptor: bytes read, or a negative error (AzOS
    /// answers an empty pipe with `-EAGAIN`-class codes; callers retry).
    fn fd_read(&self, fd: u64, buf: &mut [u8]) -> isize;
    /// One `write` on a descriptor: bytes written, or a negative error.
    fn fd_write(&self, fd: u64, buf: &[u8]) -> isize;
    /// Close one end of a pipe from [`Shell::pipe_open`].
    fn fd_close(&self, fd: u64);
    /// Round 48: open the side's own executable read-only, read 64 bytes,
    /// close it (AzOS `/fat/VSBENCH.ELF` through `Cap<File>` 563/564/566;
    /// Linux `/init`, the same binary in its initramfs, `openat`/`read`/
    /// `close`). The descriptor table's open file description is on this path.
    fn file_open_read_close(&self, buf: &mut [u8]) -> Result<(), i64>;
    /// Round 48: `dup` a held descriptor and close the duplicate (two
    /// descriptors on one description). Wave 13: timed on AzOS too, as
    /// the NATIVE `dup` is: libsys aliasing a handle in its small-fd table
    /// (owner decision 38, no kernel `dup`), with no trap on either call —
    /// against Linux's two syscalls. `None` where a side offers no `dup`.
    fn file_dup_close(&self, fd: u64) -> Option<Result<(), i64>>;
    /// The descriptor `file_dup_close` duplicates: the side's executable,
    /// opened read-only; closed with `pipe_close(fd, fd)`'s single half.
    fn file_hold(&self) -> Result<u64, i64>;
    fn file_release(&self, fd: u64);
    /// Wave 13: create the side's RAM-backed 64-byte file for `tmp-ord`
    /// (AzOS `/tmp/VSB.TMP`, ramfs, through the autorun row's `/tmp` tree
    /// grant; Linux `/vsb.tmp` in its initramfs root). Once, untimed.
    fn tmp_setup(&self) -> Result<(), i64>;
    /// Wave 13: open that file read-only, read its 64 bytes, close it — the
    /// open file description's whole life with no disk under it. `file-ord`
    /// reads `/fat` on AzOS (FAT32 over virtio-blk) and the initramfs on
    /// Linux, so its gap is mostly the disk; this lane is RAM on both sides.
    fn tmp_open_read_close(&self, buf: &mut [u8]) -> Result<(), i64>;
    /// Wave 15: make the side's DISK file system writable (AzOS: `/fat`,
    /// FAT32 over virtio-blk, nothing to do; Linux: devtmpfs, then the same
    /// kind of FAT32 image on its own virtio-blk disk mounted `vfat` at
    /// `/mnt`). Once, untimed.
    fn disk_setup(&self) -> Result<(), i64>;
    /// Wave 15 `file-write`: create-or-truncate the disk file, write `data`,
    /// `fsync` it when asked, close it.
    fn disk_write_close(&self, data: &[u8], fsync: bool) -> Result<(), i64>;
}

/// `file-write`: iterations of create/truncate + write 4 KiB + close.
pub const N_DISK: u64 = 40;
/// Bytes per `file-write` iteration.
pub const DISK_WRITE_BYTES: usize = 4096;

/// `file-ord`: iterations of open + read 64 B + close.
pub const N_FILE: u64 = 200;
/// `file-dup`: iterations of dup + close.
pub const N_DUP: u64 = 400;

/// Operations **each system offers by two paths**: the vDSO page and the trap.
///
/// The figure that matters is not what each path costs on its own but their
/// **ratio**: what the vDSO buys on that system. That ratio *is* comparable
/// across kernels, because it cancels the cost of the trap, which differs on
/// each.
///
/// `None` means "this system does not offer this operation by this path", and
/// is reported as such. That is information: the Linux vDSO serves
/// `clock_gettime`, `gettimeofday`, `clock_getres` and `getcpu`; ours serves
/// the clock and the kernel version, and nothing else.
pub trait Vdso {
    /// `false` if the vDSO could not be located. Then no number is reported,
    /// rather than one that would measure something else.
    fn vdso_ready(&self) -> bool;

    /// Clock, via the page.
    fn clock_vdso(&self) -> u64;
    /// The same clock, via the trap.
    fn clock_syscall(&self) -> u64;

    /// CPU identity, via the page. `None` if not offered.
    fn cpu_vdso(&self) -> Option<u64>;
    /// The same identity, via the trap. `None` if not offered.
    fn cpu_syscall(&self) -> Option<u64>;
}

// ── Context switching under load ───────────────────────────────────────────
//
// **Why `sched-yield` is not enough.** That lane yields the CPU with a single
// runnable task: the scheduler looks, finds nothing better, and returns. It is
// the cost of the *mechanism*, and it is the easy case.
//
// What decides whether a control loop meets its deadline is something else:
// **how long it takes to run again when other tasks are ready**. That covers
// selection, a real context switch, and the dispatch policy — which is exactly
// where the two schedulers make different choices.
//
// This lane measures that: with `N_LOAD_PEERS` runnable competitors, the cost
// per yield from one task's point of view.

/// Runnable competitors during the measurement. Four resembles a robot's
/// profile — control loop, sensors, telemetry, network — without saturating.
pub const N_LOAD_PEERS: u64 = 4;

/// Yields measured with the competitors running.
pub const N_LOAD_YIELDS: u64 = 500;

/// Yields each competitor performs before exiting.
///
/// It has to **outlive the measurement**: if a competitor finishes early the
/// load drops mid-batch and the number blends two regimes. Deliberately
/// oversized — one competitor exiting late spoils nothing, one exiting early
/// does.
pub const N_LOAD_PEER_ITERS: u64 = 200_000;

/// Yields the measurer spends before its batch, so every competitor has run
/// its prelude (the timestamp buffer below is touched there, its page faults
/// included) and is genuinely in the ready queue. One used to be assumed
/// enough, which presumes the very round-robin order the lane is testing.
pub const N_LOAD_WARMUP: u64 = 8;

/// Yields each competitor timestamps (one `u32` tick delta per yield).
///
/// **The instrument behind `yield-switch` (wave 15).** The measurer's own
/// counter says only that IT switched on every yield; how many competitor
/// yields ran between two of its yields is what decides what one
/// `switch-loaded` op contains, and the two schedulers need not agree on it.
/// Each competitor stamps its first `N_LOAD_PEER_STAMPS` yields, learns the
/// measurer's window afterwards through a pipe, and reports how many of its
/// yields returned inside it. Sized far above the ~`N_LOAD_YIELDS` a fair
/// round-robin gives each competitor; a count that does not reach the end of
/// the window is reported as a lower bound, never silently. 16 KiB per
/// competitor, touched before its first yield. Identical work on both sides:
/// one counter read and one store per competitor yield.
pub const N_LOAD_PEER_STAMPS: usize = 4096;

// ── Network: local UDP round trip ──────────────────────────────────────────
//
// **The lane that was blocked from the start.** It needed three things this
// kernel did not have: local delivery (a destination equal to our own IP went
// to the wire and died in ARP), `connect` on UDP (TCP only), and `send` on UDP
// (likewise). All three are in place now, so the comparison is possible.
//
// **Why UDP and not TCP.** With TCP we would be comparing congestion
// algorithms, Nagle and window sizes — design choices, not the cost of the
// mechanism. A datagram out and back measures the stack: syscall, IP,
// delivery, and waking the receiver.
//
// **Why local and not over the wire.** With a NIC in the path we would be
// measuring the emulated driver and the host bridge, which belong to neither
// kernel.

/// Round trips measured. Low because each is four syscalls and two wakes.
pub const N_NET: u64 = 200;

/// After this many tries with nothing received, give up. Each turn yields the
/// CPU, so the budget is in yields, not time: under a loaded emulator a
/// wall-clock deadline would produce false negatives.
pub const NET_POLL_BUDGET: u64 = 200_000;

/// Bytes per datagram. Deliberately small: what matters is the cost of the
/// path, not of the copy.
pub const NET_PAYLOAD: usize = 32;

/// The byte of [`Net::net_stop_echo`]'s datagram; the measured payload is
/// `0xA5`, so the echo can tell them apart by the first byte.
pub const NET_STOP: u8 = 0x5A;

/// UDP round trip against a local peer.
pub trait Net {
    /// `false` if the system cannot set the pair up; then no number is
    /// reported.
    fn net_ready(&self) -> bool;

    /// Set the pair up: create the local socket bound to `local_port` and
    /// connect it to the peer at `peer_port`.
    /// `Err(code)` names **which step** failed, not merely that one did:
    /// -1 no IP, -2 socket, -3 bind, -4 connect. Collapsing them into `false`
    /// forces a whole extra run to find out which; that already happened with
    /// the IPC lane.
    fn net_setup(&self, local_port: u16, peer_port: u16) -> Result<(), i64>;

    /// Send `NET_PAYLOAD` bytes and wait for the reply. `None` if it did not
    /// arrive within budget.
    fn net_round_trip(&self) -> Option<usize>;

    /// Echo side: receive and send back, `n` times. For the child.
    fn net_echo(&self, n: u64);

    /// Stop the echo started by [`Net::net_echo`]: one datagram whose bytes
    /// are all [`NET_STOP`]. Wave 15: the echo used to outlive the lane,
    /// polling `recv` + yield, and sat in `switch-loaded`'s window as a
    /// sixth runnable task on BOTH kernels (AzOS's `SWITCH_CENSUS` named its
    /// slot; on Linux the measurer's switches outnumbered the competitors'
    /// yields by ~250 of 500).
    fn net_stop_echo(&self);

    /// NIC egress lane: a UDP socket connected to the limited broadcast
    /// `255.255.255.255:9` (discard). Broadcast needs no ARP, so the lane
    /// never depends on received frames being processed. `Err` as for
    /// `net_setup`. Default: not implemented, no number.
    fn egress_setup(&self) -> Result<(), i64> { Err(-1) }

    /// Send one `NET_PAYLOAD`-byte datagram on the egress socket. `false`
    /// when the kernel refused it (no NIC, or its TX ring was full).
    fn egress_send(&self) -> bool { false }
}

/// Datagrams timed by the NIC egress lane. Each one leaves through the NIC:
/// syscall, UDP/IP, and the driver's descriptor + notify.
pub const N_EGRESS: u64 = 1000;

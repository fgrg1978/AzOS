// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `vsbench` — the same ring-3 workload, measured on Azos and on Linux.
//!
//! Build for Azos:  `cargo build --release --features azos`
//! Build for Linux:   `cargo build --release --features linux
//!                     --target riscv64gc-unknown-linux-gnu` (or musl)
//!
//! Exactly one feature must be on. The two builds share `bench_core.rs`
//! verbatim; only the `Abi` impl differs.
//!
//! # Reading the output
//!
//! Every line reports ns/op **and** a multiple of that run's own syscall
//! floor. Compare the multiples between the two sides. The nanoseconds are
//! only meaningful within one run on one host, because QEMU TCG does not tax
//! all instruction classes equally and the two kernels do not use them in the
//! same mix.

#![cfg_attr(feature = "azos", no_std)]
#![cfg_attr(feature = "azos", no_main)]
#![cfg_attr(feature = "linux", no_std)]
#![cfg_attr(feature = "linux", no_main)]

mod bench_core;
/// The wire protocol, shared with `userspace/bench/vssrv` through `#[path]`. The
/// server LOOP is deliberately not declared here — see `ipc_proto.rs`.
mod ipc_proto;
use bench_core::{
    batch, batch_tail, ns_per_op, rel_x100, ticks_to_ns, Abi, Ipc, Mem, Net, Proc, Role, Shell, Tail,
    Threads, N_THR,
    Vdso, N_DUP, N_FILE, N_PIPE, N_PIPE_OPEN, N_SPAWN, PIPE_MSG, N_DISK, DISK_WRITE_BYTES,
    IPC_RENDEZVOUS_TRIES, IPC_RETRY_BUDGET, IPC_SENTINEL, N,
    N_BRK, N_FAULT_PAGES, N_IPC, N_IPC_TOTAL, N_IPC_WARM, N_MEM, N_MEM_ROUNDS, N_PROC,
    N_EGRESS, N_LOAD_PEERS, N_LOAD_PEER_ITERS, N_LOAD_PEER_STAMPS, N_LOAD_WARMUP, N_LOAD_YIELDS, N_NET, N_SLOW, N_VDSO, PAGE,
    TCP_BULK_BYTES, TCP_CHUNK, TCP_CMD_RX, TCP_CMD_TX, TCP_DONE, TCP_STALL_NS,
};

#[cfg(feature = "azos")]
mod abi_azos;
#[cfg(feature = "linux")]
mod abi_linux;

#[cfg(all(feature = "azos", feature = "linux"))]
compile_error!("pick exactly one of `azos` / `linux`: the point is one core, one ABI");
#[cfg(not(any(feature = "azos", feature = "linux")))]
compile_error!("pick one of `azos` / `linux`");

#[cfg(feature = "azos")]
const SIDE: &[u8] = b"azos";
#[cfg(feature = "linux")]
const SIDE: &[u8] = b"linux";

fn put_i(abi: &impl Abi, n: i64) {
    if n < 0 { abi.write(b"-"); put_u(abi, n.unsigned_abs()); } else { put_u(abi, n as u64); }
}

fn put_u(abi: &impl Abi, mut n: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    if n == 0 { i -= 1; buf[i] = b'0'; }
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    abi.write(&buf[i..]);
}

/// One line: `[VSBENCH] <side> <label> = <ns> ns/op (<x.xx>x floor)`.
///
/// Printed strictly outside every measured batch — a UART write costs ~160 us
/// per 64 bytes under QEMU, which would swamp any batch it landed inside.
fn report(abi: &impl Abi, label: &[u8], ticks: u64, iters: u64, floor_ns: u64) {
    abi.write(b"[VSBENCH] ");
    abi.write(SIDE);
    abi.write(b" ");
    abi.write(label);
    abi.write(b" = ");
    put_u(abi, ns_per_op(ticks, iters));
    abi.write(b" ns/op (");
    let r = rel_x100(ticks, iters, floor_ns);
    put_u(abi, r / 100);
    abi.write(b".");
    let frac = r % 100;
    if frac < 10 { abi.write(b"0"); }
    put_u(abi, frac);
    abi.write(b"x floor)\n");
}


/// One round trip, retried through the spurious-failure budget.
///
/// Every caller uses this — rendezvous, warm-up and the measured batch — so
/// all three speak the same protocol. Measuring with retries while warming up
/// without them is how a benchmark reports "warm-up FAILED" for a system that
/// works exactly as designed.
fn rt_retry(abi: &(impl Abi + Ipc), peer: u64, val: u64, spurious: &mut u64) -> Result<(), i64> {
    let mut last = 0i64;
    for _ in 0..IPC_RETRY_BUDGET {
        match abi.round_trip(peer, val) {
            Ok(v) => { core::hint::black_box(v); return Ok(()); }
            Err(code) => { last = code; *spurious += 1; }
        }
    }
    Err(last)
}

/// The IPC round trip, and the failure handling that keeps it honest.
///
/// **A failed round trip is never counted.** A call that fails is *fast* —
/// far faster than one that actually reaches a peer and comes back — so
/// absorbing failures into the batch would report a wonderful number for a
/// benchmark that measured nothing. Any failure suppresses the line entirely
/// and says so. No number is much better than a wrong one.
fn ipc_roundtrip(abi: &(impl Abi + Ipc), floor_ns: u64) -> Option<u64> {
    let peer = match abi.spawn_peer() {
        // The child never comes back: it serves exactly the shared count and
        // exits. Client and server counts both come from N_IPC_TOTAL.
        Some(Role::Server) => abi.serve(N_IPC_TOTAL),
        Some(Role::Client(p)) => p,
        None => {
            abi.write(b"[VSBENCH] ipc-roundtrip: fork failed, skipped\n");
            return None;
        }
    };

    // Rendezvous. The parent can return from fork() and reach its first call
    // before the child has been scheduled at all, and the kernel's fast call
    // gives up rather than blocking on a server that is not accepting yet.
    // Retry with a yield until the child answers.
    let mut up = false;
    for _ in 0..IPC_RENDEZVOUS_TRIES {
        if abi.round_trip(peer, 0).is_ok() { up = true; break; }
        abi.yield_now();
    }
    if !up {
        abi.write(b"[VSBENCH] ipc-roundtrip: peer never answered, no number\n");
        return None;
    }

    // Warm-up, unmeasured: warms the icache on a brand-new code path. In every
    // run of this harness the second floor came out below the first, which
    // points at warm-up rather than random noise.
    let mut spurious = 0u64;
    for i in 0..N_IPC_WARM {
        if let Err(code) = rt_retry(abi, peer, i, &mut spurious) {
            abi.write(b"[VSBENCH] ipc-roundtrip: warm-up exhausted retries at i=");
            put_u(abi, i);
            abi.write(b" rc=");
            put_i(abi, code);
            abi.write(b", no number reported\n");
            return None;
        }
    }
    // Retries spent warming up are not part of the measured rate.
    spurious = 0;

    // **Failures here are retried, not fatal, and they are counted.**
    //
    // A `-1` from this kernel's fast call does not mean IPC is unavailable: it
    // is the K-C10 backstop in `dispatch.rs` giving up after
    // `MAX_SPURIOUS_WAKES` turns, or a momentary slot shortage. The server is
    // alive and will answer the next attempt. A caller is expected to retry,
    // so the honest cost of N completed round trips includes those retries —
    // and the count is printed so the reader can see how much of the number is
    // spin rather than work.
    let mut gave_up = 0i64;
    // Switch counts around the timed batch, for the same reason as
    // `switch-loaded`: a round trip through a BLOCKING primitive should cost
    // two context switches, and if a kernel finds a way to serve it without
    // switching then its number is not comparable with one that did.
    //
    // This lane is where the comparison actually lives. `switch-loaded` cannot
    // provide it: measured 2026-09-11, AzOS switched on 500 of 500 yields
    // and Linux on 0 of 500, because `sched_yield` re-elects the running task
    // when nothing else is runnable on its CPU. Here both sides must block.
    let ipc_sw_before = abi.ctx_switches();
    let ticks = batch(N_IPC, || {
        if let Err(code) = rt_retry(abi, peer, 1, &mut spurious) { gave_up = code; }
    });

    // The tail of the round trip, which is where this harness has been bitten
    // before: the spurious `-1` was ~1 call in 30 and left no trace in the
    // mean.
    let mut tail_spurious = 0u64;
    let tail_rt = batch_tail(N_IPC, || {
        let _ = rt_retry(abi, peer, 1, &mut tail_spurious);
    });
    report_tail(abi, b"ipc-rt ", &tail_rt);

    // The server is released by the caller ([`release_peer`]) once the ring
    // lanes, which reuse it, are done. Nothing measured moved: both the
    // batches above and the lines below are unchanged.

    if gave_up != 0 {
        abi.write(b"[VSBENCH] ipc-roundtrip: retry budget exhausted rc=");
        put_i(abi, gave_up);
        abi.write(b", no number\n");
    } else {
        report(abi, b"ipc-roundtrip", ticks, N_IPC, floor_ns);
        match (ipc_sw_before, abi.ctx_switches()) {
            (Some((v0, i0)), Some((v1, i1))) => {
                let total = (v1 - v0) + (i1 - i0);
                abi.write(b"[VSBENCH] ");
                abi.write(SIDE);
                abi.write(b" ipc-roundtrip switches = ");
                put_u(abi, total);
                abi.write(b" over ");
                put_u(abi, N_IPC);
                abi.write(b" round trips");
                if total > 0 {
                    abi.write(b", ");
                    put_u(abi, ticks_to_ns(ticks) / total);
                    abi.write(b" ns per SWITCH");
                }
                abi.write(b"\n");
            }
            _ => {}
        }
        abi.write(b"[VSBENCH] ipc-retries = ");
        put_u(abi, spurious);
        abi.write(b" spurious failures over ");
        put_u(abi, N_IPC);
        abi.write(b" round trips\n");
    }
    Some(peer)
}

/// Stop the `ipc-roundtrip` server with the sentinel, so it exits cleanly
/// rather than being left blocked when this process does.
///
/// **Retried, and a failure is printed (wave 15).** It was one unchecked
/// call, and a spurious `-1` (the K-C10 backstop, see [`rt_retry`]) would
/// have left the server behind without a word. Not what put a sixth task in
/// `switch-loaded`'s window (that was the UDP echo, see
/// [`Net::net_stop_echo`]): a census boot with no release at all shows this
/// server blocked, outside the round-robin.
fn release_peer(abi: &(impl Abi + Ipc), peer: u64) {
    let mut spurious = 0u64;
    if let Err(code) = rt_retry(abi, peer, IPC_SENTINEL, &mut spurious) {
        abi.write(b"[VSBENCH] ipc server NOT released rc=");
        put_i(abi, code);
        abi.write(b": it stays runnable under every later lane\n");
    }
}

/// The two memory lanes: mapping bookkeeping, and the demand-fault path.
fn mem_lanes(abi: &(impl Abi + Mem), floor_ns: u64) {
    // 1. Create and destroy a one-page anonymous mapping. No page is ever
    //    touched, so this is pure kernel bookkeeping -- VMA insertion and
    //    removal, not page allocation.
    let mut failed = false;
    let t_map = batch(N_MEM, || {
        match abi.map(PAGE) {
            Ok(base) => {
                if abi.unmap(base, PAGE).is_err() { failed = true; }
            }
            Err(_) => failed = true,
        }
    });
    if failed {
        abi.write(b"[VSBENCH] mmap+munmap: FAILED, no number\n");
    } else {
        report(abi, b"mmap+munmap  ", t_map, N_MEM, floor_ns);
    }

    // 2. Cost per *usable* page: map a region and write one byte in every
    //    page, both inside the measurement.
    //
    //    **This replaces a page-fault lane that was measuring nothing.** That
    //    lane mapped outside the batch and touched inside it, which assumes
    //    both kernels demand-page anonymous memory. Linux does; this one does
    //    not -- `sys_mmap` in `crates/core/syscall/src/handlers.rs` walks the range
    //    calling `pmm::alloc_page()` and `vmm::map()` with ACCESSED|DIRTY
    //    already set, so every page is resident before ring 3 runs again and
    //    the "faults" were plain stores. It reported 0.14x the syscall floor —
    //    cheaper than a syscall, which is the tell: no trap happened.
    //
    //    Measuring map-and-touch together is fair to both designs: it asks
    //    what it costs to obtain memory you can actually use, and lets each
    //    kernel pay for that wherever it chooses to. Eager population is a
    //    defensible choice for a robot -- it moves the cost out of the control
    //    loop, where an unexpected fault is a missed deadline -- but it is a
    //    different design, not a faster one, and the number has to say so.
    let len = N_FAULT_PAGES * PAGE;
    let mut failed_touch = false;
    let t_ready = batch(N_MEM_ROUNDS, || {
        match abi.map(len) {
            Err(_) => failed_touch = true,
            Ok(base) => {
                let mut page = 0u64;
                while page < N_FAULT_PAGES {
                    // `write_volatile` so the compiler cannot elide the store
                    // that is the entire point of the measurement.
                    unsafe { core::ptr::write_volatile((base + page * PAGE) as *mut u8, 1) };
                    page += 1;
                }
                if abi.unmap(base, len).is_err() { failed_touch = true; }
            }
        }
    });
    if failed_touch {
        abi.write(b"[VSBENCH] map+touch: FAILED, no number\n");
    } else {
        report(abi, b"map+touch/pg ", t_ready, N_MEM_ROUNDS * N_FAULT_PAGES, floor_ns);
    }
}

/// One tail line: `p50`, `p99` and the worst single sample.
///
/// The **p99 / p50 ratio** is the number to read. A mechanism whose 99th
/// percentile sits near its median is predictable; one where it sits a decade
/// away will miss deadlines under load no matter how good its average looks.
/// For a control loop that ratio matters more than the mean the lanes above
/// report.
fn report_tail(abi: &impl Abi, label: &[u8], t: &Tail) {
    abi.write(b"[VSBENCH] ");
    abi.write(SIDE);
    abi.write(b" tail ");
    abi.write(label);
    abi.write(b" p50=");
    put_u(abi, ticks_to_ns(t.quantile_ticks(500)));
    abi.write(b" p99=");
    put_u(abi, ticks_to_ns(t.quantile_ticks(990)));
    abi.write(b" max=");
    put_u(abi, ticks_to_ns(t.max));
    abi.write(b" ns (n=");
    put_u(abi, t.n);
    abi.write(b")\n");
}

/// Heap growth and process life cycle.
// ── Wave 13: threads ─────────────────────────────────────────────────────────

#[repr(C, align(16))]
struct ThrStack([u8; 16 * 1024]);
static mut THR_STACKS: [ThrStack; 2] = [const { ThrStack([0; 16 * 1024]) }; 2];
static THR_CTID: [core::sync::atomic::AtomicU32; 2] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 2];
/// The ping-pong word: the main thread writes odd values, the partner the
/// next even one; `u32::MAX` ends the partner.
static PP_WORD: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn thr_stack_top(i: usize) -> usize {
    unsafe { (core::ptr::addr_of_mut!(THR_STACKS[i]) as usize) + 16 * 1024 }
}

/// A thread that ends at once.
extern "C" fn thr_exit_now<A: Threads>() -> ! {
    A::thread_exit()
}

/// The ping-pong partner: answer every odd value with the next even one.
extern "C" fn thr_partner<A: Threads>() -> ! {
    use core::sync::atomic::Ordering::{Acquire, Release};
    loop {
        let v = PP_WORD.load(Acquire);
        if v == u32::MAX {
            A::thread_exit();
        }
        if v & 1 == 1 {
            PP_WORD.store(v + 1, Release);
            A::futex_wake(&PP_WORD, 1);
        } else {
            A::futex_wait(&PP_WORD, v);
        }
    }
}

/// Join thread slot `i`: wait until its exit cleared the word.
fn thr_join<A: Threads>(i: usize) {
    loop {
        let v = THR_CTID[i].load(core::sync::atomic::Ordering::Acquire);
        if v == 0 {
            return;
        }
        A::join_wait(&THR_CTID[i], v);
    }
}

/// `thread create+join`: a thread that exits at once, joined through its
/// cleared word (what `pthread_create` + `pthread_join` cost without the C
/// library's stack mapping). `futex wake+wait rt`: one round trip between two
/// threads of one process through a futex (wake the partner, wait for its
/// answer): two futex calls and two switches per side.
fn thread_lanes<A: Abi + Threads>(abi: &A, floor_ns: u64) {
    use core::sync::atomic::Ordering::{Acquire, Release};
    let mut err = 0i64;
    let t_cj = batch(N_THR, || {
        let r = A::thread_spawn(thr_exit_now::<A>, thr_stack_top(0), &THR_CTID[0]);
        if r <= 0 { err = r; return; }
        thr_join::<A>(0);
    });
    if err != 0 {
        abi.write(b"[VSBENCH] thread create+join: FAIL rc=");
        put_i(abi, err);
        abi.write(b"\n");
    } else {
        report(abi, b"thread create+join", t_cj, N_THR, floor_ns);
    }
    PP_WORD.store(0, Release);
    let r = A::thread_spawn(thr_partner::<A>, thr_stack_top(1), &THR_CTID[1]);
    if r <= 0 {
        abi.write(b"[VSBENCH] futex wake+wait rt: FAIL rc=");
        put_i(abi, r);
        abi.write(b"\n");
        return;
    }
    let mut next = 1u32;
    let t_pp = batch(N_THR, || {
        PP_WORD.store(next, Release);
        A::futex_wake(&PP_WORD, 1);
        loop {
            let v = PP_WORD.load(Acquire);
            if v == next + 1 { break; }
            A::futex_wait(&PP_WORD, v);
        }
        next += 2;
    });
    PP_WORD.store(u32::MAX, Release);
    A::futex_wake(&PP_WORD, 1);
    thr_join::<A>(1);
    report(abi, b"futex wake+wait rt", t_pp, N_THR, floor_ns);
}

/// Wave 15 (`disk`): the disk file-write lanes.
fn disk_lanes(abi: &(impl Abi + Shell), floor_ns: u64) {
    // Wave 15: create/truncate + write 4 KiB + close on the DISK file
    // system (AzOS FAT32 with its write-back cache; Linux vfat on the same
    // kind of virtio-blk disk), without and with an fsync before the close.
    match abi.disk_setup() {
        Err(e) => {
            abi.write(b"[VSBENCH] file-write: FAIL setup rc=");
            put_i(abi, e);
            abi.write(b"\n");
        }
        Ok(()) => {
            let data = [0xA5u8; DISK_WRITE_BYTES];
            for (fsync, label) in [(false, &b"file-write 4K"[..]), (true, &b"file-wr+fsync"[..])] {
                let mut err = 0i64;
                let t = batch(N_DISK, || {
                    if err == 0 {
                        if let Err(e) = abi.disk_write_close(&data, fsync) { err = e; }
                    }
                });
                if err != 0 {
                    abi.write(b"[VSBENCH] ");
                    abi.write(label);
                    abi.write(b": FAIL rc=");
                    put_i(abi, err);
                    abi.write(b"\n");
                } else {
                    report(abi, label, t, N_DISK, floor_ns);
                }
            }
        }
    }
}

fn proc_lanes(abi: &(impl Abi + Proc), floor_ns: u64) {
    // 1. `brk` upward, one page at a time. Growth only: shrinking and
    //    regrowing would measure bookkeeping on a kernel that keeps the pages,
    //    not allocation. Since wave 14 AzOS reserves the pages (demand
    //    markers) and backs each at its first touch, as Linux does; this lane
    //    never touches them, so on both sides it is the reservation alone.
    let mut brk_err = 0i64;
    let t_brk = batch(N_BRK, || {
        if let Err(e) = abi.brk_grow(PAGE) { brk_err = e; }
    });
    if brk_err != 0 {
        abi.write(b"[VSBENCH] brk-grow: FAIL rc=");
        put_i(abi, brk_err);
        abi.write(b"\n");
    } else {
        report(abi, b"brk-grow/pg  ", t_brk, N_BRK, floor_ns);
    }

    // 2. The full life cycle: fork, the child exits, the parent reaps it.
    //    Reported NEXT TO the lane above rather than replacing it, so the
    //    creation-only number stays comparable with the runs already recorded
    //    with it. Both sides poll with WNOHANG and yield; see
    //    `Proc::fork_exit_wait` for why a blocking `wait4` would be a false
    //    comparison.
    //
    //    **Do NOT read the gap between the two lanes as the cost of reaping.**
    //    Measured on QEMU 2026-09-07, five runs of the same binary:
    //    fork+exit spanned 246,450-332,975 ns/op and fork+exit+wait
    //    271,900-372,775 — about 35% either way — and the SIGN of the
    //    difference flipped run to run (+2,550, +102,900, -2,800, -22,625).
    //    At N_PROC=40 the reap is inside this instrument's noise. Two numbers
    //    from one run say nothing about it; a claim here needs repeats and the
    //    absolutes, not the ratio (the "x floor" figures moved 73x-184x across
    //    those same runs, because the floor itself oscillates).
    //    **This lane runs BEFORE `fork+exit`.** The order was load-bearing
    //    until wave 11, when `fork+exit` started reaping its own children:
    //    `note_exit`'s table held 32 entries and dropped the OLDEST when full (until wave 12),
    //    and `fork+exit` used to leave N_PROC = 40 children unreaped. Run after
    //    it, this lane's own exit notice could be evicted by a straggler
    //    finishing mid-batch, and `SYS_WAITPID` correctly reported that as
    //    `ECHILD` — measured 2026-09-07 as 2 failures in 40 iterations, always
    //    on the first poll. Draining first was not enough: the drain reaped 32
    //    of 40 and the rest had not been scheduled yet.
    //
    //    That is not a defect in `waitpid`; it is the table's drop-oldest
    //    policy becoming observable from ring 3, which `wait` hid by consuming
    //    a straggler's notice as if it were ours. Reordering removes the
    //    coupling instead of tolerating it. Since wave 14 neither lane
    //    leaves a child behind: each waits for its own.
    let mut wait_err = 0i64;
    let t_life = batch(N_PROC, || {
        if let Err(e) = abi.fork_exit_wait() { wait_err = e; }
    });
    if wait_err != 0 {
        abi.write(b"[VSBENCH] fork+exit+wait: FAIL rc=");
        put_i(abi, wait_err);
        abi.write(b"\n");
    } else {
        report(abi, b"fork+exit+wait", t_life, N_PROC, floor_ns);
    }

    // 3. fork + the child exiting immediately + its reap, the child's exit
    //    inside the window (wave 14, see `Proc::fork_exit`): each iteration
    //    returns only once THAT child has been reaped, so no child is left
    //    to run after the batch and nothing needs reaping untimed. Until
    //    wave 14 it reaped at most one finished child per iteration, and on a
    //    kernel that kept the parent on the hart the children all exited
    //    after the batch: the number was fork alone there (~68k), fork plus
    //    most exits elsewhere. Now the same operation as the lane above.
    let mut proc_err = 0i64;
    let t_proc = batch(N_PROC, || {
        if let Err(e) = abi.fork_exit() { proc_err = e; }
    });
    if proc_err != 0 {
        abi.write(b"[VSBENCH] fork+exit: FAIL rc=");
        put_i(abi, proc_err);
        abi.write(b"\n");
    } else {
        report(abi, b"fork+exit   ", t_proc, N_PROC, floor_ns);
    }

}

/// Wave 12: process start by path and the pipe (`bench_core::Shell`, which
/// says what each side runs). `spawn+wait` is start-to-reaped of an
/// exit-at-once program; `pipe-rw` one `PIPE_MSG`-byte write and its read
/// back in the same task; `pipe+close` creating a pipe and closing both
/// ends. A lane that fails prints `FAIL rc=` and no number.
fn shell_lanes(abi: &(impl Abi + Shell), floor_ns: u64) {
    let mut err = 0i64;
    let t_spawn = batch(N_SPAWN, || {
        if err == 0 {
            if let Err(e) = abi.spawn_wait() { err = e; }
        }
    });
    if err != 0 {
        abi.write(b"[VSBENCH] spawn+wait: FAIL rc=");
        put_i(abi, err);
        abi.write(b"\n");
    } else {
        report(abi, b"spawn+wait  ", t_spawn, N_SPAWN, floor_ns);
    }

    match abi.pipe_open() {
        Ok((r, w)) => {
            let mut buf = [0x5Au8; PIPE_MSG];
            let mut err = 0i64;
            let t_rw = batch(N_PIPE, || {
                if err == 0 {
                    if let Err(e) = abi.pipe_rw(r, w, &mut buf) { err = e; }
                }
            });
            abi.pipe_close(r, w);
            if err != 0 {
                abi.write(b"[VSBENCH] pipe-rw: FAIL rc=");
                put_i(abi, err);
                abi.write(b"\n");
            } else {
                report(abi, b"pipe-rw 64B ", t_rw, N_PIPE, floor_ns);
            }
        }
        Err(e) => {
            abi.write(b"[VSBENCH] pipe-rw: FAIL rc=");
            put_i(abi, e);
            abi.write(b"\n");
        }
    }

    let mut err = 0i64;
    let t_open = batch(N_PIPE_OPEN, || {
        if err == 0 {
            match abi.pipe_open() {
                Ok((r, w)) => abi.pipe_close(r, w),
                Err(e) => err = e,
            }
        }
    });
    if err != 0 {
        abi.write(b"[VSBENCH] pipe+close: FAIL rc=");
        put_i(abi, err);
        abi.write(b"\n");
    } else {
        report(abi, b"pipe+close  ", t_open, N_PIPE_OPEN, floor_ns);
    }

    // Round 48: the descriptor table's open file description on the file
    // path (open + read + close), and `dup` where the kernel offers one.
    let mut buf = [0u8; 64];
    let mut err = 0i64;
    let t_file = batch(N_FILE, || {
        if err == 0 {
            if let Err(e) = abi.file_open_read_close(&mut buf) { err = e; }
        }
    });
    if err != 0 {
        abi.write(b"[VSBENCH] file-ord: FAIL rc=");
        put_i(abi, err);
        abi.write(b"\n");
    } else {
        report(abi, b"file-ord 64B", t_file, N_FILE, floor_ns);
    }
    // Wave 13: the same open + read + close on a RAM file on both sides —
    // the open file description's cost with no disk under it.
    match abi.tmp_setup() {
        Err(e) => {
            abi.write(b"[VSBENCH] tmp-ord: FAIL setup rc=");
            put_i(abi, e);
            abi.write(b"\n");
        }
        Ok(()) => {
            let mut err = 0i64;
            let t_tmp = batch(N_FILE, || {
                if err == 0 {
                    if let Err(e) = abi.tmp_open_read_close(&mut buf) { err = e; }
                }
            });
            if err != 0 {
                abi.write(b"[VSBENCH] tmp-ord: FAIL rc=");
                put_i(abi, err);
                abi.write(b"\n");
            } else {
                report(abi, b"tmp-ord 64B ", t_tmp, N_FILE, floor_ns);
            }
        }
    }
    match abi.file_hold() {
        Ok(fd) => {
            let mut err = 0i64;
            let mut offered = true;
            let t_dup = batch(N_DUP, || {
                if err == 0 && offered {
                    match abi.file_dup_close(fd) {
                        None => offered = false,
                        Some(Err(e)) => err = e,
                        Some(Ok(())) => {}
                    }
                }
            });
            abi.file_release(fd);
            if err != 0 {
                abi.write(b"[VSBENCH] file-dup: FAIL rc=");
                put_i(abi, err);
                abi.write(b"\n");
            } else if offered {
                report(abi, b"file-dup    ", t_dup, N_DUP, floor_ns);
            }
        }
        Err(e) => {
            abi.write(b"[VSBENCH] file-dup: FAIL hold rc=");
            put_i(abi, e);
            abi.write(b"\n");
        }
    }
}

/// The vDSO lanes: **the same operation by both paths**.
///
/// A vDSO number on its own says little. The `vdso / syscall` ratio within one
/// kernel does: it cancels the cost of the trap — which differs per system —
/// and leaves what the mechanism actually buys.
///
/// What is **missing** is reported too. That the Linux vDSO serves `getcpu`
/// and ours does not is a result, not a gap in the harness.
fn vdso_lanes(abi: &(impl Abi + Vdso), floor_ns: u64) {
    if !abi.vdso_ready() {
        // No number, deliberately. The obvious fallback — making the syscall —
        // would measure a trap and label it vDSO.
        abi.write(b"[VSBENCH] vdso: unavailable, no numbers\n");
        return;
    }

    // The third path, and on RISC-V the one that matters: `rdtime` is a user
    // instruction. Both kernels enable `scounteren.TM`, so this number is
    // **the same code on both sides** and serves as the absolute floor the
    // other two are read against.
    let t_r = batch(N_VDSO, || { core::hint::black_box(bench_core::rdtime()); });
    report(abi, b"clock  [rdtm]", t_r, N_VDSO, floor_ns);

    let t_v = batch(N_VDSO, || { core::hint::black_box(abi.clock_vdso()); });
    report(abi, b"clock  [vdso]", t_v, N_VDSO, floor_ns);
    let t_s = batch(N_VDSO, || { core::hint::black_box(abi.clock_syscall()); });
    report(abi, b"clock  [call]", t_s, N_VDSO, floor_ns);

    match (abi.cpu_vdso(), abi.cpu_syscall()) {
        (Some(_), Some(_)) => {
            let c_v = batch(N_VDSO, || { core::hint::black_box(abi.cpu_vdso()); });
            report(abi, b"getcpu [vdso]", c_v, N_VDSO, floor_ns);
            let c_s = batch(N_VDSO, || { core::hint::black_box(abi.cpu_syscall()); });
            report(abi, b"getcpu [call]", c_s, N_VDSO, floor_ns);
        }
        _ => abi.write(b"[VSBENCH] getcpu: this kernel offers it by neither path\n"),
    }
}

// ── Wave 6, front V: the per-task vDSO page and the shm ring ───────────────
//
// The Linux build measures the same work where Linux has the same work
// (`abi_linux.rs`, "Wave 6 counterparts"): `notify-*` against `futex` on the
// same shared word, `ring-*` against the same SPSC ring core over a
// `MAP_SHARED` page and `futex`, `taskinfo [call]` against `getrusage`.
// `sensor-read-*` and `taskinfo [vdso]` have no Linux object to measure (no
// sensor syscall, no per-task vDSO counters): they print on the `azos` side
// only, and `tools/vsbench_compare.sh` carries a one-line justification for
// each — a missing number, not an invented one.

/// One failure line the gate's `FAIL rc=` grep catches. Printed ONLY on the
/// failure path, so its presence is the canary and its absence is not a
/// reading of this line's own text.
fn fail_line(abi: &impl Abi, what: &[u8], rc: i64) {
    abi.write(b"[VSBENCH] ");
    abi.write(what);
    abi.write(b": FAIL rc=");
    put_i(abi, rc);
    abi.write(b"\n");
}

#[cfg(feature = "azos")]
const SENSOR_ENCODER: u32 = 2;
#[cfg(feature = "azos")]
const SENSOR_ODOM: u32 = 1;
/// Spin bound for one timer-interrupt publication: several tick periods of
/// instructions at 100 Hz under `-icount` (a spin iteration is a handful of
/// instructions), and seconds of wall time on hardware. Reaching it means the
/// publisher is not running.
#[cfg(feature = "azos")]
const VDSO_PUBLISH_SPINS: u64 = 20_000_000;

/// Rung 1: the sensor the task holds a `Cap<Sensor>` for, read from its own
/// vDSO page against the same sensor through `SYS_SENSOR_READ_TYPED`; and its
/// own counters read from the page against `SYS_TASKINFO`.
///
/// Three canaries run before any number is taken, each printing `FAIL rc=`
/// only when its property is broken:
///   * authority — binding a handle that is not a `Cap<Sensor>` (the
///     endpoint capability, a real handle of the wrong kind) is refused;
///   * scope — a sensor the task did not bind (odometry, which the interrupt
///     CAN sample) never shows data in the page, before or after another
///     sensor is bound;
///   * publication — the bound sensor's slot is published and the page names
///     this task as its owner.
#[cfg(feature = "azos")]
fn vdso_task_lanes(abi: &impl Abi, floor_ns: u64) {
    use azos_libsys as sys;
    let va = sys::vdso_task_map();
    if va <= 0 { fail_line(abi, b"vdso-task map", va as i64); return; }
    let cap = sys::cap_lookup(sys::CapKind::Sensor as u8, SENSOR_ENCODER);
    if cap <= 0 { fail_line(abi, b"sensor-read-vdso cap_lookup", cap as i64); return; }
    let cap = cap as u32;
    let mut buf = [0u8; 32];

    // Canary: authority.
    let wrong_kind = sys::cap_lookup(sys::CapKind::Endpoint as u8, 1);
    if wrong_kind > 0 {
        let rc = sys::vdso_sensor_bind(wrong_kind as u32);
        if rc >= 0 { fail_line(abi, b"vdso-sensor bind accepted a non-sensor capability", rc as i64); }
    }
    // Canary: scope. Wait for the timer interrupt to publish the page at
    // least once, so an unmasked publisher WOULD have written by now, then
    // require both interrupt-sampled sensors to be absent.
    let publishes = || sys::vdso_task_counters().map(|c| c.publishes).unwrap_or(0);
    let wait_publish = |past: u64| -> bool {
        for _ in 0..VDSO_PUBLISH_SPINS {
            if publishes() > past { return true; }
            core::hint::spin_loop();
        }
        false
    };
    if !wait_publish(0) { fail_line(abi, b"vdso-task page never published", -2); return; }
    if sys::vdso_sensor_read(SENSOR_ENCODER, &mut buf).is_some()
        || sys::vdso_sensor_read(SENSOR_ODOM, &mut buf).is_some()
    {
        fail_line(abi, b"vdso-sensor data visible before any bind", -1);
    }
    let rc = sys::vdso_sensor_bind(cap);
    if rc != 1 { fail_line(abi, b"vdso-sensor bind encoder", rc as i64); return; }
    // Canary: publication of the bound sensor, and still nothing for the
    // unbound one after a publication that saw the bind.
    let p0 = publishes();
    if !wait_publish(p0) || sys::vdso_sensor_read(SENSOR_ENCODER, &mut buf).is_none() {
        fail_line(abi, b"vdso-sensor encoder never published", -2); return;
    }
    if sys::vdso_sensor_read(SENSOR_ODOM, &mut buf).is_some() {
        fail_line(abi, b"vdso-sensor odometry visible without a bind", -3);
    }
    match sys::vdso_task_counters() {
        Some(c) if c.owner_tid as isize == sys::getpid() && c.publishes > 0 => {
            abi.write(b"[VSBENCH] vdso-task page: publishes=");
            put_u(abi, c.publishes);
            abi.write(b" cpu_time_ticks=");
            put_u(abi, c.cpu_time);
            abi.write(b" sw_vol=");
            put_u(abi, c.switches_voluntary);
            abi.write(b" sw_pre=");
            put_u(abi, c.switches_preempted);
            abi.write(b" ready_site=");
            put_u(abi, c.last_ready_site as u64);
            abi.write(b"\n");
        }
        Some(c) => fail_line(abi, b"vdso-task page owner/publishes", c.owner_tid as i64),
        None => fail_line(abi, b"vdso-task page unreadable", -4),
    }

    // Canary (wave 11): the published slot carries its acquisition stamp,
    // on the reader's clock. The interrupt reads the encoder counters itself,
    // so the stamp is that publication's — never 0, never ahead of the
    // reader, and younger than the second this rung has been running.
    match sys::vdso_sensor_read(SENSOR_ENCODER, &mut buf) {
        Some(v) => {
            let now = sys::vdso_now_ns();
            if v.acq_ns == 0 || v.acq_ns > now || now - v.acq_ns >= 1_000_000_000 {
                fail_line(abi, b"vdso-sensor encoder acq_ns", v.acq_ns as i64);
            }
        }
        None => fail_line(abi, b"vdso-sensor encoder unreadable", -5),
    }
    // Canary (wave 11): the stamped call returns the header and 561's 16
    // bytes, stamped inside the call on the reader's clock.
    let mut tsbuf = [0u8; 64];
    let t0 = sys::vdso_now_ns();
    let n = sys::sensor_read_ts(cap, &mut tsbuf);
    let t1 = sys::vdso_now_ns();
    match sys::SensorSampleHdr::from_bytes(&tsbuf) {
        Some(h) if n == (sys::SENSOR_SAMPLE_HDR_LEN + 16) as isize && h.payload_len == 16
            && h.acq_ns >= t0 && h.acq_ns <= t1 => {}
        _ => fail_line(abi, b"sensor-read-ts header/stamp", n as i64),
    }

    let t_v = batch(N_VDSO, || { core::hint::black_box(sys::vdso_sensor_read(SENSOR_ENCODER, &mut buf)); });
    report(abi, b"sensor-read-vdso", t_v, N_VDSO, floor_ns);
    let t_s = batch(N_VDSO, || { core::hint::black_box(sys::sensor_read_typed(cap, &mut buf)); });
    report(abi, b"sensor-read-call", t_s, N_VDSO, floor_ns);
    let t_t = batch(N_VDSO, || { core::hint::black_box(sys::sensor_read_ts(cap, &mut tsbuf)); });
    report(abi, b"sensor-read-ts", t_t, N_VDSO, floor_ns);
    let t_cv = batch(N_VDSO, || { core::hint::black_box(sys::vdso_task_counters()); });
    report(abi, b"taskinfo [vdso]", t_cv, N_VDSO, floor_ns);
    let t_cs = batch(N_VDSO, || { core::hint::black_box(abi.ctx_switches()); });
    report(abi, b"taskinfo [call]", t_cs, N_VDSO, floor_ns);
}


/// Round trips in `ring-pingpong`, as `ipc-roundtrip`'s `N_IPC`. Shared with
/// the Linux counterpart (`abi_linux::ring_lanes`), like every count below.
const N_RING: u64 = 500;
const N_RING_WARM: u64 = 50;
/// Items in `ring-stream`: 32 ring-fulls.
const N_RING_STREAM: u64 = 4096;
/// `ring-stream`'s canary: sharing one hart, both sides together may enter
/// the kernel at most once per this many items. A correct ring enters a few
/// times per ring-full (128); a ring that entered per item fails it 16-fold.
const RING_CANARY_DIVISOR: u64 = 8;

/// Rung 3: an SPSC ring in one shared page, against `ipc-roundtrip` with the
/// same peer (`VSSRV.ELF`).
///
/// **What each lane measures.** `ring-pingpong` is a depth-1 exchange: the
/// request ring is empty whenever the server looks and the response ring is
/// empty whenever this side looks, so EVERY trip sleeps and wakes on both
/// sides — it prices notify/wait as a rendezvous (two waits, two wakes, two
/// switches at `-smp 1`), not the lock-free ring. `ring-stream` is the ring's
/// actual case: `N_RING_STREAM` items one way, and the kernel entries of both
/// sides are printed next to it, so "no kernel entry while the ring is
/// neither empty nor full" is a printed count, not a claim.
#[cfg(feature = "azos")]
fn ring_lanes(abi: &(impl Abi + Ipc), peer: u64, floor_ns: u64) {
    use ipc_proto::ring::*;
    use azos_libsys as sys;
    let cap = sys::shm_create_typed(1, sys::SHM_RW);
    if cap <= 0 { fail_line(abi, b"ring shm_create", cap as i64); return; }
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 { fail_line(abi, b"ring shm_map", va as i64); return; }
    let req = sys::SpscRing { base: va as usize, cap: RING_CAP };
    let resp = sys::SpscRing { base: va as usize + RING_RESP_OFFSET, cap: RING_CAP };
    req.init();
    resp.init();

    // Rung 2's own numbers: the two calls on the path where nothing sleeps.
    // A wake that finds no waiter (what a producer pays when its flag read
    // raced a consumer that already woke) and a wait whose word already
    // changed (-EAGAIN, what a consumer pays when the producer beat it).
    // Both resolve (region, offset) from this task's mapping and take the
    // waiter-table lock, which is their whole cost over the syscall floor.
    let w0 = req.base;
    let t_wk = batch(N_VDSO, || { core::hint::black_box(sys::notify_wake(w0, 1)); });
    let t_wt = batch(N_VDSO, || { core::hint::black_box(sys::notify_wait(w0, 1, sys::NOTIFY_FOREVER)); });
    if sys::notify_wake(w0, 1) != 0 || sys::notify_wait(w0, 1, sys::NOTIFY_FOREVER) != -11 {
        fail_line(abi, b"notify empty-path answers", -1);
    } else {
        report(abi, b"notify-wake-empty", t_wk, N_VDSO, floor_ns);
        report(abi, b"notify-wait-eagain", t_wt, N_VDSO, floor_ns);
    }
    // A word outside every mapping of this task is refused, never keyed.
    if sys::notify_wake(0x1000, 1) != -14 {
        fail_line(abi, b"notify on an unmapped address", sys::notify_wake(0x1000, 1) as i64);
    }
    // The capability MOVES to the server with this call (decision 38); this
    // side keeps its mapping, which is what notify keys on.
    match sys::fast_ipc_call_ep_moving(peer as u32, [RING_SETUP, 0, 0, 0], cap as u32) {
        Some(r) if r[0] == RING_SETUP + 1 => {}
        Some(r) => { fail_line(abi, b"ring setup refused by peer", r[0] as i64); return; }
        None => { fail_line(abi, b"ring setup call", -1); return; }
    }

    let mut st = sys::RingStats::default();
    let mut bad = 0u64;
    for i in 0..N_RING_WARM {
        sys::ring_push(&req, ring_tag(TAG_PING, i), &mut st);
        if sys::ring_pop(&resp, &mut st) != ring_tag(TAG_PING, i) + 1 { bad += 1; }
    }
    let mut st = sys::RingStats::default();
    let sw0 = abi.ctx_switches();
    let mut i = 0u64;
    let t_pp = batch(N_RING, || {
        sys::ring_push(&req, ring_tag(TAG_PING, i), &mut st);
        if sys::ring_pop(&resp, &mut st) != ring_tag(TAG_PING, i) + 1 { bad += 1; }
        i += 1;
    });
    let sw1 = abi.ctx_switches();
    if bad != 0 || st.timeouts != 0 {
        fail_line(abi, b"ring-pingpong wrong answers or lost wakes", -((bad + st.timeouts) as i64));
    } else {
        report(abi, b"ring-pingpong", t_pp, N_RING, floor_ns);
        abi.write(b"[VSBENCH] ring-pingpong client entries: waits=");
        put_u(abi, st.waits);
        abi.write(b" wakes=");
        put_u(abi, st.wakes);
        if let (Some((v0, i0)), Some((v1, i1))) = (sw0, sw1) {
            abi.write(b" switches=");
            put_u(abi, (v1 - v0) + (i1 - i0));
        }
        abi.write(b" over ");
        put_u(abi, N_RING);
        abi.write(b" round trips\n");
    }

    let mut st = sys::RingStats::default();
    let mut peer_entries = 0u64;
    let mut peer_hart = u64::MAX;
    let t_st = batch(1, || {
        for i in 0..N_RING_STREAM {
            sys::ring_push(&req, ring_tag(TAG_STREAM, i), &mut st);
        }
        sys::ring_push(&req, ring_tag(TAG_STREAM_END, 0), &mut st);
        peer_entries = sys::ring_pop(&resp, &mut st);
        peer_hart = sys::ring_pop(&resp, &mut st);
    });
    let (peer_count, peer_ops) = (peer_entries >> 32, peer_entries & 0xFFFF_FFFF);
    let my_hart = abi.current_cpu().unwrap_or(u64::MAX - 1);
    let client_ops = st.waits + st.wakes;
    if peer_count != N_RING_STREAM || st.timeouts != 0 {
        fail_line(abi, b"ring-stream lost items or wakes", -(st.timeouts as i64) - 1);
    } else {
        report(abi, b"ring-stream", t_st, N_RING_STREAM, floor_ns);
    }
    abi.write(b"[VSBENCH] ring-stream kernel entries: client=");
    put_u(abi, client_ops);
    abi.write(b" server=");
    put_u(abi, peer_ops);
    abi.write(b" over ");
    put_u(abi, N_RING_STREAM);
    abi.write(b" items, client hart=");
    put_u(abi, my_hart);
    abi.write(b" server hart=");
    put_u(abi, peer_hart);
    abi.write(b"\n");
    // The property, checked where it is deterministic: sharing one hart the
    // two sides alternate in whole ring-fulls, so a correct ring enters the
    // kernel a few times per `RING_CAP` items. A ring that entered per item
    // (a wake on every push, say) is at or above one per item.
    if my_hart == peer_hart && (client_ops + peer_ops) * RING_CANARY_DIVISOR > N_RING_STREAM {
        fail_line(abi, b"ring-stream entered the kernel while neither empty nor full",
            (client_ops + peer_ops) as i64);
    }

    sys::ring_push(&req, ring_tag(TAG_STOP, 0), &mut st);
    if sys::ring_pop(&resp, &mut st) != RING_STOP_ACK {
        fail_line(abi, b"ring stop", -5);
    }
}

/// Requests per driver-request lane (`drv-call`, `drvring-*`), a multiple of
/// `drv::DRV_BATCH`. Shared with the Linux counterpart (`abi_linux::drv_lanes`).
const N_DRV: u64 = 512;
const N_DRV_WARM: u64 = 64;
/// Reads of `drv-call` retried after an empty answer (the kernel proxy's
/// reply timeout under a stalled vCPU, see the lane); the peer serves this
/// many requests beyond the lane's (`serve.rs`'s `drv_serve` slack).
#[cfg(feature = "azos")]
const DRV_CALL_RETRIES: u64 = 8;
/// `drvring-batch8`'s canary (AzOS, one hart): a batch of `DRV_BATCH`
/// requests costs each side at most one sleep and one doorbell (4 entries
/// for 8 requests). A ring whose doorbell is not suppressed rings once per
/// request and fails this. Linux preempts a waker on one hart, so its side
/// prints the count and asserts nothing (`abi_linux::drv_lanes`).
#[cfg(feature = "azos")]
const DRV_BATCH_MAX_ENTRIES_PER_BATCH: u64 = 4;

/// The ring's own cost, no peer and no kernel: one task moves `N_DRV`
/// requests through a request ring and their answers through a reply ring,
/// both in a private page. What a request costs the two sides when neither
/// ever finds its ring empty or full — the "driver awake" case, which on one
/// hart cannot be raced, only bounded. Returns `None` if any step asked for
/// the kernel (it must not) or an answer was wrong.
fn drvring_ops(abi: &impl Abi, floor_ns: u64) {
    use ipc_proto::drv::*;
    #[repr(C, align(4096))]
    struct Page([u8; 4096]);
    struct Shared(core::cell::UnsafeCell<Page>);
    unsafe impl Sync for Shared {}
    static OPS_PAGE: Shared = Shared(core::cell::UnsafeCell::new(Page([0; 4096])));
    let base = OPS_PAGE.0.get() as usize;
    let req = azos_libsys::SpscSlots::<DRV_WORDS> { base, cap: DRV_RING_CAP };
    let resp = azos_libsys::SpscSlots::<DRV_WORDS> { base: base + DRV_RESP_OFFSET, cap: DRV_RING_CAP };
    req.init();
    resp.init();
    use azos_libsys::RingStep::Done;
    let mut bad = 0u64;
    let mut it = [0u64; DRV_WORDS];
    let mut i = 0u64;
    let t = batch(N_DRV, || {
        if req.try_push(&drv_req(TAG_CALL, i)) != Done { bad += 1; }
        if req.try_pop(&mut it) != Done { bad += 1; }
        for w in it.iter_mut() { *w = w.wrapping_add(1); }
        if resp.try_push(&it) != Done { bad += 1; }
        if resp.try_pop(&mut it) != Done || !drv_is_answer(&it, i) { bad += 1; }
        i += 1;
    });
    if bad != 0 {
        fail_line(abi, b"drvring-ops asked for the kernel or answered wrong", -(bad as i64));
    } else {
        report(abi, b"drvring-ops", t, N_DRV, floor_ns);
    }
}

/// One kernel-entry line: `[VSBENCH] <lane> entries: client=<w>+<k> server=<w>+<k> switches=<n> over <N> requests`
/// (waits+wakes). Not a lane line (no `ns/op`).
fn drv_entries_line(abi: &impl Abi, lane: &[u8], c: (u64, u64), s: (u64, u64), sw: Option<u64>, n: u64) {
    abi.write(b"[VSBENCH] ");
    abi.write(lane);
    abi.write(b" entries: client=");
    put_u(abi, c.0);
    abi.write(b"+");
    put_u(abi, c.1);
    abi.write(b" server=");
    put_u(abi, s.0);
    abi.write(b"+");
    put_u(abi, s.1);
    if let Some(sw) = sw {
        abi.write(b" switches=");
        put_u(abi, sw);
    }
    abi.write(b" over ");
    put_u(abi, n);
    abi.write(b" requests\n");
}

/// Wave 11 (SHMRING): a driver request by today's path against a slot ring
/// in shared memory, same peer (`VSSRV.ELF`), same 64-byte request.
///
/// * `drv-call` — today's path. `SYS_SENSOR_READ_TYPED(sensor.9)` reaches the
///   kernel's `UserDriverProxy` for `DRV_KIND_POWER_MON`, which queues the
///   request, blocks this task and wakes the driver parked in
///   `SYS_DRIVER_REPLY_WAIT` (610); the driver's next 610 publishes the reply
///   and wakes this task. `VSSRV.ELF` registers for the kind for the span of
///   the lane. Two kernel entries and (one hart) two switches per request,
///   by construction; this has no batch form from ring 3.
/// * `drvring-call` — one request, one answer, on `SpscSlots<8>` rings with
///   notify doorbells: the driver asleep whenever a request arrives.
/// * `drvring-batch8` — `DRV_BATCH` requests, then their answers: the
///   doorbell rings once per batch, not per request (canary below).
/// * `drvring-ops` — the ring alone, no peer (`drvring_ops`).
#[cfg(feature = "azos")]
fn drv_lanes(abi: &(impl Abi + Ipc), peer: u64, floor_ns: u64) {
    use ipc_proto::drv::*;
    use azos_libsys as sys;
    const SENSOR_POWER: u32 = 9;

    // ── drv-call ──
    let cap = sys::cap_lookup(sys::CapKind::Sensor as u8, SENSOR_POWER);
    match sys::fast_ipc_call_ep(peer as u32, [DRV_SETUP, N_DRV_WARM + N_DRV, DRV_CALL_RETRIES, 0]) {
        _ if cap <= 0 => fail_line(abi, b"drv-call cap_lookup sensor.9", cap as i64),
        Some(r) if r == DRV_SETUP + 1 => {
            let cap = cap as u32;
            let mut buf = [0u8; 16];
            let mut bad = 0u64;
            // The first wrong answer: (request index, what the read returned).
            let mut first_bad = (0u64, 0isize);
            let mut n = 0u64;
            // Reads that answered 0 bytes and then a sample on one retry
            // (wave 13). The kernel's proxy waits `PROXY_REPLY_TIMEOUT_MS`
            // (100 ms) for the driver and answers an empty sample when it
            // passes; on QEMU the guest clock is the host's, so a vCPU the
            // host descheduled ends that wait with the driver alive. Measured
            // under host load 20-22: every `rc=-1` of this lane came with the
            // kernel's `[PROXY] kind 0x11: no reply within 100000 us` and
            // "returned 0". A run with one is not a measurement (it holds a
            // 100 ms wait), so it prints no number; a driver that does not
            // answer the retry either is still a FAIL.
            let mut timeouts = 0u64;
            let mut read = |bad: &mut u64, timeouts: &mut u64| {
                let mut rc = sys::sensor_read_typed(cap, &mut buf);
                if rc == 0 && *timeouts < DRV_CALL_RETRIES {
                    *timeouts += 1;
                    rc = sys::sensor_read_typed(cap, &mut buf);
                }
                if rc != 12 {
                    if *bad == 0 { first_bad = (n, rc); }
                    *bad += 1;
                }
                n += 1;
            };
            for _ in 0..N_DRV_WARM { read(&mut bad, &mut timeouts); }
            let sw0 = abi.ctx_switches();
            let t = batch(N_DRV, || read(&mut bad, &mut timeouts));
            let sw1 = abi.ctx_switches();
            if bad != 0 {
                fail_line(abi, b"drv-call reads not answered by the driver", -(bad as i64));
                abi.write(b"[VSBENCH] drv-call first wrong read: request ");
                put_u(abi, first_bad.0);
                abi.write(b" returned ");
                put_i(abi, first_bad.1 as i64);
                abi.write(b"\n");
            } else if timeouts != 0 {
                abi.write(b"[VSBENCH] drv-call: no number, ");
                put_u(abi, timeouts);
                abi.write(b" read(s) answered empty after the kernel's reply timeout and then \
                            answered on retry (a stalled vCPU; see [PROXY] on the console)\n");
            } else {
                report(abi, b"drv-call", t, N_DRV, floor_ns);
                // One SENSOR_READ_TYPED and one 610 per request, by the ABI;
                // the switches are counted.
                if let (Some((v0, i0)), Some((v1, i1))) = (sw0, sw1) {
                    abi.write(b"[VSBENCH] drv-call switches=");
                    put_u(abi, (v1 - v0) + (i1 - i0));
                    abi.write(b" over ");
                    put_u(abi, N_DRV);
                    abi.write(b" requests\n");
                }
            }
        }
        // `0x100 + EBUSY`: a real power-monitor driver (`INADRV.ELF`) owns
        // the kind on this boot. An environment, not a defect: no number,
        // and no `FAIL` line (the gate greps for it).
        Some(r) if r == 0x100 + 16 => {
            abi.write(b"[VSBENCH] drv-call: off, the power-monitor kind is owned by a running driver\n");
        }
        // `0x100 + errno`: any other refusal to register is a defect.
        Some(r) => fail_line(abi, b"drv-call setup refused by peer", -(r as i64)),
        None => fail_line(abi, b"drv-call setup call", -1),
    }

    // ── drvring-* ──
    let scap = sys::shm_create_typed(1, sys::SHM_RW);
    if scap <= 0 { fail_line(abi, b"drvring shm_create", scap as i64); return; }
    let va = sys::shm_map_typed(scap as u32);
    if va <= 0 { fail_line(abi, b"drvring shm_map", va as i64); return; }
    let req = sys::SpscSlots::<DRV_WORDS> { base: va as usize, cap: DRV_RING_CAP };
    let resp = sys::SpscSlots::<DRV_WORDS> { base: va as usize + DRV_RESP_OFFSET, cap: DRV_RING_CAP };
    req.init();
    resp.init();
    match sys::fast_ipc_call_ep_moving(peer as u32, [DRVRING_SETUP, 0, 0, 0], scap as u32) {
        Some(r) if r[0] == DRVRING_SETUP + 1 => {}
        Some(r) => { fail_line(abi, b"drvring setup refused by peer", r[0] as i64); return; }
        None => { fail_line(abi, b"drvring setup call", -1); return; }
    }
    let mut it = [0u64; DRV_WORDS];
    let mut bad = 0u64;
    // The server's (waits, wakes, timeouts) since the last ask, and its hart.
    // (waits, wakes, timeouts, hart, preempted) since the last ask.
    let server_stats = |st: &mut sys::RingStats| -> (u64, u64, u64, u64, u64) {
        let mut a = [0u64; DRV_WORDS];
        sys::slots_push(&req, &drv_req(TAG_STATS, 0), st);
        sys::slots_pop(&resp, &mut a, st);
        (a[0], a[1], a[2], a[3], a[4])
    };
    let mut st = sys::RingStats::default();
    for i in 0..N_DRV_WARM {
        sys::slots_push(&req, &drv_req(TAG_CALL, i), &mut st);
        sys::slots_pop(&resp, &mut it, &mut st);
        if !drv_is_answer(&it, i) { bad += 1; }
    }
    let _ = server_stats(&mut st);

    let mut st = sys::RingStats::default();
    let sw0 = abi.ctx_switches();
    let mut i = 0u64;
    let t_call = batch(N_DRV, || {
        sys::slots_push(&req, &drv_req(TAG_CALL, i), &mut st);
        sys::slots_pop(&resp, &mut it, &mut st);
        if !drv_is_answer(&it, i) { bad += 1; }
        i += 1;
    });
    let sw1 = abi.ctx_switches();
    let (c_call, sv_call) = (st, server_stats(&mut sys::RingStats::default()));

    let mut st = sys::RingStats::default();
    let sw2 = abi.ctx_switches();
    let mut i = 0u64;
    let t_b8 = batch(N_DRV / DRV_BATCH, || {
        for k in 0..DRV_BATCH { sys::slots_push(&req, &drv_req(TAG_CALL, i + k), &mut st); }
        for k in 0..DRV_BATCH {
            sys::slots_pop(&resp, &mut it, &mut st);
            if !drv_is_answer(&it, i + k) { bad += 1; }
        }
        i += DRV_BATCH;
    });
    let sw3 = abi.ctx_switches();
    let (c_b8, sv_b8) = (st, server_stats(&mut sys::RingStats::default()));
    let sw = |a: Option<(u64, u64)>, b: Option<(u64, u64)>| match (a, b) {
        (Some((v0, i0)), Some((v1, i1))) => Some((v1 - v0) + (i1 - i0)),
        _ => None,
    };

    let timeouts = c_call.timeouts + sv_call.2 + c_b8.timeouts + sv_b8.2;
    if bad != 0 || timeouts != 0 {
        fail_line(abi, b"drvring wrong answers or lost wakes", -((bad + timeouts) as i64));
    } else {
        report(abi, b"drvring-call", t_call, N_DRV, floor_ns);
        drv_entries_line(abi, b"drvring-call", (c_call.waits, c_call.wakes), (sv_call.0, sv_call.1),
            sw(sw0, sw1), N_DRV);
        report(abi, b"drvring-batch8", t_b8, N_DRV, floor_ns);
        drv_entries_line(abi, b"drvring-batch8", (c_b8.waits, c_b8.wakes), (sv_b8.0, sv_b8.1),
            sw(sw2, sw3), N_DRV);
        // The property, where it is deterministic (one hart, as the ring
        // lanes' canary): a batch costs each side one sleep and one doorbell.
        // One exception, a timer preemption of either side mid-batch, which
        // costs the batch one more round — two more entries:
        // * the CLIENT preempted between two pushes: the server (same
        //   priority, same hart) runs on the half-pushed batch, answers it
        //   and sleeps; the rest of the batch rings it again;
        // * the SERVER preempted between two answers (wave 13): its first
        //   answer rang the client, which now runs, takes what is there and
        //   sleeps again; the next answer rings it again. Wave 12 saw
        //   65+64 / 64+65 on riscv64 — one more client sleep, one more
        //   server doorbell: this shape — and allowed only the client's
        //   preemptions, which cannot see the server's.
        // Allowed per preemption of either side counted in the window (the
        // client's `ctx_switches` second half, the server's `SYS_TASKINFO`
        // field 3 through `TAG_STATS`), and printed. A doorbell that is not
        // suppressed rings once per request, which a handful of preemptions
        // does not cover.
        let entries = c_b8.waits + c_b8.wakes + sv_b8.0 + sv_b8.1;
        let same_hart = abi.current_cpu() == Some(sv_b8.3);
        let preempted = match (sw2, sw3) {
            (Some((_, i0)), Some((_, i1))) => i1 - i0,
            _ => 0,
        };
        let sv_preempted = sv_b8.4;
        abi.write(b"[VSBENCH] drvring-batch8 preempted in the window: client=");
        put_u(abi, preempted);
        abi.write(b" server=");
        put_u(abi, sv_preempted);
        // The check below holds only on one hart: two harts run the sides
        // concurrently and may take extra rounds legitimately.
        abi.write(if same_hart { b"; one hart, checked\n" } else { b"; two harts, not checked\n" });
        if same_hart
            && entries > DRV_BATCH_MAX_ENTRIES_PER_BATCH * (N_DRV / DRV_BATCH)
                + 2 * (preempted + sv_preempted)
        {
            fail_line(abi, b"drvring-batch8 rang the doorbell more than once per batch", entries as i64);
        }
    }
    drvring_ops(abi, floor_ns);

    let mut a = [0u64; DRV_WORDS];
    sys::slots_push(&req, &drv_req(TAG_STOP, 0), &mut st);
    sys::slots_pop(&resp, &mut a, &mut st);
    if a[0] != DRV_STOP_ACK { fail_line(abi, b"drvring stop", -5); }
}

/// Frames in `frame-stream`. Shared with `abi_linux::frame_lanes`.
const N_FRAMES: u64 = 1024;

/// What one `frame-stream` drain saw.
#[derive(Default)]
struct FrameRun {
    /// Frames that were not the one expected (length, pattern, `seq`).
    bad: u64,
    /// This side's sleeps and doorbells.
    waits: u64,
    wakes: u64,
    /// The producer's, from its closing stats frame.
    peer_waits: u64,
    peer_wakes: u64,
    /// Sleeps that ended by timeout (a lost doorbell).
    timeouts: u64,
}

/// Drain `n` frames and the producer's stats frame from `r`: the consumer of
/// a kernel stream, with `wait(addr, expected) -> timed_out` and
/// `wake(addr)` the kernel's notify (AzOS) or `futex` (Linux).
fn frame_consume(
    r: &azos_libsys::SpscBytes,
    n: u64,
    wait: impl Fn(usize, u32) -> bool,
    wake: impl Fn(usize),
) -> FrameRun {
    use ipc_proto::frame::*;
    use azos_libsys::{RingSleep, RingStep};
    let mut run = FrameRun::default();
    let mut buf = [0u8; FRAME_BYTES];
    let mut i = 0u64;
    while i <= n {
        let (step, info) = r.try_pop(&mut buf);
        match step {
            RingStep::Blocked => {
                if let RingSleep::Wait { addr, expected } = r.consumer_sleep() {
                    run.waits += 1;
                    if wait(addr, expected) { run.timeouts += 1; }
                    r.consumer_woke();
                }
                continue;
            }
            RingStep::DoneWake { addr } => {
                run.wakes += 1;
                wake(addr);
            }
            RingStep::Done => {}
        }
        if info.seq as u64 != i { run.bad += 1; }
        if i < n {
            if !frame_ok(&buf, info.len, i) { run.bad += 1; }
        } else if info.len as usize == FRAME_STATS_BYTES {
            let w = |k: usize| u64::from_le_bytes([buf[k], buf[k + 1], buf[k + 2], buf[k + 3],
                                                   buf[k + 4], buf[k + 5], buf[k + 6], buf[k + 7]]);
            run.peer_waits = w(0);
            run.peer_wakes = w(8);
        } else {
            run.bad += 1;
        }
        i += 1;
    }
    run
}

/// The `frame-stream` report: the lane, and the entries both sides made.
fn frame_report(abi: &impl Abi, t: u64, run: &FrameRun, floor_ns: u64) {
    if run.bad != 0 || run.timeouts != 0 {
        fail_line(abi, b"frame-stream wrong frames or lost wakes", -((run.bad + run.timeouts) as i64));
        return;
    }
    report(abi, b"frame-stream", t, N_FRAMES, floor_ns);
    abi.write(b"[VSBENCH] frame-stream entries: consumer=");
    put_u(abi, run.waits);
    abi.write(b"+");
    put_u(abi, run.wakes);
    abi.write(b" producer=");
    put_u(abi, run.peer_waits);
    abi.write(b"+");
    put_u(abi, run.peer_wakes);
    abi.write(b" over ");
    put_u(abi, N_FRAMES);
    abi.write(b" frames of 1440 B\n");
}

/// Wave 11 (SHMRING): `frame-stream`, a LiDAR-scan-sized frame (1440 bytes)
/// streamed one way on the byte-slot ring the kernel's sensor streams use
/// (`SpscBytes` + `BytesProducer`, 16 slots), the consumer draining whatever
/// is there and sleeping on the doorbell only when the ring is empty.
///
/// **What it is, and is not.** The producer here is `VSSRV.ELF` in ring 3,
/// which waits (on the tail) when the ring is full; the kernel's producer
/// never waits and rings the doorbell by a direct call, not a syscall. So
/// this prices the ring's frame path and its entries, with a producer that
/// pays two syscalls the kernel's does not. It does not measure a camera or a
/// LiDAR (the QEMU ones are generated), and a kernel stream is off in the
/// image this runs on.
#[cfg(feature = "azos")]
fn frame_lanes(abi: &(impl Abi + Ipc), peer: u64, floor_ns: u64) {
    use ipc_proto::frame::*;
    use azos_libsys as sys;
    let pages = FRAME_RING_BYTES.div_ceil(sys::PAGE_SIZE) as u64;
    let cap = sys::shm_create_typed(pages, sys::SHM_RW);
    if cap <= 0 { fail_line(abi, b"frame shm_create", cap as i64); return; }
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 { fail_line(abi, b"frame shm_map", va as i64); return; }
    let r = sys::SpscBytes { base: va as usize, cap: FRAME_RING_SLOTS, slot_bytes: FRAME_SLOT_BYTES };
    match sys::fast_ipc_call_ep_moving(peer as u32, [FRAME_SETUP, N_FRAMES, 0, 0], cap as u32) {
        Some(w) if w[0] == FRAME_SETUP + 1 => {}
        Some(w) => { fail_line(abi, b"frame setup refused by peer", w[0] as i64); return; }
        None => { fail_line(abi, b"frame setup call", -1); return; }
    }
    let mut run = FrameRun::default();
    let t = batch(1, || {
        run = frame_consume(&r, N_FRAMES,
            |a, e| sys::notify_wait(a, e, sys::RING_WAIT_NS) == 1,
            |a| { let _ = sys::notify_wake(a, 1); });
    });
    frame_report(abi, t, &run, floor_ns);
}

/// Where a `switch-loaded` task ran, as one console line:
/// `[VSBENCH] azos switch-loaded hart: measurer first=2 last=2`.
///
/// The lane is bimodal on AzOS, and this line is what attributed it
/// (2026-09-13, 20 boots of one frozen binary): the mode is k, the number of
/// peers placed on the measurer's hart. k=1 gave 31-35 k ns/op in 4 boots, k=2
/// gave 48-53 k in 16, no overlap — two tasks per round against three, the
/// 1.5x between the modes. A task that only yields never changes hart on
/// AzOS, so `first` and `last` bracket the whole run and differ only if that
/// stops being true; in all 20 boots they did not.
///
/// Never inside a measured batch (the peers print after their own loop), and
/// deliberately without `ns/op` or the `<side> <lane> =` shape, so
/// `tools/vsbench_compare.sh` does not read it as a lane. Built into one buffer
/// and written once: peers print from other harts at the same time, and a line
/// assembled from several writes interleaves.
fn report_hart(abi: &impl Abi, who: &[u8], first: Option<u64>, last: Option<u64>) {
    fn push(buf: &mut [u8], n: &mut usize, bytes: &[u8]) {
        for &b in bytes {
            if *n < buf.len() {
                buf[*n] = b;
                *n += 1;
            }
        }
    }
    fn push_cpu(buf: &mut [u8], n: &mut usize, v: Option<u64>) {
        let Some(mut v) = v else {
            push(buf, n, b"?");
            return;
        };
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        loop {
            i -= 1;
            digits[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 { break; }
        }
        push(buf, n, &digits[i..]);
    }
    let mut buf = [0u8; 96];
    let mut n = 0usize;
    push(&mut buf, &mut n, b"[VSBENCH] ");
    push(&mut buf, &mut n, SIDE);
    push(&mut buf, &mut n, b" switch-loaded hart: ");
    push(&mut buf, &mut n, who);
    push(&mut buf, &mut n, b" first=");
    push_cpu(&mut buf, &mut n, first);
    push(&mut buf, &mut n, b" last=");
    push_cpu(&mut buf, &mut n, last);
    push(&mut buf, &mut n, b"\n");
    abi.write(&buf[..n]);
}

/// One competitor's timestamps (see [`N_LOAD_PEER_STAMPS`]). Each forked
/// competitor has its own copy; the measurer never touches it.
static mut PEER_STAMPS: [u32; N_LOAD_PEER_STAMPS] = [0; N_LOAD_PEER_STAMPS];

/// Bytes of the window message, measurer → competitor: `t0`, `t1` (`u64` LE
/// counter values bracketing the measured batch). `t0 == t1 == 0` means "no
/// window": the lane gave up after forking, and the competitor reports zero.
const WIN_MSG: usize = 16;
/// Bytes of a competitor's report, competitor → measurer: yields that
/// returned inside the window, yields stamped, switches over the stamped
/// yields, and 1 if the stamps ended before the window did (lower bound).
const PEER_MSG: usize = 32;

/// Read exactly `buf.len()` bytes, retrying a would-block answer with a
/// yield (AzOS answers an empty pipe without blocking). Never inside a
/// measured window. `false` if the descriptor failed or the bound ran out.
fn read_full(abi: &(impl Abi + Shell), fd: u64, buf: &mut [u8]) -> bool {
    let mut got = 0usize;
    let mut tries = 0u32;
    while got < buf.len() {
        let n = abi.fd_read(fd, &mut buf[got..]);
        if n > 0 {
            got += n as usize;
            continue;
        }
        tries += 1;
        if n == 0 || tries > 1_000_000 { return false; }
        abi.yield_now();
    }
    true
}

/// A competitor of `switch-loaded`: stamp [`N_LOAD_PEER_STAMPS`] yields,
/// learn the measurer's window, report, then keep yielding until
/// [`N_LOAD_PEER_ITERS`] so the load outlives everything after it as before.
fn yield_peer(abi: &(impl Abi + Proc + Shell), win_r: u64, win_w: u64, back_r: u64, back_w: u64) -> ! {
    // Only the measurer writes the window and reads the reports: with these
    // closed, a measurer that is gone reads as EOF, not as a wait.
    abi.fd_close(win_w);
    abi.fd_close(back_r);
    if cfg!(feature = "switch-peer-canary") { abi.exit_child() }
    let first = abi.current_cpu();
    // SAFETY: this process's own copy; nothing else in it touches the buffer.
    let stamps = unsafe { &mut *core::ptr::addr_of_mut!(PEER_STAMPS) };
    // Touch every page before the first yield, so its faults are prelude.
    for s in stamps.iter_mut() {
        unsafe { core::ptr::write_volatile(s, 0) };
    }
    let sw0 = abi.ctx_switches();
    let base = bench_core::rdtime();
    let mut i = 0usize;
    while i < N_LOAD_PEER_STAMPS {
        abi.yield_now();
        stamps[i] = bench_core::rdtime().wrapping_sub(base) as u32;
        i += 1;
    }
    let sw1 = abi.ctx_switches();

    let mut win = [0u8; WIN_MSG];
    let ok = read_full(abi, win_r, &mut win);
    let t0 = u64::from_le_bytes(win[0..8].try_into().unwrap());
    let t1 = u64::from_le_bytes(win[8..16].try_into().unwrap());
    let mut inside = 0u64;
    if ok && t1 > t0 {
        for &s in stamps.iter() {
            let t = base.wrapping_add(s as u64);
            if t > t0 && t <= t1 { inside += 1; }
        }
    }
    let last = base.wrapping_add(stamps[N_LOAD_PEER_STAMPS - 1] as u64);
    let truncated = (ok && t1 > t0 && last <= t1) as u64;
    let switches = match (sw0, sw1) {
        (Some((v0, i0)), Some((v1, i1))) => (v1 - v0) + (i1 - i0),
        _ => u64::MAX,
    };
    let mut msg = [0u8; PEER_MSG];
    msg[0..8].copy_from_slice(&inside.to_le_bytes());
    msg[8..16].copy_from_slice(&(N_LOAD_PEER_STAMPS as u64).to_le_bytes());
    msg[16..24].copy_from_slice(&switches.to_le_bytes());
    msg[24..32].copy_from_slice(&truncated.to_le_bytes());
    let _ = abi.fd_write(back_w, &msg);

    let mut j = N_LOAD_PEER_STAMPS as u64;
    while j < N_LOAD_PEER_ITERS {
        abi.yield_now();
        j += 1;
    }
    // After the loop: by then the measurer's batch is long over.
    report_hart(abi, b"peer", first, abi.current_cpu());
    abi.exit_child()
}

/// Context switching **with real competition** for the CPU.
///
/// `sched-yield` measures yielding when nobody else is ready: the scheduler
/// looks, finds nothing better and returns. Here there are `N_LOAD_PEERS`
/// genuinely runnable tasks, so every yield is a full selection and a real
/// context switch.
///
/// **Two numbers, and only the second compares across kernels (wave 15).**
/// `switch-loaded` is the measurer's time per yield: one yield of its own
/// plus whatever ran before it was picked again. How much ran is the
/// scheduler's choice, so the op need not be the same amount of work on two
/// kernels: measured at `-smp 1` under `-icount` (wave 15), AzOS ran all
/// four competitors between two measurer yields and Linux about one (0.50 to
/// 0.96 across runs), with 323 to 500 of the measurer's 500 yields switching. `ctxsw-loaded` divides the
/// same window by the context switches inside it — the measurer's own count
/// plus the competitors' yields that returned inside it (from their stamps),
/// printed only when every competitor yield switched: the cost of one
/// context switch under load, on both kernels.
fn loaded_switch_lane(abi: &(impl Abi + Proc + Shell), floor_ns: u64, unloaded_yield_ns: u64) {
    let (win_r, win_w) = match abi.pipe_open() {
        Ok(p) => p,
        Err(_) => {
            abi.write(b"[VSBENCH] switch-loaded: no pipe for the instrument, no number\n");
            return;
        }
    };
    let (back_r, back_w) = match abi.pipe_open() {
        Ok(p) => p,
        Err(_) => {
            abi.pipe_close(win_r, win_w);
            abi.write(b"[VSBENCH] switch-loaded: no pipe for the instrument, no number\n");
            return;
        }
    };
    let mut spawned = 0u64;
    for _ in 0..N_LOAD_PEERS {
        match abi.spawn_peer_raw() {
            Some(true) => yield_peer(abi, win_r, win_w, back_r, back_w),
            Some(false) => spawned += 1,
            None => break,
        }
    }
    // The competitors' end of the report pipe: once every competitor is
    // gone, the report read below sees EOF instead of waiting out its bound.
    // The window pipe's read end stays open here, so writing a window after
    // the competitors died is never a write without a reader (SIGPIPE).
    abi.fd_close(back_w);
    // Every forked competitor waits for a window message; send one on every
    // path from here on, or it waits until its read bound runs out.
    let send_window = |t0: u64, t1: u64| {
        let mut m = [0u8; WIN_MSG];
        m[0..8].copy_from_slice(&t0.to_le_bytes());
        m[8..16].copy_from_slice(&t1.to_le_bytes());
        for _ in 0..spawned { let _ = abi.fd_write(win_w, &m); }
    };
    if spawned != N_LOAD_PEERS {
        // Without the full load the number does not mean what it says, so it
        // is not reported: two competitors instead of four would be a
        // different measurement under the same label.
        send_window(0, 0);
        abi.pipe_close(win_r, win_w);
        abi.fd_close(back_r);
        abi.write(b"[VSBENCH] switch-loaded: could not spawn the competitors, no number\n");
        return;
    }

    let measurer_first = abi.current_cpu();

    // Yields before measuring, so the competitors have run their prelude and
    // are genuinely in the ready queue rather than freshly created.
    for _ in 0..N_LOAD_WARMUP { abi.yield_now(); }

    let sw_before = abi.ctx_switches();
    let w0 = bench_core::rdtime();
    let t = batch(N_LOAD_YIELDS, || abi.yield_now());
    let w1 = bench_core::rdtime();
    let sw_after = abi.ctx_switches();
    send_window(w0, w1);
    let loaded_ns = ns_per_op(t, N_LOAD_YIELDS);

    // Before the refusal check, so a refused run reports its placement too.
    report_hart(abi, b"measurer", measurer_first, abi.current_cpu());

    // **HOW MANY SWITCHES ACTUALLY HAPPENED.** This lane divides a wall-clock
    // total by a YIELD count and calls the answer the cost of a context
    // switch, which is true only if each yield switched. Both kernels can now
    // say: AzOS through `SYS_TASKINFO`, Linux through `getrusage`.
    let switches = match (sw_before, sw_after) {
        (Some((v0, i0)), Some((v1, i1))) => Some((v1 - v0, i1 - i0)),
        _ => None,
    };

    // The competitors' reports: yields inside the window, and whether each of
    // their stamped yields switched. They arrive once each competitor has
    // stamped all its yields, after the window.
    let mut peer_inside = 0u64;
    let mut peer_stamped = 0u64;
    let mut peer_switches = 0u64;
    let mut peer_truncated = 0u64;
    let mut peer_reports = 0u64;
    for _ in 0..spawned {
        let mut m = [0u8; PEER_MSG];
        if !read_full(abi, back_r, &mut m) { break; }
        let g = |i: usize| u64::from_le_bytes(m[i * 8..i * 8 + 8].try_into().unwrap());
        peer_inside += g(0);
        peer_stamped += g(1);
        peer_switches = peer_switches.saturating_add(g(2));
        peer_truncated += g(3);
        peer_reports += 1;
    }
    abi.pipe_close(win_r, win_w);
    abi.fd_close(back_r);

    // **THIS LANE'S NUMBER IS CONDITIONAL, AND NOTHING USED TO CHECK THE
    // CONDITION.** It means "a yield against four runnable competitors" only
    // if the competitors are competing. Measured 2026-09-10: across nine runs
    // of the same binary it read 30-60 us eight times and 3.3 us once, and the
    // 3.3 us was reported as a 1.4x win over Linux. Reproduced on demand by
    // making the peers return without yielding (3602 against a 3336 unloaded
    // yield). So the number is refused when it is IMPOSSIBLE — at or below the
    // unloaded yield of the same boot — and the ratio to it is always printed.
    if loaded_ns <= unloaded_yield_ns {
        abi.write(b"[VSBENCH] switch-loaded: REFUSED, ");
        put_u(abi, loaded_ns);
        abi.write(b" ns/op is not above the unloaded yield (");
        put_u(abi, unloaded_yield_ns);
        abi.write(b" ns/op): the competitors were not runnable, so this is ");
        abi.write(b"not a loaded switch. No number.\n");
        return;
    }

    report(abi, b"switch-loaded", t, N_LOAD_YIELDS, floor_ns);
    abi.write(b"[VSBENCH] switch-loaded: with ");
    put_u(abi, N_LOAD_PEERS);
    abi.write(b" runnable competitors, ");
    put_u(abi, loaded_ns / unloaded_yield_ns.max(1));
    abi.write(b"x the unloaded yield\n");

    // Per SWITCH, not per call — the number the label always claimed to mean.
    match switches {
        Some((vol, invol)) => {
            abi.write(b"[VSBENCH] ");
            abi.write(SIDE);
            abi.write(b" switch-loaded switches = ");
            put_u(abi, vol);
            abi.write(b" voluntary + ");
            put_u(abi, invol);
            abi.write(b" preempted over ");
            put_u(abi, N_LOAD_YIELDS);
            abi.write(b" yields");
            let total = vol + invol;
            if total > 0 {
                abi.write(b", ");
                put_u(abi, ticks_to_ns(t) / total);
                abi.write(b" ns per SWITCH");
            } else {
                abi.write(b": NONE. This kernel did not switch, so the ");
                abi.write(b"ns/op above is the cost of looking, not switching");
            }
            abi.write(b"\n");
        }
        None => {
            abi.write(b"[VSBENCH] switch-loaded: this kernel cannot report \
switch counts, so ns/op cannot be read as a per-switch cost\n");
        }
    }

    // The instrument line: what one `switch-loaded` op contained.
    let per_op_x100 = peer_inside * 100 / N_LOAD_YIELDS;
    abi.write(b"[VSBENCH] ");
    abi.write(SIDE);
    abi.write(b" switch-loaded competitors: ");
    put_u(abi, peer_inside);
    abi.write(b" competitor yields in the window over ");
    put_u(abi, N_LOAD_YIELDS);
    abi.write(b" measurer yields (");
    put_u(abi, per_op_x100 / 100);
    abi.write(b".");
    if per_op_x100 % 100 < 10 { abi.write(b"0"); }
    put_u(abi, per_op_x100 % 100);
    abi.write(b" per op); ");
    put_u(abi, peer_switches);
    abi.write(b" switches over ");
    put_u(abi, peer_stamped);
    abi.write(b" stamped competitor yields; reports=");
    put_u(abi, peer_reports);
    if peer_truncated > 0 { abi.write(b", TRUNCATED (lower bound)"); }
    abi.write(b"\n");

    // `ctxsw-loaded`: the comparable number, per CONTEXT SWITCH in the
    // window — the measurer's switches (its own counter) plus the
    // competitors' yields in the window, each of which switched (their
    // counters over every stamped yield say so; otherwise no number). A
    // measurer yield that did not switch stays in the window's time: it is
    // what that kernel chose to do with the yield.
    let all_reported = peer_reports == N_LOAD_PEERS && peer_truncated == 0;
    let peers_switched = peer_switches != u64::MAX && peer_switches >= peer_stamped;
    let meas_sw = switches.map(|(v, i)| v + i).unwrap_or(0);
    if all_reported && peers_switched && meas_sw + peer_inside > 0 {
        let yields = N_LOAD_YIELDS + peer_inside;
        abi.write(b"[VSBENCH] ");
        abi.write(SIDE);
        abi.write(b" ctxsw-loaded window: ");
        put_u(abi, meas_sw + peer_inside);
        abi.write(b" switches, ");
        put_u(abi, yields);
        abi.write(b" yields, ");
        put_u(abi, ticks_to_ns(w1 - w0) / yields);
        abi.write(b" ns per yield\n");
        report(abi, b"ctxsw-loaded", w1 - w0, meas_sw + peer_inside, floor_ns);
    } else {
        abi.write(b"[VSBENCH] ctxsw-loaded: the competitors' yields are not all \
accounted for and switched, no number\n");
    }
}

/// NIC egress: datagrams that leave through the network card (RFC-0046 §4
/// stage-1 gate — `udp-roundtrip` below is loopback and never reaches a
/// driver). Destination is the limited broadcast, so no ARP and no received
/// frame is needed.
///
/// Each send is timed on its own and only ACCEPTED sends are summed: ns/op
/// is per frame put on the ring. A send the kernel refuses (TX ring full)
/// is counted and excluded — whether QEMU has drained the ring by the next
/// send depends on when its host-side TX work runs, which is not guest
/// work and differs run to run, so a per-attempt average would mix a
/// host-timing artefact into a per-packet cost. The two clock reads per
/// send are in every sample on every kernel alike.
fn nic_egress_lane(abi: &(impl Abi + Net), floor_ns: u64) {
    if !abi.net_ready() {
        abi.write(b"[VSBENCH] nic-egress: no usable network, no number\n");
        return;
    }
    if let Err(code) = abi.egress_setup() {
        abi.write(b"[VSBENCH] nic-egress: setup failed rc=");
        put_i(abi, code);
        abi.write(b"\n");
        return;
    }
    // Warm-up, and the NIC check: with no NIC every send is refused.
    let mut warm = 0u64;
    for _ in 0..16 {
        if abi.egress_send() { warm += 1; }
    }
    if warm == 0 {
        abi.write(b"[VSBENCH] nic-egress: every send refused (no NIC?), no number\n");
        return;
    }
    let mut sent = 0u64;
    let mut ticks = 0u64;
    let mut attempts = 0u64;
    while sent < N_EGRESS && attempts < N_EGRESS * 20 {
        attempts += 1;
        let t0 = bench_core::rdtime();
        let ok = abi.egress_send();
        let t1 = bench_core::rdtime();
        if ok {
            ticks += t1 - t0;
            sent += 1;
        }
    }
    if sent == 0 {
        abi.write(b"[VSBENCH] nic-egress: every timed send refused, no number\n");
        return;
    }
    report(abi, b"nic-egress", ticks, sent, floor_ns);
    abi.write(b"[VSBENCH] nic-egress: sent=");
    put_u(abi, sent);
    abi.write(b" refused=");
    put_u(abi, attempts - sent);
    abi.write(b"\n");
}

/// UDP round trip against a local peer.
///
/// **Blocked until today** by three absences in this kernel: local delivery,
/// `connect` on UDP and `send` on UDP. All three are in place now.
///
/// Both sides **poll with yield**, they do not block. Azos cannot block —
/// its `recv` returns empty — so letting Linux block would compare two
/// different algorithms under one label.
fn net_lane(abi: &(impl Abi + Net + Proc), floor_ns: u64) {
    if !abi.net_ready() {
        abi.write(b"[VSBENCH] udp-rt: no usable network, no number\n");
        return;
    }
    const P_CLIENTE: u16 = 7100;
    const P_ECO: u16 = 7101;

    match abi.spawn_peer_raw() {
        Some(true) => {
            // Child: the echo side. Ports mirrored relative to the client.
            if abi.net_setup(P_ECO, P_CLIENTE).is_ok() {
                // A margin above what is measured: if the echo dies first, the
                // client exhausts its poll budget and the lane reports nothing.
                abi.net_echo(N_NET * 4);
            }
            abi.exit_child();
        }
        Some(false) => {}
        None => {
            abi.write(b"[VSBENCH] udp-rt: could not fork the peer, no number\n");
            return;
        }
    }

    if let Err(code) = abi.net_setup(P_CLIENTE, P_ECO) {
        abi.write(b"[VSBENCH] udp-rt: setup failed rc=");
        put_i(abi, code);
        abi.write(b" (-1 no IP, -2xxx socket, -3xxx bind, -4xxx connect)\n");
        return;
    }

    // Rendezvous: the child may not have reached its bind yet. Whatever
    // establishing it costs is discarded, as in the IPC lane.
    let mut listo = false;
    for _ in 0..8 {
        if abi.net_round_trip().is_some() { listo = true; break; }
    }
    if !listo {
        abi.net_stop_echo();
        abi.write(b"[VSBENCH] udp-rt: the peer never answered, no number\n");
        return;
    }

    let mut fallo = false;
    let t = batch(N_NET, || {
        if abi.net_round_trip().is_none() { fallo = true; }
    });
    // The echo exits on this; it would otherwise poll for the rest of the run.
    if !cfg!(feature = "echo-stop-canary") { abi.net_stop_echo(); }
    if fallo {
        abi.write(b"[VSBENCH] udp-rt: a round trip never came back, no number\n");
    } else {
        report(abi, b"udp-roundtrip", t, N_NET, floor_ns);
    }
}

/// TCP bulk, both directions, against a host peer over QEMU user networking
/// (wave 15): `tcp-bulk-tx` (the guest sends [`TCP_BULK_BYTES`]) and
/// `tcp-bulk-rx` (the guest receives them). One op is one KiB, so ns/op is
/// guest nanoseconds per KiB, and under `-icount shift=0` (the TCP pass of
/// `tools/vsbench_compare.sh` always runs so) instructions per KiB: the
/// whole guest, kernel and application, at one hart.
///
/// **One algorithm on both kernels**, as `udp-roundtrip`: non-blocking calls
/// and a yield when nothing moved. AzOS cannot block in `send` or `recv`, and
/// in a `bench-minimal` boot nothing else runs its network stack: a `recv`
/// is what processes received frames (ACKs included), so a `send` that took
/// nothing is followed by a `recv` on both sides before the yield.
///
/// **What the number holds, and what it cannot.** The clock runs from the
/// request to the last byte (rx) or to the peer's [`TCP_DONE`] after its
/// last read (tx), so it covers the whole transfer. The host side (slirp
/// and the peer) runs on host threads beside the guest: guest instructions
/// spent polling while the host works are counted, and how many depends on
/// the host. Read the spread of several runs before reading a difference.
fn tcp_bulk_lanes(abi: &(impl Abi + Net), floor_ns: u64) {
    let Some(port) = abi.tcp_peer_port() else {
        abi.write(b"[VSBENCH] tcp-bulk: no host peer on this boot (the TCP pass \
of tools/vsbench_compare.sh brings one), no number\n");
        return;
    };
    tcp_bulk_one(abi, port, true, floor_ns);
    tcp_bulk_one(abi, port, false, floor_ns);
}

/// The data buffer of the TCP bulk lanes: one chunk, reused. A static, not
/// a stack array: [`TCP_CHUNK`] is more than a ring-3 stack should carry.
struct TcpBuf(core::cell::UnsafeCell<[u8; TCP_CHUNK]>);
unsafe impl Sync for TcpBuf {}
static TCP_BUF: TcpBuf = TcpBuf(core::cell::UnsafeCell::new([0xA5; TCP_CHUNK]));

fn tcp_bulk_one(abi: &(impl Abi + Net), port: u16, tx: bool, floor_ns: u64) {
    let label: &[u8] = if tx { b"tcp-bulk-tx" } else { b"tcp-bulk-rx" };
    if let Err(code) = abi.tcp_open(port) {
        fail_line(abi, label, code);
        return;
    }
    // Single-threaded: the only reference to the buffer while this runs.
    let buf = unsafe { &mut *TCP_BUF.0.get() };
    let total = TCP_BULK_BYTES as usize;
    let n = (total as u32).to_be_bytes();
    let req = [if tx { TCP_CMD_TX } else { TCP_CMD_RX }, n[0], n[1], n[2], n[3]];
    let mut calls = 0u64;      // calls that moved at least one byte
    let mut empty = 0u64;      // polls that moved nothing (each then yields)
    let mut one = [0u8; 1];
    // When a call last moved a byte. Each poll that moved nothing counts
    // and yields; `TCP_STALL_NS` without progress fails the lane (-110).
    let mut stalled_at = bench_core::rdtime();
    let idle = |empty: &mut u64, at: &mut u64, moved: bool| -> Result<(), i64> {
        let now = bench_core::rdtime();
        if moved { *at = now; return Ok(()); }
        *empty += 1;
        if ticks_to_ns(now - *at) > TCP_STALL_NS { return Err(-110); }
        abi.yield_now();
        Ok(())
    };

    let t0 = bench_core::rdtime();
    let res: Result<(), i64> = (|| {
        // The request: five bytes, normally one call.
        let mut off = 0usize;
        while off < req.len() {
            let r = abi.tcp_send(&req[off..]);
            if r < 0 { return Err(-1000 + r as i64); }
            off += r as usize;
            idle(&mut empty, &mut stalled_at, r > 0)?;
        }
        let mut done = 0usize;
        if tx {
            while done < total {
                let len = (total - done).min(TCP_CHUNK);
                let r = abi.tcp_send(&buf[..len]);
                if r < 0 { return Err(-2000 + r as i64); }
                if r > 0 {
                    done += r as usize;
                    calls += 1;
                } else {
                    // Nothing taken: let the stack read its ACKs. The peer
                    // sends nothing before the last byte, so a byte here is
                    // a protocol error.
                    let g = abi.tcp_recv(&mut one);
                    if g != 0 { return Err(-3000 + g as i64); }
                }
                idle(&mut empty, &mut stalled_at, r > 0)?;
            }
            // The peer's answer: every byte reached its `read`.
            loop {
                let g = abi.tcp_recv(&mut one);
                if g < 0 { return Err(-4000 + g as i64); }
                if g > 0 {
                    if one[0] != TCP_DONE { return Err(-4999); }
                    break;
                }
                idle(&mut empty, &mut stalled_at, false)?;
            }
        } else {
            while done < total {
                let len = (total - done).min(TCP_CHUNK);
                let r = abi.tcp_recv(&mut buf[..len]);
                if r < 0 { return Err(-5000 + r as i64); }
                if r > 0 {
                    done += r as usize;
                    calls += 1;
                }
                idle(&mut empty, &mut stalled_at, r > 0)?;
            }
        }
        Ok(())
    })();
    let t1 = bench_core::rdtime();
    abi.tcp_close();
    if let Err(code) = res {
        // -110: no progress for TCP_STALL_NS.
        fail_line(abi, label, code);
        return;
    }
    report(abi, label, t1 - t0, TCP_BULK_BYTES / 1024, floor_ns);
    let ns = ticks_to_ns(t1 - t0).max(1);
    abi.write(b"[VSBENCH] ");
    abi.write(label);
    abi.write(b": ");
    put_u(abi, TCP_BULK_BYTES);
    abi.write(b" bytes, ");
    put_u(abi, (TCP_BULK_BYTES as u128 * 1_000_000_000 / ns as u128) as u64);
    abi.write(b" bytes/s guest clock, ");
    put_u(abi, calls);
    abi.write(if tx { b" sends" } else { b" recvs" });
    abi.write(b" that moved data, ");
    put_u(abi, empty);
    abi.write(b" empty polls, ");
    put_u(abi, abi.tcp_send_refused());
    abi.write(b" sends refused\n");
}

/// Fork without reaping, until the kernel refuses. Exists to make
/// `sys_fork_impl`'s task-pool-exhausted refusal (`ForkRefusalSite::
/// PoolExhausted`, `crates/core/sched/src/process.rs`) fire on demand in a QEMU
/// boot, instead of trusting the fork-bomb guard from reading the source.
///
/// Every child spins on `yield_now()` forever — never exits, never gets
/// reaped — so each successful fork permanently costs the parent one
/// `MAX_TASKS` slot. Bounded well past any plausible slot count so this
/// terminates on the kernel's refusal rather than a guessed trip count.
///
/// Feature-gated (`fork-bomb`) and called only from a `#[cfg]`'d call site
/// below: this is not part of the default `run()` any build under
/// `tools/vsbench_aarch64.sh` or the main gate links.
#[cfg(feature = "fork-bomb")]
fn fork_bomb_probe(abi: &(impl Abi + Proc)) {
    const ATTEMPTS: u32 = 96; // > MAX_TASKS=64 with room for background tasks
    let mut spawned: u32 = 0;
    let mut refused = false;
    for _ in 0..ATTEMPTS {
        match abi.spawn_peer_raw() {
            Some(true) => loop { abi.yield_now(); }, // child: never returns
            Some(false) => spawned += 1,               // parent: keep going
            None => { refused = true; break; }          // sys_fork_impl's -1
        }
    }
    abi.write(b"[VSBENCH] fork-bomb: spawned=");
    put_u(abi, spawned as u64);
    if refused {
        abi.write(b" refused=yes\n");
    } else {
        abi.write(b" refused=no\n");
    }
}

/// Ops per ioring lane point: divisible by every batch size below, so each
/// point runs the same number of operations. Shared with the Linux
/// counterpart (`abi_linux::ioring_lanes`), as are the batch sizes and the
/// label builder: the comparison joins the two sides on the label bytes.
const N_IORING_OPS: u64 = 1920;
/// Batch sizes: 1 up to `RING_SQ_SIZE` (32).
const IORING_BATCHES: [u32; 6] = [1, 2, 4, 8, 16, 32];

/// `<prefix><n>` into a fixed buffer, for a lane label.
fn label_n(prefix: &[u8], n: u32) -> ([u8; 32], usize) {
    let mut b = [0u8; 32];
    b[..prefix.len()].copy_from_slice(prefix);
    let mut len = prefix.len();
    let mut digits = [0u8; 10];
    let (mut i, mut v) = (digits.len(), n);
    if v == 0 { i -= 1; digits[i] = b'0'; }
    while v > 0 { i -= 1; digits[i] = b'0' + (v % 10) as u8; v /= 10; }
    for &d in &digits[i..] { b[len] = d; len += 1; }
    while len < 16 { b[len] = b' '; len += 1; }
    (b, len)
}

/// `ioring-batch`: N operations through one `SYS_IORING_SUBMIT_TYPED` against
/// the same N operations as N syscalls. The Linux side drives real `io_uring`
/// for the same three operations (`abi_linux::ioring_lanes`).
///
/// Three operations, each quoted per operation, ring and syscall:
///  * `nop`  — the mechanism alone: a NOP entry against the null syscall.
///  * `chan` — a real entry that resolves a capability and moves a message:
///    a channel send followed by a receive (one pair = two operations) against
///    `SYS_CHAN_WRITE_TYPED` + `SYS_CHAN_READ_TYPED`. Batches start at 2.
///  * `tmr`  — a timer whose deadline has passed (completes 1, parks nothing)
///    against `SYS_SLEEP_UNTIL(0)`.
///
/// Every completion is checked after the batch that produced it — result and
/// refusal flag — and a wrong one prints `FAIL rc=`, which
/// `tools/vsbench_aarch64.sh` refuses. A number from a ring whose entries were
/// refused (a seccomp row without the typed call) would be the cost of a
/// refusal.
///
/// The per-batch CQ drain is inside the measurement: consuming completions is
/// part of what a ring client pays.
#[cfg(feature = "azos")]
fn ioring_lanes(abi: &impl Abi, floor_ns: u64) {
    use azos_libsys as sys;

    let mut out = [0u8; 8];
    let cap = sys::ioring_create_typed(&mut out);
    if cap <= 0 {
        abi.write(b"[VSBENCH] ioring-batch: FAIL rc=");
        put_i(abi, cap as i64);
        abi.write(b" (create)\n");
        return;
    }
    let ring = sys::ioring::Ring::new(cap as u32, out);
    let ch = sys::chan_create_typed();
    if ch <= 0 {
        abi.write(b"[VSBENCH] ioring-batch: FAIL rc=");
        put_i(abi, ch as i64);
        abi.write(b" (channel create)\n");
        let _ = sys::ioring_destroy_typed(ring.cap);
        return;
    }
    let ch = ch as u32;
    // The message the channel entries send, at offset 0; receives land at 64.
    unsafe { core::ptr::copy_nonoverlapping(b"vsbench!".as_ptr(), ring.data(), 8); }

    // Drain and check: `want(i)` is the result entry `i` of a batch must carry.
    let drain = |n: u32, want: &dyn Fn(u32) -> i32, bad: &mut u32, last: &mut i64| {
        let mut i = 0;
        while let Some((_, result, flags)) = ring.pop() {
            if flags & sys::ioring::CQE_F_REFUSED != 0 || result != want(i) {
                *bad += 1;
                *last = result as i64;
            }
            i += 1;
        }
        if i != n { *bad += 1; }
    };
    let fail = |what: &[u8], bad: u32, last: i64| {
        abi.write(b"[VSBENCH] ioring-batch ");
        abi.write(what);
        abi.write(b": FAIL rc=");
        put_i(abi, last);
        abi.write(b" in ");
        put_u(abi, bad as u64);
        abi.write(b" batches\n");
    };

    // Syscall twins, per operation.
    let chan_pairs = N_IORING_OPS / 2;
    let mut buf = [0u8; 8];
    let mut twin_bad = 0u32;
    let t_chan = batch(chan_pairs, || {
        if sys::chan_write_typed(ch, b"vsbench!") != 0 { twin_bad += 1; }
        if sys::chan_read_typed(ch, &mut buf) != 8 { twin_bad += 1; }
    });
    let t_tmr = batch(N_IORING_OPS, || {
        if sys::sleep_until_ns(0) != sys::SleepResult::Overrun { twin_bad += 1; }
    });
    if twin_bad != 0 {
        fail(b"twins", twin_bad, -1);
        return;
    }
    report(abi, b"chan-call       ", t_chan, N_IORING_OPS, floor_ns);
    report(abi, b"sleep-until0    ", t_tmr, N_IORING_OPS, floor_ns);
    let chan_call_ns = ns_per_op(t_chan, N_IORING_OPS);
    let tmr_call_ns = ns_per_op(t_tmr, N_IORING_OPS);

    // Smallest batch whose per-op cost is at or below the syscall's, 0 if none.
    let mut be = [0u32; 3];
    for &n in IORING_BATCHES.iter() {
        let iters = N_IORING_OPS / n as u64;
        for (k, prefix) in [&b"ioring-nop  x"[..], b"ioring-chan x", b"ioring-tmr  x"].iter().enumerate() {
            if k == 1 && n < 2 { continue; }
            let (mut bad, mut last) = (0u32, 0i64);
            let t = batch(iters, || {
                for i in 0..n {
                    let ok = match k {
                        0 => ring.push(sys::ioring::OP_NOP, 0, 0, 0, i as u64),
                        1 if i % 2 == 0 => ring.push(sys::ioring::OP_CHAN_SEND, ch, 0, 8, i as u64),
                        1 => ring.push(sys::ioring::OP_CHAN_RECV, ch, 64, 8, i as u64),
                        _ => ring.push(sys::ioring::OP_TIMER, 0, 0, 0, i as u64),
                    };
                    if !ok { bad += 1; }
                }
                let rc = sys::ioring_submit_typed(ring.cap);
                if rc != n as isize { bad += 1; last = rc as i64; }
                match k {
                    0 => drain(n, &|_| 0, &mut bad, &mut last),
                    1 => drain(n, &|i| if i % 2 == 0 { 0 } else { 8 }, &mut bad, &mut last),
                    _ => drain(n, &|_| 1, &mut bad, &mut last),
                }
            });
            if bad != 0 {
                fail(prefix, bad, last);
                continue;
            }
            let (label, len) = label_n(prefix, n);
            report(abi, &label[..len], t, iters * n as u64, floor_ns);
            let per_op = ns_per_op(t, iters * n as u64);
            let twin = [floor_ns, chan_call_ns, tmr_call_ns][k];
            if be[k] == 0 && per_op <= twin { be[k] = n; }
        }
    }
    // Not a lane line (no `ns/op`), so the comparison scripts do not read it.
    abi.write(b"[VSBENCH] ioring-batch break-even N (0 = never): nop=");
    put_u(abi, be[0] as u64);
    abi.write(b" chan=");
    put_u(abi, be[1] as u64);
    abi.write(b" tmr=");
    put_u(abi, be[2] as u64);
    abi.write(b"\n");

    let _ = sys::close_typed(ch);
    let _ = sys::ioring_destroy_typed(ring.cap);
}

/// `sqpoll`: the same NOP entries with an SQ poller consuming the ring —
/// no submit per batch, a wake-up submit only when the poller has parked.
///
/// Runs only when the kernel's topology lets this task start a poller
/// (`sqpoll_idle_ms` on the autorun row, the kernel's `sqpoll-bench`
/// feature); otherwise the START is refused `-EPERM` and this says so.
///
/// **Read at `-smp 4`, not `-smp 1`.** On one hart the poller and this task
/// share the CPU, so a completion waits for this task to yield: the number is
/// the scheduler's round trip, not the poller's. The waits below yield after
/// a short spin so the lane still completes on one hart; `syscalls/op` says
/// how many kernel entries the lane actually made per operation.
///
/// Also checks, before measuring, that the poller REFUSES what the owner may
/// not do: a forged `Cap<File>` read through the poller completes
/// `-ECAPSTALE` with the refusal flag, the answer the syscall gives.
#[cfg(feature = "azos")]
fn sqpoll_lanes(abi: &impl Abi, floor_ns: u64) {
    use azos_libsys as sys;

    let mut out = [0u8; 8];
    let cap = sys::ioring_create_typed(&mut out);
    if cap <= 0 {
        abi.write(b"[VSBENCH] sqpoll: FAIL rc=");
        put_i(abi, cap as i64);
        abi.write(b" (create)\n");
        return;
    }
    let ring = sys::ioring::Ring::new(cap as u32, out);
    // One wake-up submit when the poller has parked (see `sys::ioring::Ring::needs_wakeup`).
    let kick = || -> bool {
        if ring.needs_wakeup() {
            let _ = sys::ioring_submit_typed(ring.cap);
            return true;
        }
        false
    };
    let mut syscalls = 0u64;
    // Spin, then yield: see the lane doc for why a wait may yield.
    let wait_one = |syscalls: &mut u64| -> Option<(u64, i32, u32)> {
        let mut spins = 0u32;
        loop {
            if let Some(c) = ring.pop() { return Some(c); }
            spins += 1;
            if spins % 64 == 0 {
                let _ = sys::yield_now();
                *syscalls += 1;
            }
            if spins > 64 * 100_000 { return None; }
        }
    };

    let _ = ring.push(sys::ioring::OP_SQPOLL_START, 0, 0, 0, 0);
    let rc = sys::ioring_submit_typed(ring.cap);
    match ring.pop() {
        Some((_, 0, 0)) if rc == 1 && ring.polled() => {}
        Some((_, res, _)) => {
            abi.write(b"[VSBENCH] sqpoll: off, START answered ");
            put_i(abi, res as i64);
            abi.write(b" (no sqpoll_idle_ms in the topology row, or refused on a one-hart machine)\n");
            let _ = sys::ioring_destroy_typed(ring.cap);
            return;
        }
        None => {
            abi.write(b"[VSBENCH] sqpoll: FAIL rc=");
            put_i(abi, rc as i64);
            abi.write(b" (START did not complete)\n");
            let _ = sys::ioring_destroy_typed(ring.cap);
            return;
        }
    }

    // The refusal, through the poller.
    let _ = ring.push(sys::ioring::OP_FILE_READ, 0, 0, 16, 0x0F);
    if kick() { syscalls += 1; }
    match wait_one(&mut syscalls) {
        Some((0x0F, res, flags)) if flags & sys::ioring::CQE_F_REFUSED != 0 && res as isize == sys::file_read_typed(0, &mut [0u8; 16]) => {
            abi.write(b"[VSBENCH] sqpoll: forged Cap<File> read refused by the poller, rc=");
            put_i(abi, res as i64);
            abi.write(b" (the syscall's answer)\n");
        }
        other => {
            abi.write(b"[VSBENCH] sqpoll: FAIL rc=");
            put_i(abi, other.map_or(-1, |c| c.1 as i64));
            abi.write(b" (the poller did not refuse a forged file read as the syscall does)\n");
            let _ = sys::ioring_destroy_typed(ring.cap);
            return;
        }
    }

    for &n in [1u32, 32].iter() {
        let iters = N_IORING_OPS / n as u64;
        let (mut bad, mut last) = (0u32, 0i64);
        let before = syscalls;
        let t = batch(iters, || {
            for i in 0..n {
                if !ring.push(sys::ioring::OP_NOP, 0, 0, 0, i as u64) { bad += 1; }
            }
            if kick() { syscalls += 1; }
            for _ in 0..n {
                match wait_one(&mut syscalls) {
                    Some((_, 0, 0)) => {}
                    Some((_, res, _)) => { bad += 1; last = res as i64; }
                    None => { bad += 1; last = -110; }
                }
            }
        });
        if bad != 0 {
            abi.write(b"[VSBENCH] sqpoll-nop: FAIL rc=");
            put_i(abi, last);
            abi.write(b"\n");
            continue;
        }
        let (label, len) = label_n(b"sqpoll-nop  x", n);
        report(abi, &label[..len], t, iters * n as u64, floor_ns);
        abi.write(b"[VSBENCH] sqpoll x");
        put_u(abi, n as u64);
        abi.write(b": kernel entries per 1000 ops = ");
        put_u(abi, (syscalls - before) * 1000 / (iters * n as u64));
        abi.write(b"\n");
    }

    // Idle: past the 20 ms idle time the poller parks and says so on the page;
    // one kicked entry then costs one wake-up submit.
    let _ = sys::sleep_until_ns(sys::vdso_now_ns().saturating_add(60_000_000));
    let flags = unsafe { core::ptr::read_volatile((ring.va + sys::ioring::SQ_FLAGS) as *const u32) };
    abi.write(b"[VSBENCH] sqpoll: parked after idle = ");
    abi.write(if flags & sys::ioring::SQ_F_NEED_WAKEUP != 0 { b"yes" } else { b"no" });
    let _ = ring.push(sys::ioring::OP_NOP, 0, 0, 0, 0x77);
    let t0 = bench_core::rdtime();
    let kicked = kick();
    let woke = wait_one(&mut syscalls);
    let dt = bench_core::rdtime().wrapping_sub(t0);
    abi.write(b", wake-up submit = ");
    abi.write(if kicked { b"yes" } else { b"no" });
    abi.write(b", parked-to-completion = ");
    put_u(abi, ticks_to_ns(dt));
    abi.write(if matches!(woke, Some((0x77, 0, 0))) { b" ns\n" } else { b" ns FAIL rc=-1\n" });

    // The poller may hold the ring mid-pass: a destroy then answers -EBADF.
    let mut rc = sys::ioring_destroy_typed(ring.cap);
    let mut tries = 0;
    while rc != 0 && tries < 1000 {
        let _ = sys::yield_now();
        rc = sys::ioring_destroy_typed(ring.cap);
        tries += 1;
    }
    if rc != 0 {
        abi.write(b"[VSBENCH] sqpoll: FAIL rc=");
        put_i(abi, rc as i64);
        abi.write(b" (destroy)\n");
    }
}

fn run<A: Abi + Ipc + Mem + Net + Proc + Shell + Vdso + Threads>(abi: &A) {
    abi.write(b"[VSBENCH] side=");
    abi.write(SIDE);
    abi.write(b" start\n");
    // `VSBENCH_LANES`: sections not named are skipped; the default runs all.
    let lanes = abi.lanes();
    if !lanes.is_all() {
        abi.write(b"[VSBENCH] lanes filtered: only the named sections run\n");
    }

    // 1. Syscall floor. Everything else is quoted against this, so it is
    //    measured first and never inside another batch.
    let t_floor = batch(N, || abi.null_syscall());
    let floor_ns = ns_per_op(t_floor, N);
    report(abi, b"syscall-floor", t_floor, N, floor_ns);

    // 2. Voluntary yield. On a single runnable task this is the scheduler's
    //    "decide there is nothing better to do" path — the cheapest honest
    //    look at dispatch cost that needs no second process.
    let t_yield = batch(N, || abi.yield_now());
    report(abi, b"sched-yield  ", t_yield, N, floor_ns);
    // Kept for `loaded_switch_lane`: the UNLOADED cost of the same operation,
    // measured in this same boot, is what makes the loaded number falsifiable.
    let unloaded_yield_ns = ns_per_op(t_yield, N);

    // 2b. The same two mechanisms, measured per operation instead of in bulk.
    //     Bracketing every call with `rdtime` costs something, so these are
    //     not comparable with the means above — only with the same lane on
    //     the other kernel.
    let tail_floor = batch_tail(N, || abi.null_syscall());
    report_tail(abi, b"syscall", &tail_floor);
    let tail_yield = batch_tail(N, || abi.yield_now());
    report_tail(abi, b"yield  ", &tail_yield);

    // 3. IPC round trip, between yield and the closing floor so it is quoted
    //    against the same run's floor and still bounded by the same noise
    //    check. A separate binary or a separate run would break the rule that
    //    every lane is quoted against the floor of its own run.
    if !lanes.on(b"ipc") {
    } else if let Some(peer) = ipc_roundtrip(abi, floor_ns) {
        // 3b. Wave 6: notify/wait and the shm ring, against the same peer.
        #[cfg(feature = "azos")]
        ring_lanes(abi, peer, floor_ns);
        // 3c. Wave 11 (SHMRING): a driver request, today's path against a
        //     shared-memory slot ring, same peer.
        #[cfg(feature = "azos")]
        drv_lanes(abi, peer, floor_ns);
        #[cfg(feature = "azos")]
        frame_lanes(abi, peer, floor_ns);
        // Linux: the same ring core over futex, served by its own forked
        // child (the pipe server above cannot receive a mapping).
        #[cfg(feature = "linux")]
        abi_linux::ring_lanes(abi, floor_ns);
        #[cfg(feature = "linux")]
        abi_linux::drv_lanes(abi, floor_ns);
        #[cfg(feature = "linux")]
        abi_linux::frame_lanes(abi, floor_ns);
        release_peer(abi, peer);
    }

    // 4. Memory: mapping bookkeeping and the demand-fault path.
    if lanes.on(b"mem") { mem_lanes(abi, floor_ns); }

    // 4b. Heap and processes: two operations the harness used without ever
    //     measuring.
    if lanes.on(b"proc") { proc_lanes(abi, floor_ns); }
    if lanes.on(b"disk") { disk_lanes(abi, floor_ns); }
    // 4b'. Wave 13: threads of one process, both sides.
    if lanes.on(b"thread") { thread_lanes::<A>(abi, floor_ns); }

    // 4c. The only lane that measures the cost of NOT entering the kernel.
    if lanes.on(b"vdso") { vdso_lanes(abi, floor_ns); }
    // 4d. Wave 6: the task's own vDSO page — its sensors and counters.
    #[cfg(feature = "azos")]
    if lanes.on(b"vdso") { vdso_task_lanes(abi, floor_ns); }
    // Linux: only `taskinfo [call]` has a counterpart, and it is the very
    // call `ctx_switches` already makes (`getrusage`), in the same batch.
    #[cfg(feature = "linux")]
    if lanes.on(b"vdso") {
        let t_cs = batch(N_VDSO, || { core::hint::black_box(abi.ctx_switches()); });
        report(abi, b"taskinfo [call]", t_cs, N_VDSO, floor_ns);
    }

    // 4d. N operations per trap against N traps (`sqpoll` is AzOS only).
    #[cfg(feature = "azos")]
    if lanes.on(b"ioring") { ioring_lanes(abi, floor_ns); }
    #[cfg(feature = "linux")]
    if lanes.on(b"ioring") { abi_linux::ioring_lanes(abi, floor_ns); }
    #[cfg(feature = "azos")]
    if lanes.on(b"ioring") { sqpoll_lanes(abi, floor_ns); }

    // 4e. Wave 12: the user shell's primitives (`bench_core::Shell`), both
    //     sides. Appended before the closing floor, so no lane above moves.
    if lanes.on(b"shell") { shell_lanes(abi, floor_ns); }

    // 4f. Wave 13 (RT7): periodic timer wake jitter, both sides. Appended
    //     before the closing floor, so no lane above moves.
    if lanes.on(b"timer") { timer_periodic_lane(abi); }

    // 5. The floor again, at the end. Not redundant: its spread against the
    //    first measurement is this run's noise floor, and any conclusion
    //    smaller than that spread is not a conclusion. Cheap insurance
    //    against reporting host load as a kernel difference.
    let t_floor2 = batch(N, || abi.null_syscall());
    report(abi, b"syscall-floor2", t_floor2, N, floor_ns);

    // 6. Context switching under load. **Deliberately after `syscall-floor2`.**
    //    It leaves four runnable competitors behind, and placing it earlier
    //    would have the noise control measured with that load on top: the
    //    resulting spread would look like host noise when it is declared load.
    //    Last, and the noise floor stays clean.
    if lanes.on(b"net") {
        nic_egress_lane(abi, floor_ns);
        net_lane(abi, floor_ns);
    }
    // 6b. Wave 15: TCP bulk against a host peer. Only a boot with a NIC and
    //     a peer measures it (the TCP pass of tools/vsbench_compare.sh);
    //     every other boot prints one line and moves on.
    if lanes.on(b"tcp") { tcp_bulk_lanes(abi, floor_ns); }

    if lanes.on(b"switch") { loaded_switch_lane(abi, floor_ns, unloaded_yield_ns); }

    // Reserved: socketpair and futex on the Linux side, to bracket the pipe
    // number. One primitive per side is enough for a first honest comparison.
    let _ = N_SLOW;

    // `fork-bomb` only, and strictly LAST: it leaves the task pool full of
    // spinning children on purpose, so nothing timed above it can be
    // perturbed by tasks this lane creates.
    #[cfg(feature = "fork-bomb")]
    fork_bomb_probe(abi);

    abi.write(b"[VSBENCH] side=");
    abi.write(SIDE);
    abi.write(b" done\n");
}

#[cfg(feature = "azos")]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    run(&abi_azos::AzosAbi);
    azos_libsys::exit(0);
}

/// A naked `_start` **because the original `sp` is required**.
///
/// The kernel hands the process `argc`, `argv`, `envp` and the auxiliary
/// vector on the stack. An ordinary `extern "C"` has already run its prologue
/// by the time the first line of Rust executes, and that prologue moves `sp`:
/// reading it then would give a shifted position and the auxiliary-vector walk
/// would land in garbage. Naked, the first instruction is ours.
#[cfg(feature = "linux")]
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!("mv a0, sp", "j {0}", sym linux_main)
}

#[cfg(feature = "linux")]
extern "C" fn linux_main(sp: usize) -> ! {
    // Wave 12: started by the `spawn+wait` lane as its exit-at-once child.
    if abi_linux::init_args(sp) {
        abi_linux::exit(0);
    }
    // Before measuring anything: resolve the vDSO while the initial stack is
    // still intact.
    abi_linux::vdso_init(sp);
    run(&abi_linux::LinuxAbi);
    abi_linux::drain_console();
    abi_linux::exit(0)
}

#[cfg(any(feature = "azos", feature = "linux"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Wakes measured by `timer-periodic` (after [`TIMER_PERIODIC_WARM`]).
const TIMER_PERIODIC_N: usize = 500;
const TIMER_PERIODIC_WARM: usize = 20;
/// The period: 1 ms, rt-motor's.
const TIMER_PERIODIC_NS: u64 = 1_000_000;

/// Wave 13 (RT7): `timer-periodic` — a task sleeps to absolute deadlines one
/// period apart and records how late each wake is (`now - deadline`, ns, on
/// the clock the sleep is defined on). AzOS: `SYS_SLEEP_UNTIL` against the
/// vDSO clock; Linux: `clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME)` against
/// the vDSO `clock_gettime(CLOCK_MONOTONIC)`. Not a `ns/op` lane (the
/// period is the op): one line,
/// `[VSBENCH] timer-periodic 1ms: wakes=N late_ns mean=.. p50=.. p99=.. max=.. overruns=..`.
/// A deadline already past when a sleep is entered (the previous wake was
/// later than a period) is an overrun: the next deadline is re-based on the
/// clock, so one stall is not counted again on every later wake.
fn timer_periodic_lane(abi: &(impl Abi + Vdso)) {
    let mut late = [0u64; TIMER_PERIODIC_N];
    let mut overruns = 0u64;
    let mut next = timer_now_ns(abi) + TIMER_PERIODIC_NS;
    for i in 0..TIMER_PERIODIC_WARM + TIMER_PERIODIC_N {
        timer_sleep_until_ns(next);
        let t = timer_now_ns(abi);
        if i >= TIMER_PERIODIC_WARM {
            late[i - TIMER_PERIODIC_WARM] = t.saturating_sub(next);
        }
        next += TIMER_PERIODIC_NS;
        if next <= t {
            overruns += 1;
            next = t + TIMER_PERIODIC_NS;
        }
    }
    late.sort_unstable();
    let sum: u64 = late.iter().sum();
    abi.write(b"[VSBENCH] timer-periodic 1ms: wakes=");
    put_u(abi, TIMER_PERIODIC_N as u64);
    abi.write(b" late_ns mean=");
    put_u(abi, sum / TIMER_PERIODIC_N as u64);
    abi.write(b" p50=");
    put_u(abi, late[TIMER_PERIODIC_N / 2]);
    abi.write(b" p99=");
    put_u(abi, late[TIMER_PERIODIC_N * 99 / 100]);
    abi.write(b" max=");
    put_u(abi, late[TIMER_PERIODIC_N - 1]);
    abi.write(b" overruns=");
    put_u(abi, overruns);
    abi.write(b"\n");
}

#[cfg(feature = "azos")]
fn timer_now_ns(_abi: &impl Vdso) -> u64 {
    azos_libsys::vdso_now_ns()
}
#[cfg(feature = "azos")]
fn timer_sleep_until_ns(deadline: u64) {
    let _ = azos_libsys::sleep_until_ns(deadline);
}
#[cfg(feature = "linux")]
fn timer_now_ns(abi: &impl Vdso) -> u64 {
    if abi.vdso_ready() { abi.clock_vdso() } else { abi.clock_syscall() }
}
#[cfg(feature = "linux")]
fn timer_sleep_until_ns(deadline: u64) {
    abi_linux::sleep_until_abs_ns(deadline);
}

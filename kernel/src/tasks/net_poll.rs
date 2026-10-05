// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The network polling task and its wake paths (MSI and timer kick).

use crate::*;

/// Network polling daemon (Phase U1: a dedicated task).
///
/// Decouples network I/O from the behavior loop so incoming packets (TCP, UDP,
/// ARP, DHCP) are processed promptly regardless of behavior loop timing.
///
/// K-C27: polls on a 1 kHz nominal timer block, not on `task_yield()`. The
/// old header claimed "~100 Hz (1 yield = 10 ms at 100 Hz scheduler)" —
/// false: a yield returns immediately when nothing outranks the caller, so
/// this loop spun flat out at priority 12 and monopolised hart 3 against
/// all best-effort work. 1 kHz nominal (tick-grid-quantised, see
/// `RT_MOTOR_TICK_INTERVAL`) keeps TCP RTT and the RX ring drain cadence
/// in the low-millisecond range; the ring is sized to the link and counts
/// what it must drop, so a poll-interval burst degrades measurably rather
/// than silently.
///
/// Shared between both ISAs (aarch64 parity, this task): the body has no
/// RISC-V content — `azos_net::net_poll`/`tcp_tick` and
/// `azos_sched::task_block` are already ISA-neutral (`crates/net/net` has
/// no `target_arch` cfg anywhere in it). What kept this riscv64-only was
/// `NET_POLL_INTERVAL` reading `timebase::TIMER_FREQ`, which re-exports
/// `clint::TIMER_FREQ` — a RISC-V-only module by name, even though its own
/// value is just `= platform::hw::TIMER_FREQ` (see `clint.rs`). Reading
/// `platform::hw::TIMER_FREQ` directly below is the identical constant on
/// riscv64 (byte-identical codegen — same value, one alias fewer) and the
/// aarch64 arm's own `CNTFRQ_EL0`-matching value (1 GHz) on that ISA.
///
/// Three modes, chosen once at task start from `virtio::net::irq_driven()`
/// and `net_device::is_ready()` (the NIC backend is selected once, by
/// `net_init()`, before this task is created):
/// - Poll mode (a NIC with no interrupt reaching this task, e.g. virtio-mmio):
///   the loop runs on the `NET_POLL_INTERVAL` timer alone.
/// - IRQ mode (virtio-pci with MSI/MSI-X, both ISAs): an RX MSI wakes this
///   task through [`net_msi_wake`]; the timer only drives `tcp_tick`, and only
///   while `tcp::tick_needed()` is true. A connection that leaves
///   `Closed`/`Listen` elsewhere wakes it through [`net_timer_kick`].
/// - No NIC: nothing can arrive to poll for, so the timer is armed exactly as
///   in IRQ mode, only while `tcp::tick_needed()` (a loopback connection to
///   our own address still needs `tcp_tick`), and [`net_timer_kick`] wakes
///   it. Measured 2026-09-28, riscv64 `--features qemu`, -smp 1, no NIC,
///   30 s idle: 17 900 iterations (596/s) with the 1 ms timer, 0 without.
///   Timer interrupts did not move measurably (603/s -> 616/s): `rt-motor`
///   and `flight-ctrl` also sleep 1 ms, and the tick coalesces the three.
pub(crate) fn net_poll_task(_: usize) {
    kprintln!("[NET-POLL] Phase U1: dedicated network polling task started");

    /// Requested poll period: 1 ms — **a floor, not a rate.**
    ///
    /// This used to say "Nominal poll period: 1 kHz", and the boot line above
    /// says `100Hz`. Both cannot be true, and neither was: `wake_expired_timers`
    /// runs ONLY from the scheduler timer ISR, which fires at `sched_hz`
    /// (default 100, i.e. every 10 ms). A 1 ms deadline can therefore never be
    /// honoured as such — it means "wake me at the first tick after 1 ms".
    ///
    /// **Measured 2026-09-10**, `-smp 4` with a NIC, 12 000 iterations:
    /// the work (`net_poll` + `tcp_tick`) costs **8 µs on average, 526 µs
    /// worst, never above 5 ms**; the wait averages **3.2 ms** (~310 Hz — better
    /// than the tick alone, because IRQ-driven wakes also fire) with a worst
    /// case of **13 ms** (one tick period plus dispatch).
    ///
    /// Poll mode only (see above). The tickless timer now arms the nearest
    /// sleep deadline, so the 1 ms floor is honoured more closely than the
    /// paragraph above says: measured 2026-09-28, riscv64 default features,
    /// -smp 1, no NIC, 30 s: 20 040 iterations (~670/s). That boot had no
    /// NIC, which no longer runs this timer at all (see the modes above).
    ///
    /// So the poller is NOT starved and this is NOT a missed deadline: the
    /// number to compare against is `sched_hz`, not this constant. Raising the
    /// real rate means raising `sched_hz` (config, 10..10_000) or waking this
    /// task from the NIC IRQ instead of a timer — both design changes, neither
    /// made here.
    const NET_POLL_INTERVAL: u64 = azos_drv_base::platform::hw::TIMER_FREQ / 1000;
    /// virtio-pci IRQ mode: RX wakes this task through [`net_msi_wake`], so
    /// the timer only drives `tcp_tick` (retransmission/keep-alive
    /// deadlines, which read the clock themselves) — 10 Hz, and only while
    /// `tcp::tick_needed()` says a connection has a clock-driven deadline.
    const NET_TICK_IRQ_MODE: u64 = azos_drv_base::platform::hw::TIMER_FREQ / 10;
    /// IRQ mode or no NIC, with no TCP deadline pending: nothing but an RX
    /// MSI or a [`net_timer_kick`] can give this task work, so it sleeps
    /// this long.
    /// A self-heal bound, not a poll: 60 s, the same ceiling an idle
    /// non-boot hart gets (`timebase::IDLE_HART_CEILING_US`).
    const NET_IDLE_CEILING_IRQ_MODE: u64 = azos_drv_base::platform::hw::TIMER_FREQ * 60;

    NET_POLL_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    let irq_mode = azos_drv_virtio::virtio::net::irq_driven();
    let no_nic = !azos_drv_net::net_device::is_ready();
    // Arm the timer only while `tcp_tick` has a deadline: in IRQ mode an RX
    // MSI brings frames, and with no NIC no frame can arrive at all.
    let tick_on_demand = irq_mode || no_nic;
    if tick_on_demand {
        // A connection leaving `Closed`/`Listen` outside this task (a
        // `connect` from a syscall, a SYN drained by another reader) wakes
        // this task, which then re-reads `tick_needed` below.
        azos_net::tcp::set_timer_kick(net_timer_kick);
    }
    if no_nic {
        kprintln!("[NET-POLL] no NIC ready: no poll timer, tcp_tick only while a connection needs it");
    }

    // One line the first time an RX MSI arrives after the scheduler
    // started — the runtime half of the IRQ path, which the pre-scheduler
    // DHCP smoke does not exercise. `dispatched` counts the MSIs whose ISR
    // wake took this task out of its timer sleep (`net_msi_wake`); `early`
    // says whether it then ran before that timer would have fired (it can
    // lose the CPU to other tasks for longer than that — informational).
    let mut rx_seen = azos_drv_virtio::virtio::net::msi_counts()[1];
    let mut announced = !azos_drv_virtio::virtio::net::irq_driven();

    loop {
        azos_net::net_poll();
        // AR: TCP tick — drive retransmissions, TIME-WAIT, keep-alive timers.
        azos_net::tcp::tcp_tick();
        let period = if !tick_on_demand {
            NET_POLL_INTERVAL
        } else if azos_net::tcp::tick_needed() {
            NET_TICK_IRQ_MODE
        } else {
            NET_IDLE_CEILING_IRQ_MODE
        };
        NET_POLL_ITERS.fetch_add(1, Ordering::Relaxed);
        let dl = azos_drv_sys::timebase::now() + period;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
        if !announced {
            let rx = azos_drv_virtio::virtio::net::msi_counts()[1];
            if rx != rx_seen {
                announced = true;
                let early = azos_drv_sys::timebase::now() < dl;
                let dispatched = NET_MSI_WAKES[1].load(Ordering::Relaxed);
                let other = NET_MSI_WAKES[0].load(Ordering::Relaxed);
                if dispatched != 0 {
                    kprintln!("[NET-POLL] RX MSI woke this task: rx {} -> {}, dispatched={} other={} early={}",
                        rx_seen, rx, dispatched, other, if early { "y" } else { "n" });
                } else {
                    kprintln!("[NET-POLL] RX MSI taken but no ISR wake dispatched: rx {} -> {}, other={}",
                        rx_seen, rx, other);
                }
            }
            rx_seen = rx;
        }
    }
}

/// TID of `net_poll_task`, published by the task itself (0 = not running).
static NET_POLL_TID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Interrupt path, both ISAs: the virtio-pci NIC took an MSI that
/// `virtio::net::msi_irq` accepted. Wake `net_poll_task` out of its timer
/// sleep; if it is not asleep yet, the wake is stamped (K-C9) and its next
/// block returns at once, so an RX MSI landing while it drains is not lost.
/// Returns whether a task was dispatched.
pub(crate) fn net_msi_wake() -> bool {
    let tid = NET_POLL_TID.load(Ordering::Acquire);
    let woke = tid != 0 && azos_sched::scheduler::wake_task_by_tid(
        tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
    NET_MSI_WAKES[woke as usize].fetch_add(1, Ordering::Relaxed);
    woke
}

/// Registered with `tcp::set_timer_kick` in IRQ mode: a TCP connection left
/// `Closed`/`Listen`, so `tcp_tick` has deadlines again. Same wake as
/// [`net_msi_wake`] (stamped if the task is not asleep yet, so a kick that
/// lands between `tick_needed` and `task_block` is not lost), counted apart.
fn net_timer_kick() {
    let tid = NET_POLL_TID.load(Ordering::Acquire);
    let woke = tid != 0 && azos_sched::scheduler::wake_task_by_tid(
        tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
    NET_TIMER_KICKS.fetch_add(woke as u32, Ordering::Relaxed);
}

/// [`net_timer_kick`] calls that dispatched the poller.
static NET_TIMER_KICKS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Iterations of `net_poll_task`'s loop (one per wake). Read over the GDB
/// stub to count the poller's wakes per second.
static NET_POLL_ITERS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// [`net_msi_wake`] outcomes: `[not dispatched (stamped, not blocked yet,
/// or no task), dispatched]`.
static NET_MSI_WAKES: [core::sync::atomic::AtomicU32; 2] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 2];

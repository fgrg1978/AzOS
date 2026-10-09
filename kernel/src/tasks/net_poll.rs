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
/// In every mode the task sleeps until the nearest TCP deadline
/// (`tcp::next_deadline`: delayed ACK, RTO, SYN/FIN retry, persist,
/// TIME-WAIT, keep-alive) on the kernel's timer, and a deadline armed
/// elsewhere that falls earlier wakes it through [`net_timer_kick`]
/// (`tcp::poll_sleep_until`). On top of that:
/// - Poll mode (a NIC with no interrupt reaching this task): never longer
///   than `NET_POLL_INTERVAL`.
/// - IRQ mode (virtio-pci with MSI/MSI-X, or the virtio-mmio line, Kconfig
///   `NET_RX_IRQ`): an RX interrupt wakes this task through [`net_msi_wake`];
///   with no TCP deadline it sleeps up to the self-heal ceiling.
/// - No NIC: as IRQ mode (a loopback connection to our own address still
///   has TCP deadlines). Measured 2026-09-28, riscv64 `--features qemu`, -smp 1, no NIC,
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
    /// Kconfig `NET_POLL_PERIOD_US` (default 1000: the 1 ms above).
    const NET_POLL_INTERVAL: u64 =
        azos_drv_base::platform::hw::TIMER_FREQ * azos_limits::NET_POLL_PERIOD_US / 1_000_000;
    /// IRQ mode or no NIC, with no TCP deadline pending: nothing but an RX
    /// MSI or a [`net_timer_kick`] can give this task work, so it sleeps
    /// this long.
    /// A self-heal bound, not a poll: 60 s, the same ceiling an idle
    /// non-boot hart gets (`timebase::IDLE_HART_CEILING_US`).
    /// Kconfig `NET_IRQ_IDLE_CEILING_MS` (default 60 000).
    const NET_IDLE_CEILING_IRQ_MODE: u64 =
        azos_drv_base::platform::hw::TIMER_FREQ * azos_limits::NET_IRQ_IDLE_CEILING_MS / 1000;

    NET_POLL_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    // N7: tasks waiting on a network event (handshake, window, ARP reply,
    // DNS answer, accept) block until the receive path wakes them instead
    // of sleeping 1 ms and looking again. Registered here, on every NIC
    // mode: before this task runs nothing can deliver those events anyway.
    azos_net::wait::set_hooks(azos_sched::current_task_tid, net_wait_block, net_wait_wake);
    let irq_mode = azos_drv_virtio::virtio::net::irq_driven();
    let no_nic = !azos_drv_net::net_device::is_ready();
    // Arm the timer only while `tcp_tick` has a deadline: in IRQ mode an RX
    // MSI brings frames, and with no NIC no frame can arrive at all.
    let tick_on_demand = irq_mode || no_nic;
    // A TCP deadline armed outside this task (a `connect`, the first byte
    // of a `send`, a held window update from `recv`, a FIN from `close`,
    // a segment delivered by loopback) earlier than this task's wake kicks
    // it (`tcp::poll_sleep_until`), on every NIC mode.
    azos_net::tcp::set_timer_kick(net_timer_kick);
    if no_nic {
        kprintln!("[NET-POLL] no NIC ready: no poll timer, tcp_tick only while a connection needs it");
    }

    // One line the first time an RX MSI arrives after the scheduler
    // started — the runtime half of the IRQ path, which the pre-scheduler
    // DHCP smoke does not exercise. `dispatched` counts the MSIs whose ISR
    // wake took this task out of its timer sleep (`net_msi_wake`); `early`
    // says whether it then ran before that timer would have fired (it can
    // lose the CPU to other tasks for longer than that — informational).
    let mut rx_seen = azos_drv_virtio::virtio::net::rx_irq_count();
    let mut announced = !azos_drv_virtio::virtio::net::irq_driven();

    loop {
        // Running: TCP deadlines armed from here on are picked up by the
        // computation below, so they need no kick.
        azos_net::tcp::poll_running();
        let more = azos_net::net_poll();
        // AR: TCP tick — drive retransmissions, TIME-WAIT, keep-alive timers.
        // One TX batch: the retransmissions it sends share doorbells.
        azos_net::net_tx_batch_begin();
        azos_net::tcp::tcp_tick();
        azos_net::net_tx_batch_end();
        if more {
            // The pass stopped at NET_RX_DRAIN_PER_POLL with frames possibly still
            // queued. In IRQ mode RX interrupts are off while a drain is in
            // progress, so no interrupt would wake this task for them: run
            // another pass now, after letting this priority's peers run.
            NET_POLL_ITERS.fetch_add(1, Ordering::Relaxed);
            azos_sched::task_yield();
            continue;
        }
        // The next wake: the nearest TCP deadline (delayed ACK, RTO, SYN/FIN
        // retry, persist, TIME-WAIT, keep-alive — `tcp::next_deadline`), on
        // the kernel's timer, bounded by the poll period (polled NIC) or by
        // the self-heal ceiling (RX interrupt, or no NIC). TCP timing no
        // longer depends on this task's cadence: a 40 ms delayed ACK leaves
        // at 40 ms, not at the next 100 ms tick.
        let now = azos_drv_sys::timebase::now();
        let ceiling = now + if !tick_on_demand { NET_POLL_INTERVAL } else { NET_IDLE_CEILING_IRQ_MODE };
        let dl = match azos_net::tcp::next_deadline() {
            Some(d) => d.max(now + 1).min(ceiling),
            None => ceiling,
        };
        if !azos_net::tcp::poll_sleep_until(dl) {
            // A nearer deadline was armed meanwhile: run again.
            continue;
        }
        NET_POLL_ITERS.fetch_add(1, Ordering::Relaxed);
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
        if !announced {
            let rx = azos_drv_virtio::virtio::net::rx_irq_count();
            if rx != rx_seen {
                announced = true;
                let early = azos_drv_sys::timebase::now() < dl;
                let dispatched = NET_MSI_WAKES[1].load(Ordering::Relaxed);
                let other = NET_MSI_WAKES[0].load(Ordering::Relaxed);
                // "RX MSI" on virtio-pci (a gate row reads that line), "RX
                // interrupt" on the virtio-mmio line (Kconfig NET_RX_IRQ).
                let what = if azos_drv_virtio::virtio::net::msi_armed() { "RX MSI" } else { "RX interrupt" };
                if dispatched != 0 {
                    kprintln!("[NET-POLL] {} woke this task: rx {} -> {}, dispatched={} other={} early={}",
                        what, rx_seen, rx, dispatched, other, if early { "y" } else { "n" });
                } else {
                    kprintln!("[NET-POLL] {} taken but no ISR wake dispatched: rx {} -> {}, other={}",
                        what, rx_seen, rx, other);
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

/// Registered with `tcp::set_timer_kick`: a TCP deadline earlier than this
/// task's wake was armed elsewhere. Same wake as [`net_msi_wake`] (stamped
/// if the task is not asleep yet, so a kick that lands between
/// `poll_sleep_until` and `task_block` is not lost), counted apart.
fn net_timer_kick() {
    let tid = NET_POLL_TID.load(Ordering::Acquire);
    let woke = tid != 0 && azos_sched::scheduler::wake_task_by_tid(
        tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
    NET_TIMER_KICKS.fetch_add(woke as u32, Ordering::Relaxed);
}

/// `azos_net::wait` block hook: sleep until `deadline` or a wake from the
/// receive path. `false` when the scheduler refused to block (K-C29: a
/// critical section is open), so the caller falls back to its own wait.
fn net_wait_block(deadline: u64) -> bool {
    azos_sched::task_block_killable(azos_sched::WaitReason::Timer(deadline))
        != azos_sched::BlockOutcome::Refused
}

/// `azos_net::wait` wake hook: the event a waiter registered for landed.
/// Same wake as [`net_msi_wake`]: stamped if the waiter has not blocked yet.
fn net_wait_wake(tid: u32) {
    let _ = azos_sched::scheduler::wake_task_by_tid(
        tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
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

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 interrupts: the GICv3 claim / EOI and the line ladder (`handle_irq`),
//! the periodic timer, the console UART's interrupt, and the reschedule point
//! `trap_entry.S` calls on the IRQ path. The bracket around the arm, the work of
//! a tick and the reschedule policy are `crate::trap::irq`.

use super::*;
use crate::trap::{Frame, Kernel};

/// Ask for a reschedule, on THIS core, on the way out of this trap
/// (`crate::trap::RESCHED`): a handler runs on the hart's IRQ stack and may
/// only raise the flag.
fn request_resched() {
    crate::trap::RESCHED.request(azos_sched::smp::current_cpu_id());
}

/// The interrupt arm of [`super::trap::aarch64_trap_entry`]: the generic
/// bracket (QSBR boundary, ISR depth) around [`handle_irq`]. The ISR depth
/// marks interrupt context for `azos_ipc`, which notices a lock taken from an
/// ISR (the precondition of a same-hart fast-IPC deadlock: detected, not
/// masked against, for interrupt latency). The forced stop and the Linux
/// signal taken at an interrupt from EL0 are handled in
/// [`aarch64_trap_resched`], on the task's own stack: both can park the task.
#[inline(never)]
pub(super) fn irq_arm(frame: &mut TrapFrame) {
    crate::trap::irq::arm::<Kernel, TrapFrame>(frame, handle_irq);
}

/// Arm the EL1 virtual timer for periodic ticks and record the period so
/// [`handle_irq`] can keep re-arming it. Call AFTER GIC distributor +
/// redistributor + CPU-interface init and `enable_ppi(0, TIMER_PPI_ENABLED)`, BEFORE
/// unmasking IRQs — `kernel_main` is the only caller.
pub fn arm_periodic_timer(period_ticks: u64) {
    use azos_arch::{Cpu, ARCH};
    TICK_PERIOD.store(period_ticks, Ordering::Relaxed);
    let now = ARCH.now_ticks();
    // Through `timebase`, which records what this core programmed: a task
    // blocking on a timer deadline compares against that record (wave 11).
    azos_drv_sys::timebase::program_at(0, now.wrapping_add(period_ticks));
}

/// Task 4c — prove FP/SIMD state survives an interrupt.
///
/// Loads [`FP_PROBE_PATTERN`] into `v8`, then busy-waits (via `wfi`) until
/// EITHER [`TICK_COUNT`] reaches `target_ticks` OR the live `CNTVCT_EL0`
/// reaches `deadline_cntvct` — whichever comes first, so a timer that ticks too slowly stops after
/// one deadline — then reads `v8` back. With the line never enabled (or
/// masked) there is no interrupt to leave the `wfi`, and the deadline is
/// never compared: the boot parks before this point (the tick check above
/// it) and this probe is not reached.
///
/// **Why one `asm!` block and not "set, then loop in Rust, then read".**
/// Splitting it across separate `asm!`/Rust statements gives the compiler
/// license to reuse the physical `v8` register for its own codegen in
/// between calls — nothing ties a bare `dup v8.2d, ...` to a Rust value
/// once that `asm!` block ends. A probe built that way could read back a
/// wrong value for a reason that has nothing to do with trap handling,
/// which is the opposite of what a canary is for. Keeping "set → wait →
/// read" as one block means the only thing that can touch `v8` in between
/// is a real hardware exception — exactly what this probes.
///
/// Returns `(v8.d[0], v8.d[1], final tick count)`. Pass = both lanes still
/// equal `FP_PROBE_PATTERN`.
#[cfg(feature = "boot-selftests")]
#[inline(never)] // its own symbol: `tools/aarch64_fp_free_check.sh` allows it by name
pub fn fp_survives_interrupt_probe(target_ticks: u64, deadline_cntvct: u64) -> (u64, u64, u64) {
    let tick_ptr = &TICK_COUNT as *const AtomicU64 as *const u64;
    let out_lo: u64;
    let out_hi: u64;
    let final_ticks: u64;
    unsafe {
        core::arch::asm!(
            // Soft-float kernel: V registers are named on purpose here.
            ".arch_extension fp",
            ".arch_extension simd",
            "dup v8.2d, {pattern}",
            "80:",
            "wfi",
            "ldr {cur}, [{tick_ptr}]",
            "cmp {cur}, {target}",
            "b.hs 81f",
            "mrs {now}, CNTVCT_EL0",
            "cmp {now}, {deadline}",
            "b.lo 80b",
            "81:",
            "mov {lo}, v8.d[0]",
            "mov {hi}, v8.d[1]",
            pattern  = in(reg) FP_PROBE_PATTERN,
            tick_ptr = in(reg) tick_ptr,
            target   = in(reg) target_ticks,
            deadline = in(reg) deadline_cntvct,
            cur      = out(reg) final_ticks,
            now      = out(reg) _,
            lo       = out(reg) out_lo,
            hi       = out(reg) out_hi,
            options(nostack),
        );
    }
    (out_lo, out_hi, final_ticks)
}

/// The PL011 console's receive/transmit interrupt handler: empty the FIFO
/// into the ring the console readers use (`uart::irq_handler` also refills it
/// from the TX ring, wave 11, and clears RXIC/RTIC), then wake the reader
/// parked on input — a TID wake of a `Timer` sleeper, which STAMPS instead
/// when the task has not committed to `Blocked` yet, so the arm-then-retest in
/// `readline` has no lost-wakeup window. Only RX work counts and wakes the
/// reader. `true` when a task was made ready. No FP: the ring is bytes and
/// atomics. Run in `handle_irq`, or in the IRQ thread (Kconfig IRQ_THREADED).
fn pl011_rx() -> bool {
    let (rx, woke) = Kernel::console_rx();
    if rx {
        PL011_RX_IRQS.fetch_add(1, Ordering::Relaxed);
    }
    if woke {
        PL011_RX_WAKES.fetch_add(1, Ordering::Relaxed);
    }
    woke
}

/// The handler of a kernel SPI as the IRQ thread runs it (Kconfig
/// IRQ_THREADED): the distributor masked and EOId the line, the thread
/// acknowledges it at the device here and unmasks it afterwards. The same
/// bodies `handle_irq` runs inline for a line that is not threaded.
pub(crate) fn kernel_line_bottom_half(intid: u32) {
    let pl011 = PL011_RX_INTID.load(Ordering::Relaxed);
    if intid == pl011 && pl011 != 0 {
        let _ = pl011_rx();
    } else if azos_drv_virtio::virtio::net::mmio_irq(intid) {
        let _ = crate::net_msi_wake();
    } else if azos_drv_virtio::virtio::blk::irq(intid).is_some() {
        // A disk request completed; its waiter was woken by TID.
    } else {
        #[cfg(feature = "virtio-input")]
        if let Some(pushed) = azos_drv_virtio::virtio::input::irq(intid) {
            if pushed {
                let _ = crate::console_rx_wake();
            }
            return;
        }
        // Kconfig DRV_VIRTIO_SND: the sound device's virtio-mmio SPI.
        #[cfg(feature = "virtio-snd")]
        let _ = crate::boot::snd_irq::line(intid);
    }
}

/// What the profiler (Kconfig `PROFILER`) samples of the interrupted code,
/// for the tick and the PMU's overflow alike. A kernel-mode interrupt's stack
/// pointer is just above its frame.
fn interrupted(frame: &TrapFrame) -> crate::prof::Interrupted {
    let user = frame.came_from_user();
    crate::prof::Interrupted {
        pc: frame.elr_el1 as usize,
        fp: frame.regs[29] as usize,
        sp: if user { frame.sp_el0 as usize } else { core::ptr::from_ref(frame) as usize + core::mem::size_of::<TrapFrame>() },
        user,
    }
}

/// GICv3 dispatch for a real IRQ (vector `VEC_IRQ_CURRENT_EL_SP0` or
/// `VEC_IRQ_LOWER_EL`) — tasks 2/3. Runs on this hart's dedicated IRQ
/// stack: `_trap_common` in `trap_entry.S` switches `sp` before calling
/// here for the interrupt vectors specifically (never for sync/syscall).
/// The frame itself stays on the INTERRUPTED stack regardless — only the
/// handler moves, same split riscv64's `trap_entry.S` documents.
fn handle_irq(_frame: &mut TrapFrame) {
    // One-shot "did I really run on the IRQ stack" probe.
    if !IRQ_STACK_PROBED.swap(true, Ordering::AcqRel) {
        let sp: usize;
        unsafe { core::arch::asm!("mov {0}, sp", out(reg) sp, options(nomem, nostack)); }
        let base = IRQ_STACK_BASE.load(Ordering::Relaxed);
        let top  = IRQ_STACK_TOP.load(Ordering::Relaxed);
        IRQ_TOOK_OWN_STACK.store(base != 0 && sp >= base && sp < top, Ordering::Release);
    }

    // No FP/SIMD here, and no handler may use any. The kernel is soft-float
    // and the trap path no longer saves V0-V31 for the interrupted code
    // (user FP state is saved lazily, on context switch), so a V register
    // touched here would be the interrupted user task's, silently
    // corrupted. `fp_survives_interrupt_probe` (boot) checks that `v8`
    // comes back intact across many timer IRQs; its canary is putting a
    // `movi v8.2d, #0` back at this spot (this used to be here, when the
    // trap path saved the full FP file and handlers were allowed FP).

    let intid = azos_arch::irq::gic::iar1();
    const INTID_SPURIOUS: u32 = 1023;
    const INTID_EL1_VIRT_TIMER: u32 = azos_arch::irq::gic::PPI_VIRT_TIMER; // PPI 27
    // SGI 0 — this kernel's cross-core IPI, both for the scheduler's own
    // cross-CPU wake doorbell (`crates/core/sched::scheduler::cpu_enqueue_locked`
    // → `arch-api::Interrupts::send_ipi` → `arch-aarch64::api_impl`'s
    // `ICC_SGI1R_EL1` write) and for Phase 4's own send/receive marker. RISC-V's
    // equivalent doorbell is `INT_SOFTWARE_S` (`kernel/src/entry/riscv64/irq.rs`) — same
    // purpose, different mechanism (a CSR-pending bit there, a GIC SGI here).
    const INTID_IPI_SGI: u32 = 0;

    if intid == INTID_SPURIOUS {
        // GICv3 §4.2: a spurious read (nothing was actually pending) must
        // NOT be deactivated — there is nothing to EOI.
        return;
    }
    // Wave 15 (TRACE): the irq class, the GIC INTID; the exit record is the
    // scope's drop, at every return below.
    let _irq_scope = azos_trace::IrqScope::enter(intid);

    // console-splice-smoke: an interrupt-context kernel line on every
    // interrupt, not only the timer's (on this ISA the timer is the one that
    // fires steadily while the smoke runs) — except the console's own: since
    // wave 11 the PL011's TX interrupt refills the FIFO from the TX ring, and
    // a line printed from each refill is new TX work for the next one.
    #[cfg(feature = "console-splice-smoke")]
    if intid != PL011_RX_INTID.load(Ordering::Relaxed) {
        crate::console_splice_isr_print();
    }

    if intid == INTID_IPI_SGI {
        // The panic handler's stop IPI (Kconfig PANIC_QUIESCE) is SGI 0 too:
        // once the kernel has panicked it parks here (never returns, so no
        // EOI owed); then the wakes another core left for this one.
        Kernel::ipi_work();
        let hart = azos_sched::smp::current_cpu_id();
        if let Some(slot) = SGI_RECEIVED.get(hart) {
            slot.fetch_add(1, Ordering::Release);
        }
        // A cross-core wake only RAISES A FLAG here: `handle_irq` runs on this
        // hart's dedicated IRQ stack and `schedule()` can `context_switch()`
        // away. `request_resched()` targets THIS core's own slot.
        request_resched();
        azos_arch::irq::gic::eoir1(intid);
        return;
    }

    // The PMU's overflow PPI (Kconfig PROFILER_PMU; 0 when the DTB names
    // none, and no INTID that reaches here is 0): the profiler's sampling
    // counter. Level on PMOVSSET_EL0 & PMINTENSET_EL1, so `on_overflow`
    // clears the counter's overflow flag before the EOI, as the timer re-arms
    // before its own.
    let pmu = azos_arch::pmu::irq();
    if intid == pmu && pmu != 0 {
        crate::prof::on_overflow(|| interrupted(_frame));
        azos_arch::irq::gic::eoir1(intid);
        return;
    }

    // A kernel line the IRQ thread serves (Kconfig IRQ_THREADED,
    // `irq_thread::deferred`: the PL011, a virtio device): delivered like a
    // ring-3 SPI, mask-until-ACK. Masked at the distributor, EOId, queued to
    // the thread; the handler that follows (`kernel_line_bottom_half`) runs
    // there and the thread's ACK unmasks the line. One load of one bitmap
    // word for every other interrupt.
    if crate::irq_thread::deferred(intid) {
        azos_arch::irq::gic::disable_spi(intid);
        azos_arch::irq::gic::eoir1(intid);
        azos_ipc::irq_dispatch(intid);
        request_resched();
        return;
    }

    // The PL011 console's RX / RX-timeout interrupt (a level SPI routed to
    // the boot hart; see `boot_hooks::console_irq`). `PL011_RX_INTID` is
    // 0 when it was not wired, and no INTID that reaches this line is 0
    // (SGI 0 returned above), so an unwired line never matches.
    //
    // Drain, THEN EOI: the line is level on the PL011's RX FIFO level /
    // timeout status. `pl011_rx` empties the FIFO into the ring the console
    // readers use and clears RXIC/RTIC; only then is the line low, so the EOI
    // below does not let the GIC re-pend the same interrupt (the timer arm's
    // order, for the same reason). Only raise the reschedule flag when a task
    // was actually dispatched; never `schedule()` from here (IRQ stack).
    let pl011 = PL011_RX_INTID.load(Ordering::Relaxed);
    if intid == pl011 && pl011 != 0 {
        if pl011_rx() {
            request_resched();
        }
        azos_arch::irq::gic::eoir1(intid);
        return;
    }

    if intid == INTID_EL1_VIRT_TIMER {
        // The sampling profiler (Kconfig `PROFILER`): the interrupted code.
        crate::prof::on_tick(|| interrupted(_frame));
        // Re-arm BEFORE EOI, not after. PPI 27 is level-triggered on
        // CNTV_CTL_EL0.ISTATUS, which stays asserted until CNTV_CVAL_EL0
        // moves past CNTVCT_EL0 — EOI only deactivates the GIC's record of
        // the interrupt, not the timer line itself. EOI-then-rearm leaves
        // the line asserted for however long the rearm takes, and the GIC
        // re-pends it immediately: two "ticks" would fire back to back per
        // real period, corrupting every measurement this milestone takes
        // (tick count, elapsed time, the FP-probe deadline). Order matters
        // and is not an optimisation.
        //
        // This write is the next tick; the nearest timer sleeper, when it is
        // earlier, is programmed after the wake sweep below (wave 11
        // ONESHOT). Not folded into one write here: before the sweep the
        // nearest deadline is the one that just expired, and programming a
        // past instant would leave the line asserted.
        let period = TICK_PERIOD.load(Ordering::Relaxed);
        let mut now = 0u64;
        if period != 0 {
            use azos_arch::{Cpu, ARCH};
            now = ARCH.now_ticks();
            azos_drv_sys::timebase::program_at(0, now.wrapping_add(period));
        }
        let ticks = TICK_COUNT.fetch_add(1, Ordering::Release) + 1;
        let hart = azos_sched::smp::current_cpu_id();
        if let Some(slot) = TICK_PER_HART.get(hart) {
            slot.fetch_add(1, Ordering::Release);
        }

        // The work every ISA's tick shares (`crate::trap::irq::tick_work`): the
        // safety watchdog (its own counter, not `TICK_COUNT`: `TICK_COUNT`'s
        // address is handed to `wait_for_ticks` and feeds the vDSO), the vDSO
        // timing page and the running task's own page (skipped while `now ==
        // 0`, the timer not armed on this core, or `VDSO_TIMEBASE_HZ` not yet
        // published), the sleepers whose deadline (in `CNTVCT_EL0` units)
        // passed, and the wakes stamped onto a task that parked before
        // consuming them (K-C25: a one-shot wake has no second chance, and
        // recovering it needs no clock reading).
        let vdso_hz = VDSO_TIMEBASE_HZ.load(Ordering::Relaxed);
        // `>= 1000`, as `vdso_clock` and x86_64: a bad CNTFRQ below 1 kHz would
        // make the divisor 0 (K1 L11).
        let uptime_ms = (now != 0 && vdso_hz >= 1000).then(|| now / (vdso_hz / 1000));
        crate::trap::irq::tick_work::<Kernel, TrapFrame>(now, Some(ticks), uptime_ms);

        // Wave 11 ONESHOT: the nearest remaining timer
        // sleeper, when it is earlier than the tick programmed above — what
        // riscv64's handler gets from `set_next_tick_smart`. Without it this
        // handler programmed `now + period` unconditionally, and a sleeper on
        // a hart that stayed busy woke at the next tick (the `lat:` rows'
        // ~1790 of 2000 late periods). `oneshot-canary` compiles it out.
        #[cfg(not(feature = "oneshot-canary"))]
        if period != 0 {
            if let Some(d) = azos_sched::nearest_timer_deadline() {
                azos_drv_sys::timebase::arm_if_earlier(d);
            }
        }

        // Phase 3 (context switch + scheduler): a timer tick only RAISES A
        // FLAG here, spent later by `aarch64_trap_resched` — never call
        // `azos_sched::schedule()` from this function directly. `handle_irq`
        // runs on this hart's dedicated IRQ stack (`_trap_common` switched `sp`
        // before calling here — see this function's own doc comment), and
        // `schedule()` can `context_switch()` away, which parks the outgoing
        // task by saving ITS `sp` into its own `TaskContext`. A task parked
        // with `sp` pointing into a stack shared by every interrupt on this
        // hart is a task whose frame the next interrupt overwrites. Mirrors
        // riscv64's `request_resched`/`trap_resched` split
        // (`kernel/src/entry/riscv64/irq.rs`) exactly, for the exact same reason.
        request_resched();
        // Done: the tick does not walk the device ladder below (K1 L10: it
        // ran the LPI, virtio, input, sound and user-SPI tests on every tick,
        // and a driver that claimed INTID 27 would have acted on the timer).
        azos_arch::irq::gic::eoir1(intid);
        return;
    }

    if intid >= azos_arch::irq::gic::LPI_INTID_BASE {
        // An LPI never carries a "which collection" tag back through
        // ICC_IAR1_EL1 — only the physical INTID the MAPTI command
        // assigned. `map_vector`'s caller (kernel_main's PCI/virtio-net-pci
        // wiring, A2-main.diff) is what makes `intid - LPI_INTID_BASE`
        // line up with an EventID; this handler does not know or need to
        // know which PCI function or queue it came from.
        let slot = (intid - azos_arch::irq::gic::LPI_INTID_BASE) as usize;
        if let Some(counter) = LPI_VECTOR_COUNT.get(slot) {
            counter.fetch_add(1, Ordering::Release);
        }
        // The virtio-pci NIC's vectors (kernel_main's `ItsRoute`, token =
        // LPI slot): count, open its RX gate, wake `net_poll_task`.
        // Kconfig DRV_NVME: the NVMe controller's I/O vectors (`boot::nvme`,
        // LPI slots 8..): wake the tasks waiting on a command.
        #[cfg(feature = "nvme")]
        if let Some(woke) = azos_drv_block::nvme::msi_irq(slot as u32) {
            if woke {
                request_resched();
            }
            azos_arch::irq::gic::eoir1(intid);
            return;
        }
        // Kconfig DRV_AHCI: the SATA host's MSI (`boot::ahci`, LPI slot 19, after
        // the sound function's 18).
        #[cfg(feature = "ahci")]
        if let Some(woke) = azos_drv_block::ahci::msi_irq(slot as u32) {
            if woke {
                request_resched();
            }
            azos_arch::irq::gic::eoir1(intid);
            return;
        }
        // Kconfig DRV_E1000E / DRV_IGC: an Intel NIC's MSI (LPI slot 16 / 17,
        // `kernel_main`'s routes, after NVMe's 8-15).
        if azos_drv_net::net_device::pci_msi_irq(slot as u32) {
            if crate::net_msi_wake() {
                request_resched();
            }
            azos_arch::irq::gic::eoir1(intid);
            return;
        }
        // Kconfig DRV_VIRTIO_SND: the sound function's vector (LPI slot 18).
        #[cfg(feature = "virtio-snd")]
        if let Some(woke) = crate::boot::snd_irq::msi(slot as u32) {
            if woke {
                request_resched();
            }
            azos_arch::irq::gic::eoir1(intid);
            return;
        }
        if azos_drv_virtio::virtio::net::msi_irq(slot as u32) && crate::net_msi_wake() {
            request_resched();
        }
        azos_arch::irq::gic::eoir1(intid);
        return;
    }

    // The virtio-mmio NIC's SPI (Kconfig NET_RX_IRQ, edge on QEMU `virt`):
    // acknowledged at the device, RX gate open; wake the poll task like an
    // RX MSI. One atomic compare for every other SPI.
    if azos_drv_virtio::virtio::net::mmio_irq(intid) {
        if crate::net_msi_wake() {
            request_resched();
        }
        azos_arch::irq::gic::eoir1(intid);
        return;
    }

    // An SPI a ring-3 driver bound (`DEVICE_IRQ_BIND`), delivered
    // mask-until-ACK — riscv64's `irq_dispatch`
    // (`kernel/src/entry/riscv64/irq.rs`'s `INT_EXTERNAL_S` arm), plus the mask
    // that a level line needs while ring 3 has not quietened its device yet:
    // without it the EOI below re-pends the line at once and this hart takes
    // it forever.
    //
    // Order is load-bearing: MASK (ICENABLER + RWP wait), then EOI, then
    // dispatch. Dispatch is what lets the driver run (on any PE) and ACK;
    // `DEVICE_IRQ_ACK`'s unmask (ISENABLER) therefore cannot be ordered
    // before this delivery's mask. Not EOImode=1 (priority drop here,
    // `ICC_DIR_EL1` at ACK): EOImode is per PE and would put a DIR write into
    // the timer, SGI, PL011 and LPI arms above, and the deactivate would have
    // to run on the PE that took the interrupt; `GICD_ISENABLER` is a
    // distributor register any PE can write.
    //
    // The dispatch takes `lock_irqsave` spinlocks (bindings, ports) and wakes
    // by enqueueing — the PL011 arm's shape. No `schedule()` here (IRQ stack):
    // only the reschedule flag. No FP.
    // Wave 15: the virtio-blk line (`boot::blk_irq`): the device is
    // acknowledged and its sleeping waiter woken by TID; the waiter reaps.
    if let Some(woke) = azos_drv_virtio::virtio::blk::irq(intid) {
        azos_arch::irq::gic::eoir1(intid);
        if woke { request_resched(); }
        return;
    }

    // A virtio-input device (`boot::input_irq`): level line, acknowledged at
    // the device; key bytes wake the console's parked reader.
    #[cfg(feature = "virtio-input")]
    if let Some(pushed) = azos_drv_virtio::virtio::input::irq(intid) {
        azos_arch::irq::gic::eoir1(intid);
        if pushed && crate::console_rx_wake() { request_resched(); }
        return;
    }

    // The virtio-sound device (`boot::snd_irq`): level line, acknowledged at
    // the device; the device pump is woken when a stream is open.
    #[cfg(feature = "virtio-snd")]
    if let Some(woke) = crate::boot::snd_irq::line(intid) {
        azos_arch::irq::gic::eoir1(intid);
        if woke { request_resched(); }
        return;
    }

    if azos_arch::irq::gic::user_spi_in_range(intid)
        && azos_arch::irq::gic::user_spi_owned(intid)
    {
        #[cfg(not(feature = "irq-mask-canary"))]
        azos_arch::irq::gic::disable_spi(intid);
        azos_arch::irq::gic::eoir1(intid);
        // The event queued on the handler's port, its waiter woken by TID.
        azos_ipc::irq_dispatch(intid);
        request_resched();
        return;
    }

    azos_arch::irq::gic::eoir1(intid);
}

/// Called from `entry/aarch64/asm/trap_entry.S`'s IRQ path, AFTER
/// `aarch64_trap_entry` returns and `sp` is back on the INTERRUPTED task's own
/// stack (never on the shared IRQ stack): spend the reschedule flag the
/// interrupt raised (`crate::trap::irq::resched_exit`). Not called from the
/// sync/svc path, nor from a nested IRQ (trap_entry.S's own `91:` label), so an
/// SVC or a trap-within-a-trap never pays for a call and an atomic swap it can
/// never need.
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_trap_resched(frame: &mut TrapFrame) {
    // Masked-window tracer: the IRQ path's window ends when this returns
    // towards the `eret` (every path below).
    #[cfg(feature = "lat-trace")]
    let _lat_exit = crate::lat_trace::IrqExit(core::panic::Location::caller());
    crate::trap::irq::resched_exit::<Kernel, TrapFrame, { crate::MAX_HARTS }>(&crate::trap::RESCHED, frame);
}

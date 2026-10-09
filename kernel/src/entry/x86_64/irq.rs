// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 interrupt dispatch (every vector >= 32) and the tick: the LAPIC
//! side of what `entry/aarch64.rs::handle_irq` does for the GIC.
//!
//! The trap path calls [`dispatch`] with the vector of an interrupt (not an
//! exception) and requests a reschedule when it returns true; [`dispatch`]
//! sends the EOI itself (never for the spurious vector). The vector map is
//! `azos_arch::encode`'s: the timer, the reschedule / TLB / call IPIs, the
//! LAPIC error and spurious vectors, the masked 8259s, and the IOAPIC GSIs
//! at `apic::IRQ_VECTOR_BASE + gsi`.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use azos_arch::{apic, encode};

/// Timer interrupts taken, all CPUs.
pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
/// Timer interrupts taken per CPU (the SMP bring-up check reads it).
pub static TICK_PER_HART: [AtomicU64; crate::MAX_HARTS] = [const { AtomicU64::new(0) }; crate::MAX_HARTS];
/// The periodic tick in clock ticks (`TIMER_FREQ / SCHED_HZ`); 0 until
/// `timer_init` arms it.
pub static TICK_PERIOD: AtomicU64 = AtomicU64::new(0);
/// Reschedule IPIs taken per CPU.
pub static IPI_RECEIVED: [AtomicU64; crate::MAX_HARTS] = [const { AtomicU64::new(0) }; crate::MAX_HARTS];
/// Set by each CPU once its LAPIC and timer are up (`secondary_publish_online`).
pub static CORE_ONLINE: [AtomicBool; crate::MAX_HARTS] = [const { AtomicBool::new(false) }; crate::MAX_HARTS];
/// Spurious, 8259 and LAPIC-error interrupts (should stay 0).
pub static STRAY: AtomicU64 = AtomicU64::new(0);
/// COM1's GSI once its line is routed (`u32::MAX`: polled).
pub static COM1_GSI: AtomicU32 = AtomicU32::new(u32::MAX);

/// The TLB-shootdown and function-call IPI handlers, installed by their
/// owners (the TLB code; the icache-sync path). 0 = none: the IPI is only
/// acknowledged.
static TLB_IPI_HANDLER: AtomicUsize = AtomicUsize::new(0);
static CALL_IPI_HANDLER: AtomicUsize = AtomicUsize::new(0);

/// Run `f` on every `encode::TLB_VECTOR` IPI this CPU takes.
pub fn set_tlb_ipi_handler(f: fn()) {
    TLB_IPI_HANDLER.store(f as usize, Ordering::Release);
}

/// Run `f` on every `encode::CALL_VECTOR` IPI this CPU takes.
pub fn set_call_ipi_handler(f: fn()) {
    CALL_IPI_HANDLER.store(f as usize, Ordering::Release);
}

fn run_hook(slot: &AtomicUsize) {
    let f = slot.load(Ordering::Acquire);
    if f != 0 {
        // SAFETY: only `set_*_ipi_handler` stores here, always a `fn()`.
        let f: fn() = unsafe { core::mem::transmute::<usize, fn()>(f) };
        f();
    }
}

/// Arm this CPU's periodic tick (`period` clock ticks from now).
pub fn arm_periodic_timer(period: u64) {
    use azos_arch::{Cpu, ARCH};
    TICK_PERIOD.store(period, Ordering::Relaxed);
    let now = ARCH.now_ticks();
    azos_drv_sys::timebase::program_at(0, now.wrapping_add(period));
}

/// Handle interrupt `vector` (>= 32). True: reschedule on the way out.
pub fn dispatch(vector: u8) -> bool {
    match vector {
        encode::SPURIOUS_VECTOR => {
            // Never EOI'd: no in-service bit was set.
            STRAY.fetch_add(1, Ordering::Relaxed);
            false
        }
        encode::TIMER_VECTOR => {
            apic::eoi();
            timer_tick();
            true
        }
        encode::RESCHED_VECTOR => {
            if let Some(slot) = IPI_RECEIVED.get(azos_sched::smp::current_cpu_id()) {
                slot.fetch_add(1, Ordering::Release);
            }
            // `SCHED_REMOTE_WAKE_DEFER`: queue the wakes another CPU left for
            // this one (see the riscv64 SSIP arm). One load when none.
            azos_sched::scheduler::drain_remote_wakes();
            apic::eoi();
            true
        }
        encode::TLB_VECTOR => {
            run_hook(&TLB_IPI_HANDLER);
            apic::eoi();
            false
        }
        encode::CALL_VECTOR => {
            run_hook(&CALL_IPI_HANDLER);
            apic::eoi();
            false
        }
        encode::ERROR_VECTOR => {
            // ESR latches on a write; the read is the error, the count the record.
            apic::write(encode::LAPIC_ESR, 0);
            let _ = apic::read(encode::LAPIC_ESR);
            STRAY.fetch_add(1, Ordering::Relaxed);
            apic::eoi();
            false
        }
        v if (encode::PIC_VECTOR_BASE..encode::PIC_VECTOR_BASE + 16).contains(&v) => {
            // A masked 8259's spurious IRQ 7/15: not through the LAPIC, no EOI.
            STRAY.fetch_add(1, Ordering::Relaxed);
            false
        }
        v => match encode::vector_gsi(apic::IRQ_VECTOR_BASE, v) {
            Some(gsi) => device(gsi),
            None => {
                STRAY.fetch_add(1, Ordering::Relaxed);
                apic::eoi();
                false
            }
        },
    }
}

/// An IOAPIC line.
fn device(gsi: u32) -> bool {
    if gsi == COM1_GSI.load(Ordering::Relaxed) {
        let mut resched = false;
        if azos_drv_sys::uart::irq_handler() {
            if azos_drv_sys::uart::take_intr() {
                azos_syscall::linux::console_signal(2);
            }
            let tid = azos_drv_sys::uart::rx_waiter_take();
            resched = tid != 0
                && azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
        }
        // Edge-triggered: a cause still pending gets a fresh edge.
        azos_drv_sys::uart::irq_rearm();
        apic::eoi();
        return resched;
    }
    // Wave 15: the virtio-blk line (`boot::blk_irq`): acknowledged at the
    // device, its sleeping waiter woken by TID.
    if let Some(woke) = azos_drv_virtio::virtio::blk::irq(gsi) {
        apic::eoi();
        return woke;
    }
    if azos_drv_irqchip::user_irq::owned(gsi) {
        // Masked until the ring-3 owner acknowledges (a level line would
        // otherwise fire again at once).
        azos_arch::ioapic::set_masked(gsi, true);
        apic::eoi();
        azos_ipc::irq_dispatch(gsi);
        azos_sched::wake_by_irq(gsi);
        return true;
    }
    // The virtio-mmio NIC's GSI (Kconfig NET_RX_IRQ): acknowledged at the
    // device first (a level line), then EOI; wake the poll task.
    if azos_drv_virtio::virtio::net::mmio_irq(gsi) {
        apic::eoi();
        return crate::net_msi_wake();
    }
    // Other kernel virtio-mmio lines: their drivers poll.
    apic::eoi();
    false
}

/// The periodic tick: re-arm, count, and the work every ISA's tick does.
fn timer_tick() {
    use azos_arch::{Cpu, ARCH};
    let period = TICK_PERIOD.load(Ordering::Relaxed);
    let now = ARCH.now_ticks();
    if period != 0 {
        azos_drv_sys::timebase::program_at(0, now.wrapping_add(period));
    }
    let ticks = TICK_COUNT.fetch_add(1, Ordering::Release) + 1;
    if let Some(slot) = TICK_PER_HART.get(azos_sched::smp::current_cpu_id()) {
        slot.fetch_add(1, Ordering::Release);
    }

    let _ = azos_actuation::watchdog::tick();
    azos_actuation::watchdog::halt_if_panicked();
    azos_actuation::watchdog::feed_from_timer_tick();

    let hz = azos_arch::timer::TICK_HZ;
    if hz >= 1000 {
        azos_mm::vdso::vdso_update(ticks, now / (hz / 1000));
        azos_syscall::vdso_notify::vdso_task_tick(now);
    }
    azos_sched::wake_expired_timers(now);
    azos_sched::reap_stamped_sleepers();

    let mut expired = [0u32; azos_ipc::MAX_LEASES];
    let n = azos_ipc::lease_tick(now, &mut expired);
    for &lessor_tid in expired.iter().take(n) {
        azos_sched::wq_wake_by_tid(lessor_tid);
    }
    if n != 0 {
        crate::tasks::wake_lease_worker();
    }

    if period != 0 {
        if let Some(d) = azos_sched::nearest_timer_deadline() {
            azos_drv_sys::timebase::arm_if_earlier(d);
        }
    }
}

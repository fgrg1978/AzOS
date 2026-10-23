// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 interrupt dispatch (every vector >= 32) and the tick: the LAPIC
//! side of what `entry/aarch64/irq.rs::handle_irq` does for the GIC.
//!
//! The trap path calls [`irq_arm`], whose bracket (`crate::trap::irq::arm`) calls
//! [`dispatch`] with the vector of an interrupt (not an exception) and requests a
//! reschedule when it returns true; [`dispatch`] sends the EOI itself (never for the spurious vector). The vector map is
//! `azos_arch::irq::encode`'s: the timer, the reschedule / TLB / call IPIs, the
//! LAPIC error and spurious vectors, the masked 8259s, and the IOAPIC GSIs
//! at `apic::IRQ_VECTOR_BASE + gsi`.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use azos_arch::irq::apic;
use azos_arch::irq::encode;

use super::TrapFrame;
use crate::trap::{Frame, Kernel};

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

azos_common::ro_hook! {
    /// The TLB-shootdown IPI handler, installed by its owner (the TLB code).
    /// Unset: the IPI is only acknowledged.
    static TLB_IPI_HANDLER: fn();
}

/// Run `f` on every `encode::TLB_VECTOR` IPI this CPU takes.
pub fn set_tlb_ipi_handler(f: fn()) {
    TLB_IPI_HANDLER.set(f);
}

/// Arm this CPU's periodic tick (`period` clock ticks from now).
pub fn arm_periodic_timer(period: u64) {
    use azos_arch::{Cpu, ARCH};
    TICK_PERIOD.store(period, Ordering::Relaxed);
    let now = ARCH.now_ticks();
    azos_drv_sys::timebase::program_at(0, now.wrapping_add(period));
}

/// The interrupt arm of [`super::trap::x86_64_trap_entry`]: the generic bracket
/// (QSBR boundary, ISR depth) around [`handle_irq`]. Out of line so the syscall
/// path's frame does not grow with the guard's registers.
#[inline(never)]
pub(super) fn irq_arm(frame: &mut TrapFrame) {
    crate::trap::irq::arm::<Kernel, TrapFrame>(frame, |frame| {
        if frame.vector == encode::TIMER_VECTOR as u64 {
            // The sampling profiler (Kconfig `PROFILER`): the interrupted code.
            crate::prof::on_tick(|| crate::prof::Interrupted {
                pc: frame.rip as usize,
                fp: frame.regs[super::gpr::RBP] as usize,
                sp: frame.rsp as usize,
                user: frame.came_from_user(),
            });
        }
        handle_irq(frame.vector as usize);
    });
}

/// The preemption point `trap_entry.S` calls after an interrupt, back on the
/// interrupted task's own stack: spend the reschedule flag the interrupt raised
/// (`crate::trap::irq::resched_exit`).
#[unsafe(no_mangle)]
pub extern "C" fn x86_64_trap_resched(frame: &mut TrapFrame) {
    crate::trap::irq::resched_exit::<Kernel, TrapFrame, { crate::MAX_HARTS }>(&crate::trap::RESCHED, frame);
}

/// A vector >= 32: [`dispatch`] owns the whole map (timer, IPIs, LAPIC error and
/// spurious, the masked 8259s, the IOAPIC lines) and sends the EOI itself; a
/// true return asks for a reschedule on the way out.
fn handle_irq(vector: usize) {
    let _scope = azos_trace::IrqScope::enter(vector as u32);
    if dispatch(vector as u8) {
        crate::trap::RESCHED.request(azos_sched::smp::current_cpu_id());
    }
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
            // The panic handler's stop IPI (Kconfig PANIC_QUIESCE) is this
            // vector too: once the kernel has panicked, park here (never
            // returns, so no EOI owed); then the wakes another CPU left for this one.
            Kernel::ipi_work();
            if let Some(slot) = IPI_RECEIVED.get(azos_sched::smp::current_cpu_id()) {
                slot.fetch_add(1, Ordering::Release);
            }
            apic::eoi();
            true
        }
        encode::TLB_VECTOR => {
            if let Some(f) = TLB_IPI_HANDLER.get() {
                f();
            }
            apic::eoi();
            false
        }
        // The function-call IPI: the thermal task's access to another CPU's
        // level-request registers (`ext/thermal_hw.rs`). Without ENERGY
        // nothing sends it and it is only acknowledged.
        encode::CALL_VECTOR => {
            #[cfg(all(feature = "energy", not(feature = "thermal-smoke")))]
            super::ext::thermal_hw::call_ipi();
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
        v if apic::msi_owns(v) => msi(v),
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

/// A PCI MSI or MSI-X vector (`apic::msi_alloc`): the token a driver's
/// `msi_irq` matches is the vector, which is the MSI data word. Nothing to
/// acknowledge at the device; the waiter that wakes reaps its queue.
fn msi(vector: u8) -> bool {
    apic::msi_note(vector);
    let token = vector as u32;
    // Kconfig DRV_NVME: a completion of the NVMe controller (`boot::nvme`).
    #[cfg(feature = "nvme")]
    if let Some(woke) = azos_drv_block::nvme::msi_irq(token) {
        apic::eoi();
        return woke;
    }
    // Kconfig DRV_VIRTIO_SND: the sound function's vector (`boot::snd_irq`).
    #[cfg(feature = "virtio-snd")]
    if let Some(woke) = crate::boot::snd_irq::msi(token) {
        apic::eoi();
        return woke;
    }
    // Kconfig DRV_AHCI: a completion of the SATA host (`boot::ahci`).
    #[cfg(feature = "ahci")]
    if let Some(woke) = azos_drv_block::ahci::msi_irq(token) {
        apic::eoi();
        return woke;
    }
    // A vector a ring-3 handler holds (`DEVICE_IRQ_BIND` on an `msi.<k>` slot)
    // when no kernel driver claims it: the event is queued on its port, or
    // dropped while the handler is out of budget.
    // Kconfig DRV_E1000E / DRV_IGC: an Intel NIC's MSI.
    let resched = if azos_drv_net::net_device::pci_msi_irq(token) || azos_drv_virtio::virtio::net::msi_irq(token) {
        crate::net_msi_wake()
    } else {
        azos_ipc::irq_msi_dispatch(token)
    };
    apic::eoi();
    resched
}

/// An IOAPIC line.
fn device(gsi: u32) -> bool {
    if gsi == COM1_GSI.load(Ordering::Relaxed) {
        let resched = Kernel::console_rx().1;
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
    // A virtio-input device (`boot::input_irq`): acknowledged at the device,
    // key bytes wake the console's parked reader.
    #[cfg(feature = "virtio-input")]
    if let Some(pushed) = azos_drv_virtio::virtio::input::irq(gsi) {
        apic::eoi();
        return pushed && crate::console_rx_wake();
    }
    // The virtio-sound device's line (`boot::snd_irq`): acknowledged at the
    // device, the device pump woken when a stream is open.
    #[cfg(feature = "virtio-snd")]
    if let Some(woke) = crate::boot::snd_irq::line(gsi) {
        apic::eoi();
        return woke;
    }
    // The PS/2 controller's keyboard or mouse line (`boot::ps2_irq`): bytes
    // are read at the controller, key bytes wake the console's parked reader.
    #[cfg(feature = "ps2")]
    if let Some(pushed) = azos_drv_input::ps2::irq(gsi) {
        apic::eoi();
        return pushed && crate::console_rx_wake();
    }
    if azos_drv_irqchip::user_irq::owned(gsi) {
        // Masked until the ring-3 owner acknowledges (a level line would
        // otherwise fire again at once).
        azos_arch::irq::ioapic::set_masked(gsi, true);
        apic::eoi();
        azos_ipc::irq_dispatch(gsi);
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

/// The periodic tick: re-arm, count, then the work every ISA's tick does
/// (`crate::trap::irq::tick_work`), then the nearest sleeper's deadline when it
/// is earlier than the tick.
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

    let hz = azos_arch::timer::TICK_HZ;
    let uptime_ms = (hz >= 1000).then(|| now / (hz / 1000));
    crate::trap::irq::tick_work::<Kernel, TrapFrame>(now, Some(ticks), uptime_ms);

    if period != 0 {
        if let Some(d) = azos_sched::nearest_timer_deadline() {
            azos_drv_sys::timebase::arm_if_earlier(d);
        }
    }
}

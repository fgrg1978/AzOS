// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Interrupt lines as scheduled objects (L5), every ISA (Kconfig KTEST).
//!
//! * `irq_storm_is_contained`: a handler on a hard reservation serves a line
//!   whose device asserts again the moment it is unmasked. The device is a
//!   task of its own that obeys the controller's mask (the hooks are counting
//!   ones for the test). The handler ACKs first and works after, so its
//!   budget runs out with the line unmasked and idle: the rule under test is
//!   that the throttle masks it, so no delivery reaches a handler that is
//!   throttled, and the replenishment lets the storm resume. Also: the budget
//!   did run out, the handler's work stayed inside its share, and the
//!   overrun left an `irq-budget` decision record.
//!   Canary `canary=irq-storm` (the budget rule is off: a throttle leaves an
//!   idle line live, an ACK unmasks a spent budget): the device delivers
//!   while the handler is throttled, `not ok`.
//! * `irq_msi_reaches_a_ring3_binding` (x86_64: its LAPIC takes a self IPI as
//!   an MSI would arrive): an `msi.<k>` slot takes a vector at bind, a
//!   delivery on it reaches the port with the slot as its source id, and the
//!   vector is given back and handed out again. Other ISAs: the slot is
//!   refused where there is no MSI for ring 3, Ok.
//!
//! The line used is a number no controller input has: only the binding table
//! sees it, and the test's hooks stand for the controller.

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("the L5 ktests know riscv64, aarch64 and x86_64: a new ISA answers the MSI test here");

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use azos_ipc::irq_bind::{self, Route};

/// A line number no controller has.
const LINE: u32 = 0x7F0;
const HANDLER_PRIO: u32 = 10;
const DEVICE_PRIO: u32 = 2;
/// The handler's hard reservation: 1 ms of every 10.
const BUDGET_US: u64 = 1_000;
const PERIOD_US: u64 = 10_000;
/// What the handler does after each ACK.
const WORK_US: u64 = 500;
/// How long the storm lasts.
const RUN_MS: u64 = 120;

/// The controller as the test's hooks leave it.
static MASKED: AtomicBool = AtomicBool::new(false);
static STOP: AtomicBool = AtomicBool::new(false);
static RESERVED: AtomicU32 = AtomicU32::new(0);
static READY: AtomicBool = AtomicBool::new(false);
static HANDLER_DONE: AtomicBool = AtomicBool::new(false);
static DEVICE_DONE: AtomicBool = AtomicBool::new(false);
static HANDLER_IDX: AtomicUsize = AtomicUsize::new(usize::MAX);
static HANDLER_TID: AtomicU32 = AtomicU32::new(0);
/// Deliveries the device made, those that found the handler throttled, and
/// those the handler took.
static TOP_HALVES: AtomicU32 = AtomicU32::new(0);
static WHILE_THROTTLED: AtomicU32 = AtomicU32::new(0);
static HANDLED: AtomicU32 = AtomicU32::new(0);

fn hook_release(_: u32) {
    MASKED.store(true, Ordering::Release);
}
fn hook_mask(_: u32) {
    MASKED.store(true, Ordering::Release);
}
fn hook_unmask(_: u32) {
    MASKED.store(false, Ordering::Release);
}

fn us_to_ticks(us: u64) -> u64 {
    us * (azos_drv_sys::timebase::TIMER_FREQ / 1_000_000).max(1)
}

fn burn(us: u64) {
    let until = azos_drv_sys::timebase::now() + us_to_ticks(us);
    while azos_drv_sys::timebase::now() < until {
        core::hint::spin_loop();
    }
}

fn sleep_us(us: u64) {
    let until = azos_drv_sys::timebase::now() + us_to_ticks(us);
    azos_sched::task_block(azos_sched::WaitReason::Timer(until));
}

/// The handler: binds the line on its reservation, then for every event
/// ACKs first and works after.
fn handler(cpu: usize) {
    // The test admits the reservation after it creates this task.
    while RESERVED.load(Ordering::Acquire) == 0 {
        // Asleep, not yielding: this task outranks the test that admits it.
        sleep_us(200);
    }
    let tid = azos_sched::current_task_tid();
    HANDLER_TID.store(tid, Ordering::Release);
    let Some(port) = azos_ipc::port::port_create_ref(tid as usize) else {
        HANDLER_DONE.store(true, Ordering::Release);
        return;
    };
    if irq_bind::irq_bind_port_budgeted(LINE, tid, port, 1, Route::Cpu(cpu as u32)).is_err() {
        HANDLER_DONE.store(true, Ordering::Release);
        return;
    }
    READY.store(true, Ordering::Release);
    while !STOP.load(Ordering::Acquire) {
        let waited = azos_ipc::port::port_wait_until_ref(
            port,
            tid,
            // Wake every few ms to look at STOP.
            azos_abi::time::ticks_to_ns(
                azos_drv_sys::timebase::now() + us_to_ticks(5_000),
                azos_drv_sys::timebase::TIMER_FREQ,
            ),
            || azos_abi::time::ticks_to_ns(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::TIMER_FREQ),
            |until| {
                let reason = match until {
                    None => azos_sched::WaitReason::Port(port),
                    Some(ns) => azos_sched::WaitReason::Timer(azos_abi::time::ns_to_ticks_ceil(
                        ns,
                        azos_drv_sys::timebase::TIMER_FREQ,
                    )),
                };
                azos_sched::task_block(reason);
                false
            },
        );
        if let Ok(Some(_)) = waited {
            HANDLED.fetch_add(1, Ordering::Relaxed);
            let _ = irq_bind::irq_ack_unmask(LINE, tid);
            // After the ACK the line is live and idle: the budget runs out
            // here, in the work.
            burn(WORK_US);
        }
    }
    irq_bind::irq_unbind_all(tid);
    HANDLER_DONE.store(true, Ordering::Release);
}

/// The device behind the line: asserts whenever the controller lets it, and
/// notes when the handler it delivers to is throttled.
fn device(_: usize) {
    while !STOP.load(Ordering::Acquire) {
        if !MASKED.load(Ordering::Acquire) {
            // The top half: mask-until-ACK, then queue.
            MASKED.store(true, Ordering::Release);
            let idx = HANDLER_IDX.load(Ordering::Acquire);
            if azos_sched::rt::task_reservation(idx).is_some_and(|(_, throttled, _)| throttled) {
                WHILE_THROTTLED.fetch_add(1, Ordering::Relaxed);
            }
            azos_ipc::irq_dispatch(LINE);
            TOP_HALVES.fetch_add(1, Ordering::Relaxed);
        }
        sleep_us(100);
    }
    DEVICE_DONE.store(true, Ordering::Release);
}

fn reset() {
    for a in [&MASKED, &STOP, &READY, &HANDLER_DONE, &DEVICE_DONE] {
        a.store(false, Ordering::Release);
    }
    RESERVED.store(0, Ordering::Release);
    HANDLER_IDX.store(usize::MAX, Ordering::Release);
    HANDLER_TID.store(0, Ordering::Release);
    for a in [&TOP_HALVES, &WHILE_THROTTLED, &HANDLED] {
        a.store(0, Ordering::Release);
    }
}

/// Put the arch's own hooks back and disarm the canary, whatever the verdict.
struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        let lines = crate::boot_hooks::line_hooks();
        irq_bind::set_line_hooks(lines.release, lines.mask, lines.unmask);
        irq_bind::canary_storm(false);
    }
}

azos_ktest::ktest_late! {
    fn irq_storm_is_contained() {
        if azos_sched::smp::NUM_ONLINE_CPUS.load(Ordering::Acquire) == 0 {
            return Err("no CPU online");
        }
        reset();
        let _restore = Restore;
        irq_bind::set_line_hooks(hook_release, hook_mask, hook_unmask);
        irq_bind::canary_storm(canary!("irq-storm"));
        // Both tasks on this CPU: the device runs only when the handler,
        // which is in the deadline class, is not.
        let cpu = azos_sched::smp::current_cpu_id();
        #[cfg(feature = "decisions")]
        let seq0 = azos_decision::total();
        let overruns0 = irq_bind::irq_overruns();

        let h = azos_sched::task_create_affinity("irq-handler", handler, cpu, HANDLER_PRIO, cpu as i8);
        HANDLER_IDX.store(h, Ordering::Release);
        let r = azos_sched::rt::Reservation {
            runtime_us: BUDGET_US, period_us: PERIOD_US, deadline_us: 0, hard: true,
            cpu_mask: 1 << cpu, band: true, level: HANDLER_PRIO,
        };
        if azos_sched::rt::reserve(h, r).is_err() {
            STOP.store(true, Ordering::Release);
            RESERVED.store(1, Ordering::Release);
            crate::ktest::wait("the handler never ended", || HANDLER_DONE.load(Ordering::Acquire))?;
            return Err("the handler's reservation was refused");
        }
        RESERVED.store(1, Ordering::Release);
        crate::ktest::wait("the handler never bound its line", || {
            READY.load(Ordering::Acquire) || HANDLER_DONE.load(Ordering::Acquire)
        })?;
        if !READY.load(Ordering::Acquire) {
            return Err("a handler on a hard reservation could not bind its line");
        }
        azos_sched::task_create_affinity("irq-device", device, 0, DEVICE_PRIO, cpu as i8);

        // Let the storm run, then stop both.
        azos_syscall::sleep::sleep_ms(RUN_MS);
        STOP.store(true, Ordering::Release);
        crate::ktest::wait("the storm's tasks never ended", || {
            HANDLER_DONE.load(Ordering::Acquire) && DEVICE_DONE.load(Ordering::Acquire)
        })?;

        let (top, late, handled) = (
            TOP_HALVES.load(Ordering::Relaxed),
            WHILE_THROTTLED.load(Ordering::Relaxed),
            HANDLED.load(Ordering::Relaxed),
        );
        let overruns = irq_bind::irq_overruns() - overruns0;
        azos_drv_sys::kprintln!(
            "# irq_storm_is_contained: {} deliveries, {} to a throttled handler, {} handled, {} overruns",
            top, late, handled, overruns
        );
        if handled == 0 {
            return Err("the handler took no delivery: the storm never ran");
        }
        if overruns == 0 {
            return Err("the handler's budget never ran out: nothing was contained");
        }
        if late != 0 {
            return Err("the device delivered to a handler whose budget was spent: its line was left live");
        }
        // Its work stayed inside its reservation: each period it spans lets
        // it finish the jobs its budget covers, plus the one it overruns in;
        // two periods more for the edges. A handler without the reservation
        // does a job every `WORK_US` plus the device's pause.
        let jobs_per_period = BUDGET_US / WORK_US + 1;
        if u64::from(handled) > (RUN_MS * 1000 / PERIOD_US + 2) * jobs_per_period {
            return Err("the handler ran past its reservation");
        }
        #[cfg(feature = "decisions")]
        {
            let tid = HANDLER_TID.load(Ordering::Acquire);
            let mut hit = false;
            azos_decision::for_each(|rec| {
                hit |= rec.seq > seq0
                    && rec.rule == azos_decision::Rule::IrqBudget as u8
                    && rec.subject == tid
                    && rec.n[0] == LINE as u64;
            });
            if !hit {
                return Err("the overrun left no irq-budget decision record");
            }
        }
        Ok(())
    }
}

azos_ktest::ktest_late! {
    fn irq_msi_reaches_a_ring3_binding() {
        // A handler on a reservation is not what this test builds: the bind
        // below is the one without the budget rule's requirement.
        if azos_limits::IRQ_THREADED {
            return Ok(());
        }
        let tid = azos_sched::current_task_tid();
        let Some(port) = azos_ipc::port::port_create_ref(tid as usize) else {
            return Err("no port to bind to");
        };
        let verdict = msi_scenario(tid, port);
        // Whatever the verdict: no binding and no port stays behind.
        irq_bind::irq_unbind_all(tid);
        let _ = azos_ipc::port::port_destroy_ref(port);
        verdict
    }
}

/// The MSI scenario: bind the slot, raise its vector, read the event, bind
/// again and see the vector come back.
fn msi_scenario(tid: u32, port: u32) -> Result<(), &'static str> {
    use azos_ipc::irq_bind::MSI_LINE;
    const SLOT: u32 = MSI_LINE | 9;
    let cpu = azos_sched::smp::current_cpu_id() as u32;
    let bound = irq_bind::irq_bind_port(SLOT, tid, port, 0x4D53, Route::Cpu(cpu));

    #[cfg(target_arch = "aarch64")]
    {
        // No MSI for ring 3 here (the GICv3 ITS is not exposed): the slot is
        // refused, nothing is bound.
        return match bound {
            Err(irq_bind::BindError::NoMsi) => Ok(()),
            Ok(_) => Err("a platform without MSI for ring 3 bound an MSI slot"),
            Err(_) => Err("an MSI slot was refused with the wrong error"),
        };
    }
    #[cfg(target_arch = "riscv64")]
    {
        // MSI for ring 3 only with AIA (an IMSIC identity); the PLIC refuses
        // the slot.
        return match (&bound, azos_drv_irqchip::irqchip::is_aia()) {
            (Err(irq_bind::BindError::NoMsi), false) | (Ok(_), true) => Ok(()),
            (Ok(_), false) => Err("a PLIC platform bound an MSI slot"),
            (Err(_), _) => Err("an MSI slot was refused where the platform has MSI, or with the wrong error"),
        };
    }
    #[cfg(target_arch = "x86_64")]
    {
        let b = bound.map_err(|_| "the MSI slot was not bound")?;
        let Some(msi) = b.msi else { return Err("an MSI bind answered no message") };
        if msi.data != msi.id || msi.address == 0 {
            return Err("the MSI message does not name the vector");
        }
        // A self IPI on the vector reaches the LAPIC as a message would.
        if !azos_arch::apic::send_ipi(cpu as usize, msi.id as u8) {
            return Err("the self IPI was not sent");
        }
        crate::ktest::wait("the MSI never reached the port", || {
            azos_ipc::port::port_has_events(azos_ipc::cap::objref::PORT.idx(port))
        })?;
        match azos_ipc::port::port_poll_ref(port) {
            Ok(e) if e.key == 0x4D53 && e.source_id == SLOT
                && e.source_type == azos_abi::syscall_nr::PORT_EVENT_IRQ => {}
            _ => return Err("the MSI event does not carry the slot and the key"),
        }
        // Unbound, the vector is given back: the next bind takes it again.
        irq_bind::irq_unbind_all(tid);
        let again = irq_bind::irq_bind_port(SLOT, tid, port, 1, Route::Cpu(cpu)).map(|b| b.msi.map(|m| m.id));
        if again != Ok(Some(msi.id)) {
            return Err("the vector was not given back when the binding went");
        }
        Ok(())
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Boot self-tests (Kconfig BOOT_SELFTESTS) and feature-gated boot smokes.
//! Each item keeps the `cfg` it had in `main.rs`; a module declaration is
//! gated on the union of its items' gates (so an all-off module is not
//! compiled as an empty file with an unused import), and a new item behind a
//! new feature must add that feature here or its call site fails to resolve. Everything is re-exported
//! so `kernel_main` and the trap handlers name each entry point directly.
//! The spawn sequences at the end are stretches of `kernel_main`, in its order.

// Read by the feature-gated spawns below only: unused in a default image.
#[allow(unused_imports)]
use crate::*;
// The driver registry smoke (every boot).
mod registry;
pub(crate) use registry::driver_registry_smoke;

#[cfg(any(feature = "boot-selftests", all(feature = "rvv", feature = "rvv-isolation-probe")))]
mod selftest;
#[cfg(any(feature = "boot-selftests", all(feature = "rvv", feature = "rvv-isolation-probe")))]
pub(crate) use selftest::*;
// The network conformance probe and loopback check (Kconfig BOOT_SELFTESTS).
#[cfg(feature = "boot-selftests")]
pub(crate) mod net_conformance;
#[cfg(feature = "cpuid-probe")]
pub(crate) mod cpuid_probe;
#[cfg(feature = "trace-cost-probe")]
mod trace_cost;
#[cfg(feature = "trace-cost-probe")]
pub(crate) use trace_cost::*;
#[cfg(feature = "nicq-cost-probe")]
mod nicq_cost;
#[cfg(feature = "nicq-cost-probe")]
pub(crate) use nicq_cost::*;
#[cfg(all(target_arch = "aarch64", feature = "boot-selftests"))]
mod aarch64_sched;
#[cfg(all(target_arch = "aarch64", feature = "boot-selftests"))]
pub(crate) use aarch64_sched::*;
#[cfg(feature = "ipc-census")]
mod ipc_census;
#[cfg(feature = "ipc-census")]
pub(crate) use ipc_census::*;
#[cfg(any(feature = "fat-barrier-smoke", feature = "mmc-flush-smoke", feature = "disk-part-row", feature = "blk-discard-smoke"))]
mod storage;
#[cfg(any(feature = "fat-barrier-smoke", feature = "mmc-flush-smoke", feature = "disk-part-row", feature = "blk-discard-smoke"))]
pub(crate) use storage::*;
#[cfg(any(feature = "dhcp-smoke", feature = "net-smoke"))]
mod net;
#[cfg(any(feature = "dhcp-smoke", feature = "net-smoke"))]
pub(crate) use net::*;
#[cfg(any(feature = "orderly-reboot-smoke", feature = "safe-mode-smoke", feature = "power-off-durability-smoke",
          feature = "orderly-drain-smoke"))]
mod ota;
#[cfg(any(feature = "orderly-reboot-smoke", feature = "safe-mode-smoke", feature = "power-off-durability-smoke",
          feature = "orderly-drain-smoke"))]
pub(crate) use ota::*;
#[cfg(any(feature = "reflex-smoke", feature = "envelope-smoke", feature = "geofence-smoke",
          feature = "brain-lies-smoke", feature = "cap-deny-smoke", feature = "disk-part-row",
          feature = "rc-failsafe-smoke", feature = "fence-refuse-smoke",
          all(feature = "ktest", feature = "use-robot")))]
mod safety;
#[cfg(any(feature = "reflex-smoke", feature = "envelope-smoke",
          all(feature = "geofence-smoke", not(feature = "ktest")),
          feature = "brain-lies-smoke", feature = "cap-deny-smoke", feature = "disk-part-row",
          feature = "rc-failsafe-smoke", feature = "fence-refuse-smoke"))]
pub(crate) use safety::*;
// Wave 15: RC receiver and geofence wiring, one property per boot.
#[cfg(any(feature = "rc-failsafe-smoke", feature = "rc-stick-smoke", feature = "fence-refuse-smoke"))]
mod rc_fence;
#[cfg(any(feature = "rc-failsafe-smoke", feature = "rc-stick-smoke", feature = "fence-refuse-smoke"))]
pub(crate) use rc_fence::*;
#[cfg(any(feature = "gpio-aq3-smoke", feature = "ring3-drv-smoke", feature = "estop-gpio-smoke",
          all(feature = "qemu", feature = "boot-selftests")))]
mod drivers;
#[cfg(any(feature = "gpio-aq3-smoke", feature = "ring3-drv-smoke", feature = "estop-gpio-smoke",
          all(feature = "qemu", feature = "boot-selftests")))]
pub(crate) use drivers::*;
#[cfg(feature = "console-splice-smoke")]
mod console_splice;
#[cfg(feature = "console-splice-smoke")]
pub(crate) use console_splice::*;

// Former inline `mod name { ... }` blocks of main.rs, one file each.
#[cfg(any(feature = "sched-hooks-smoke", feature = "ktest"))]
pub(crate) mod sched_hooks_smoke;
#[cfg(feature = "proxy-pi-smoke")]
pub(crate) mod proxy_pi_smoke;
#[cfg(feature = "ring3-drv-smoke")]
pub(crate) mod ring3_drv_smoke;
#[cfg(feature = "qemu")]
#[cfg(any(feature = "tlb-smoke", feature = "ktest"))]
pub(crate) mod tlb_probe;
// N12: ASID rollover vs a retained TLB (uses `tlb_probe`'s fault-safe load).
#[cfg(all(feature = "qemu", feature = "ktest"))]
pub(crate) mod asid_rollover;
// The hart-id-then-table audit: the fixed sites read under a mask.
#[cfg(feature = "ktest")]
pub(crate) mod percpu_hazard;
// N12b: the per-address-space hart mask (Kconfig TLB_SPACE_MASK).
#[cfg(all(feature = "qemu", feature = "ktest"))]
pub(crate) mod tlb_space_mask;
// N12c: one ASID per address space (the per-space record in tlb_gen).
#[cfg(all(feature = "qemu", feature = "ktest"))]
pub(crate) mod asid_one_per_space;
// N12f: the kernel half every user root shares (Kconfig RV_KERNEL_GLOBAL).
#[cfg(all(feature = "qemu", feature = "ktest"))]
pub(crate) mod kernel_half_shared;
// A user device window as a copy buffer is EFAULT (front uaccess-mmio-buffer).
#[cfg(feature = "ktest")]
pub(crate) mod uaccess_mmio;
// arch-only: x86_64 has no user images yet; riscv64 and aarch64 reach ring
// 3 through theirs (the rows that boot them).
#[cfg(all(feature = "ktest", target_arch = "x86_64"))]
pub(crate) mod x86_64_ring3;
#[cfg(feature = "irq-order-probe")]
pub(crate) mod irq_order_probe;
// N4 (Kconfig RCU_QSBR): grace periods, the idle hook and the lock-free
// capability reads, every ISA.
#[cfg(feature = "ktest")]
pub(crate) mod rcu;
// N5: PeerDied / Revoked completion, many
// callers on one endpoint, the grace period before a slot is reused.
#[cfg(feature = "ktest")]
pub(crate) mod ipc_endpoint;
// A copy helper called by a task with no user page table refuses a user-range
// VA instead of storing through it (the `thread` page fault at 0x14fb8).
#[cfg(feature = "ktest")]
pub(crate) mod copyout_kernel_ctx;
// Phase 4 elasticity: the kernel's own call to an endpoint a task serves, and
// its refusal under a spinlock.
#[cfg(feature = "ktest")]
pub(crate) mod kcall;
// Live update, Level 1 hooks: an endpoint changes server under load, no call
// lost.
#[cfg(feature = "ktest")]
pub(crate) mod ipc_handover;
// Chain E stage a (Kconfig IPC_FASTPATH): the fast path is taken for a
// parked peer and not with calls queued.
#[cfg(feature = "ktest")]
pub(crate) mod ipc_fastpath;
// Wave 15 N9: the futex requeue wakes one waiter, not the herd.
#[cfg(feature = "ktest")]
pub(crate) mod futex_requeue;
// Wave 15 N10w (Kconfig WAIT_GRAPH + FUTEX_PI): an RT LOCK_PI waiter boosts
// the fair owner of the word through the futex table; UNLOCK_PI restores it.
#[cfg(feature = "ktest")]
pub(crate) mod futex_pi;
// FX5: a process signal pending on a thread that is detached goes back to
// the process (the Linux exit path's `signal::detach`).
#[cfg(feature = "ktest")]
pub(crate) mod sig_retarget;
#[cfg(any(feature = "sensor-ts-smoke", all(feature = "ktest", feature = "use-robot")))]
pub(crate) mod sensor_ts;
#[cfg(feature = "pifast-smoke")]
pub(crate) mod pifast_smoke;
#[cfg(feature = "rt-panic-canary")]
pub(crate) mod rt_panic_smoke;
#[cfg(feature = "panic-splice-smoke")]
pub(crate) mod panic_splice_smoke;
#[cfg(feature = "drv-contain-smoke")]
pub(crate) mod drv_contain_smoke;
#[cfg(feature = "timer-heap-smoke")]
pub(crate) mod timer_heap_smoke;
#[cfg(any(feature = "preempt-account-smoke", feature = "ktest"))]
pub(crate) mod preempt_account_smoke;
#[cfg(all(feature = "ktest", feature = "use-robot"))]
pub(crate) mod commander_exit;
#[cfg(all(feature = "ktest", feature = "use-robot", feature = "effect-gate"))]
mod held_wheel;
#[cfg(feature = "tail-smoke")]
pub(crate) mod tail_smoke;
#[cfg(feature = "energy-smoke")]
pub(crate) mod energy_smoke;
#[cfg(feature = "thermal-smoke")]
pub(crate) mod thermal_smoke;
#[cfg(feature = "ktest")]
pub(crate) mod rt_console;
// L5: an interrupt storm is contained by its handler's reservation; an MSI
// slot reaches a ring-3 binding.
#[cfg(feature = "ktest")]
pub(crate) mod irq_budget;
// XC: a task-context kernel line waits for a held, full console; never dropped.
#[cfg(feature = "ktest")]
pub(crate) mod console_wait;
// K1: an io_ring fsync completes after the flush, posted by the flush path.
#[cfg(feature = "ktest")]
pub(crate) mod ioring_k1;

/// `kernel_main`'s scheduler and real-time smokes, in its order: TLB
/// shootdown, wake-up latency, fast-IPC priority inversion, the RT band and
/// admission, the panic policy and splice, driver containment, the timer
/// heap, preemption accounting, tail latency, energy and thermal. Each is
/// feature-gated; a default image spawns none. Inlined, as every boot phase
/// (see `boot`'s module doc).
#[inline(always)]
#[cfg_attr(not(any(all(feature = "tlb-smoke", not(feature = "ktest")), feature = "lat-smoke")),
           allow(unused_variables))]
pub(crate) fn spawn_sched_smokes(num_cpus: usize) {
    // Wave 8: cross-hart TLB shootdown, observed (see `tlb_probe`). Runner on
    // hart 1, toucher on hart 2 (hart 3 is net-poll's); needs >= 3 harts.
    #[cfg(all(feature = "tlb-smoke", not(feature = "ktest")))]
    {
        if num_cpus >= 3 {
            azos_sched::task_create_affinity("tlb-probe", tlb_probe::runner, 2,
                                                 tlb_probe::PROBE_PRIO, 1);
            kprintln!("[SCHED] Created tlb-probe task (wave 8 shootdown) [harts 1,2]");
        } else {
            kprintln!("[TLB-SMOKE] SKIP: needs -smp >= 3, have {}", num_cpus);
        }
    }

    // Wave 11 (LAT): worst-case wake-up latency under load, see `lat_smoke`.
    #[cfg(feature = "lat-smoke")]
    lat_smoke::spawn(num_cpus);

    // Wave 11 (PIFAST): priority inversion through fast IPC, see the module.
    #[cfg(feature = "pifast-smoke")]
    smokes::pifast_smoke::spawn();
    // Wave 11 (SCHED-RT): band budget, EDF + CBS, admission, see `rt_smoke`.
    #[cfg(feature = "sched-rt-smoke")]
    rt_smoke::spawn();
    // Wave 15: admitted deadlines near the admission bound, see `rt_util_smoke`.
    #[cfg(feature = "sched-rt-util")]
    rt_util_smoke::spawn();
    // RT7: panic policy by profile, see `smokes::rt_panic_smoke`.
    #[cfg(feature = "rt-panic-canary")]
    smokes::rt_panic_smoke::spawn();
    // Wave 15 GR5: a panic while another CPU floods the console, see
    // `smokes::panic_splice_smoke`.
    #[cfg(feature = "panic-splice-smoke")]
    smokes::panic_splice_smoke::spawn();
    // RT7 (wave 13): a contained panic in a kernel-placed driver's host, and
    // its restart, see `smokes::drv_contain_smoke`.
    #[cfg(feature = "drv-contain-smoke")]
    smokes::drv_contain_smoke::spawn();
    // RT7 P2 (wave 13): timer sleepers racing early wakes on every hart, see
    // `smokes::timer_heap_smoke`.
    #[cfg(feature = "timer-heap-smoke")]
    smokes::timer_heap_smoke::spawn();
    // RT7 (wave 13): a tick deferred by a SpinLock counts as a preemption.
    #[cfg(all(feature = "preempt-account-smoke", not(feature = "ktest")))]
    smokes::preempt_account_smoke::spawn();
    // RT7 (wave 13): periodic-wake tail latency under ping-pong contention.
    #[cfg(feature = "tail-smoke")]
    smokes::tail_smoke::spawn();
    // The energy model and the utilisation signals.
    #[cfg(feature = "energy-smoke")]
    smokes::energy_smoke::spawn();
    // The thermal row: a scripted temperature through the real runtime.
    #[cfg(feature = "thermal-smoke")]
    smokes::thermal_smoke::spawn();
}

/// `kernel_main`'s ring-3 driver, safety and refusal smokes, in its order:
/// the AQ3 GPIO round trip (and the supervisor smoke after it), the OTA and
/// durability probes, the buzzer and INA219 test, the supervised restarts,
/// the e-stop line, the console splice, reflex, envelope, geofence and RC
/// smokes, the sensor stamp, the flight-recorder read-backs, then the
/// fork-refusal probe. Each is feature-gated; a default image spawns none.
/// Inlined, as every boot phase (see `boot`'s module doc).
#[inline(always)]
pub(crate) fn spawn_system_smokes() {
    // E11.AQ3 validation smoke: if a userspace gpio_drv was autorun'd, exercise
    // the ring-3 driver round-trip from a kernel task, on a hart other than the
    // autorun hart (3): the cross-hart case. The same-hart case — a client more
    // urgent than the driver, on the driver's hart — is `proxy-pi-smoke`,
    // started by this task once the driver has answered. QEMU-only: a
    // validation aid, not production. A boot self-test (Kconfig
    // BOOT_SELFTESTS), and on its own in the smokes it starts (`gpio-aq3-smoke`):
    // an image without gpio_drv used to wait out its whole retry budget.
    //
    // **Priority 16, not 13.** It was 13, which on hart 1 is ABOVE
    // `sensor-ahrs` at 14, while the proxy still waited for the reply with a
    // million-iteration `spin_loop()`: for the whole span of a wait
    // `sensor-ahrs` got no CPU, and `flight-ctrl` on hart 0 ages the attitude
    // it publishes for its failsafe. The proxy now blocks for the reply
    // (wave 8), so the wait no longer costs hart 1 anything; the priority
    // stays below the sensor loop because nothing needs it higher.
    #[cfg(any(feature = "gpio-aq3-smoke", all(feature = "qemu", feature = "boot-selftests")))]
    {
        const GPIO_SMOKE_PRIORITY: u32 = azos_sched::DEFAULT_PRIORITY;
        const GPIO_SMOKE_HART: i8 = 1;
        azos_sched::task_create_affinity(
            "gpio-aq3-smoke", gpio_user_driver_smoke_task, 0,
            GPIO_SMOKE_PRIORITY, GPIO_SMOKE_HART,
        );
        // sup-smoke: kill the ring-3 GPIO driver four times, after the AQ3
        // smoke is done with it.
        #[cfg(feature = "sup-smoke")]
        drv_supervisor::start_smoke();
    }
    #[cfg(feature = "orderly-reboot-smoke")]
    azos_sched::task_create_affinity("orderly-smoke", orderly_reboot_smoke_task, 0,
                                         azos_sched::DEFAULT_PRIORITY, 1);
    #[cfg(feature = "safe-mode-smoke")]
    azos_sched::task_create_affinity("safe-mode-probe", safe_mode_probe_task, 0,
                                         azos_sched::DEFAULT_PRIORITY, 1);
    #[cfg(feature = "power-off-durability-smoke")]
    azos_sched::task_create_affinity("durable-smoke", power_off_durability_smoke_task, 0,
                                         azos_sched::DEFAULT_PRIORITY, 1);
    #[cfg(feature = "orderly-drain-smoke")]
    azos_sched::task_create("drain-smoke", orderly_drain_smoke_task, 0, azos_sched::DEFAULT_PRIORITY);

    // DRV1: the buzzer and INA219 functional test. Hart 1, default priority,
    // like `gpio-aq3-smoke`: it only waits and reads.
    #[cfg(feature = "ring3-drv-smoke")]
    azos_sched::task_create_affinity(
        "drv-smoke", ring3_drv_smoke::task, 0, azos_sched::DEFAULT_PRIORITY, 1,
    );

    // Wave 11: the topology's `start = true` drivers killed under supervision
    // (`drv_supervisor::supall`).
    #[cfg(feature = "supall-smoke")]
    drv_supervisor::start_supall_smoke();
    #[cfg(feature = "restart-smoke")]
    drv_supervisor::start_restart_smoke();

    // reflex-smoke: drive the ring-3 obstacle-avoidance daemon through a real
    // decision by moving the simulated rangefinder underneath it, and assert
    // it reacts. Without this, "reflex runs" only ever meant "reflex printed
    // its banner": with a clear road it correctly does nothing, so a working
    // daemon and a daemon whose sensor reads are all denied produce identical
    // output. That ambiguity is exactly what hid the missing capability grant.
    #[cfg(feature = "estop-gpio-smoke")]
    {
        // Hart 1, not hart 3 — that one is autorun's and net-poll's.
        //
        // DEFAULT priority, for the reason `gpio-aq3-smoke` above spells out.
        // Its body is millions of `task_yield`s, and a yield re-selects the
        // highest-priority ready task on the hart — which at 13 was this task,
        // above `sensor-ahrs` (14). The smoke starved the attitude publisher
        // for as long as it waited, in the very scenario that asserts a safety
        // path. Nothing here needs to outrank anything: it waits for other
        // tasks to make progress, so running in the gaps they leave is the
        // whole design.
        azos_sched::task_create_affinity(
            "estop-gpio-smoke", estop_gpio_smoke_task, 0,
            azos_sched::DEFAULT_PRIORITY, 1,
        );
    }

    #[cfg(feature = "console-splice-smoke")]
    {
        // Harts 1 and 2 so that, with `-smp 4`, the ring-3 writer and the
        // kernel printer contend from different harts; with `-smp 1` both are
        // rescued onto hart 0 and the contention is preemption + the timer ISR.
        azos_sched::task_create_affinity(
            "splice-w", console_splice_writer_task, 0,
            azos_sched::DEFAULT_PRIORITY, 1,
        );
        azos_sched::task_create_affinity(
            "splice-k", console_splice_kprint_task, 0,
            azos_sched::DEFAULT_PRIORITY, 2,
        );
    }

    #[cfg(feature = "reflex-smoke")]
    {
        // DEFAULT, not 13: same yield-loop-above-`sensor-ahrs` shape as
        // `estop-gpio-smoke` above, and the same fix.
        const REFLEX_SMOKE_PRIORITY: u32 = azos_sched::DEFAULT_PRIORITY;
        const REFLEX_SMOKE_HART: i8 = 1;   // not hart 3 — that is autorun's
        azos_sched::task_create_affinity(
            "reflex-smoke", reflex_smoke_task, 0,
            REFLEX_SMOKE_PRIORITY, REFLEX_SMOKE_HART,
        );
    }

    // envelope-smoke: drive the motor-envelope chokepoint with a command above the
    // per-robot-type cap and observe the refusal on the console.
    #[cfg(feature = "envelope-smoke")]
    {
        azos_sched::task_create(
            "envelope-smoke", envelope_smoke_task, 0,
            azos_sched::DEFAULT_PRIORITY,
        );
    }

    // geofence-smoke: arm a fence around the simulated GPS fix, feed the GPS
    // driver a fix outside it, and print the verdict L0 would act on.
    #[cfg(all(feature = "geofence-smoke", not(feature = "ktest")))]
    {
        azos_sched::task_create(
            "geofence-smoke", geofence_smoke_task, 0,
            azos_sched::DEFAULT_PRIORITY,
        );
    }

    // Wave 15 (RC input and geofence): one property per boot, see
    // `smokes::rc_fence`.
    #[cfg(feature = "rc-failsafe-smoke")]
    azos_sched::task_create("rc-failsafe-smoke", rc_failsafe_smoke_task, 0,
                            azos_sched::DEFAULT_PRIORITY);
    #[cfg(feature = "rc-stick-smoke")]
    azos_sched::task_create("rc-stick-smoke", rc_stick_smoke_task, 0,
                            azos_sched::DEFAULT_PRIORITY);
    #[cfg(feature = "fence-refuse-smoke")]
    azos_sched::task_create("fence-refuse-smoke", fence_refuse_smoke_task, 0,
                            azos_sched::DEFAULT_PRIORITY);

    // sensor-ts-smoke (wave 11): the IMU's acquisition stamp, from the driver
    // to the bus staleness check L0 reads (see `smokes::sensor_ts`).
    #[cfg(all(feature = "sensor-ts-smoke", not(feature = "ktest")))]
    {
        azos_sched::task_create(
            "sensor-ts-smoke", smokes::sensor_ts::sensor_ts_smoke_task, 0,
            azos_sched::DEFAULT_PRIORITY,
        );
    }

    // brain-lies-smoke: wait for the peer's unknown-packet frame and read the
    // SAFETY_UNKNOWN_PKT record back off the flight recorder. Priority is the
    // default, NOT the real-time band: a task in that band on the NIC's hart
    // is what starved `net-poll` when the brain-lies scenario was written, and
    // this one depends on exactly that link working.
    #[cfg(feature = "brain-lies-smoke")]
    {
        azos_sched::task_create(
            "brain-lies-smoke", brain_lies_smoke_task, 0,
            azos_sched::DEFAULT_PRIORITY,
        );
    }

    // cap-deny-smoke: read captest's forged-handle refusal back off the flight
    // recorder. Default priority for the same reason as the probe above.
    #[cfg(feature = "cap-deny-smoke")]
    {
        azos_sched::task_create(
            "cap-deny-smoke", cap_deny_smoke_task, 0,
            azos_sched::DEFAULT_PRIORITY,
        );
    }

    // disk-part-row: read captest's out-of-partition refusal back off the
    // flight recorder. Default priority, as the probes above.
    #[cfg(feature = "disk-part-row")]
    {
        azos_sched::task_create(
            "disk-part-row", disk_part_row_task, 0,
            azos_sched::DEFAULT_PRIORITY,
        );
    }

    // (OTA auto-recv listener was spawned earlier, right after net_init().)

    // ── Fork-refusal probe (opt-in only; never in a normal or board build) ──
    //
    // `sys_fork_impl` refuses from SIX distinct sites and, until 2026-09-25,
    // every one returned a bare `-1`. That cost a week: an aarch64
    // `fork+exit` `rc=-1` was mis-filed as a known gap because a `-1` in a log
    // cannot say WHICH site fired. Each site now bumps its own counter and
    // prints `[FORK] refusal site first hit: <name>` once, on the 0→1 edge.
    // A counter no row ever observes is indistinguishable from one that is not
    // wired, so the gate has to watch one fire — that is this probe's whole
    // job, on both ISAs.
    //
    // **POSITION IS THE WHOLE CORRECTNESS ARGUMENT, and the first placement was
    // wrong.** Site 1's test is `current_user_pt() == 0`, which reads
    // `PER_CPU[current_cpu_id()].current_idx`. Placed after
    // `arch_wake_secondaries`, the probe ran while OTHER harts were already
    // dispatching user tasks, and gate 180 caught it: one boot in seven
    // returned `rc=0` — a SUCCESSFUL fork — meaning that read landed on a slot
    // that had a user page table. Only `do_schedule` writes `current_idx`, and
    // only for its own hart, so on hart 0 (which had not scheduled yet) that
    // should be impossible. **That anomaly is NOT explained and is recorded as
    // an open finding, not fixed here** — see the memory note; it may be a real
    // `current_cpu_id()` defect under load.
    //
    // Here, before any secondary is woken and before hart 0 schedules, there is
    // exactly one running hart and no task has ever been current: the read is
    // unambiguous. Measured 6/6 `rc=-1` at the old position on a quiet host and
    // 7/7 here; the point of moving it is that the probe must not be able to
    // observe someone else's scheduler state at all.
    //
    // The call allocates nothing and cannot reach the five later sites. The
    // (since deleted) console `fork` command exercised the identical path with
    // the same zeroed `sepc`/`user_sp`/regs; this is that call without needing
    // typed input in QEMU's console, which is where an earlier attempt stalled.
    #[cfg(feature = "fork-refusal-probe")]
    {
        kprintln!("[FORK] refusal probe: calling fork from kernel context (must refuse)");
        let rc = azos_sched::process::sys_fork_impl(
            0, 0, &azos_sched::UserRegs::default());
        kprintln!("[FORK] refusal probe: rc={} (expected -1)", rc);
    }
}

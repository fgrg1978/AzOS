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
#[cfg(any(feature = "orderly-reboot-smoke", feature = "safe-mode-smoke", feature = "power-off-durability-smoke"))]
mod ota;
#[cfg(any(feature = "orderly-reboot-smoke", feature = "safe-mode-smoke", feature = "power-off-durability-smoke"))]
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

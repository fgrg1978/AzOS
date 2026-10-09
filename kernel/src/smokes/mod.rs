// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Boot self-tests and feature-gated boot smokes. Each item keeps the `cfg`
//! it had in `main.rs`; a module declaration is gated on the union of its
//! items' gates (so an all-off module is not compiled as an empty file with
//! an unused import), and a new item behind a new feature must add that
//! feature here or its call site fails to resolve. Everything is re-exported
//! so `kernel_main` and the trap handlers name each entry point directly.

mod selftest;
pub(crate) use selftest::*;
#[cfg(feature = "cpuid-probe")]
pub(crate) mod cpuid_probe;
#[cfg(feature = "trace-cost-probe")]
mod trace_cost;
#[cfg(feature = "trace-cost-probe")]
pub(crate) use trace_cost::*;
#[cfg(target_arch = "aarch64")]
mod aarch64_sched;
#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64_sched::*;
#[cfg(feature = "ipc-census")]
mod ipc_census;
#[cfg(feature = "ipc-census")]
pub(crate) use ipc_census::*;
#[cfg(any(feature = "fat-barrier-smoke", feature = "mmc-flush-smoke", feature = "disk-part-row"))]
mod storage;
#[cfg(any(feature = "fat-barrier-smoke", feature = "mmc-flush-smoke", feature = "disk-part-row"))]
pub(crate) use storage::*;
#[cfg(feature = "dhcp-smoke")]
mod net;
#[cfg(feature = "dhcp-smoke")]
pub(crate) use net::*;
#[cfg(any(feature = "orderly-reboot-smoke", feature = "safe-mode-smoke"))]
mod ota;
#[cfg(any(feature = "orderly-reboot-smoke", feature = "safe-mode-smoke"))]
pub(crate) use ota::*;
#[cfg(any(feature = "reflex-smoke", feature = "envelope-smoke", feature = "geofence-smoke",
          feature = "brain-lies-smoke", feature = "cap-deny-smoke", feature = "disk-part-row",
          feature = "ml-kill-smoke", feature = "rc-failsafe-smoke", feature = "fence-refuse-smoke",
          all(feature = "ktest", feature = "domain-robot")))]
mod safety;
#[cfg(any(feature = "reflex-smoke", feature = "envelope-smoke",
          all(feature = "geofence-smoke", not(feature = "ktest")),
          feature = "brain-lies-smoke", feature = "cap-deny-smoke", feature = "disk-part-row",
          feature = "ml-kill-smoke", feature = "rc-failsafe-smoke", feature = "fence-refuse-smoke"))]
pub(crate) use safety::*;
// Wave 15: RC receiver and geofence wiring, one property per boot.
#[cfg(any(feature = "rc-failsafe-smoke", feature = "rc-stick-smoke", feature = "fence-refuse-smoke"))]
mod rc_fence;
#[cfg(any(feature = "rc-failsafe-smoke", feature = "rc-stick-smoke", feature = "fence-refuse-smoke"))]
pub(crate) use rc_fence::*;
#[cfg(any(feature = "qemu", feature = "estop-gpio-smoke"))]
mod drivers;
#[cfg(any(feature = "qemu", feature = "estop-gpio-smoke"))]
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
#[cfg(feature = "lease-pi3-smoke")]
pub(crate) mod lease_pi3_smoke;
#[cfg(feature = "ring3-drv-smoke")]
pub(crate) mod ring3_drv_smoke;
#[cfg(feature = "qemu")]
#[cfg(any(feature = "tlb-smoke", feature = "ktest"))]
pub(crate) mod tlb_probe;
// arch-only: x86_64 has no user images yet; riscv64 and aarch64 reach ring
// 3 through theirs (the rows that boot them).
#[cfg(all(feature = "ktest", target_arch = "x86_64"))]
pub(crate) mod x86_64_ring3;
#[cfg(feature = "irq-order-probe")]
pub(crate) mod irq_order_probe;
#[cfg(any(feature = "pi-smoke", feature = "ktest"))]
pub(crate) mod pi_probe;
#[cfg(feature = "pi-flush-smoke")]
pub(crate) mod pi_flush_probe;
#[cfg(any(feature = "i3-smoke", feature = "ktest"))]
pub(crate) mod i3_probe;
#[cfg(any(feature = "sensor-ts-smoke", all(feature = "ktest", feature = "domain-robot")))]
pub(crate) mod sensor_ts;
#[cfg(feature = "pifast-smoke")]
pub(crate) mod pifast_smoke;
#[cfg(feature = "rt-panic-canary")]
pub(crate) mod rt_panic_smoke;
#[cfg(feature = "drv-contain-smoke")]
pub(crate) mod drv_contain_smoke;
#[cfg(feature = "timer-heap-smoke")]
pub(crate) mod timer_heap_smoke;
#[cfg(any(feature = "preempt-account-smoke", feature = "ktest"))]
pub(crate) mod preempt_account_smoke;
#[cfg(all(feature = "ktest", feature = "domain-robot"))]
pub(crate) mod commander_exit;
#[cfg(feature = "tail-smoke")]
pub(crate) mod tail_smoke;
#[cfg(feature = "energy-smoke")]
pub(crate) mod energy_smoke;
#[cfg(feature = "ktest")]
pub(crate) mod rt_console;
// K1: an io_ring fsync completes after the flush, posted by the flush path.
#[cfg(feature = "ktest")]
pub(crate) mod ioring_k1;

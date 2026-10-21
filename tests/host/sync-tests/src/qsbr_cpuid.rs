// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `crates/core/sync/src/qsbr_cpu.rs` with `qsbr_nohz.rs`: QSBR's per-CPU
//! words and CPU masks follow the CPU id the arch reports (`Cpu::hart_id`),
//! which is the dense logical id on every ISA; the hardware numbering (a
//! non-zero boot hart, sparse hart ids) is mapped away at the boundary
//! (`azos_percpu::hw_id`, tested in `tests/host/percpu-tests`) and never
//! reaches QSBR.
//!
//! The kernel's `this_cpu()` and `user_is_eqs` are pulled by path; the shim
//! reports whatever CPU id the test sets.
//!
//! Registered in `lib.rs` by `#[cfg(test)] mod qsbr_cpuid;`.

use super::qsbr_core::cpu_in_mask;

#[path = "../../../../crates/core/sync/src/qsbr_cpu.rs"]
mod cpu;
#[path = "../../../../crates/core/sync/src/qsbr_nohz.rs"]
mod nohz;

/// Run `body` on each CPU of a sparse-looking set, with the shim reporting it.
fn on_each_cpu(mut body: impl FnMut(usize)) {
    for cpu in [0usize, 1, 2] {
        azos_arch::set_hart(cpu);
        body(cpu);
    }
}

/// Canary: index QSBR by anything but the arch's id (a fixed 0, say) and the
/// slot assertion fails on CPU 1.
#[test]
fn slots_and_masks_follow_the_cpu_id() {
    let nocbs = 1usize << 0;
    let tickless = 1u64 << 2;
    let mut slots = [0u32; 3];
    on_each_cpu(|c| {
        let i = cpu::this_cpu();
        assert_eq!(i, c, "slot {i}, not CPU {c}'s");
        slots[i] += 1;
        assert_eq!(nohz::user_is_eqs(nocbs, 0, i), c == 0, "RCU_NOCBS_CPUS");
        assert_eq!(nohz::user_is_eqs(0, tickless, i), c == 2, "tickless set");
        assert_eq!(cpu_in_mask(nocbs, i), c == 0, "cpu_in_mask");
    });
    assert_eq!(slots, [1, 1, 1], "each CPU's slot written exactly once");
}

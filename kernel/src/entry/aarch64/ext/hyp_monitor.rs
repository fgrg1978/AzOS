// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's side of the resident monitor (VIRT_SPLIT / Kconfig
//! HYP_MONITOR): the monitor blob `.incbin`'d into the `.hyp` section, and the
//! boot probe that proves it is up. The EL2 code itself is a separate image
//! (`crates/core/hyp-mon`); the kernel only starts it (the trampoline branch
//! in `arch/aarch64/src/mmu/boot.rs`) and talks to it over the ABI.
//!
//! The blob variant is chosen by feature so a gate canary that removes one
//! monitor mechanism links a differently-built monitor and turns one row red.

use azos_drv_sys::kprintln;
use azos_hyp_api::{
    is_monitor_call, CALL_PROBE, INVARIANT_NAMES, OK,
};

// The blob, placed in `.hyp` (a non-exec `alloc` section the linker keeps out
// of the kernel's text/rodata ranges). `_hyp_blob_start` is the monitor's
// entry; the trampoline branches to it. One `.incbin` per build variant.
macro_rules! hyp_blob {
    ($file:literal) => {
        core::arch::global_asm!(
            concat!(
                ".section .hyp, \"a\"\n",
                ".balign 4096\n",
                ".globl _hyp_blob_start\n",
                "_hyp_blob_start:\n",
                ".incbin \"", env!("AZOS_OUT"), $file, "\"\n",
                ".balign 4096\n",
                ".globl _hyp_blob_end\n",
                "_hyp_blob_end:\n",
            )
        );
    };
}

#[cfg(not(any(
    feature = "hyp-mmu-off-canary",
    feature = "hyp-no-secondary-init-canary",
    feature = "hyp-hole-mapped-canary",
    feature = "hyp-tsc-off-canary"
)))]
hyp_blob!("/build/aarch64/hyp-mon.bin");
#[cfg(feature = "hyp-mmu-off-canary")]
hyp_blob!("/build/aarch64/hyp-mon-mmu-off.bin");
#[cfg(feature = "hyp-no-secondary-init-canary")]
hyp_blob!("/build/aarch64/hyp-mon-no-secondary-init.bin");
#[cfg(feature = "hyp-hole-mapped-canary")]
hyp_blob!("/build/aarch64/hyp-mon-hole-mapped.bin");
#[cfg(feature = "hyp-tsc-off-canary")]
hyp_blob!("/build/aarch64/hyp-mon-tsc-off.bin");

/// Issue a monitor call (SMCCC: id in x0, args in x1..x3, results back in
/// x0..x3). An HVC, which the monitor traps at EL2.
#[inline]
fn monitor_call(id: u64, a1: u64) -> [u64; 4] {
    let (mut x0, mut x1, mut x2, mut x3) = (id, a1, 0u64, 0u64);
    // SAFETY: the monitor is resident (HYP_MONITOR built it in and the
    // trampoline started it) before this runs.
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") x0,
            inout("x1") x1,
            inout("x2") x2,
            inout("x3") x3,
        );
    }
    [x0, x1, x2, x3]
}

/// The EL2 line of the boot banner for a split image: probe the monitor and
/// list the invariants it reports in force. The probe is the first EL1→EL2
/// call; a monitor that is wrong stops the boot here, not at a later attack.
pub(crate) fn report() {
    debug_assert!(is_monitor_call(CALL_PROBE));
    let r = monitor_call(CALL_PROBE, 0);
    if r[0] as i64 != OK {
        kprintln!("[BOOT] EL2:        monitor probe failed ({})", r[0] as i64);
        return;
    }
    let (abi, inv, pes) = (r[1], r[2], r[3]);
    kprintln!("[BOOT] EL2:        monitor up (abi {}, PEs {})", abi, pes);
    let mut first = true;
    for (bit, name) in INVARIANT_NAMES {
        if inv & bit != 0 {
            kprintln!("[BOOT] EL2:        invariant {} in force", name);
            first = false;
        }
    }
    if first {
        kprintln!("[BOOT] EL2:        no invariants reported");
    }
}

/// A secondary released through a spin table jumps to a kernel-written address
/// at EL2, past the monitor, and the monitor cannot intercept that. `found` is
/// how many spin-table CPUs the tree lists; any is a halt for a split image.
pub(crate) fn refuse_spin_table(found: usize) {
    if (found == 0 && !canary!("hyp-fake-spin-table")) || canary!("hyp-halt-skip") {
        return;
    }
    crate::boot::isa::refuse_text(
        "[BOOT] EL2:        refused: spin-table secondaries bypass the monitor (split never degrades)",
    )
}

/// Without a PSCI conduit a second PE cannot be started through the monitor,
/// so a split image with more than one CPU and no conduit halts.
pub(crate) fn refuse_no_conduit(no_conduit: bool, cpus: usize) {
    if !((no_conduit || canary!("hyp-fake-no-conduit")) && cpus > 1) || canary!("hyp-halt-skip") {
        return;
    }
    crate::boot::isa::refuse_text(
        "[BOOT] EL2:        refused: no PSCI conduit with more than one CPU (split never degrades)",
    )
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Split-lock detection (Kconfig `X86_SPLIT_LOCK`): `MSR_TEST_CTRL` bit 29
//! makes a locked atomic that crosses a cache line raise #AC instead of
//! taking a bus lock that stalls every other core for microseconds, which
//! is unbounded jitter for a real-time task on another core.
//!
//! Every MSR access here is guarded by the probe: the CPUID bit for
//! IA32_CORE_CAPABILITIES, then its bit 5 (`features::split_lock_supported`,
//! host-tested with the rest of the decisions). Where the guard fails the
//! MSRs are never touched, so a CPU or an emulator (QEMU TCG) without them
//! never sees a #GP. The MSR is per core: the boot CPU calls [`set_wanted`]
//! and [`enable_this_cpu`], each secondary calls [`enable_this_cpu`] when
//! [`wanted`].

use core::sync::atomic::{AtomicBool, Ordering};

use crate::features::{
    detect, split_lock_supported, test_ctrl_with_split_lock, MSR_IA32_CORE_CAPABILITIES,
    MSR_TEST_CTRL, TEST_CTRL_SPLIT_LOCK_DETECT,
};
use crate::hw::{rdmsr, wrmsr};

/// Set once by the boot CPU: detection is allowed (policy) and present (probe).
static WANTED: AtomicBool = AtomicBool::new(false);

/// Does this CPU have split-lock detection? The only place that reads
/// IA32_CORE_CAPABILITIES, and only after its CPUID bit.
pub fn probe() -> bool {
    let cpuid_bit = detect().core_capabilities;
    split_lock_supported(cpuid_bit, if cpuid_bit { rdmsr(MSR_IA32_CORE_CAPABILITIES) } else { 0 })
}

/// Record the boot CPU's decision (policy gate over the probe).
pub fn set_wanted(on: bool) {
    WANTED.store(on, Ordering::Release);
}

/// Is detection to be on, on every CPU?
pub fn wanted() -> bool {
    WANTED.load(Ordering::Acquire)
}

/// Turn detection on in this CPU's MSR_TEST_CTRL; the readback. False, and no
/// MSR touched, unless [`wanted`].
pub fn enable_this_cpu() -> bool {
    if !wanted() {
        return false;
    }
    wrmsr(MSR_TEST_CTRL, test_ctrl_with_split_lock(rdmsr(MSR_TEST_CTRL), true));
    active_this_cpu()
}

/// Turn detection off in this CPU's MSR_TEST_CTRL (the kernel's release-build
/// answer to a split lock: warn once, then let the access retry). No MSR touched
/// unless [`wanted`].
pub fn disable_this_cpu() {
    if wanted() {
        wrmsr(MSR_TEST_CTRL, test_ctrl_with_split_lock(rdmsr(MSR_TEST_CTRL), false));
    }
}

/// Is detection on in this CPU's MSR right now? The #AC handler's input to
/// `features::classify_ac`.
pub fn active_this_cpu() -> bool {
    wanted() && rdmsr(MSR_TEST_CTRL) & TEST_CTRL_SPLIT_LOCK_DETECT != 0
}

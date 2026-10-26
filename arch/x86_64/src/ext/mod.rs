// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64-only extras with no counterpart on the other ISAs.

/// Hybrid core types (Intel P/E, AMD Zen 5/5c) from CPUID, per logical
/// processor, for the energy model's capacity classes.
pub mod hybrid;

/// Speculation mitigations (Kconfig `X86_MIT_*`): the pure decision, then the
/// MSR half, which is x86_64 only.
pub mod mitigations;
/// The indirect-branch thunk of `X86_MIT_SPECTRE_V2` = probe.
#[cfg(target_arch = "x86_64")]
pub mod retpoline;
/// Split-lock detection (Kconfig `X86_SPLIT_LOCK`): MSR_TEST_CTRL, probe-guarded.
#[cfg(target_arch = "x86_64")]
pub mod splitlock;

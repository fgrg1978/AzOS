// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! System suspend on aarch64: PSCI `SYSTEM_SUSPEND`, and when the kernel may
//! call it.
//!
//! The call loses the CPU's context and resumes at an entry point with the MMU
//! off, so the wrong answer here is silent in the bad direction: a kernel that
//! says "available" without a resume entry suspends and never comes back. The
//! decision is pinned from every side: PSCI older than 1.0 has no such call, a
//! firmware that does not list it is refused with its own code, and a firmware
//! that has it still needs the kernel's entry.

use crate::aarch64_firmware::*;
use std::cell::Cell;

#[test]
fn the_function_id_is_the_64_bit_system_suspend() {
    assert_eq!(PSCI_SYSTEM_SUSPEND_64, 0xC400_000E);
    // SMC64 fast call, standard secure service: the same family as CPU_ON_64.
    assert_eq!(PSCI_SYSTEM_SUSPEND_64 >> 24, PSCI_CPU_ON_64 >> 24);
}

#[test]
fn the_firmware_answers_first() {
    let never = || -> i32 { panic!("PSCI_FEATURES does not exist before 1.0") };
    let entry = Some(0x4008_0000);
    use SystemSuspendMissing::Firmware;
    assert_eq!(system_suspend_available(-1, never, entry), Err(Firmware(-1)), "PSCI_VERSION not implemented");
    assert_eq!(system_suspend_available(0x0000_0002, never, entry), Err(Firmware(PSCI_NOT_SUPPORTED)), "0.2 has no SYSTEM_SUSPEND");
    assert_eq!(system_suspend_available(0x0001_0000, || PSCI_NOT_SUPPORTED, entry), Err(Firmware(PSCI_NOT_SUPPORTED)));
    assert_eq!(system_suspend_available(0x0001_0001, || PSCI_INVALID_PARAMS, entry), Err(Firmware(PSCI_INVALID_PARAMS)));
    // A firmware without the call needs no entry to say so: it is the first reason.
    assert_eq!(system_suspend_available(0x0001_0001, || PSCI_NOT_SUPPORTED, None), Err(Firmware(PSCI_NOT_SUPPORTED)));
}

#[test]
fn a_firmware_that_has_it_still_needs_the_kernels_entry() {
    use SystemSuspendMissing::ResumeEntry;
    assert_eq!(system_suspend_available(0x0001_0001, || 0, None), Err(ResumeEntry));
    assert_eq!(system_suspend_available(0x0001_0001, || 0, Some(0x4008_0000)), Ok(()));
    // PSCI_FEATURES answers 0 (or a flags word) for an implemented call.
    assert_eq!(system_suspend_available(0x0001_0000, || 1, Some(1)), Ok(()));
}

#[test]
fn features_is_asked_once_and_only_from_1_0() {
    let asked = Cell::new(0);
    let _ = system_suspend_available(0x0001_0001, || { asked.set(asked.get() + 1); 0 }, Some(1));
    assert_eq!(asked.get(), 1);
    let _ = system_suspend_available(0x0000_0002, || { asked.set(asked.get() + 1); 0 }, Some(1));
    assert_eq!(asked.get(), 1, "PSCI 0.2 is refused without asking");
}

/// The kernel has no resume entry yet. This pins that it does not claim one:
/// when the trampoline lands, the constant and this test move together.
#[test]
fn the_kernel_names_no_entry_it_does_not_have() {
    assert_eq!(RESUME_ENTRY, None);
    assert_eq!(
        system_suspend_available(0x0001_0001, || 0, RESUME_ENTRY),
        Err(SystemSuspendMissing::ResumeEntry),
    );
}

#[test]
fn a_return_from_the_call_is_never_a_sleep() {
    // The call resumes at the entry point; a return is a refusal, whatever the
    // code, so none of them classifies as a sleep that was woken... except 0,
    // which `classify_suspend` reads for CPU_SUSPEND and the sequence never
    // gets from SYSTEM_SUSPEND (the glue maps every return to an error).
    for code in [PSCI_NOT_SUPPORTED, PSCI_INVALID_PARAMS, PSCI_DENIED, PSCI_INVALID_ADDRESS, PSCI_INTERNAL_FAILURE] {
        assert_ne!(classify_suspend(code), SuspendOutcome::Slept, "{code}");
    }
}

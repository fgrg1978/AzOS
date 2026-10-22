// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's side of the resident EL2 stub (`azos_arch::ext::hv`): the
//! boot record of whether EL2 was kept, and the proof that the stub answers.
//!
//! The vector table and the HVC handler are in the arch crate, next to the
//! `_azos_drop_to_el1` trampoline that installs them, so that every user of
//! the trampoline gets a working EL2. Here is only what the kernel does with them at boot.

use azos_arch::ext::hv::{self, Availability};
use azos_drv_sys::kprintln;

/// The EL2 lines of the boot banner. With EL2 kept it issues the probe `HVC`
/// (EL1 to the stub and back: before the stub existed that call hung the PE),
/// so a stub that is installed but wrong stops the boot here, at its first
/// use, and not at a guest's first `HVC`. A boot that entered at EL1 has no
/// EL2: the hypervisor degrades to none, with the reason.
pub(crate) fn report() {
    match hv::availability() {
        Availability::Resident => match hv::probe() {
            Some(abi) => {
                kprintln!("[BOOT] EL2:        kept; resident stub answers HVC (abi {})", abi);
                // Entering a guest needs the GICv3 virtual CPU interface: a
                // GICv2 machine keeps the stub (the host's PSCI goes through it)
                // and refuses guests.
                if azos_arch_api::Hypervisor::can_enter(&azos_arch::HvImpl) {
                    kprintln!("[BOOT] EL2:        guest entry ready (GICv3 virtual CPU interface)");
                } else {
                    kprintln!("[BOOT] EL2:        no guest entry (no GICv3 system-register interface)");
                }
            }
            None => kprintln!("[BOOT] EL2:        kept; the stub's probe HVC answered wrongly"),
        },
        Availability::Absent(reason) => {
            kprintln!("[BOOT] EL2:        none ({:?}); the hypervisor role degrades to none", reason)
        }
    }
    if let Some((esr, elr)) = hv::last_unhandled_trap() {
        kprintln!("[BOOT] EL2:        a PE is parked on an unhandled trap, ESR_EL2={:#x} ELR_EL2={:#x}", esr, elr);
    }
}

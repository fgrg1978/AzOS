// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The boot decision for the H extension (Kconfig `RV_H`): the device tree
//! says whether cpu@0 declares `h`, the policy says whether the kernel may
//! use it, and one trap-safe `hstatus` access on this hart confirms it. The
//! primitives themselves live in `azos_arch::ext::hv` (arch/riscv64);
//! the `[ISA]` row `h=` reports what this resolves to.

use azos_arch_api::isa::riscv64 as policy;

/// Resolve H on the boot hart: `dt_declares_h` is cpu@0's `riscv,isa`.
/// Under `n`, or without an `h` in the device tree, no CSR is touched.
pub(crate) fn select(dt_declares_h: bool) -> bool {
    azos_arch::ext::hv::probe::select(
        policy::H.allowed(),
        dt_declares_h,
        azos_arch::ext::hv::probe::trap_probe,
    )
}

/// Is H in use (the `[ISA]` row's `present`)?
pub(crate) fn present() -> bool {
    azos_arch::ext::hv::probe::available()
}

/// Hand the guest entry what the boot found (`azos_arch::ext::hv::inject::wire`):
/// Sstc as the host timer resolved it (Kconfig `RV_SSTC`), Smstateen from a
/// trap-safe `hstateen0` access, and the IMSIC's guest interrupt files when
/// the AIA is what the host runs on (Kconfig `RV_AIA`, the device tree's
/// `guest-index-bits`). Only where H was confirmed; without it every field is
/// off and a guest runs as it did before these paths existed. After
/// [`select`], and after the timer and the interrupt controller were chosen.
#[cfg(feature = "hv")]
pub(crate) fn wire(sstc_on: bool) {
    use azos_arch::ext::hv::{inject::{self, Wiring}, probe};
    let h = probe::available();
    let (ids, files) = azos_drv_irqchip::irqchip::imsic_guest_files();
    // Not executed without H: the access would trap whatever the extension.
    let w = Wiring::resolve(h, sstc_on, h && probe::smstateen_probe(), ids, files);
    inject::wire(w);
    if h {
        azos_drv_sys::kprintln!("[HV] guest wiring: sstc={} smstateen={} imsic-guest-ids={}",
            w.sstc, w.smstateen, w.guest_ids);
    }
}

/// The supervisor guest-external interrupt (cause 12) of this hart: the
/// files a waiting vCPU armed and that have an identity pending are
/// disarmed, and each owner's thread is woken (`azos_syscall::vm`).
#[cfg(feature = "hv")]
pub(crate) fn guest_external(hart: usize) {
    // SAFETY: the interrupt is taken only on a hart that enabled it, and that
    // is only a hart with H and guest files (`Hart::guest_files` of the
    // entry); the handler runs with the interrupts off.
    unsafe {
        azos_arch::ext::hv::inject::sgei_take(hart, |owner| azos_syscall::vm::wake_file_owner(owner.key()));
    }
}

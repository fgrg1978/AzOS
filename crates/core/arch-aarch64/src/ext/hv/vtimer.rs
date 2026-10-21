// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The generic timer under a hypervisor: what a guest sees of time.
//!
//! A guest reads the *virtual* count (`CNTVCT_EL0 = CNTPCT - CNTVOFF_EL2`) and
//! programs the *virtual* timer (`CNTV_*`), neither of which traps.
//! `CNTVOFF_EL2` is **one value per VM**, written on every vCPU's entry: the
//! vCPUs of an SMP guest must read one clock, so it never changes while the VM
//! has a vCPU that may run. It is set when the VM starts to the physical
//! count it started at, so the guest's count begins at zero
//! ([`cntvoff_on_resume`] with a saved count of 0), and again only when the
//! *whole* VM was stopped and runs again: its clock does not advance while
//! no vCPU ran ([`cntvoff_on_resume`]). The other time it moves is a pause:
//! the time the VM was held with every running vCPU held is added to it
//! (`GuestIrq::skip_time`), so the count resumes where it stopped. Each vCPU
//! keeps a copy (`GuestIrq`), starting from the VM's slot, and brings it to
//! the VM's value at its entry: `GuestCtx::time_skip` carries all of the
//! lost time at a vCPU's first entry and what is new after a hold, so a vCPU
//! started later (PSCI `CPU_ON`) reads the count the running ones read. The
//! slot itself stays the VM's start, so the time is added once.
//! `CNTHCTL_EL2` decides whether the guest may touch the physical count and
//! timer ([`Cnthctl`]): the host kernel does (it runs on them), a guest does
//! not, so its `CNTP_*` accesses trap and are reported as a system-register
//! exit. The hardware virtual timer belongs to whichever vCPU is on the CPU
//! (the entry swaps it with the host's, `stub.rs`); a vCPU that is off it
//! keeps its timer in a [`Vtimer`], the host arms a physical deadline
//! ([`expiry_physical_count`](Vtimer::expiry_physical_count)) to wake it, and
//! the timer's PPI ([`VTIMER_PPI`]) reaches the guest through the list
//! registers (`inject.rs`).
//!
//! Pure: the register writes are the entry's (`stub.rs`, `vcpu.rs`).

/// The virtual timer's PPI (the architecturally recommended INTID 27).
pub const VTIMER_PPI: u32 = 27;

const CTL_ENABLE: u64 = 1 << 0;
const CTL_IMASK: u64 = 1 << 1;
const CTL_ISTATUS: u64 = 1 << 2;

/// `CNTHCTL_EL2` (E2H = 0): the physical count and timer for EL1/EL0.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cnthctl(u64);

impl Cnthctl {
    /// `EL1PCTEN`: EL1 and EL0 may read the physical count (`CNTPCT_EL0`).
    pub const EL1PCTEN: u64 = 1 << 0;
    /// `EL1PCEN`: EL1 and EL0 may use the physical timer (`CNTP_*`).
    pub const EL1PCEN: u64 = 1 << 1;

    /// The kernel itself: both granted, as `_azos_drop_to_el1` leaves them.
    pub const HOST: Cnthctl = Cnthctl(Self::EL1PCTEN | Self::EL1PCEN);
    /// A guest: both trap to EL2, where the physical timer is emulated.
    pub const GUEST: Cnthctl = Cnthctl(0);

    pub const fn bits(self) -> u64 {
        self.0
    }

    /// `base` (the register's current value) with the two physical-timer
    /// grants taken from `self`, every other bit kept.
    pub const fn apply(self, base: u64) -> u64 {
        (base & !(Self::EL1PCTEN | Self::EL1PCEN)) | self.0
    }

    pub const fn guest_has_physical_timer(self) -> bool {
        self.0 & Self::EL1PCEN != 0
    }
}

/// The virtual count a guest reads: `CNTPCT - CNTVOFF` (wrapping, as the hardware).
pub const fn virtual_count(physical: u64, cntvoff: u64) -> u64 {
    physical.wrapping_sub(cntvoff)
}

/// The `CNTVOFF_EL2` that makes a VM run at the virtual count it left at
/// (`guest_vcnt`, saved when its last vCPU stopped) when the physical count
/// is `physical_now`: its clock does not advance while no vCPU ran. A new VM
/// uses a `guest_vcnt` of 0.
pub const fn cntvoff_on_resume(physical_now: u64, guest_vcnt: u64) -> u64 {
    physical_now.wrapping_sub(guest_vcnt)
}

/// The guest's `CNTV_CTL_EL0` / `CNTV_CVAL_EL0` pair, saved while it is off the CPU.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Vtimer {
    pub ctl: u64,
    pub cval: u64,
}

impl Vtimer {
    /// The guest's timer from the registers read at an exit. `ISTATUS` is
    /// read-only, a function of the condition: it is not state.
    pub const fn from_hw(ctl: u64, cval: u64) -> Vtimer {
        Vtimer { ctl: ctl & !CTL_ISTATUS, cval }
    }

    /// The timer condition holds: enabled and the virtual count reached `cval`.
    pub const fn condition_met(self, vcnt: u64) -> bool {
        self.ctl & CTL_ENABLE != 0 && vcnt >= self.cval
    }

    /// The interrupt line is asserted: the condition holds and `IMASK` is clear.
    pub const fn asserted(self, vcnt: u64) -> bool {
        self.condition_met(vcnt) && self.ctl & CTL_IMASK == 0
    }

    /// `CNTV_CTL_EL0` as the guest reads it back: `ISTATUS` follows the condition.
    pub const fn ctl_as_read(self, vcnt: u64) -> u64 {
        let base = self.ctl & !CTL_ISTATUS;
        if self.condition_met(vcnt) { base | CTL_ISTATUS } else { base }
    }

    /// The physical count at which the host should wake to inject the timer
    /// while the guest is off the CPU, or `None` if it can never fire
    /// (disabled or masked).
    pub const fn expiry_physical_count(self, cntvoff: u64) -> Option<u64> {
        if self.ctl & CTL_ENABLE != 0 && self.ctl & CTL_IMASK == 0 {
            Some(self.cval.wrapping_add(cntvoff))
        } else {
            None
        }
    }
}

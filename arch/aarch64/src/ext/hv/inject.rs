// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Interrupts into a guest: the virtual timer's PPI and the device lines,
//! through the list registers. (The riscv64 counterpart is `hvip`.)
//!
//! Two sources feed one vCPU's [`VgicCpu`]:
//!
//! * **The virtual timer** (`CNTV_*`, [`VTIMER_PPI`] = INTID 27): a *level*
//!   line. The condition is recomputed at every entry from the saved
//!   [`Vtimer`] and the VM's `CNTVOFF`: asserted and not yet listed, the PPI
//!   is raised; no longer asserted (the guest masked or reprogrammed the timer
//!   while the interrupt was listed and untaken), it is taken back. One the
//!   guest is handling is left alone.
//! * **Device lines**: the monitor's `Vcpu::inject(irq)` lines (0..64, the
//!   `GuestCtx::irqs` bits) are SPIs, line `n` = INTID [`SPI_BASE`]` + n`,
//!   software interrupts (no physical interrupt behind them).
//!
//! Order of injection, which is the order the interrupts take list registers
//! and, when they outnumber the LRs, the order the queue serves equal
//! priorities (FIFO): the timer PPI, then the lines in ascending order. Every
//! interrupt is Group 1 at [`GUEST_PRIO`]: the guest's virtual distributor
//! (which would hold per-interrupt enable, priority and group) is the
//! monitor's device model and is not consulted here yet. A line the LRs and the
//! queue cannot take stays in a backlog; at the next entry the backlog is
//! listed before the lines raised since, each group in ascending order.
//!
//! The timer interrupt is delivered by software (`HW = 0`), never linked to
//! the physical PPI, so the host's GIC handling of INTID 27 stays the host's.
//! An asserted timer is the one thing that would still raise that physical
//! PPI at the host on every entry: [`EntryPlan::silence_ppi`] says so, and
//! the entry disables PPI 27 at the CPU's redistributor for the run
//! (`vcpu.rs`), which leaves `CNTV_CTL_EL0` exactly as the guest wrote it:
//! `IMASK`, `ENABLE` and `ISTATUS` read back are the guest's and nothing else.
//! (Masking the hardware timer with `IMASK` instead made the guest's own
//! `IMASK` indistinguishable from the entry's.)
//!
//! Pure: the run loop writes [`GuestIrq::lrs`] / [`GuestIrq::hcr`] and the
//! returned [`TimerRegs`] into the hardware before the `eret`, and reads the
//! LRs and `CNTV_CTL_EL0` / `CNTV_CVAL_EL0` back into [`GuestIrq::after_exit`].

use super::vgic::{VgicCpu, VgicError};
use super::vtimer::{virtual_count, Vtimer, VTIMER_PPI};

/// INTID of device line 0: the first SPI.
pub const SPI_BASE: u32 = 32;
/// Device lines a vCPU tracks (`Vcpu::inject`'s range): one bit each of the
/// `u64` the lines travel in.
pub const LINES: u32 = 64;
const _: () = assert!(LINES == u64::BITS);
/// Priority every guest interrupt is listed at.
pub const GUEST_PRIO: u8 = 0xA0;

/// The INTID of device line `line`.
pub const fn line_intid(line: u32) -> u32 {
    SPI_BASE + line
}

/// What to write into the hardware timer before entering the guest.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TimerRegs {
    pub ctl: u64,
    pub cval: u64,
}

/// What an entry does about interrupts, from [`GuestIrq::pre_entry`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EntryPlan {
    /// The guest's own timer, unchanged.
    pub timer: TimerRegs,
    /// The timer interrupt is already listed for the guest (asserted), and
    /// the hardware timer would raise it at the host as well: the entry
    /// disables the physical PPI ([`VTIMER_PPI`]) for the run.
    pub silence_ppi: bool,
}

/// The interrupt state of one vCPU: its list registers, its saved virtual
/// timer, and the VM's clock offset.
pub struct GuestIrq {
    vgic: VgicCpu,
    timer: Vtimer,
    cntvoff: u64,
    backlog: u64,
}

impl GuestIrq {
    /// A vCPU with `nr_lr` list registers (`vgic::nr_lrs_from_vtr`) of a VM
    /// whose `CNTVOFF_EL2` is `cntvoff` (one value for all of its vCPUs).
    pub const fn new(nr_lr: usize, cntvoff: u64) -> GuestIrq {
        GuestIrq { vgic: VgicCpu::new(nr_lr), timer: Vtimer { ctl: 0, cval: 0 }, cntvoff, backlog: 0 }
    }

    /// Prepare an entry: raise or retract the timer's PPI against the
    /// physical count `physical_count`, list the device `lines` (and the
    /// backlog), and say what to write into `CNTV_CTL_EL0` / `CNTV_CVAL_EL0`
    /// and whether the physical PPI must be silenced for the run.
    pub fn pre_entry(&mut self, lines: u64, physical_count: u64) -> EntryPlan {
        let asserted = self.timer.asserted(virtual_count(physical_count, self.cntvoff));
        if asserted {
            // A full queue is no loss: the line is recomputed at the next entry.
            if cfg!(feature = "canary-ppi-listed-twice") {
                // Canary: a level re-pended over an interrupt the guest is handling.
                let _ = self.vgic.inject(VTIMER_PPI, GUEST_PRIO, true, None);
            } else {
                let _ = self.vgic.raise_level(VTIMER_PPI, GUEST_PRIO, true);
            }
        } else {
            self.vgic.retract_pending(VTIMER_PPI);
        }
        let old = core::mem::take(&mut self.backlog);
        self.list_lines(old);
        self.list_lines(lines & !old);
        EntryPlan {
            timer: TimerRegs { ctl: self.timer.ctl, cval: self.timer.cval },
            // Canary: the physical PPI is left enabled, so the host takes the
            // guest's timer interrupt on every entry.
            silence_ppi: asserted && !cfg!(feature = "canary-ppi-not-silenced"),
        }
    }

    /// List `lines` in ascending order; those no LR or queue slot takes go to the backlog.
    fn list_lines(&mut self, mut todo: u64) {
        while todo != 0 {
            let n = todo.trailing_zeros();
            todo &= todo - 1;
            if self.vgic.inject(line_intid(n), GUEST_PRIO, true, None) == Err(VgicError::QueueFull) {
                self.backlog |= 1 << n;
            }
        }
    }

    /// After the exit: the LRs and the timer registers as read back. The
    /// timer is the guest's own: the entry never altered it.
    pub fn after_exit(&mut self, hw_lrs: &[u64], ctl: u64, cval: u64) {
        self.vgic.absorb(hw_lrs);
        self.timer = Vtimer::from_hw(ctl, cval);
    }

    /// The physical count at which the host must wake this vCPU while it is
    /// parked on a `wfi`, if its timer can fire.
    pub fn wake_at(&self) -> Option<u64> {
        self.timer.expiry_physical_count(self.cntvoff)
    }

    /// The LRs to write into `ICH_LR<n>_EL2`.
    pub fn lrs(&self) -> &[u64] {
        self.vgic.lrs()
    }

    /// `ICH_HCR_EL2` for the entry.
    pub fn hcr(&self) -> u64 {
        self.vgic.hcr()
    }

    /// `CNTVOFF_EL2` for the entry.
    pub fn cntvoff(&self) -> u64 {
        if cfg!(feature = "canary-cntvoff-per-vcpu") {
            // Canary: an offset of this vCPU's own (its address) instead of the VM's one.
            return self.cntvoff.wrapping_add(self as *const Self as usize as u64);
        }
        self.cntvoff
    }

    /// The guest's virtual count did not run for `ticks` physical counts (the
    /// vCPU was held): move the offset ahead by them, so the count the guest
    /// reads, and the deadline of its timer against it, resume where they
    /// stopped.
    pub fn skip_time(&mut self, ticks: u64) {
        self.cntvoff = self.cntvoff.wrapping_add(ticks);
    }

    /// The guest's timer as it was last saved.
    pub fn timer(&self) -> Vtimer {
        self.timer
    }

    /// Device lines no LR or queue slot took yet.
    pub fn backlog(&self) -> u64 {
        self.backlog
    }
}

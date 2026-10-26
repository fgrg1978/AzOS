// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The virtual GICv3 CPU interface: the list-register (LR) model.
//!
//! A guest's interrupts reach it through the `ICH_LR<n>_EL2` registers: EL2
//! writes a virtual interrupt into a free LR, the CPU interface signals it to
//! the guest, and the guest's acknowledge and end-of-interrupt move the LR
//! through Pending, Active and back to Invalid without a trap. A CPU has 4 to
//! 16 LRs (`ICH_VTR_EL2.ListRegs + 1`), so more virtual interrupts than LRs
//! wait in a software queue, highest priority first, and move into LRs as
//! they free up. [`VgicCpu`] is that state for one virtual CPU, pure: the
//! run loop writes [`VgicCpu::lrs`] into `ICH_LR<n>_EL2` (and
//! [`VgicCpu::hcr`] into `ICH_HCR_EL2`) before entering the guest and hands
//! the registers read back on exit to [`VgicCpu::absorb`]. The `msr`/`mrs`
//! pairs arrive with that run loop, the model's only user.
//!
//! Merging follows the GIC: an interrupt raised again while it is Pending
//! stays one pending interrupt, and while it is Active becomes Pending and
//! Active (edge behaviour). A *level* line (the virtual timer) is the
//! caller's to follow: [`VgicCpu::raise_level`] raises it only if it is not
//! already listed, so an interrupt the guest is handling is not delivered
//! twice, and [`VgicCpu::retract_pending`] takes back one that was listed
//! and has not been taken when the line fell.

/// Most LRs a GICv3 CPU interface has.
pub const MAX_LRS: usize = 16;
/// Virtual interrupts that may wait for a free LR, per virtual CPU.
pub const QUEUE_CAP: usize = 32;
/// Highest physical INTID an LR can link (`pINTID`, bits `[41:32]`).
pub const MAX_HW_PINTID: u16 = 1023;

const LR_VINTID_MASK: u64 = 0xFFFF_FFFF;
const LR_PINTID_SHIFT: u32 = 32;
const LR_PINTID_MASK: u64 = 0x3FF;
/// `EOI` (bit 41): maintenance interrupt on the guest's EOI; software
/// interrupts only (`HW = 0`).
const LR_EOI: u64 = 1 << 41;
const LR_PRIO_SHIFT: u32 = 48;
const LR_GROUP1: u64 = 1 << 60;
const LR_HW: u64 = 1 << 61;
const LR_STATE_SHIFT: u32 = 62;

/// `ICH_HCR_EL2.En`: the virtual CPU interface is on.
pub const ICH_HCR_EN: u64 = 1 << 0;
/// `ICH_HCR_EL2.UIE`: maintenance interrupt when at most one LR is still in
/// use, so a queue that overflowed the LRs gets refilled.
pub const ICH_HCR_UIE: u64 = 1 << 1;

/// `ICH_VTR_EL2.ListRegs + 1`: the number of LRs.
pub const fn nr_lrs_from_vtr(vtr: u64) -> usize {
    ((vtr & 0x1F) + 1) as usize
}

/// State of one list register.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LrState {
    Invalid = 0,
    Pending = 1,
    Active = 2,
    PendingActive = 3,
}

/// An LR value. `hw`: the physical INTID this virtual interrupt is linked to
/// (the guest's EOI then deactivates it too); `eoi_maint`: ask for a
/// maintenance interrupt when the guest EOIs it (only without `hw`).
pub const fn lr_value(
    state: LrState,
    vintid: u32,
    prio: u8,
    group1: bool,
    hw: Option<u16>,
    eoi_maint: bool,
) -> u64 {
    let mut v = (vintid as u64) | ((prio as u64) << LR_PRIO_SHIFT) | ((state as u64) << LR_STATE_SHIFT);
    if group1 {
        v |= LR_GROUP1;
    }
    match hw {
        Some(p) => v |= LR_HW | (((p as u64) & LR_PINTID_MASK) << LR_PINTID_SHIFT),
        None => {
            if eoi_maint {
                v |= LR_EOI;
            }
        }
    }
    v
}

pub const fn lr_state(lr: u64) -> LrState {
    match (lr >> LR_STATE_SHIFT) & 0b11 {
        0 => LrState::Invalid,
        1 => LrState::Pending,
        2 => LrState::Active,
        _ => LrState::PendingActive,
    }
}

pub const fn lr_vintid(lr: u64) -> u32 {
    (lr & LR_VINTID_MASK) as u32
}

pub const fn lr_priority(lr: u64) -> u8 {
    (lr >> LR_PRIO_SHIFT) as u8
}

pub const fn lr_group1(lr: u64) -> bool {
    lr & LR_GROUP1 != 0
}

/// The linked physical INTID, if `HW` is set.
pub const fn lr_hw(lr: u64) -> Option<u16> {
    if lr & LR_HW != 0 { Some(((lr >> LR_PINTID_SHIFT) & LR_PINTID_MASK) as u16) } else { None }
}

pub const fn lr_eoi_maint(lr: u64) -> bool {
    lr & LR_HW == 0 && lr & LR_EOI != 0
}

/// Why [`VgicCpu::inject`] refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VgicError {
    /// Every LR is in use and so is the queue.
    QueueFull,
    /// A linked physical INTID above [`MAX_HW_PINTID`].
    BadPhysicalIntid,
}

/// What [`VgicCpu::inject`] did with the interrupt.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Injected {
    /// Written into this LR.
    Listed(usize),
    /// Every LR was busy: waiting in the queue (the CPU interface is asked
    /// for a maintenance interrupt, see [`VgicCpu::hcr`]).
    Queued,
    /// Already pending (or queued), or re-pended while active.
    Merged,
}

#[derive(Copy, Clone)]
struct Waiting {
    vintid: u32,
    prio: u8,
    group1: bool,
    hw: Option<u16>,
}

const NOBODY: Waiting = Waiting { vintid: 0, prio: 0, group1: false, hw: None };

/// The list registers and the overflow queue of one virtual CPU.
pub struct VgicCpu {
    nr_lr: usize,
    lr: [u64; MAX_LRS],
    queue: [Waiting; QUEUE_CAP],
    queued: usize,
}

impl VgicCpu {
    /// A CPU interface with `nr_lr` LRs (from [`nr_lrs_from_vtr`]), clamped to
    /// 1..=[`MAX_LRS`].
    pub const fn new(nr_lr: usize) -> VgicCpu {
        let n = if nr_lr < 1 { 1 } else if nr_lr > MAX_LRS { MAX_LRS } else { nr_lr };
        VgicCpu { nr_lr: n, lr: [0; MAX_LRS], queue: [NOBODY; QUEUE_CAP], queued: 0 }
    }

    /// The LRs to write into `ICH_LR<n>_EL2` before entering the guest.
    pub fn lrs(&self) -> &[u64] {
        &self.lr[..self.nr_lr]
    }

    /// Interrupts waiting for an LR.
    pub fn queued(&self) -> usize {
        self.queued
    }

    /// Bit `i` set: LR `i` is free (what `ICH_ELRSR_EL2` would read).
    pub fn elrsr(&self) -> u32 {
        let mut m = 0;
        let mut i = 0;
        while i < self.nr_lr {
            if lr_state(self.lr[i]) == LrState::Invalid {
                m |= 1 << i;
            }
            i += 1;
        }
        m
    }

    /// `ICH_HCR_EL2` for the next entry: the interface on, and an underflow
    /// maintenance interrupt while the queue is non-empty.
    pub fn hcr(&self) -> u64 {
        if self.queued > 0 { ICH_HCR_EN | ICH_HCR_UIE } else { ICH_HCR_EN }
    }

    fn find(&self, vintid: u32) -> Option<usize> {
        (0..self.nr_lr).find(|&i| lr_state(self.lr[i]) != LrState::Invalid && lr_vintid(self.lr[i]) == vintid)
    }

    /// Raise virtual interrupt `vintid` (lower `prio` is more urgent).
    pub fn inject(&mut self, vintid: u32, prio: u8, group1: bool, hw: Option<u16>) -> Result<Injected, VgicError> {
        if matches!(hw, Some(p) if p > MAX_HW_PINTID) {
            return Err(VgicError::BadPhysicalIntid);
        }
        if let Some(i) = self.find(vintid) {
            if lr_state(self.lr[i]) == LrState::Active {
                self.lr[i] |= (LrState::PendingActive as u64) << LR_STATE_SHIFT;
            }
            return Ok(Injected::Merged);
        }
        if self.queue[..self.queued].iter().any(|w| w.vintid == vintid) {
            return Ok(Injected::Merged);
        }
        let w = Waiting { vintid, prio, group1, hw };
        if let Some(i) = (0..self.nr_lr).find(|&i| lr_state(self.lr[i]) == LrState::Invalid) {
            self.lr[i] = Self::pending_lr(&w);
            return Ok(Injected::Listed(i));
        }
        if self.queued == QUEUE_CAP {
            return Err(VgicError::QueueFull);
        }
        // After every entry of equal or better priority: FIFO within a priority.
        let at = self.queue[..self.queued].iter().position(|q| q.prio > prio).unwrap_or(self.queued);
        let mut j = self.queued;
        while j > at {
            self.queue[j] = self.queue[j - 1];
            j -= 1;
        }
        self.queue[at] = w;
        self.queued += 1;
        Ok(Injected::Queued)
    }

    /// Is `vintid` listed in an LR (in any state) or waiting in the queue?
    pub fn holds(&self, vintid: u32) -> bool {
        self.find(vintid).is_some() || self.queue[..self.queued].iter().any(|w| w.vintid == vintid)
    }

    /// Raise a level-triggered interrupt: [`inject`](Self::inject) unless it
    /// is already listed or queued, in which case nothing changes (a level
    /// that is still high after the guest's EOI is raised again by the next
    /// call, which is what the line does in hardware).
    pub fn raise_level(&mut self, vintid: u32, prio: u8, group1: bool) -> Result<Injected, VgicError> {
        if self.holds(vintid) {
            return Ok(Injected::Merged);
        }
        self.inject(vintid, prio, group1, None)
    }

    /// The level line of `vintid` fell: an interrupt still waiting in the
    /// queue or Pending in an LR (the guest has not acknowledged it) is
    /// taken back, one Pending and Active returns to Active. An Active one
    /// is the guest's to finish. True if something was taken back.
    pub fn retract_pending(&mut self, vintid: u32) -> bool {
        if let Some(at) = self.queue[..self.queued].iter().position(|w| w.vintid == vintid) {
            self.queue.copy_within(at + 1..self.queued, at);
            self.queued -= 1;
            return true;
        }
        let Some(i) = self.find(vintid) else { return false };
        let to = match lr_state(self.lr[i]) {
            LrState::Pending => LrState::Invalid,
            LrState::PendingActive => LrState::Active,
            _ => return false,
        };
        self.lr[i] = (self.lr[i] & !(0b11 << LR_STATE_SHIFT)) | ((to as u64) << LR_STATE_SHIFT);
        self.refill();
        true
    }

    fn pending_lr(w: &Waiting) -> u64 {
        lr_value(LrState::Pending, w.vintid, w.prio, w.group1, w.hw, false)
    }

    /// After the guest ran: take the LRs read back from the hardware, then
    /// move queued interrupts into the LRs the guest freed.
    pub fn absorb(&mut self, hw_lrs: &[u64]) {
        let n = hw_lrs.len().min(self.nr_lr);
        self.lr[..n].copy_from_slice(&hw_lrs[..n]);
        self.refill();
    }

    /// Move queued interrupts, best first, into the free LRs.
    fn refill(&mut self) {
        let mut i = 0;
        while i < self.nr_lr && self.queued > 0 {
            if lr_state(self.lr[i]) == LrState::Invalid {
                self.lr[i] = Self::pending_lr(&self.queue[0]);
                self.queue.copy_within(1..self.queued, 0);
                self.queued -= 1;
            }
            i += 1;
        }
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What a kernel-placed controller does when the device stops answering: one
//! policy for every block, network and USB host controller driver (owner
//! decision 2026-10-23, Q8 a).
//!
//! A command (block, USB host) or a transmit ring (network) that runs out of
//! its budget makes the driver ask [`Recovery::timed_out`]:
//!
//! * **Reset**, while the device has resets left (Kconfig
//!   `DEVICE_TIMEOUT_RESETS`, default 1, counted per boot): the driver stops
//!   the device, confirms the stop (virtio status reads 0, NVMe `CSTS.RDY`
//!   drops, the AHCI HBA reset bit clears, the NIC's reset bit clears, the
//!   xHCI controller halts and its reset bit clears), ends every command the
//!   device held with a typed error (`block::HwStatus::Timeout` for the one
//!   whose budget ran out, `block::HwStatus::Reset` for the others; a NIC
//!   drops the frames in its ring; a USB host's devices are gone, their
//!   transfers end `Disconnected`, and they are enumerated again), programs
//!   the device again over the same memory and tells
//!   [`Recovery::reset_done`] whether it came back. Nothing is requeued: a
//!   started request is never recalled (`azos_drv_block::queue`), and the
//!   caller of a failed one sees an error and decides.
//! * **Latch**, once the resets are spent: the driver stops the device and
//!   latches itself dead until reboot, as every driver did at the first
//!   timeout before this policy. Its staging memory is then never reused: a
//!   device whose stop was not confirmed may still write to it.
//!
//! A stop that cannot be confirmed, a reset that does not bring the device
//! back, and a protocol violation (a completion naming no command) latch dead
//! at once ([`Recovery::latch`] for the last).
//!
//! Every reset and every latch the policy decides is reported to the kernel's
//! sink ([`set_sink`]): the `block-timeout` / `net-timeout` / `usb-timeout`
//! decision record (`azos_decision`), `action` [`Action`].
//!
//! Rejected: reset forever with a backoff (Q8 c): a device that wedges again
//! after a clean reset is failing, and a disk that keeps half-working is what
//! "no disk beats silently wrong disk" is about. Rejected: "dead means dead"
//! (Q8 b, the old behaviour): one lost interrupt or one firmware hiccup took
//! the boot disk or the only NIC away until reboot, where Linux
//! (`nvme_reset_ctrl`, `ndo_tx_timeout`) resets and carries on.

use core::sync::atomic::{AtomicU8, Ordering};

pub use crate::block::{StallClock, STALL_GAP_US};

/// Which decision record a device's events go to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
    /// `block-timeout` (virtio-blk, NVMe, AHCI).
    Block = 0,
    /// `net-timeout` (virtio-net, e1000e, igc).
    Net = 1,
    /// `usb-timeout` (xHCI).
    Usb = 2,
}

/// What the policy did; the values are the `action` field of the class's
/// decision record. `block-timeout` uses 3 and 4 for what the request layer
/// did (failed the request, took the device offline); they are not the
/// policy's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    /// The device was reset and programmed again, and is back in service.
    Reset = 2,
    /// The device timed out with its resets spent: latched dead until reboot.
    Latched = 5,
    /// The reset did not bring the device back (its stop was not confirmed,
    /// or it would not program again): latched dead until reboot.
    ResetFailed = 6,
}

/// The answer of [`Recovery::timed_out`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// This caller resets the device, then calls [`Recovery::reset_done`].
    Reset,
    /// The resets are spent: this caller latches the device dead (stops it,
    /// keeps its memory quarantined). The record is written.
    Latch,
    /// Another caller is resetting the device, or it is dead already.
    Handled,
}

azos_common::ro_hook! {
    /// Where the policy's resets and latches are reported (the kernel: the
    /// class's decision record and a console line), as `sink(class, device,
    /// action, detail, waited_ms)`: `device` is the driver's name for it (its
    /// topology row's: `virtio-blk`, `nvme`, `e1000e`, `xhci`, ...), `detail`
    /// the first sector of the command that timed out (block), the frames the
    /// ring held (network) or the TRB type of the command that went
    /// unanswered (USB host), `waited_ms` how long it waited. Called from the
    /// driver's reap or send path; it must not do I/O on the device it is
    /// told about. Unset: not reported.
    static SINK: fn(Class, &'static str, Action, u64, u64);
}

/// Register where the policy's events go (the kernel, at boot).
pub fn set_sink(f: fn(Class, &'static str, Action, u64, u64)) {
    SINK.set(f);
}

const LIVE: u8 = 0;
const RESETTING: u8 = 1;
const DEAD: u8 = 2;

/// One device's place in the policy: live, being reset, or dead for good;
/// and how many resets it has had. Lock-free; one per device, a `static` of
/// the driver.
pub struct Recovery {
    class: Class,
    /// The device's name in the record (its topology row's).
    name: &'static str,
    /// Resets allowed per boot (Kconfig `DEVICE_TIMEOUT_RESETS`).
    budget: u8,
    state: AtomicU8,
    resets: AtomicU8,
}

impl Recovery {
    /// A live device of `class`, named `name` in the record, that may be
    /// reset `budget` times.
    pub const fn new(class: Class, name: &'static str, budget: u8) -> Self {
        Recovery { class, name, budget, state: AtomicU8::new(LIVE), resets: AtomicU8::new(0) }
    }

    /// In service: commands may be started.
    pub fn live(&self) -> bool {
        self.state.load(Ordering::Acquire) == LIVE
    }

    /// Being reset: a claim waits (`Claim::Busy`), nothing is started.
    pub fn resetting(&self) -> bool {
        self.state.load(Ordering::Acquire) == RESETTING
    }

    /// Latched dead until reboot.
    pub fn dead(&self) -> bool {
        self.state.load(Ordering::Acquire) == DEAD
    }

    /// Resets done since boot.
    pub fn resets(&self) -> u8 {
        self.resets.load(Ordering::Acquire)
    }

    /// A command (or the transmit ring) ran out of its budget: `detail` and
    /// `waited_ms` go into the record. Exactly one of the callers that see
    /// the device live gets [`Verdict::Reset`] or [`Verdict::Latch`]; the
    /// others, and every caller while it is being reset or dead, get
    /// [`Verdict::Handled`].
    pub fn timed_out(&self, detail: u64, waited_ms: u64) -> Verdict {
        let spent = self.resets.load(Ordering::Acquire) >= self.budget;
        let to = if spent { DEAD } else { RESETTING };
        if self.state.compare_exchange(LIVE, to, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Verdict::Handled;
        }
        if spent {
            report(self, Action::Latched, detail, waited_ms);
            return Verdict::Latch;
        }
        self.resets.fetch_add(1, Ordering::AcqRel);
        Verdict::Reset
    }

    /// The reset [`timed_out`](Self::timed_out) handed out is over: `ok` the
    /// device is programmed again and back in service, else it is latched
    /// dead. Recorded either way.
    pub fn reset_done(&self, ok: bool, detail: u64, waited_ms: u64) {
        if self.state.compare_exchange(RESETTING, if ok { LIVE } else { DEAD }, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return;
        }
        report(self, if ok { Action::Reset } else { Action::ResetFailed }, detail, waited_ms);
    }

    /// Latch dead at once, with no reset: the device broke the protocol (a
    /// completion naming no command it was given), which a reset does not
    /// explain. `true` for the call that latched it. Not recorded here: the
    /// request layer records the device it finds dead.
    pub fn latch(&self) -> bool {
        self.state.swap(DEAD, Ordering::AcqRel) != DEAD
    }
}

fn report(r: &Recovery, action: Action, detail: u64, waited_ms: u64) {
    if let Some(f) = SINK.get() {
        f(r.class, r.name, action, detail, waited_ms);
    }
}

// ── The transmit ring's budget ──────────────────────────────────────────

/// How long a NIC's transmit ring may hold frames without the device taking
/// any (`net-timeout`): the moment it last made progress, measured in time
/// the guest ran ([`StallClock`]), as a block command's budget is.
///
/// Kept under the driver's transmit lock: [`published`](Self::published)
/// after a frame is put on the ring, [`reclaimed`](Self::reclaimed) after
/// the completed ones are taken back, [`expired`](Self::expired) when a send
/// or the network poller looks (`NetDevice::tx_watch`). A ring that empties
/// stops the clock; one that keeps moving restarts it at every reclaim that
/// freed something.
///
/// The stall clock credits every gap between two looks longer than
/// [`STALL_GAP_US`] as time the guest did not run, so a ring that holds
/// frames must be looked at more often than that: a send alone is not enough
/// (a DHCP or TCP retry comes seconds apart, and every such gap would be
/// credited, so the ring never ran out of its budget). While
/// [`running`](Self::running), the poller looks every [`TX_LOOK_US`].
#[derive(Clone, Copy, Debug, Default)]
pub struct TxWatch {
    /// Tick of the last progress while frames were outstanding; 0: none
    /// outstanding.
    since: u64,
    /// The stall credit at `since`.
    credit: u64,
}

impl TxWatch {
    pub const fn new() -> Self {
        TxWatch { since: 0, credit: 0 }
    }

    /// A frame was put on the ring at tick `now` (`credit`: the stall
    /// clock's credit). Starts the clock on an idle ring.
    pub fn published(&mut self, now: u64, credit: u64) {
        if self.since == 0 {
            self.since = now.max(1);
            self.credit = credit;
        }
    }

    /// The reclaim at `now` freed `freed` frames and left `outstanding`.
    pub fn reclaimed(&mut self, now: u64, credit: u64, freed: usize, outstanding: usize) {
        if outstanding == 0 {
            self.since = 0;
        } else if freed != 0 {
            self.since = now.max(1);
            self.credit = credit;
        }
    }

    /// Has the ring held frames with no progress for `budget_ticks` at
    /// `now`? Call `stall.observe(now, ..)` first.
    pub fn expired(&self, stall: &StallClock, now: u64, budget_ticks: u64) -> bool {
        self.since != 0 && stall.expired(now, self.since.saturating_add(budget_ticks), self.credit)
    }

    /// Ticks since the last progress (0: idle), for the record.
    pub fn waited(&self, now: u64) -> u64 {
        if self.since == 0 { 0 } else { now.saturating_sub(self.since) }
    }

    /// The ring was emptied by a reset.
    pub fn clear(&mut self) {
        self.since = 0;
    }

    /// Frames are outstanding: the clock runs, and the ring must be looked at
    /// within [`TX_LOOK_US`].
    pub fn running(&self) -> bool {
        self.since != 0
    }
}

/// How often the network poller looks at a transmit ring whose
/// [`TxWatch`] runs: well inside [`STALL_GAP_US`], so a gap the stall clock
/// credits is one the guest really did not run.
pub const TX_LOOK_US: u64 = STALL_GAP_US / 2;

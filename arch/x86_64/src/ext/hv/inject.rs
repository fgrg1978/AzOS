// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Event injection: how an interrupt, an NMI or an exception gets into a
//! guest on the next `VMRUN` (AMD APM vol. 2, 15.20).
//!
//! `EVENT_INJ` holds one event: the vector, its type, whether an error code
//! goes with it, and the valid bit; the hardware clears the valid bit when
//! the guest has taken it. An interrupt may be injected only when the guest
//! can take it: `RFLAGS.IF` set, no interrupt shadow (`sti`, `mov ss`), and
//! nothing else queued. When it cannot, the monitor asks for the *interrupt
//! window*: `V_IRQ` plus the `VINTR` intercept make the guest exit at the first
//! instruction boundary where it can, and the monitor injects then.
//!
//! An exit that happens while an event is being delivered (a nested page
//! fault pushing the interrupt frame) leaves that event in `EXIT_INT_INFO`;
//! [`Vmcb::requeue_exit_event`] puts it back in `EVENT_INJ` so the guest does
//! not lose it.

use super::svm::{ctl, icpt, off, Vmcb};

/// `RFLAGS.IF`.
pub const RFLAGS_IF: u64 = 1 << 9;
/// `EXIT_INT_INFO` bit 31: the event field is valid.
pub const EXITINTINFO_VALID: u32 = 1 << 31;
/// `V_INTR_PRIO` field of `INT_CTL` (bits 19:16), the priority the window
/// interrupt claims: all ones, above any `TPR`.
const V_INTR_PRIO_MAX: u32 = 0xF << 16;

/// Exception vectors the monitor injects.
pub mod vector {
    /// Undefined opcode.
    pub const UD: u8 = 6;
    /// General protection (error code 0).
    pub const GP: u8 = 13;
}

impl Vmcb {
    /// Is an event waiting in `EVENT_INJ` for the next entry?
    pub fn event_queued(&self) -> bool {
        self.rd32(off::EVENT_INJ) & ctl::EVENT_VALID != 0
    }

    /// Can the guest take an external interrupt at its next instruction:
    /// interrupts enabled, no interrupt shadow, no event already queued.
    pub fn can_take_interrupt(&self) -> bool {
        self.rd64(off::RFLAGS) & RFLAGS_IF != 0 && self.rd32(off::INT_STATE) & ctl::INT_SHADOW == 0 && !self.event_queued()
    }

    /// Queue an external interrupt with `vector` (the caller checked
    /// [`Vmcb::can_take_interrupt`] and moves the vector from requested to
    /// in-service in its APIC).
    pub fn inject_interrupt(&mut self, vector: u8) {
        self.wr32(off::EVENT_INJ, ctl::EVENT_VALID | ctl::EVENT_INTR | vector as u32);
    }

    /// Queue an NMI.
    pub fn inject_nmi(&mut self) {
        self.wr32(off::EVENT_INJ, ctl::EVENT_VALID | ctl::EVENT_NMI | 2);
    }

    /// Is the guest in the shadow of `sti` / `mov ss`?
    pub fn in_shadow(&self) -> bool {
        self.rd32(off::INT_STATE) & ctl::INT_SHADOW != 0
    }

    /// Exit at the guest's next `IRET`: how the end of an NMI handler is
    /// seen (SVM has no bit for "NMIs are blocked"; the CPU's own blocking
    /// ends at the `IRET` the intercept stops before).
    pub fn set_iret_intercept(&mut self, on: bool) {
        let w = self.rd32(off::INTERCEPT_W3);
        self.wr32(off::INTERCEPT_W3, if on { w | icpt::IRET } else { w & !icpt::IRET });
    }

    /// Queue a hardware exception, with its error code if it has one.
    pub fn inject_exception(&mut self, vector: u8, error: Option<u32>) {
        let mut w = ctl::EVENT_VALID | ctl::EVENT_EXCEPTION | vector as u32;
        if let Some(e) = error {
            w |= ctl::EVENT_ERR;
            self.wr32(off::EVENT_INJ_ERR, e);
        }
        self.wr32(off::EVENT_INJ, w);
    }

    /// Ask for the interrupt window: the guest exits (`VINTR`) as soon as it
    /// can take an interrupt.
    pub fn request_window(&mut self) {
        self.or32(off::INT_CTL, ctl::V_IRQ | ctl::V_IGN_TPR | V_INTR_PRIO_MAX);
        self.or32(off::INTERCEPT_W3, icpt::VINTR);
    }

    /// Withdraw the window request.
    pub fn clear_window(&mut self) {
        let c = self.rd32(off::INT_CTL) & !(ctl::V_IRQ | ctl::V_IGN_TPR | V_INTR_PRIO_MAX);
        self.wr32(off::INT_CTL, c);
        self.wr32(off::INTERCEPT_W3, self.rd32(off::INTERCEPT_W3) & !icpt::VINTR);
    }

    /// Is the window requested?
    pub fn window_requested(&self) -> bool {
        self.rd32(off::INT_CTL) & ctl::V_IRQ != 0
    }

    /// After an exit: the event the guest was in the middle of taking, if
    /// any, is queued to be injected again (and the record cleared, so the
    /// next exit does not repeat it). `true` when one was.
    pub fn requeue_exit_event(&mut self) -> bool {
        let info = self.rd32(off::EXIT_INT_INFO);
        if info & EXITINTINFO_VALID == 0 {
            return false;
        }
        let err = self.rd32(off::EXIT_INT_INFO_ERR);
        self.wr32(off::EXIT_INT_INFO, 0);
        self.wr32(off::EVENT_INJ, info);
        self.wr32(off::EVENT_INJ_ERR, err);
        true
    }
}

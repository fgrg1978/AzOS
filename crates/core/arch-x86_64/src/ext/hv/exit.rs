// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! One decode of "why did the guest stop".
//!
//! An SVM `#VMEXIT` gives an exit code and two information words. The
//! monitor's loop switches on [`Exit`]. The decode is pure: [`svm`] takes the
//! raw words.

use super::svm::code;

/// How a memory access that faulted in the nested page tables
/// looked.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct NestedFault {
    /// The guest-physical address.
    pub gpa: u64,
    /// The access was a write.
    pub write: bool,
    /// The access was an instruction fetch.
    pub exec: bool,
    /// The page was present (a permission fault), not absent.
    pub present: bool,
    /// The fault was on the final guest-physical address, not on the
    /// translation of one of the guest's own page-table pages.
    pub final_translation: bool,
}

/// An I/O instruction.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct IoAccess {
    pub port: u16,
    /// `out`/`outs` (the guest writes the device).
    pub write: bool,
    /// Access size in bytes: 1, 2 or 4.
    pub size: u8,
    /// `ins`/`outs`.
    pub string: bool,
    /// `rep` prefix.
    pub rep: bool,
    /// RIP after the instruction (`EXITINFO2`).
    pub next_rip: u64,
}

/// Why the guest stopped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Exit {
    /// A nested page fault: the monitor maps the page, emulates a
    /// device, or kills the guest.
    NestedFault(NestedFault),
    /// IN/OUT/INS/OUTS on a port the permission map intercepts.
    Io(IoAccess),
    /// CPUID.
    Cpuid,
    /// RDMSR (`write: false`) or WRMSR.
    Msr { write: bool },
    /// HLT.
    Halt,
    /// XSETBV (`XCR0` is the guest's, not the host's).
    Xsetbv,
    /// The interrupt window: the guest can take the virtual interrupt that
    /// asked for it (`INT_CTL.V_IRQ`).
    IntWindow,
    /// A physical interrupt arrived while the guest ran: the host takes it as
    /// soon as it re-enables interrupts, then re-enters.
    Interrupt,
    /// NMI.
    Nmi,
    /// The hypercall instruction (VMMCALL).
    Hypercall,
    /// Triple fault.
    Shutdown,
    /// Entry failed: the control block failed the hardware's consistency
    /// checks (SVM `VMEXIT_INVALID`).
    InvalidState,
    /// Anything else: the raw exit code / basic reason.
    Other(u64),
}

/// Decode an SVM `#VMEXIT` from `EXITCODE`, `EXITINFO1`, `EXITINFO2`.
pub fn svm(exit_code: u64, info1: u64, info2: u64) -> Exit {
    match exit_code {
        code::NPF => Exit::NestedFault(NestedFault {
            gpa: info2,
            present: info1 & 1 != 0,
            write: info1 & (1 << 1) != 0,
            exec: info1 & (1 << 4) != 0,
            final_translation: info1 & (1 << 32) != 0,
        }),
        code::IOIO => Exit::Io(IoAccess {
            port: (info1 >> 16) as u16,
            write: info1 & 1 == 0,
            size: if info1 & (1 << 4) != 0 {
                1
            } else if info1 & (1 << 5) != 0 {
                2
            } else {
                4
            },
            string: info1 & (1 << 2) != 0,
            rep: info1 & (1 << 3) != 0,
            next_rip: info2,
        }),
        code::CPUID => Exit::Cpuid,
        code::MSR => Exit::Msr { write: info1 & 1 != 0 },
        code::HLT => Exit::Halt,
        code::XSETBV => Exit::Xsetbv,
        code::VINTR => Exit::IntWindow,
        code::INTR => Exit::Interrupt,
        code::NMI => Exit::Nmi,
        code::VMMCALL => Exit::Hypercall,
        code::SHUTDOWN => Exit::Shutdown,
        code::INVALID => Exit::InvalidState,
        other => Exit::Other(other),
    }
}

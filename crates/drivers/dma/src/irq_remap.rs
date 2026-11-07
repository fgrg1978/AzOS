// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Whether the interrupts a device sends are confined as its memory is.
//!
//! An IOMMU domain confines what a function reads and writes. On x86_64 a
//! message-signalled interrupt is such a write, to the LAPIC's window, and
//! without interrupt remapping the unit lets it through untouched: the data
//! word picks the vector and the delivery mode, so a driver of a function it
//! controls can send INIT or NMI, raise any kernel vector, or raise an
//! exception vector. Only a remapping table of the kernel's confines that.

/// How the platform treats the interrupts a PCI function sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptRemapping {
    /// A translated function cannot reach the interrupt controller (its
    /// doorbell is not in the domain), so its memory confinement is enough.
    NotNeeded,
    /// The firmware names no interrupt remapping.
    Absent,
    /// The hardware has it and nothing turns it on.
    PresentOff,
    /// Enabled: every message interrupt goes through a table the kernel owns.
    On,
}

impl InterruptRemapping {
    /// Do the interrupts of a function whose memory an IOMMU confines stay
    /// confined too.
    pub const fn confines_interrupts(self) -> bool {
        matches!(self, InterruptRemapping::NotNeeded | InterruptRemapping::On) || cfg!(feature = "ir-assumed-canary")
    }
}

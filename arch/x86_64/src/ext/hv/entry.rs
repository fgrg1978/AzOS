// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The state a guest vCPU starts in.
//!
//! * The **boot CPU** starts the way the PVH boot protocol says (Xen's
//!   PVH document, `pvh.pandoc`; `boot.S` is written to it): 32-bit protected
//!   mode, paging off, flat 4 GiB code and data segments, interrupts off,
//!   `EBX` = the physical address of the `hvm_start_info`, `EIP` = the entry
//!   the ELF note names. The guest builds its own GDT, page tables and long
//!   mode from there.
//! * An **application processor** is not started at all: it waits (`Power`)
//!   until the boot CPU sends INIT and a startup IPI through the vLAPIC. INIT
//!   puts it in the wait-for-SIPI state, the first SIPI starts it in real mode
//!   at `vector << 12` (CS selector `vector << 8`, `IP` 0), as the hardware
//!   does, and the second one, which the guest's startup sequence sends
//!   anyway, finds it running and does nothing.
//!
//! The encoders only write VMCB fields and general registers; nested paging,
//! the permission maps and the ASID are the caller's, as for
//! [`Vmcb::init_real_mode`].

use super::svm::{efer, off, GuestRegs, Vmcb, ATTR_TSS_BUSY};

/// Attributes of a 32-bit flat code segment: present, readable, accessed,
/// `D/B` and granularity set (descriptor access byte `0x9B`, flags `0xC`).
pub const ATTR_CODE32: u16 = 0xC9B;
/// Attributes of a 32-bit flat data segment: present, writable, accessed,
/// `D/B` and granularity set (access byte `0x93`, flags `0xC`).
pub const ATTR_DATA32: u16 = 0xC93;
/// Limit of a flat 32-bit segment: 4 GiB.
pub const FLAT_LIMIT: u32 = 0xFFFF_FFFF;
/// Limit of the 32-bit TSS the PVH protocol names.
pub const TSS_LIMIT: u32 = 0x67;
/// The selectors the entry state carries; no GDT backs them, the guest
/// reloads every one after `lgdt`.
pub const SEL_CODE: u16 = 0x10;
pub const SEL_DATA: u16 = 0x18;
pub const SEL_TSS: u16 = 0x20;

/// `CR0.PE | CR0.ET`: protected mode on, paging off, caches on.
pub const CR0_PVH: u64 = 1 << 0 | 1 << 4;

/// A PVH entry the 32-bit protocol cannot express.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BadEntry;

impl Vmcb {
    /// The PVH boot CPU: 32-bit protected mode at `entry`, `EBX` =
    /// `start_info` (written to `regs`, which is cleared), the rest of the
    /// registers zero. `asid` as for [`Vmcb::init_real_mode`].
    ///
    /// `entry` and `start_info` are 32-bit physical addresses: the protocol
    /// has no more bits, and a 64-bit value that does not fit is refused.
    pub fn init_pvh(&mut self, regs: &mut GuestRegs, entry: u64, start_info: u64, asid: u32) -> Result<(), BadEntry> {
        let (Ok(entry), Ok(start_info)) = (u32::try_from(entry), u32::try_from(start_info)) else {
            return Err(BadEntry);
        };
        self.init_real_mode(0, asid);
        self.set_segment(off::CS, SEL_CODE, ATTR_CODE32, FLAT_LIMIT, 0);
        for seg in [off::DS, off::ES, off::SS, off::FS, off::GS] {
            self.set_segment(seg, SEL_DATA, ATTR_DATA32, FLAT_LIMIT, 0);
        }
        self.set_segment(off::TR, SEL_TSS, ATTR_TSS_BUSY, TSS_LIMIT, 0);
        self.wr64(off::CR0, CR0_PVH);
        self.wr64(off::RIP, entry as u64);
        self.wr64(off::EFER, efer::SVME);
        *regs = GuestRegs { rbx: start_info as u64, ..GuestRegs::default() };
        Ok(())
    }

    /// An application processor started by a startup IPI with `vector`:
    /// 16-bit real mode, `CS` = `vector << 8` with base `vector << 12`, `IP`
    /// 0, interrupts off, paging off. The CPU's reset also leaves `EDX` with
    /// its signature (`CPUID.1:EAX`), which `signature` is.
    pub fn init_startup(&mut self, regs: &mut GuestRegs, vector: u8, asid: u32, signature: u32) {
        self.init_real_mode(0, asid);
        self.set_segment(off::CS, (vector as u16) << 8, super::svm::ATTR_REAL_CODE, 0xFFFF, (vector as u64) << 12);
        *regs = GuestRegs { rdx: signature as u64, ..GuestRegs::default() };
    }
}

/// Whether a vCPU runs, and what a startup event does to it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Power {
    /// Runs (the boot CPU from its first entry, an AP after its SIPI).
    Running,
    /// Never started, or after INIT: waits for a startup IPI. The vCPU does
    /// not enter the guest.
    WaitSipi,
}

/// What the start sequence asks the monitor to do with the vCPU.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Start {
    /// Nothing.
    Nothing,
    /// INIT: reset the vCPU's state (and its APIC's) and wait for a SIPI.
    Reset,
    /// A startup IPI reached a vCPU that waited for it: start it at this
    /// vector.
    Run(u8),
}

impl Power {
    /// An INIT IPI: whatever the vCPU was doing, it now waits for a SIPI.
    pub fn init(&mut self) -> Start {
        *self = Power::WaitSipi;
        Start::Reset
    }

    /// A startup IPI: starts a vCPU that waits for one, and is ignored by one
    /// that runs.
    pub fn sipi(&mut self, vector: u8) -> Start {
        match *self {
            Power::WaitSipi => {
                *self = Power::Running;
                Start::Run(vector)
            }
            Power::Running => Start::Nothing,
        }
    }
}

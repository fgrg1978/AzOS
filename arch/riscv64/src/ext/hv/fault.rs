// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Decode of a VM exit: why the guest stopped running.
//!
//! The trap lands in HS-mode with `scause` and the trap value registers
//! `stval`, `htval`, `htinst`, `hstatus` as [`super::enter::GuestFrame`]
//! captured them. A guest page fault (cause 20, 21, 23) is an access the
//! G-stage refused: the faulting guest-physical address is `htval << 2` with
//! its low two bits from `stval` (the same rule Linux KVM applies), and
//! `htinst` hands the monitor the faulting load/store already decoded, which
//! is what MMIO emulation runs on without fetching the guest's instruction.

use super::csr::{self, SCAUSE_INTERRUPT};
use super::gstage::Access;

/// A load, store or atomic that faulted, from a transformed `htinst`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemOp {
    pub kind: MemKind,
    /// Access width in bytes.
    pub width: u8,
    /// A load sign-extends (`lb`/`lh`/`lw`; `ld` and the unsigned loads do not).
    pub signed: bool,
    /// Floating-point load/store: `rd`/`rs2` index the f registers.
    pub fp: bool,
    /// Destination register (loads and atomics).
    pub rd: u8,
    /// Source register (stores and atomics).
    pub rs2: u8,
    /// Bytes of the original instruction (2 compressed, 4): how far to
    /// advance the guest PC once the access is emulated.
    pub insn_len: u8,
    /// Offset of the faulting address from the base register's value, for
    /// an access that straddles pages.
    pub addr_offset: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemKind {
    Load,
    Store,
    Atomic,
}

/// What `htinst` says about the faulting instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultInsn {
    /// `htinst` is 0: the hardware gave nothing; fetch the instruction.
    NoInfo,
    /// A decoded load, store or atomic.
    Mem(MemOp),
    /// The access was the VS-stage page walk's own read, or its A/D update
    /// (`write`): the guest's page table sits in unmapped guest memory.
    Implicit { write: bool },
    /// A transformed instruction this decoder does not classify.
    Other(u64),
}

/// A refused guest access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestFault {
    pub access: Access,
    pub gpa: u64,
    /// The guest virtual address, when the hardware recorded one
    /// (`hstatus.GVA`).
    pub gva: Option<u64>,
    pub insn: FaultInsn,
}

/// Why the guest stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// A host interrupt arrived while the guest ran; `code` is the interrupt
    /// number. Re-enable interrupts and let the normal trap path take it.
    Interrupt(u64),
    /// `ecall` from the guest kernel (VS-mode): an SBI call to emulate.
    VsEcall,
    /// A G-stage fault.
    GuestPageFault(GuestFault),
    /// The guest executed an instruction the hypervisor traps (`wfi` under
    /// `VTW`, `sfence.vma` under `VTVM`, a CSR it may not touch); `stval`
    /// holds the instruction bits.
    VirtualInstruction { insn: u64 },
    /// Any other exception (code).
    Exception(u64),
}

/// The guest-physical address of a guest page fault.
pub const fn fault_gpa(htval: u64, stval: u64) -> u64 {
    (htval << 2) | (stval & 3)
}

/// Decode `htinst`.
pub const fn decode_htinst(htinst: u64) -> FaultInsn {
    if htinst == 0 {
        return FaultInsn::NoInfo;
    }
    if htinst & 1 == 0 {
        // A pseudoinstruction: the VS-stage walk's implicit load (0x2000
        // for 4 bytes, 0x3000 for 8) or store (bit 5 set).
        return match htinst {
            0x2000 | 0x3000 => FaultInsn::Implicit { write: false },
            0x2020 | 0x3020 => FaultInsn::Implicit { write: true },
            _ => FaultInsn::Other(htinst),
        };
    }
    // A transformed instruction. Bit 0 is set so a transformed instruction is
    // never 0; bit 1 is set when the original was 32-bit and clear when it
    // was compressed. Decoded with bits 1:0 forced to 0b11.
    let insn = htinst | 3;
    let insn_len = if htinst & 2 != 0 { 4 } else { 2 };
    let funct3 = (insn >> 12) & 7;
    let rd = ((insn >> 7) & 0x1F) as u8;
    let rs2 = ((insn >> 20) & 0x1F) as u8;
    let addr_offset = ((insn >> 15) & 0x1F) as u8;
    let (kind, fp, width, signed) = match insn & 0x7F {
        0x03 => (MemKind::Load, false, 1u8 << (funct3 & 3), funct3 & 4 == 0),
        0x07 => (MemKind::Load, true, 1u8 << (funct3 & 3), false),
        0x23 => (MemKind::Store, false, 1u8 << (funct3 & 3), false),
        0x27 => (MemKind::Store, true, 1u8 << (funct3 & 3), false),
        0x2F => (MemKind::Atomic, false, 1u8 << (funct3 & 3), false),
        _ => return FaultInsn::Other(htinst),
    };
    FaultInsn::Mem(MemOp { kind, width, signed, fp, rd, rs2, insn_len, addr_offset })
}

/// Classify a trap into HS-mode taken while a guest was running.
pub const fn decode(scause: u64, stval: u64, htval: u64, htinst: u64, hstatus: u64) -> Exit {
    if scause & SCAUSE_INTERRUPT != 0 {
        return Exit::Interrupt(scause & !SCAUSE_INTERRUPT);
    }
    let access = match scause {
        csr::EXC_INST_GUEST_PAGE_FAULT => Access::Fetch,
        csr::EXC_LOAD_GUEST_PAGE_FAULT => Access::Load,
        csr::EXC_STORE_GUEST_PAGE_FAULT => Access::Store,
        csr::EXC_ECALL_VS => return Exit::VsEcall,
        csr::EXC_VIRTUAL_INSTRUCTION => return Exit::VirtualInstruction { insn: stval },
        other => return Exit::Exception(other),
    };
    Exit::GuestPageFault(GuestFault {
        access,
        gpa: fault_gpa(htval, stval),
        gva: if hstatus & csr::HSTATUS_GVA != 0 { Some(stval) } else { None },
        insn: decode_htinst(htinst),
    })
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! H-extension CSR addresses and bit fields (RISC-V privileged spec 1.12,
//! chapter "Hypervisor Extension"), RV64 layouts.
//!
//! CSRs are touched by number (`csrr {t}, {addr}` with a `const` operand),
//! not by mnemonic: the assembler only knows `hstatus` and friends when the
//! target feature `h` is on, which this build's flags do not enable (the same
//! reason `cpu.rs` writes `stimecmp` as 0x14d).

// ── HS-level hypervisor CSRs ────────────────────────────────────────────
pub const HSTATUS: u16 = 0x600;
pub const HEDELEG: u16 = 0x602;
pub const HIDELEG: u16 = 0x603;
pub const HIE: u16 = 0x604;
pub const HTIMEDELTA: u16 = 0x605;
pub const HCOUNTEREN: u16 = 0x606;
pub const HGEIE: u16 = 0x607;
pub const HENVCFG: u16 = 0x60A;
/// Smstateen: the state a VS-mode guest may touch (`hstateen0`).
pub const HSTATEEN0: u16 = 0x60C;
pub const HTVAL: u16 = 0x643;
pub const HIP: u16 = 0x644;
pub const HVIP: u16 = 0x645;
pub const HTINST: u16 = 0x64A;
pub const HGATP: u16 = 0x680;
pub const HGEIP: u16 = 0xE12;

// ── VS-level CSRs: the guest's supervisor registers, as the host sees them ─
pub const VSSTATUS: u16 = 0x200;
pub const VSIE: u16 = 0x204;
pub const VSTVEC: u16 = 0x205;
pub const VSSCRATCH: u16 = 0x240;
pub const VSEPC: u16 = 0x241;
pub const VSCAUSE: u16 = 0x242;
pub const VSTVAL: u16 = 0x243;
pub const VSIP: u16 = 0x244;
// AIA (Ssaia): what the guest's `siselect`, `sireg` and `stopei` are while V=1. From HS
// they reach the guest interrupt file `hstatus.VGEIN` selects.
pub const VSISELECT: u16 = 0x250;
pub const VSIREG: u16 = 0x251;
/// Sstc: the guest's timer compare (`stimecmp` when V=1 maps here).
pub const VSTIMECMP: u16 = 0x24D;
pub const VSATP: u16 = 0x280;

// ── S-level CSRs the H extension does not bank ──────────────────────────
// A VS-mode guest reads and writes the hart's real `scounteren` and
// `senvcfg` (there is no `vs` copy), so the monitor swaps them per vCPU.
pub const SCOUNTEREN: u16 = 0x106;
pub const SENVCFG: u16 = 0x10A;

// ── hstatus ─────────────────────────────────────────────────────────────
/// Guest virtual address: `stval` holds a guest virtual address (set by a trap into HS).
pub const HSTATUS_GVA: u64 = 1 << 6;
/// Previous virtualization mode: 1 = the trap came from a guest, and `sret`
/// returns to one (with `sstatus.SPP` the guest privilege: 1 VS, 0 VU).
pub const HSTATUS_SPV: u64 = 1 << 7;
/// Effective privilege of a hypervisor-initiated virtual-machine load/store.
pub const HSTATUS_SPVP: u64 = 1 << 8;
/// AIA: which guest interrupt file backs the guest's `siselect`/`sireg`/`stopei`
/// and feeds `hip.VSEIP` (0: none). Bits 17:12; up to GEILEN (at most 63).
pub const HSTATUS_VGEIN_SHIFT: u32 = 12;
pub const HSTATUS_VGEIN: u64 = 0x3F << HSTATUS_VGEIN_SHIFT;
/// HLV/HSV allowed from U-mode.
pub const HSTATUS_HU: u64 = 1 << 9;
/// Trap guest `sfence.vma`/`satp` access (VTVM), `wfi` (VTW), `sret` (VTSR).
pub const HSTATUS_VTVM: u64 = 1 << 20;
pub const HSTATUS_VTW: u64 = 1 << 21;
pub const HSTATUS_VTSR: u64 = 1 << 22;

// ── hgatp (RV64) ────────────────────────────────────────────────────────
pub const HGATP_MODE_SHIFT: u32 = 60;
pub const HGATP_MODE_BARE: u64 = 0;
pub const HGATP_MODE_SV39X4: u64 = 8;
pub const HGATP_MODE_SV48X4: u64 = 9;
pub const HGATP_VMID_SHIFT: u32 = 44;
/// VMID is 14 bits on RV64; an implementation may keep fewer.
pub const HGATP_VMID_MASK: u64 = 0x3FFF << HGATP_VMID_SHIFT;
pub const HGATP_PPN_MASK: u64 = (1 << 44) - 1;

// ── hvip / hip / hie: the VS-level interrupt bits ───────────────────────
pub const VSSIP: u64 = 1 << 2;
pub const VSTIP: u64 = 1 << 6;
pub const VSEIP: u64 = 1 << 10;
/// Supervisor guest external (hip/hie only; not injectable).
pub const SGEIP: u64 = 1 << 12;

// ── hstateen0 (Smstateen) ───────────────────────────────────────────────
// A bit clear makes the guest's access to that state a virtual-instruction
// exception. The numbers are the Smstateen / AIA tables.
/// The guest may use `senvcfg`.
pub const HSTATEEN0_ENVCFG: u64 = 1 << 62;
/// The guest may use the IMSIC's `stopei` and the interrupt file registers.
pub const HSTATEEN0_IMSIC: u64 = 1 << 58;
/// The guest may use the other AIA state (`stopi`, `siph`, ...).
pub const HSTATEEN0_AIA: u64 = 1 << 59;
/// The guest may use `siselect` and `sireg` (indirect CSR access).
pub const HSTATEEN0_ISEL: u64 = 1 << 60;

// ── henvcfg ─────────────────────────────────────────────────────────────
/// Sstc enable for the guest: `vstimecmp` is live and `hip.VSTIP` follows it.
pub const HENVCFG_STCE: u64 = 1 << 63;

// ── hcounteren ──────────────────────────────────────────────────────────
/// The guest may read `time`.
pub const HCOUNTEREN_TM: u64 = 1 << 1;

// ── scause ──────────────────────────────────────────────────────────────
pub const SCAUSE_INTERRUPT: u64 = 1 << 63;
pub const EXC_INST_MISALIGNED: u64 = 0;
pub const EXC_BREAKPOINT: u64 = 3;
pub const EXC_ECALL_VU: u64 = 8;
pub const EXC_ECALL_VS: u64 = 10;
pub const EXC_INST_PAGE_FAULT: u64 = 12;
pub const EXC_LOAD_PAGE_FAULT: u64 = 13;
pub const EXC_STORE_PAGE_FAULT: u64 = 15;
pub const EXC_INST_GUEST_PAGE_FAULT: u64 = 20;
pub const EXC_LOAD_GUEST_PAGE_FAULT: u64 = 21;
pub const EXC_VIRTUAL_INSTRUCTION: u64 = 22;
pub const EXC_STORE_GUEST_PAGE_FAULT: u64 = 23;

/// Exceptions a guest OS handles itself, delegated from HS to VS through
/// `hedeleg`: the set Linux KVM delegates (misaligned fetch, breakpoint, a
/// user ecall, the three VS-stage page faults). The guest page faults (20,
/// 21, 23), the VS ecall (10) and the virtual-instruction exception (22) are
/// not delegatable: they are the exits the monitor exists to see.
pub const HEDELEG_GUEST: u64 = (1 << EXC_INST_MISALIGNED)
    | (1 << EXC_BREAKPOINT)
    | (1 << EXC_ECALL_VU)
    | (1 << EXC_INST_PAGE_FAULT)
    | (1 << EXC_LOAD_PAGE_FAULT)
    | (1 << EXC_STORE_PAGE_FAULT);

/// The three VS interrupts go straight to the guest.
pub const HIDELEG_GUEST: u64 = VSSIP | VSTIP | VSEIP;

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Arm SMMUv3 register offsets, entry layouts and command and event records:
//! the part of the unit that is numbers. No dependency, so the kernel's driver
//! (`smmuv3.rs`) and the resident monitor, which drives the unit itself on a
//! split image, include the same file.

// ---- registers ----
pub const REG_IDR0: usize = 0x00;
pub const REG_IDR1: usize = 0x04;
pub const REG_IDR5: usize = 0x14;
pub const REG_CR0: usize = 0x20;
pub const REG_CR0ACK: usize = 0x24;
pub const REG_CR1: usize = 0x28;
pub const REG_CR2: usize = 0x2c;
pub const REG_IRQ_CTRL: usize = 0x50;
pub const REG_STRTAB_BASE: usize = 0x80;
pub const REG_STRTAB_BASE_CFG: usize = 0x88;
pub const REG_CMDQ_BASE: usize = 0x90;
pub const REG_CMDQ_PROD: usize = 0x98;
pub const REG_CMDQ_CONS: usize = 0x9c;
pub const REG_EVTQ_BASE: usize = 0xa0;
/// The event queue's index registers are in register page 1.
pub const REG_EVTQ_PROD: usize = 0x100a8;
pub const REG_EVTQ_CONS: usize = 0x100ac;

pub const CR0_SMMUEN: u32 = 1 << 0;
pub const CR0_EVTQEN: u32 = 1 << 2;
pub const CR0_CMDQEN: u32 = 1 << 3;
pub const CR1: u32 = (3 << 10) | (1 << 8) | (1 << 6) | (3 << 4) | (1 << 2) | 1; // WB, inner shareable
pub const CR2_PTM: u32 = 1 << 2;
pub const CR2_RECINVSID: u32 = 1 << 1;

pub const IDR0_S1P: u32 = 1 << 1;
pub const IDR0_TTF_AARCH64: u32 = 2 << 2;
pub const IDR0_TTF_MASK: u32 = 3 << 2;
pub const IDR1_TABLES_PRESET: u32 = 1 << 30;
pub const IDR1_QUEUES_PRESET: u32 = 1 << 29;

// ---- STE ----
pub const STE_DWORDS: usize = 8;
pub const STE_BYTES: u64 = 64;
pub const STE_V: u64 = 1 << 0;
pub const STE_CFG_ABORT: u64 = 0;
pub const STE_CFG_BYPASS: u64 = 4;
pub const STE_CFG_S1_TRANS: u64 = 5;
pub const STE_CFG_SHIFT: u32 = 1;
pub const STE_CTXPTR_MASK: u64 = 0x000f_ffff_ffff_ffc0; // bits 51:6
pub const STE1_S1DSS_SSID0: u64 = 2;
pub const STE1_S1CIR_WB: u64 = 1 << 2;
pub const STE1_S1COR_WB: u64 = 1 << 4;
pub const STE1_S1CSH_ISH: u64 = 3 << 6;
pub const STE1_SHCFG_INCOMING: u64 = 1 << 44;

// ---- CD ----
pub const CD_DWORDS: usize = 8;
pub const CD_BYTES: u64 = 64;
pub const CD_IRGN0_WB: u64 = 1 << 8;
pub const CD_ORGN0_WB: u64 = 1 << 10;
pub const CD_SH0_ISH: u64 = 3 << 12;
pub const CD_EPD1: u64 = 1 << 30;
pub const CD_V: u64 = 1 << 31;
pub const CD_AA64: u64 = 1 << 41;
pub const CD_R: u64 = 1 << 45;
pub const CD_A: u64 = 1 << 46;
pub const CD_ASET: u64 = 1 << 47;
pub const CD_TTB0_MASK: u64 = 0x000f_ffff_ffff_fff0; // bits 51:4
/// MAIR attribute 0: Normal memory, inner and outer write-back (the index
/// every leaf in `pgtable` uses).
pub const MAIR_ATTR0_NORMAL_WB: u64 = 0xff;

/// A Context Descriptor for a stage 1 table of `levels` levels at `root_pa`;
/// `oas` is the unit's `IDR5.OAS` code (the CD's `IPS` takes the same).
pub fn encode_cd(root_pa: u64, levels: u8, oas: u64, asid: u16) -> [u64; CD_DWORDS] {
    let t0sz = 64 - 12 - 9 * levels as u64;
    let mut cd = [0u64; CD_DWORDS];
    cd[0] = t0sz
        | CD_IRGN0_WB
        | CD_ORGN0_WB
        | CD_SH0_ISH
        | CD_EPD1
        | CD_V
        | ((oas & 7) << 32)
        | CD_AA64
        | CD_R
        | CD_A
        | CD_ASET
        | ((asid as u64) << 48);
    cd[1] = root_pa & CD_TTB0_MASK;
    cd[3] = MAIR_ATTR0_NORMAL_WB;
    cd
}

// ---- commands ----
pub const CMD_CFGI_STE: u64 = 0x03;
pub const CMD_CFGI_ALL: u64 = 0x04;
pub const CMD_CFGI_CD_ALL: u64 = 0x06;
pub const CMD_TLBI_NH_ASID: u64 = 0x11;
pub const CMD_TLBI_NSNH_ALL: u64 = 0x30;
pub const CMD_SYNC: u64 = 0x46;

/// `CFGI_STE` for stream `sid` (leaf: only that STE).
pub const fn cmd_cfgi_ste(sid: u32) -> [u64; 2] {
    [CMD_CFGI_STE | ((sid as u64) << 32), 1]
}
/// `CFGI_CD_ALL` for stream `sid`: every Context Descriptor cached for it.
pub const fn cmd_cfgi_cd_all(sid: u32) -> [u64; 2] {
    [CMD_CFGI_CD_ALL | ((sid as u64) << 32), 0]
}
/// `CFGI_ALL`: every cached configuration (`Range` 31 = the whole space).
pub const fn cmd_cfgi_all() -> [u64; 2] {
    [CMD_CFGI_ALL, 31]
}
pub const fn cmd_tlbi_nsnh_all() -> [u64; 2] {
    [CMD_TLBI_NSNH_ALL, 0]
}
pub const fn cmd_tlbi_nh_asid(asid: u16) -> [u64; 2] {
    [CMD_TLBI_NH_ASID | ((asid as u64) << 48), 0]
}
/// `CMD_SYNC` signalling by SEV (CS = 2): the queue's consumer index passes
/// it only once every earlier command has completed.
pub const fn cmd_sync() -> [u64; 2] {
    [CMD_SYNC | (2 << 12), 0]
}

// ---- events ----
pub mod event {
    pub const F_UUT: u8 = 0x01;
    pub const C_BAD_STREAMID: u8 = 0x02;
    pub const F_STE_FETCH: u8 = 0x03;
    pub const C_BAD_STE: u8 = 0x04;
    pub const F_STREAM_DISABLED: u8 = 0x06;
    pub const F_CD_FETCH: u8 = 0x09;
    pub const C_BAD_CD: u8 = 0x0a;
    pub const F_TRANSLATION: u8 = 0x10;
    pub const F_ADDR_SIZE: u8 = 0x11;
    pub const F_ACCESS: u8 = 0x12;
    pub const F_PERMISSION: u8 = 0x13;
}

/// An event-queue record, reduced to what the DMA-fault row needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventRecord {
    pub event_type: u8,
    pub stream_id: u32,
    pub input_addr: u64,
}

impl EventRecord {
    /// Decode a 32-byte record: type in bits 7:0 of dword 0, StreamID in
    /// bits 63:32 of dword 0, input address in dword 2.
    pub fn decode(buf: &[u8; 32]) -> Self {
        let d0 = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let input_addr = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        EventRecord { event_type: (d0 & 0xff) as u8, stream_id: (d0 >> 32) as u32, input_addr }
    }

    /// Encode a record the way a unit lays it out (for tests of `decode`).
    pub fn encode(&self) -> [u8; 32] {
        let d0 = self.event_type as u64 | ((self.stream_id as u64) << 32);
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&d0.to_le_bytes());
        buf[16..24].copy_from_slice(&self.input_addr.to_le_bytes());
        buf
    }
}


// ---- STE with stage 2: the host's tables under a stream ----
pub const STE_CFG_S2_TRANS: u64 = 6;
pub const STE_CFG_NESTED: u64 = 7;
/// STE dword 2 bits 50:32 hold `VTCR_EL2` bits 18:0 as they are (`T0SZ`, `SL0`,
/// `IR0`, `OR0`, `SH0`, `TG0`, `PS`): a stream walks the tables the CPU's
/// stage 2 walks, under the same translation control.
pub const STE2_VTCR_MASK: u64 = 0x7_ffff << 32;
pub const STE2_S2AA64: u64 = 1 << 51;
pub const STE2_S2PTW: u64 = 1 << 54;
pub const STE2_S2R: u64 = 1 << 58;
pub const STE3_S2TTB_MASK: u64 = 0x000f_ffff_ffff_fff0; // bits 51:4

/// A Stream Table Entry that translates through stage 2 (`s2_root`, the table
/// the host's `VTTBR_EL2` names, `vtcr` its control): by itself (`cd_pa` 0,
/// stage 1 bypassed) or under the stage 1 of the Context Descriptor at
/// `cd_pa`. VMID 0, the host's.
pub fn encode_ste_s2(vtcr: u64, s2_root: u64, cd_pa: u64) -> [u64; STE_DWORDS] {
    let mut ste = [0u64; STE_DWORDS];
    ste[2] = (vtcr & 0x7_ffff) << 32 | STE2_S2AA64 | STE2_S2PTW | STE2_S2R;
    ste[3] = s2_root & STE3_S2TTB_MASK;
    if cd_pa == 0 {
        ste[0] = STE_V | (STE_CFG_S2_TRANS << 1);
        ste[1] = STE1_SHCFG_INCOMING;
    } else {
        ste[0] = STE_V | (STE_CFG_NESTED << 1) | (cd_pa & STE_CTXPTR_MASK);
        ste[1] = STE1_S1DSS_SSID0 | STE1_S1CIR_WB | STE1_S1COR_WB | STE1_S1CSH_ISH | STE1_SHCFG_INCOMING;
    }
    ste
}

pub const CMD_TLBI_NH_ALL: u64 = 0x10;
pub const CMD_TLBI_S12_VMALL: u64 = 0x28;

/// `TLBI_NH_ALL`: every stage 1 translation of `vmid`.
pub const fn cmd_tlbi_nh_all(vmid: u16) -> [u64; 2] {
    [CMD_TLBI_NH_ALL | ((vmid as u64) << 32), 0]
}
/// `TLBI_S12_VMALL`: every stage 1 and stage 2 translation of `vmid`.
pub const fn cmd_tlbi_s12_vmall(vmid: u16) -> [u64; 2] {
    [CMD_TLBI_S12_VMALL | ((vmid as u64) << 32), 0]
}

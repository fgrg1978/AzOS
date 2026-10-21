// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Arm SMMUv3 (architecture spec IHI 0070; QEMU `-M virt,iommu=smmuv3`).
//!
//! A linear stream table maps a StreamID (the PCI requester id) to a Stream
//! Table Entry (STE, 64 bytes); a translating STE points at a Context
//! Descriptor (CD, 64 bytes) holding the stage 1 translation table base and
//! TCR. Commands go in a command queue (16-byte entries), events come out of
//! an event queue (32-byte entries); both are polled, interrupts stay off.
//!
//! STE dword 0: `V` bit 0, `Config` bits 3:1 (abort 0, bypass 4, stage 1
//! translate 5), `S1Fmt` 5:4, `S1ContextPtr` 51:6, `S1CDMax` 63:59. CD
//! dword 0: `T0SZ` 5:0, `TG0` 7:6, `IRGN0` 9:8, `ORGN0` 11:10, `SH0` 13:12,
//! `EPD1` 30, `V` 31, `IPS` 34:32, `AA64` 41, `R` 45, `A` 46, `ASET` 47,
//! `ASID` 63:48; dword 1 `TTB0` 51:4; dword 3 `MAIR`.

use core::sync::atomic::{fence, Ordering};

use crate::pgtable::{PtFormat, PtKind};
use crate::{
    rd64, wait_for, wr64, DmaFault, DomainMode, FaultKind, Flavour, IommuError, IommuUnit, Mmio, TableMem, POLL,
};

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
const CR1: u32 = (3 << 10) | (1 << 8) | (1 << 6) | (3 << 4) | (1 << 2) | 1; // WB, inner shareable
const CR2_PTM: u32 = 1 << 2;
const CR2_RECINVSID: u32 = 1 << 1;

pub const IDR0_S1P: u32 = 1 << 1;
const IDR0_TTF_AARCH64: u32 = 2 << 2;
const IDR0_TTF_MASK: u32 = 3 << 2;
const IDR1_TABLES_PRESET: u32 = 1 << 30;
const IDR1_QUEUES_PRESET: u32 = 1 << 29;

// ---- STE ----
pub const STE_DWORDS: usize = 8;
pub const STE_BYTES: u64 = 64;
pub const STE_V: u64 = 1 << 0;
pub const STE_CFG_ABORT: u64 = 0;
pub const STE_CFG_BYPASS: u64 = 4;
pub const STE_CFG_S1_TRANS: u64 = 5;
const STE_CFG_SHIFT: u32 = 1;
const STE_CTXPTR_MASK: u64 = 0x000f_ffff_ffff_ffc0; // bits 51:6
const STE1_S1DSS_SSID0: u64 = 2;
const STE1_S1CIR_WB: u64 = 1 << 2;
const STE1_S1COR_WB: u64 = 1 << 4;
const STE1_S1CSH_ISH: u64 = 3 << 6;
const STE1_SHCFG_INCOMING: u64 = 1 << 44;

/// The eight dwords of a Stream Table Entry for `mode`. `cd_pa` is the
/// Context Descriptor a translating entry points at (ignored otherwise).
pub fn encode_ste(mode: DomainMode, cd_pa: u64) -> [u64; STE_DWORDS] {
    let mut ste = [0u64; STE_DWORDS];
    match mode {
        // V clear: the unit refuses the stream (C_BAD_STE / C_BAD_STREAMID).
        DomainMode::Block => {}
        DomainMode::Bypass => {
            ste[0] = STE_V | (STE_CFG_BYPASS << STE_CFG_SHIFT);
            // Keep the transaction's own attributes through the bypass.
            ste[1] = STE1_SHCFG_INCOMING;
        }
        DomainMode::Translate { .. } => {
            ste[0] = STE_V | (STE_CFG_S1_TRANS << STE_CFG_SHIFT) | (cd_pa & STE_CTXPTR_MASK);
            ste[1] = STE1_S1DSS_SSID0 | STE1_S1CIR_WB | STE1_S1COR_WB | STE1_S1CSH_ISH | STE1_SHCFG_INCOMING;
        }
    }
    ste
}

// ---- CD ----
pub const CD_DWORDS: usize = 8;
pub const CD_BYTES: u64 = 64;
const CD_IRGN0_WB: u64 = 1 << 8;
const CD_ORGN0_WB: u64 = 1 << 10;
const CD_SH0_ISH: u64 = 3 << 12;
const CD_EPD1: u64 = 1 << 30;
const CD_V: u64 = 1 << 31;
const CD_AA64: u64 = 1 << 41;
const CD_R: u64 = 1 << 45;
const CD_A: u64 = 1 << 46;
const CD_ASET: u64 = 1 << 47;
const CD_TTB0_MASK: u64 = 0x000f_ffff_ffff_fff0; // bits 51:4
/// MAIR attribute 0: Normal memory, inner and outer write-back (the index
/// every leaf in `pgtable` uses).
const MAIR_ATTR0_NORMAL_WB: u64 = 0xff;

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
pub const CMD_TLBI_NH_ASID: u64 = 0x11;
pub const CMD_TLBI_NSNH_ALL: u64 = 0x30;
pub const CMD_SYNC: u64 = 0x46;

/// `CFGI_STE` for stream `sid` (leaf: only that STE).
pub const fn cmd_cfgi_ste(sid: u32) -> [u64; 2] {
    [CMD_CFGI_STE | ((sid as u64) << 32), 1]
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

pub fn classify(record: &EventRecord) -> DmaFault {
    let kind = match record.event_type {
        event::F_TRANSLATION | event::F_PERMISSION => FaultKind::UnmappedIova,
        event::C_BAD_STREAMID
        | event::F_STE_FETCH
        | event::C_BAD_STE
        | event::F_STREAM_DISABLED
        | event::F_CD_FETCH
        | event::C_BAD_CD => FaultKind::BadDeviceEntry,
        other => FaultKind::Other(other as u32),
    };
    DmaFault { device_id: record.stream_id, fault_addr: record.input_addr, kind }
}

// ---- the unit ----

const OVFLG: u32 = 1 << 31;
const CONS_ERR_MASK: u32 = 0x7f << 24;

/// One SMMUv3 with a linear stream table and polled queues.
pub struct Smmuv3<M: Mmio> {
    mmio: M,
    mem: &'static dyn TableMem,
    pt: PtFormat,
    oas: u64,
    strtab: u64,
    strtab_log2: u32,
    cmdq: u64,
    cmdq_log2: u32,
    cmdq_prod: u32,
    evtq: u64,
    evtq_log2: u32,
    evtq_cons: u32,
    cd_page: u64,
    cd_next: u64,
}

impl<M: Mmio> Smmuv3<M> {
    /// Bring the unit up for streams `0..=max_dev`. Every stream is refused
    /// (STE invalid) until `attach`ed.
    pub fn new(mmio: M, mem: &'static dyn TableMem, max_dev: u32) -> Result<Self, IommuError> {
        let idr0 = mmio.read32(REG_IDR0);
        let idr1 = mmio.read32(REG_IDR1);
        let idr5 = mmio.read32(REG_IDR5);
        if idr0 & IDR0_S1P == 0 {
            return Err(IommuError::Unsupported("smmuv3: no stage 1 translation"));
        }
        if idr0 & IDR0_TTF_MASK & IDR0_TTF_AARCH64 == 0 {
            return Err(IommuError::Unsupported("smmuv3: no AArch64 translation tables"));
        }
        if idr1 & (IDR1_TABLES_PRESET | IDR1_QUEUES_PRESET) != 0 {
            return Err(IommuError::Unsupported("smmuv3: tables or queues are not programmable"));
        }
        let sid_bits = idr1 & 0x3f;
        let want = 32 - max_dev.max(1).leading_zeros(); // bits to index 0..=max_dev
        if want > sid_bits {
            return Err(IommuError::Unsupported("smmuv3: stream id space smaller than the devices"));
        }
        let strtab_log2 = want;
        let cmdq_log2 = ((idr1 >> 21) & 0x1f).min(8);
        let evtq_log2 = ((idr1 >> 16) & 0x1f).min(7);
        if cmdq_log2 < 2 || evtq_log2 < 2 {
            return Err(IommuError::Unsupported("smmuv3: queues too small"));
        }
        let oas = (idr5 & 7) as u64;

        // Disable, then program with the unit quiet.
        mmio.write32(REG_CR0, 0);
        if !wait_for(POLL, || mmio.read32(REG_CR0ACK) == 0) {
            return Err(IommuError::Timeout("smmuv3: would not disable"));
        }
        mmio.write32(REG_CR1, CR1);
        mmio.write32(REG_CR2, CR2_PTM | CR2_RECINVSID);
        mmio.write32(REG_IRQ_CTRL, 0);

        let strtab_bytes = STE_BYTES << strtab_log2;
        let strtab = mem
            .alloc_aligned(strtab_bytes as usize, (strtab_bytes as usize).max(4096))
            .ok_or(IommuError::NoMemory)?;
        let cmdq = mem.alloc_page().ok_or(IommuError::NoMemory)?;
        let evtq = mem.alloc_page().ok_or(IommuError::NoMemory)?;
        // The unit writes the event queue: no dirty zero lines over its records.
        mem.clean(evtq, 4096);
        let cd_page = mem.alloc_page().ok_or(IommuError::NoMemory)?;

        // Linear format (FMT 0), LOG2SIZE.
        mmio.write64(REG_STRTAB_BASE, strtab & 0x000f_ffff_ffff_ffc0);
        mmio.write32(REG_STRTAB_BASE_CFG, strtab_log2);
        mmio.write64(REG_CMDQ_BASE, (cmdq & 0x000f_ffff_ffff_ffe0) | cmdq_log2 as u64);
        mmio.write32(REG_CMDQ_PROD, 0);
        mmio.write32(REG_CMDQ_CONS, 0);
        mmio.write32(REG_CR0, CR0_CMDQEN);
        if !wait_for(POLL, || mmio.read32(REG_CR0ACK) & CR0_CMDQEN != 0) {
            return Err(IommuError::Timeout("smmuv3: command queue did not enable"));
        }

        let mut unit = Smmuv3 {
            mmio,
            mem,
            pt: PtFormat::new(PtKind::ArmLpae, 4),
            oas,
            strtab,
            strtab_log2,
            cmdq,
            cmdq_log2,
            cmdq_prod: 0,
            evtq,
            evtq_log2,
            evtq_cons: 0,
            cd_page,
            cd_next: 0,
        };
        unit.command(cmd_cfgi_all())?;
        unit.command(cmd_tlbi_nsnh_all())?;
        unit.sync()?;

        unit.mmio.write64(REG_EVTQ_BASE, (evtq & 0x000f_ffff_ffff_ffe0) | evtq_log2 as u64);
        unit.mmio.write32(REG_EVTQ_PROD, 0);
        unit.mmio.write32(REG_EVTQ_CONS, 0);
        unit.mmio.write32(REG_CR0, CR0_CMDQEN | CR0_EVTQEN);
        if !wait_for(POLL, || unit.mmio.read32(REG_CR0ACK) & CR0_EVTQEN != 0) {
            return Err(IommuError::Timeout("smmuv3: event queue did not enable"));
        }
        unit.mmio.write32(REG_CR0, CR0_CMDQEN | CR0_EVTQEN | CR0_SMMUEN);
        if !wait_for(POLL, || unit.mmio.read32(REG_CR0ACK) & CR0_SMMUEN != 0) {
            return Err(IommuError::Timeout("smmuv3: would not enable"));
        }
        Ok(unit)
    }

    fn command(&mut self, cmd: [u64; 2]) -> Result<(), IommuError> {
        let size = 1u32 << self.cmdq_log2;
        let wrap_mask = (size << 1) - 1;
        let cons = self.mmio.read32(REG_CMDQ_CONS);
        // Full: same index, opposite wrap bit.
        if (self.cmdq_prod ^ cons) & wrap_mask == size {
            self.wait_drained()?;
        }
        let slot = (self.cmdq_prod & (size - 1)) as usize * 2;
        wr64(self.mem, self.cmdq, slot, cmd[0]);
        wr64(self.mem, self.cmdq, slot + 1, cmd[1]);
        self.mem.clean(self.cmdq + slot as u64 * 8, 16);
        self.cmdq_prod = (self.cmdq_prod + 1) & wrap_mask;
        fence(Ordering::SeqCst);
        self.mmio.write32(REG_CMDQ_PROD, self.cmdq_prod);
        Ok(())
    }

    fn wait_drained(&self) -> Result<(), IommuError> {
        let size = 1u32 << self.cmdq_log2;
        let wrap_mask = (size << 1) - 1;
        let target = self.cmdq_prod;
        let ok = wait_for(POLL, || {
            let c = self.mmio.read32(REG_CMDQ_CONS);
            c & CONS_ERR_MASK != 0 || c & wrap_mask == target
        });
        if !ok {
            return Err(IommuError::Timeout("smmuv3: command queue did not drain"));
        }
        if self.mmio.read32(REG_CMDQ_CONS) & CONS_ERR_MASK != 0 {
            return Err(IommuError::Hardware("smmuv3: command rejected"));
        }
        Ok(())
    }

    /// `CMD_SYNC`, then wait for the queue to pass it.
    fn sync(&mut self) -> Result<(), IommuError> {
        self.command(cmd_sync())?;
        self.wait_drained()
    }

    fn ste_slot(&self, dev: u32) -> Result<u64, IommuError> {
        if dev >= 1 << self.strtab_log2 {
            return Err(IommuError::DeviceOutOfRange);
        }
        Ok(self.strtab + dev as u64 * STE_BYTES)
    }

    /// A fresh 64-byte slot for a Context Descriptor.
    fn cd_slot(&mut self) -> Result<u64, IommuError> {
        if self.cd_next == 4096 / CD_BYTES {
            self.cd_page = self.mem.alloc_page().ok_or(IommuError::NoMemory)?;
            self.cd_next = 0;
        }
        let slot = self.cd_page + self.cd_next * CD_BYTES;
        self.cd_next += 1;
        Ok(slot)
    }

    fn write_ste(&mut self, dev: u32, slot: u64, ste: [u64; STE_DWORDS]) -> Result<(), IommuError> {
        // Dwords 1.. first, dword 0 (V and Config) last.
        for (i, w) in ste.iter().enumerate().skip(1) {
            wr64(self.mem, slot, i, *w);
        }
        self.mem.clean(slot, STE_BYTES as usize);
        fence(Ordering::Release);
        wr64(self.mem, slot, 0, ste[0]);
        self.mem.clean(slot, 8);
        self.command(cmd_cfgi_ste(dev))?;
        self.sync()
    }
}

impl<M: Mmio + Send> IommuUnit for Smmuv3<M> {
    fn flavour(&self) -> Flavour {
        Flavour::Smmuv3
    }

    fn pt_format(&self) -> PtFormat {
        self.pt
    }

    /// The device must not be mid-DMA: a live STE is made invalid first.
    fn attach(&mut self, dev: u32, mode: DomainMode) -> Result<(), IommuError> {
        let slot = self.ste_slot(dev)?;
        if rd64(self.mem, slot, 0) & STE_V != 0 {
            wr64(self.mem, slot, 0, 0);
            self.mem.clean(slot, 8);
            self.command(cmd_cfgi_ste(dev))?;
            self.sync()?;
        }
        let cd_pa = match mode {
            DomainMode::Translate { root_pa } => {
                let cd_pa = self.cd_slot()?;
                let cd = encode_cd(root_pa, self.pt.levels, self.oas, 1);
                for (i, w) in cd.iter().enumerate() {
                    wr64(self.mem, cd_pa, i, *w);
                }
                self.mem.clean(cd_pa, CD_BYTES as usize);
                cd_pa
            }
            _ => 0,
        };
        self.write_ste(dev, slot, encode_ste(mode, cd_pa))
    }

    fn flush(&mut self, _dev: u32) -> Result<(), IommuError> {
        self.command(cmd_tlbi_nsnh_all())?;
        self.sync()
    }

    fn poll_faults(&mut self, sink: &mut dyn FnMut(DmaFault)) -> usize {
        let size = 1u32 << self.evtq_log2;
        let wrap_mask = (size << 1) - 1;
        let prod = self.mmio.read32(REG_EVTQ_PROD);
        let mut n = 0;
        while self.evtq_cons != prod & wrap_mask {
            let base = self.evtq + (self.evtq_cons & (size - 1)) as u64 * 32;
            self.mem.invalidate(base, 32);
            let mut raw = [0u8; 32];
            for (i, chunk) in raw.chunks_exact_mut(8).enumerate() {
                chunk.copy_from_slice(&rd64(self.mem, base, i).to_le_bytes());
            }
            sink(classify(&EventRecord::decode(&raw)));
            n += 1;
            self.evtq_cons = (self.evtq_cons + 1) & wrap_mask;
        }
        // Acknowledge an overflow by echoing the flag back in CONS.
        self.mmio.write32(REG_EVTQ_CONS, self.evtq_cons | (prod & OVFLG));
        n
    }
}

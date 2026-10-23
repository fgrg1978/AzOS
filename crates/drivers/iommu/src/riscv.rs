// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RISC-V IOMMU (ratified spec 1.0; QEMU `riscv-iommu-pci`).
//!
//! The unit is a PCI function (class 0x0806) whose BAR 0 holds the
//! registers. The device directory table (DDT) maps a requester id to a
//! device context (DC); a DC names the first-stage page table (`fsc`, here
//! Sv39 or Sv48), or Bare for pass-through. Commands go in a command queue,
//! faults come out of a fault queue; both are polled, interrupts stay off.
//!
//! # Layouts used
//!
//! DC, base format (32 bytes): `tc`, `iohgatp`, `ta`, `fsc`. Extended format
//! (64 bytes, when `capabilities.MSI_FLAT`): the same four, then `msiptp`,
//! `msi_addr_mask`, `msi_addr_pattern`, reserved. `tc.V` is bit 0; `fsc` is
//! `PPN[43:0] | MODE[63:60]` (Bare 0, Sv39 8, Sv48 9); `ta.PSCID` is bits
//! 31:12, the tag of the device's cached first-stage translations (`tc.PDTV`
//! clear: no process directory); `iohgatp` stays Bare (second stage unused). A DDT non-leaf entry is `V | PPN<<10`. Fault
//! record (32 bytes): `hdr` (`CAUSE[11:0]`, `TTYP[39:34]`, `DID[63:40]`),
//! reserved, `iotval`, `iotval2`.

use crate::pgtable::{PtFormat, PtKind};
use crate::{
    rd64, wait_for, wr64, DmaFault, DomainMode, FaultKind, Flavour, IommuError, IommuUnit, Mmio, TableMem, Tags, PAGE,
    POLL, TAGS,
};

// ---- registers (byte offsets) ----
pub const REG_CAP: usize = 0x00;
pub const REG_FCTL: usize = 0x08;
pub const REG_DDTP: usize = 0x10;
pub const REG_CQB: usize = 0x18;
pub const REG_CQH: usize = 0x20;
pub const REG_CQT: usize = 0x24;
pub const REG_FQB: usize = 0x28;
pub const REG_FQH: usize = 0x30;
pub const REG_FQT: usize = 0x34;
pub const REG_CQCSR: usize = 0x48;
pub const REG_FQCSR: usize = 0x4c;

// capabilities
pub const CAP_SV39: u64 = 1 << 9;
pub const CAP_SV48: u64 = 1 << 10;
pub const CAP_MSI_FLAT: u64 = 1 << 22;

// ddtp
pub const DDTP_BUSY: u64 = 1 << 4;
pub const DDTP_MODE_2LVL: u64 = 3;
pub const DDTP_PPN_SHIFT: u32 = 10;

// queue control and status (cqcsr / fqcsr)
pub const QCSR_EN: u32 = 1 << 0;
pub const QCSR_MEM_FAULT: u32 = 1 << 8;
pub const QCSR_CMD_TO_OR_OVERFLOW: u32 = 1 << 9; // cqcsr.CMD_TO, fqcsr.FQOF
pub const QCSR_CMD_ILL: u32 = 1 << 10; // cqcsr only
pub const QCSR_ON: u32 = 1 << 16;
pub const QCSR_BUSY: u32 = 1 << 17;

// ---- device context ----
pub const DC_TC_V: u64 = 1 << 0;
const ATP_MODE_SHIFT: u32 = 60;
const ATP_PPN_MASK: u64 = (1 << 44) - 1;
const TA_PSCID_SHIFT: u32 = 12;
/// PSCIDs are 20 bits wide.
const PSCID_MASK: u32 = (1 << 20) - 1;
pub const ATP_MODE_BARE: u64 = 0;
pub const ATP_MODE_SV39: u64 = 8;
pub const ATP_MODE_SV48: u64 = 9;

/// A device context. `encode` builds it, `to_dwords` lays it out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceContext {
    pub tc: u64,
    pub iohgatp: u64,
    pub ta: u64,
    pub fsc: u64,
}

impl DeviceContext {
    /// The context for `mode`; `levels` is the first-stage depth (3 = Sv39,
    /// 4 = Sv48) and `pscid` the tag of a translating device's cached
    /// translations. `Block` is a context with `tc.V` clear: the unit refuses
    /// the device with cause 258 (DDT entry not valid).
    pub fn encode(mode: DomainMode, levels: u8, pscid: u32) -> Self {
        match mode {
            DomainMode::Block => DeviceContext { tc: 0, iohgatp: 0, ta: 0, fsc: 0 },
            DomainMode::Bypass => DeviceContext { tc: DC_TC_V, iohgatp: 0, ta: 0, fsc: ATP_MODE_BARE << ATP_MODE_SHIFT },
            DomainMode::Translate { root_pa } => {
                let m = if levels == 4 { ATP_MODE_SV48 } else { ATP_MODE_SV39 };
                DeviceContext {
                    tc: DC_TC_V,
                    iohgatp: 0,
                    ta: ((pscid & PSCID_MASK) as u64) << TA_PSCID_SHIFT,
                    fsc: (m << ATP_MODE_SHIFT) | ((root_pa >> 12) & ATP_PPN_MASK),
                }
            }
        }
    }

    pub fn is_valid(&self) -> bool {
        self.tc & DC_TC_V != 0
    }

    /// The mode this context encodes, or `None` for a first-stage mode this
    /// crate does not emit.
    pub fn decode_mode(&self) -> Option<DomainMode> {
        if !self.is_valid() {
            return Some(DomainMode::Block);
        }
        match self.fsc >> ATP_MODE_SHIFT {
            ATP_MODE_BARE => Some(DomainMode::Bypass),
            ATP_MODE_SV39 | ATP_MODE_SV48 => Some(DomainMode::Translate { root_pa: (self.fsc & ATP_PPN_MASK) << 12 }),
            _ => None,
        }
    }

    /// The context as the 64-bit words of memory: 4 (base format) or 8
    /// (extended, the MSI words zero). Returns the array and the length.
    pub fn to_dwords(&self, ext: bool) -> ([u64; 8], usize) {
        ([self.tc, self.iohgatp, self.ta, self.fsc, 0, 0, 0, 0], if ext { 8 } else { 4 })
    }
}

/// `(DDI[1], DDI[0])` of a requester id in a two-level DDT, or `None` when
/// it does not fit. Base format: 7 bits at the leaf, 9 above (16 total);
/// extended: 6 and 9 (15 total).
pub const fn ddt_index(dev: u32, ext: bool) -> Option<(usize, usize)> {
    let leaf_bits = if ext { 6 } else { 7 };
    if dev >= 1 << (leaf_bits + 9) {
        return None;
    }
    Some(((dev >> leaf_bits) as usize, (dev & ((1 << leaf_bits) - 1)) as usize))
}

/// A DDT non-leaf entry pointing at the leaf page `pa`.
pub const fn ddt_nonleaf(pa: u64) -> u64 {
    ((pa >> 12) << DDTP_PPN_SHIFT) | 1
}

// ---- commands (two 64-bit words) ----

/// `IODIR.INVAL_DDT` for device `dev`: forget the cached device context.
pub const fn cmd_iodir_inval_ddt(dev: u32) -> [u64; 2] {
    // opcode 3 (IODIR), func 0 (INVAL_DDT), DV (bit 33), DID (63:40).
    [3 | (1 << 33) | ((dev as u64 & 0xff_ffff) << 40), 0]
}

/// `IOTINVAL.VMA` scoped to process soft-context `pscid` (PSCV, bit 32;
/// PSCID 31:12), no address or guest scope: every first-stage translation
/// cached under that tag.
pub const fn cmd_iotinval_vma_pscid(pscid: u32) -> [u64; 2] {
    [1 | (((pscid & PSCID_MASK) as u64) << 12) | (1 << 32), 0]
}

/// `IOFENCE.C` ordering all prior reads and writes (PR, PW); no memory
/// write (AV clear). Completion is the queue head reaching it.
pub const fn cmd_iofence() -> [u64; 2] {
    [2 | (1 << 12) | (1 << 13), 0]
}

// ---- fault record ----

/// Cause codes this crate names (spec table "Fault causes").
pub mod cause {
    pub const INST_FAULT_S: u32 = 12;
    pub const RD_FAULT_S: u32 = 13;
    pub const WR_FAULT_S: u32 = 15;
    pub const DMA_DISABLED: u32 = 256;
    pub const DDT_LOAD_FAULT: u32 = 257;
    pub const DDT_INVALID: u32 = 258;
    pub const DDT_MISCONFIGURED: u32 = 259;
    pub const TTYP_BLOCKED: u32 = 260;
    pub const DDT_CORRUPTED: u32 = 268;
}

/// A fault-queue record, reduced to what the DMA-fault row needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultRecord {
    pub cause: u32,
    pub device_id: u32,
    pub iotval: u64,
}

impl FaultRecord {
    /// Decode a 32-byte record.
    pub fn decode(buf: &[u8; 32]) -> Self {
        let hdr = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let iotval = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        FaultRecord { cause: (hdr & 0xfff) as u32, device_id: ((hdr >> 40) & 0xff_ffff) as u32, iotval }
    }

    /// Encode a record the way a unit lays it out (for tests of `decode`).
    pub fn encode(&self) -> [u8; 32] {
        let hdr = (self.cause as u64 & 0xfff) | ((self.device_id as u64 & 0xff_ffff) << 40);
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&hdr.to_le_bytes());
        buf[16..24].copy_from_slice(&self.iotval.to_le_bytes());
        buf
    }
}

pub fn classify(record: &FaultRecord) -> DmaFault {
    let kind = match record.cause {
        cause::INST_FAULT_S | cause::RD_FAULT_S | cause::WR_FAULT_S => FaultKind::UnmappedIova,
        cause::DMA_DISABLED
        | cause::DDT_LOAD_FAULT
        | cause::DDT_INVALID
        | cause::DDT_MISCONFIGURED
        | cause::TTYP_BLOCKED
        | cause::DDT_CORRUPTED => FaultKind::BadDeviceEntry,
        other => FaultKind::Other(other),
    };
    DmaFault { device_id: record.device_id, fault_addr: record.iotval, kind }
}

// ---- the unit ----

/// The first PSCID of a translating device (0 is left alone, as Linux does).
const PSCID_FIRST: u16 = 1;

const CQ_ENTRIES: u32 = 256; // 16 bytes each: one page
const FQ_ENTRIES: u32 = 128; // 32 bytes each: one page

/// One RISC-V IOMMU, brought up with a two-level DDT and polled queues.
pub struct RiscvIommu<M: Mmio> {
    mmio: M,
    mem: &'static dyn TableMem,
    ext: bool,
    pt: PtFormat,
    ddt_root: u64,
    cq: u64,
    cq_tail: u32,
    fq: u64,
    fq_head: u32,
    /// The PSCID of each translating device.
    tags: Tags,
}

impl<M: Mmio> RiscvIommu<M> {
    /// Bring the unit up: queues on, device directory installed. Every
    /// device is refused (DC invalid) until `attach`ed.
    pub fn new(mmio: M, mem: &'static dyn TableMem) -> Result<Self, IommuError> {
        let caps = mmio.read64(REG_CAP);
        let levels = if caps & CAP_SV39 != 0 {
            3
        } else if caps & CAP_SV48 != 0 {
            4
        } else {
            return Err(IommuError::Unsupported("riscv-iommu: neither Sv39 nor Sv48 first stage"));
        };
        let ext = caps & CAP_MSI_FLAT != 0;

        let cq = mem.alloc_page().ok_or(IommuError::NoMemory)?;
        let fq = mem.alloc_page().ok_or(IommuError::NoMemory)?;
        // The unit writes the fault queue: no dirty zero lines over its records.
        mem.clean(fq, PAGE as usize);
        let ddt_root = mem.alloc_page().ok_or(IommuError::NoMemory)?;

        // Command queue: LOG2SZ-1 in the low five bits, PPN above bit 10.
        mmio.write64(REG_CQB, ((cq >> 12) << 10) | (CQ_ENTRIES.trailing_zeros() as u64 - 1));
        mmio.write32(REG_CQCSR, QCSR_EN);
        if !wait_for(POLL, || {
            let c = mmio.read32(REG_CQCSR);
            c & QCSR_ON != 0 && c & QCSR_BUSY == 0
        }) {
            return Err(IommuError::Timeout("riscv-iommu: command queue did not come on"));
        }
        // Fault queue.
        mmio.write64(REG_FQB, ((fq >> 12) << 10) | (FQ_ENTRIES.trailing_zeros() as u64 - 1));
        mmio.write32(REG_FQCSR, QCSR_EN);
        if !wait_for(POLL, || {
            let c = mmio.read32(REG_FQCSR);
            c & QCSR_ON != 0 && c & QCSR_BUSY == 0
        }) {
            return Err(IommuError::Timeout("riscv-iommu: fault queue did not come on"));
        }

        // Install the device directory: from Off, any table mode is allowed.
        mmio.write64(REG_DDTP, DDTP_MODE_2LVL | ((ddt_root >> 12) << DDTP_PPN_SHIFT));
        if !wait_for(POLL, || mmio.read64(REG_DDTP) & DDTP_BUSY == 0) {
            return Err(IommuError::Timeout("riscv-iommu: ddtp stayed busy"));
        }
        if mmio.read64(REG_DDTP) & 0xf != DDTP_MODE_2LVL {
            return Err(IommuError::Unsupported("riscv-iommu: two-level device directory refused"));
        }

        Ok(RiscvIommu {
            mmio,
            mem,
            ext,
            pt: PtFormat::new(PtKind::RiscvSv, levels),
            ddt_root,
            cq,
            cq_tail: 0,
            fq,
            fq_head: 0,
            tags: Tags::new(PSCID_FIRST, TAGS),
        })
    }

    /// Does this unit use the 64-byte device context?
    pub fn extended_dc(&self) -> bool {
        self.ext
    }

    fn command(&mut self, cmd: [u64; 2]) -> Result<(), IommuError> {
        let slot = (self.cq_tail % CQ_ENTRIES) as usize * 2;
        wr64(self.mem, self.cq, slot, cmd[0]);
        wr64(self.mem, self.cq, slot + 1, cmd[1]);
        self.mem.clean(self.cq + slot as u64 * 8, 16);
        self.cq_tail = (self.cq_tail + 1) % CQ_ENTRIES;
        // The tail write is the doorbell: the command before it, for the unit.
        azos_dma::order::io_wmb();
        self.mmio.write32(REG_CQT, self.cq_tail);
        let tail = self.cq_tail;
        let done = wait_for(POLL, || {
            self.mmio.read32(REG_CQH) == tail
                || self.mmio.read32(REG_CQCSR) & (QCSR_CMD_ILL | QCSR_MEM_FAULT | QCSR_CMD_TO_OR_OVERFLOW) != 0
        });
        if !done {
            return Err(IommuError::Timeout("riscv-iommu: command queue did not drain"));
        }
        if self.mmio.read32(REG_CQCSR) & (QCSR_CMD_ILL | QCSR_MEM_FAULT | QCSR_CMD_TO_OR_OVERFLOW) != 0 {
            return Err(IommuError::Hardware("riscv-iommu: command rejected"));
        }
        Ok(())
    }

    fn invalidate_dc(&mut self, dev: u32) -> Result<(), IommuError> {
        self.command(cmd_iodir_inval_ddt(dev))?;
        self.command(cmd_iofence())
    }

    /// The physical address of the DC of `dev`, allocating its leaf page.
    fn dc_slot(&mut self, dev: u32) -> Result<u64, IommuError> {
        let (i1, i0) = ddt_index(dev, self.ext).ok_or(IommuError::DeviceOutOfRange)?;
        let e = rd64(self.mem, self.ddt_root, i1);
        let leaf = if e & 1 != 0 {
            ((e >> DDTP_PPN_SHIFT) & ((1 << 44) - 1)) << 12
        } else {
            let leaf = self.mem.alloc_page().ok_or(IommuError::NoMemory)?;
            wr64(self.mem, self.ddt_root, i1, ddt_nonleaf(leaf));
            self.mem.clean(self.ddt_root + i1 as u64 * 8, 8);
            leaf
        };
        let dc_bytes = if self.ext { 64 } else { 32 };
        debug_assert!((i0 as u64 + 1) * dc_bytes <= PAGE);
        Ok(leaf + i0 as u64 * dc_bytes)
    }
}

impl<M: Mmio + Send> IommuUnit for RiscvIommu<M> {
    fn flavour(&self) -> Flavour {
        Flavour::Riscv
    }

    fn pt_format(&self) -> PtFormat {
        self.pt
    }

    /// A translating device gets a PSCID of its own; one that stops
    /// translating gives it back once the unit forgot what it cached under it.
    fn attach(&mut self, dev: u32, mode: DomainMode) -> Result<(), IommuError> {
        let slot = self.dc_slot(dev)?;
        let pscid = match mode {
            DomainMode::Translate { .. } => {
                self.tags.take(dev).ok_or(IommuError::Unsupported("riscv-iommu: out of PSCIDs"))?
            }
            _ => 0,
        };
        let dc = DeviceContext::encode(mode, self.pt.levels, pscid as u32);
        let (words, n) = dc.to_dwords(self.ext);
        // A valid context may be cached: make it invalid, flush, rewrite the
        // body, and make it valid last (spec 3.1.3 "Device-context update").
        if rd64(self.mem, slot, 0) & DC_TC_V != 0 {
            wr64(self.mem, slot, 0, 0);
            self.mem.clean(slot, 8);
            self.invalidate_dc(dev)?;
        }
        for i in 1..n {
            wr64(self.mem, slot, i, words[i]);
        }
        self.mem.clean(slot, n * 8);
        azos_dma::order::dma_wmb();
        wr64(self.mem, slot, 0, words[0]);
        self.mem.clean(slot, 8);
        self.command(cmd_iodir_inval_ddt(dev))?;
        // A device's PSCID tags the translations of whatever table it had
        // before: they go with the context, and a tag is free again only once
        // they are gone.
        let Some(tag) = self.tags.of(dev) else {
            return self.command(cmd_iofence());
        };
        self.command(cmd_iotinval_vma_pscid(tag as u32))?;
        self.command(cmd_iofence())?;
        if !matches!(mode, DomainMode::Translate { .. }) {
            self.tags.release(dev);
        }
        Ok(())
    }

    /// Only a translating device has translations cached, under its PSCID.
    fn flush(&mut self, dev: u32) -> Result<(), IommuError> {
        let Some(pscid) = self.tags.of(dev) else {
            return Ok(());
        };
        self.command(cmd_iotinval_vma_pscid(pscid as u32))?;
        self.command(cmd_iofence())
    }

    fn poll_faults(&mut self, sink: &mut dyn FnMut(DmaFault)) -> usize {
        let mut n = 0;
        // FQH is ours, FQT the unit's.
        while self.fq_head != self.mmio.read32(REG_FQT) % FQ_ENTRIES {
            let base = self.fq + (self.fq_head as u64) * 32;
            self.mem.invalidate(base, 32);
            let mut raw = [0u8; 32];
            for (i, chunk) in raw.chunks_exact_mut(8).enumerate() {
                chunk.copy_from_slice(&rd64(self.mem, base, i).to_le_bytes());
            }
            sink(classify(&FaultRecord::decode(&raw)));
            n += 1;
            self.fq_head = (self.fq_head + 1) % FQ_ENTRIES;
            self.mmio.write32(REG_FQH, self.fq_head);
        }
        // The unit stops logging on overflow or a memory fault until these
        // (write-1-to-clear) bits are cleared.
        let csr = self.mmio.read32(REG_FQCSR);
        if csr & (QCSR_MEM_FAULT | QCSR_CMD_TO_OR_OVERFLOW) != 0 {
            self.mmio.write32(REG_FQCSR, QCSR_EN | (csr & (QCSR_MEM_FAULT | QCSR_CMD_TO_OR_OVERFLOW)));
        }
        n
    }
}

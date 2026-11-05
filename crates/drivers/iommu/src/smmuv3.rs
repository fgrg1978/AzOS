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

use crate::pgtable::{PtFormat, PtKind};
use crate::{
    rd64, wait_for, wr64, DmaFault, DomainMode, FaultKind, Flavour, IommuError, IommuUnit, TableMem, Tags, POLL,
    TAGS,
};
use azos_drvkit::Mmio;

#[path = "smmuv3_fmt.rs"]
mod fmt;
pub use fmt::*;

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

/// The first ASID of a translating device (0 is left alone, as Linux does).
const ASID_FIRST: u16 = 1;

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
    /// One Context Descriptor per ASID: the CD of ASID `a` is at
    /// `cds + (a - ASID_FIRST) * CD_BYTES`.
    cds: u64,
    /// The ASID of each translating device.
    tags: Tags,
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
        let cds = mem.alloc_page().ok_or(IommuError::NoMemory)?;

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
            cds,
            tags: Tags::new(ASID_FIRST, TAGS),
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
        // The tail write is the doorbell: the command before it, for the unit.
        azos_dma::order::io_wmb();
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

    /// The Context Descriptor of `asid`.
    fn cd_of(&self, asid: u16) -> u64 {
        self.cds + (asid - ASID_FIRST) as u64 * CD_BYTES
    }

    /// Drop what the unit cached under `asid` (the commands are queued: a
    /// `sync` completes them).
    fn tlbi_asid(&mut self, asid: u16) -> Result<(), IommuError> {
        self.command(cmd_tlbi_nh_asid(asid))
    }

    fn write_ste(&mut self, dev: u32, slot: u64, ste: [u64; STE_DWORDS]) -> Result<(), IommuError> {
        // Dwords 1.. first, dword 0 (V and Config) last.
        for (i, w) in ste.iter().enumerate().skip(1) {
            wr64(self.mem, slot, i, *w);
        }
        self.mem.clean(slot, STE_BYTES as usize);
        azos_dma::order::dma_wmb();
        wr64(self.mem, slot, 0, ste[0]);
        self.mem.clean(slot, 8);
        self.command(cmd_cfgi_ste(dev))
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
    /// A translating device gets an ASID and a CD of its own; one that stops
    /// translating gives its ASID back once the unit forgot what it cached
    /// under it.
    fn attach(&mut self, dev: u32, mode: DomainMode) -> Result<(), IommuError> {
        let slot = self.ste_slot(dev)?;
        if rd64(self.mem, slot, 0) & STE_V != 0 {
            wr64(self.mem, slot, 0, 0);
            self.mem.clean(slot, 8);
            self.command(cmd_cfgi_ste(dev))?;
            self.sync()?;
        }
        match mode {
            DomainMode::Translate { root_pa } => {
                let asid = self.tags.take(dev).ok_or(IommuError::Unsupported("smmuv3: out of ASIDs"))?;
                let cd_pa = self.cd_of(asid);
                // Nothing reads this CD now: the device's STE is invalid and
                // no other device's points at it.
                let cd = encode_cd(root_pa, self.pt.levels, self.oas, asid);
                for (i, w) in cd.iter().enumerate() {
                    wr64(self.mem, cd_pa, i, *w);
                }
                self.mem.clean(cd_pa, CD_BYTES as usize);
                self.write_ste(dev, slot, encode_ste(mode, cd_pa))?;
                // The unit may hold the stream's old CD and, under this ASID,
                // translations of the table the device had before.
                self.command(cmd_cfgi_cd_all(dev))?;
                self.tlbi_asid(asid)?;
                self.sync()
            }
            _ => {
                self.write_ste(dev, slot, encode_ste(mode, 0))?;
                if let Some(asid) = self.tags.of(dev) {
                    self.tlbi_asid(asid)?;
                    self.sync()?;
                    self.tags.release(dev);
                    return Ok(());
                }
                self.sync()
            }
        }
    }

    /// Only a translating device has translations cached, under its ASID.
    fn flush(&mut self, dev: u32) -> Result<(), IommuError> {
        let Some(asid) = self.tags.of(dev) else {
            return Ok(());
        };
        self.tlbi_asid(asid)?;
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

// ---- a unit a resident monitor owns ----

/// How a stream is set up when a monitor owns the unit. Stage 2 is the host's
/// in every case: the monitor builds the entry, the kernel only says what it
/// wants of stage 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteStream {
    /// Every access refused.
    Block,
    /// Stage 1 bypassed: bus address == physical, under the host stage 2.
    S2Only,
    /// The Context Descriptor at the given address, under the host stage 2.
    Nested(u64),
}

/// What the kernel asks of the monitor that owns the unit (VIRT_SPLIT). The
/// kernel implements it with the monitor's calls; the tests with a model.
pub trait Remote: Send {
    /// Bring the unit up for streams `0..=max_sid`; its `IDR5.OAS` code.
    fn init(&self, base: u64, size: u64, max_sid: u32) -> Option<u64>;
    fn attach(&self, sid: u32, stream: RemoteStream) -> bool;
    /// Drop what the unit cached about the stream's stage 1.
    fn flush(&self, sid: u32) -> bool;
    /// The oldest fault record: dword 0 and dword 2.
    fn event(&self) -> Option<[u64; 2]>;
}

/// The same stream interface as [`Smmuv3`], with no register in the kernel's
/// reach: the stream table, the queues and the registers are the monitor's, and
/// the kernel keeps what it always kept, the Context Descriptors and the stage 1
/// tables they name.
pub struct Smmuv3Remote<R: Remote> {
    remote: R,
    mem: &'static dyn TableMem,
    pt: PtFormat,
    oas: u64,
    cds: u64,
    tags: Tags,
}

impl<R: Remote> Smmuv3Remote<R> {
    pub fn new(remote: R, mem: &'static dyn TableMem, base: u64, size: u64, max_dev: u32) -> Result<Self, IommuError> {
        let oas = remote.init(base, size, max_dev).ok_or(IommuError::Unsupported("smmuv3: the monitor refused the unit"))?;
        let cds = mem.alloc_page().ok_or(IommuError::NoMemory)?;
        Ok(Smmuv3Remote { remote, mem, pt: PtFormat::new(PtKind::ArmLpae, 4), oas, cds, tags: Tags::new(ASID_FIRST, TAGS) })
    }

    fn cd_of(&self, asid: u16) -> u64 {
        self.cds + (asid - ASID_FIRST) as u64 * CD_BYTES
    }

    fn refused(&self) -> IommuError {
        IommuError::Hardware("smmuv3: the monitor refused the stream")
    }
}

impl<R: Remote> IommuUnit for Smmuv3Remote<R> {
    fn flavour(&self) -> Flavour {
        Flavour::Smmuv3
    }

    fn pt_format(&self) -> PtFormat {
        self.pt
    }

    fn attach(&mut self, dev: u32, mode: DomainMode) -> Result<(), IommuError> {
        match mode {
            DomainMode::Translate { root_pa } => {
                // A stream that translates already points at this descriptor
                // (the ASID is kept): it is refused until the new one is written.
                if self.tags.of(dev).is_some() && !self.remote.attach(dev, RemoteStream::Block) {
                    return Err(self.refused());
                }
                let asid = self.tags.take(dev).ok_or(IommuError::Unsupported("smmuv3: out of ASIDs"))?;
                let cd_pa = self.cd_of(asid);
                // The monitor makes the entry that names this descriptor live
                // only after it is written.
                let cd = encode_cd(root_pa, self.pt.levels, self.oas, asid);
                for (i, w) in cd.iter().enumerate() {
                    wr64(self.mem, cd_pa, i, *w);
                }
                self.mem.clean(cd_pa, CD_BYTES as usize);
                if !self.remote.attach(dev, RemoteStream::Nested(cd_pa)) {
                    return Err(self.refused());
                }
                Ok(())
            }
            _ => {
                let stream = if mode == DomainMode::Block { RemoteStream::Block } else { RemoteStream::S2Only };
                if !self.remote.attach(dev, stream) {
                    return Err(self.refused());
                }
                // The monitor flushed the stream's entry; the ASID it held is free.
                self.tags.release(dev);
                Ok(())
            }
        }
    }

    fn flush(&mut self, dev: u32) -> Result<(), IommuError> {
        if self.tags.of(dev).is_none() {
            return Ok(());
        }
        if self.remote.flush(dev) { Ok(()) } else { Err(self.refused()) }
    }

    fn poll_faults(&mut self, sink: &mut dyn FnMut(DmaFault)) -> usize {
        let mut n = 0;
        while let Some([d0, d2]) = self.remote.event() {
            sink(classify(&EventRecord { event_type: (d0 & 0xff) as u8, stream_id: (d0 >> 32) as u32, input_addr: d2 }));
            n += 1;
        }
        n
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Intel VT-d (spec rev 4.x, legacy mode; QEMU `-device intel-iommu`).
//!
//! A root table of 256 entries (one per PCI bus) points at context tables of
//! 256 entries (one per devfn); a context entry names the second-level page
//! table, or marks the device pass-through. Invalidations use the register
//! interface (context-command and IOTLB-invalidate registers), faults come
//! out of the fault-recording registers; both are polled, interrupts stay
//! masked.
//!
//! A unit in caching mode (`CAP.CM`, QEMU `caching-mode=on`, a virtualised
//! VT-d) may cache not-present entries, so `IoDomain` asks for an IOTLB
//! invalidation on every new mapping, not only on a replaced one.
//!
//! Root entry (128 bits): `P` bit 0, `CTP` 63:12 (low qword). Context entry
//! (128 bits): low `P` 0, `FPD` 1, `TT` 3:2 (0 translate, 2 pass-through),
//! `SLPTPTR` 63:12; high `AW` 2:0 (1 = 39-bit, 2 = 48-bit), `DID` 23:8.

use core::sync::atomic::{fence, Ordering};

use crate::pgtable::{PtFormat, PtKind};
use crate::{
    rd64, wait_for, wr64, DmaFault, DomainMode, FaultKind, Flavour, IommuError, IommuUnit, Mmio, TableMem, POLL,
};

// ---- registers ----
pub const REG_CAP: usize = 0x08;
pub const REG_ECAP: usize = 0x10;
pub const REG_GCMD: usize = 0x18;
pub const REG_GSTS: usize = 0x1c;
pub const REG_RTADDR: usize = 0x20;
pub const REG_CCMD: usize = 0x28;
pub const REG_FSTS: usize = 0x34;
pub const REG_FECTL: usize = 0x38;

pub const GCMD_TE: u32 = 1 << 31;
pub const GCMD_SRTP: u32 = 1 << 30;
pub const GCMD_WBF: u32 = 1 << 27;
pub const GSTS_TES: u32 = 1 << 31;
pub const GSTS_RTPS: u32 = 1 << 30;
pub const GSTS_WBFS: u32 = 1 << 27;
pub const FECTL_IM: u32 = 1 << 31;
pub const FSTS_PFO: u32 = 1 << 0;

pub const CCMD_ICC: u64 = 1 << 63;
pub const CCMD_GLOBAL: u64 = 1 << 61;
pub const IOTLB_IVT: u64 = 1 << 63;
pub const IOTLB_GLOBAL: u64 = 1 << 60;
pub const IOTLB_DRAIN_R: u64 = 1 << 49;
pub const IOTLB_DRAIN_W: u64 = 1 << 48;

pub const ECAP_PT: u64 = 1 << 6;
pub const CAP_RWBF: u64 = 1 << 4;

/// `ECAP.IRO * 16` is the offset of the IOTLB-invalidate register block; the
/// register itself is 8 bytes into it.
pub const fn iotlb_reg(ecap: u64) -> usize {
    (((ecap >> 8) & 0x3ff) as usize) * 16 + 8
}

/// `CAP.FRO * 16`: the offset of the fault-recording registers.
pub const fn frcd_base(cap: u64) -> usize {
    (((cap >> 24) & 0x3ff) as usize) * 16
}

/// `CAP.NFR + 1`: how many fault-recording registers.
pub const fn frcd_count(cap: u64) -> usize {
    (((cap >> 40) & 0xff) as usize) + 1
}

/// `CAP.SAGAW`: bit 1 = 39-bit (3-level), bit 2 = 48-bit (4-level).
pub const fn sagaw(cap: u64) -> u32 {
    ((cap >> 8) & 0x1f) as u32
}

/// Number of domain ids (`CAP.ND`: 16 << 2n).
pub const fn ndoms(cap: u64) -> u32 {
    1u32 << (4 + 2 * (cap & 7) as u32)
}

// ---- tables ----
const ROOT_P: u64 = 1 << 0;
const CTX_P: u64 = 1 << 0;
const CTX_TT_SHIFT: u32 = 2;
pub const TT_TRANSLATE: u64 = 0;
pub const TT_PASSTHROUGH: u64 = 2;
const CTX_AW_MASK: u64 = 7;
const CTX_DID_SHIFT: u32 = 8;
const ADDR_MASK: u64 = !0xfff;

/// The root entry pointing at the context table `ctx_pa`.
pub const fn root_entry(ctx_pa: u64) -> [u64; 2] {
    [(ctx_pa & ADDR_MASK) | ROOT_P, 0]
}

/// The context entry for `mode`. `aw` is the address-width code (1 or 2),
/// `did` the domain id. `Block` is a not-present entry.
pub const fn context_entry(mode: DomainMode, aw: u8, did: u16) -> [u64; 2] {
    let hi = (aw as u64 & CTX_AW_MASK) | ((did as u64) << CTX_DID_SHIFT);
    match mode {
        DomainMode::Block => [0, 0],
        DomainMode::Bypass => [CTX_P | (TT_PASSTHROUGH << CTX_TT_SHIFT), hi],
        DomainMode::Translate { root_pa } => [(root_pa & ADDR_MASK) | CTX_P | (TT_TRANSLATE << CTX_TT_SHIFT), hi],
    }
}

// ---- fault recording ----

/// Fault reasons this crate names (VT-d spec table "Fault Reasons").
pub mod reason {
    pub const ROOT_ENTRY_NOT_PRESENT: u8 = 0x01;
    pub const CONTEXT_ENTRY_NOT_PRESENT: u8 = 0x02;
    pub const CONTEXT_ENTRY_INVALID: u8 = 0x03;
    pub const ADDR_ABOVE_MGAW: u8 = 0x04;
    pub const WRITE_NOT_PERMITTED: u8 = 0x05;
    pub const READ_NOT_PERMITTED: u8 = 0x06;
    pub const ROOT_TABLE_ACCESS: u8 = 0x08;
    pub const CONTEXT_TABLE_ACCESS: u8 = 0x09;
    pub const ROOT_ENTRY_RESERVED: u8 = 0x0a;
    pub const CONTEXT_ENTRY_RESERVED: u8 = 0x0b;
    pub const TT_BLOCKED: u8 = 0x0d;
}

/// A fault-recording register (128 bits), reduced to what the DMA-fault
/// row needs: low qword `FI` 63:12 (the page address), high qword `SID`
/// 15:0, `FR` 39:32, `F` 63.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultRecord {
    pub reason: u8,
    pub source_id: u16,
    pub page_addr: u64,
}

pub const FRCD_F: u64 = 1 << 63;

impl FaultRecord {
    /// `None` when the register holds no fault (`F` clear).
    pub fn decode(lo: u64, hi: u64) -> Option<Self> {
        if hi & FRCD_F == 0 {
            return None;
        }
        Some(FaultRecord { reason: ((hi >> 32) & 0xff) as u8, source_id: (hi & 0xffff) as u16, page_addr: lo & ADDR_MASK })
    }

    /// The two qwords as a unit would hold them (for tests of `decode`).
    pub fn encode(&self) -> (u64, u64) {
        (self.page_addr & ADDR_MASK, FRCD_F | ((self.reason as u64) << 32) | self.source_id as u64)
    }
}

pub fn classify(r: &FaultRecord) -> DmaFault {
    let kind = match r.reason {
        reason::ADDR_ABOVE_MGAW | reason::WRITE_NOT_PERMITTED | reason::READ_NOT_PERMITTED => FaultKind::UnmappedIova,
        reason::ROOT_ENTRY_NOT_PRESENT
        | reason::CONTEXT_ENTRY_NOT_PRESENT
        | reason::CONTEXT_ENTRY_INVALID
        | reason::ROOT_TABLE_ACCESS
        | reason::CONTEXT_TABLE_ACCESS
        | reason::ROOT_ENTRY_RESERVED
        | reason::CONTEXT_ENTRY_RESERVED
        | reason::TT_BLOCKED => FaultKind::BadDeviceEntry,
        other => FaultKind::Other(other as u32),
    };
    DmaFault { device_id: r.source_id as u32, fault_addr: r.page_addr, kind }
}

// ---- the unit ----

/// Domain id of every pass-through device (the IOTLB is not used for them).
const DID_BYPASS: u16 = 1;
/// Translating devices at once; their domain ids are `DID_FIRST + slot`
/// (0 is reserved in caching mode, 1 is `DID_BYPASS`).
const DOMAIN_SLOTS: usize = 16;
const DID_FIRST: u16 = 2;

/// One VT-d remapping unit in legacy mode.
pub struct Vtd<M: Mmio> {
    mmio: M,
    mem: &'static dyn TableMem,
    cap: u64,
    ecap: u64,
    pt: PtFormat,
    aw: u8,
    root: u64,
    gcmd: u32,
    /// The device each translating domain id belongs to; `u32::MAX` is a
    /// free id. Only the first `slots` entries are ids the unit has.
    domains: [u32; DOMAIN_SLOTS],
    slots: usize,
}

impl<M: Mmio> Vtd<M> {
    /// Bring the unit up with an empty root table (every device refused until
    /// `attach`ed) and translation on.
    pub fn new(mmio: M, mem: &'static dyn TableMem) -> Result<Self, IommuError> {
        let cap = mmio.read64(REG_CAP);
        let ecap = mmio.read64(REG_ECAP);
        let (levels, aw) = if sagaw(cap) & 0b010 != 0 {
            (3, 1)
        } else if sagaw(cap) & 0b100 != 0 {
            (4, 2)
        } else {
            return Err(IommuError::Unsupported("vt-d: neither 39-bit nor 48-bit second-level tables"));
        };
        if ecap & ECAP_PT == 0 {
            return Err(IommuError::Unsupported("vt-d: no pass-through translation type"));
        }
        let root = mem.alloc_page().ok_or(IommuError::NoMemory)?;

        // Keep the fault-event interrupt masked: faults are polled.
        mmio.write32(REG_FECTL, FECTL_IM);

        // `CAP.ND` domain ids, less the two this crate keeps for itself.
        let slots = (ndoms(cap) as usize - DID_FIRST as usize).min(DOMAIN_SLOTS);
        let mut unit = Vtd {
            mmio,
            mem,
            cap,
            ecap,
            pt: PtFormat::new(PtKind::Vtd, levels),
            aw,
            root,
            gcmd: 0,
            domains: [u32::MAX; DOMAIN_SLOTS],
            slots,
        };
        unit.write_buffer_flush()?;
        // Root table pointer, legacy mode (TTM = 0).
        unit.mmio.write64(REG_RTADDR, root);
        unit.command(GCMD_SRTP, GSTS_RTPS)?;
        unit.invalidate_all()?;
        unit.gcmd |= GCMD_TE;
        unit.command(0, GSTS_TES)?;
        Ok(unit)
    }

    /// Write `GCMD` (our enabled bits plus the one-shot `extra`) and wait for
    /// `GSTS` to show `status`.
    fn command(&mut self, extra: u32, status: u32) -> Result<(), IommuError> {
        self.mmio.write32(REG_GCMD, self.gcmd | extra);
        if !wait_for(POLL, || self.mmio.read32(REG_GSTS) & status != 0) {
            return Err(IommuError::Timeout("vt-d: global command not acknowledged"));
        }
        Ok(())
    }

    /// Units with `CAP.RWBF` buffer table writes: flush them before the unit reads.
    fn write_buffer_flush(&mut self) -> Result<(), IommuError> {
        if self.cap & CAP_RWBF == 0 {
            return Ok(());
        }
        self.mmio.write32(REG_GCMD, self.gcmd | GCMD_WBF);
        if !wait_for(POLL, || self.mmio.read32(REG_GSTS) & GSTS_WBFS == 0) {
            return Err(IommuError::Timeout("vt-d: write-buffer flush"));
        }
        Ok(())
    }

    /// Global context-cache and IOTLB invalidation through the registers.
    fn invalidate_all(&mut self) -> Result<(), IommuError> {
        self.mmio.write64(REG_CCMD, CCMD_ICC | CCMD_GLOBAL);
        if !wait_for(POLL, || self.mmio.read64(REG_CCMD) & CCMD_ICC == 0) {
            return Err(IommuError::Timeout("vt-d: context-cache invalidation"));
        }
        let reg = iotlb_reg(self.ecap);
        self.mmio.write64(reg, IOTLB_IVT | IOTLB_GLOBAL | IOTLB_DRAIN_R | IOTLB_DRAIN_W);
        if !wait_for(POLL, || self.mmio.read64(reg) & IOTLB_IVT == 0) {
            return Err(IommuError::Timeout("vt-d: IOTLB invalidation"));
        }
        Ok(())
    }

    fn context_slot(&mut self, dev: u32) -> Result<u64, IommuError> {
        if dev > 0xffff {
            return Err(IommuError::DeviceOutOfRange);
        }
        let bus = (dev >> 8) as usize;
        let devfn = (dev & 0xff) as u64;
        let root_lo = rd64(self.mem, self.root, bus * 2);
        let ctx = if root_lo & ROOT_P != 0 {
            root_lo & ADDR_MASK
        } else {
            let ctx = self.mem.alloc_page().ok_or(IommuError::NoMemory)?;
            let e = root_entry(ctx);
            wr64(self.mem, self.root, bus * 2 + 1, e[1]);
            wr64(self.mem, self.root, bus * 2, e[0]);
            self.mem.clean(self.root + bus as u64 * 16, 16);
            ctx
        };
        Ok(ctx + devfn * 16)
    }

    /// The domain id of translating device `dev`: one per device, kept while
    /// the device translates.
    fn domain_of(&mut self, dev: u32) -> Result<u16, IommuError> {
        let slots = &mut self.domains[..self.slots];
        let slot = match slots.iter().position(|&d| d == dev) {
            Some(slot) => slot,
            None => {
                let slot = slots
                    .iter()
                    .position(|&d| d == u32::MAX)
                    .ok_or(IommuError::Unsupported("vt-d: out of domain ids"))?;
                slots[slot] = dev;
                slot
            }
        };
        Ok(DID_FIRST + slot as u16)
    }
}

impl<M: Mmio + Send> IommuUnit for Vtd<M> {
    fn flavour(&self) -> Flavour {
        Flavour::Vtd
    }

    fn pt_format(&self) -> PtFormat {
        self.pt
    }

    fn attach(&mut self, dev: u32, mode: DomainMode) -> Result<(), IommuError> {
        let slot = self.context_slot(dev)?;
        let did = match mode {
            DomainMode::Translate { .. } => self.domain_of(dev)?,
            _ => DID_BYPASS,
        };
        let e = context_entry(mode, self.aw, did);
        // Not present first, so the unit never sees a half-written entry.
        wr64(self.mem, slot, 0, 0);
        wr64(self.mem, slot, 1, e[1]);
        self.mem.clean(slot, 16);
        fence(Ordering::Release);
        wr64(self.mem, slot, 0, e[0]);
        self.mem.clean(slot, 16);
        self.write_buffer_flush()?;
        // The global invalidation also drops the IOTLB entries of the id the
        // device gives up, so the id is free for another device.
        self.invalidate_all()?;
        if !matches!(mode, DomainMode::Translate { .. }) {
            if let Some(d) = self.domains.iter_mut().find(|d| **d == dev) {
                *d = u32::MAX;
            }
        }
        Ok(())
    }

    fn flush(&mut self, _dev: u32) -> Result<(), IommuError> {
        self.invalidate_all()
    }

    fn poll_faults(&mut self, sink: &mut dyn FnMut(DmaFault)) -> usize {
        let base = frcd_base(self.cap);
        let mut n = 0;
        for i in 0..frcd_count(self.cap) {
            let off = base + i * 16;
            let hi = self.mmio.read64(off + 8);
            if hi & FRCD_F == 0 {
                continue;
            }
            let lo = self.mmio.read64(off);
            if let Some(r) = FaultRecord::decode(lo, hi) {
                sink(classify(&r));
                n += 1;
            }
            // Write 1 to F to free the register.
            self.mmio.write64(off + 8, FRCD_F);
        }
        // Overflow (a fault was lost): write 1 to clear.
        if self.mmio.read32(REG_FSTS) & FSTS_PFO != 0 {
            self.mmio.write32(REG_FSTS, FSTS_PFO);
        }
        n
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AMD-Vi (AMD I/O Virtualization Technology spec rev 3.x; QEMU
//! `-device amd-iommu` models interrupt remapping only, so this unit has
//! host tests and no QEMU row).
//!
//! A flat device table of 32-byte entries (DTE) indexed by requester id;
//! a DTE names the I/O page table (host address translation, v1 format) and
//! its depth, or marks the device pass-through. Commands go in a 16-byte-
//! entry command buffer, events come out of a 16-byte-entry event log; both
//! are polled, interrupts stay off.
//!
//! A unit may cache not-present page-table entries (`NpCache`, in the PCI
//! capability, which a register-only driver cannot read), so `IoDomain` asks
//! for an invalidation on every new mapping, not only on a replaced one.
//!
//! DTE qword 0: `V` 0, `TV` 1, `Mode` 11:9 (0 = translation off, n = n-level
//! table), `HostPageTableRoot` 51:12, `IR` 61, `IW` 62. Qword 1: `DomainID`
//! 15:0. Qword 2: `IntCtl` 61:60 (1 = forward interrupts unmapped).
//!
//! An all-zero DTE does NOT block: with `V` clear the unit passes the
//! device's DMA through untranslated (AMD IOMMU spec, DTE `V`). Blocking is `V` and `TV` set with `Mode` 0 and `IR`/`IW`
//! clear: translation off and neither reads nor writes permitted, the entry
//! Linux gives every device at init (`init_device_table_dma`: "make sure any
//! uninitialized DTE will block DMA"). So the bring-up writes it into every
//! entry of a fresh table, and `attach` passes through it, never through
//! zero, while it rewrites an entry. Interrupt requests are not covered:
//! interrupt remapping is out of this crate's scope (`IV` stays clear).

use core::sync::atomic::{fence, Ordering};

use crate::pgtable::{PtFormat, PtKind};
use crate::{
    rd64, wait_for, wr64, DmaFault, DomainMode, FaultKind, Flavour, IommuError, IommuUnit, Mmio, TableMem, Tags, POLL,
    TAGS,
};

// ---- registers ----
pub const REG_DEV_TABLE: usize = 0x0000;
pub const REG_CMD_BUF: usize = 0x0008;
pub const REG_EVT_LOG: usize = 0x0010;
pub const REG_CONTROL: usize = 0x0018;
/// Extended Feature Register.
pub const REG_EFR: usize = 0x0030;
pub const REG_CMD_HEAD: usize = 0x2000;
pub const REG_CMD_TAIL: usize = 0x2008;
pub const REG_EVT_HEAD: usize = 0x2010;
pub const REG_EVT_TAIL: usize = 0x2018;
pub const REG_STATUS: usize = 0x2020;

pub const CTRL_IOMMU_EN: u64 = 1 << 0;
pub const CTRL_EVT_LOG_EN: u64 = 1 << 2;
pub const CTRL_CMD_BUF_EN: u64 = 1 << 12;
/// `EFR.IASup`: the unit implements `INVALIDATE_IOMMU_ALL`.
pub const EFR_IASUP: u64 = 1 << 6;
pub const STATUS_EVT_OVERFLOW: u64 = 1 << 0;
pub const STATUS_EVT_LOG_RUN: u64 = 1 << 3;
pub const STATUS_CMD_BUF_RUN: u64 = 1 << 4;

/// The first domain id of a translating device (id 1 is the pass-through
/// domain, 0 is left alone).
const DOMAIN_FIRST: u16 = 2;
/// Commands issued between two completion waits when the bring-up
/// invalidates entry by entry (the command buffer holds 256).
const INV_BATCH: u32 = 64;

/// Command buffer and event log: 256 entries of 16 bytes (length code 8).
const LOG_LEN_CODE: u64 = 8;
const LOG_LEN_SHIFT: u32 = 56;
const LOG_BYTES: u64 = 4096;
const ENTRY: u64 = 16;

// ---- device table entry ----
pub const DTE_BYTES: u64 = 32;
pub const DTE_V: u64 = 1 << 0;
pub const DTE_TV: u64 = 1 << 1;
const DTE_MODE_SHIFT: u32 = 9;
const DTE_ROOT_MASK: u64 = 0x000f_ffff_ffff_f000;
pub const DTE_IR: u64 = 1 << 61;
pub const DTE_IW: u64 = 1 << 62;
const DTE_INTCTL_PASS: u64 = 1 << 60;
/// Qword 0 of a blocking DTE (`encode_dte`).
const DTE_BLOCK: u64 = DTE_V | DTE_TV;

/// The four qwords of the DTE for `mode`; `levels` is the depth of the table
/// at `root_pa` (1..=6) and `domain_id` its domain. `Block` is `V` and `TV`
/// with translation off and no permission (module doc): the unit refuses
/// every access (IO_PAGE_FAULT); it carries no domain id.
pub const fn encode_dte(mode: DomainMode, levels: u8, domain_id: u16) -> [u64; 4] {
    match mode {
        DomainMode::Block => [DTE_BLOCK, 0, 0, 0],
        DomainMode::Bypass => [
            DTE_V | DTE_TV | DTE_IR | DTE_IW,
            domain_id as u64,
            DTE_INTCTL_PASS,
            0,
        ],
        DomainMode::Translate { root_pa } => [
            DTE_V
                | DTE_TV
                | ((levels as u64 & 7) << DTE_MODE_SHIFT)
                | (root_pa & DTE_ROOT_MASK)
                | DTE_IR
                | DTE_IW,
            domain_id as u64,
            DTE_INTCTL_PASS,
            0,
        ],
    }
}

// ---- commands (two 64-bit words: dwords 0-1 and 2-3) ----
const OP_COMPLETION_WAIT: u64 = 0x01;
const OP_INV_DEV_ENTRY: u64 = 0x02;
const OP_INV_IOMMU_PAGES: u64 = 0x03;
const OP_INV_ALL: u64 = 0x08;
const OP_SHIFT: u32 = 28 + 32; // opcode is bits 31:28 of dword 1

/// `INVALIDATE_DEVTAB_ENTRY` for requester id `dev`.
pub const fn cmd_inv_dev_entry(dev: u32) -> [u64; 2] {
    [(dev as u64 & 0xffff) | (OP_INV_DEV_ENTRY << OP_SHIFT), 0]
}

/// `INVALIDATE_IOMMU_PAGES` for every page of domain `domain_id` (`S` set,
/// address all ones, `PDE` set so the page-directory caches go too).
pub const fn cmd_inv_pages_all(domain_id: u16) -> [u64; 2] {
    // dword 1: DomainID 15:0 and the opcode; dwords 2-3: the address with
    // S (bit 0) and PDE (bit 1) in the low bits of dword 2.
    let addr = 0x7fff_ffff_ffff_f000u64;
    [((domain_id as u64) << 32) | (OP_INV_IOMMU_PAGES << OP_SHIFT), addr | 0b11]
}

/// `INVALIDATE_IOMMU_ALL`.
pub const fn cmd_inv_all() -> [u64; 2] {
    [OP_INV_ALL << OP_SHIFT, 0]
}

/// `COMPLETION_WAIT` that stores `value` at the 8-byte aligned `store_pa`
/// once every earlier command has completed.
pub const fn cmd_completion_wait(store_pa: u64, value: u64) -> [u64; 2] {
    // dword 0: store address bits 31:3 and S (bit 0); dword 1: address bits
    // 51:32 and the opcode; dwords 2-3: the data.
    let d0 = (store_pa & 0xffff_fff8) | 1;
    let d1 = ((store_pa >> 32) & 0xf_ffff) | (OP_COMPLETION_WAIT << 28);
    [d0 | (d1 << 32), value]
}

// ---- events ----
pub mod event {
    pub const ILLEGAL_DEV_TABLE_ENTRY: u8 = 0x1;
    pub const IO_PAGE_FAULT: u8 = 0x2;
    pub const DEV_TAB_HW_ERROR: u8 = 0x3;
    pub const PAGE_TAB_HW_ERROR: u8 = 0x4;
}

/// An event-log entry (16 bytes), reduced to what the DMA-fault row needs:
/// `DeviceID` in dword 0 bits 15:0, the type in dword 1 bits 31:28, the
/// faulting address in dwords 2-3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventRecord {
    pub event_type: u8,
    pub device_id: u16,
    pub address: u64,
}

impl EventRecord {
    pub fn decode(q0: u64, q1: u64) -> Self {
        EventRecord { event_type: ((q0 >> 60) & 0xf) as u8, device_id: (q0 & 0xffff) as u16, address: q1 }
    }

    /// The two qwords a unit logs (for tests of `decode`).
    pub fn encode(&self) -> (u64, u64) {
        ((self.device_id as u64) | ((self.event_type as u64) << 60), self.address)
    }
}

pub fn classify(r: &EventRecord) -> DmaFault {
    let kind = match r.event_type {
        event::IO_PAGE_FAULT => FaultKind::UnmappedIova,
        event::ILLEGAL_DEV_TABLE_ENTRY | event::DEV_TAB_HW_ERROR => FaultKind::BadDeviceEntry,
        other => FaultKind::Other(other as u32),
    };
    DmaFault { device_id: r.device_id as u32, fault_addr: r.address, kind }
}

// ---- the unit ----

/// One AMD-Vi unit with a flat device table.
pub struct AmdVi<M: Mmio> {
    mmio: M,
    mem: &'static dyn TableMem,
    pt: PtFormat,
    devtab: u64,
    max_dev: u32,
    cmd: u64,
    cmd_tail: u64,
    evt: u64,
    evt_head: u64,
    sem: u64,
    sem_seq: u64,
    /// The domain id of each translating device.
    tags: Tags,
}

impl<M: Mmio> AmdVi<M> {
    /// Bring the unit up for requester ids `0..=max_dev`. Every device is
    /// blocked until `attach`ed: every entry of the table, those past
    /// `max_dev` in its last page included, starts as a blocking DTE.
    pub fn new(mmio: M, mem: &'static dyn TableMem, max_dev: u32) -> Result<Self, IommuError> {
        if max_dev > 0xffff {
            return Err(IommuError::DeviceOutOfRange);
        }
        let bytes = ((max_dev as u64 + 1) * DTE_BYTES).next_multiple_of(4096);
        let devtab = mem
            .alloc_aligned(bytes as usize, (bytes as usize).next_power_of_two())
            .ok_or(IommuError::NoMemory)?;
        for i in 0..bytes / DTE_BYTES {
            wr64(mem, devtab + i * DTE_BYTES, 0, DTE_BLOCK);
        }
        mem.clean(devtab, bytes as usize);
        let cmd = mem.alloc_page().ok_or(IommuError::NoMemory)?;
        let evt = mem.alloc_page().ok_or(IommuError::NoMemory)?;
        let sem = mem.alloc_page().ok_or(IommuError::NoMemory)?;
        // The unit writes the event log and the semaphore: no dirty zero
        // lines over its records.
        mem.clean(evt, 4096);
        mem.clean(sem, 4096);
        let efr = mmio.read64(REG_EFR);

        // Device table: base address, size in 4 KiB pages minus one.
        mmio.write64(REG_DEV_TABLE, (devtab & DTE_ROOT_MASK) | (bytes / 4096 - 1));
        mmio.write64(REG_CMD_BUF, (cmd & DTE_ROOT_MASK) | (LOG_LEN_CODE << LOG_LEN_SHIFT));
        mmio.write64(REG_CMD_HEAD, 0);
        mmio.write64(REG_CMD_TAIL, 0);
        mmio.write64(REG_EVT_LOG, (evt & DTE_ROOT_MASK) | (LOG_LEN_CODE << LOG_LEN_SHIFT));
        mmio.write64(REG_EVT_HEAD, 0);
        mmio.write64(REG_EVT_TAIL, 0);
        // Translation on with the buffers, not after them: a unit may run its
        // command buffer only while it is enabled (QEMU's model does), and the
        // table already blocks every device, so nothing passes before the
        // invalidation below drops what the unit cached from before.
        mmio.write64(REG_CONTROL, CTRL_CMD_BUF_EN | CTRL_EVT_LOG_EN | CTRL_IOMMU_EN);
        if !wait_for(POLL, || {
            mmio.read64(REG_STATUS) & (STATUS_CMD_BUF_RUN | STATUS_EVT_LOG_RUN) == STATUS_CMD_BUF_RUN | STATUS_EVT_LOG_RUN
        }) {
            return Err(IommuError::Timeout("amd-vi: command buffer and event log did not start"));
        }

        let mut unit = AmdVi {
            mmio,
            mem,
            pt: PtFormat::new(PtKind::AmdVi, 4),
            devtab,
            max_dev,
            cmd,
            cmd_tail: 0,
            evt,
            evt_head: 0,
            sem,
            sem_seq: 0,
            tags: Tags::new(DOMAIN_FIRST, TAGS),
        };
        unit.invalidate_all(efr & EFR_IASUP != 0)?;
        Ok(unit)
    }

    fn command(&mut self, cmd: [u64; 2]) -> Result<(), IommuError> {
        let slot = (self.cmd_tail / ENTRY) as usize * 2;
        wr64(self.mem, self.cmd, slot, cmd[0]);
        wr64(self.mem, self.cmd, slot + 1, cmd[1]);
        self.mem.clean(self.cmd + self.cmd_tail, ENTRY as usize);
        self.cmd_tail = (self.cmd_tail + ENTRY) % LOG_BYTES;
        fence(Ordering::SeqCst);
        self.mmio.write64(REG_CMD_TAIL, self.cmd_tail);
        Ok(())
    }

    /// Drop whatever the unit cached about the device table and the I/O page
    /// tables. `INVALIDATE_IOMMU_ALL` exists only when `EFR.IASup` is set
    /// (anything else is ILLEGAL_COMMAND); without it, every device table
    /// entry and every domain id this crate can use is invalidated one by one.
    fn invalidate_all(&mut self, ia_sup: bool) -> Result<(), IommuError> {
        if ia_sup {
            self.command(cmd_inv_all())?;
            return self.wait_complete();
        }
        let mut batch = 0;
        let pages = (1..DOMAIN_FIRST + TAGS as u16).map(cmd_inv_pages_all);
        let devs = (0..=self.max_dev).map(cmd_inv_dev_entry);
        for cmd in devs.chain(pages) {
            self.command(cmd)?;
            batch += 1;
            if batch == INV_BATCH {
                self.wait_complete()?;
                batch = 0;
            }
        }
        self.wait_complete()
    }

    /// `COMPLETION_WAIT`, then wait for the unit to store the sequence number.
    fn wait_complete(&mut self) -> Result<(), IommuError> {
        self.sem_seq += 1;
        let seq = self.sem_seq;
        self.command(cmd_completion_wait(self.sem, seq))?;
        let mem = self.mem;
        let sem = self.sem;
        if !wait_for(POLL, || {
            mem.invalidate(sem, 8);
            rd64(mem, sem, 0) == seq
        }) {
            return Err(IommuError::Timeout("amd-vi: command completion"));
        }
        Ok(())
    }

    /// Device `dev` stopped translating: drop what the unit cached for its
    /// domain id and free the id for another device.
    fn release_domain(&mut self, dev: u32) -> Result<(), IommuError> {
        let Some(did) = self.tags.of(dev) else {
            return Ok(());
        };
        self.command(cmd_inv_pages_all(did))?;
        self.wait_complete()?;
        self.tags.release(dev);
        Ok(())
    }
}

impl<M: Mmio + Send> IommuUnit for AmdVi<M> {
    fn flavour(&self) -> Flavour {
        Flavour::AmdVi
    }

    fn pt_format(&self) -> PtFormat {
        self.pt
    }

    fn attach(&mut self, dev: u32, mode: DomainMode) -> Result<(), IommuError> {
        if dev > self.max_dev {
            return Err(IommuError::DeviceOutOfRange);
        }
        let did = match mode {
            DomainMode::Translate { .. } => {
                self.tags.take(dev).ok_or(IommuError::Unsupported("amd-vi: out of domains"))?
            }
            _ => 1,
        };
        let dte = encode_dte(mode, self.pt.levels, did);
        let slot = self.devtab + dev as u64 * DTE_BYTES;
        // Blocking first (an invalid entry would pass DMA through), then the
        // body, then the qword that carries the mode.
        wr64(self.mem, slot, 0, DTE_BLOCK);
        for i in 1..4 {
            wr64(self.mem, slot, i, dte[i]);
        }
        self.mem.clean(slot, DTE_BYTES as usize);
        fence(Ordering::Release);
        wr64(self.mem, slot, 0, dte[0]);
        self.mem.clean(slot, 8);
        self.command(cmd_inv_dev_entry(dev))?;
        self.wait_complete()?;
        match mode {
            DomainMode::Translate { .. } => Ok(()),
            _ => self.release_domain(dev),
        }
    }

    fn flush(&mut self, dev: u32) -> Result<(), IommuError> {
        // Only a translating device has a domain of its own to flush.
        let Some(did) = self.tags.of(dev) else {
            return Ok(());
        };
        self.command(cmd_inv_pages_all(did))?;
        self.wait_complete()
    }

    fn poll_faults(&mut self, sink: &mut dyn FnMut(DmaFault)) -> usize {
        let mut n = 0;
        // The unit advances the tail; the head is ours.
        while self.evt_head != self.mmio.read64(REG_EVT_TAIL) % LOG_BYTES {
            self.mem.invalidate(self.evt + self.evt_head, ENTRY as usize);
            let q0 = rd64(self.mem, self.evt + self.evt_head, 0);
            let q1 = rd64(self.mem, self.evt + self.evt_head, 1);
            // q0 is dwords 0-1: the type is bits 31:28 of dword 1 = bits 63:60.
            sink(classify(&EventRecord::decode(q0, q1)));
            n += 1;
            self.evt_head = (self.evt_head + ENTRY) % LOG_BYTES;
            self.mmio.write64(REG_EVT_HEAD, self.evt_head);
        }
        if self.mmio.read64(REG_STATUS) & STATUS_EVT_OVERFLOW != 0 {
            self.mmio.write64(REG_STATUS, STATUS_EVT_OVERFLOW);
        }
        n
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! APLIC (Advanced Platform-Level Interrupt Controller) driver, MSI
//! delivery mode — RISC-V AIA, RFC-0046 stage 1a.
//!
//! Routes wired sources (UART, virtio-mmio lines) as MSIs into the S-level
//! IMSIC (`crate::imsic`). Direct (IDC) delivery mode is not implemented:
//! QEMU `virt,aia=aplic-imsic` gives S-mode an MSI-mode domain.
//!
//! Only the S-domain is touched. `virt,aia=aplic-imsic` has two
//! `riscv,aplic` nodes: the M-level root (has `riscv,children` and
//! `riscv,delegation`) and the S-level child. M-mode firmware owns the
//! root: it delegates the sources to the child and programs the root's
//! `smsiaddrcfg`, which is where the S-domain's MSI target addresses come
//! from — S-mode cannot write it. A source the firmware did not delegate
//! reads back 0 from the child's `sourcecfg`; [`Aplic::wire_source`]
//! reports that instead of assuming the write took.
//!
//! Register offsets (AIA spec APLIC chapter; Linux
//! `include/linux/irqchip/riscv-aplic.h`): `domaincfg` 0x0,
//! `sourcecfg[i]` 0x4 + 4*(i-1), `setienum` 0x1edc, `clrienum` 0x1fdc,
//! `setipnum_le` 0x2000, `target[i]` 0x3004 + 4*(i-1).

const REG_DOMAINCFG: usize = 0x0000;
const REG_SOURCECFG_BASE: usize = 0x0004;
const REG_SETIENUM: usize = 0x1edc;
const REG_CLRIENUM: usize = 0x1fdc;
const REG_SETIPNUM_LE: usize = 0x2000;
const REG_TARGET_BASE: usize = 0x3004;

/// `domaincfg.IE` — domain-wide interrupt enable.
const DOMAINCFG_IE: u32 = 1 << 8;
/// `domaincfg.DM` — 1 selects MSI delivery mode.
const DOMAINCFG_DM: u32 = 1 << 2;

/// `sourcecfg.SM` values used here. 0 = inactive, 1 = detached,
/// 4/5 = edge rising/falling, 6/7 = level high/low.
pub const SOURCECFG_SM_INACTIVE: u32 = 0;
pub const SOURCECFG_SM_EDGE_RISE: u32 = 4;
pub const SOURCECFG_SM_LEVEL_HIGH: u32 = 6;

const TARGET_HART_IDX_SHIFT: u32 = 18;
const TARGET_HART_IDX_MASK: u32 = 0x3fff;
const TARGET_EIID_MASK: u32 = 0x7ff;

/// MSI-mode `target[i]` value: hart index in bits 31:18, guest index
/// (bits 17:12) 0, EIID in bits 10:0.
pub const fn msi_target(hart: u32, eiid: u32) -> u32 {
    ((hart & TARGET_HART_IDX_MASK) << TARGET_HART_IDX_SHIFT) | (eiid & TARGET_EIID_MASK)
}

/// One S-domain APLIC in MSI delivery mode.
pub struct Aplic {
    base: usize,
}

impl Aplic {
    /// `base` must be the S-domain APLIC's MMIO base, mapped in the kernel
    /// page tables before any method is called.
    pub const fn new(base: usize) -> Self {
        Aplic { base }
    }

    fn write(&self, off: usize, val: u32) {
        // SAFETY: `base` is the mapped S-domain APLIC (constructor
        // contract); every offset used here is inside its 32 KiB window.
        unsafe { core::ptr::write_volatile((self.base + off) as *mut u32, val) }
    }

    fn read(&self, off: usize) -> u32 {
        // SAFETY: as for `write`.
        unsafe { core::ptr::read_volatile((self.base + off) as *const u32) }
    }

    /// Select MSI delivery and enable the domain. Runs before any source
    /// is configured.
    pub fn init(&self) {
        self.write(REG_DOMAINCFG, DOMAINCFG_IE | DOMAINCFG_DM);
    }

    /// Configure wired `source` (1-based) as level-high, target identity
    /// `eiid` on `hart`, and enable it. Returns the `sourcecfg` value read
    /// back: `SOURCECFG_SM_LEVEL_HIGH` when it took, 0 when the firmware
    /// did not delegate this source to the S-domain.
    pub fn wire_source(&self, source: u32, hart: u32, eiid: u32) -> u32 {
        self.wire_source_sm(source, hart, eiid, SOURCECFG_SM_LEVEL_HIGH)
    }

    /// [`Self::wire_source`] with source mode `sm` (`SOURCECFG_SM_*`): a
    /// ring-3 line takes its trigger from the device tree (wave 9 IRQ4).
    /// Returns the `sourcecfg` read-back: `sm` when it took.
    pub fn wire_source_sm(&self, source: u32, hart: u32, eiid: u32, sm: u32) -> u32 {
        if source == 0 {
            return 0;
        }
        let idx = (source - 1) as usize;
        self.write(REG_SOURCECFG_BASE + 4 * idx, sm);
        let readback = self.read(REG_SOURCECFG_BASE + 4 * idx);
        self.write(REG_TARGET_BASE + 4 * idx, msi_target(hart, eiid));
        self.write(REG_SETIENUM, source);
        readback
    }

    /// Enable (`setienum`) or disable (`clrienum`) `source`, leaving its
    /// configuration and target alone: the ring-3 mask-until-ACK switch.
    pub fn set_enabled(&self, source: u32, on: bool) {
        if source == 0 {
            return;
        }
        self.write(if on { REG_SETIENUM } else { REG_CLRIENUM }, source);
    }

    /// Disable and deactivate `source`.
    pub fn unwire_source(&self, source: u32) {
        if source == 0 {
            return;
        }
        self.write(REG_CLRIENUM, source);
        self.write(REG_SOURCECFG_BASE + 4 * (source - 1) as usize, SOURCECFG_SM_INACTIVE);
    }

    /// Re-arm a level-sensitive source after its handler ran. In MSI mode
    /// the APLIC clears a source's pending bit when it forwards the MSI,
    /// and a line that stays asserted does not set it again by itself.
    /// Writing the source number to `setipnum_le` sets it again only if
    /// the line is still asserted (AIA spec, "special consideration for
    /// level-sensitive interrupt sources"; Linux `aplic_msi_irq_eoi`).
    pub fn retrigger_level(&self, source: u32) {
        self.write(REG_SETIPNUM_LE, source);
    }
}

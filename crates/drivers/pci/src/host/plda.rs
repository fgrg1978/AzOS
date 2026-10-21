// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! StarFive JH7110 PCIe (PLDA XpressRICH3-AXI root port), the VisionFive 2.
//!
//! Two register blocks: the PLDA bridge (DT `reg` "apb": identity, interrupt
//! and address-translation (ATR) registers) and the SoC's STG syscon, where
//! the root-port mode and the link status live. Configuration space is the
//! ECAM-shaped "cfg" window, made reachable by ATR entry 0 (a
//! configuration-type translation of the `cfg` AXI range to PCI address 0).
//! Memory windows are further ATR entries: AXI slave table for outbound, the
//! "PCIe master" table for inbound.
//!
//! The ATR layout and every register below are from `pcie-plda.h`,
//! `pcie-plda-host.c` and `pcie-starfive.c`; the inbound table's stride and
//! translation-parameter value are the two the sources do not settle
//! (`[verify]`). The VisionFive 2 needs the STG offsets of controller 0 or 1.

use super::*;

/// STG syscon block of PCIe controller 0 / 1 (picked by the PCI domain).
pub const STG_PCIE0_BASE: u32 = 0x48;
pub const STG_PCIE1_BASE: u32 = 0x1f8;

/// Link wait: Linux checks 10 times, 90 ms apart.
pub const DEFAULT_LINK_TIMEOUT_US: u32 = 900_000;
const LINK_STEP_US: u32 = 90_000;

/// Translation entries per table the block implements; `[verify]` against
/// the JH7110 TRM (the Linux loop is unbounded; the JH7110 DT needs 3).
pub const MAX_ATR: usize = 8;

/// What `init` needs from the board.
#[derive(Clone, Copy, Debug)]
pub struct PldaConfig<'a> {
    /// [`STG_PCIE0_BASE`] or [`STG_PCIE1_BASE`].
    pub stg_base: u32,
    /// The "cfg" `reg` range: CPU address and size of the ECAM window.
    pub cfg_base: u64,
    pub cfg_size: u64,
    pub outbound: &'a [OutboundWindow],
    /// DT `dma-ranges`. Empty keeps the block's reset translation, which is
    /// what Linux relies on for this SoC.
    pub inbound: &'a [InboundWindow],
    /// PCI bus address endpoints write MSIs to: where the bridge's own APB
    /// block (the DT `reg` "apb" range) appears on the PCI side, through an
    /// inbound window in `inbound` or one the board keeps from reset. `init`
    /// programs it into IMSI_ADDR (only the low 32 bits exist there), so it
    /// must lie below 4 GiB and be dword-aligned.
    pub msi_doorbell: u64,
    pub link_timeout_us: u32,
}

// --- STG syscon, relative to the controller's block ---
const STG_AR: u32 = 0x78;
const STG_AR_MASK: u32 = 0x007f_ff00; // GENMASK(22, 8)
const STG_AR_PHY_SHIFT: u32 = 17; // GENMASK(20, 17)
const STG_AW: u32 = 0x7c;
const STG_AW_MASK: u32 = 0x7fff; // GENMASK(14, 0)
const STG_AW_PHY_SHIFT: u32 = 9; // GENMASK(12, 9)
const STG_CLKREQ: u32 = 1 << 22;
const STG_CKREF_SRC_MASK: u32 = 0x000c_0000; // GENMASK(19, 18)
const STG_CKREF_SRC_VAL: u32 = 2 << 18;
const STG_RP_NEP: u32 = 0xe8;
const STG_K_RP_NEP: u32 = 1 << 8;
const STG_LNKSTA: u32 = 0x170;
const STG_DATA_LINK_ACTIVE: u32 = 1 << 5;
/// Physical functions of the core (all but 0 are disabled).
const FUNC_NUM: u32 = 4;

// --- PLDA bridge registers (Region::Apb) ---
const GEN_SETTINGS: u32 = 0x80;
const RP_ENABLE: u32 = 1;
const PCIE_PCI_IDS_DW1: u32 = 0x9c;
const IDS_CLASS_CODE_SHIFT: u32 = 16;
const IDS_CLASS_MASK: u32 = 0xffff_ff00; // CLASS_CODE_ID_MASK
const CLASS_BRIDGE_PCI: u32 = 0x0604;
const PCI_MISC: u32 = 0xb4;
const PHY_FUNCTION_DIS: u32 = 1 << 15;
const PCIE_WINROM: u32 = 0xfc;
const PREF_MEM_WIN_64_SUPPORT: u32 = 1 << 3;
const PMSG_SUPPORT_RX: u32 = 0x3f0;
const PMSG_LTR_SUPPORT: u32 = 1 << 2;
/// The bridge's own root-port config space; BAR0 and BAR1 sit at +0x10, +0x14.
const CONFIG_SPACE_ADDR_OFFSET: u32 = 0x1000;
const ISTATUS_LOCAL: u32 = 0x184;
const IMSI_ADDR: u32 = 0x190;
const ISTATUS_MSI: u32 = 0x194;
const PM_MSI_INT_MSI_MASK: u32 = 0x1000_0000;
const MSI_VECTORS: u32 = 32;

// --- address translation tables (Region::Apb) ---
/// PCIe master table (PCI -> AXI): inbound. Entry stride `[verify]`.
const ATR_PCIE_WIN0: u32 = 0x600;
/// AXI slave table (AXI -> PCI): outbound and config.
const ATR_AXI4_SLV0: u32 = 0x800;
const ATR_ENTRY_SIZE: u32 = 0x20;
const ATR_SRC_PARAM: u32 = 0x00;
const ATR_SRC_ADDR: u32 = 0x04;
const ATR_TRSL_ADDR_LSB: u32 = 0x08;
const ATR_TRSL_ADDR_UDW: u32 = 0x0c;
const ATR_TRSL_PARAM: u32 = 0x10;
const ATR_SIZE_SHIFT: u32 = 1;
const ATR_IMPL_ENABLE: u32 = 1;
const PCIE_TX_RX_INTERFACE: u32 = 0;
const PCIE_CONFIG_INTERFACE: u32 = 1;
/// Inbound translation target: the AXI4 master 0 port. `[verify]`
const TRSL_ID_AXI4_MASTER_0: u32 = 4;

fn pow2_window(base_a: u64, base_b: u64, size: u64) -> bool {
    matches!(log2_exact(size), Some(12..=62)) && base_a % size == 0 && base_b % size == 0 && base_a.checked_add(size).is_some() && base_b.checked_add(size).is_some()
}

fn validate(cfg: &PldaConfig) -> Result<(), HostError> {
    if !pow2_window(cfg.cfg_base, 0, cfg.cfg_size) {
        return Err(HostError::BadConfigWindow);
    }
    if cfg.msi_doorbell > u32::MAX as u64 || cfg.msi_doorbell & 3 != 0 {
        return Err(HostError::BadMsiDoorbell);
    }
    // Entry 0 of the outbound table is the config window.
    if cfg.outbound.len() + 1 > MAX_ATR {
        return Err(HostError::TooManyOutbound);
    }
    if cfg.inbound.len() > MAX_ATR {
        return Err(HostError::TooManyInbound);
    }
    for (i, w) in cfg.outbound.iter().enumerate() {
        if !pow2_window(w.window.cpu_base, w.window.bus_base, w.window.size) {
            return Err(HostError::BadOutbound(i));
        }
    }
    for (i, w) in cfg.inbound.iter().enumerate() {
        if !pow2_window(w.bus_base, w.cpu_base, w.size) {
            return Err(HostError::BadInbound(i));
        }
    }
    Ok(())
}

/// Program one translation entry: addresses `[src, src + size)` become
/// `[trsl, trsl + size)`. `validate` has checked `size`.
fn set_atr_entry<B: Bus>(bus: &B, table: u32, index: u32, src: u64, trsl: u64, size: u64, trsl_param: u32) {
    let e = table + index * ATR_ENTRY_SIZE;
    let atr_size = log2_exact(size).unwrap_or(12) - 1;
    bus.write32(Region::Apb, e + ATR_TRSL_PARAM, trsl_param);
    bus.write32(Region::Apb, e + ATR_SRC_PARAM, (src as u32 & !0xfff) | (atr_size << ATR_SIZE_SHIFT) | ATR_IMPL_ENABLE);
    bus.write32(Region::Apb, e + ATR_SRC_ADDR, (src >> 32) as u32);
    bus.write32(Region::Apb, e + ATR_TRSL_ADDR_LSB, trsl as u32);
    bus.write32(Region::Apb, e + ATR_TRSL_ADDR_UDW, (trsl >> 32) as u32);
}

/// Bring the root port up, wait for the link, then open the windows (the
/// order of `starfive_pcie_host_init` and `plda_pcie_host_init`). On
/// [`HostError::LinkDown`] PERST# is asserted again and no ATR entry was
/// written.
pub fn init<B: Bus + Perst>(bus: &B, cfg: &PldaConfig) -> Result<HostReport, HostError> {
    validate(cfg)?;
    let stg = cfg.stg_base;

    // Root-port mode and reference clock, in the SoC syscon.
    update_bits(bus, Region::Stg, stg + STG_RP_NEP, STG_K_RP_NEP, STG_K_RP_NEP);
    update_bits(bus, Region::Stg, stg + STG_AW, STG_CKREF_SRC_MASK, STG_CKREF_SRC_VAL);
    update_bits(bus, Region::Stg, stg + STG_AW, STG_CLKREQ, STG_CLKREQ);

    bus.set_perst(true);

    // Disable physical functions 1..3: select each, set the disable bit.
    for f in 1..FUNC_NUM {
        update_bits(bus, Region::Stg, stg + STG_AR, STG_AR_MASK, f << STG_AR_PHY_SHIFT);
        update_bits(bus, Region::Stg, stg + STG_AW, STG_AW_MASK, f << STG_AW_PHY_SHIFT);
        update_bits(bus, Region::Apb, PCI_MISC, PHY_FUNCTION_DIS, PHY_FUNCTION_DIS);
    }
    update_bits(bus, Region::Stg, stg + STG_AR, STG_AR_MASK, 0);
    update_bits(bus, Region::Stg, stg + STG_AW, STG_AW_MASK, 0);

    update_bits(bus, Region::Apb, GEN_SETTINGS, RP_ENABLE, RP_ENABLE);
    bus.write32(Region::Apb, CONFIG_SPACE_ADDR_OFFSET + crate::OFF_BAR0 as u32, 0);
    bus.write32(Region::Apb, CONFIG_SPACE_ADDR_OFFSET + crate::OFF_BAR0 as u32 + 4, 0);
    update_bits(bus, Region::Apb, PCIE_PCI_IDS_DW1, IDS_CLASS_MASK, CLASS_BRIDGE_PCI << IDS_CLASS_CODE_SHIFT);
    update_bits(bus, Region::Apb, PMSG_SUPPORT_RX, PMSG_LTR_SUPPORT, 0);
    update_bits(bus, Region::Apb, PCIE_WINROM, PREF_MEM_WIN_64_SUPPORT, PREF_MEM_WIN_64_SUPPORT);

    // PERST# asserted for at least 100 ms, released, 100 ms before the first
    // config access, then the link.
    bus.delay_us(PERST_HOLD_US);
    bus.set_perst(false);
    bus.delay_us(RESET_CONFIG_WAIT_US);
    let link_wait_us = match wait_link(bus, checks_for(cfg.link_timeout_us, LINK_STEP_US), LINK_STEP_US, || {
        bus.read32(Region::Stg, stg + STG_LNKSTA) & STG_DATA_LINK_ACTIVE != 0
    }) {
        Ok(w) => w,
        Err(waited_us) => {
            bus.set_perst(true);
            return Err(HostError::LinkDown { waited_us });
        }
    };

    // Entry 0: the ECAM window, a configuration-type translation to PCI 0.
    set_atr_entry(bus, ATR_AXI4_SLV0, 0, cfg.cfg_base, 0, cfg.cfg_size, PCIE_CONFIG_INTERFACE);
    for (i, w) in cfg.outbound.iter().enumerate() {
        let HostWindow { cpu_base, bus_base, size } = w.window;
        set_atr_entry(bus, ATR_AXI4_SLV0, i as u32 + 1, cpu_base, bus_base, size, PCIE_TX_RX_INTERFACE);
    }
    for (i, w) in cfg.inbound.iter().enumerate() {
        set_atr_entry(bus, ATR_PCIE_WIN0, i as u32, w.bus_base, w.cpu_base, w.size, TRSL_ID_AXI4_MASTER_0);
    }
    // The doorbell endpoints target: a PCI bus address, not a register offset.
    bus.write32(Region::Apb, IMSI_ADDR, cfg.msi_doorbell as u32);

    Ok(HostReport {
        config: ConfigAccess::Ecam { size: cfg.cfg_size },
        windows: firmware_windows(cfg.outbound),
        // The doorbell is the bus address the bridge's APB block answers at
        // (`cfg.msi_doorbell`, now in IMSI_ADDR); vector n is data n. The
        // unmask bit in IMASK_LOCAL is the irqchip's. [verify]
        msi: Some(MsiHookup {
            doorbell: cfg.msi_doorbell,
            data_base: 0,
            vectors: MSI_VECTORS,
            status_off: ISTATUS_MSI,
            ack_off: ISTATUS_MSI,
            summary: Some((ISTATUS_LOCAL, PM_MSI_INT_MSI_MASK)),
        }),
        link_wait_us,
    })
}

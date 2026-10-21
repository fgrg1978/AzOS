// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Broadcom brcmstb PCIe root complex as the BCM2712 (Raspberry Pi 5) has it:
//! the controller that leads to the RP1 south bridge.
//!
//! One register block does everything: the controller's own registers, the
//! root complex's config space (at offset 0), and an index/data pair for the
//! config space behind it ([`ConfigAccess::Indirect`]). Outbound windows are
//! MiB-granular base/limit registers; inbound windows are "RC BARs" (a bus
//! base and a size code) with a UBUS remap register that gives the CPU
//! address. Offsets are the BCM7712 table of `pcie-brcmstb.c`, which the
//! BCM2712 uses; the MDIO tuning words are the BCM2712 `post_setup` ones.
//!
//! Not done here (platform glue, before `init`): the `rescal` calibration and
//! the bridge/`swinit` reset controller when the DT names one, clocks, and the
//! L1SS / SSC / `num-lanes` tuning, none of which gate link-up.

use super::*;

/// Link training budget: Linux polls 100 ms in 5 ms steps.
pub const DEFAULT_LINK_TIMEOUT_US: u32 = 100_000;
const LINK_STEP_US: u32 = 5_000;

/// Outbound windows the controller has (`BRCM_NUM_PCIE_OUT_WINS`).
pub const MAX_OUTBOUND: usize = 4;
/// Inbound windows of the BCM2712 (`num_inbound_wins`).
pub const MAX_INBOUND: usize = 10;

/// What `init` needs from the board: the DT `ranges` and `dma-ranges`.
#[derive(Clone, Copy, Debug)]
pub struct BrcmConfig<'a> {
    pub outbound: &'a [OutboundWindow],
    pub inbound: &'a [InboundWindow],
    pub link_timeout_us: u32,
}

// --- register map (BCM7712 offsets) ---
const RC_CFG_VENDOR_SPECIFIC_REG1: u32 = 0x0188;
const ENDIAN_MODE_BAR2_MASK: u32 = 0xc;
const RC_CFG_PRIV1_ID_VAL3: u32 = 0x043c;
const CLASS_CODE_MASK: u32 = 0xff_ffff;
const CLASS_BRIDGE_PCI_NORMAL: u32 = 0x06_0400;
const RC_DL_MDIO_ADDR: u32 = 0x1100;
const RC_DL_MDIO_WR_DATA: u32 = 0x1104;
const MDIO_PORT_SHIFT: u32 = 16;
const MDIO_REGAD_MASK: u32 = 0xffff;
const MDIO_DATA_DONE: u32 = 0x8000_0000;
const RC_PL_PHY_CTL_15: u32 = 0x184c;
const PHY_CTL_15_PM_CLK_PERIOD_MASK: u32 = 0xff;
const MISC_CTRL: u32 = 0x4008;
const MISC_CTRL_RCB_64B_MODE: u32 = 0x80;
const MISC_CTRL_RCB_MPS_MODE: u32 = 0x400;
const MISC_CTRL_SCB_ACCESS_EN: u32 = 0x1000;
const MISC_CTRL_CFG_READ_UR_MODE: u32 = 0x2000;
const MISC_CTRL_MAX_BURST_MASK: u32 = 0x30_0000;
const MISC_CTRL_MAX_BURST_512: u32 = 2 << 20;
const MEM_WIN0_LO: u32 = 0x400c;
const MEM_WIN0_HI: u32 = 0x4010;
const MEM_WIN0_BASE_LIMIT: u32 = 0x4070;
const WIN_LIMIT_MASK: u32 = 0xfff0_0000;
const WIN_BASE_MASK: u32 = 0xfff0;
const MEM_WIN0_BASE_HI: u32 = 0x4080;
const MEM_WIN0_LIMIT_HI: u32 = 0x4084;
const HI_MASK: u32 = 0xff;
const RC_BAR1_CONFIG_LO: u32 = 0x402c;
const RC_BAR4_CONFIG_LO: u32 = 0x40d4;
const RC_BAR_SIZE_MASK: u32 = 0x1f;
const UBUS_BAR1_CONFIG_REMAP: u32 = 0x40ac;
const UBUS_BAR4_CONFIG_REMAP: u32 = 0x410c;
const UBUS_REMAP_ACCESS_EN: u32 = 1;
const MSI_BAR_CONFIG_LO: u32 = 0x4044;
const MSI_BAR_CONFIG_HI: u32 = 0x4048;
const MSI_DATA_CONFIG: u32 = 0x404c;
const MSI_DATA_CONFIG_VAL_32: u32 = 0xffe0_6540;
const MSI_DATA_BASE: u32 = 0x6540;
const PCIE_CTRL: u32 = 0x4064;
const PCIE_CTRL_PERSTB: u32 = 0x4;
const PCIE_STATUS: u32 = 0x4068;
const STATUS_PORT: u32 = 0x80;
const STATUS_DL_ACTIVE: u32 = 0x20;
const STATUS_PHYLINKUP: u32 = 0x10;
const HARD_DEBUG: u32 = 0x4304;
const HARD_DEBUG_SERDES_IDDQ: u32 = 0x0800_0000;
const MSI_INTR2_BASE: u32 = 0x4500;
const MSI_INT_CLR: u32 = 0x8;
const MSI_INT_MASK_CLR: u32 = 0x14;
const EXT_CFG_DATA: u32 = 0x8000;
const EXT_CFG_INDEX: u32 = 0x9000;
const RGR1_SW_INIT_1: u32 = 0x9210;
const RGR1_SW_INIT_1_INIT: u32 = 0x2;

/// MSI doorbells (`BRCM_MSI_TARGET_ADDR_{LT,GT}_4GB`): the last dword of the
/// first 4 GiB, or of the first 64 GiB; the one an inbound window does not
/// cover is used.
const MSI_TARGET_LT_4GB: u64 = 0x0_ffff_fffc;
const MSI_TARGET_GT_4GB: u64 = 0xf_ffff_fffc;
const MSI_VECTORS: u32 = 32;

/// BCM2712 `post_setup`: PHY tuning over MDIO port 0, `(register, value)`.
const PHY_TUNING: [(u32, u32); 8] = [
    (0x1f, 0x1600),
    (0x16, 0x50b9),
    (0x17, 0xbda1),
    (0x18, 0x0094),
    (0x19, 0x97b4),
    (0x1b, 0x5030),
    (0x1c, 0x5030),
    (0x1e, 0x0007),
];
const PHY_PM_CLK_PERIOD: u32 = 0x12;

const MIB: u64 = 1 << 20;

/// The size code of an inbound window (`brcm_pcie_encode_ibar_size`).
fn encode_ibar_size(size: u64) -> Option<u32> {
    match log2_exact(size)? {
        l @ 12..=15 => Some(l - 12 + 0x1c),
        l @ 16..=36 => Some(l - 15),
        _ => None,
    }
}

/// Register offset of RC BAR `n` (1-based) and of its UBUS remap register.
fn bar_regs(n: u32) -> (u32, u32) {
    if n <= 3 {
        (RC_BAR1_CONFIG_LO + 8 * (n - 1), UBUS_BAR1_CONFIG_REMAP + 8 * (n - 1))
    } else {
        (RC_BAR4_CONFIG_LO + 8 * (n - 4), UBUS_BAR4_CONFIG_REMAP + 8 * (n - 4))
    }
}

fn validate(cfg: &BrcmConfig) -> Result<(), HostError> {
    if cfg.outbound.len() > MAX_OUTBOUND {
        return Err(HostError::TooManyOutbound);
    }
    if cfg.inbound.len() > MAX_INBOUND {
        return Err(HostError::TooManyInbound);
    }
    for (i, w) in cfg.outbound.iter().enumerate() {
        let HostWindow { cpu_base, bus_base, size } = w.window;
        let ok = size != 0
            && cpu_base % MIB == 0
            && bus_base % MIB == 0
            && cpu_base.checked_add(size).is_some()
            && bus_base.checked_add(size).is_some()
            // base and limit in MiB must fit the 12 + 8 bit register fields
            && (cpu_base + size - 1) >> 20 < (1 << 20);
        if !ok {
            return Err(HostError::BadOutbound(i));
        }
    }
    for (i, w) in cfg.inbound.iter().enumerate() {
        let ok = encode_ibar_size(w.size).is_some()
            && w.bus_base % w.size == 0
            && w.cpu_base % 0x1000 == 0
            && w.bus_base.checked_add(w.size).is_some();
        if !ok {
            return Err(HostError::BadInbound(i));
        }
    }
    Ok(())
}

fn perst<B: Bus>(bus: &B, asserted: bool) {
    // PERSTB is active low.
    update_bits(bus, Region::Apb, PCIE_CTRL, PCIE_CTRL_PERSTB, if asserted { 0 } else { PCIE_CTRL_PERSTB });
}

fn link_up<B: Bus>(bus: &B) -> bool {
    let both = STATUS_DL_ACTIVE | STATUS_PHYLINKUP;
    bus.read32(Region::Apb, PCIE_STATUS) & both == both
}

fn mdio_write<B: Bus>(bus: &B, regad: u32, data: u32) -> Result<(), HostError> {
    // Command 0 (write), port 0.
    bus.write32(Region::Apb, RC_DL_MDIO_ADDR, (0 << MDIO_PORT_SHIFT) | (regad & MDIO_REGAD_MASK));
    bus.read32(Region::Apb, RC_DL_MDIO_ADDR);
    bus.write32(Region::Apb, RC_DL_MDIO_WR_DATA, MDIO_DATA_DONE | data);
    // The controller clears DONE when the PHY took the word: 10 us steps,
    // 100 us in all.
    for _ in 0..10 {
        if bus.read32(Region::Apb, RC_DL_MDIO_WR_DATA) & MDIO_DATA_DONE == 0 {
            return Ok(());
        }
        bus.delay_us(10);
    }
    Err(HostError::MdioTimeout)
}

fn program_outbound<B: Bus>(bus: &B, n: u32, w: &HostWindow) {
    let base_mb = w.cpu_base >> 20;
    let limit_mb = (w.cpu_base + w.size - 1) >> 20;
    bus.write32(Region::Apb, MEM_WIN0_LO + 8 * n, w.bus_base as u32);
    bus.write32(Region::Apb, MEM_WIN0_HI + 8 * n, (w.bus_base >> 32) as u32);
    update_bits(
        bus,
        Region::Apb,
        MEM_WIN0_BASE_LIMIT + 4 * n,
        WIN_BASE_MASK | WIN_LIMIT_MASK,
        (((base_mb & 0xfff) << 4) as u32 & WIN_BASE_MASK) | (((limit_mb & 0xfff) << 20) as u32 & WIN_LIMIT_MASK),
    );
    update_bits(bus, Region::Apb, MEM_WIN0_BASE_HI + 8 * n, HI_MASK, (base_mb >> 12) as u32);
    update_bits(bus, Region::Apb, MEM_WIN0_LIMIT_HI + 8 * n, HI_MASK, (limit_mb >> 12) as u32);
}

fn program_inbound<B: Bus>(bus: &B, n: u32, w: &InboundWindow) {
    let (bar, remap) = bar_regs(n);
    // `validate` has checked the size encodes.
    let code = encode_ibar_size(w.size).unwrap_or(0);
    bus.write32(Region::Apb, bar, (w.bus_base as u32 & !RC_BAR_SIZE_MASK) | code);
    bus.write32(Region::Apb, bar + 4, (w.bus_base >> 32) as u32);
    bus.write32(Region::Apb, remap, (w.cpu_base as u32 & !0xfff) | UBUS_REMAP_ACCESS_EN);
    bus.write32(Region::Apb, remap + 4, (w.cpu_base >> 32) as u32);
}

/// The MSI doorbell: the first of the two Linux targets no inbound window
/// covers, `None` when both are covered (MSIs are then not offered).
fn msi_target(inbound: &[InboundWindow]) -> Option<u64> {
    let covered = |t: u64| inbound.iter().any(|w| t >= w.bus_base && t - w.bus_base < w.size);
    [MSI_TARGET_LT_4GB, MSI_TARGET_GT_4GB].into_iter().find(|&t| !covered(t))
}

/// Bring the root complex up and wait for the link (see the module docs of
/// [`super`] for the flow). On `Err` nothing may be enumerated behind it;
/// after [`HostError::LinkDown`] PERST# is asserted again.
pub fn init<B: Bus>(bus: &B, cfg: &BrcmConfig) -> Result<HostReport, HostError> {
    validate(cfg)?;

    // Hold the endpoint in reset before anything is programmed: firmware may
    // have left the link trained (the Pi 5 boots from it), and the windows,
    // RC BARs and PHY tuning below must not change under a live link.
    perst(bus, true);
    bus.delay_us(PERST_HOLD_US);

    // Reset the bridge, then power the SerDes.
    update_bits(bus, Region::Apb, RGR1_SW_INIT_1, RGR1_SW_INIT_1_INIT, RGR1_SW_INIT_1_INIT);
    bus.delay_us(200);
    update_bits(bus, Region::Apb, RGR1_SW_INIT_1, RGR1_SW_INIT_1_INIT, 0);
    update_bits(bus, Region::Apb, HARD_DEBUG, HARD_DEBUG_SERDES_IDDQ, 0);
    bus.delay_us(200);

    update_bits(
        bus,
        Region::Apb,
        MISC_CTRL,
        MISC_CTRL_SCB_ACCESS_EN
            | MISC_CTRL_CFG_READ_UR_MODE
            | MISC_CTRL_MAX_BURST_MASK
            | MISC_CTRL_RCB_MPS_MODE
            | MISC_CTRL_RCB_64B_MODE,
        MISC_CTRL_SCB_ACCESS_EN
            | MISC_CTRL_CFG_READ_UR_MODE
            | MISC_CTRL_MAX_BURST_512
            | MISC_CTRL_RCB_MPS_MODE
            | MISC_CTRL_RCB_64B_MODE,
    );

    // Inbound windows are RC BARs 1..; BAR 0 does not exist.
    for (i, w) in cfg.inbound.iter().enumerate() {
        program_inbound(bus, i as u32 + 1, w);
    }

    if bus.read32(Region::Apb, PCIE_STATUS) & STATUS_PORT == 0 {
        return Err(HostError::NotRootComplex);
    }

    update_bits(bus, Region::Apb, RC_CFG_PRIV1_ID_VAL3, CLASS_CODE_MASK, CLASS_BRIDGE_PCI_NORMAL);
    for (i, w) in cfg.outbound.iter().enumerate() {
        program_outbound(bus, i as u32, &w.window);
    }
    update_bits(bus, Region::Apb, RC_CFG_VENDOR_SPECIFIC_REG1, ENDIAN_MODE_BAR2_MASK, 0);

    for (reg, val) in PHY_TUNING {
        mdio_write(bus, reg, val)?;
    }
    bus.delay_us(200);
    update_bits(bus, Region::Apb, RC_PL_PHY_CTL_15, PHY_CTL_15_PM_CLK_PERIOD_MASK, PHY_PM_CLK_PERIOD);

    let msi = msi_target(cfg.inbound).map(|target| {
        bus.write32(Region::Apb, MSI_INTR2_BASE + MSI_INT_MASK_CLR, u32::MAX);
        bus.write32(Region::Apb, MSI_INTR2_BASE + MSI_INT_CLR, u32::MAX);
        bus.write32(Region::Apb, MSI_BAR_CONFIG_LO, target as u32 | 1);
        bus.write32(Region::Apb, MSI_BAR_CONFIG_HI, (target >> 32) as u32);
        bus.write32(Region::Apb, MSI_DATA_CONFIG, MSI_DATA_CONFIG_VAL_32);
        MsiHookup {
            doorbell: target,
            data_base: MSI_DATA_BASE,
            vectors: MSI_VECTORS,
            status_off: MSI_INTR2_BASE,
            ack_off: MSI_INTR2_BASE + MSI_INT_CLR,
            summary: None,
        }
    });

    // Start the link.
    perst(bus, false);
    bus.delay_us(RESET_CONFIG_WAIT_US);
    let waited_us = match wait_link(bus, checks_for(cfg.link_timeout_us, LINK_STEP_US), LINK_STEP_US, || link_up(bus)) {
        Ok(w) => w,
        Err(waited_us) => {
            perst(bus, true);
            return Err(HostError::LinkDown { waited_us });
        }
    };

    Ok(HostReport {
        config: ConfigAccess::Indirect { index_off: EXT_CFG_INDEX, data_off: EXT_CFG_DATA },
        windows: firmware_windows(cfg.outbound),
        msi,
        link_wait_us: waited_us,
    })
}

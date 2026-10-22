// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Synopsys DesignWare USB3 core (`snps,dwc3`) as far as the xHCI driver
//! needs it: is the port a host, and put the core in host mode.
//!
//! A DWC3 is a dual-role core: the xHCI register file sits at the start of the
//! window and the core's own global registers at 0xc100, and which of the host
//! or the device (gadget) controller answers on the port is `GCTL.PRTCAPDIR`.
//! A board's gadget port (the mass-storage gadget) is the same core in
//! `peripheral` mode, so the device tree's `dr_mode` decides whether the xHCI
//! driver may touch it at all. Not here, and not the xHCI driver's business:
//! the PHY and the clocks and resets of the glue wrapper (the board's, through
//! the SoC frameworks), and the core soft reset.

use crate::hw::Regs;

/// Global Core Control register, bytes from the window's start.
pub const GCTL: usize = 0xc110;
/// `GCTL.PRTCAPDIR`: the mode the port is in (bits 13:12).
pub const GCTL_PRTCAPDIR_MASK: u32 = 3 << 12;
/// `PRTCAPDIR` = host.
pub const GCTL_PRTCAPDIR_HOST: u32 = 1 << 12;

/// Smallest register window that holds `GCTL`.
pub const MIN_WINDOW: u64 = GCTL as u64 + 4;

/// May the xHCI driver take a DWC3 whose `dr_mode` property is `dr_mode`
/// (the raw property value, `None` when the node has none)? Only `host`. The
/// binding's default for a missing property is `otg`, which is a core that can
/// be a device, so a missing property refuses as `peripheral` and `otg` do.
pub fn is_host_only(dr_mode: Option<&[u8]>) -> bool {
    #[cfg(feature = "canary-dr-mode")]
    {
        let _ = dr_mode;
        true
    }
    #[cfg(not(feature = "canary-dr-mode"))]
    {
        dr_mode.is_some_and(|v| v == b"host\0" || v == b"host")
    }
}

/// Switch the core's port to host mode (read-modify-write of `GCTL`, the
/// other fields untouched). The window must cover [`MIN_WINDOW`].
pub fn set_host_mode<R: Regs>(regs: &R) {
    let g = regs.read32(GCTL);
    regs.write32(GCTL, (g & !GCTL_PRTCAPDIR_MASK) | GCTL_PRTCAPDIR_HOST);
}

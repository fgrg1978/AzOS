// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which device-tree devices master the bus, by what their `compatible` names.
//!
//! A device tree says a node does DMA only sometimes (`dma-coherent`,
//! `dma-noncoherent`, `iommus`, a `dma-ranges` above it): a non-coherent SoC's
//! USB host or Ethernet MAC carries none of them. So the node's DMA properties
//! are one source ([`crate::Device::may_master_bus`]) and this table is the
//! other: the controllers known to move memory, the peripherals known not to,
//! and a third answer, *unknown*, which reads as a master. Writing the
//! registers of a master points it at any memory, so a node nobody classified
//! is not trusted with a writable window.
//!
//! A token matches as a substring of any `compatible` string, so a vendor's
//! spelling of a family (`snps,dwc3`, `spacemit,k1-dwc3`) lands in the same
//! row. A master token wins over a peripheral one: `compatible` lists most
//! specific first, and a node that names a controller anywhere is one.

/// What a device's `compatible` list says about its DMA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DtRole {
    /// A known bus master.
    Master,
    /// Known to do no DMA of its own.
    Peripheral,
    /// Neither list names it: treated as a master.
    Unknown,
}

/// Controllers that read or write memory on their own: USB, Ethernet, SD/MMC,
/// DMA engines, storage, GPU, display, video and camera blocks, PCIe hosts,
/// and the serial engines with a DMA of their own (Qualcomm GENI and QUP,
/// whose `iommus` sits on the wrapper above them).
const MASTERS: &[&str] = &[
    "dwc2", "dwc3", "xhci", "ehci", "ohci", "uhci", "usb", "cdns3", "cdnsp", "musb",
    "ethernet", "gmac", "dwmac", "stmmac", "emac", "eqos", "macb", "genet", "fec",
    "sdhci", "mmc", "mshc", "sdio", "sdhc",
    "dma", "pl330", "pl080",
    "ahci", "sata", "nvme", "ufs", "scsi",
    "gpu", "mali", "vivante", "etnaviv", "drm", "display", "dsi", "hdmi", "vop", "lcdc", "dpu",
    "vpu", "video", "isp", "csi", "jpeg", "venc", "vdec",
    "pcie", "pci-host",
    "geni", "qup", "uartdm",
];

/// Peripherals that only answer register accesses.
const PERIPHERALS: &[&str] = &[
    "uart", "serial", "ns16550", "ns8250", "pl011",
    "rtc", "pl031",
    "gpio", "pl061",
    "i2c", "pwm", "wdt", "watchdog", "pinctrl", "thermal",
    "sifive,test", "syscon",
];

/// The role the `compatible` strings `list` (most specific first) give.
pub fn dt_role<'a>(list: impl Iterator<Item = &'a str>) -> DtRole {
    let (mut master, mut peripheral) = (false, false);
    for c in list {
        master |= MASTERS.iter().any(|t| c.contains(t));
        peripheral |= PERIPHERALS.iter().any(|t| c.contains(t));
    }
    if master {
        DtRole::Master
    } else if peripheral || cfg!(feature = "dt-unknown-peripheral-canary") {
        DtRole::Peripheral
    } else {
        DtRole::Unknown
    }
}

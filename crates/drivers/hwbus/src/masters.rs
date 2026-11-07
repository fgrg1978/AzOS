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
//! A master token matches as a substring of any `compatible` string, so a
//! vendor's spelling of a family (`snps,dwc3`, `spacemit,k1-dwc3`) lands in the
//! same row. A peripheral is known by its whole `compatible` string, never by
//! a substring: a bare `i2c`, `uart` or `serial` in a name says what the
//! register block is, not that it has no DMA engine of its own (Qualcomm's
//! GENI serial engines, a vendor's UART with a built-in controller), so a
//! name the table does not list is a master, and a device is added to the
//! table after its binding was read. A master token wins over a peripheral
//! name: `compatible` lists most specific first, and a node that names a
//! controller anywhere is one.

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

/// Peripherals that only answer register accesses, by their whole
/// `compatible` string.
const PERIPHERALS: &[&str] = &[
    "arm,pl011", "ns16550a", "ns16550", "ns8250", "brcm,bcm2835-aux-uart",
    "arm,pl031", "google,goldfish-rtc",
    "arm,pl061", "spacemit,k1-gpio",
    "snps,designware-i2c", "spacemit,k1-i2c",
    "spacemit,k1-pwm", "starfive,jh7110-pwm", "opencores,pwm-v1",
    "starfive,jh7110-wdt", "starfive,jh7110-sys-pinctrl",
    "sifive,test0", "sifive,test1", "syscon",
    "spacemit,k1-syscon-apbc", "spacemit,k1-syscon-mpmu", "spacemit,k1-syscon-apmu",
    "azos,thermal-fixture",
];

/// Names the old substring rule took for peripherals; kept only for the canary.
const BARE_TOKENS: &[&str] = &["uart", "serial", "rtc", "gpio", "i2c", "pwm", "wdt", "pinctrl", "thermal"];

/// The role the `compatible` strings `list` (most specific first) give.
pub fn dt_role<'a>(list: impl Iterator<Item = &'a str>) -> DtRole {
    let (mut master, mut peripheral) = (false, false);
    for c in list {
        master |= MASTERS.iter().any(|t| c.contains(t));
        peripheral |= PERIPHERALS.contains(&c)
            || (cfg!(feature = "dt-bare-token-canary") && BARE_TOKENS.iter().any(|t| c.contains(t)));
    }
    if master {
        DtRole::Master
    } else if peripheral || cfg!(feature = "dt-unknown-peripheral-canary") {
        DtRole::Peripheral
    } else {
        DtRole::Unknown
    }
}

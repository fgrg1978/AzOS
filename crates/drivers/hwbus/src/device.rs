// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A device object: what an enumerator found, in a fixed-size record.

use crate::pattern::{Pattern, ANY};

/// Bytes of a device or driver name kept.
pub const NAME_LEN: usize = 32;
/// Bytes of a device-tree `compatible` list kept (NUL-separated strings, most
/// specific first; a string that does not fit whole is dropped).
pub const COMPAT_LEN: usize = 96;

/// Which enumerator found a device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BusKind {
    /// A PCI/PCIe function behind the ECAM window (or the legacy port pair).
    Pci,
    /// A node of the device tree with a `compatible` and a `reg`.
    Dt,
    /// A populated virtio-mmio window.
    VirtioMmio,
}

/// A fixed-capacity text field (a name), always valid UTF-8.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Name {
    bytes: [u8; NAME_LEN],
    len: u8,
}

impl Name {
    pub const EMPTY: Name = Name { bytes: [0; NAME_LEN], len: 0 };

    /// `s` cut at a character boundary to fit.
    pub fn new(s: &str) -> Self {
        let mut n = s.len().min(NAME_LEN);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        let mut bytes = [0u8; NAME_LEN];
        bytes[..n].copy_from_slice(&s.as_bytes()[..n]);
        Name { bytes, len: n as u8 }
    }

    pub fn as_str(&self) -> &str {
        // `new` only ever stores a prefix cut on a character boundary.
        core::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("")
    }
}

impl core::fmt::Debug for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

/// A PCI function's identity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PciId {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor: u16,
    pub device_id: u16,
    /// Base class, sub class, programming interface (config offset 0x09..0x0b).
    pub class: u32,
}

/// One device object.
#[derive(Clone, Copy, Debug)]
pub struct Device {
    pub kind: BusKind,
    pub name: Name,
    /// Valid when `kind == Pci`.
    pub pci: PciId,
    /// Valid when `kind == VirtioMmio`.
    pub virtio_id: u32,
    compat: [u8; COMPAT_LEN],
    compat_len: u8,
    /// The first register window (DT `reg`, the virtio-mmio window, a
    /// published PCI BAR); 0 while unknown.
    pub base: u64,
    pub size: u64,
    /// The second register window of a device-tree node, `(base, size)`;
    /// `None` when the node has one (the SBSA watchdog's refresh frame).
    pub reg2: Option<(u64, u64)>,
    /// The first interrupt specifier cell (DT), or the line the transport
    /// uses; 0 when none is known.
    pub irq: u32,
    /// The highest physical address (inclusive) the device's DMA can reach:
    /// from the device tree's `dma-ranges` for a DT node or the PCI host
    /// bridge a function sits behind. `u64::MAX` (the default, and a PCI
    /// function's 64-bit one) when nothing narrows it. A driver that
    /// allocates DMA memory allocates at or below it.
    pub dma_mask: u64,
    /// What the bus adds to a CPU physical address to give the device's DMA
    /// address (device tree `dma-ranges`; 0xc000_0000 on a Raspberry Pi's
    /// VideoCore bus): 0, the default, on an identity bus. The platform DMA
    /// domain applies it (`azos_dma::registry::declare_mmio`).
    pub dma_offset: u64,
    /// The firmware declared the device's DMA cache-coherent with the CPU
    /// (DT `dma-coherent` on the node or a bus above it). `false`: nothing
    /// declared, so the platform default (Kconfig `DMA_NONCOHERENT`) holds;
    /// a device that declared it skips the cache maintenance a non-coherent
    /// master needs around each transfer.
    pub dma_coherent: bool,
    /// Where the device's node sits in the device tree: the offset of its
    /// `FDT_BEGIN_NODE` token in the structure block (`azos_soc::NodeId`),
    /// the key the SoC frameworks resolve the device's `clocks`, `resets`,
    /// `*-supply`, `pinctrl-N` and `power-domains` properties from. `None`
    /// for a device that did not come from the tree, or whose enumerator
    /// does not report it.
    pub dt_node: Option<u32>,
}

const NO_PCI: PciId = PciId { bus: 0, device: 0, function: 0, vendor: 0, device_id: 0, class: 0 };

impl Device {
    /// A free slot's content.
    pub const EMPTY: Device = Device::blank(BusKind::Dt);

    const fn blank(kind: BusKind) -> Self {
        Device {
            kind,
            name: Name::EMPTY,
            pci: NO_PCI,
            virtio_id: 0,
            compat: [0; COMPAT_LEN],
            compat_len: 0,
            base: 0,
            size: 0,
            reg2: None,
            irq: 0,
            dma_mask: u64::MAX,
            dma_offset: 0,
            dma_coherent: false,
            dt_node: None,
        }
    }

    /// A PCI function. The name is its address, `bb:dd.f`.
    pub fn pci(pci: PciId) -> Self {
        let mut d = Self::blank(BusKind::Pci);
        d.pci = pci;
        let mut buf = [0u8; 8];
        let hex = |n: u8| b"0123456789abcdef"[(n & 15) as usize];
        buf[0] = hex(pci.bus >> 4);
        buf[1] = hex(pci.bus);
        buf[2] = b':';
        buf[3] = hex(pci.device >> 4);
        buf[4] = hex(pci.device);
        buf[5] = b'.';
        buf[6] = hex(pci.function);
        // ASCII by construction.
        d.name = Name::new(core::str::from_utf8(&buf[..7]).unwrap_or(""));
        d
    }

    /// A device-tree node. `compatible` is the property as the tree stores it:
    /// NUL-separated strings, most specific first.
    pub fn dt(name: &str, compatible: &[u8], base: u64, size: u64, irq: u32) -> Self {
        let mut d = Self::blank(BusKind::Dt);
        d.name = Name::new(name);
        d.set_compatible(compatible);
        d.base = base;
        d.size = size;
        d.irq = irq;
        d
    }

    /// A virtio-mmio window whose transport reported `virtio_id`.
    pub fn virtio_mmio(base: u64, size: u64, irq: u32, virtio_id: u32) -> Self {
        let mut d = Self::blank(BusKind::VirtioMmio);
        let mut buf = [0u8; NAME_LEN];
        let prefix = b"virtio@";
        buf[..prefix.len()].copy_from_slice(prefix);
        let mut n = prefix.len();
        let mut started = false;
        for shift in (0..16).rev() {
            let nib = ((base >> (shift * 4)) & 15) as u8;
            if nib != 0 || started || shift == 0 {
                started = true;
                buf[n] = b"0123456789abcdef"[nib as usize];
                n += 1;
            }
        }
        d.name = Name::new(core::str::from_utf8(&buf[..n]).unwrap_or(""));
        d.base = base;
        d.size = size;
        d.irq = irq;
        d.virtio_id = virtio_id;
        d
    }

    /// The device with its first register window set (a PCI function's first
    /// assigned memory BAR).
    pub fn with_window(mut self, base: u64, size: u64) -> Self {
        self.base = base;
        self.size = size;
        self
    }

    /// The device with its DMA reach limited to `mask` (see [`Device::dma_mask`]).
    pub fn with_dma_mask(mut self, mask: u64) -> Self {
        self.dma_mask = mask;
        self
    }

    /// The device behind a bus that moves its DMA addresses by `offset` (see
    /// [`Device::dma_offset`]).
    pub fn with_dma_offset(mut self, offset: u64) -> Self {
        self.dma_offset = offset;
        self
    }

    /// The device with its DMA coherence as the firmware declared it (see
    /// [`Device::dma_coherent`]).
    pub fn with_dma_coherent(mut self, coherent: bool) -> Self {
        self.dma_coherent = coherent;
        self
    }

    /// The device with its second register window (see [`Device::reg2`]).
    pub fn with_reg2(mut self, reg2: Option<(u64, u64)>) -> Self {
        self.reg2 = reg2;
        self
    }

    /// The device with the position of its device-tree node (see
    /// [`Device::dt_node`]).
    pub fn with_dt_node(mut self, node: u32) -> Self {
        self.dt_node = Some(node);
        self
    }

    fn set_compatible(&mut self, list: &[u8]) {
        let mut used = 0usize;
        for s in list.split(|&b| b == 0).filter(|s| !s.is_empty()) {
            if used + s.len() + 1 > COMPAT_LEN {
                break;
            }
            self.compat[used..used + s.len()].copy_from_slice(s);
            used += s.len() + 1; // the NUL is already there
        }
        self.compat_len = used as u8;
    }

    /// The `compatible` strings, most specific first.
    pub fn compatible(&self) -> impl Iterator<Item = &str> {
        self.compat[..self.compat_len as usize]
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .filter_map(|s| core::str::from_utf8(s).ok())
    }

    /// Does `pattern` name this device?
    pub fn matches(&self, pattern: &Pattern<'_>) -> bool {
        match (self.kind, pattern) {
            (BusKind::Pci, Pattern::Pci { vendor, device, class, class_mask }) => {
                (*vendor == ANY || *vendor == self.pci.vendor as u32)
                    && (*device == ANY || *device == self.pci.device_id as u32)
                    && (self.pci.class ^ *class) & *class_mask == 0
            }
            (BusKind::Dt, Pattern::Dt(c)) => self.compatible().any(|s| s == *c),
            (BusKind::VirtioMmio, Pattern::Virtio(id)) => self.virtio_id == *id,
            _ => false,
        }
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the kernel reads from the host bridge's device-tree node before
//! calling a controller's `init`: which controller it is, its named `reg`
//! ranges, and the `ranges` / `dma-ranges` windows. Pure functions over the
//! raw property bytes (big-endian cells), so the cell arithmetic host-tests
//! against fixture nodes; finding the node and mapping the windows are the
//! kernel's (`kernel/src/boot/pci.rs`).

use super::{plda, InboundWindow, MemSpace, OutboundWindow};
use crate::HostWindow;

/// DT `compatible` of the JH7110 PLDA root port.
pub const PLDA_COMPATIBLE: &str = "starfive,jh7110-pcie";
/// DT `compatible` of the BCM2712 root complex (the Raspberry Pi 5's, which
/// leads to the RP1).
pub const BRCMSTB_COMPATIBLE: &str = "brcm,bcm2712-pcie";

/// Which bring-up flow a node needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Controller {
    Plda,
    Brcmstb,
}

impl Controller {
    /// The controller a `compatible` string names.
    pub fn from_compatible(c: &str) -> Option<Controller> {
        match c {
            PLDA_COMPATIBLE => Some(Controller::Plda),
            BRCMSTB_COMPATIBLE => Some(Controller::Brcmstb),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Controller::Plda => "plda (JH7110)",
            Controller::Brcmstb => "brcmstb (BCM2712)",
        }
    }
}

/// The order the boot tries a tree's SoC bridges in, as indices into the
/// first `n` of `described` (`described[i]`: bridge `i`'s node has a child,
/// so what sits behind it is described, as the Raspberry Pi 5's `pcie2`
/// describes the RP1): the described ones first, then the others, each group
/// in tree order. The first one whose link comes up is the one enumerated.
pub fn bring_up_order<const N: usize>(described: &[bool; N], n: usize) -> ([usize; N], usize) {
    let n = n.min(N);
    let mut order = [0; N];
    let mut k = 0;
    for pass in [true, false] {
        for (i, &d) in described[..n].iter().enumerate() {
            if d == pass {
                order[k] = i;
                k += 1;
            }
        }
    }
    (order, k)
}

/// STG syscon block of a PLDA controller, from DT `linux,pci-domain`.
pub fn plda_stg_base(domain: u32) -> Option<u32> {
    match domain {
        0 => Some(plda::STG_PCIE0_BASE),
        1 => Some(plda::STG_PCIE1_BASE),
        _ => None,
    }
}

/// Why a property could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DtError {
    /// Not a whole number of entries, or a cell count the flow cannot read
    /// (an address or size wider than two cells).
    Malformed,
    /// More entries than the caller has room for.
    TooMany,
}

fn cell(v: &[u8], i: usize) -> Option<u32> {
    let b = v.get(i.checked_mul(4)?..)?.get(..4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// `count` (1 or 2) cells from cell `first`, as one number.
fn cells(v: &[u8], first: usize, count: usize) -> Option<u64> {
    match count {
        1 => cell(v, first).map(u64::from),
        2 => Some(u64::from(cell(v, first)?) << 32 | u64::from(cell(v, first + 1)?)),
        _ => None,
    }
}

/// `(base, size)` of the `reg` entry named `name`. The cell counts are the
/// parent's. With no `reg-names` the entry is the first one if `name` is the
/// controller's only register block, which is the caller's to know: pass
/// `None` for `names` and index 0 is returned.
pub fn reg_named(
    reg: &[u8],
    names: Option<&[u8]>,
    name: &str,
    addr_cells: usize,
    size_cells: usize,
) -> Option<(u64, u64)> {
    let stride = addr_cells + size_cells;
    if stride == 0 || reg.len() % (4 * stride) != 0 {
        return None;
    }
    let index = match names {
        None => 0,
        Some(n) => {
            let body = n.strip_suffix(&[0]).unwrap_or(n);
            body.split(|&b| b == 0).position(|s| s == name.as_bytes())?
        }
    };
    let first = index.checked_mul(stride)?;
    let base = cells(reg, first, addr_cells)?;
    let size = if size_cells == 0 { 0 } else { cells(reg, first + addr_cells, size_cells)? };
    Some((base, size))
}

/// One decoded `ranges` / `dma-ranges` entry of a PCI node: three child
/// address cells (flags, then a 64-bit PCI address), the parent address and
/// the size.
struct Entry {
    hi: u32,
    pci: u64,
    parent: u64,
    size: u64,
}

fn entries<'a>(
    v: &'a [u8],
    parent_addr_cells: usize,
    size_cells: usize,
) -> Result<impl Iterator<Item = Entry> + 'a, DtError> {
    let stride = 3 + parent_addr_cells + size_cells;
    if !(1..=2).contains(&parent_addr_cells) || !(1..=2).contains(&size_cells) || v.len() % (4 * stride) != 0 {
        return Err(DtError::Malformed);
    }
    Ok((0..v.len() / (4 * stride)).filter_map(move |i| {
        let f = i * stride;
        Some(Entry {
            hi: cell(v, f)?,
            pci: cells(v, f + 1, 2)?,
            parent: cells(v, f + 3, parent_addr_cells)?,
            size: cells(v, f + 3 + parent_addr_cells, size_cells)?,
        })
    }))
}

/// The memory windows of a PCI node's `ranges`, in order; the I/O window and
/// the configuration space entry are not memory and are skipped. Returns how
/// many were written to `out`.
pub fn parse_ranges(
    ranges: &[u8],
    parent_addr_cells: usize,
    size_cells: usize,
    out: &mut [OutboundWindow],
) -> Result<usize, DtError> {
    let mut n = 0;
    for e in entries(ranges, parent_addr_cells, size_cells)? {
        // Bits 25:24 of the first cell are the address space: 0 config,
        // 1 I/O, 2 32-bit memory, 3 64-bit memory.
        let space = match (e.hi >> 24) & 3 {
            2 => MemSpace::Mem32,
            3 => MemSpace::Mem64,
            _ => continue,
        };
        if n == out.len() {
            return Err(DtError::TooMany);
        }
        out[n] = OutboundWindow { space, window: HostWindow { cpu_base: e.parent, bus_base: e.pci, size: e.size } };
        n += 1;
    }
    Ok(n)
}

/// A PCI node's `dma-ranges`: PCI address `[bus_base, bus_base + size)` is
/// CPU memory at `cpu_base`. Returns how many were written to `out`.
pub fn parse_dma_ranges(
    dma_ranges: &[u8],
    parent_addr_cells: usize,
    size_cells: usize,
    out: &mut [InboundWindow],
) -> Result<usize, DtError> {
    let mut n = 0;
    for e in entries(dma_ranges, parent_addr_cells, size_cells)? {
        if n == out.len() {
            return Err(DtError::TooMany);
        }
        out[n] = InboundWindow { bus_base: e.pci, cpu_base: e.parent, size: e.size };
        n += 1;
    }
    Ok(n)
}

/// The DMA mask a device behind the bridge has: every bus address one of the
/// inbound windows covers fits in it. No window means the block's reset
/// translation (the JH7110's): no limit from the bridge.
pub fn dma_mask(inbound: &[InboundWindow]) -> u64 {
    let top = inbound.iter().map(|w| w.bus_base.saturating_add(w.size)).max().unwrap_or(0);
    if top <= 1 {
        u64::MAX
    } else {
        u64::MAX >> (top - 1).leading_zeros()
    }
}

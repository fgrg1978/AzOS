// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Native PCI/PCIe enumeration over ECAM.
//!
//! Pure logic against an injected [`ConfigSpace`] — no raw pointers, no
//! target asm, no `unsafe`. That is what lets `azos_pci_tests` pull
//! this crate on the host and exercise it against a fake config space,
//! and it is why `crates/drivers/virtio/src/virtio/pci.rs` is built the same way
//! (against this crate's types, not a `*mut u32`).
//!
//! Scope, stated once so it doesn't drift: one ECAM segment, no ARI, no
//! SR-IOV, no hot-plug, no I/O-space BARs. Bus 0 and the buses behind
//! PCI-to-PCI bridges are walked ([`enumerate_tree`]), bridges the firmware
//! left without bus numbers are numbered, BARs are placed from the host
//! bridge's windows ([`window`]), and the windows of the bridges in between
//! are sized around what sits behind them ([`bridge`]). It is explicitly NOT
//! a general PCIe subsystem.
#![no_std]
#![forbid(unsafe_code)]

use core::fmt;

pub mod bridge;
pub mod host;
pub mod window;

pub use bridge::{place_behind_bridges, BridgePlan, BridgeWindows, MAX_BRIDGES};
pub use window::{
    resolve_bar_window, BarWindow, FirmwareWindows, HostWindow, Pool, ResolvedWindow, WindowReport,
    WindowSource, MAX_RESERVED,
};

// ---------------------------------------------------------------------
// BDF
// ---------------------------------------------------------------------

/// Bus/Device/Function address. `device` is 0..=31, `function` 0..=7 —
/// callers passing a wider value get it masked, never a panic (PCI config
/// space is reachable from a fault handler; a panic there is a reset).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bdf {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Bdf {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Bdf { bus, device: device & 0x1f, function: function & 0x07 }
    }

    /// The requester id this function puts on the bus (`bus << 8 | device
    /// << 3 | function`): the key IOMMUs and the GICv3 ITS identify it by.
    pub const fn requester_id(self) -> u32 {
        ((self.bus as u32) << 8) | ((self.device as u32) << 3) | self.function as u32
    }
}

impl fmt::Display for Bdf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}.{:x}", self.bus, self.device, self.function)
    }
}

// ---------------------------------------------------------------------
// ECAM address math
// ---------------------------------------------------------------------

/// Byte offset of `bdf`'s 4 KiB config-space window within an ECAM region,
/// per PCI Express Base Spec ECAM layout: `bus<<20 | dev<<15 | func<<12`.
/// `offset` must be `< 4096` (extended config space); callers indexing a
/// capability at a computed offset must bounds-check that themselves —
/// this function does not, because it has no register-width to check
/// against (callers read/write 8/16/32-bit windows starting here).
pub const fn ecam_function_offset(bdf: Bdf) -> usize {
    ((bdf.bus as usize) << 20) | ((bdf.device as usize) << 15) | ((bdf.function as usize) << 12)
}

/// Absolute ECAM byte address for `bdf`'s config-space register at
/// `offset` (0..4096), given the ECAM window's own physical/virtual base.
pub const fn ecam_address(ecam_base: usize, bdf: Bdf, offset: u16) -> usize {
    ecam_base + ecam_function_offset(bdf) + offset as usize
}

// ---------------------------------------------------------------------
// ConfigSpace — the seam that makes this crate host-testable
// ---------------------------------------------------------------------

/// Config-space access, 32-bit granularity (PCIe config space is only
/// guaranteed safe to access as 8/16/32-bit naturally-aligned reads —
/// this crate only ever does 32-bit, matching every ECAM implementation
/// QEMU `virt` exposes).
///
/// The kernel-side implementor computes `ecam_address` and does a
/// volatile MMIO read/write; `azos_pci_tests` implements it over a
/// `[u32; N]` array standing in for a fake device's config space.
pub trait ConfigSpace {
    fn read32(&self, bdf: Bdf, offset: u16) -> u32;
    fn write32(&mut self, bdf: Bdf, offset: u16, val: u32);

    fn read16(&self, bdf: Bdf, offset: u16) -> u16 {
        let shift = (offset & 2) * 8;
        ((self.read32(bdf, offset & !3) >> shift) & 0xffff) as u16
    }

    fn read8(&self, bdf: Bdf, offset: u16) -> u8 {
        let shift = (offset & 3) * 8;
        ((self.read32(bdf, offset & !3) >> shift) & 0xff) as u8
    }
}

// ---------------------------------------------------------------------
// Standard header offsets / well-known fields
// ---------------------------------------------------------------------

pub const OFF_VENDOR_ID: u16 = 0x00;
pub const OFF_DEVICE_ID: u16 = 0x02;
pub const OFF_COMMAND: u16 = 0x04;
pub const OFF_STATUS: u16 = 0x06;
pub const OFF_CLASS_REV: u16 = 0x08;
pub const OFF_HEADER_TYPE: u16 = 0x0e;
/// A PCI-to-PCI bridge's (header type 1) primary bus number; the dword here
/// also holds the secondary (`+1`) and subordinate (`+2`) bus numbers and the
/// secondary latency timer (`+3`).
pub const OFF_PRIMARY_BUS: u16 = 0x18;
/// A PCI-to-PCI bridge's secondary bus number.
pub const OFF_SECONDARY_BUS: u16 = 0x19;
/// A PCI-to-PCI bridge's subordinate bus number: the highest bus behind it.
pub const OFF_SUBORDINATE_BUS: u16 = 0x1a;
/// Header type 1 (the low seven bits of the header-type byte): a PCI-to-PCI
/// bridge, which leads to a bus of its own.
pub const HEADER_TYPE_BRIDGE: u8 = 1;
pub const OFF_BAR0: u16 = 0x10;
pub const OFF_CAP_PTR: u16 = 0x34;
pub const OFF_INTERRUPT_PIN: u16 = 0x3d;

pub const STATUS_CAP_LIST: u16 = 1 << 4;
pub const HEADER_TYPE_MULTIFUNC: u8 = 1 << 7;
pub const HEADER_TYPE_MASK: u8 = 0x7f;

pub const VENDOR_ID_NONE: u16 = 0xffff;
/// Vendor id 0 is no vendor either: a mapping that reads zeros (an ECAM
/// base nothing decodes) must not look like a full bus.
pub const VENDOR_ID_ZERO: u16 = 0x0000;

pub const CAP_ID_MSI: u8 = 0x05;
pub const CAP_ID_PCI_EXPRESS: u8 = 0x10;
pub const CAP_ID_MSIX: u8 = 0x11;
pub const CAP_ID_VENDOR: u8 = 0x09;

/// Present iff the vendor id is a vendor: an absent function reads all-ones
/// on every register, so 0xffff is the spec-defined "nothing here" sentinel;
/// 0x0000 is what a window with nothing behind it can read instead.
pub fn function_exists<C: ConfigSpace>(cfg: &C, bdf: Bdf) -> bool {
    !matches!(cfg.read16(bdf, OFF_VENDOR_ID), VENDOR_ID_NONE | VENDOR_ID_ZERO)
}

// ---------------------------------------------------------------------
// Capability walk
// ---------------------------------------------------------------------

/// Upper bound on capability-list hops. The list is a linked list inside
/// memory a *device* controls; a hostile or corrupt device can point
/// `next` at itself and spin the walker forever (kernel context, no
/// preemption — that's a hang, not a crash). Real lists on QEMU `virt`
/// devices are under 10 entries; 48 is generous headroom with a hard
/// stop.
pub const CAP_WALK_MAX_HOPS: usize = 48;

/// One entry from the standard (non-extended) capability list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability {
    pub id: u8,
    /// Offset of this capability's own header (the `id` byte), so the
    /// caller can re-read type-specific fields at `offset + N`.
    pub offset: u16,
}

/// Fixed-capacity capability list — no allocator in this crate (kernel
/// context on the enumeration path, before `mm::kheap` is guaranteed
/// live, and the brief is explicit: don't allocate on hot paths anyway).
pub const MAX_CAPS_PER_FUNCTION: usize = 16;

#[derive(Clone, Copy, Debug, Default)]
pub struct CapabilityList {
    caps: [Option<Capability>; MAX_CAPS_PER_FUNCTION],
    len: usize,
}

impl CapabilityList {
    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.caps[..self.len].iter().filter_map(|c| c.as_ref())
    }

    pub fn find(&self, id: u8) -> Option<Capability> {
        self.iter().find(|c| c.id == id).copied()
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

/// Walk `bdf`'s standard capability list starting from `OFF_CAP_PTR`.
///
/// Terminates on: `next == 0` (spec end-of-list), a hop count of
/// [`CAP_WALK_MAX_HOPS`] (corrupt/hostile device), an unaligned pointer
/// (capability headers are dword-aligned per spec — `next & 3 != 0` is
/// already invalid, so treat it as end-of-list rather than trust it), a
/// pointer `< 0x40` (that would read inside the fixed header, never a
/// valid capability location), or the fixed-capacity list filling up.
pub fn walk_capabilities<C: ConfigSpace>(cfg: &C, bdf: Bdf) -> CapabilityList {
    let mut out = CapabilityList::default();

    let status = cfg.read16(bdf, OFF_STATUS);
    if status & STATUS_CAP_LIST == 0 {
        return out;
    }

    let mut ptr = cfg.read8(bdf, OFF_CAP_PTR) as u16;
    let mut hops = 0usize;

    while ptr != 0 && hops < CAP_WALK_MAX_HOPS && out.len < MAX_CAPS_PER_FUNCTION {
        if ptr < 0x40 || ptr & 0x3 != 0 {
            break;
        }
        let id = cfg.read8(bdf, ptr);
        out.caps[out.len] = Some(Capability { id, offset: ptr });
        out.len += 1;

        let next = cfg.read8(bdf, ptr + 1) as u16;
        hops += 1;
        ptr = next;
    }

    out
}

// ---------------------------------------------------------------------
// BAR sizing / decode
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarKind {
    Io,
    Mem32,
    /// 64-bit memory BAR. Occupies *two* BAR slots (this one + the next,
    /// which holds the high 32 bits and must be skipped by the caller —
    /// `decode_bars` does that for you).
    Mem64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bar {
    pub index: u8,
    pub kind: BarKind,
    pub prefetchable: bool,
    /// PCI bus address as currently programmed (0 if unassigned — callers
    /// doing BAR *assignment* look at `size` and pick their own base out of
    /// a window). The CPU reaches it at [`BarWindow::bar_cpu_addr`], which
    /// differs when the host bridge translates.
    pub address: u64,
    /// Size in bytes, from the size-probe sequence below. Always nonzero —
    /// [`decode_bars`] does not emit an entry for a BAR slot that probes
    /// to zero size (real hardware's way of saying "not implemented"; a
    /// caller dividing by `size` never needs to check for this).
    pub size: u64,
}

const BAR_IO_FLAG: u32 = 0x1;
const BAR_MEM_TYPE_MASK: u32 = 0x6;
const BAR_MEM_TYPE_64: u32 = 0x4;
const BAR_PREFETCHABLE: u32 = 0x8;

/// Number of standard BAR slots in a type-0 (non-bridge) header.
pub const BAR_COUNT: usize = 6;

/// BAR slots a type-1 (PCI-to-PCI bridge) header has. Its registers from
/// `0x18` on are bus numbers and forwarding windows, not BARs.
pub const BRIDGE_BAR_COUNT: usize = 2;

/// How many BAR slots the header type in `header_type` has: 6 (endpoint),
/// 2 (bridge), none (CardBus and anything else).
const fn bar_slots(header_type: u8) -> usize {
    match header_type & HEADER_TYPE_MASK {
        0 => BAR_COUNT,
        HEADER_TYPE_BRIDGE => BRIDGE_BAR_COUNT,
        _ => 0,
    }
}

/// Decode all implemented BARs of a function (six slots on an endpoint, two
/// on a bridge: its `0x18..0x30` are bus numbers and windows, which sizing
/// must never write), sizing each one via
/// the standard probe sequence: save original, write all-1s, read back
/// the size mask, **restore the original value** (leaving a BAR
/// temporarily unmapped between the two writes is a real hazard for a
/// live device — this function does the save/restore around each probed
/// BAR, not just at the end, so a fault mid-walk cannot leave two BARs
/// disabled at once).
///
/// **Decode is off while the BARs are sized.** A BAR that reads all-1s is,
/// for that instant, a window at the top of the address space: with Memory
/// or I/O Space decode on (the firmware of a PC leaves it on for the devices
/// it used) the function claims cycles meant for whatever lives there, the
/// local APIC and the flash below 4 GiB among them. The Command register's
/// I/O and Memory Space bits are cleared for the walk and put back as found
/// after it (Linux `__pci_read_base` does the same). Nothing in this kernel
/// reaches config space through a BAR, so the walk does not cut its own
/// access. A host bridge (class 0x0600) keeps its decode: on a real chipset
/// its Command bits can gate the memory decode of the whole hierarchy, the
/// ECAM window the walk reads through included (Linux's
/// `quirk_mmio_always_on` for `PCI_CLASS_BRIDGE_HOST`).
///
/// A 64-bit BAR consumes its own slot plus the next one (which holds the
/// high 32 address bits, never itself sized); this returns one `Bar` for
/// the pair and the caller does not see the consumed slot separately. A
/// slot that probes to size 0 (not implemented — the spec-defined way of
/// saying so) is skipped entirely: no `Bar` entry, matching what `lspci`
/// shows and keeping the gate's one-line-per-function output free of
/// `bar3=mem32:0x0+0x0` noise for slots that don't exist.
pub fn decode_bars<C: ConfigSpace>(cfg: &mut C, bdf: Bdf) -> ([Option<Bar>; BAR_COUNT], usize) {
    let mut out: [Option<Bar>; BAR_COUNT] = [None; BAR_COUNT];
    let mut n = 0usize;
    let mut i = 0usize;
    let slots = bar_slots(cfg.read8(bdf, OFF_HEADER_TYPE));
    let host_bridge = cfg.read32(bdf, OFF_CLASS_REV) >> 16 == CLASS_BRIDGE_HOST;
    let decode = if host_bridge { 0 } else { cfg.read16(bdf, OFF_COMMAND) & (CMD_IO_SPACE | CMD_MEM_SPACE) };
    if slots != 0 && decode != 0 {
        clear_command_bits(cfg, bdf, decode);
    }

    while i < slots {
        let off = OFF_BAR0 + (i as u16) * 4;
        let orig = cfg.read32(bdf, off);

        if orig & BAR_IO_FLAG != 0 {
            let size = size_probe_32(cfg, bdf, off, orig, !0x3u32);
            if size != 0 {
                out[n] = Some(Bar {
                    index: i as u8,
                    kind: BarKind::Io,
                    prefetchable: false,
                    address: (orig & !0x3) as u64,
                    size,
                });
                n += 1;
            }
            i += 1;
            continue;
        }

        let is64 = orig & BAR_MEM_TYPE_MASK == BAR_MEM_TYPE_64;
        let prefetchable = orig & BAR_PREFETCHABLE != 0;

        if is64 && i + 1 < slots {
            let off_hi = off + 4;
            let orig_hi = cfg.read32(bdf, off_hi);

            let size_lo = size_probe_32(cfg, bdf, off, orig, !0xfu32);
            let size = if size_lo == 0 {
                // Low word claimed zero size (all decode bits landed high);
                // probe the high word too and combine. Rare on QEMU virt
                // (BARs there fit in 32 bits) but correct for a >4GiB BAR.
                let size_hi = size_probe_32(cfg, bdf, off_hi, orig_hi, !0u32);
                (size_hi as u64) << 32
            } else {
                size_lo as u64
            };

            let address = ((orig_hi as u64) << 32) | (orig & !0xf) as u64;

            if size != 0 {
                out[n] = Some(Bar { index: i as u8, kind: BarKind::Mem64, prefetchable, address, size });
                n += 1;
            }
            i += 2; // consume the high-half slot too, implemented or not
            continue;
        }

        let size = size_probe_32(cfg, bdf, off, orig, !0xfu32);
        if size != 0 {
            out[n] = Some(Bar {
                index: i as u8,
                kind: BarKind::Mem32,
                prefetchable,
                address: (orig & !0xf) as u64,
                size,
            });
            n += 1;
        }
        i += 1;
    }

    if slots != 0 && decode != 0 {
        set_command_bits(cfg, bdf, decode);
    }
    (out, n)
}

/// Save/probe/restore one 32-bit BAR register. `decode_mask` strips the
/// low decode-type bits (`!0x3` for I/O, `!0xf` for memory) before the
/// two's-complement size derivation.
fn size_probe_32<C: ConfigSpace>(cfg: &mut C, bdf: Bdf, off: u16, orig: u32, decode_mask: u32) -> u64 {
    cfg.write32(bdf, off, 0xffff_ffff);
    let probed = cfg.read32(bdf, off);
    cfg.write32(bdf, off, orig); // restore before doing anything else

    let masked = probed & decode_mask;
    // The size is the lowest address bit the BAR decodes. Not `!masked + 1`:
    // an I/O BAR that decodes 16 bits reads its upper half back as 0
    // (0x0000_ffe1 for 32 bytes), and the complement would make it 4 GiB
    // (Linux `pci_size` takes the lowest set bit too).
    (masked & masked.wrapping_neg()) as u64
}

// ---------------------------------------------------------------------
// MSI (capability 0x05)
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsiInfo {
    pub cap_offset: u16,
    pub addr64_capable: bool,
    pub per_vector_masking: bool,
    /// 2^n vectors the device *can* request (Multiple Message Capable).
    pub max_vectors: u16,
}

/// Parse the MSI capability at `cap.offset` (caller already found it via
/// [`walk_capabilities`] and checked `id == CAP_ID_MSI`). Does not enable
/// MSI or program an address/data pair — that is a policy decision
/// (which vector table, which IMSIC/ITS to target) this crate does not
/// make, which is why vector *delivery* is out of scope here.
pub fn parse_msi<C: ConfigSpace>(cfg: &C, bdf: Bdf, cap: Capability) -> MsiInfo {
    let msg_ctrl = cfg.read16(bdf, cap.offset + 2);
    let mmc = (msg_ctrl >> 1) & 0x7;
    MsiInfo {
        cap_offset: cap.offset,
        addr64_capable: msg_ctrl & (1 << 7) != 0,
        per_vector_masking: msg_ctrl & (1 << 8) != 0,
        max_vectors: 1u16 << mmc,
    }
}

// ---------------------------------------------------------------------
// MSI-X (capability 0x11)
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsixInfo {
    pub cap_offset: u16,
    /// Table size is encoded as N-1; this is already N (vector count).
    pub table_size: u16,
    pub table_bar: u8,
    pub table_offset: u32,
    pub pba_bar: u8,
    pub pba_offset: u32,
}

/// Parse the MSI-X capability at `cap.offset`. The table/PBA offset
/// fields pack a BAR index into the low 3 bits — mask those off before
/// treating the rest as a byte offset (the field is defined 8-byte
/// aligned, so the low 3 bits are exactly the BAR-index bits and no
/// offset bits are lost).
pub fn parse_msix<C: ConfigSpace>(cfg: &C, bdf: Bdf, cap: Capability) -> MsixInfo {
    let msg_ctrl = cfg.read16(bdf, cap.offset + 2);
    let table = cfg.read32(bdf, cap.offset + 4);
    let pba = cfg.read32(bdf, cap.offset + 8);

    MsixInfo {
        cap_offset: cap.offset,
        table_size: (msg_ctrl & 0x7ff) + 1,
        table_bar: (table & 0x7) as u8,
        table_offset: table & !0x7,
        pba_bar: (pba & 0x7) as u8,
        pba_offset: pba & !0x7,
    }
}

/// Do the MSI-X table and the PBA lie inside the memory BARs they name?
/// Both are read off config space the device controls: a BIR of 6 or 7, an
/// I/O or absent BAR, or an offset plus the table (16 bytes a vector) or the
/// PBA (a bit a vector, in dwords) that runs past the BAR's size would send
/// [`program_msix_entry`]'s writes outside the window the kernel mapped.
pub fn msix_fits(msix: &MsixInfo, bars: &[Option<Bar>]) -> bool {
    let fits = |bir: u8, off: u32, len: u64| {
        bars.iter().flatten().any(|b| {
            b.index == bir && b.kind != BarKind::Io && off as u64 + len <= b.size
        })
    };
    let n = msix.table_size as u64;
    fits(msix.table_bar, msix.table_offset, n * MSIX_TABLE_ENTRY_SIZE as u64)
        && fits(msix.pba_bar, msix.pba_offset, n.div_ceil(32) * 4)
}

// ---------------------------------------------------------------------
// One-line-per-function report (the gate keys on this format)
// ---------------------------------------------------------------------

/// Everything the stage-1 gate row needs about one function, gathered in
/// one pass so the caller (kernel boot enumeration, or a host test) can
/// format it without re-walking config space.
#[derive(Clone, Copy, Debug)]
pub struct FunctionInfo {
    pub bdf: Bdf,
    pub vendor: u16,
    pub device: u16,
    /// The class code: base class, sub class, programming interface
    /// (config offset 0x09..0x0b), `0x010802` for an NVMe controller.
    pub class: u32,
    pub bars: [Option<Bar>; BAR_COUNT],
    pub bar_count: usize,
    pub msi: Option<MsiInfo>,
    /// `None` too when the capability is there but its table or PBA does
    /// not fit its BAR ([`msix_fits`]): the function is driven without it.
    pub msix: Option<MsixInfo>,
    pub vendor_cap: Option<Capability>,
}

pub fn probe_function<C: ConfigSpace>(cfg: &mut C, bdf: Bdf) -> Option<FunctionInfo> {
    if !function_exists(cfg, bdf) {
        return None;
    }
    let vendor = cfg.read16(bdf, OFF_VENDOR_ID);
    let device = cfg.read16(bdf, OFF_DEVICE_ID);
    let class = cfg.read32(bdf, OFF_CLASS_REV) >> 8;
    let (bars, bar_count) = decode_bars(cfg, bdf);
    let caps = walk_capabilities(cfg, bdf);

    let msi = caps.find(CAP_ID_MSI).map(|c| parse_msi(cfg, bdf, c));
    let msix = caps.find(CAP_ID_MSIX).map(|c| parse_msix(cfg, bdf, c)).filter(|m| msix_fits(m, &bars));
    let vendor_cap = caps.find(CAP_ID_VENDOR);

    Some(FunctionInfo { bdf, vendor, device, class, bars, bar_count, msi, msix, vendor_cap })
}

/// Buses [`enumerate_tree`] walks at most (bus 0 and the buses behind
/// bridges). Real machines have a handful; a bridge pointing back is cut by
/// the visited set, a long chain by this bound.
pub const TREE_MAX_BUSES: usize = 32;

/// Bridges the firmware left unnumbered that [`enumerate_tree`] remembers to
/// number after the walk. More than this on bus 0 and the rest stay dark.
const MAX_UNNUMBERED: usize = 8;

/// Memoised `ensure_bus`: the kernel maps a bus's slice of the ECAM window
/// there, once, however many times the walk comes back to the bus.
struct Reach<'a> {
    ensure: &'a mut dyn FnMut(u8) -> bool,
    asked: [bool; 256],
    ok: [bool; 256],
}

impl Reach<'_> {
    fn bus(&mut self, bus: u8) -> bool {
        if bus == 0 {
            return true;
        }
        let i = bus as usize;
        if !self.asked[i] {
            self.asked[i] = true;
            self.ok[i] = (self.ensure)(bus);
        }
        self.ok[i]
    }
}

/// The functions [`enumerate_tree`] found: the first `n` of `funcs`, and how
/// many more there were that did not fit (`dropped`: the capacity `N` is
/// Kconfig `PCI_MAX_FUNCTIONS` in the kernel). A dropped function is still
/// walked through (a bridge's buses behind it are numbered), it just has no
/// slot: no driver sees it.
pub struct Found<const N: usize> {
    pub funcs: [Option<FunctionInfo>; N],
    pub n: usize,
    pub dropped: usize,
}

impl<const N: usize> Found<N> {
    fn push(&mut self, info: FunctionInfo) {
        if self.n < N {
            self.funcs[self.n] = Some(info);
            self.n += 1;
        } else {
            self.dropped += 1;
        }
    }
}

/// Probe devices 0..32 of `bus` (function 0 gates whether 1..8 are probed at
/// all, per spec: a non-multifunction function-0 header means the rest of
/// that device's functions cannot exist), push every function found to `out`
/// and call `on_bridge` for each PCI-to-PCI bridge.
fn scan_bus<C: ConfigSpace, const N: usize>(
    cfg: &mut C,
    bus: u8,
    out: &mut Found<N>,
    on_bridge: &mut dyn FnMut(&mut C, Bdf),
) {
    for device in 0u8..32 {
        let bdf0 = Bdf::new(bus, device, 0);
        if !function_exists(cfg, bdf0) {
            continue;
        }
        let header_type = cfg.read8(bdf0, OFF_HEADER_TYPE);
        let multifunction = header_type & HEADER_TYPE_MULTIFUNC != 0;
        let max_func = if multifunction { 8 } else { 1 };

        for function in 0u8..max_func {
            let bdf = Bdf::new(bus, device, function);
            let Some(info) = probe_function(cfg, bdf) else { continue };
            out.push(info);
            if cfg.read8(bdf, OFF_HEADER_TYPE) & HEADER_TYPE_MASK == HEADER_TYPE_BRIDGE {
                on_bridge(cfg, bdf);
            }
        }
    }
}

/// Program bridge `bdf`'s bus numbers and return whether they stuck (a
/// register that ignores the write is no bridge worth walking behind). The
/// secondary latency timer byte is left as it was.
pub fn set_bus_numbers<C: ConfigSpace>(cfg: &mut C, bdf: Bdf, primary: u8, secondary: u8, subordinate: u8) -> bool {
    let keep = cfg.read32(bdf, OFF_PRIMARY_BUS) & 0xff00_0000;
    cfg.write32(
        bdf,
        OFF_PRIMARY_BUS,
        keep | (subordinate as u32) << 16 | (secondary as u32) << 8 | primary as u32,
    );
    cfg.read8(bdf, OFF_SECONDARY_BUS) == secondary && cfg.read8(bdf, OFF_SUBORDINATE_BUS) == subordinate
}

/// The numbering state of the DFS that gives a fresh bridge its buses.
struct Numbering<'r, 'a> {
    reach: &'r mut Reach<'a>,
    /// Next bus number to hand out.
    next: u16,
    /// Buses the walk may still add (the [`TREE_MAX_BUSES`] bound).
    budget: usize,
}

/// Give bridge `bdf` (on `bus`) a secondary bus, walk it, give the bridges
/// found there theirs, and close the bridge's subordinate range around all
/// of them. Depth first, so every bridge's `[secondary, subordinate]` holds
/// exactly the buses behind it: a breadth-first numbering would put a
/// sibling's bus inside the first bridge's range. While the buses below are
/// walked the subordinate is 0xff, or config cycles would stop at the bridge.
fn number_below<C: ConfigSpace, const N: usize>(
    cfg: &mut C,
    st: &mut Numbering<'_, '_>,
    bdf: Bdf,
    out: &mut Found<N>,
) {
    // The bus number is narrowed once, with the bound as the conversion: a
    // `next` past 255 (the firmware used bus 255) has no bus to give, and an
    // `as u8` there would wrap to a bus the walk already numbered.
    let Ok(sec) = u8::try_from(st.next) else { return };
    if st.budget == 0 {
        return;
    }
    let before = cfg.read32(bdf, OFF_PRIMARY_BUS);
    if !set_bus_numbers(cfg, bdf, bdf.bus, sec, 0xff) {
        // Hardware ignored the numbers: the bridge stays as it was.
        cfg.write32(bdf, OFF_PRIMARY_BUS, before);
        return;
    }
    st.next += 1;
    st.budget -= 1;
    if st.reach.bus(sec) {
        let mut below = [Bdf::new(0, 0, 0); MAX_UNNUMBERED];
        let mut n_below = 0usize;
        scan_bus(cfg, sec, out, &mut |_, b| {
            if n_below < MAX_UNNUMBERED {
                below[n_below] = b;
                n_below += 1;
            }
        });
        for b in &below[..n_below] {
            number_below(cfg, st, *b, out);
        }
    }
    // `next` is at most 256 here, so `next - 1` fits; saturate rather than wrap.
    set_bus_numbers(cfg, bdf, bdf.bus, sec, u8::try_from(st.next - 1).unwrap_or(0xff));
}

/// Enumerate the functions of bus 0 and of every bus behind a PCI-to-PCI
/// bridge: devices 0..32, functions 0..8, in bus order (bus 0 first, then
/// the buses in the order their bridges were found). Fixed output capacity
/// `N` (the kernel's is Kconfig `PCI_MAX_FUNCTIONS`); the functions past it
/// are counted in [`Found::dropped`], never silently lost.
///
/// `ensure_bus(b)` is called once, before bus `b > 0` is read, and answers
/// whether its configuration space is reachable (the kernel maps that bus's
/// slice of the ECAM window there); `false` skips the bus.
///
/// A bridge on bus 0 whose secondary bus number is 0, or not above its own
/// bus (firmware that never numbered it: nothing runs a PCI init step ahead
/// of this kernel on QEMU `virt`, and a board's firmware may leave bridges
/// dark too), is given buses of its own after the walk, above every bus the
/// firmware used, and the buses behind it are walked and numbered the same
/// way (their functions follow the others in the output). A bridge on any
/// other firmware-numbered bus is left as found, as is one whose secondary
/// bus another bridge already claimed or whose registers ignore the write.
pub fn enumerate_tree<C: ConfigSpace, const N: usize>(
    cfg: &mut C,
    ensure_bus: &mut dyn FnMut(u8) -> bool,
) -> Found<N> {
    let mut out = Found { funcs: [None; N], n: 0, dropped: 0 };
    let mut reach = Reach { ensure: ensure_bus, asked: [false; 256], ok: [false; 256] };
    let mut queue = [0u8; TREE_MAX_BUSES];
    let (mut head, mut tail) = (0usize, 1usize);
    let mut seen = [false; 256];
    seen[0] = true;
    // Highest bus number the firmware's own numbering uses.
    let mut highest = 0u8;
    let mut unnumbered = [Bdf::new(0, 0, 0); MAX_UNNUMBERED];
    let mut n_unnumbered = 0usize;

    while head < tail {
        let bus = queue[head];
        head += 1;
        if !reach.bus(bus) {
            continue;
        }
        scan_bus(cfg, bus, &mut out, &mut |cfg, bdf| {
            let sec = cfg.read8(bdf, OFF_SECONDARY_BUS);
            let sub = cfg.read8(bdf, OFF_SUBORDINATE_BUS);
            if sec > bus {
                highest = highest.max(sec).max(sub);
                if !seen[sec as usize] && tail < TREE_MAX_BUSES {
                    seen[sec as usize] = true;
                    queue[tail] = sec;
                    tail += 1;
                }
            } else if bus == 0 && n_unnumbered < MAX_UNNUMBERED {
                unnumbered[n_unnumbered] = bdf;
                n_unnumbered += 1;
            }
        });
    }

    let mut st = Numbering { reach: &mut reach, next: highest as u16 + 1, budget: TREE_MAX_BUSES - tail };
    for bdf in &unnumbered[..n_unnumbered] {
        number_below(cfg, &mut st, *bdf, &mut out);
    }

    out
}

/// Format one function as the gate's one-line-per-function text, e.g.
/// `pci 00:01.0 1af4:1041 bar0=mem64:0x40000000+0x4000 msix=y`.
pub fn format_function_line(info: &FunctionInfo, buf: &mut dyn fmt::Write) -> fmt::Result {
    write!(buf, "pci {} {:04x}:{:04x}", info.bdf, info.vendor, info.device)?;
    for bar in info.bars[..info.bar_count].iter().flatten() {
        let kind = match bar.kind {
            BarKind::Io => "io",
            BarKind::Mem32 => "mem32",
            BarKind::Mem64 => "mem64",
        };
        write!(buf, " bar{}={}:0x{:x}+0x{:x}", bar.index, kind, bar.address, bar.size)?;
    }
    write!(buf, " msi={} msix={}", if info.msi.is_some() { "y" } else { "n" }, if info.msix.is_some() { "y" } else { "n" })?;
    Ok(())
}

// ---------------------------------------------------------------------
// Command register (MSI-X delivery needs both bits)
// ---------------------------------------------------------------------

/// Base class and sub class (config 0x0b, 0x0a) of a host bridge.
pub const CLASS_BRIDGE_HOST: u32 = 0x0600;

pub const CMD_IO_SPACE: u16 = 1 << 0;
pub const CMD_MEM_SPACE: u16 = 1 << 1;
pub const CMD_BUS_MASTER: u16 = 1 << 2;
/// Interrupt Disable: the function does not assert its INTx pin. Set while
/// MSI or MSI-X is on (PCI Local Bus 3.0 section 6.8: a function "is
/// prohibited from using its INTx# pin" then, and a device that still drives
/// it shares a line with nobody's handler); cleared when MSI-X goes off.
pub const CMD_INTX_DISABLE: u16 = 1 << 10;

/// Set `bits` in the Command register (a read-modify-write that never
/// clears a bit the caller didn't name). **`CMD_BUS_MASTER` is not
/// optional for MSI-X**: an MSI-X message is the device's own DMA write to
/// the target address, and with Bus Master Enable clear QEMU (and real
/// hardware) silently drops that write. Without this, an MSI-X delivery
/// canary's "count stays 0" bucket would pass for the wrong reason — the
/// device never being allowed to write at all, not the AIA/IMSIC wiring
/// under test being absent.
///
/// The Command/Status pair share one dword (Command low 16 bits, Status
/// high 16). Status's upper bits are RW1C (write-1-to-clear) error flags
/// (Detected Parity Error, Signaled Target Abort, ...); writing back
/// whatever Status currently reads as would risk clearing a real pending
/// error the instant this function is called for an unrelated reason.
/// Writing 0 for the whole Status half instead is always safe — RW1C bits
/// ignore a 0, by definition — so that is what this function does.
pub fn set_command_bits<C: ConfigSpace>(cfg: &mut C, bdf: Bdf, bits: u16) {
    let cur = cfg.read16(bdf, OFF_COMMAND);
    let merged = (cur | bits) as u32; // high 16 (Status) left 0 — see doc above.
    cfg.write32(bdf, OFF_COMMAND, merged);
}

/// Clear `bits` in the Command register, leaving every other Command bit
/// as read and writing 0 to Status (RW1C — see [`set_command_bits`]).
/// Used before re-assigning BARs of a function whose Memory Space decode
/// an earlier user left on: [`assign_bar`] requires decode off.
pub fn clear_command_bits<C: ConfigSpace>(cfg: &mut C, bdf: Bdf, bits: u16) {
    let cur = cfg.read16(bdf, OFF_COMMAND);
    cfg.write32(bdf, OFF_COMMAND, (cur & !bits) as u32);
}

// ---------------------------------------------------------------------
// MSI-X table / PBA arithmetic and programming
// ---------------------------------------------------------------------

/// Byte size of one MSI-X table entry (PCI Express Base Spec §6.8.2.9,
/// fixed regardless of implementation): address_lo, address_hi, data,
/// vector_control — four dwords.
pub const MSIX_TABLE_ENTRY_SIZE: u32 = 16;

/// Byte offset of vector `index`'s table entry within the BAR window
/// `msix.table_bar` points at (caller adds `msix.table_offset`).
pub const fn msix_table_entry_offset(index: u16) -> u32 {
    index as u32 * MSIX_TABLE_ENTRY_SIZE
}

/// `vector_control`'s Mask Bit (bit 0 of the entry's 4th dword) — 1 masks
/// the vector (the device must not deliver it even with MSI-X Enable
/// set), 0 unmasks. Per-vector; [`MSGCTRL_FUNCTION_MASK`] is the
/// whole-function override at the capability level instead.
pub const MSIX_VECTOR_CTRL_MASK: u32 = 1 << 0;

/// Which PBA dword, and which bit within it, holds vector `index`'s
/// pending bit (PCI Express Base Spec §6.8.2.10: one bit per vector,
/// packed 32 per dword).
pub const fn msix_pba_word_and_bit(index: u16) -> (u32, u32) {
    ((index as u32) / 32, (index as u32) % 32)
}

/// Message Control (capability offset `cap_offset + 2`) bits this crate
/// programs.
pub const MSGCTRL_MSIX_ENABLE: u16 = 1 << 15;
pub const MSGCTRL_FUNCTION_MASK: u16 = 1 << 14;

/// Set or clear MSI-X Enable at the capability level (Message Control bit
/// 15) — the bit the stage-1a canary flips: "disable the MSI-X enable bit
/// -> the per-vector count stays 0 and the row fails". Leaves Function
/// Mask (bit 14) untouched. INTx goes off before MSI-X goes on and comes
/// back after it goes off ([`CMD_INTX_DISABLE`], Linux `pci_intx_for_msi`).
pub fn msix_set_enable<C: ConfigSpace>(cfg: &mut C, bdf: Bdf, msix: &MsixInfo, enable: bool) {
    let enable = enable && !cfg!(feature = "msix-enable-canary");
    if enable {
        set_command_bits(cfg, bdf, CMD_INTX_DISABLE);
    }
    let dword = cfg.read32(bdf, msix.cap_offset);
    let msg_ctrl = (dword >> 16) as u16;
    let new_ctrl = if enable { msg_ctrl | MSGCTRL_MSIX_ENABLE } else { msg_ctrl & !MSGCTRL_MSIX_ENABLE };
    let merged = ((new_ctrl as u32) << 16) | (dword & 0xffff);
    cfg.write32(bdf, msix.cap_offset, merged);
    if !enable {
        clear_command_bits(cfg, bdf, CMD_INTX_DISABLE);
    }
}

/// Is MSI-X Enable currently set? Re-reads hardware rather than trusting
/// a cached flag — the same discipline `plic::complete`'s SMP fix already
/// established in this tree ("read the hardware enable register, not a
/// cached software flag").
pub fn msix_is_enabled<C: ConfigSpace>(cfg: &C, bdf: Bdf, msix: &MsixInfo) -> bool {
    cfg.read16(bdf, msix.cap_offset + 2) & MSGCTRL_MSIX_ENABLE != 0
}

// ---------------------------------------------------------------------
// MSI programming (one vector)
// ---------------------------------------------------------------------

/// Message Control bit 0: MSI Enable.
pub const MSGCTRL_MSI_ENABLE: u16 = 1 << 0;
/// Message Control bits 6:4: Multiple Message Enable.
pub const MSGCTRL_MSI_MME_MASK: u16 = 0x7 << 4;

/// Program the single vector of the MSI capability `msi` with the message
/// (`addr`, `data`) and turn MSI on. Devices with one interrupt cause and no
/// MSI-X table (the Intel e1000e family) use this where the virtio and NVMe
/// drivers use [`program_msix_entry`].
///
/// Layout (PCI Local Bus 3.0 section 6.8.1): Message Control at +2, Message
/// Address at +4 (and its upper half at +8 when the function is 64-bit
/// capable), Message Data (16 bits) after them, the mask bits after that when
/// per-vector masking is implemented.
///
/// Returns `false` and writes nothing when the message does not fit: `data`
/// wider than the 16-bit register, or an `addr` above 4 GiB on a function
/// that only has the low half.
pub fn program_msi<C: ConfigSpace>(cfg: &mut C, bdf: Bdf, msi: &MsiInfo, addr: u64, data: u32) -> bool {
    if data > 0xffff || (!msi.addr64_capable && addr > u32::MAX as u64) {
        return false;
    }
    let base = msi.cap_offset;
    // Message Control is the upper half of the capability's first dword; the
    // lower half (id, next pointer) is written back as read.
    let set_ctrl = |cfg: &mut C, f: &dyn Fn(u16) -> u16| {
        let dword = cfg.read32(bdf, base);
        let ctrl = f((dword >> 16) as u16);
        cfg.write32(bdf, base, (ctrl as u32) << 16 | (dword & 0xffff));
    };
    // Quiesce first: a half-written message must not be deliverable.
    set_ctrl(cfg, &|c| c & !MSGCTRL_MSI_ENABLE);
    cfg.write32(bdf, base + 4, addr as u32);
    let (data_off, mask_off) = if msi.addr64_capable {
        cfg.write32(bdf, base + 8, (addr >> 32) as u32);
        (base + 12, base + 16)
    } else {
        (base + 8, base + 12)
    };
    // The register is 16 bits; the half above it is reserved.
    cfg.write32(bdf, data_off, data);
    if msi.per_vector_masking {
        cfg.write32(bdf, mask_off, 0);
    }
    // INTx off before the message path is on ([`CMD_INTX_DISABLE`]).
    set_command_bits(cfg, bdf, CMD_INTX_DISABLE);
    // One vector: Multiple Message Enable (bits 6:4) = 0.
    set_ctrl(cfg, &|c| c & !MSGCTRL_MSI_MME_MASK | MSGCTRL_MSI_ENABLE);
    true
}

/// Is MSI Enable currently set? Re-reads the hardware, as
/// [`msix_is_enabled`] does.
pub fn msi_is_enabled<C: ConfigSpace>(cfg: &C, bdf: Bdf, msi: &MsiInfo) -> bool {
    cfg.read16(bdf, msi.cap_offset + 2) & MSGCTRL_MSI_ENABLE != 0
}

/// Byte-addressed MMIO access to a mapped PCI BAR — the seam that makes
/// MSI-X table/PBA programming host-testable, mirroring [`ConfigSpace`]
/// above. Deliberately NOT the same trait as
/// `crates/drivers/virtio/src/virtio/pci.rs`'s `Mmio` (which covers a virtio
/// device's own common/notify/isr BAR): reusing that one would make this
/// crate depend on `azos_drv_virtio`, inverting the dependency direction
/// this crate's module doc already commits to (drivers depends on pci).
pub trait BarMem {
    fn read32(&self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, val: u32);
}

/// Program MSI-X table entry `index` of `msix`'s table: message address
/// `addr` (64-bit — e.g. a RISC-V IMSIC hart file's physical address, or a
/// GICv3 ITS translater address on aarch64; this function has no ISA
/// content, only the PCI-defined entry layout), message data `data` (the
/// interrupt identity), and the per-vector mask bit. `false`, nothing
/// written, for an `index` past the table: the table ends at
/// `table_size` entries, and what follows it in the BAR (or past the BAR,
/// for a table at its end) is not ours to write. That the table itself
/// fits its BAR is [`msix_fits`]'s, checked when the function is probed.
pub fn program_msix_entry<M: BarMem>(
    mem: &mut M,
    msix: &MsixInfo,
    index: u16,
    addr: u64,
    data: u32,
    masked: bool,
) -> bool {
    if index >= msix.table_size {
        return false;
    }
    let base = msix.table_offset as usize + msix_table_entry_offset(index) as usize;
    mem.write32(base, addr as u32);
    mem.write32(base + 4, (addr >> 32) as u32);
    mem.write32(base + 8, data);
    mem.write32(base + 12, if masked { MSIX_VECTOR_CTRL_MASK } else { 0 });
    true
}

/// Read back pending bit `index` from `msix`'s PBA (`None` past the table).
/// The real completion count
/// this task's acceptance criteria wants is driven by the interrupt
/// controller (APLIC/IMSIC), not by polling this — this function exists
/// for tests and diagnostics, not the hot path.
pub fn msix_pba_pending<M: BarMem>(mem: &M, msix: &MsixInfo, index: u16) -> Option<bool> {
    if index >= msix.table_size {
        return None;
    }
    let (word, bit) = msix_pba_word_and_bit(index);
    let val = mem.read32(msix.pba_offset as usize + word as usize * 4);
    Some((val >> bit) & 1 != 0)
}

// ---------------------------------------------------------------------
// BAR assignment — nothing ahead of this kernel
// assigns BARs on QEMU `virt`, so a function's BARs read address 0. The
// addresses come from [`BarWindow`] (`window.rs`).
// ---------------------------------------------------------------------

/// Program memory BAR `bar` with BUS address `addr` and return it updated.
/// A 64-bit BAR gets both halves; a 32-bit BAR refuses an address above
/// 4 GiB; an I/O BAR is refused (this crate assigns memory BARs only).
/// Memory Space decode must be off (it is after reset) or enabled only
/// after this, so the device never decodes a half-written address.
pub fn assign_bar<C: ConfigSpace>(cfg: &mut C, bdf: Bdf, bar: &Bar, addr: u64) -> Option<Bar> {
    let off = OFF_BAR0 + (bar.index as u16) * 4;
    match bar.kind {
        BarKind::Io => return None,
        BarKind::Mem32 => {
            if addr > u32::MAX as u64 {
                return None;
            }
            let flags = cfg.read32(bdf, off) & 0xf;
            cfg.write32(bdf, off, (addr as u32 & !0xf) | flags);
        }
        BarKind::Mem64 => {
            let flags = cfg.read32(bdf, off) & 0xf;
            cfg.write32(bdf, off, (addr as u32 & !0xf) | flags);
            cfg.write32(bdf, off + 4, (addr >> 32) as u32);
        }
    }
    Some(Bar { address: addr, ..*bar })
}

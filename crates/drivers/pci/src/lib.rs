// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Native PCI/PCIe enumeration over ECAM (RFC-0046 stage 1).
//!
//! Pure logic against an injected [`ConfigSpace`] — no raw pointers, no
//! target asm, no `unsafe`. That is what lets `azos_pci_tests` pull
//! this crate on the host and exercise it against a fake config space,
//! and it is why `crates/drivers/virtio/src/virtio/pci.rs` is built the same way
//! (against this crate's types, not a `*mut u32`).
//!
//! Scope, stated once so it doesn't drift: bus 0 only (every QEMU `virt`
//! `-device ...-pci` attachment lands there), one ECAM segment, no ARI,
//! no SR-IOV. That covers stage 1's gate (one line per function on QEMU
//! `virt`, both ISAs) and is explicitly NOT a general PCIe subsystem.
#![no_std]

use core::fmt;

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
pub const OFF_HEADER_TYPE: u16 = 0x0e;
pub const OFF_BAR0: u16 = 0x10;
pub const OFF_CAP_PTR: u16 = 0x34;
pub const OFF_INTERRUPT_PIN: u16 = 0x3d;

pub const STATUS_CAP_LIST: u16 = 1 << 4;
pub const HEADER_TYPE_MULTIFUNC: u8 = 1 << 7;
pub const HEADER_TYPE_MASK: u8 = 0x7f;

pub const VENDOR_ID_NONE: u16 = 0xffff;

pub const CAP_ID_MSI: u8 = 0x05;
pub const CAP_ID_PCI_EXPRESS: u8 = 0x10;
pub const CAP_ID_MSIX: u8 = 0x11;
pub const CAP_ID_VENDOR: u8 = 0x09;

/// Present iff `Function::exists()` — cheapest possible probe: an absent
/// function reads all-ones on every register, so vendor id 0xffff is the
/// spec-defined "nothing here" sentinel.
pub fn function_exists<C: ConfigSpace>(cfg: &C, bdf: Bdf) -> bool {
    cfg.read16(bdf, OFF_VENDOR_ID) != VENDOR_ID_NONE
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
    /// Physical base address as currently programmed (0 if unassigned —
    /// callers doing BAR *assignment* look at `size` and pick their own
    /// base out of a window).
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

/// Decode all implemented BARs for a type-0 function, sizing each one via
/// the standard probe sequence: save original, write all-1s, read back
/// the size mask, **restore the original value** (leaving a BAR
/// temporarily unmapped between the two writes is a real hazard for a
/// live device — this function does the save/restore around each probed
/// BAR, not just at the end, so a fault mid-walk cannot leave two BARs
/// disabled at once).
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

    while i < BAR_COUNT {
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

        if is64 && i + 1 < BAR_COUNT {
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
    if masked == 0 {
        return 0;
    }
    // Size = ~masked + 1, in the same bit width as the mask.
    ((!masked).wrapping_add(1)) as u64
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
    pub bars: [Option<Bar>; BAR_COUNT],
    pub bar_count: usize,
    pub msi: Option<MsiInfo>,
    pub msix: Option<MsixInfo>,
    pub vendor_cap: Option<Capability>,
}

pub fn probe_function<C: ConfigSpace>(cfg: &mut C, bdf: Bdf) -> Option<FunctionInfo> {
    if !function_exists(cfg, bdf) {
        return None;
    }
    let vendor = cfg.read16(bdf, OFF_VENDOR_ID);
    let device = cfg.read16(bdf, OFF_DEVICE_ID);
    let (bars, bar_count) = decode_bars(cfg, bdf);
    let caps = walk_capabilities(cfg, bdf);

    let msi = caps.find(CAP_ID_MSI).map(|c| parse_msi(cfg, bdf, c));
    let msix = caps.find(CAP_ID_MSIX).map(|c| parse_msix(cfg, bdf, c));
    let vendor_cap = caps.find(CAP_ID_VENDOR);

    Some(FunctionInfo { bdf, vendor, device, bars, bar_count, msi, msix, vendor_cap })
}

/// Enumerate bus 0, devices 0..32, functions 0..8 (function 0 gates
/// whether 1..8 are probed at all, per spec — a non-multifunction
/// function-0 header means the rest of that device's functions cannot
/// exist). Fixed output capacity `N`; QEMU `virt` with the stage-1 gate's
/// device list (`virtio-net-pci`, `virtio-blk-pci`, `nvme`, the ECAM
/// bridge itself) needs single digits, so 32 is headroom, not a real
/// bound on PCI.
pub fn enumerate_bus0<C: ConfigSpace, const N: usize>(cfg: &mut C) -> ([Option<FunctionInfo>; N], usize) {
    let mut out: [Option<FunctionInfo>; N] = [None; N];
    let mut n = 0usize;

    for device in 0u8..32 {
        let bdf0 = Bdf::new(0, device, 0);
        if !function_exists(cfg, bdf0) {
            continue;
        }
        let header_type = cfg.read8(bdf0, OFF_HEADER_TYPE);
        let multifunction = header_type & HEADER_TYPE_MULTIFUNC != 0;
        let max_func = if multifunction { 8 } else { 1 };

        for function in 0u8..max_func {
            let bdf = Bdf::new(0, device, function);
            if let Some(info) = probe_function(cfg, bdf) {
                if n < N {
                    out[n] = Some(info);
                    n += 1;
                }
            }
        }
    }

    (out, n)
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
// Command register (RFC-0046 stage 1a — MSI-X delivery needs both bits)
// ---------------------------------------------------------------------

pub const CMD_MEM_SPACE: u16 = 1 << 1;
pub const CMD_BUS_MASTER: u16 = 1 << 2;

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
// MSI-X table / PBA arithmetic and programming (RFC-0046 stage 1a)
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
/// Mask (bit 14) untouched.
pub fn msix_set_enable<C: ConfigSpace>(cfg: &mut C, bdf: Bdf, msix: &MsixInfo, enable: bool) {
    let enable = enable && !cfg!(feature = "msix-enable-canary");
    let dword = cfg.read32(bdf, msix.cap_offset);
    let msg_ctrl = (dword >> 16) as u16;
    let new_ctrl = if enable { msg_ctrl | MSGCTRL_MSIX_ENABLE } else { msg_ctrl & !MSGCTRL_MSIX_ENABLE };
    let merged = ((new_ctrl as u32) << 16) | (dword & 0xffff);
    cfg.write32(bdf, msix.cap_offset, merged);
}

/// Is MSI-X Enable currently set? Re-reads hardware rather than trusting
/// a cached flag — the same discipline `plic::complete`'s SMP fix already
/// established in this tree ("read the hardware enable register, not a
/// cached software flag").
pub fn msix_is_enabled<C: ConfigSpace>(cfg: &C, bdf: Bdf, msix: &MsixInfo) -> bool {
    cfg.read16(bdf, msix.cap_offset + 2) & MSGCTRL_MSIX_ENABLE != 0
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

/// Program MSI-X table entry `index`: message address `addr` (64-bit —
/// e.g. a RISC-V IMSIC hart file's physical address, or a GICv3 ITS
/// translater address on aarch64; this function has no ISA content, only
/// the PCI-defined entry layout), message data `data` (the interrupt
/// identity), and the per-vector mask bit.
pub fn program_msix_entry<M: BarMem>(
    mem: &mut M,
    table_offset: u32,
    index: u16,
    addr: u64,
    data: u32,
    masked: bool,
) {
    let base = table_offset as usize + msix_table_entry_offset(index) as usize;
    mem.write32(base, addr as u32);
    mem.write32(base + 4, (addr >> 32) as u32);
    mem.write32(base + 8, data);
    mem.write32(base + 12, if masked { MSIX_VECTOR_CTRL_MASK } else { 0 });
}

/// Read back pending bit `index` from the PBA. The real completion count
/// this task's acceptance criteria wants is driven by the interrupt
/// controller (APLIC/IMSIC), not by polling this — this function exists
/// for tests and diagnostics, not the hot path.
pub fn msix_pba_pending<M: BarMem>(mem: &M, pba_offset: u32, index: u16) -> bool {
    let (word, bit) = msix_pba_word_and_bit(index);
    let val = mem.read32(pba_offset as usize + word as usize * 4);
    (val >> bit) & 1 != 0
}

// ---------------------------------------------------------------------
// BAR assignment (RFC-0046 stage 1a) — nothing ahead of this kernel
// assigns BARs on QEMU `virt`, so a function's BARs read address 0.
// ---------------------------------------------------------------------

/// Bump allocator over one bus-address window for memory BARs. BAR sizes
/// are powers of two and a BAR must be naturally aligned to its size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarWindow {
    next: u64,
    end: u64,
}

impl BarWindow {
    /// Window `[base, base + size)`.
    pub const fn new(base: u64, size: u64) -> Self {
        BarWindow { next: base, end: base.saturating_add(size) }
    }

    /// Reserve `size` bytes aligned to `size`. `None` if `size` is not a
    /// power of two or the window is exhausted.
    pub fn alloc(&mut self, size: u64) -> Option<u64> {
        if size == 0 || !size.is_power_of_two() {
            return None;
        }
        let addr = self.next.checked_add(size - 1)? & !(size - 1);
        let top = addr.checked_add(size)?;
        if top > self.end {
            return None;
        }
        self.next = top;
        Some(addr)
    }
}

/// Program memory BAR `bar` with bus address `addr` and return it updated.
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

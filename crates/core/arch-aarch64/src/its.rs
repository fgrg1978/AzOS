// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! GICv3 ITS (Interrupt Translation Service) — PCI MSI/MSI-X → LPI
//! delivery (RFC-0046 stage 1a).
//!
//! Companion to `gic.rs`'s new LPI section (redistributor PROPBASER/
//! PENDBASER/EnableLPIs — see that module's doc for the memory-attribute
//! decision the two share). This module owns the ITS side: the command
//! queue, the Devices `GITS_BASERn` table, and one Interrupt Translation
//! Table (ITT) per PCI device. Together they let a virtio-net-pci
//! (or any MSI-X) device's write to `GITS_TRANSLATER` turn into an LPI
//! (INTID >= [`crate::gic::LPI_INTID_BASE`]) delivered to a CPU interface.
//!
//! # Register offsets / command opcodes — verified, not recalled
//!
//! Every constant below was cross-checked against Linux v7.2.7's
//! `include/linux/irqchip/arm-gic-v3.h` and the `its_encode_*`/
//! `its_build_*_cmd` bodies in `drivers/irqchip/irq-gic-v3-its.c`
//! (elixir.bootlin.com, this session) rather than trusted from memory —
//! a wrong command opcode or bit range does not fault, it silently maps
//! nothing, which is exactly the failure mode this driver's absence already
//! meant ("MSIs have nowhere to go").
//!
//! # Scope (stage 1a, matches the brief's incremental structure)
//!
//! - **One collection (id 0, bound to the boot CPU).** `GITS_TYPER.HCC`
//!   (Hardware Collection Count) says how many collections the ITS holds
//!   internally. With `HCC >= 1` collection 0 lives in hardware; with
//!   `HCC == 0` (QEMU `virt`'s ITS) [`ItsDriver::init`] programs a one-page
//!   memory-backed table in the `GITS_BASERn` slot of Type Collection, and
//!   returns [`ItsError::NoCollectionCapacity`] only if no such slot exists.
//!   Multi-CPU LPI routing (more collections, one per hart) is follow-up
//!   work, not
//!   this stage's acceptance criterion (one virtio-net-pci device's
//!   MSI-X vectors landing as LPIs).
//! - **No Indirect device table.** [`MAX_DEVICES`] is small (this
//!   stage's device list is "the one virtio-net-pci function" plus
//!   headroom); a direct (non-indirect) `GITS_BASERn` table sized for
//!   `MAX_DEVICES * entry_size` fits in one 4 KiB page on every QEMU
//!   `virt` entry-size this driver has seen, and [`ItsDriver::init`]
//!   checks that rather than assuming it.
//! - **One command at a time, synchronously.** Every mapping call issues
//!   its command(s), a `SYNC`, and polls `GITS_CREADR` to completion
//!   before returning — no batching, no async completion tracking. Wrong
//!   for a hot path; irrelevant here, since device/vector mapping happens
//!   a handful of times at boot, not per-packet.

#[cfg(any(target_arch = "aarch64", test))]
use crate::gic;

// ──────────────────────────────────────────────────────────────────────────
// Pure decode/encode — no `target_arch` gate (see `gic.rs`'s own header
// comment for exactly why that matters on this project: the host test
// target is `aarch64-apple-darwin`, where `target_arch = "aarch64"` is
// true but EL1-only asm is not legal at EL0).
// ──────────────────────────────────────────────────────────────────────────

/// `GENMASK_ULL(hi, lo)` — inclusive bit range, same semantics as the
/// Linux macro this module's encoders are checked against. `hi == 63` is
/// handled separately because `1u64 << 64` is a shift-overflow panic in
/// debug builds, not merely UB, and every 64-bit-wide field this module
/// touches (`Valid`, `PTZ`) needs exactly that case.
const fn genmask(hi: u32, lo: u32) -> u64 {
    debug_assert!(hi < 64 && lo <= hi);
    if hi == 63 {
        !0u64 << lo
    } else {
        ((1u64 << (hi + 1)) - 1) & !((1u64 << lo) - 1)
    }
}

/// PCI RequesterID convention used as the ITS `DeviceID`: `bus<<8 |
/// device<<3 | function`. Matches `azos_pci::Bdf`'s own field masks
/// (`device` 0..=31, `function` 0..=7) — callers on the PCI side should
/// build this from a `Bdf` rather than pack the fields by hand a second
/// time (see `A2-pci.diff`, delivered to A1, for the arch hook that does
/// exactly that).
pub const fn device_id(bus: u8, device: u8, function: u8) -> u32 {
    ((bus as u32) << 8) | (((device & 0x1f) as u32) << 3) | ((function & 0x07) as u32)
}

// ---- GITS_TYPER decode --------------------------------------------------

pub const fn typer_plpis(typer: u64) -> bool {
    typer & 1 != 0
}
/// `GITS_TYPER.PTA` (bit 19) — 0: a collection's `target` field is a
/// linear Processor Number (redistributor's own `GICR_TYPER` bits
/// [23:8]); 1: `target` is the redistributor's physical base address.
/// [`ItsDriver::init`] reads this once and picks the matching
/// `collection_target_*` helper below — never assumed either way.
pub const fn typer_pta(typer: u64) -> bool {
    typer & (1 << 19) != 0
}
/// `GITS_TYPER.HCC` (bits [31:24]) — Hardware Collection Count, the
/// number of collections usable WITHOUT a memory-backed Collections
/// table. See this module's header doc for why stage 1a relies on this
/// being `>= 1` instead of building that table.
pub const fn typer_hcc(typer: u64) -> u8 {
    ((typer >> 24) & 0xff) as u8
}

// ---- ITS command opcodes (GITS_CMD_*) -----------------------------------

pub const GITS_CMD_MOVI: u8 = 0x01;
pub const GITS_CMD_INT: u8 = 0x03;
pub const GITS_CMD_CLEAR: u8 = 0x04;
pub const GITS_CMD_SYNC: u8 = 0x05;
pub const GITS_CMD_MAPD: u8 = 0x08;
pub const GITS_CMD_MAPC: u8 = 0x09;
pub const GITS_CMD_MAPTI: u8 = 0x0a;
pub const GITS_CMD_MAPI: u8 = 0x0b;
pub const GITS_CMD_INV: u8 = 0x0c;
pub const GITS_CMD_INVALL: u8 = 0x0d;
pub const GITS_CMD_MOVALL: u8 = 0x0e;
pub const GITS_CMD_DISCARD: u8 = 0x0f;

/// Every ITS command is 32 bytes: four 64-bit doublewords.
pub type ItsCommand = [u64; 4];

/// `MAPD` — bind `device_id` to an Interrupt Translation Table at
/// `itt_addr` (must be 256-byte aligned — the architectural ITT address
/// field is `[51:8]`, so any nonzero low byte is silently dropped by the
/// hardware, not rejected). `id_bits_minus1` is the number of EventID
/// bits this device's ITT covers, minus one (i.e. `log2(event_capacity)
/// - 1`) — the same "Size" field Linux's `its_build_mapd_cmd` derives
/// from `ilog2(nr_ites)`.
pub const fn cmd_mapd(dev: u32, id_bits_minus1: u8, itt_addr: u64, valid: bool) -> ItsCommand {
    let dw0 = (GITS_CMD_MAPD as u64 & genmask(7, 0)) | (((dev as u64) << 32) & genmask(63, 32));
    let dw1 = (id_bits_minus1 as u64) & genmask(4, 0);
    let dw2 = (itt_addr & genmask(51, 8)) | if valid { genmask(63, 63) } else { 0 };
    [dw0, dw1, dw2, 0]
}

/// `MAPC` — bind collection `col` to `target` (pre-shifted by
/// [`collection_target_cpu_number`] or [`collection_target_rdbase`] —
/// its low 16 bits MUST already be zero, which both of those guarantee;
/// see their docs for why masking here alone is not equivalent to
/// Linux's `its_encode_target`'s explicit `>> 16` unless that holds).
pub const fn cmd_mapc(col: u16, target: u64, valid: bool) -> ItsCommand {
    let dw0 = GITS_CMD_MAPC as u64 & genmask(7, 0);
    let dw2 = ((col as u64) & genmask(15, 0))
        | (target & genmask(51, 16))
        | if valid { genmask(63, 63) } else { 0 };
    [dw0, 0, dw2, 0]
}

/// `MAPTI` — map `dev`'s `event_id` to physical INTID `phys_id`
/// (>= [`crate::gic::LPI_INTID_BASE`]) in collection `col`.
pub const fn cmd_mapti(dev: u32, event_id: u32, phys_id: u32, col: u16) -> ItsCommand {
    let dw0 = (GITS_CMD_MAPTI as u64 & genmask(7, 0)) | (((dev as u64) << 32) & genmask(63, 32));
    let dw1 = ((event_id as u64) & genmask(31, 0)) | (((phys_id as u64) << 32) & genmask(63, 32));
    let dw2 = (col as u64) & genmask(15, 0);
    [dw0, dw1, dw2, 0]
}

/// `INVALL` — invalidate cached config for every LPI in collection `col`.
pub const fn cmd_invall(col: u16) -> ItsCommand {
    let dw0 = GITS_CMD_INVALL as u64 & genmask(7, 0);
    let dw2 = (col as u64) & genmask(15, 0);
    [dw0, 0, dw2, 0]
}

/// One shape shared by `INV`/`CLEAR`/`DISCARD`/`INT` — all four take just
/// `(device_id, event_id)`, differing only in opcode.
const fn cmd_dev_event(opcode: u8, dev: u32, event_id: u32) -> ItsCommand {
    let dw0 = (opcode as u64 & genmask(7, 0)) | (((dev as u64) << 32) & genmask(63, 32));
    let dw1 = (event_id as u64) & genmask(31, 0);
    [dw0, dw1, 0, 0]
}
pub const fn cmd_inv(dev: u32, event_id: u32) -> ItsCommand {
    cmd_dev_event(GITS_CMD_INV, dev, event_id)
}
pub const fn cmd_clear(dev: u32, event_id: u32) -> ItsCommand {
    cmd_dev_event(GITS_CMD_CLEAR, dev, event_id)
}
pub const fn cmd_discard(dev: u32, event_id: u32) -> ItsCommand {
    cmd_dev_event(GITS_CMD_DISCARD, dev, event_id)
}

/// `SYNC` — drain the ITS's internal pipeline for `target`'s redistributor
/// before any command queued after this one is guaranteed visible there.
/// [`ItsDriver`] issues one after every mapping command and polls
/// `GITS_CREADR` past it — the only completion signal this driver uses.
pub const fn cmd_sync(target: u64) -> ItsCommand {
    let dw0 = GITS_CMD_SYNC as u64 & genmask(7, 0);
    let dw2 = target & genmask(51, 16);
    [dw0, 0, dw2, 0]
}

/// A collection `target` when `GITS_TYPER.PTA == 0`: the redistributor's
/// own linear Processor Number ([`crate::gic::typer_cpu_number`]),
/// pre-shifted into the position [`cmd_mapc`]/[`cmd_sync`] expect (bits
/// [51:16] of the raw command — Linux's `its_encode_target` gets there by
/// right-shifting `target_addr` by 16 first; shifting `cpu_number` LEFT by
/// 16 up front and masking `[51:16]` directly is the same result exactly
/// because the low 16 bits are zero either way — see the module doc's
/// verified-not-recalled note for where this equivalence was checked).
pub const fn collection_target_cpu_number(cpu_number: u16) -> u64 {
    (cpu_number as u64) << 16
}

/// A collection `target` when `GITS_TYPER.PTA == 1`: the redistributor's
/// physical `RD_base` directly (already 64 KiB aligned, so its own low 16
/// bits are zero — same masking argument as
/// [`collection_target_cpu_number`]).
pub const fn collection_target_rdbase(rd_phys_base: u64) -> u64 {
    rd_phys_base
}

// ---- GITS_CBASER / GITS_BASERn ------------------------------------------

/// `GIC_BASER_CACHE_RaWaWb` (architecture spec naming, value `0b111`) —
/// Normal Read-allocate/Write-allocate Write-Back. Same choice as
/// `gic.rs`'s `BASER_CACHE_RAWAWB` and the same reasoning (this module's
/// doc's memory-attribute note); duplicated here as its own named
/// constant because `GITS_CBASER`/`GITS_BASERn`'s cacheability field sits
/// at a DIFFERENT bit shift (59) than `GICR_PROPBASER`/`PENDBASER`'s (7),
/// so the two crates' constants are not interchangeable even though the
/// 3-bit code is.
const BASER_CACHE_RAWAWB: u64 = 0b111;
const BASER_SHAREABILITY_INNER: u64 = 0b01;

/// Physical address the ITS/redistributor must be given for a kernel
/// static. The aarch64 kernel runs in the TTBR1 upper half
/// (`crate::mmu::KERNEL_VA_OFFSET`, `phys_to_virt(pa) = pa | OFFSET`), so a
/// `'static`'s address is a HIGH virtual address, not the physical one the
/// GIC's table walker uses. Masking the offset back off is exact for a VA
/// produced by that OR and idempotent on an already-low address — the same
/// idiom `crates/core/mm::addr::virt_to_phys` uses, which this crate cannot
/// depend on. (This driver used to pass `addr_of!(STATIC) as u64` straight
/// through, under a stated identity-mapping assumption that stopped being
/// true when the kernel moved into TTBR1.)
pub const fn kva_to_pa(va: u64) -> u64 {
    va & !crate::mmu::KERNEL_VA_OFFSET
}

/// One LPI Configuration table entry (GICv3 §5.1.1): priority in bits
/// [7:2], bit 1 RES1-as-0 here, bit 0 = Enable. The table is indexed from
/// LPI 8192 (`byte[intid - LPI_INTID_BASE]`). An entry left at 0 (the
/// static table's initial value) is a DISABLED LPI: the ITS still
/// translates the device's write, and the redistributor drops it — which is
/// how the first wave-4 boot read `tx used=1` with zero LPIs delivered.
/// Priority 0xA0 matches the SPIs `init_distributor` programs; the CPU
/// interface's PMR is 0xFF, so it is never masked.
pub const LPI_DEFAULT_PRIORITY: u8 = 0xA0;
pub const fn lpi_config_byte(priority: u8, enabled: bool) -> u8 {
    (priority & 0xFC) | if enabled { 1 } else { 0 }
}

pub const BASER_TYPE_DEVICE: u8 = 1;
pub const BASER_TYPE_COLLECTION: u8 = 4;

/// `GITS_BASERn.Type` (bits [58:56]) — which table this slot describes.
/// Software must probe all 8 `GITS_BASERn` registers and read each one's
/// reset value to find out (the slot→type binding is hardware-fixed, NOT
/// index 0 == Devices — a driver that assumed that would work on some
/// implementations and silently misprogram others).
pub const fn baser_type(reg: u64) -> u8 {
    ((reg >> 56) & 0x7) as u8
}
/// `GITS_BASERn.EntrySize` (bits [52:48], value+1) — bytes per table
/// entry, hardware-defined and read-only; software sizes the table from
/// this, never assumes a fixed entry width.
pub const fn baser_entry_size(reg: u64) -> u32 {
    (((reg >> 48) & 0x1f) as u32) + 1
}

/// Rebuild a `GITS_BASERn` value from its own reset value `existing`
/// (which supplies the hardware-fixed `Type`/`EntrySize`/`Indirect` bits
/// this function must NOT clobber), pointing it at `phys_base`
/// (4 KiB-aligned, `n_pages_minus1` 4 KiB pages) and setting `Valid`.
pub const fn baser_value(existing: u64, phys_base: u64, n_pages_minus1: u8, valid: bool) -> u64 {
    let preserved = existing & (genmask(62, 62) | genmask(58, 48)); // Indirect, Type, EntrySize
    preserved
        | (BASER_CACHE_RAWAWB << 59)
        | (BASER_SHAREABILITY_INNER << 10)
        | (phys_base & genmask(47, 12))
        | (n_pages_minus1 as u64 & genmask(7, 0))
        | if valid { genmask(63, 63) } else { 0 }
}

/// `GITS_CBASER` — the command queue's own base/size/valid.
pub const fn cbaser_value(phys_base: u64, n_pages_minus1: u8, valid: bool) -> u64 {
    (BASER_CACHE_RAWAWB << 59)
        | (BASER_SHAREABILITY_INNER << 10)
        | (phys_base & genmask(51, 12))
        | (n_pages_minus1 as u64 & genmask(7, 0))
        | if valid { genmask(63, 63) } else { 0 }
}

/// Absolute address of `GITS_TRANSLATER` — the ONE register a PCI
/// function's MSI-X address points at. Frame layout (verified against
/// Linux's `GITS_TRANSLATER == 0x10040` relative to the ITS control
/// frame's own base): control frame `[GITS_BASE, +0x10000)`, translation
/// frame `[GITS_BASE+0x10000, +0x20000)`, register at `+0x40` within
/// that second frame.
pub const fn translater_address(its_base: usize) -> usize {
    its_base + 0x1_0000 + 0x0040
}

/// The MSI address/data pair for `event_id` on the ITS at `its_base` —
/// exactly what a PCI MSI-X table entry needs (address = where to write,
/// data = what to write). This is the "arch hook" `A2-pci.diff` wires
/// `crates/drivers/virtio/src/virtio/pci.rs`'s `msix_vector` doc up to, in place
/// of the `VIRTIO_PCI_NO_VECTOR` it programs today.
pub const fn msi_target(its_base: usize, event_id: u32) -> (u64, u32) {
    (translater_address(its_base) as u64, event_id)
}

// ──────────────────────────────────────────────────────────────────────────
// Driver — target_arch-gated (see `gic.rs`'s header comment for why: the
// host test target is `aarch64-apple-darwin`, `target_arch = "aarch64"`
// there too, so anything that touches real MMIO or EL1-only state lives
// only behind this gate, never reachable from `cargo test`).
// ──────────────────────────────────────────────────────────────────────────

/// ITS MMIO base for `qemu-system-aarch64 -M virt,gic-version=3,its=on`
/// (QEMU's `virt_memmap[VIRT_GIC_ITS]`). Same caveat as `gic.rs`'s
/// `GICD_BASE`/`GICR_BASE`: a compile-time QEMU-virt constant, not parsed
/// from the DTB; a different board needs a new constant, not a DTB read.
#[cfg(target_arch = "aarch64")]
pub const ITS_BASE: usize = 0x0808_0000;

#[cfg(target_arch = "aarch64")]
mod regs {
    pub const GITS_CTLR: usize = 0x0000;
    pub const GITS_TYPER: usize = 0x0008;
    pub const GITS_CBASER: usize = 0x0080;
    pub const GITS_CWRITER: usize = 0x0088;
    pub const GITS_CREADR: usize = 0x0090;
    pub const GITS_BASER0: usize = 0x0100;
    pub const GITS_CTLR_ENABLE: u32 = 1 << 0;
    pub const GITS_CTLR_QUIESCENT: u32 = 1 << 31;
}

/// Bounded spin count for command-queue drain and `GITS_CTLR.Quiescent`.
/// Same rationale as `gic.rs`'s `GICR_WAKE_MAX_SPINS`: real hardware
/// clears in a handful of cycles, but an infinite wait on a QEMU model
/// that never sets the bit (or a genuinely wedged ITS) would hang boot
/// instead of surfacing a diagnosable failure.
#[cfg(target_arch = "aarch64")]
pub const ITS_MAX_SPINS: u32 = 1_000_000;

#[cfg(target_arch = "aarch64")]
pub const MAX_DEVICES: usize = 4;
/// `log2` of this is the `id_bits` [`cmd_mapd`] programs — 8 EventIDs per
/// device is enough headroom for a virtio-pci function's queue vectors
/// (rx/tx/config, typically 2-3) without sizing an ITT per device larger
/// than one cache line's worth of entries.
#[cfg(target_arch = "aarch64")]
pub const MAX_EVENTS_PER_DEVICE: usize = 8;
#[cfg(target_arch = "aarch64")]
const EVENT_ID_BITS_MINUS1: u8 = 2; // log2(8) - 1

/// One ITT entry is defined by `GITS_TYPER.ITT_entry_size` (hardware,
/// commonly 8 or 16 bytes on QEMU virt); 32 is generous headroom, checked
/// against the discovered size at [`ItsDriver::init`] rather than
/// assumed.
#[cfg(target_arch = "aarch64")]
const ITT_ENTRY_BYTES_CAP: usize = 32;

#[cfg(target_arch = "aarch64")]
#[repr(align(4096))]
#[derive(Clone, Copy)]
struct CmdQueue([u8; 4096]);

#[cfg(target_arch = "aarch64")]
#[repr(align(4096))]
#[derive(Clone, Copy)]
struct DeviceTable([u8; 4096]);

#[cfg(target_arch = "aarch64")]
#[repr(align(256))]
#[derive(Clone, Copy)]
struct Itt([u8; MAX_EVENTS_PER_DEVICE * ITT_ENTRY_BYTES_CAP]);

#[cfg(target_arch = "aarch64")]
#[repr(align(4096))]
struct PropTable([u8; gic::lpi_prop_table_size(gic::LPI_ID_BITS)]);

/// 64 KiB, matching `GICR_PENDBASER`'s address field alignment
/// (`[51:16]`, verified in `gic.rs`'s `pendbaser_value` doc) — allocated
/// at that size regardless of how few LPIs are actually pending-tracked,
/// same "the alignment IS the size floor" reasoning as `gic.rs`'s
/// `LPI_ID_BITS`.
#[cfg(target_arch = "aarch64")]
#[repr(align(65536))]
struct PendTable([u8; 65536]);

#[cfg(target_arch = "aarch64")]
static mut CMD_QUEUE: CmdQueue = CmdQueue([0; 4096]);
#[cfg(target_arch = "aarch64")]
static mut DEVICE_TABLE: DeviceTable = DeviceTable([0; 4096]);
/// Memory-backed Collections table, used only when `GITS_TYPER.HCC == 0`
/// (QEMU's ITS is one: it keeps no collections in hardware). One page is
/// far more than the single collection this stage maps.
#[cfg(target_arch = "aarch64")]
static mut COLLECTION_TABLE: DeviceTable = DeviceTable([0; 4096]);
#[cfg(target_arch = "aarch64")]
static mut ITTS: [Itt; MAX_DEVICES] = [Itt([0; MAX_EVENTS_PER_DEVICE * ITT_ENTRY_BYTES_CAP]); MAX_DEVICES];
#[cfg(target_arch = "aarch64")]
static mut PROP_TABLE: PropTable = PropTable([0; gic::lpi_prop_table_size(gic::LPI_ID_BITS)]);
#[cfg(target_arch = "aarch64")]
static mut PEND_TABLE: PendTable = PendTable([0; 65536]);

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItsError {
    /// `GITS_TYPER.PLPIS == 0` — this ITS cannot generate physical LPIs
    /// at all (only virtual ones, GICv4). Nothing below is usable.
    NoPhysicalLpis,
    /// Every `GITS_BASERn` register's reset `Type` came back
    /// != [`BASER_TYPE_DEVICE`] — no slot for the Devices table.
    NoDeviceBaser,
    /// The hardware-defined `EntrySize` times [`MAX_DEVICES`] does not
    /// fit the single page [`DeviceTable`] provides — a real board with
    /// an unusually wide device-table entry would need a bigger (or
    /// indirect) table, which this stage-1a driver does not build.
    DeviceTableTooSmall,
    /// `GITS_TYPER.HCC == 0` AND no `GITS_BASERn` slot of Type
    /// Collection — the ITS can hold no collection at all.
    NoCollectionCapacity,
    /// [`MAX_DEVICES`] already-mapped devices; [`ItsDriver::map_device`]
    /// has no free ITT slot left.
    TooManyDevices,
    /// A command queue drain ([`GITS_CREADR`] catching up to
    /// `GITS_CWRITER`) or `GITS_CTLR.Quiescent` did not happen within
    /// [`ITS_MAX_SPINS`] — the canary this driver's own acceptance test
    /// (unmap the device, or skip `MAPTI`) is expected to trip
    /// differently (count stays 0, not a timeout) but a genuinely wedged
    /// ITS surfaces here instead of hanging boot forever.
    CommandTimedOut,
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn mmio_read32(addr: usize) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}
#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn mmio_write32(addr: usize, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}
#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn mmio_read64(addr: usize) -> u64 {
    core::ptr::read_volatile(addr as *const u64)
}
#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn mmio_write64(addr: usize, val: u64) {
    core::ptr::write_volatile(addr as *mut u64, val);
}

/// One ITS instance, owning the command queue + Devices table + one ITT
/// per mapped device (statics above — a bare-metal kernel with no
/// allocator live yet at the point this initializes, same constraint
/// `crates/drivers/pci` documents for why ITS enumeration output is
/// fixed-capacity).
///
/// **Addresses.** Every table this driver hands the ITS/redistributor
/// (`GITS_CBASER`, `GITS_BASERn`, `GICR_PROPBASER`/`PENDBASER`, each ITT) is
/// a kernel `'static`, passed through [`kva_to_pa`]: the kernel runs in the
/// TTBR1 upper half, so a static's address is not its physical address.
#[cfg(target_arch = "aarch64")]
pub struct ItsDriver {
    its_base: usize,
    cmd_write_off: usize,
    target: u64,
    n_devices: usize,
    device_ids: [u32; MAX_DEVICES],
}

#[cfg(target_arch = "aarch64")]
impl ItsDriver {
    pub const fn new(its_base: usize) -> Self {
        ItsDriver { its_base, cmd_write_off: 0, target: 0, n_devices: 0, device_ids: [0; MAX_DEVICES] }
    }

    fn ctlr_wait_quiescent(&self) {
        let mut spins = 0u32;
        unsafe {
            while mmio_read32(self.its_base + regs::GITS_CTLR) & regs::GITS_CTLR_QUIESCENT == 0
                && spins < ITS_MAX_SPINS
            {
                core::hint::spin_loop();
                spins += 1;
            }
        }
    }

    /// Bring the ITS up and enable LPIs on `rd_base`'s redistributor
    /// (the boot CPU's frame — this stage's one collection targets it
    /// exclusively; see module doc's Scope note).
    pub fn init(&mut self, rd_base: usize) -> Result<(), ItsError> {
        self.ctlr_wait_quiescent();

        let typer = unsafe { mmio_read64(self.its_base + regs::GITS_TYPER) };
        if !typer_plpis(typer) {
            return Err(ItsError::NoPhysicalLpis);
        }
        let hcc = typer_hcc(typer);

        // Command queue: one 4 KiB page, CBASER written before CWRITER
        // per spec (CBASER write resets CREADR).
        let cq_pa = kva_to_pa(core::ptr::addr_of!(CMD_QUEUE) as u64);
        unsafe {
            mmio_write64(self.its_base + regs::GITS_CBASER, cbaser_value(cq_pa, 0, true));
            mmio_write64(self.its_base + regs::GITS_CWRITER, 0);
        }
        self.cmd_write_off = 0;

        // Devices table: probe all 8 GITS_BASERn slots for Type == Device.
        let dt_pa = kva_to_pa(core::ptr::addr_of!(DEVICE_TABLE) as u64);
        let mut found_device_baser = false;
        for n in 0..8usize {
            let off = regs::GITS_BASER0 + n * 8;
            let reset = unsafe { mmio_read64(self.its_base + off) };
            if baser_type(reset) != BASER_TYPE_DEVICE {
                continue;
            }
            let entry_size = baser_entry_size(reset) as usize;
            if MAX_DEVICES * entry_size > 4096 {
                return Err(ItsError::DeviceTableTooSmall);
            }
            unsafe {
                mmio_write64(self.its_base + off, baser_value(reset, dt_pa, 0, true));
            }
            found_device_baser = true;
            break;
        }
        if !found_device_baser {
            return Err(ItsError::NoDeviceBaser);
        }

        // Collections: with `HCC >= 1` the ITS holds collection 0 itself.
        // With `HCC == 0` (QEMU `virt`) it needs a memory-backed table in
        // the `GITS_BASERn` slot whose reset Type is Collection; without
        // it MAPC has nowhere to store the mapping and every LPI stays
        // untranslated.
        if hcc == 0 {
            let ct_pa = kva_to_pa(core::ptr::addr_of!(COLLECTION_TABLE) as u64);
            let mut found = false;
            for n in 0..8usize {
                let off = regs::GITS_BASER0 + n * 8;
                let reset = unsafe { mmio_read64(self.its_base + off) };
                if baser_type(reset) != BASER_TYPE_COLLECTION {
                    continue;
                }
                unsafe { mmio_write64(self.its_base + off, baser_value(reset, ct_pa, 0, true)); }
                found = true;
                break;
            }
            if !found {
                return Err(ItsError::NoCollectionCapacity);
            }
        }

        // Enable the ITS itself before issuing any command.
        unsafe {
            let ctlr = mmio_read32(self.its_base + regs::GITS_CTLR);
            mmio_write32(self.its_base + regs::GITS_CTLR, ctlr | regs::GITS_CTLR_ENABLE);
        }

        // Enable LPIs on the target redistributor (gic.rs owns this half
        // of the memory-attribute/ordering story — see its doc).
        let prop_pa = kva_to_pa(core::ptr::addr_of!(PROP_TABLE) as u64);
        let pend_pa = kva_to_pa(core::ptr::addr_of!(PEND_TABLE) as u64);
        gic::enable_lpis_at(rd_base, prop_pa, pend_pa);

        // Map collection 0 to this CPU (held in hardware when HCC >= 1,
        // in COLLECTION_TABLE otherwise — see above).
        let rd_typer = unsafe { mmio_read64(rd_base + 0x0008) }; // GICR_TYPER
        let target = if typer_pta(typer) {
            collection_target_rdbase(rd_base as u64)
        } else {
            collection_target_cpu_number(gic::typer_cpu_number(rd_typer))
        };
        self.target = target;
        self.submit(cmd_mapc(0, target, true));
        self.submit(cmd_invall(0));
        self.drain()?;

        Ok(())
    }

    /// Register `dev` (build with [`device_id`]) and return its device
    /// slot index for [`map_vector`]. Allocates the next free ITT.
    pub fn map_device(&mut self, dev: u32) -> Result<usize, ItsError> {
        if self.n_devices >= MAX_DEVICES {
            return Err(ItsError::TooManyDevices);
        }
        let slot = self.n_devices;
        self.device_ids[slot] = dev;
        self.n_devices += 1;

        let itt_pa = kva_to_pa(unsafe { core::ptr::addr_of!(ITTS[slot]) as u64 });
        self.submit(cmd_mapd(dev, EVENT_ID_BITS_MINUS1, itt_pa, true));
        self.drain()?;
        Ok(slot)
    }

    /// Map `slot`'s `event_id` (0..[`MAX_EVENTS_PER_DEVICE`], what a
    /// PCI MSI-X vector's data word carries — see [`msi_target`]) to
    /// physical LPI `lpi_intid` (caller-chosen, `>=
    /// `[`crate::gic::LPI_INTID_BASE`]``, and unique across every mapped
    /// vector — this driver does not allocate LPI numbers itself).
    pub fn map_vector(&mut self, slot: usize, event_id: u32, lpi_intid: u32) -> Result<(), ItsError> {
        debug_assert!(slot < self.n_devices);
        debug_assert!(lpi_intid >= gic::LPI_INTID_BASE);
        // Wave-4 canary hook (RFC-0046 stage 1a acceptance test) — see this
        // crate's Cargo.toml `its-skip-mapti` feature doc. Skipping the
        // MAPTI submission below must be the ONLY thing this feature
        // changes: the device is still registered (`map_device` above
        // ran), the ITS is still enabled, only the one command that would
        // have made an EventID resolve to an LPI never goes out — so the
        // failure this produces is "count stays 0", not a boot fault or a
        // compile error, matching the acceptance criterion's own wording.
        #[cfg(feature = "its-skip-mapti")]
        {
            let _ = (event_id, lpi_intid);
            return Ok(());
        }
        #[cfg(not(feature = "its-skip-mapti"))]
        {
            let dev = self.device_ids[slot];
            // Enable the LPI in the configuration table BEFORE the ITS can
            // deliver it, then MAPTI, then INV so the redistributor re-reads
            // the entry (it may cache configuration).
            let idx = (lpi_intid - gic::LPI_INTID_BASE) as usize;
            unsafe {
                let table = &mut *core::ptr::addr_of_mut!(PROP_TABLE);
                if let Some(b) = table.0.get_mut(idx) {
                    core::ptr::write_volatile(b, lpi_config_byte(LPI_DEFAULT_PRIORITY, true));
                }
                core::arch::asm!("dsb ishst", options(nostack, preserves_flags));
            }
            self.submit(cmd_mapti(dev, event_id, lpi_intid, 0));
            self.submit(cmd_inv(dev, event_id));
            self.drain()
        }
    }

    /// The MSI address/data pair for `event_id` — see [`msi_target`]'s
    /// own doc for who consumes this (a PCI MSI-X table entry).
    pub fn msi_target(&self, event_id: u32) -> (u64, u32) {
        msi_target(self.its_base, event_id)
    }

    fn submit(&mut self, cmd: ItsCommand) {
        let base = core::ptr::addr_of!(CMD_QUEUE) as usize;
        let ptr = (base + self.cmd_write_off) as *mut u64;
        unsafe {
            for (i, word) in cmd.iter().enumerate() {
                core::ptr::write_volatile(ptr.add(i), *word);
            }
            // Coherency ordering, not cache maintenance — see this
            // module's + gic.rs's shared memory-attribute doc (Normal WB
            // Inner-Shareable tables, `dsb ishst` is the whole contract).
            core::arch::asm!("dsb ishst", options(nostack, preserves_flags));
        }
        self.cmd_write_off = (self.cmd_write_off + 32) % 4096;
        unsafe {
            mmio_write64(self.its_base + regs::GITS_CWRITER, self.cmd_write_off as u64);
        }
    }

    /// Issue `SYNC` for this driver's one collection target, then poll
    /// `GITS_CREADR` until it catches up with the last `CWRITER` write —
    /// the acceptance criterion's canary (device unmapped in the ITS, or
    /// `MAPTI` skipped) manifests as the per-vector LPI count staying 0,
    /// NOT as this timing out, so [`ItsError::CommandTimedOut`] here
    /// means the ITS itself is wedged, a different failure than the
    /// canary exercises.
    fn drain(&mut self) -> Result<(), ItsError> {
        self.submit(cmd_sync(self.target));
        let mut spins = 0u32;
        unsafe {
            while mmio_read64(self.its_base + regs::GITS_CREADR) != self.cmd_write_off as u64
                && spins < ITS_MAX_SPINS
            {
                core::hint::spin_loop();
                spins += 1;
            }
        }
        if spins >= ITS_MAX_SPINS {
            Err(ItsError::CommandTimedOut)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genmask_matches_hand_computed_ranges() {
        assert_eq!(genmask(7, 0), 0xff);
        assert_eq!(genmask(63, 32), 0xffff_ffff_0000_0000);
        assert_eq!(genmask(51, 12), 0x000f_ffff_ffff_f000);
        assert_eq!(genmask(51, 16), 0x000f_ffff_ffff_0000);
        assert_eq!(genmask(63, 63), 1u64 << 63);
    }

    #[test]
    fn device_id_packs_bus_device_function() {
        assert_eq!(device_id(0, 1, 0), 0x0008);
        assert_eq!(device_id(0, 0x1f, 0x7), 0x00ff);
        // Out-of-range device/function are masked, never overflow into
        // the bus field — mirrors azos_pci::Bdf::new's own masking.
        assert_eq!(device_id(0, 0x3f, 0xf), device_id(0, 0x1f, 0x7));
    }

    #[test]
    fn cmd_mapd_opcode_devid_size_itt_valid_land_at_verified_offsets() {
        let cmd = cmd_mapd(0x0008, 2, 0x4000_1000, true);
        assert_eq!(cmd[0] & 0xff, GITS_CMD_MAPD as u64);
        assert_eq!((cmd[0] >> 32) & 0xffff_ffff, 0x0008);
        assert_eq!(cmd[1] & 0x1f, 2);
        assert_eq!(cmd[2] & genmask(51, 8), 0x4000_1000);
        assert_ne!(cmd[2] & (1u64 << 63), 0);
    }

    #[test]
    fn cmd_mapd_invalid_clears_the_valid_bit_only() {
        let valid = cmd_mapd(1, 0, 0x1000, true);
        let invalid = cmd_mapd(1, 0, 0x1000, false);
        assert_eq!(valid[2] & !(1u64 << 63), invalid[2] & !(1u64 << 63));
        assert_ne!(valid[2] & (1u64 << 63), 0);
        assert_eq!(invalid[2] & (1u64 << 63), 0);
    }

    #[test]
    fn cmd_mapc_collection_and_target_share_dw2_without_overlap() {
        let target = collection_target_cpu_number(3);
        assert_eq!(target, 3u64 << 16);
        let cmd = cmd_mapc(7, target, true);
        assert_eq!(cmd[2] & 0xffff, 7);
        assert_eq!(cmd[2] & genmask(51, 16), target);
        assert_ne!(cmd[2] & (1u64 << 63), 0);
    }

    #[test]
    fn cmd_mapti_places_devid_eventid_physid_collection_in_the_right_words() {
        let cmd = cmd_mapti(0x0008, 5, gic::LPI_INTID_BASE + 2, 0);
        assert_eq!((cmd[0] >> 32) & 0xffff_ffff, 0x0008);
        assert_eq!(cmd[0] & 0xff, GITS_CMD_MAPTI as u64);
        assert_eq!(cmd[1] & 0xffff_ffff, 5);
        assert_eq!((cmd[1] >> 32) & 0xffff_ffff, (gic::LPI_INTID_BASE + 2) as u64);
        assert_eq!(cmd[2] & 0xffff, 0);
    }

    #[test]
    fn cmd_inv_clear_discard_share_shape_but_not_opcode() {
        let inv = cmd_inv(9, 1);
        let clear = cmd_clear(9, 1);
        let discard = cmd_discard(9, 1);
        assert_eq!(inv[0] & 0xff, GITS_CMD_INV as u64);
        assert_eq!(clear[0] & 0xff, GITS_CMD_CLEAR as u64);
        assert_eq!(discard[0] & 0xff, GITS_CMD_DISCARD as u64);
        // Same devid/event_id encoding underneath every one of the three.
        assert_eq!(inv[0] & !0xffu64, clear[0] & !0xffu64);
        assert_eq!(inv[1], clear[1]);
        assert_eq!(clear[0] & !0xffu64, discard[0] & !0xffu64);
    }

    #[test]
    fn cmd_sync_reuses_the_mapc_target_encoding() {
        let target = collection_target_rdbase(0x0808_0000_0000);
        let mapc = cmd_mapc(0, target, true);
        let sync = cmd_sync(target);
        assert_eq!(mapc[2] & genmask(51, 16), sync[2] & genmask(51, 16));
        assert_eq!(sync[0] & 0xff, GITS_CMD_SYNC as u64);
    }

    /// **Canary.** Make `lpi_config_byte` ignore `enabled`: the first
    /// assertion fails (a zero-enable entry is exactly the dropped-LPI bug).
    #[test]
    fn lpi_config_byte_sets_enable_and_keeps_priority_bits() {
        assert_eq!(lpi_config_byte(0xA0, true), 0xA1, "enabled LPI at priority 0xA0");
        assert_eq!(lpi_config_byte(0xA0, false), 0xA0, "disabled LPI keeps its priority");
        assert_eq!(lpi_config_byte(0xFF, true) & 0x2, 0, "bit 1 is never set");
    }

    /// **Canary.** Return `va` unchanged from `kva_to_pa`: the high-half
    /// assertion fails (the ITS would be pointed at a VA it cannot walk).
    #[test]
    fn kva_to_pa_strips_the_ttbr1_offset_and_keeps_low_addresses() {
        let off = crate::mmu::KERNEL_VA_OFFSET;
        assert_eq!(kva_to_pa(off | 0x4020_1000), 0x4020_1000, "a TTBR1 kernel VA maps back to its PA");
        assert_eq!(kva_to_pa(0x4020_1000), 0x4020_1000, "an already-physical address is unchanged");
    }

    #[test]
    fn typer_decode_reads_plpis_pta_hcc_independently() {
        // PLPIS=1, PTA=0, HCC=4.
        let typer = 1u64 | (4u64 << 24);
        assert!(typer_plpis(typer));
        assert!(!typer_pta(typer));
        assert_eq!(typer_hcc(typer), 4);

        let typer_pta_set = typer | (1 << 19);
        assert!(typer_pta(typer_pta_set));
    }

    #[test]
    fn baser_value_preserves_type_and_entry_size_never_clobbers_them() {
        // Reset value: Type=Device(1), EntrySize=8-1=7, Indirect=0.
        let reset = (BASER_TYPE_DEVICE as u64) << 56 | (7u64 << 48);
        assert_eq!(baser_type(reset), BASER_TYPE_DEVICE);
        assert_eq!(baser_entry_size(reset), 8);

        let v = baser_value(reset, 0x4010_0000, 0, true);
        assert_eq!(baser_type(v), BASER_TYPE_DEVICE);
        assert_eq!(baser_entry_size(v), 8);
        assert_eq!(v & genmask(47, 12), 0x4010_0000);
        assert_ne!(v & (1u64 << 63), 0);
    }

    #[test]
    fn cbaser_value_masks_phys_base_to_the_4k_aligned_field() {
        let v = cbaser_value(0x4020_0FFF, 0, true); // low 12 bits must be dropped
        assert_eq!(v & genmask(51, 12), 0x4020_0000);
    }

    #[test]
    fn msi_target_points_at_the_translation_frame_not_the_control_frame() {
        let (addr, data) = msi_target(0x0808_0000, 42);
        assert_eq!(addr, 0x0808_0000 + 0x1_0000 + 0x40);
        assert_eq!(data, 42);
    }

    /// Canary's third bucket: a caller that flips a verified constant
    /// (e.g. treats MAPC's opcode as MAPD's) gets a DIFFERENT opcode
    /// byte, not the same one — this is what makes the two-line diff
    /// between a correct and a swapped opcode observable in a test
    /// rather than only at boot.
    #[test]
    fn opcodes_are_pairwise_distinct() {
        let ops = [
            GITS_CMD_MOVI, GITS_CMD_INT, GITS_CMD_CLEAR, GITS_CMD_SYNC, GITS_CMD_MAPD,
            GITS_CMD_MAPC, GITS_CMD_MAPTI, GITS_CMD_MAPI, GITS_CMD_INV, GITS_CMD_INVALL,
            GITS_CMD_MOVALL, GITS_CMD_DISCARD,
        ];
        for i in 0..ops.len() {
            for j in (i + 1)..ops.len() {
                assert_ne!(ops[i], ops[j], "opcodes at {i} and {j} collide");
            }
        }
    }
}

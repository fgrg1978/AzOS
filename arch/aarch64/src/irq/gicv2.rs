// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! GICv2 — the memory-mapped Generic Interrupt Controller (GIC-400, the
//! Cortex-A15 GIC): a distributor (GICD) and, per CPU, a CPU interface (GICC)
//! reached through MMIO at one address that each CPU sees banked.
//!
//! The boot selects it ([`select`]) when the device tree names an
//! `arm,gic-400` or `arm,cortex-a15-gic` node; `azos_drv_irqchip::gic` makes
//! the choice and passes the node's two `reg` windows. With nothing selected
//! every `irq::gic` function takes its GICv3 branch, as before. When this is
//! selected those functions come here instead, so the callers (the IRQ
//! handler, the IPI sender, the ring-3 line binding) do not know which
//! controller they use.
//!
//! What differs from GICv3 ([`super::gic`]):
//!
//! - No system-register CPU interface and no redistributor. A CPU's SGI/PPI
//!   state sits in `GICD_*0` registers that read and write the calling CPU's
//!   own copy; its priority mask and acknowledge are the GICC frame.
//! - Routing is a CPU-interface bit mask per SPI (`GICD_ITARGETSR`, one byte
//!   per INTID), not an affinity (`GICD_IROUTER`). The mask of a CPU is not
//!   its MPIDR: each CPU reads it from its own banked `GICD_ITARGETSR0`
//!   ([`init_cpu_interface`]) and the table [`IF_TABLE`] maps the affinity the
//!   rest of the kernel names a CPU by to that mask. Eight interfaces at most.
//! - An SGI goes out by a write to `GICD_SGIR` (target mask + INTID), and
//!   `GICC_IAR` says which CPU sent it: the end of the interrupt must carry
//!   that CPU back, so [`iar`] keeps it for [`eoir`].
//! - Priorities are the upper bits only and the distributor has no
//!   affinity routing, no LPIs, no ITS: ring 3 gets no MSI here.
//!
//! The pure halves (register encodings, the interface table) compile
//! everywhere so the host tests run them as written; only the MMIO and the
//! `dsb` are `aarch64`-gated.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

// ──────────────────────────────────────────────────────────────────────────
// Register offsets (GIC Architecture Specification v2.0, §4 and §5)
// ──────────────────────────────────────────────────────────────────────────

const GICD_CTLR: usize = 0x000;
const GICD_TYPER: usize = 0x004;
const GICD_ISENABLER0: usize = 0x100;
const GICD_ICENABLER0: usize = 0x180;
const GICD_IPRIORITYR0: usize = 0x400;
/// One byte per INTID: the CPU-interface mask the SPI is sent to. For INTIDs
/// 0..31 the bytes are banked and read-only, and read back the calling CPU's
/// own interface bit.
const GICD_ITARGETSR0: usize = 0x800;
const GICD_ICFGR0: usize = 0xC00;
const GICD_SGIR: usize = 0xF00;
/// `GICD_ICPIDR2`, the GICv2 name of the ID register: bits `[7:4]` are the
/// architecture revision (2 for GICv2). It sits inside the 4 KiB distributor
/// window; 0xFFE8 is the GICv3 offset and lies past a GICv2 window.
pub const GICD_PIDR2: usize = 0xFE8;

const GICC_CTLR: usize = 0x00;
const GICC_PMR: usize = 0x04;
const GICC_IAR: usize = 0x0C;
const GICC_EOIR: usize = 0x10;

/// The priority mask: priorities below it (more urgent) are signalled. The
/// distributor's default priority (`0xA0`) is in; Linux's `GIC_CPU_PRIORITY`
/// value, `0xF0`, leaves the lowest few priorities out.
const GICC_PMR_ALL: u32 = 0xF0;
/// Default priority of every SPI, SGI and PPI (the GICv3 path's value).
const DEFAULT_PRIORITY_WORD: u32 = 0xA0A0_A0A0;

/// The most CPU interfaces a GICv2 has: the width of a target mask.
pub const MAX_INTERFACES: usize = 8;

// ──────────────────────────────────────────────────────────────────────────
// Pure encode/decode — no `target_arch` gate (see gic.rs for why).
// ──────────────────────────────────────────────────────────────────────────

/// `GICD_SGIR` for SGI `intid` (0..=15, masked if wider) sent to the CPU
/// interfaces in `target_mask`: `TargetListFilter` 0 (the list), the mask at
/// `[23:16]`, `NSATT` 0 (only a secure write reads it), the INTID at `[3:0]`.
pub const fn sgir_encode(target_mask: u8, intid: u8) -> u32 {
    ((target_mask as u32) << 16) | (intid as u32 & 0xF)
}

/// The INTID of a `GICC_IAR` value: bits `[9:0]`. For an SGI the bits
/// `[12:10]` are the CPU that sent it ([`iar_source`]).
pub const fn iar_intid(iar: u32) -> u32 {
    iar & 0x3FF
}

/// The sending CPU interface of an SGI in a `GICC_IAR` value (`[12:10]`).
pub const fn iar_source(iar: u32) -> u8 {
    ((iar >> 10) & 0x7) as u8
}

/// The `GICC_EOIR` value that ends `intid`: for an SGI (INTID 0..=15) the
/// sending CPU goes back in `[12:10]` (the spec requires it, and an SGI sent
/// by two CPUs is two interrupts), for every other INTID the INTID alone.
pub const fn eoir_encode(intid: u32, source: u8) -> u32 {
    if intid < 16 { intid | ((source as u32 & 0x7) << 10) } else { intid }
}

/// The architecture revision of a `GICD_PIDR2` value (`[7:4]`): 2 for GICv2,
/// 3 and 4 for GICv3 and GICv4.
pub const fn pidr2_arch_rev(pidr2: u32) -> u32 {
    (pidr2 >> 4) & 0xF
}

/// Byte offset, from the distributor base, of `intid`'s `GICD_ITARGETSR`.
pub const fn itargetsr_offset(intid: u32) -> usize {
    GICD_ITARGETSR0 + intid as usize
}

/// The mask of the CPU interface the calling CPU reads out of its banked
/// `GICD_ITARGETSR0` (the same byte for INTIDs 0..3): the lowest nonzero byte
/// of the word, 0 when none is (an interface the distributor does not give
/// this CPU).
pub const fn own_interface_mask(itargetsr0: u32) -> u8 {
    let mut i = 0;
    while i < 4 {
        let b = ((itargetsr0 >> (8 * i)) & 0xFF) as u8;
        if b != 0 {
            return b;
        }
        i += 1;
    }
    0
}

// ──────────────────────────────────────────────────────────────────────────
// Selection and the CPU-interface table
// ──────────────────────────────────────────────────────────────────────────

/// A GICv2 is the controller of this boot ([`select`]).
static ACTIVE: AtomicBool = AtomicBool::new(false);
static GICD: AtomicUsize = AtomicUsize::new(0);
static GICD_SIZE: AtomicUsize = AtomicUsize::new(0);
static GICC: AtomicUsize = AtomicUsize::new(0);
static GICC_SIZE: AtomicUsize = AtomicUsize::new(0);

/// One slot per CPU interface, claimed by the CPU that owns it
/// ([`register_interface`]): `1 << 40 | mask << 32 | affinity key`, 0 free.
/// One word, so a reader never sees a mask without its key.
static IF_TABLE: [AtomicU64; MAX_INTERFACES] = [const { AtomicU64::new(0) }; MAX_INTERFACES];
/// The sender of the SGI each CPU acknowledged last ([`iar`]), for [`eoir`].
/// Written and read by the owning CPU, with interrupts masked.
static IF_SGI_SOURCE: [AtomicU32; MAX_INTERFACES] = [const { AtomicU32::new(0) }; MAX_INTERFACES];

/// A slot word for the CPU with affinity `key` and interface mask `mask`.
pub const fn if_entry(key: u32, mask: u8) -> u64 {
    (1 << 40) | ((mask as u64) << 32) | key as u64
}

/// The affinity key of a slot word, `None` for a free slot.
pub const fn if_entry_key(e: u64) -> Option<u32> {
    if e >> 40 & 1 == 0 { None } else { Some(e as u32) }
}

/// The interface mask of a slot word.
pub const fn if_entry_mask(e: u64) -> u8 {
    (e >> 32) as u8
}

/// Select the GICv2 backend: the distributor at `gicd` (`gicd_size` bytes) and
/// the CPU interface at `gicc`. Boot calls it once, before any `irq::gic`
/// function runs and before the windows are mapped (they are read back
/// through [`windows`]); the state is only read afterwards.
pub fn select(gicd: usize, gicd_size: usize, gicc: usize, gicc_size: usize) {
    GICD.store(gicd, Ordering::Relaxed);
    GICD_SIZE.store(gicd_size, Ordering::Relaxed);
    GICC.store(gicc, Ordering::Relaxed);
    GICC_SIZE.store(gicc_size, Ordering::Relaxed);
    ACTIVE.store(true, Ordering::Release);
}

/// Whether a GICv2 is the controller of this boot. One load on every GIC
/// access.
#[inline(always)]
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// The two MMIO windows the boot maps: `(distributor, CPU interface)`, each
/// `(base, bytes)`. Meaningful once [`select`] ran.
pub fn windows() -> [(usize, usize); 2] {
    [
        (GICD.load(Ordering::Relaxed), GICD_SIZE.load(Ordering::Relaxed)),
        (GICC.load(Ordering::Relaxed), GICC_SIZE.load(Ordering::Relaxed)),
    ]
}

fn slot_of(key: u32) -> Option<usize> {
    IF_TABLE.iter().position(|s| if_entry_key(s.load(Ordering::Acquire)) == Some(key))
}

/// Record that the CPU with affinity `key` owns the interface `mask`. A CPU
/// that registers twice keeps its slot. `false` when all eight are taken.
pub fn register_interface(key: u32, mask: u8) -> bool {
    if slot_of(key).is_some() {
        return true;
    }
    IF_TABLE.iter().any(|s| {
        s.compare_exchange(0, if_entry(key, mask), Ordering::AcqRel, Ordering::Relaxed).is_ok()
    })
}

/// The interface mask of the CPU with affinity `key`; `None` for a CPU that
/// never ran [`init_cpu_interface`].
pub fn interface_mask(key: u32) -> Option<u8> {
    slot_of(key).map(|i| if_entry_mask(IF_TABLE[i].load(Ordering::Acquire)))
}

// ──────────────────────────────────────────────────────────────────────────
// MMIO
// ──────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn read32(addr: usize) -> u32 {
    azos_arch_api::mmio::read32(addr)
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn write32(addr: usize, val: u32) {
    azos_arch_api::mmio::write32(addr, val);
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn gicd() -> usize {
    GICD.load(Ordering::Relaxed)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn gicc() -> usize {
    GICC.load(Ordering::Relaxed)
}

/// The calling CPU's affinity key, the one [`register_interface`] was given.
#[cfg(target_arch = "aarch64")]
#[inline]
fn my_key() -> u32 {
    crate::cpu::read_mpidr().affinity_key()
}

/// `GICD_PIDR2`'s architecture revision, read from the hardware, to set
/// against the device tree's word for it. The window must be mapped.
#[cfg(target_arch = "aarch64")]
pub fn hardware_arch_rev() -> u32 {
    pidr2_arch_rev(unsafe { read32(gicd() + GICD_PIDR2) })
}

/// Initialise the distributor: every SPI disabled at the default priority and
/// routed nowhere (a bind or [`route`] sets its target), then the distributor
/// enabled. Group 0 for everything, as Linux leaves a GICv2: the
/// non-secure view of `GICD_CTLR` bit 0 enables what the CPU interface
/// signals. Must run once, before [`init_cpu_interface`].
#[cfg(target_arch = "aarch64")]
pub fn init_distributor() {
    let d = gicd();
    unsafe {
        write32(d + GICD_CTLR, 0);
        let typer = read32(d + GICD_TYPER);
        let it_lines = (typer & 0x1F) as usize;
        super::gic::note_spi_limit(typer);
        for i in 1..=it_lines {
            write32(d + GICD_ICENABLER0 + i * 4, 0xFFFF_FFFF);
        }
        for i in 8..(8 + it_lines * 8) {
            write32(d + GICD_IPRIORITYR0 + i * 4, DEFAULT_PRIORITY_WORD);
        }
        write32(d + GICD_CTLR, 1);
    }
}

/// Initialise the calling CPU: its banked SGI/PPI state (all disabled at the
/// default priority; [`enable_ppi`] turns individual ones on), its entry in
/// the interface table, and its CPU interface (priority mask, enable). Runs
/// on each CPU, after [`init_distributor`] on the boot CPU.
#[cfg(target_arch = "aarch64")]
pub fn init_cpu_interface() {
    let d = gicd();
    let c = gicc();
    unsafe {
        let mask = own_interface_mask(read32(d + GICD_ITARGETSR0));
        debug_assert!(mask != 0, "GICD_ITARGETSR0 gave this CPU no interface");
        let _ = register_interface(my_key(), mask);
        write32(d + GICD_ICENABLER0, 0xFFFF_FFFF);
        for i in 0..8 {
            write32(d + GICD_IPRIORITYR0 + i * 4, DEFAULT_PRIORITY_WORD);
        }
        write32(c + GICC_PMR, GICC_PMR_ALL);
        write32(c + GICC_CTLR, 1);
    }
}

/// Enable the SGI or PPI `intid` (0..31) on the calling CPU: the register is
/// banked, so it is always the caller's own.
#[cfg(target_arch = "aarch64")]
pub fn enable_ppi(intid: u32) {
    debug_assert!(intid < 32, "use enable_spi for INTIDs >= 32");
    unsafe { write32(gicd() + GICD_ISENABLER0, 1 << intid) };
}

/// Enable SPI `intid` at the distributor.
#[cfg(target_arch = "aarch64")]
pub fn enable_spi(intid: u32) {
    unsafe { write32(gicd() + GICD_ISENABLER0 + (intid / 32) as usize * 4, 1 << (intid % 32)) };
}

/// Disable SPI `intid`. A GICv2 has no register-write-pending bit: the write
/// is visible to every CPU when it completes, which a `dsb` closes.
#[cfg(target_arch = "aarch64")]
pub fn disable_spi(intid: u32) {
    unsafe {
        write32(gicd() + GICD_ICENABLER0 + (intid / 32) as usize * 4, 1 << (intid % 32));
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
}

/// Program SPI `intid`'s trigger and its target: the CPU interface of the PE
/// `mpidr` names, the boot CPU's when that PE has none yet (a bind to a CPU
/// that is not up). The caller holds `gic`'s route lock and has IRQs masked
/// (`ICFGR` is a read-modify-write of a register sixteen INTIDs share).
#[cfg(target_arch = "aarch64")]
pub fn program_route(intid: u32, mpidr: u64, edge: bool) {
    let d = gicd();
    let mask = interface_mask(crate::cpu::mpidr_affinity_key(mpidr))
        .or_else(|| IF_TABLE.first().and_then(|s| {
            let e = s.load(Ordering::Acquire);
            if_entry_key(e).map(|_| if_entry_mask(e))
        }))
        .unwrap_or(0);
    unsafe {
        let cfg = d + GICD_ICFGR0 + (intid / 16) as usize * 4;
        write32(cfg, super::gic::icfgr_with_trigger(read32(cfg), intid, edge));
        azos_arch_api::mmio::write8(d + itargetsr_offset(intid), mask);
    }
}

/// `(target mask, edge, enabled)` of SPI `intid`, as `gic::spi_state` reports
/// them (the first is the interface mask where GICv3 has the router).
#[cfg(target_arch = "aarch64")]
pub fn spi_state(intid: u32) -> (u64, bool, bool) {
    let d = gicd();
    unsafe {
        let target = azos_arch_api::mmio::read8(d + itargetsr_offset(intid));
        let cfg = read32(d + GICD_ICFGR0 + (intid / 16) as usize * 4);
        let en = read32(d + GICD_ISENABLER0 + (intid / 32) as usize * 4);
        (target as u64, cfg & (1 << (((intid % 16) * 2) + 1)) != 0, en & (1 << (intid % 32)) != 0)
    }
}

/// Send SGI `intid` to the CPU with affinity `target_affinity`. `dsb ishst`
/// first, for the reason `gic::send_sgi` gives. A CPU that never initialised
/// its interface gets nothing: there is no mask to send it to.
#[cfg(target_arch = "aarch64")]
pub fn send_sgi(target_affinity: u32, intid: u8) {
    let Some(mask) = interface_mask(target_affinity) else { return };
    unsafe {
        core::arch::asm!("dsb ishst", options(nostack, preserves_flags));
        write32(gicd() + GICD_SGIR, sgir_encode(mask, intid));
    }
}

/// Acknowledge the highest-priority pending interrupt and return its INTID
/// (1023 when none). For an SGI the sender is kept for [`eoir`].
#[cfg(target_arch = "aarch64")]
pub fn iar() -> u32 {
    let raw = unsafe { read32(gicc() + GICC_IAR) };
    let intid = iar_intid(raw);
    if intid < 16 {
        if let Some(i) = slot_of(my_key()) {
            IF_SGI_SOURCE[i].store(iar_source(raw) as u32, Ordering::Relaxed);
        }
    }
    intid
}

/// End the interrupt `iar` returned: priority drop and deactivation together
/// (`EOImode` 0), with the SGI's sender put back.
#[cfg(target_arch = "aarch64")]
pub fn eoir(intid: u32) {
    let source = if intid < 16 {
        slot_of(my_key()).map_or(0, |i| IF_SGI_SOURCE[i].load(Ordering::Relaxed) as u8)
    } else {
        0
    };
    unsafe { write32(gicc() + GICC_EOIR, eoir_encode(intid, source)) };
}

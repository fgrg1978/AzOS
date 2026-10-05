// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! External interrupt controller selection — RFC-0046 stage 1a.
//!
//! One kernel binary runs on QEMU `virt` (PLIC) and on
//! `virt,aia=aplic-imsic` (APLIC in MSI mode + per-hart IMSIC, no PLIC:
//! a PLIC access there is a store/load access fault). Boot calls
//! [`select_aia`] when the DTB describes an S-level APLIC/IMSIC pair;
//! every caller then goes through this module instead of `plic::*`. With
//! nothing selected every function takes the PLIC branch, i.e. behaves
//! exactly as the direct `plic::*` call did.
//!
//! State is written once by the boot hart before interrupts are enabled
//! and before secondary harts start, and only read afterwards.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::aplic::Aplic;
use crate::imsic::{self, GroupLayout};
use crate::plic;

static AIA: AtomicBool = AtomicBool::new(false);
static APLIC_BASE: AtomicUsize = AtomicUsize::new(0);
static APLIC_NUM_SOURCES: AtomicU32 = AtomicU32::new(0);
static IMSIC_BASE: AtomicUsize = AtomicUsize::new(0);
static IMSIC_NUM_IDS: AtomicU32 = AtomicU32::new(0);
static IMSIC_STRIDE: AtomicUsize = AtomicUsize::new(0);
/// Next free MSI identity (above the APLIC's wired range).
static NEXT_MSI_ID: AtomicU32 = AtomicU32::new(0);

/// APLIC sources routed by [`wire_aia_source`] (bit per source, 1..1023).
/// [`complete`] re-arms only these; MSI-X identities have no APLIC source.
static WIRED: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];

/// Identities counted by [`claim`] on the AIA path. QEMU's IMSIC
/// implements 255; identities past this array are delivered, not counted.
pub const COUNTED_IDS: usize = 256;
static DELIVERED: [AtomicU32; COUNTED_IDS] = [const { AtomicU32::new(0) }; COUNTED_IDS];

/// Select the AIA path: S-domain APLIC at `aplic_base` with
/// `aplic_num_sources` sources, S-level IMSIC files described by `imsic`.
pub fn select_aia(aplic_base: usize, aplic_num_sources: u32, imsic: GroupLayout) {
    APLIC_BASE.store(aplic_base, Ordering::Relaxed);
    APLIC_NUM_SOURCES.store(aplic_num_sources, Ordering::Relaxed);
    IMSIC_BASE.store(imsic.base, Ordering::Relaxed);
    IMSIC_NUM_IDS.store(imsic.num_ids, Ordering::Relaxed);
    IMSIC_STRIDE.store(imsic.hart_stride, Ordering::Relaxed);
    NEXT_MSI_ID.store(aplic_num_sources + 1, Ordering::Relaxed);
    AIA.store(true, Ordering::Release);
}

#[inline(always)]
pub fn is_aia() -> bool {
    AIA.load(Ordering::Relaxed)
}

/// The S-domain APLIC's MMIO base when AIA is selected — boot maps it
/// (32 KiB) before [`init_aia_domain`]. The IMSIC files need no mapping:
/// the kernel reaches its own file through CSRs only.
pub fn aplic_mmio_base() -> Option<usize> {
    if is_aia() {
        Some(APLIC_BASE.load(Ordering::Relaxed))
    } else {
        None
    }
}

fn imsic_group() -> GroupLayout {
    GroupLayout {
        base: IMSIC_BASE.load(Ordering::Relaxed),
        num_ids: IMSIC_NUM_IDS.load(Ordering::Relaxed),
        hart_stride: IMSIC_STRIDE.load(Ordering::Relaxed),
    }
}

fn aplic() -> Aplic {
    Aplic::new(APLIC_BASE.load(Ordering::Relaxed))
}

/// Per-hart init: `plic::init(hart)`, or this hart's IMSIC file.
pub fn init(hart: u32) {
    if is_aia() {
        imsic::init();
    } else {
        plic::init(hart);
    }
}

/// Domain-wide APLIC init (MSI mode, enabled). No-op on the PLIC path.
pub fn init_aia_domain() {
    if is_aia() {
        aplic().init();
    }
}

/// Claim the pending external interrupt of the current hart; 0 if none.
#[inline]
pub fn claim(hart: u32) -> u32 {
    if is_aia() {
        let id = imsic::claim();
        if let Some(c) = DELIVERED.get(id as usize) {
            c.fetch_add(1, Ordering::Relaxed);
        }
        id
    } else {
        plic::claim(hart)
    }
}

/// Finish handling `irq`. PLIC: completion write. AIA: the IMSIC claim
/// already cleared it; a wired level-sensitive source is re-armed so a
/// line that is still asserted raises a new MSI.
#[inline]
pub fn complete(hart: u32, irq: u32) {
    if is_aia() {
        if is_wired(irq) {
            aplic().retrigger_level(irq);
        }
    } else {
        plic::complete(hart, irq);
    }
}

/// `SYS_DRV_IRQ_ACK` on a line ring 3 does not own: [`complete`], except
/// that a PLIC source not enabled for `hart`'s context is left alone. An ACK
/// is not the handler: it must not complete a line this hart never claimed
/// ([`plic::complete`] enables a disabled source to write its completion).
pub fn complete_if_enabled(hart: u32, irq: u32) {
    if is_aia() {
        complete(hart, irq);
    } else if plic::is_enabled(hart, irq) {
        plic::complete(hart, irq);
    }
}

fn is_wired(source: u32) -> bool {
    match WIRED.get((source / 64) as usize) {
        Some(w) => w.load(Ordering::Relaxed) & (1u64 << (source % 64)) != 0,
        None => false,
    }
}

/// Enable `irq` for `hart`. On the AIA path the enable bit lives in the
/// target hart's own IMSIC file, reachable only from that hart: a call
/// for another hart does nothing.
pub fn enable_irq(hart: u32, irq: u32) {
    // A line the kernel enables for itself is never ring 3's to bind.
    crate::user_irq::mark_kernel(irq);
    if is_aia() {
        if hart == azos_arch::cpu::hart_id() as u32 {
            imsic::enable(irq);
        }
    } else {
        plic::enable_irq(hart, irq);
    }
}

pub fn disable_irq(hart: u32, irq: u32) {
    if is_aia() {
        if hart == azos_arch::cpu::hart_id() as u32 {
            imsic::disable(irq);
        }
    } else {
        plic::disable_irq(hart, irq);
    }
}

/// AIA only: route wired APLIC `source` to `hart`, with the source number
/// as its IMSIC identity. Returns the `sourcecfg` read-back (see
/// `Aplic::wire_source`); `None` on the PLIC path, where wired lines need
/// no routing step.
pub fn wire_aia_source(source: u32, hart: u32) -> Option<u32> {
    if !is_aia() || source == 0 || source > APLIC_NUM_SOURCES.load(Ordering::Relaxed) {
        return None;
    }
    crate::user_irq::mark_kernel(source);
    let readback = aplic().wire_source(source, hart, source);
    if let Some(w) = WIRED.get((source / 64) as usize) {
        w.fetch_or(1u64 << (source % 64), Ordering::Relaxed);
    }
    Some(readback)
}

/// AIA only: route wired APLIC `source` to `hart` for a ring-3 binding
/// (`user_irq::bind`), with the trigger the device tree gave (`edge`), the
/// source number as its IMSIC identity, and enabled. Unlike
/// [`wire_aia_source`] it does not mark the line the kernel's. A level
/// source is re-armed by [`complete`] and by the unmask, an edge one is not:
/// `setipnum` on an edge source raises it unconditionally. `None` off AIA,
/// for a source outside the domain, or when the firmware did not delegate
/// it (the read-back is not the mode written).
pub fn wire_aia_user_source(source: u32, hart: u32, edge: bool) -> Option<u32> {
    if !is_aia() || source == 0 || source > APLIC_NUM_SOURCES.load(Ordering::Relaxed) {
        return None;
    }
    let sm = if edge { crate::aplic::SOURCECFG_SM_EDGE_RISE } else { crate::aplic::SOURCECFG_SM_LEVEL_HIGH };
    let readback = aplic().wire_source_sm(source, hart, source, sm);
    if readback != sm {
        return None;
    }
    if let Some(w) = WIRED.get((source / 64) as usize) {
        if edge {
            w.fetch_and(!(1u64 << (source % 64)), Ordering::Relaxed);
        } else {
            w.fetch_or(1u64 << (source % 64), Ordering::Relaxed);
        }
    }
    Some(readback)
}

/// AIA only: the S-domain APLIC's source count (0 off AIA).
pub fn aia_num_sources() -> u32 {
    if is_aia() { APLIC_NUM_SOURCES.load(Ordering::Relaxed) } else { 0 }
}

/// AIA only: enable or disable wired APLIC `source` (domain-global, any
/// hart); enabling a level source also re-arms it, so a line still asserted
/// while it was disabled is forwarded now. No-op off AIA.
pub fn aia_source_enable(source: u32, on: bool) {
    if !is_aia() {
        return;
    }
    let a = aplic();
    a.set_enabled(source, on);
    if on && is_wired(source) {
        a.retrigger_level(source);
    }
}

/// AIA only: reserve `n` consecutive MSI identities above the wired range.
/// Returns the first, or `None` when not on AIA or the IMSIC has too few.
pub fn alloc_msi_ids(n: u32) -> Option<u32> {
    if !is_aia() || n == 0 {
        return None;
    }
    let first = NEXT_MSI_ID.fetch_add(n, Ordering::Relaxed);
    if first + n - 1 > IMSIC_NUM_IDS.load(Ordering::Relaxed) {
        return None;
    }
    Some(first)
}

/// AIA only: the physical address a device writes an identity to so that
/// it becomes pending in `hart`'s S-level IMSIC file.
pub fn msi_target_addr(hart: u32) -> Option<u64> {
    if is_aia() {
        Some(imsic_group().msi_target_addr(hart) as u64)
    } else {
        None
    }
}

/// How many times [`claim`] returned `id` (AIA path only).
pub fn delivered(id: u32) -> u32 {
    DELIVERED.get(id as usize).map_or(0, |c| c.load(Ordering::Relaxed))
}

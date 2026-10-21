// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! External interrupt controller selection.
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

use azos_arch::{Cpu as _, Interrupts as _};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use azos_arch::irq::aplic::{self, Aplic};
use azos_arch::irq::imsic::{self, GroupLayout};
use azos_arch::irq::plic;

use crate::msi_pending::MsiPending;

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

/// MSI identities that a driver asked to have enabled in another hart's file
/// ([`enable_irq`]): that hart's [`init`] enables them. Indexed by the number
/// `enable_irq` and `init` are given for the hart (the logical CPU).
static MSI_PENDING: MsiPending<{ azos_limits::NR_CPUS }> = MsiPending::new();

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

/// The S-level IMSIC's guest interrupt files, for the hypervisor's wiring
/// (`kernel/src/entry/riscv64/ext/hv.rs`): `(identities, files per hart)`,
/// both 0 when the AIA is not what the host runs on or the group has no guest
/// files.
pub fn imsic_guest_files() -> (u32, u32) {
    if !is_aia() {
        return (0, 0);
    }
    let g = imsic_group();
    (g.num_ids, g.guest_files())
}

fn aplic() -> Aplic {
    Aplic::new(APLIC_BASE.load(Ordering::Relaxed))
}

/// Per-hart init: `plic::init(hart)`, or this hart's IMSIC file with the
/// identities other harts asked for it ([`enable_irq`]).
pub fn init(hart: u32) {
    if is_aia() {
        imsic::init();
        MSI_PENDING.hart_init(hart, imsic::enable);
    } else {
        plic::init(hart, crate::user_irq::owned);
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

fn is_wired(source: u32) -> bool {
    match WIRED.get((source / 64) as usize) {
        Some(w) => w.load(Ordering::Relaxed) & (1u64 << (source % 64)) != 0,
        None => false,
    }
}

/// Enable `irq` for `hart`. On the AIA path the enable bit lives in the
/// target hart's own IMSIC file, reachable only from that hart: a call for
/// another hart is kept and that hart's [`init`] enables it (an MSI-X vector
/// routed at boot to a CPU that has not started). `false` when that cannot
/// happen: the hart has already run [`init`], so nothing enables the identity,
/// or the identity is outside the counted range.
pub fn enable_irq(hart: u32, irq: u32) -> bool {
    // A line the kernel enables for itself is never ring 3's to bind.
    crate::user_irq::mark_kernel(irq);
    if is_aia() {
        // Masked across the hart test and the file write: the IMSIC file is
        // the executing hart's, and a ring-3 bind comes from a task with
        // interrupts on, which a tick could move to another hart between
        // "this is `hart`" and the write (enabling the line on the wrong file).
        let prev = azos_arch::ARCH.disable_all();
        let done = if hart == azos_arch::ARCH.hart_id() as u32 {
            imsic::enable(irq);
            true
        } else {
            MSI_PENDING.request(hart, irq)
        };
        azos_arch::ARCH.restore(prev);
        done
    } else {
        plic::enable_irq(hart, irq);
        true
    }
}

pub fn disable_irq(hart: u32, irq: u32) {
    if is_aia() {
        // Masked, as in `enable_irq`.
        let prev = azos_arch::ARCH.disable_all();
        if hart == azos_arch::ARCH.hart_id() as u32 {
            imsic::disable(irq);
        } else {
            MSI_PENDING.cancel(hart, irq);
        }
        azos_arch::ARCH.restore(prev);
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
    let sm = if edge { aplic::SOURCECFG_SM_EDGE_RISE } else { aplic::SOURCECFG_SM_LEVEL_HIGH };
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

/// Identities set aside for ring-3 MSI handlers: one window of this many,
/// taken from the IMSIC's range on first use, handed out one at a time and
/// given back with the binding that held them.
pub const USER_MSI_IDS: u32 = 32;

/// First identity of the window (0 until [`user_msi_alloc`] takes it) and which
/// of its identities are handed out (one bit each).
static USER_MSI_FIRST: AtomicU32 = AtomicU32::new(0);
static USER_MSI_USED: AtomicU32 = AtomicU32::new(0);

/// AIA only: an identity for a ring-3 MSI handler, `None` off AIA or when the
/// window is spent (or could not be taken from the IMSIC).
pub fn user_msi_alloc() -> Option<u32> {
    if !is_aia() {
        return None;
    }
    if USER_MSI_FIRST.load(Ordering::Acquire) == 0 {
        let first = alloc_msi_ids(USER_MSI_IDS)?;
        // A concurrent first use took the window already: its identities are
        // the ones in use, ours go unused (the pool is a fixed window).
        let _ = USER_MSI_FIRST.compare_exchange(0, first, Ordering::AcqRel, Ordering::Acquire);
    }
    let first = USER_MSI_FIRST.load(Ordering::Acquire);
    let mut used = USER_MSI_USED.load(Ordering::Acquire);
    loop {
        let bit = (!used).trailing_zeros();
        if bit >= USER_MSI_IDS {
            return None;
        }
        match USER_MSI_USED.compare_exchange(used, used | 1 << bit, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(first + bit),
            Err(now) => used = now,
        }
    }
}

/// Give back an identity [`user_msi_alloc`] handed out. Outside the window it
/// is ignored.
pub fn user_msi_free(id: u32) {
    let first = USER_MSI_FIRST.load(Ordering::Acquire);
    if first != 0 && id >= first && id - first < USER_MSI_IDS {
        USER_MSI_USED.fetch_and(!(1u32 << (id - first)), Ordering::AcqRel);
    }
}

/// Is `id` an identity [`user_msi_alloc`] handed out (the interrupt handler's
/// test, before the kernel's own MSI handlers)?
#[inline]
pub fn user_msi_owned(id: u32) -> bool {
    let first = USER_MSI_FIRST.load(Ordering::Acquire);
    first != 0
        && id >= first
        && id - first < USER_MSI_IDS
        && USER_MSI_USED.load(Ordering::Acquire) & (1 << (id - first)) != 0
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

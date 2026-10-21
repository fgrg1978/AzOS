// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cache maintenance for masters that are not cache-coherent with the CPU.
//!
//! A coherent device needs nothing: the CPU's caches and the device see the
//! same bytes. A non-coherent one (a SoC whose DMA engine reads RAM behind
//! the CPU's caches: the JH7110 of the VisionFive 2) needs two things per
//! transfer:
//!
//! - before the device runs: the CPU's dirty lines for the buffer written
//!   back (`clean`), or the device reads stale RAM; and, for a buffer the
//!   device will WRITE, the lines dropped (`flush`), or a later eviction of
//!   a dirty line overwrites what the device stored;
//! - after the device ran: the lines dropped again (`flush`), or the CPU
//!   reads what its cache held before the device wrote.
//!
//! Only `clean` and `flush` (clean + invalidate) are used, never a bare
//! invalidate: a buffer that does not start and end on a cache line shares
//! its edge lines with neighbours, and a bare invalidate would throw their
//! dirty data away. Per ISA the two are riscv64 Zicbom `cbo.clean` /
//! `cbo.flush`, or, on a core without Zicbom but with a SiFive composable
//! cache (the JH7110's U74), the controller's `Flush64` line flush for BOTH
//! halves ([`crate::ccache`]: it has no clean-only operation, and a flush
//! where a clean would do costs a refill, never data); aarch64 `dc cvac` /
//! `dc civac`; x86_64 is coherent and installs nothing. The boot installs the
//! pair, and only when the hardware has it (riscv64: the Zicbom probe, else
//! the cache controller the device tree names).
//!
//! Whether a master is coherent is a property of the master, not of the
//! machine: the platform default is Kconfig `DMA_NONCOHERENT`, and a device
//! tree `dma-coherent` property (recorded by the hardware bus) turns the
//! maintenance off for the devices that declare it
//! ([`crate::registry::declare_mmio`]). The routines run through
//! [`Maintain`], so a host test can drive the very sequence the drivers run
//! against a model of the caches.

use crate::domain::DmaDomain;
use crate::Direction;

/// A cache-maintenance routine over the virtual range `[va, va + len)`.
pub type CacheFn = unsafe fn(va: usize, len: usize);

azos_common::ro_hook! {
    static CLEAN: CacheFn;
}
azos_common::ro_hook! {
    static FLUSH: CacheFn;
}

/// What a transfer needs done to the CPU's caches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheOp {
    None,
    /// Write dirty lines back, keep them cached.
    Clean,
    /// Write dirty lines back and drop them.
    Flush,
}

/// What to do before the device starts a transfer of direction `dir`.
pub const fn op_for_device(dir: Direction) -> CacheOp {
    match dir {
        Direction::ToDevice => CacheOp::Clean,
        Direction::FromDevice | Direction::Bidirectional => CacheOp::Flush,
    }
}

/// What to do after the device finished a transfer of direction `dir`.
pub const fn op_for_cpu(dir: Direction) -> CacheOp {
    match dir {
        Direction::ToDevice => CacheOp::None,
        Direction::FromDevice | Direction::Bidirectional => CacheOp::Flush,
    }
}

/// Install the arch's pair. Called once at boot by the arch layer, only
/// when the CPU can do it.
pub fn install(clean: CacheFn, flush: CacheFn) {
    CLEAN.set(clean);
    FLUSH.set(flush);
}

/// Has an arch installed its routines?
pub fn installed() -> bool {
    CLEAN.is_set() && FLUSH.is_set()
}

/// The cache routines a bracketed transfer runs: the installed arch pair in
/// the kernel, a model of the caches in the host test.
pub trait Maintain {
    /// Write the dirty lines of `[va, va + len)` back, keep them cached.
    ///
    /// # Safety
    /// The range must be mapped kernel memory.
    unsafe fn clean(&self, va: usize, len: usize);
    /// Write the dirty lines back and drop them.
    ///
    /// # Safety
    /// The range must be mapped kernel memory.
    unsafe fn flush(&self, va: usize, len: usize);
}

/// The pair [`install`] registered. Installed nothing: the call is dropped
/// (a non-coherent domain with no routines is refused at boot, so reaching
/// here means the domain was coherent, which the `sync_*` filter drops first).
struct Installed;

impl Installed {
    unsafe fn call(slot: &azos_common::hook::Hook<CacheFn>, va: usize, len: usize) {
        if let Some(f) = slot.get() {
            // SAFETY: the caller's contract: the range is mapped kernel memory.
            unsafe { f(va, len) };
        }
    }
}

impl Maintain for Installed {
    unsafe fn clean(&self, va: usize, len: usize) {
        unsafe { Self::call(&CLEAN, va, len) }
    }
    unsafe fn flush(&self, va: usize, len: usize) {
        unsafe { Self::call(&FLUSH, va, len) }
    }
}

/// Write back `[va, va + len)` with the installed routine, for memory a
/// non-snooping unit reads (the IOMMU's tables): the caller has already
/// decided the machine is non-coherent. Nothing is done when nothing is
/// installed.
///
/// # Safety
/// `[va, va + len)` must be mapped kernel memory.
pub unsafe fn clean_installed(va: usize, len: usize) {
    unsafe { Installed.clean(va, len) }
}

/// Write back and drop `[va, va + len)` with the installed routine, for
/// memory a non-snooping unit wrote (the IOMMU's queues).
///
/// # Safety
/// `[va, va + len)` must be mapped kernel memory.
pub unsafe fn flush_installed(va: usize, len: usize) {
    unsafe { Installed.flush(va, len) }
}

unsafe fn run(m: &dyn Maintain, op: CacheOp, va: usize, len: usize) {
    match op {
        CacheOp::None => {}
        CacheOp::Clean => unsafe { m.clean(va, len) },
        CacheOp::Flush => unsafe { m.flush(va, len) },
    }
}

/// [`sync_for_device`] over `m`.
///
/// # Safety
/// `[va, va + len)` must be mapped kernel memory.
pub unsafe fn sync_for_device_with(m: &dyn Maintain, domain: &dyn DmaDomain, va: usize, len: usize, dir: Direction) {
    if !domain.coherent() {
        unsafe { run(m, op_for_device(dir), va, len) };
    }
}

/// [`sync_for_cpu`] over `m`.
///
/// # Safety
/// `[va, va + len)` must be mapped kernel memory.
pub unsafe fn sync_for_cpu_with(m: &dyn Maintain, domain: &dyn DmaDomain, va: usize, len: usize, dir: Direction) {
    if !domain.coherent() {
        unsafe { run(m, op_for_cpu(dir), va, len) };
    }
}

/// Hand the buffer at `va` to the device of `domain`. A no-op for a
/// coherent domain.
///
/// # Safety
/// `[va, va + len)` must be mapped kernel memory.
pub unsafe fn sync_for_device(domain: &dyn DmaDomain, va: usize, len: usize, dir: Direction) {
    unsafe { sync_for_device_with(&Installed, domain, va, len, dir) }
}

/// Take the buffer at `va` back from the device of `domain`. A no-op for a
/// coherent domain.
///
/// # Safety
/// `[va, va + len)` must be mapped kernel memory.
pub unsafe fn sync_for_cpu(domain: &dyn DmaDomain, va: usize, len: usize, dir: Direction) {
    unsafe { sync_for_cpu_with(&Installed, domain, va, len, dir) }
}

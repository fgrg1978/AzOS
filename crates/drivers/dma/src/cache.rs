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
//! `cbo.flush`, aarch64 `dc cvac` / `dc civac`; x86_64 is coherent and
//! installs nothing. The arch layer installs the pair at boot, and only
//! when the hardware has it (riscv64: the Zicbom probe).

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::domain::DmaDomain;
use crate::Direction;

/// A cache-maintenance routine over the virtual range `[va, va + len)`.
pub type CacheFn = unsafe fn(va: usize, len: usize);

static CLEAN: AtomicUsize = AtomicUsize::new(0);
static FLUSH: AtomicUsize = AtomicUsize::new(0);

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
    CLEAN.store(clean as usize, Ordering::Release);
    FLUSH.store(flush as usize, Ordering::Release);
}

/// Has an arch installed its routines?
pub fn installed() -> bool {
    CLEAN.load(Ordering::Acquire) != 0 && FLUSH.load(Ordering::Acquire) != 0
}

unsafe fn run(op: CacheOp, va: usize, len: usize) {
    let slot = match op {
        CacheOp::None => return,
        CacheOp::Clean => &CLEAN,
        CacheOp::Flush => &FLUSH,
    };
    let f = slot.load(Ordering::Acquire);
    if f == 0 {
        // A non-coherent domain with no routines is refused at boot
        // (`kernel/src/boot/dma.rs`); reaching here means a coherent
        // domain was asked, which `sync_*` filters out first.
        return;
    }
    // SAFETY: `f` was stored by `install` from a `CacheFn`.
    let f: CacheFn = unsafe { core::mem::transmute::<usize, CacheFn>(f) };
    unsafe { f(va, len) };
}

/// Hand the buffer at `va` to the device of `domain`. A no-op for a
/// coherent domain.
///
/// # Safety
/// `[va, va + len)` must be mapped kernel memory.
pub unsafe fn sync_for_device(domain: &dyn DmaDomain, va: usize, len: usize, dir: Direction) {
    if !domain.coherent() {
        unsafe { run(op_for_device(dir), va, len) };
    }
}

/// Take the buffer at `va` back from the device of `domain`. A no-op for a
/// coherent domain.
///
/// # Safety
/// `[va, va + len)` must be mapped kernel memory.
pub unsafe fn sync_for_cpu(domain: &dyn DmaDomain, va: usize, len: usize, dir: Direction) {
    if !domain.coherent() {
        unsafe { run(op_for_cpu(dir), va, len) };
    }
}

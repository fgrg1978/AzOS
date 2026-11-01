// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel heap leak tracking (Kconfig `KHEAP_LEAKS`, on top of the heap
//! guard): every live block of the global allocator is on one list, with the
//! number of its allocation, the CPU, and the call chain that made it
//! (a scan of the stack for return addresses into the kernel's text: the
//! kernel keeps no frame pointers, so the chain is approximate, outermost
//! frames possibly missing and stale slots possibly present).
//!
//! A scenario takes a [`mark`] before it starts and asks [`since`] when it is
//! over: the blocks allocated after the mark and still live. The ktest runner
//! does it around every early test and prints what remains; the chain is
//! symbolized with `tools/dev/symbolize_bt.py`.
//!
//! The record sits in front of the red zone, so an underflow reaches the red
//! zone first and is reported before the list is touched. It outlives the
//! free (the poisoned block keeps it), which is how a use-after-free or a
//! second free names the allocation it is about.
//!
//! Not a leak detector in the reachability sense: a block still referenced
//! by a cache, a registry or a task that has not exited is live, and so is
//! reported. The caller decides which of those it expects.

use core::fmt;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use azos_arch::ARCH;
use azos_arch_api::Cpu;
use azos_sync::SpinLock;

/// Frames of call chain kept per block: Kconfig `KHEAP_LEAKS_FRAMES`.
pub const FRAMES: usize = azos_limits::KHEAP_LEAKS_FRAMES as usize;

/// What sits in front of a block's red zone.
#[repr(C)]
pub struct Record {
    next: *mut Record,
    prev: *mut Record,
    seq: u64,
    body: usize,
    size: usize,
    cpu: u32,
    depth: u32,
    frames: [usize; FRAMES],
}

/// Bytes the record takes in front of the red zone.
pub const HDR: usize = core::mem::size_of::<Record>();

struct Live(*mut Record);
// SAFETY: the list is touched only under its lock.
unsafe impl Send for Live {}

static LIVE: SpinLock<Live> = SpinLock::new(Live(core::ptr::null_mut()));
static SEQ: AtomicU64 = AtomicU64::new(0);
/// The kernel's stack walker (`set_walker`): fills the slice, returns how many.
static WALKER: AtomicUsize = AtomicUsize::new(0);

/// Install the function that reads the calling CPU's call chain, innermost
/// first. Blocks allocated before it is set carry no chain.
pub fn set_walker(f: fn(&mut [usize]) -> usize) {
    WALKER.store(f as usize, Relaxed);
}

/// A live block, as [`since`] reports it.
#[derive(Clone, Copy, Default)]
pub struct Leak {
    pub addr: usize,
    pub size: usize,
    pub seq: u64,
    pub cpu: u32,
    pub depth: u32,
    pub frames: [usize; FRAMES],
}

/// The allocation number the next block gets.
pub fn mark() -> u64 {
    SEQ.load(Relaxed)
}

/// Put the block at `base` (a [`Record`]'s worth of room first) on the list.
///
/// # Safety
/// `base` is the start of a block of the guard, `body` its body.
pub(crate) unsafe fn register(base: *mut u8, body: usize, size: usize) {
    let r = base as *mut Record;
    let mut frames = [0usize; FRAMES];
    let w = WALKER.load(Relaxed);
    let depth = if w == 0 {
        0
    } else {
        // SAFETY: `w` came from `set_walker`.
        let f: fn(&mut [usize]) -> usize = unsafe { core::mem::transmute(w) };
        f(&mut frames).min(FRAMES)
    };
    // The chain's first entries are the allocator's own, whose number varies
    // with inlining; the reader skips what it does not want.
    unsafe {
        r.write(Record {
            next: core::ptr::null_mut(),
            prev: core::ptr::null_mut(),
            seq: SEQ.fetch_add(1, Relaxed),
            body,
            size,
            // percpu-hint: a label on a report; a task that migrates here is named for the CPU it started on
            cpu: ARCH.hart_id() as u32,
            depth: depth as u32,
            frames,
        });
    }
    let t = crate::kheap::irq_off();
    let mut l = LIVE.lock();
    unsafe {
        (*r).next = l.0;
        if !l.0.is_null() {
            (*l.0).prev = r;
        }
    }
    l.0 = r;
    drop(l);
    crate::kheap::irq_restore(t);
}

/// Take the block at `base` off the list.
///
/// # Safety
/// `base` was passed to [`register`] and not yet here.
pub(crate) unsafe fn unregister(base: *mut u8) {
    let r = base as *mut Record;
    let t = crate::kheap::irq_off();
    let mut l = LIVE.lock();
    unsafe {
        let (n, p) = ((*r).next, (*r).prev);
        if !n.is_null() {
            (*n).prev = p;
        }
        if p.is_null() {
            l.0 = n;
        } else {
            (*p).next = n;
        }
    }
    drop(l);
    crate::kheap::irq_restore(t);
}

/// The blocks allocated at or after `mark` and still live, on `cpu` (any
/// when `None`): how many, and their bytes as the callers asked for them.
/// The newest `out.len()` of them are written to `out`.
pub fn since(mark: u64, cpu: Option<u32>, out: &mut [Leak]) -> (usize, usize) {
    let (mut n, mut bytes) = (0, 0);
    let t = crate::kheap::irq_off();
    let l = LIVE.lock();
    let mut p = l.0;
    while !p.is_null() {
        // SAFETY: a record on the list is in a live block, and the lock is held.
        let r = unsafe { &*p };
        if r.seq >= mark && cpu.is_none_or(|c| c == r.cpu) {
            if let Some(slot) = out.get_mut(n) {
                *slot = Leak {
                    addr: r.body,
                    size: r.size,
                    seq: r.seq,
                    cpu: r.cpu,
                    depth: r.depth,
                    frames: r.frames,
                };
            }
            n += 1;
            bytes += r.size;
        }
        p = r.next;
    }
    drop(l);
    crate::kheap::irq_restore(t);
    (n, bytes)
}

/// The record of the block whose record is at `base`, as text for a report.
pub(crate) struct Site(pub *const u8);

impl fmt::Display for Site {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SAFETY: the guard passes the base of a block it made.
        let r = unsafe { &*(self.0 as *const Record) };
        write!(f, "; allocation {} on cpu {}, chain", r.seq, r.cpu)?;
        for a in &r.frames[..(r.depth as usize).min(FRAMES)] {
            write!(f, " {:#x}", a)?;
        }
        Ok(())
    }
}

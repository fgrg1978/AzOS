// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_mm` — the page allocator only.
//!
//! **WHY this exists.** `crates/core/ipc/src/io_ring.rs` allocates one physical
//! page per ring and dereferences it as `*mut IoRing`. The real
//! `azos_mm::pmm` manages the board's physical bitmap and cannot run on
//! the host, so the `#[path]` trick stops at `alloc_page()`.
//!
//! **What this is for.** The property under test in `io_ring_release_all` is
//! not *which* physical page is used — it is **whether the page is freed, and
//! whether it is freed before or after the in-flight submit pass ends**. A
//! counting allocator answers exactly that: `shim_free_count(addr)` proves
//! "freed exactly once, and not one instruction earlier". Pages come from a
//! 4 KiB-aligned static pool so the ring's atomics are properly aligned and
//! the module's real writes land in real memory.
//!
//! Pulled in under the name `azos_mm` via a Cargo dependency rename. The
//! kernel never sees it.

use std::cell::UnsafeCell;
use std::sync::Mutex;

pub mod addr {
    /// Identity on the host, which is what the real constant is everywhere
    /// except an aarch64 kernel build.
    #[inline]
    pub fn phys_to_virt(pa: usize) -> usize { pa }
    #[inline]
    pub fn virt_to_phys(va: usize) -> usize { va }

    /// Same surface `io_ring.rs` uses: `PhysAddr::new` / `as_usize`.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct PhysAddr(usize);

    impl PhysAddr {
        pub const fn new(a: usize) -> Self {
            PhysAddr(a)
        }
        pub const fn as_usize(&self) -> usize {
            self.0
        }
    }
}

/// The pool's page: 4 KiB, or 16 KiB under the crate's `page-16k` feature
/// (an aarch64 16 KiB-granule build), so the code that splits an offset
/// into (page, offset in page) can be run at a granule the old fixed 4096
/// disagrees with (`memobj.rs`'s notify-word test).
#[cfg(not(feature = "page-16k"))]
pub const PAGE_SIZE: usize = 4096;
/// See the 4 KiB arm.
#[cfg(feature = "page-16k")]
pub const PAGE_SIZE: usize = 16384;
/// `MAX_IO_RINGS` is 16; a couple spare so exhaustion tests hit the ring
/// table's limit rather than the allocator's.
pub const SHIM_PAGES: usize = 24;

#[cfg_attr(not(feature = "page-16k"), repr(C, align(4096)))]
#[cfg_attr(feature = "page-16k", repr(C, align(16384)))]
#[derive(Clone, Copy)]
struct Page([u8; PAGE_SIZE]);

struct Pool(UnsafeCell<[Page; SHIM_PAGES]>);
// Access is serialised by `STATE` below; the tests are single-threaded per
// module anyway (see each suite's SERIAL mutex).
unsafe impl Sync for Pool {}

static POOL: Pool = Pool(UnsafeCell::new([Page([0u8; PAGE_SIZE]); SHIM_PAGES]));

struct State {
    used: [bool; SHIM_PAGES],
    /// How many times each page has been handed to `free_page`. Anything
    /// other than 0 or 1 at the end of a test is a double free.
    frees: [u32; SHIM_PAGES],
}

static STATE: Mutex<State> = Mutex::new(State {
    used: [false; SHIM_PAGES],
    frees: [0; SHIM_PAGES],
});

fn base() -> usize {
    POOL.0.get() as usize
}

fn index_of(a: usize) -> Option<usize> {
    let b = base();
    if a < b {
        return None;
    }
    let off = a - b;
    if off % PAGE_SIZE != 0 {
        return None;
    }
    let i = off / PAGE_SIZE;
    if i < SHIM_PAGES {
        Some(i)
    } else {
        None
    }
}

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// The zone names `io_ring.rs` allocates by; the shim has one pool.
pub mod zone {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Zone { PageTable, Ring }
}

pub mod pmm {
    use super::*;
    pub use crate::addr::PhysAddr;

    /// A zoned page is a page here: the shim pool has no types to keep apart.
    pub fn alloc_page_zone(_z: crate::zone::Zone) -> Result<PhysAddr, ()> { alloc_page() }

    /// The real signature is `KResult<PhysAddr>`; `io_ring.rs` only ever calls
    /// `.ok()?` on it, so any `Result` with the same shape works.
    pub fn alloc_page() -> Result<PhysAddr, ()> {
        let mut s = state();
        for i in 0..SHIM_PAGES {
            if !s.used[i] {
                s.used[i] = true;
                // The real `alloc_page` hands back a zeroed page and
                // `io_ring_create`'s comment relies on that.
                unsafe {
                    let p = (base() + i * PAGE_SIZE) as *mut u8;
                    std::ptr::write_bytes(p, 0, PAGE_SIZE);
                }
                return Ok(PhysAddr::new(base() + i * PAGE_SIZE));
            }
        }
        Err(())
    }

    /// `n` consecutive zeroed pages (wave 11, SHMRING: `memobj.rs`'s kernel
    /// stream regions), first fit, as the real one; freed one page at a time.
    pub fn alloc_contiguous(n: usize) -> Result<PhysAddr, ()> {
        let mut s = state();
        let start = (0..SHIM_PAGES.saturating_sub(n.saturating_sub(1)))
            .find(|&i| n > 0 && (i..i + n).all(|j| !s.used[j]))
            .ok_or(())?;
        for j in start..start + n {
            s.used[j] = true;
            unsafe { std::ptr::write_bytes((base() + j * PAGE_SIZE) as *mut u8, 0, PAGE_SIZE) };
        }
        Ok(PhysAddr::new(base() + start * PAGE_SIZE))
    }

    pub fn free_page(a: PhysAddr) -> Result<(), ()> {
        let i = match index_of(a.as_usize()) {
            Some(i) => i,
            None => return Err(()),
        };
        let mut s = state();
        s.frees[i] += 1;
        s.used[i] = false;
        Ok(())
    }

    pub fn free_pages() -> usize {
        let s = state();
        SHIM_PAGES - s.used.iter().filter(|u| **u).count()
    }
}

/// The page cache's backing callback and its page arithmetic: the REAL
/// `crates/core/mm/src/page_backing.rs` (core-only), under the path the real
/// crate exports it by (`azos_mm::pager`), for `memobj.rs`'s Paged objects.
#[path = "../../../../../../crates/core/mm/src/page_backing.rs"]
mod page_backing;

pub mod pager {
    pub use crate::page_backing::*;
}

/// The COW share count (`cow_table.rs`), over the pool: `0` is untracked, the
/// first `addref` takes a page to `2`, a `decref` from `1` or `0` answers
/// "free it". The same rules as the real table, one counter per pool page.
pub mod cow {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static REFS: [AtomicU32; SHIM_PAGES] = [const { AtomicU32::new(0) }; SHIM_PAGES];

    pub fn page_addref(phys: usize) -> Result<(), ()> {
        let i = index_of(phys).ok_or(())?;
        let _ = REFS[i].fetch_update(Ordering::AcqRel, Ordering::Relaxed, |c| Some(if c == 0 { 2 } else { c + 1 }));
        Ok(())
    }

    pub fn page_decref(phys: usize) -> bool {
        let Some(i) = index_of(phys) else { return true };
        let mut last = true;
        let _ = REFS[i].fetch_update(Ordering::AcqRel, Ordering::Relaxed, |c| {
            last = c <= 1;
            Some(if c <= 1 { 0 } else { c - 1 })
        });
        last
    }

    pub fn page_is_sole(phys: usize) -> bool {
        index_of(phys).is_some_and(|i| REFS[i].load(Ordering::Acquire) <= 1)
    }

    pub fn page_forget_if_sole(phys: usize) -> bool {
        let Some(i) = index_of(phys) else { return false };
        REFS[i].fetch_update(Ordering::AcqRel, Ordering::Relaxed, |c| (c <= 1).then_some(0)).is_ok()
    }

    pub fn page_getref(phys: usize) -> u32 {
        index_of(phys).map_or(0, |i| REFS[i].load(Ordering::Acquire))
    }

    pub fn shim_clear() {
        for r in REFS.iter() {
            r.store(0, Ordering::Release);
        }
    }
}

/// The marker PTEs of `demand.rs`, as a set of `(root, va)`: the all-or-nothing
/// range reservation and the clear, with the real module's refusals (a
/// page already marked is `AlreadyMapped`).
pub mod demand {
    use super::PAGE_SIZE;
    use std::sync::Mutex;

    static MARKERS: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());

    pub fn map_demand_range(root: usize, base: usize, pages: usize) -> Result<(), ()> {
        let mut m = MARKERS.lock().unwrap_or_else(|e| e.into_inner());
        if (0..pages).any(|i| m.contains(&(root, base + i * PAGE_SIZE))) {
            return Err(());
        }
        for i in 0..pages {
            m.push((root, base + i * PAGE_SIZE));
        }
        Ok(())
    }

    pub fn clear_demand_marker(root: usize, va: usize) -> bool {
        let mut m = MARKERS.lock().unwrap_or_else(|e| e.into_inner());
        match m.iter().position(|&x| x == (root, va & !(PAGE_SIZE - 1))) {
            Some(i) => {
                m.swap_remove(i);
                true
            }
            None => false,
        }
    }

    /// Markers standing now.
    pub fn shim_markers() -> usize {
        MARKERS.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn shim_clear() {
        MARKERS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

// ── Test-only observability ────────────────────────────────────────────────

pub fn shim_reset() {
    cow::shim_clear();
    demand::shim_clear();
    let mut s = state();
    s.used = [false; SHIM_PAGES];
    s.frees = [0; SHIM_PAGES];
}

/// How many times the page at `addr` has been freed. 0 = still held,
/// 1 = released cleanly, >1 = double free.
pub fn shim_free_count(addr: usize) -> u32 {
    match index_of(addr) {
        Some(i) => state().frees[i],
        None => u32::MAX,
    }
}

/// Pages currently checked out of the pool.
pub fn shim_pages_in_use() -> usize {
    state().used.iter().filter(|u| **u).count()
}

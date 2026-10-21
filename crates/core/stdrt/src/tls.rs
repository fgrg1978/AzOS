// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The thread registry and the keyed thread-local storage `std` keys off it.
//!
//! Keyed, not segment based: the image has no `PT_TLS` and the main thread of
//! an x86_64 image has no thread pointer setting call. The block of values of
//! the running thread is found from its stack pointer in a small registry of
//! stack ranges (one range per live thread `crate::thread` started; a stack
//! pointer outside all of them is the main thread's). The registry is the
//! process's, at most [`MAX_THREADS`] entries, the kernel's limit of live
//! threads of a process being 16.
//!
//! **Keys** carry a generation: a key handed out is `generation << 8 |
//! (index + 1)`, and the generation of an index moves when the key is
//! destroyed. A value is stored with the generation of the key it was set
//! under, so the value a thread still holds under a destroyed key is never
//! seen by the key that reuses the index (no stale `get`, no destructor of the
//! new key run on the old owner's value). Destroying a key does not run the
//! destructors of the values left under it (POSIX).
//!
//! Nothing here traps: the stack pointer is a parameter and the block
//! allocator is given at construction, so `tests/host/stdrt-tests` drives the
//! whole thing on the host.

use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

/// Registry capacity (the kernel allows 16 live threads of a process).
pub const MAX_THREADS: usize = 32;
/// Keys one process can create.
pub const KEYS_MAX: usize = 128;
/// Rounds of destructors a thread's exit runs before giving up on a value
/// that keeps re-creating itself (the POSIX bound).
pub const DTOR_ROUNDS: usize = 4;

/// A destructor of a key's value.
pub type Dtor = unsafe extern "C" fn(*mut u8);

/// The values of one thread: the pointer and the generation of the key it was
/// set under (0 = never set).
pub struct Block {
    vals: [AtomicPtr<u8>; KEYS_MAX],
    gens: [AtomicU32; KEYS_MAX],
}

/// Bytes of a [`Block`] (what the allocator is asked for and gives back).
pub const BLOCK_SIZE: usize = core::mem::size_of::<Block>();
const BLOCK_ALIGN: usize = core::mem::align_of::<Block>();

struct Slot {
    lo: AtomicUsize,
    hi: AtomicUsize,
    tls: AtomicPtr<Block>,
}

const EMPTY_SLOT: Slot = Slot { lo: AtomicUsize::new(0), hi: AtomicUsize::new(0), tls: AtomicPtr::new(ptr::null_mut()) };

/// The registry, the key table and the block allocator.
pub struct Registry {
    slots: [Slot; MAX_THREADS],
    main: AtomicPtr<Block>,
    key_used: [AtomicBool; KEYS_MAX],
    /// A destructor stored as a usize (0 = none) so the table is atomic.
    key_dtor: [AtomicUsize; KEYS_MAX],
    /// Moves when the key is destroyed; a live key's is stable.
    key_gen: [AtomicU32; KEYS_MAX],
    alloc: fn(usize, usize) -> *mut u8,
    free: fn(*mut u8, usize),
}

fn split(k: usize) -> Option<(usize, u32)> {
    let i = (k & 0xff).checked_sub(1)?;
    if i < KEYS_MAX {
        Some((i, (k >> 8) as u32))
    } else {
        None
    }
}

impl Registry {
    /// An empty registry whose blocks come from `alloc(size, align)` and go
    /// back through `free(ptr, size)`.
    pub const fn new(alloc: fn(usize, usize) -> *mut u8, free: fn(*mut u8, usize)) -> Registry {
        Registry {
            slots: [EMPTY_SLOT; MAX_THREADS],
            main: AtomicPtr::new(ptr::null_mut()),
            key_used: [const { AtomicBool::new(false) }; KEYS_MAX],
            key_dtor: [const { AtomicUsize::new(0) }; KEYS_MAX],
            key_gen: [const { AtomicU32::new(0) }; KEYS_MAX],
            alloc,
            free,
        }
    }

    /// Claim a slot for the stack `[base, base + len)`; `None` when all are
    /// taken.
    pub fn claim(&self, base: usize, len: usize) -> Option<usize> {
        for (i, s) in self.slots.iter().enumerate() {
            if s.lo.compare_exchange(0, base, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                s.tls.store(ptr::null_mut(), Ordering::Release);
                s.hi.store(base + len, Ordering::Release);
                return Some(i);
            }
        }
        None
    }

    /// Give slot `i` back. `hi` goes first: `lo` is what a claim takes, so a
    /// claim cannot have its `hi` wiped by a release that is still running.
    pub fn release(&self, i: usize) {
        self.slots[i].hi.store(0, Ordering::Release);
        self.slots[i].lo.store(0, Ordering::Release);
    }

    /// The cell holding the block pointer of the thread whose stack pointer
    /// is `sp`.
    ///
    /// `lo` and `hi` are two words, so a reader can see a pair from two
    /// claims of the same slot (the `lo` of a thread that has released it and
    /// the `hi` of the next one to claim it), a range that covers stacks of
    /// neither. `lo` is read again after `hi`: it moves on every release and
    /// claim, and a slot whose `lo` moved is not a match.
    fn cell(&self, sp: usize) -> &AtomicPtr<Block> {
        for s in self.slots.iter() {
            let lo = s.lo.load(Ordering::Acquire);
            if lo == 0 || sp < lo {
                continue;
            }
            let hi = s.hi.load(Ordering::Acquire);
            if sp < hi && s.lo.load(Ordering::Acquire) == lo {
                return &s.tls;
            }
        }
        &self.main
    }

    fn block(&self, sp: usize, create: bool) -> *mut Block {
        let cell = self.cell(sp);
        let b = cell.load(Ordering::Acquire);
        if !b.is_null() || !create {
            return b;
        }
        let n = (self.alloc)(BLOCK_SIZE, BLOCK_ALIGN) as *mut Block;
        if !n.is_null() {
            // SAFETY: fresh memory of the right size and alignment; all-zero
            // is a valid `Block` (null pointers, generation 0).
            unsafe { ptr::write_bytes(n, 0, 1) };
        }
        cell.store(n, Ordering::Release);
        n
    }

    /// A new key, or `None` when [`KEYS_MAX`] are in use.
    pub fn key_create(&self, dtor: Option<Dtor>) -> Option<usize> {
        for (i, u) in self.key_used.iter().enumerate() {
            if u.compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                self.key_dtor[i].store(dtor.map_or(0, |d| d as usize), Ordering::Release);
                let g = self.key_gen[i].load(Ordering::Acquire);
                return Some((g as usize) << 8 | (i + 1));
            }
        }
        None
    }

    /// Free key `k`. The values threads still hold under it are not
    /// destroyed, and nothing reaches them again: the generation moves
    /// before the destructor goes, so no window pairs an old value with the
    /// next owner's destructor.
    pub fn key_destroy(&self, k: usize) {
        let Some((i, g)) = split(k) else { return };
        if !self.key_used[i].load(Ordering::Acquire) || self.key_gen[i].load(Ordering::Acquire) != g {
            return;
        }
        self.key_gen[i].fetch_add(1, Ordering::AcqRel);
        self.key_dtor[i].store(0, Ordering::Release);
        self.key_used[i].store(false, Ordering::Release);
    }

    fn live(&self, i: usize, g: u32) -> bool {
        self.key_used[i].load(Ordering::Acquire) && self.key_gen[i].load(Ordering::Acquire) == g
    }

    /// The value of the thread at `sp` under `k` (null if never set, or if
    /// `k` is not a live key).
    pub fn key_get(&self, sp: usize, k: usize) -> *mut u8 {
        let Some((i, g)) = split(k) else { return ptr::null_mut() };
        let b = self.block(sp, false);
        if b.is_null() || !self.live(i, g) {
            return ptr::null_mut();
        }
        // SAFETY: the block is the caller thread's own and lives until its
        // exit.
        unsafe {
            if (*b).gens[i].load(Ordering::Relaxed) != g {
                return ptr::null_mut();
            }
            (*b).vals[i].load(Ordering::Relaxed)
        }
    }

    /// Set the value of the thread at `sp` under `k`. `false` if the block
    /// could not be allocated or `k` is not a live key. A value left under a
    /// destroyed key at this index is overwritten, not destructed.
    pub fn key_set(&self, sp: usize, k: usize, v: *mut u8) -> bool {
        let Some((i, g)) = split(k) else { return false };
        if !self.live(i, g) {
            return false;
        }
        let b = self.block(sp, true);
        if b.is_null() {
            return false;
        }
        // SAFETY: as in `key_get`.
        unsafe {
            (*b).vals[i].store(v, Ordering::Relaxed);
            (*b).gens[i].store(g, Ordering::Relaxed);
        }
        true
    }

    /// Run the destructors of the values of the thread at `sp`, and free its
    /// block. A value whose key is gone (or reused since) is dropped without
    /// a destructor.
    pub fn run_dtors(&self, sp: usize) {
        let cell = self.cell(sp);
        let b = cell.load(Ordering::Acquire);
        if b.is_null() {
            return;
        }
        for _ in 0..DTOR_ROUNDS {
            let mut ran = false;
            for i in 0..KEYS_MAX {
                // SAFETY: the block is the caller thread's own.
                let (v, vg) = unsafe {
                    ((*b).vals[i].swap(ptr::null_mut(), Ordering::Relaxed), (*b).gens[i].load(Ordering::Relaxed))
                };
                if v.is_null() || !self.live(i, vg) {
                    continue;
                }
                let d = self.key_dtor[i].load(Ordering::Acquire);
                if d != 0 {
                    // SAFETY: the destructor was stored by `key_create` as a
                    // `Dtor`, for the generation `vg` this value belongs to.
                    unsafe { core::mem::transmute::<usize, Dtor>(d)(v) };
                    ran = true;
                }
            }
            if !ran {
                break;
            }
        }
        // Destructors may have set values again; a dtor re-creating its value
        // past the bound leaks it (the block is freed regardless).
        cell.store(ptr::null_mut(), Ordering::Release);
        (self.free)(b as *mut u8, BLOCK_SIZE);
    }
}

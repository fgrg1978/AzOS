// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The allocator behind `std::alloc::System`: `azos_ualloc`'s engine (size
//! classes, checksummed headers, quarantine, guard pages, randomized
//! placement) over [`mem`](crate::mem) and the kernel entropy pool, behind a
//! spin lock, with the knobs of Kconfig `USER_ALLOC_*` ([`config`](crate::config)).
//! The same engine and the same knobs as `azos_ualloc::UserAlloc` of the
//! `no_std` programs.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use azos_ualloc::engine::{Config, Fault, Heap, Sys};

use crate::{config, entropy, mem, sys};

struct NativeSys;

impl Sys for NativeSys {
    const PAGE: usize = mem::PAGE_SIZE;

    fn map(&mut self, len: usize, guards: bool) -> Option<usize> {
        mem::map(len, guards)
    }

    fn unmap(&mut self, base: usize, len: usize, _guards: bool) {
        mem::unmap(base, len);
    }

    fn entropy(&mut self, out: &mut [u8]) -> bool {
        fill_entropy(out)
    }

    fn note(&mut self, msg: &[u8]) {
        let _ = crate::console::write(2, msg);
        let _ = crate::console::write(2, b"\n");
    }

    fn fault(&mut self, kind: Fault, addr: usize) -> ! {
        let mut line = [0u8; 96];
        let mut n = 0;
        for part in [b"[ualloc] FAULT: ".as_slice(), kind.name().as_bytes(), b" at 0x".as_slice()] {
            line[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
        for i in (0..16).rev() {
            let d = ((addr >> (4 * i)) & 0xf) as u8;
            line[n] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
            n += 1;
        }
        self.note(&line[..n]);
        sys::trap()
    }
}

/// The kernel pool behind the program's `entropy` endpoint capability.
pub fn fill_entropy(out: &mut [u8]) -> bool {
    let ep = crate::start::cap_lookup_host(entropy::ENTROPY_KEY, 0);
    if ep <= 0 {
        return false;
    }
    entropy::fill(&mut |m| sys::ipc_call(ep as u32, m), out)
}

const CFG: Config = Config {
    quarantine_bytes: config::USER_ALLOC_QUARANTINE_KB * 1024,
    block_bytes: config::USER_ALLOC_BLOCK_KB * 1024,
    randomize: config::USER_ALLOC_RANDOMIZE,
    poison: config::USER_ALLOC_POISON_FREED,
    guard: config::USER_ALLOC_GUARD_PAGES,
    seed_required: config::USER_ALLOC_SEED_REQUIRED,
};

type NativeHeap = Heap<NativeSys, { config::USER_ALLOC_MAX_MAPS }, { config::USER_ALLOC_QUARANTINE_SLOTS }>;

struct Global {
    lock: AtomicBool,
    heap: UnsafeCell<NativeHeap>,
}

// SAFETY: every access to `heap` holds `lock`.
unsafe impl Sync for Global {}

static HEAP: Global = Global { lock: AtomicBool::new(false), heap: UnsafeCell::new(Heap::new(NativeSys, CFG)) };

fn with<R>(f: impl FnOnce(&mut NativeHeap) -> R) -> R {
    while HEAP.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    // SAFETY: the lock is held. A fault never returns, so the lock is never
    // left held for a thread that survives it.
    let r = f(unsafe { &mut *HEAP.heap.get() });
    HEAP.lock.store(false, Ordering::Release);
    r
}

/// `size` bytes aligned to `align` (not zeroed), or null.
pub fn malloc(size: usize, align: usize) -> *mut u8 {
    with(|h| h.alloc(size, align))
}

/// Free a block [`malloc`] returned, of the size it was asked for. Anything
/// else is a recorded fault.
pub fn free(p: *mut u8, size: usize) {
    with(|h| h.free(p, Some(size)))
}

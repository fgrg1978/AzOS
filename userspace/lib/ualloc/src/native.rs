// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The engine over the AzOS calls.
//!
//! * Memory: `SYS_MMAP` anonymous, placed at the break. A guard is an `mmap`
//!   with `prot = 0` (the kernel reserves the range and maps nothing: a touch
//!   kills the task). A block with its two guards is three consecutive calls;
//!   if another thread's `mmap` came between them the three are not adjacent
//!   and the set is dropped and made again. There is no ring-3 `mprotect`.
//! * Entropy: the kernel-hosted `entropy` endpoint the program's topology row
//!   grants (`sys::dev::entropy_read`).
//! * A fault prints one `[ualloc]` line and takes a trap instruction, so the
//!   kernel kills the task with a fault status and its fault report.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use azos_libsys as sys;

use crate::engine::{Config, Fault, Heap, Stats, Sys};

pub struct NativeSys;

const MAP_ATTEMPTS: usize = 4;

fn mmap(len: usize, prot: u64) -> Option<usize> {
    let r = sys::mmap(0, len as u64, prot, 0, sys::MAP_ANON_FD, 0);
    (r > 0).then_some(r as usize)
}

impl Sys for NativeSys {
    const PAGE: usize = sys::PAGE_SIZE;

    fn map(&mut self, len: usize, guards: bool) -> Option<usize> {
        if !guards {
            return mmap(len, sys::PROT_READ | sys::PROT_WRITE);
        }
        for _ in 0..MAP_ATTEMPTS {
            let before = mmap(Self::PAGE, 0);
            let body = mmap(len, sys::PROT_READ | sys::PROT_WRITE);
            let after = mmap(Self::PAGE, 0);
            match (before, body, after) {
                (Some(g0), Some(b), Some(g1)) if b == g0 + Self::PAGE && g1 == b + len => return Some(b),
                (_, Some(b), _) => {
                    sys::munmap(b as u64, len as u64);
                }
                _ => return None,
            }
        }
        None
    }

    fn unmap(&mut self, base: usize, len: usize, _guards: bool) {
        // The guards hold no page; only the body is unmapped.
        sys::munmap(base as u64, len as u64);
    }

    fn entropy(&mut self, out: &mut [u8]) -> bool {
        sys::dev::lookup(sys::dev::key::ENTROPY, 0)
            .is_some_and(|ep| sys::dev::entropy_read(ep, out).is_ok())
    }

    fn note(&mut self, msg: &[u8]) {
        sys::println(msg);
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
        sys::println(&line[..n]);
        trap()
    }
}

/// A trap instruction: the kernel kills the task and reports the fault.
#[cfg(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64"))]
fn trap() -> ! {
    // SAFETY: a trap instruction; the kernel ends the task.
    unsafe {
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!("ebreak", options(noreturn));
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("brk #0", options(noreturn));
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("ud2", options(noreturn));
    }
}

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("ualloc: no trap instruction for this ISA (riscv64, aarch64, x86_64)");

const CFG: Config = Config {
    quarantine_bytes: azos_limits::USER_ALLOC_QUARANTINE_KB * 1024,
    block_bytes: azos_limits::USER_ALLOC_BLOCK_KB * 1024,
    randomize: azos_limits::USER_ALLOC_RANDOMIZE,
    poison: azos_limits::USER_ALLOC_POISON_FREED,
    guard: azos_limits::USER_ALLOC_GUARD_PAGES,
    seed_required: azos_limits::USER_ALLOC_SEED_REQUIRED,
};

type NativeHeap = Heap<NativeSys, { azos_limits::USER_ALLOC_MAX_MAPS }, { azos_limits::USER_ALLOC_QUARANTINE_SLOTS }>;

/// The program's allocator: `#[global_allocator] static A: UserAlloc = UserAlloc::new();`,
/// or called directly through [`UserAlloc::malloc`] and [`UserAlloc::free`].
pub struct UserAlloc {
    lock: AtomicBool,
    heap: UnsafeCell<NativeHeap>,
}

// SAFETY: every access to `heap` holds `lock`.
unsafe impl Sync for UserAlloc {}

impl UserAlloc {
    pub const fn new() -> Self {
        UserAlloc { lock: AtomicBool::new(false), heap: UnsafeCell::new(Heap::new(NativeSys, CFG)) }
    }

    fn with<R>(&self, f: impl FnOnce(&mut NativeHeap) -> R) -> R {
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: the lock is held. A fault never returns, so it is never
        // left locked for a thread that survives it.
        let r = f(unsafe { &mut *self.heap.get() });
        self.lock.store(false, Ordering::Release);
        r
    }

    /// `size` bytes aligned to `align` (not zeroed), or null.
    pub fn malloc(&self, size: usize, align: usize) -> *mut u8 {
        self.with(|h| h.alloc(size, align))
    }

    /// Free a chunk [`malloc`](Self::malloc) returned. Anything else is a
    /// fault.
    pub fn free(&self, p: *mut u8) {
        self.with(|h| h.free(p, None))
    }

    pub fn stats(&self) -> Stats {
        self.with(|h| h.stats())
    }
}

// SAFETY: the engine returns blocks of at least `layout.size()` bytes aligned
// to `layout.align()`, distinct while live.
unsafe impl GlobalAlloc for UserAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.malloc(layout.size(), layout.align())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.with(|h| h.free(ptr, Some(layout.size())))
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = self.malloc(layout.size(), layout.align());
        if !p.is_null() {
            core::ptr::write_bytes(p, 0, layout.size());
        }
        p
    }
}

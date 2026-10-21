// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Threads over `SYS_THREAD_CREATE`.
//!
//! **A thread** runs on a stack this layer maps (with guard pages) and ends
//! with `SYS_THREAD_EXIT`; the kernel clears the 32-bit word `ctid` names and
//! wakes its futex when the thread is gone, which is what [`Thread::join`]
//! waits on. A thread that is dropped without a join keeps its stack mapped
//! (it cannot unmap the stack it stands on), so detaching costs the stack.
//!
//! **Thread-local storage** is [`crate::tls`]'s registry of stack ranges and
//! keys, the process's one instance [`REG`]; a thread claims its range in
//! [`spawn`] and runs its destructors and gives the range back when it ends.

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::tls::Registry;
use crate::{alloc, config, futex, mem, sys};
use azos_abi::syscall_nr::{SYS_THREAD_CREATE, SYS_THREAD_EXIT};

pub use crate::tls::{Dtor, KEYS_MAX, MAX_THREADS};

/// Default stack of a thread, bytes.
pub const DEFAULT_STACK: usize = config::SDK_THREAD_STACK_KB * 1024;

static REG: Registry = Registry::new(alloc::malloc, alloc::free);

fn sp() -> usize {
    let x = 0u8;
    ptr::addr_of!(x) as usize
}

/// A new key, or `None` when [`KEYS_MAX`] are in use.
pub fn key_create(dtor: Option<Dtor>) -> Option<usize> {
    REG.key_create(dtor)
}

/// Free key `k`. The values threads still hold under it are not destroyed.
pub fn key_destroy(k: usize) {
    REG.key_destroy(k)
}

/// The running thread's value under `k` (null if never set).
pub fn key_get(k: usize) -> *mut u8 {
    REG.key_get(sp(), k)
}

/// Set the running thread's value under `k`. `false` if the block could not
/// be allocated.
pub fn key_set(k: usize, v: *mut u8) -> bool {
    REG.key_set(sp(), k, v)
}

/// A started thread: its stack, its exit word and the function it runs.
pub struct Thread {
    ctl: *mut Ctl,
}

// SAFETY: the control block is only touched by the creator (before the
// start), the thread (its own fields) and the joiner (after the exit word
// reads 0).
unsafe impl Send for Thread {}
unsafe impl Sync for Thread {}

#[repr(C)]
struct Ctl {
    /// Cleared and futex-woken by the kernel when the thread is gone.
    ctid: AtomicU32,
    slot: usize,
    stack: usize,
    stack_len: usize,
    f: extern "C" fn(usize),
    arg: usize,
}

extern "C" fn trampoline(_zero: u64, _sp: u64, arg: u64) -> ! {
    let ctl = arg as *mut Ctl;
    // SAFETY: `spawn` made it and keeps it until the join or the leak.
    let (f, a, slot) = unsafe { ((*ctl).f, (*ctl).arg, (*ctl).slot) };
    f(a);
    REG.run_dtors(sp());
    // Nothing after this line keys off the registry.
    REG.release(slot);
    // SAFETY: a plain call; it does not return.
    unsafe { sys::syscall6(SYS_THREAD_EXIT, 0, 0, 0, 0, 0, 0) };
    sys::trap()
}

/// Start a thread running `f(arg)` on a new stack of `stack` bytes (rounded
/// up to pages; 0 for the default). The `Err` is the native code.
pub fn spawn(stack: usize, f: extern "C" fn(usize), arg: usize) -> Result<Thread, isize> {
    let len = mem::page_up(if stack == 0 { DEFAULT_STACK } else { stack });
    let Some(base) = mem::map(len, true) else { return Err(-12) };
    let ctl = alloc::malloc(core::mem::size_of::<Ctl>(), core::mem::align_of::<Ctl>()) as *mut Ctl;
    if ctl.is_null() {
        mem::unmap(base, len);
        return Err(-12);
    }
    // Claim a registry slot for the new stack.
    let Some(slot) = REG.claim(base, len) else {
        alloc::free(ctl as *mut u8, core::mem::size_of::<Ctl>());
        mem::unmap(base, len);
        return Err(-11);
    };
    // SAFETY: fresh memory of the right size and alignment.
    unsafe {
        ctl.write(Ctl { ctid: AtomicU32::new(1), slot, stack: base, stack_len: len, f, arg });
    }
    let top = (base + len) & !15;
    // SAFETY: a plain call; the entry is `trampoline`, which never returns.
    let r = unsafe {
        sys::syscall6(
            SYS_THREAD_CREATE,
            trampoline as *const () as usize as u64,
            top as u64,
            ctl as u64,
            // `ctl` is valid; the field's address is stable.
            ptr::addr_of!((*ctl).ctid) as u64,
            0,
            0,
        )
    };
    if r <= 0 {
        REG.release(slot);
        alloc::free(ctl as *mut u8, core::mem::size_of::<Ctl>());
        mem::unmap(base, len);
        return Err(if r == 0 { -1 } else { r });
    }
    Ok(Thread { ctl })
}

impl Thread {
    /// Wait for the thread to end, then give its stack back.
    pub fn join(self) {
        // SAFETY: `ctl` is valid until `release` frees it.
        let ctid = unsafe { &(*self.ctl).ctid };
        loop {
            let v = ctid.load(Ordering::Acquire);
            if v == 0 {
                break;
            }
            futex::wait(ctid, v, None);
        }
        // `drop` releases the stack of a thread that is gone.
    }
}

impl Drop for Thread {
    /// A thread that has ended gives its stack back; one that is still
    /// running keeps it (it stands on it), which is what a detach costs.
    fn drop(&mut self) {
        // SAFETY: `ctl` is valid until freed here.
        if unsafe { (*self.ctl).ctid.load(Ordering::Acquire) } != 0 {
            return;
        }
        // SAFETY: the thread is gone; nothing else points at the block.
        let (stack, len) = unsafe { ((*self.ctl).stack, (*self.ctl).stack_len) };
        mem::unmap(stack, len);
        alloc::free(self.ctl as *mut u8, core::mem::size_of::<Ctl>());
    }
}

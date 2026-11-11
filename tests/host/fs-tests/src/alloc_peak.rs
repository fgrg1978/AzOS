// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The largest single heap allocation each test thread has made since its
//! last [`reset`]: what a test reads to show that a call never took a buffer
//! the size of the file it works on.

#![cfg(test)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

std::thread_local!(static LARGEST: Cell<usize> = const { Cell::new(0) });

struct Counting;

#[global_allocator]
static ALLOCATOR: Counting = Counting;

// SAFETY: every call is `System`'s; the counter is a thread-local `Cell`.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = LARGEST.try_with(|l| l.set(l.get().max(layout.size())));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = LARGEST.try_with(|l| l.set(l.get().max(new_size)));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Forget what this thread has allocated so far.
pub fn reset() {
    LARGEST.with(|l| l.set(0));
}

/// The largest allocation of this thread since [`reset`].
pub fn largest() -> usize {
    LARGEST.with(|l| l.get())
}

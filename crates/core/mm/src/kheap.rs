// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Kernel heap allocator using `linked_list_allocator`.
///
/// Implements `GlobalAlloc` so Rust's `alloc` crate works (Vec, Box, String, etc).
/// Uses our own SpinLock instead of `linked_list_allocator`'s `LockedHeap`
/// to keep the lock implementation consistent across the kernel.
///
/// Ported from kernel/mm/kheap.c (upgraded from bump to real free-list).

use core::alloc::{GlobalAlloc, Layout};
use linked_list_allocator::Heap;
use azos_sync::SpinLock;

struct LockedHeap(SpinLock<Heap>);

unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0
            .lock()
            .allocate_first_fit(layout)
            .ok()
            .map_or(core::ptr::null_mut(), |nn| nn.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            self.0
                .lock()
                .deallocate(core::ptr::NonNull::new_unchecked(ptr), layout);
        }
    }
}

#[global_allocator]
static HEAP: LockedHeap = LockedHeap(SpinLock::new(Heap::empty()));

/// Initialize the kernel heap.
///
/// # Safety
/// `start` must point to a valid, unused memory region of at least `size` bytes.
/// Must be called exactly once before any heap allocation.
pub unsafe fn init(start: usize, size: usize) {
    unsafe {
        HEAP.0.lock().init(start as *mut u8, size);
    }
}

/// Get the number of bytes currently used by the heap.
pub fn used() -> usize {
    HEAP.0.lock().used()
}

/// Get the total heap size in bytes.
pub fn size() -> usize {
    HEAP.0.lock().size()
}

/// Get the number of free bytes in the heap.
pub fn free() -> usize {
    HEAP.0.lock().free()
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_mm`, reduced to what the file layer pulled here
//! reaches of it: the page cache's backing callback.

/// The page cache's backing callback: the REAL
/// `crates/core/mm/src/page_backing.rs` (core-only), under the path the real
/// crate exports it by (`azos_mm::pager`), for `crates/fs/src/pagecache.rs`.
#[path = "../../../../../../crates/core/mm/src/page_backing.rs"]
mod page_backing;

pub mod pager {
    pub use crate::page_backing::*;
}

/// The typed object cache, as the boot volume's sector cache uses it: zeroed
/// objects that live for the whole test run.
pub mod cache {
    use core::marker::PhantomData;
    use core::sync::atomic::{AtomicBool, Ordering};

    pub struct Cache<T>(AtomicBool, PhantomData<fn() -> T>);

    impl<T> Cache<T> {
        pub const fn new() -> Self { Self(AtomicBool::new(false), PhantomData) }
        pub fn alloc(&self) -> *mut T { self.alloc_zeroed() }
        pub fn alloc_zeroed(&self) -> *mut T {
            // SAFETY: a non-zero-sized layout; the object is leaked on purpose.
            unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<T>()).cast() }
        }
        pub fn preload(&self, _n: usize) -> bool { self.0.store(true, Ordering::Relaxed); true }
        pub fn is_sealed(&self) -> bool { self.0.load(Ordering::Relaxed) }
    }
}

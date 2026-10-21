// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_mm`, reduced to `pmm::alloc_page`.
//!
//! **It returns memory the process actually owns.** `virtq_init` writes the
//! descriptor, avail and used rings into the pages it gets back, so a stub
//! handing out a plausible-looking physical address would segfault the suite —
//! the same trap `mm-tests` hit when it passed a made-up `0x8000_0000`.
//!
//! Pages are leaked deliberately: the queue keeps raw pointers into them for
//! the lifetime of the test binary.

/// Mirror of `azos_mm::addr` for host tests.
///
/// The real crate's offset is zero everywhere except an aarch64 KERNEL
/// build, and this shim only ever builds for the host, so identity is the
/// faithful stand-in — not a simplification.
pub mod addr {
    /// A physical address, as the real `azos_mm::addr::PhysAddr`.
    pub struct PhysAddr(pub usize);

    /// Identity, except for a page `pmm::use_low_phys` handed out: that one
    /// has a made-up address below 4 GiB, and this finds the memory behind it.
    #[inline]
    pub fn phys_to_virt(pa: usize) -> usize { crate::pmm::low_phys_to_virt(pa).unwrap_or(pa) }
    #[inline]
    pub fn virt_to_phys(va: usize) -> usize { va }
}

pub mod pmm {
    pub use crate::addr::PhysAddr;
    use std::cell::Cell;
    use std::sync::Mutex;

    thread_local! {
        /// Pages from `alloc_page` on this thread get addresses below 4 GiB.
        static LOW: Cell<bool> = const { Cell::new(false) };
    }

    /// The made-up physical range of the low pages and the memory behind it.
    const LOW_BASE: usize = 0x4000_0000;
    static LOW_PAGES: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    /// From now on, on this thread, `alloc_page` returns pages a 32-bit
    /// device can name: a 64-bit host's heap lies above 4 GiB, so the real
    /// pointer cannot be the "physical" address of a page an ADMA2 descriptor
    /// must hold. The address is made up; `addr::phys_to_virt` translates it.
    pub fn use_low_phys(on: bool) {
        LOW.with(|l| l.set(on));
    }

    /// The memory behind a made-up low address, if it is one.
    pub fn low_phys_to_virt(pa: usize) -> Option<usize> {
        if pa < LOW_BASE {
            return None;
        }
        let pages = LOW_PAGES.lock().unwrap();
        let i = (pa - LOW_BASE) / 4096;
        pages.get(i).map(|v| v + (pa - LOW_BASE) % 4096)
    }

    /// Give a page back (the real allocator's `free_page`): the host leaks.
    pub fn free_page(_pa: PhysAddr) -> Result<(), ()> {
        Ok(())
    }

    /// Carve `n` consecutive pages from one large leaked slab, under one lock.
    /// Real memory, page-aligned, zeroed (the slab is `vec![0u8; ..]` and
    /// never reused).
    fn carve(n: usize) -> Result<PhysAddr, ()> {
        const PAGE: usize = 4096;
        const SLAB_PAGES: usize = 64;
        static SLAB: Mutex<(usize, usize)> = Mutex::new((0, 0));
        if n == 0 || n > SLAB_PAGES {
            return Err(());
        }
        let mut g = SLAB.lock().unwrap();
        if g.0 == 0 || g.1 + n > SLAB_PAGES {
            let raw = vec![0u8; PAGE * (SLAB_PAGES + 1)].leak();
            let base = (raw.as_ptr() as usize + PAGE - 1) & !(PAGE - 1);
            *g = (base, 0);
        }
        let addr = g.0 + g.1 * PAGE;
        g.1 += n;
        Ok(PhysAddr(addr))
    }

    /// Hand out a real, page-aligned, zeroed 4 KiB page.
    pub fn alloc_page() -> Result<PhysAddr, ()> {
        let real = carve(1)?;
        if !LOW.with(|l| l.get()) {
            return Ok(real);
        }
        let mut pages = LOW_PAGES.lock().unwrap();
        pages.push(real.0);
        Ok(PhysAddr(LOW_BASE + (pages.len() - 1) * 4096))
    }

    /// Hand out `n` physically contiguous, zeroed pages: the legacy
    /// `virtq_init` path. The real `pmm::alloc_contiguous` guarantees
    /// contiguity with a run search; consecutive `alloc_page` calls do not
    /// (see `tests/host/mm-tests`, `consecutive_alloc_page_calls_are_not_
    /// physically_contiguous`), so the shim no longer pretends they do.
    pub fn alloc_contiguous(n: usize) -> Result<PhysAddr, ()> {
        carve(n)
    }
}

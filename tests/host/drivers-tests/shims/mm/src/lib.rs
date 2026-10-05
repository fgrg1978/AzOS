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
    #[inline]
    pub fn phys_to_virt(pa: usize) -> usize { pa }
    #[inline]
    pub fn virt_to_phys(va: usize) -> usize { va }
}

pub mod pmm {
    pub struct PhysAddr(pub usize);

    /// Carve `n` consecutive pages from one large leaked slab, under one lock.
    /// Real memory, page-aligned, zeroed (the slab is `vec![0u8; ..]` and
    /// never reused).
    fn carve(n: usize) -> Result<PhysAddr, ()> {
        use std::sync::Mutex;
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
        carve(1)
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

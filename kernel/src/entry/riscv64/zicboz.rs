// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Zicboz zero-fill self-check and bench the riscv64 `post_heap` hook
//! runs on QEMU.

#[cfg(feature = "qemu")]
use azos_drv_sys::kprintln;

/// RFC-0045 Tier 0 item 3 canary (QEMU only): poison a page, free it, force a
/// first-fit reallocation of the same physical page, and confirm it comes
/// back all zero, under whichever zero-fill `zicboz_select` chose. A stride
/// or block-size bug in `cbo.zero`'s loop would leave `0xAA` behind.
///
/// Placed after `kheap::init`, not right after `pmm::init`, on purpose:
/// `vmm::init`'s page tables rely on first-fit placing them right after
/// `kernel_end`, and an alloc/free cycle before it moves the allocator's
/// scan position, so `kheap::init`'s `range_is_free` check fails.
///
/// Then the bench (RFC-0045 §10): under `-icount shift=0,sleep=off`,
/// `rdcycle` is a deterministic proxy for retired instructions; a batch of
/// pages is freed and re-allocated through the chosen zero-fill, and the
/// cycle delta printed, to compare against `-cpu rv64,zicboz=off`.
#[inline(always)]
pub(crate) fn selfcheck() {
    #[cfg(feature = "qemu")]
    {
        use azos_arch::mmu::PAGE_SIZE;
        let ok = (|| -> Option<bool> {
            let p = azos_mm::pmm::alloc_page().ok()?;
            let addr = p.as_usize();
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0xAA, PAGE_SIZE) };
            azos_mm::pmm::free_page(p).ok()?;
            let again = azos_mm::pmm::alloc_page().ok()?;
            let same_page = again.as_usize() == addr;
            let bytes = unsafe {
                core::slice::from_raw_parts(again.as_usize() as *const u8, PAGE_SIZE)
            };
            let all_zero = bytes.iter().all(|&b| b == 0);
            let _ = azos_mm::pmm::free_page(again);
            Some(same_page && all_zero)
        })().unwrap_or(false);
        // The bad path says `FAILED:` on purpose: `QEMU_FAIL_RE` in
        // tools/ci_check.sh matches it, so a broken zero-fill turns EVERY
        // QEMU scenario red, not just a dedicated row.
        if ok {
            kprintln!("[MM] Zicboz zero-fill self-check: PASS");
        } else {
            azos_drv_sys::kerr!("[MM] Zicboz zero-fill self-check FAILED: reallocated page \
                       was not all zero");
        }

        const BENCH_PAGES: usize = 32;
        let mut held: [Option<azos_mm::addr::PhysAddr>; BENCH_PAGES] = [None; BENCH_PAGES];
        let mut filled = 0usize;
        while filled < BENCH_PAGES {
            match azos_mm::pmm::alloc_page() {
                Ok(p) => { held[filled] = Some(p); filled += 1; }
                Err(_) => break,
            }
        }
        for slot in held.iter().take(filled) {
            if let Some(p) = slot { let _ = azos_mm::pmm::free_page(*p); }
        }
        let bench_start = azos_arch::rvv::rdcycle();
        for slot in held.iter_mut().take(filled) {
            *slot = azos_mm::pmm::alloc_page().ok();
        }
        let bench_end = azos_arch::rvv::rdcycle();
        for slot in held.iter().take(filled) {
            if let Some(p) = slot { let _ = azos_mm::pmm::free_page(*p); }
        }
        kprintln!("[MM] Zicboz zero-fill bench: {} pages, {} cycles ({} cycles/page)",
            filled, bench_end - bench_start,
            if filled > 0 { (bench_end - bench_start) / filled as u64 } else { 0 });
    }
}

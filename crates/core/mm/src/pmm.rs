// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Physical Memory Manager (PMM).
///
/// Bitmap-based page allocator. Each bit represents one 4 KiB page:
///   0 = free, 1 = allocated.
///
/// Ported from kernel/mm/pmm.c

use core::sync::atomic::{AtomicUsize, Ordering};

use azos_arch::mmu::PAGE_SIZE;
use azos_sync::SpinLock;
use crate::addr::PhysAddr;
use azos_common::error::{KResult, KernelError};

/// Maximum number of physical pages: the board's Kconfig `RAM_SIZE` (MiB), on
/// every profile. `init` manages the RAM the caller reports, capped here; the
/// bitmap costs RAM_SIZE × 32 bytes of `.bss`.
pub(crate) const MAX_PAGES: usize = azos_limits::RAM_SIZE * 1024 * 1024 / PAGE_SIZE;

/// Bitmap words needed: MAX_PAGES / 64 (rounded up).
const BITMAP_WORDS: usize = (MAX_PAGES + 63) / 64;

struct PmmInner {
    /// Allocation bitmap (1 bit per page). 0=free, 1=used.
    bitmap: [u64; BITMAP_WORDS],
    /// Total number of pages being managed.
    total_pages: usize,
    /// Number of currently free pages.
    free_pages: usize,
    /// Physical address of the first managed page.
    managed_start: usize,
    /// Initialized flag.
    initialized: bool,
    /// Bitmap word to start the next `alloc_page()` scan from.
    ///
    /// Set to the word a successful allocation was satisfied from, so the
    /// next call resumes where this one left off instead of re-scanning
    /// already-full words from index 0 every time. This turns the common
    /// case (long runs of sequential single-page allocations, which is
    /// the fork/exec/page-fault/shm/io_ring pattern) into an amortized
    /// O(1) scan instead of O(BITMAP_WORDS): the cursor follows the
    /// allocation frontier forward through the bitmap.
    ///
    /// A stale or "wrong" value here can never cause a correctness bug —
    /// `alloc_page()` scans every valid word exactly once per call (see
    /// there for why it's two passes rather than one modulo-indexed loop),
    /// just starting from this word instead of 0. A page freed below the
    /// cursor is still found; it just costs the second pass the one time
    /// the words from the cursor onward are all full, exactly like the
    /// old code cost on every single call.
    next_scan_word: usize,
}

/// The managed range, published for lock-free reads: `frame_index` is on the COW
/// refcount path (`cow_table.rs`), which runs once per user page on every fork.
/// Written only by `init`, from the same values it stores in `PMM`.
static FRAME_BASE: AtomicUsize = AtomicUsize::new(0);
static FRAME_COUNT: AtomicUsize = AtomicUsize::new(0);

/// The index of the frame at `phys` among the managed frames, or `None` if
/// `phys` is unaligned or outside the managed range.
///
/// This is the same numbering `free_page` uses for its bitmap, so a per-frame
/// table indexed by it (`cow_table.rs`) needs no lookup structure at all.
pub fn frame_index(phys: usize) -> Option<usize> {
    let off = phys.checked_sub(FRAME_BASE.load(Ordering::Relaxed))?;
    if off % PAGE_SIZE != 0 {
        return None;
    }
    let i = off / PAGE_SIZE;
    if i < FRAME_COUNT.load(Ordering::Relaxed) { Some(i) } else { None }
}

static PMM: SpinLock<PmmInner> = SpinLock::new(PmmInner {
    bitmap: [0; BITMAP_WORDS],
    total_pages: 0,
    free_pages: 0,
    managed_start: 0,
    initialized: false,
    next_scan_word: 0,
});

#[inline]
fn bitmap_set(bitmap: &mut [u64; BITMAP_WORDS], page: usize) {
    bitmap[page / 64] |= 1u64 << (page % 64);
}

#[inline]
fn bitmap_clear(bitmap: &mut [u64; BITMAP_WORDS], page: usize) {
    bitmap[page / 64] &= !(1u64 << (page % 64));
}

#[inline]
fn bitmap_test(bitmap: &[u64; BITMAP_WORDS], page: usize) -> bool {
    bitmap[page / 64] & (1u64 << (page % 64)) != 0
}

/// Try to satisfy an allocation from bitmap word `word_idx`.
///
/// On success: marks the page used, decrements `free_pages`, moves the
/// scan cursor to this word (so the next call resumes here), and returns
/// the page number. Returns `None` if the word is fully allocated, or if
/// its only free bit is a phantom tail bit beyond `total_pages` (possible
/// only in the last word when `total_pages` isn't a multiple of 64 — those
/// high bits are never marked used by `init()`).
///
/// Caller is responsible for the `word_idx * 64 >= total_pages` check that
/// bounds which words are worth trying at all; this only handles the
/// single-bit case inside an otherwise-valid word.
#[inline]
fn try_alloc_from_word(pmm: &mut PmmInner, word_idx: usize) -> Option<usize> {
    let word = pmm.bitmap[word_idx];
    if word == u64::MAX {
        return None;
    }
    let bit = (!word).trailing_zeros() as usize;
    let page = word_idx * 64 + bit;
    if page >= pmm.total_pages {
        return None;
    }
    bitmap_set(&mut pmm.bitmap, page);
    pmm.free_pages -= 1;
    pmm.next_scan_word = word_idx;
    Some(page)
}

/// Initialize the PMM.
///
/// `mem_start`: physical start of RAM (e.g., 0x8000_0000).
/// `mem_size`: total RAM size in bytes.
/// `kernel_end`: physical address after the last byte of the kernel + bitmap.
///
/// Pages from `mem_start` to `kernel_end` are marked as reserved.
///
/// Returns `false`, refusing to initialize the allocator, if `mem_start >
/// kernel_end`. That ordering is impossible on real hardware — the kernel
/// image is loaded INTO the RAM range `mem_start` describes, so the image's
/// own end address can never sit below the range's start — and can only
/// come from a corrupt or hostile `/memory` node (DTB audit, 2026-09-22:
/// the parser-side out-of-bounds read that could hand back a fabricated
/// `mem_start` was closed in `crates/drivers/dtb`; this is the consumer-side half).
/// `reserved_pages` below computes `kernel_end - mem_start`; trusting that
/// input used to underflow the subtraction and, under this kernel's release
/// profile (`overflow-checks = true`, `panic = "abort"`), reset the board
/// with no diagnostic. Refusing beats clamping to a guessed-at range: a
/// clamp would still boot on a self-reported memory map this function has
/// no way to verify against the real hardware.
///
/// On refusal every field is left (or reset) to the same all-zero state
/// the static initializer starts in — `total_pages == 0` in particular, so
/// `alloc_page` already refuses every allocation with `OutOfMemory` rather
/// than handing one out computed from garbage, and every existing caller
/// already halts loudly the moment it reads back `free_pages() == 0` right
/// after this call (see the "[MM] FAILED: no free pages" marker in
/// `kernel/src/entry/{riscv64,aarch64}/boot_hooks.rs`, both ISAs) — refusing here routes a hostile map
/// into that same, already-tested fail-closed path instead of adding a
/// second one.
pub fn init(mem_start: usize, mem_size: usize, kernel_end: usize) -> bool {
    let mut pmm = PMM.lock();

    if mem_start > kernel_end {
        pmm.bitmap = [0; BITMAP_WORDS];
        pmm.total_pages = 0;
        pmm.free_pages = 0;
        pmm.managed_start = 0;
        pmm.next_scan_word = 0;
        pmm.initialized = false;
        FRAME_BASE.store(0, Ordering::Relaxed);
        FRAME_COUNT.store(0, Ordering::Relaxed);
        return false;
    }

    let total = core::cmp::min(mem_size / PAGE_SIZE, MAX_PAGES);
    pmm.total_pages = total;
    pmm.managed_start = mem_start;
    FRAME_BASE.store(mem_start, Ordering::Relaxed);
    FRAME_COUNT.store(total, Ordering::Relaxed);

    // Clear bitmap (all free)
    pmm.bitmap = [0; BITMAP_WORDS];
    pmm.next_scan_word = 0;

    // Reserve pages from start to kernel_end. Safe now: the guard above
    // has already established mem_start <= kernel_end.
    let reserved_pages = (kernel_end - mem_start + PAGE_SIZE - 1) / PAGE_SIZE;
    for i in 0..reserved_pages {
        if i < total {
            bitmap_set(&mut pmm.bitmap, i);
        }
    }

    // Count free pages via popcount on bitmap words — O(BITMAP_WORDS)
    // (~128K iter for 4M-page systems via bit ops) vs the previous
    // O(total) bit-by-bit loop (~16M iter). 100× faster on init.
    let used_bits: u32 = pmm.bitmap.iter().map(|w| w.count_ones()).sum();
    let used = used_bits as usize;
    pmm.free_pages = total.saturating_sub(used);
    pmm.initialized = true;
    true
}

/// Allocate a single 4 KiB physical page.
/// Returns the physical address of the page, or `OutOfMemory`.
pub fn alloc_page() -> KResult<PhysAddr> {
    let addr = alloc_page_raw()?;
    zero_new_page(addr);
    Ok(addr)
}

/// Allocate a single 4 KiB physical page WITHOUT zeroing it.
///
/// For a caller that is about to overwrite every byte anyway —
/// `mm::cow::handle_cow_fault`'s break, which `copy_nonoverlapping`s the
/// whole page immediately after allocating it (U09-11). `alloc_page`'s
/// zero is there for the callers that DON'T immediately overwrite the
/// whole page (a demand-paged anonymous page, which must not hand a task
/// a stale sibling's bytes); a COW break already has real data to put
/// there, so `alloc_page`'s ~1500-instruction `write_bytes` was pure waste
/// on that path — 8 KiB written to produce 4 KiB of live data. Marked
/// `unsafe`: the caller must overwrite the page before anything reads it,
/// same contract `MaybeUninit` documents for the same reason.
///
/// # Safety
/// The caller must fully initialise the returned page (e.g. via
/// `copy_nonoverlapping`) before any code — including a fault handler
/// re-entering with the same physical address after a `free_page` — can
/// read from it. Handing this page to userspace, or reading it back,
/// before that write happens leaks whatever physical RAM previously held.
pub unsafe fn alloc_page_uninit() -> KResult<PhysAddr> {
    alloc_page_raw()
}

/// Allocate `n` physically contiguous, zeroed 4 KiB pages; returns the
/// physical address of the first.
///
/// For a device that is told one base address and then reads or writes the
/// whole block (the legacy virtio-mmio queue: one PFN for descriptor table,
/// avail ring and used ring). Consecutive `alloc_page` calls do NOT give that:
/// the scan resumes at `next_scan_word` and takes that word's lowest free bit,
/// which can sit below, or far from, the page the previous call returned.
///
/// A first-fit run search over the bitmap, under the lock, bounded by
/// `total_pages` (the tail bits of the last word past `total_pages` read as
/// free and must never count towards a run). It does not move
/// `next_scan_word`: the cursor is a hint for `alloc_page`, and a run
/// allocated elsewhere does not change where single pages are likely free.
/// The pages are zeroed after the lock is dropped, for the same reason and
/// with the same bit-before-zero ordering as `alloc_page` (see
/// `zero_new_page`). The scan is O(total_pages) with the lock held, so this
/// is for boot-time and driver-setup callers, not a hot path.
///
/// Each page is released with `free_page`, one call per page. `n == 0` is
/// `InvalidArg`; no run of `n` free pages is `OutOfMemory`, with nothing
/// claimed.
pub fn alloc_contiguous(n: usize) -> KResult<PhysAddr> {
    if n == 0 {
        return Err(KernelError::InvalidArg);
    }
    let addr = {
        let mut pmm = PMM.lock();
        if n > pmm.free_pages {
            return Err(KernelError::OutOfMemory);
        }
        let total = pmm.total_pages;
        let mut run_start = 0usize;
        let mut run_len = 0usize;
        let mut found: Option<usize> = None;
        let mut page = 0usize;
        while page < total {
            // A full word ends any run; skip it whole.
            if page % 64 == 0 && pmm.bitmap[page / 64] == u64::MAX {
                run_len = 0;
                page += 64;
                continue;
            }
            if bitmap_test(&pmm.bitmap, page) {
                run_len = 0;
            } else {
                if run_len == 0 {
                    run_start = page;
                }
                run_len += 1;
                if run_len == n {
                    found = Some(run_start);
                    break;
                }
            }
            page += 1;
        }
        let start = match found {
            Some(s) => s,
            None => return Err(KernelError::OutOfMemory),
        };
        for p in start..start + n {
            bitmap_set(&mut pmm.bitmap, p);
        }
        pmm.free_pages -= n;
        pmm.managed_start + start * PAGE_SIZE
    };
    for i in 0..n {
        zero_new_page(PhysAddr::new(addr + i * PAGE_SIZE));
    }
    Ok(PhysAddr::new(addr))
}

/// [`alloc_contiguous`] whose run starts at a physical address that is a
/// multiple of `align` (a power of two, at least `PAGE_SIZE`). For the
/// boot-time 2 MiB-leaf regions (Kconfig `LOCKED_HUGE_LEAVES`): a level-1
/// leaf needs its physical base aligned to the leaf size, which a plain
/// first-fit run does not give. Same contract otherwise: under the lock,
/// O(total_pages), zeroed after the lock is dropped, `OutOfMemory` with
/// nothing claimed when no aligned run of `n` free pages exists.
pub fn alloc_contiguous_aligned(n: usize, align: usize) -> KResult<PhysAddr> {
    if n == 0 || !align.is_power_of_two() || align < PAGE_SIZE {
        return Err(KernelError::InvalidArg);
    }
    let addr = {
        let mut pmm = PMM.lock();
        if n > pmm.free_pages {
            return Err(KernelError::OutOfMemory);
        }
        let total = pmm.total_pages;
        let base = pmm.managed_start;
        // First page index whose address is aligned, then every `step` pages.
        let first = (((base + align - 1) & !(align - 1)) - base) / PAGE_SIZE;
        let step = align / PAGE_SIZE;
        let mut found: Option<usize> = None;
        let mut start = first;
        while start + n <= total {
            match (start..start + n).find(|&p| bitmap_test(&pmm.bitmap, p)) {
                None => {
                    found = Some(start);
                    break;
                }
                // Next aligned candidate past the used page.
                Some(used) => start += ((used - start) / step + 1) * step,
            }
        }
        let start = match found {
            Some(s) => s,
            None => return Err(KernelError::OutOfMemory),
        };
        for p in start..start + n {
            bitmap_set(&mut pmm.bitmap, p);
        }
        pmm.free_pages -= n;
        base + start * PAGE_SIZE
    };
    for i in 0..n {
        zero_new_page(PhysAddr::new(addr + i * PAGE_SIZE));
    }
    Ok(PhysAddr::new(addr))
}

/// The bitmap-scan half of `alloc_page`, shared with `alloc_page_uninit`.
/// Returns a freshly claimed (but NOT zeroed) page.
fn alloc_page_raw() -> KResult<PhysAddr> {
    // Everything that touches the bitmap happens in this inner block, so
    // the lock (and the preemption-disabled section that comes with it,
    // per SpinLock::lock()) is dropped before the page is zeroed by the
    // caller (`alloc_page`) below.
    let addr = {
        let mut pmm = PMM.lock();

        if pmm.total_pages == 0 {
            return Err(KernelError::OutOfMemory);
        }

        // Start the scan at the word the last successful allocation left
        // off at, instead of always starting over at word 0. `next_scan_word`
        // is only ever written below to a `word_idx` this same scan just
        // visited, so it is always a valid index — no modulo needed to
        // sanitize it.
        //
        // Split into two passes — cursor..BITMAP_WORDS, then 0..cursor —
        // rather than one loop indexing with `(start + i) % BITMAP_WORDS`.
        // Both forms visit the same words in the same order and are
        // equally correct (a free page below the cursor is only found
        // after the words above it, in the second pass, never skipped).
        // The difference is codegen: each of these two ranges has a
        // constant, compile-time-provable upper bound matching the
        // array's own length (`BITMAP_WORDS..` for the first, and the
        // second is bounded by the first pass having already checked
        // every earlier index), so the compiler elides the bitmap's
        // bounds check on every iteration. The single-loop modulo version
        // was measured (disassembly, riscv64imac release) to cost 15
        // instructions per skipped word instead of 10 — the modulo
        // bookkeeping plus a bounds check LLVM could no longer elide —
        // which makes the true worst case (a full sweep near OOM) *worse*
        // than the original code specifically to speed up the common
        // case. This form keeps the fast path fast without that trade.
        let mut found: Option<usize> = None;
        for word_idx in pmm.next_scan_word..BITMAP_WORDS {
            if word_idx * 64 >= pmm.total_pages {
                break;
            }
            if let Some(page) = try_alloc_from_word(&mut pmm, word_idx) {
                found = Some(page);
                break;
            }
        }
        if found.is_none() {
            for word_idx in 0..pmm.next_scan_word {
                if word_idx * 64 >= pmm.total_pages {
                    break;
                }
                if let Some(page) = try_alloc_from_word(&mut pmm, word_idx) {
                    found = Some(page);
                    break;
                }
            }
        }

        let page = match found {
            Some(p) => p,
            None => return Err(KernelError::OutOfMemory),
        };

        pmm.managed_start + page * PAGE_SIZE
    };

    Ok(PhysAddr::new(addr))
}

/// Zero a freshly allocated page OUTSIDE `PMM`'s lock (identity-mapped, so
/// phys == virt before paging, and after `vmm_init` the kernel has an
/// identity mapping).
///
/// Safe to do without holding the lock specifically because the bit was
/// already set, under the lock, inside `alloc_page_raw`: `alloc_page_raw`
/// and `next_free_addr` are the only ways this page's address can be
/// produced, both read the bitmap under `PMM.lock()`, and both will now see
/// this page as used. No second caller — on this hart or another — can be
/// handed this same address while it is being zeroed. The bit-before-zero
/// order the original code relied on (so a concurrent allocator can't
/// double-hand the page) is preserved: the bit is still set strictly before
/// the zeroing begins, and the unlock inside `alloc_page_raw` is a release
/// store that publishes it to every other hart before any of them can
/// observe the bitmap. What changes is only that the zeroing itself no
/// longer holds the lock (or blocks preemption) while it runs, which is the
/// whole point: a 4 KiB `write_bytes` is roughly 1500 RV64 instructions, and
/// every other hart's fork/exec/fault/shm/io_ring allocation was previously
/// serialized behind it.
///
/// RFC-0045 Tier 0 item 3: dispatches to `cbo.zero` when a boot-time probe
/// confirmed it (see `azos_arch::cbo`), and to plain `write_bytes`
/// otherwise — the "outside the lock" property above holds exactly the
/// same for either path, since neither touches `PMM` at all.
fn zero_new_page(addr: PhysAddr) {
    unsafe {
        // `addr` is PHYSICAL. The CPU reaches it through the kernel's own
        // mapping, which is identity on riscv64 and the upper half on
        // aarch64 — zeroing through the raw physical number worked only
        // while a task's TTBR0 happened to still identity-map RAM, and
        // stopped the moment a user page table was installed.
        azos_arch::cbo::zero_memory(crate::addr::phys_to_virt(addr.as_usize()), PAGE_SIZE);
    }
}

/// Free a single 4 KiB physical page.
pub fn free_page(addr: PhysAddr) -> KResult<()> {
    let mut pmm = PMM.lock();

    let phys = addr.as_usize();
    if phys < pmm.managed_start {
        return Err(KernelError::InvalidArg);
    }
    if !addr.is_page_aligned() {
        return Err(KernelError::NotAligned);
    }

    let page = (phys - pmm.managed_start) / PAGE_SIZE;
    if page >= pmm.total_pages {
        return Err(KernelError::InvalidArg);
    }
    if !bitmap_test(&pmm.bitmap, page) {
        return Err(KernelError::DoubleFree);
    }

    bitmap_clear(&mut pmm.bitmap, page);
    pmm.free_pages += 1;
    Ok(())
}

/// Get the total number of managed pages.
pub fn total_pages() -> usize {
    PMM.lock().total_pages
}

/// Get the number of currently free pages.
pub fn free_pages() -> usize {
    PMM.lock().free_pages
}

/// Get the number of currently used pages.
pub fn used_pages() -> usize {
    let pmm = PMM.lock();
    pmm.total_pages - pmm.free_pages
}

/// Reserve a range of physical memory in the PMM (mark pages as allocated).
///
/// Used after `kheap::init()` to prevent PMM from handing out heap pages
/// to later callers (e.g. VirtIO DMA buffers).
pub fn reserve_range(start: usize, size: usize) {
    let mut pmm = PMM.lock();
    if start < pmm.managed_start { return; }
    let first_page = (start - pmm.managed_start) / PAGE_SIZE;
    let num_pages  = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    for i in 0..num_pages {
        let page = first_page + i;
        if page >= pmm.total_pages { break; }
        if !bitmap_test(&pmm.bitmap, page) {
            bitmap_set(&mut pmm.bitmap, page);
            if pmm.free_pages > 0 { pmm.free_pages -= 1; }
        }
    }
}

/// Is every page of `[start, start + size)` managed by the PMM and free?
///
/// For a caller that takes a whole range as one block, the kernel heap above
/// all: `reserve_range` skips pages already in use and stops at the end of
/// RAM without a word, so a range it "reserved" can still hold another
/// owner's page (the boot stack once sat inside the heap) or none at all.
pub fn range_is_free(start: usize, size: usize) -> bool {
    let pmm = PMM.lock();
    if start < pmm.managed_start { return false; }
    let first_page = (start - pmm.managed_start) / PAGE_SIZE;
    let num_pages  = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    if first_page + num_pages > pmm.total_pages { return false; }
    (first_page..first_page + num_pages).all(|page| !bitmap_test(&pmm.bitmap, page))
}

/// Return the physical address of the first free page.
///
/// Used to determine where the kernel heap should start after vmm::init()
/// has allocated all page table pages from the PMM.
pub fn next_free_addr() -> usize {
    let pmm = PMM.lock();
    for word_idx in 0..BITMAP_WORDS {
        if word_idx * 64 >= pmm.total_pages { break; }
        if pmm.bitmap[word_idx] == u64::MAX { continue; }
        let word = pmm.bitmap[word_idx];
        let bit = (!word).trailing_zeros() as usize;
        let page = word_idx * 64 + bit;
        if page < pmm.total_pages {
            return pmm.managed_start + page * PAGE_SIZE;
        }
    }
    // No free pages — return end of managed range
    pmm.managed_start + pmm.total_pages * PAGE_SIZE
}

// ── RFC-0049 P7: the boot-reserved DMA pool ────────────────────────────────

static DMA_POOL_BASE: AtomicUsize = AtomicUsize::new(0);
static DMA_POOL_PAGES: AtomicUsize = AtomicUsize::new(0);

/// Reserve the DMA pool: `pages` physically contiguous frames taken out of the
/// allocator once, at boot, before anything can fragment it
/// (`alloc_contiguous`, the mechanism). Returns its physical base.
///
/// Reserve only: nothing allocates from the pool yet (`crates/drivers/dma`'s
/// `CoherentPool` is the intended user). It is one number memory admission can
/// count, where growing on demand could fail at run time from fragmentation.
/// A second call is refused (`InvalidArg`), so the pool cannot be replaced by
/// one of another size after admission counted it. `pages == 0` reserves
/// nothing and succeeds.
pub fn reserve_dma_pool(pages: usize) -> KResult<PhysAddr> {
    if DMA_POOL_PAGES.load(Ordering::Acquire) != 0 {
        return Err(KernelError::InvalidArg);
    }
    if pages == 0 {
        return Ok(PhysAddr::new(0));
    }
    let base = alloc_contiguous(pages)?;
    DMA_POOL_BASE.store(base.as_usize(), Ordering::Release);
    DMA_POOL_PAGES.store(pages, Ordering::Release);
    Ok(base)
}

/// `(physical base, pages)` of the DMA pool; `(0, 0)` before it is reserved.
pub fn dma_pool() -> (usize, usize) {
    (DMA_POOL_BASE.load(Ordering::Acquire), DMA_POOL_PAGES.load(Ordering::Acquire))
}

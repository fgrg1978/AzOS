// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! User-memory access sections: what keeps the frame a kernel copy is using
//! from being freed, reissued or read out from under it.
//!
//! **Why this is needed.** The kernel never dereferences a user VA.
//! `copy_to_user` and its siblings resolve each user page in software
//! (`vmm::translate_user`: `VALID + USER + R/W`, demand commit, COW break)
//! and copy through the kernel's own map of the frame (`addr::phys_to_virt`).
//! A TLB shootdown does not stop such a copy, it stops only accesses through
//! the user's mapping. So when another thread of the process ran `munmap` on
//! the page between the copy's walk and its last byte, the unmap cleared the
//! leaf, shot the TLBs down and freed the frame while the copy still wrote it
//! (or read it): a store into a frame the allocator may already have handed
//! to another process or to the kernel, or another owner's bytes handed back
//! to the caller. Proved on the code before this module by the host suite
//! `syscall-tests` (`uaccess_race.rs`: a copy parked between its walk and its
//! copy, the real `unmap_user_range_and_free` on another thread, and the
//! frame reissued by the next `alloc_page`). The same window was open to the
//! reclaimer taking a page out (`pager`), a copy-on-write break or fork
//! (`cow`), a superpage promotion or split, and `mprotect`.
//!
//! **Readers.** Every access to user memory through the kernel's map runs in
//! a [`Section`] covering the leaf walk and the access, at most one page:
//! interrupts off (the section is neither preempted nor migrated), this CPU's
//! sequence word made odd, a full fence; then the walk, which in a section
//! never faults a page in, allocates or shoots TLBs down
//! (`vmm::translate_user_{readable,writable}_nofault`); then the access; then
//! the word even again (release). A walk that misses leaves the section,
//! faults the page in with `vmm::translate_user` as the copy did before, and
//! tries again.
//!
//! **Writers.** Whoever takes a user leaf away (clears it, write-protects it,
//! moves its page to another frame) calls [`wait_readers`] after the leaf
//! store and its TLB shootdown, before it frees the frame, reuses it, or reads
//! it to keep a copy: `vmm::user_shootdown` is the shootdown and the wait,
//! and every user-leaf shootdown in this crate goes through it. So a kernel
//! copy has the guarantee a ring-3 access has from the shootdown: once it
//! returns, nothing uses the old translation.
//!
//! **Why that is enough (two fences, Dekker).** The writer stores the leaf,
//! fences, reads each CPU's word; a reader stores its word odd, fences,
//! reads the leaf. Either the reader's walk sees the new leaf, or the writer
//! sees the word odd and waits until it moves (the section ended: its
//! accesses are ordered before the even store, which the writer reads with
//! acquire). A section started after the writer's read sees the new leaf.
//! A section never waits for anything, so a writer waiting for one cannot
//! deadlock: with interrupts off it cannot be preempted by the writer, and it
//! takes no lock. A writer never runs inside a section (nothing in one
//! frees or unmaps), so it never waits for itself.
//!
//! **Cost.** A reader pays interrupts off and on, two stores and a fence per
//! page. A writer pays one load per online CPU per shootdown, and a wait only
//! for a CPU that is copying at that instant (a page at most). The
//! alternative the brief named, pinning the frame through its share count
//! (`cow_table`), costs a reader two compare-and-swap loops on the frame's
//! descriptor and a second walk to re-check the leaf per page, and that count
//! is the copy-on-write share count: a pinned private page reads as shared.
//!
//! Gate canary `uaccess-race-canary`: [`wait_readers`] returns at once, as the
//! code before this module did (`uaccess_race.rs` must fail).

use core::sync::atomic::{fence, AtomicU64, Ordering};

use azos_arch::{ArchPlatform as _, PAGE_SIZE, ARCH};

use crate::vmm;

/// One sequence word per CPU, each on its own cache line: a copying CPU
/// writes only its own, a writer reads them all.
#[repr(C, align(64))]
struct Seq(AtomicU64);

const NCPU: usize = azos_limits::NR_CPUS;

static SEQ: [Seq; NCPU] = [const { Seq(AtomicU64::new(0)) }; NCPU];

#[cfg(target_os = "none")]
use crate::kheap::{irq_off, irq_restore};

/// Host suites: interrupts are a thread's own business there; the section's
/// word is what is tested.
#[cfg(not(target_os = "none"))]
fn irq_off() -> usize {
    0
}
#[cfg(not(target_os = "none"))]
fn irq_restore(_: usize) {}

/// This CPU's logical id (the dense id every per-CPU table uses).
// percpu-hint: read only by `enter`, after its `irq_off`.
#[cfg(target_os = "none")]
#[inline(always)]
fn this_cpu() -> usize {
    use azos_arch_api::Cpu as _;
    ARCH.hart_id()
}

/// CPUs whose words a writer reads: the possible set, not the 64 of
/// Kconfig NR_CPUS.
#[cfg(target_os = "none")]
#[inline(always)]
fn cpus() -> usize {
    azos_percpu::nr_cpu_ids().min(NCPU)
}

#[cfg(not(target_os = "none"))]
std::thread_local! {
    static HOST_CPU: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(not(target_os = "none"))]
fn this_cpu() -> usize {
    HOST_CPU.with(|c| c.get())
}

#[cfg(not(target_os = "none"))]
fn cpus() -> usize {
    NCPU
}

/// Host suites only: the "CPU" the calling thread copies on, so two threads
/// use two words as two CPUs would.
#[cfg(not(target_os = "none"))]
pub fn shim_set_cpu(cpu: usize) {
    assert!(cpu < NCPU);
    HOST_CPU.with(|c| c.set(cpu));
}

#[cfg(not(target_os = "none"))]
static HOOK: azos_sync::SpinLock<Option<fn(usize)>> = azos_sync::SpinLock::new(None);

/// Host suites only: call `hook` with the frame address inside every section,
/// between the walk and the access (`uaccess_race.rs` parks a copy there).
#[cfg(not(target_os = "none"))]
pub fn shim_set_hook(hook: Option<fn(usize)>) {
    *HOOK.lock() = hook;
}

/// An open section on this CPU: see the module doc. Not `Send`.
pub struct Section {
    irq: usize,
    word: &'static AtomicU64,
    odd: u64,
    _cpu: core::marker::PhantomData<*mut ()>,
}

/// Open a section. Nothing in it may fault a page in, allocate, take a lock
/// or unmap: it runs with interrupts off and a writer may be waiting for it.
#[inline(always)]
pub fn enter() -> Section {
    let irq = irq_off();
    let word = &SEQ[this_cpu()].0;
    let odd = word.load(Ordering::Relaxed) | 1;
    word.store(odd, Ordering::Relaxed);
    // The odd store before the walk's loads (the writer's fence pairs).
    fence(Ordering::SeqCst);
    Section { irq, word, odd, _cpu: core::marker::PhantomData }
}

impl Drop for Section {
    #[inline(always)]
    fn drop(&mut self) {
        // Every access of the section before the even store.
        self.word.store(self.odd + 1, Ordering::Release);
        irq_restore(self.irq);
    }
}

/// Wait until no CPU is inside a section that may have walked a user leaf
/// before the caller's store to it. Called after a user leaf was cleared,
/// write-protected or moved (and shot down), before its old frame is freed,
/// reused or read. Never from inside a section.
pub fn wait_readers() {
    if cfg!(feature = "uaccess-race-canary") {
        return;
    }
    // The caller's leaf stores before the loads of the words.
    fence(Ordering::SeqCst);
    for s in &SEQ[..cpus()] {
        let w = s.0.load(Ordering::Acquire);
        if w & 1 != 0 {
            while s.0.load(Ordering::Acquire) == w {
                core::hint::spin_loop();
            }
        }
    }
}

/// The frame `va` of `pt` resolves to, for a read or a write, if it is
/// resident with that permission: the walk a section may do (no fault-in).
#[inline(always)]
fn resident(pt: usize, va: usize, write: bool) -> Option<usize> {
    if write {
        vmm::translate_user_writable_nofault(pt, va)
    } else {
        vmm::translate_user_readable_nofault(pt, va)
    }
}

/// Run `f` on the frame address `va` resolves to, inside a section; on a miss,
/// fault the page in outside it (demand commit, COW break: what ring 3's own
/// access would do) and try again. `None` when the page cannot be made
/// accessible. The retry ends when the walk hits or `translate_user` refuses:
/// another thread unmapping the page over and over only delays it, and
/// interrupts are on between tries.
#[inline(always)]
fn with_frame<R>(pt: usize, va: usize, write: bool, f: impl FnOnce(usize) -> R) -> Option<R> {
    loop {
        {
            let _s = enter();
            if let Some(pa) = resident(pt, va, write) {
                #[cfg(not(target_os = "none"))]
                {
                    let h = *HOOK.lock();
                    if let Some(h) = h {
                        h(pa);
                    }
                }
                // O3.2 (PAN/SUM): the access below goes through the kernel's
                // map of the frame, which neither PAN nor SUM gates; the
                // walk above is what makes it safe. The window keeps a
                // future access through the user's own VA failing outside it.
                let _ua = ARCH.user_access();
                return Some(f(pa));
            }
        }
        vmm::translate_user(pt, va, write)?;
    }
}

/// Bytes from `va` to the end of its page, at most `left`.
#[inline(always)]
fn chunk(va: usize, left: usize) -> usize {
    (PAGE_SIZE - (va & (PAGE_SIZE - 1))).min(left)
}

/// Copy `len` bytes from the kernel buffer `src` to user `va` of the address
/// space `pt`, a page per section. `false` on any page that is not (and
/// cannot be made) user-writable, or a range that wraps. Pages before a
/// failing one are written.
pub fn copy_out(pt: usize, va: usize, src: *const u8, len: usize) -> bool {
    if va.checked_add(len).is_none() {
        return false;
    }
    let mut done = 0;
    while done < len {
        let at = va + done;
        let n = chunk(at, len - done);
        // SAFETY: `pa` is a user-writable frame of `pt` resolved inside this
        // section, `n` bytes stay inside its page, and the caller's `src` holds
        // `len` bytes.
        let ok = with_frame(pt, at, true, |pa| unsafe {
            core::ptr::copy_nonoverlapping(src.add(done), crate::addr::phys_to_virt(pa) as *mut u8, n);
        });
        if ok.is_none() {
            return false;
        }
        done += n;
    }
    true
}

/// Copy `len` bytes from user `va` of `pt` into the kernel buffer `dst`, a
/// page per section. `false` on any page that is not user-readable (a
/// reserved page not touched yet is committed first), or a range that wraps.
pub fn copy_in(pt: usize, dst: *mut u8, va: usize, len: usize) -> bool {
    if va.checked_add(len).is_none() {
        return false;
    }
    let mut done = 0;
    while done < len {
        let at = va + done;
        let n = chunk(at, len - done);
        // SAFETY: as `copy_out`, for a user-readable frame and `dst`.
        let ok = with_frame(pt, at, false, |pa| unsafe {
            core::ptr::copy_nonoverlapping(crate::addr::phys_to_virt(pa) as *const u8, dst.add(done), n);
        });
        if ok.is_none() {
            return false;
        }
        done += n;
    }
    true
}

/// [`copy_in`] that never faults a page in (no commit, no COW break, no
/// allocation, no lock): for a reader in interrupt context (the sampling
/// profiler, the crash dump). Stops at the first page that is not resident
/// and readable; the bytes copied.
pub fn copy_in_resident(pt: usize, dst: *mut u8, va: usize, len: usize) -> usize {
    let mut done = 0;
    while done < len {
        let Some(at) = va.checked_add(done) else { break };
        let n = chunk(at, len - done);
        let _s = enter();
        let Some(pa) = resident(pt, at, false) else { break };
        // SAFETY: as `copy_in`.
        unsafe { core::ptr::copy_nonoverlapping(crate::addr::phys_to_virt(pa) as *const u8, dst.add(done), n) };
        done += n;
    }
    done
}

/// Copy the NUL-terminated string at user `va` of `pt` into `dst`, the NUL
/// included, scanning a page per section. The length without the NUL;
/// `None` when a page is not user-readable or no NUL comes within
/// `dst.len()` bytes.
pub fn cstr_in(pt: usize, dst: &mut [u8], va: usize) -> Option<usize> {
    let mut len = 0usize;
    loop {
        if len >= dst.len() {
            return None;
        }
        let at = va.checked_add(len)?;
        let n = chunk(at, dst.len() - len);
        let start = len;
        let found = with_frame(pt, at, false, |pa| {
            let k = crate::addr::phys_to_virt(pa) as *const u8;
            for i in 0..n {
                // SAFETY: `i < n`, inside the frame's page.
                let b = unsafe { *k.add(i) };
                dst[start + i] = b;
                if b == 0 {
                    return Some(start + i);
                }
            }
            None
        })?;
        if found.is_some() {
            return found;
        }
        len += n;
    }
}

/// Compare-and-swap the aligned user word at `va` of `pt`: `old` becomes
/// `new` atomically against every thread of the process. `Ok(())` on success,
/// `Err(Some(current))` when the word held another value, `Err(None)` when it
/// is not a writable user word (not 4-aligned, not mapped, read-only).
/// `fault`: make a copy-on-write or reserved page writable first (no lock may
/// be held); otherwise such a page answers `Err(None)` with nothing done.
pub fn cas_u32(pt: usize, va: usize, old: u32, new: u32, fault: bool) -> Result<(), Option<u32>> {
    if va & 3 != 0 {
        return Err(None);
    }
    let cas = |pa: usize| {
        // SAFETY: a user-writable frame resolved in this section; `pa` is
        // 4-aligned inside it, and the kernel's map of RAM is valid for an
        // atomic 32-bit access.
        let w = unsafe { &*(crate::addr::phys_to_virt(pa) as *const core::sync::atomic::AtomicU32) };
        w.compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire).map(|_| ()).map_err(Some)
    };
    if fault {
        return with_frame(pt, va, true, cas).unwrap_or(Err(None));
    }
    let _s = enter();
    match resident(pt, va, true) {
        Some(pa) => {
            let _ua = ARCH.user_access();
            cas(pa)
        }
        None => Err(None),
    }
}

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
//! **Cost, measured** (vsbench `uaccess-*`, QEMU -icount -smp 1,
//! instructions per op, sections against the same build with them taken
//! out): a section is about 22 instructions on riscv64, 16 on aarch64 and
//! 21 on x86_64 (interrupts off and on, two stores and a fence), so the
//! small lanes pay the most. `uaccess-get-u32` (a futex wait whose word
//! differs) is one section: the syscall edge answers it from one read
//! before the futex table or the region table is taken
//! (`vdso_notify::futex_precheck`). Measured when a read before the table
//! lock did the same inside `futex_table`, that one section was +1.3% on
//! riscv64 (1,647 -> 1,669), +1.0% on aarch64 (1,583 -> 1,599) and +1.2%
//! on x86_64 (1,792 -> 1,813), and no lane was above +1.3% on any ISA (the
//! most: x86_64 `uaccess-cstr-7`); the word read twice, two sections, was
//! +2.3% on riscv64 (1,920 -> 1,964). The edge read takes that lane to
//! about 530 instructions, so its one section is a larger share of it (not
//! measured again). The alternative the brief named,
//! pinning the frame through its share count, cost 2,222 on that lane
//! (`cow_table`: two compare-and-swap loops on the frame's descriptor and a
//! second walk to re-check the leaf per page; and that count is the
//! copy-on-write share count, so a pinned private page reads as shared). A
//! writer pays one load per online CPU per shootdown, and a wait only for a
//! CPU that is copying at that instant (a page at most).
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

/// The word of CPU `cpu`. The dense logical id is below NR_CPUS (the bound
/// `pmm`'s per-CPU caches and `isr_depth::MAX_HARTS` rest on too), so a
/// power-of-two NR_CPUS (the defconfigs') masks the id instead of
/// bounds-checking it: the same word for every valid id, two instructions
/// fewer on every section.
#[inline(always)]
fn slot(cpu: usize) -> usize {
    if NCPU.is_power_of_two() {
        cpu & (NCPU - 1)
    } else {
        cpu
    }
}

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
    let word = &SEQ[slot(this_cpu())].0;
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
        self.word.store(self.odd.wrapping_add(1), Ordering::Release);
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

/// Copy `n` bytes, at most a page, between the kernel's map of a user frame
/// and a kernel buffer: what `copy_nonoverlapping` does, cheaper on the sizes
/// user-memory accesses have. A scalar (1, 2, 4, 8 bytes: an argument, a
/// futex word, a handle) is one load and one store instead of a call to
/// `memcpy`; a run of 64 bytes or more between 8-aligned addresses goes eight
/// words per iteration ([`copy_words`]). Measured on riscv64 (vsbench
/// `uaccess-*`, QEMU -icount): `compiler_builtins`' `memcpy` spent about 0.6
/// instructions per byte on a page, a word per five instructions.
///
/// # Safety
///
/// `dst` and `src` are valid for `n` bytes and do not overlap.
#[inline(always)]
unsafe fn copy_bytes(dst: *mut u8, src: *const u8, n: usize) {
    use core::ptr::{read_unaligned as rd, write_unaligned as wr};
    // SAFETY: the caller's contract, for each width.
    unsafe {
        let aligned = (dst as usize | src as usize) & n.wrapping_sub(1) == 0;
        match n {
            1 => *dst = *src,
            // Aligned (a futex word, a handle in a kernel struct): one load
            // and one store. Unaligned: the bytewise sequence the ISA needs
            // (riscv64 without Zicclsm splits a misaligned access in bytes).
            2 if aligned => (dst as *mut u16).write((src as *const u16).read()),
            4 if aligned => (dst as *mut u32).write((src as *const u32).read()),
            8 if aligned => (dst as *mut u64).write((src as *const u64).read()),
            2 => wr(dst as *mut u16, rd(src as *const u16)),
            4 => wr(dst as *mut u32, rd(src as *const u32)),
            8 => wr(dst as *mut u64, rd(src as *const u64)),
            // x86_64's `memcpy` is a string move (`rep movs`), which neither
            // loop below beats: measured on vsbench `uaccess-read-4k`, the
            // word loop cost x86_64 6,300 instructions a call more.
            _ if n >= 64 && !STRING_MOVE && (dst as usize | src as usize) & 7 == 0 => copy_words(dst, src, n),
            _ if n >= 64 && !STRING_MOVE => copy_shifted(dst, src, n),
            _ => core::ptr::copy_nonoverlapping(src, dst, n),
        }
    }
}

/// The ISA's `memcpy` moves a run as one string instruction (x86_64's
/// `compiler_builtins` uses `rep movs`); elsewhere it is the generic Rust loop
/// that [`copy_words`] and [`copy_shifted`] beat.
const STRING_MOVE: bool = cfg!(target_arch = "x86_64");

/// [`copy_bytes`]' run: eight 8-byte words per iteration, the tail by
/// `copy_nonoverlapping`. Volatile so the compiler cannot turn the loop back
/// into a call to `memcpy` (its loop-idiom pass would).
///
/// # Safety
///
/// As [`copy_bytes`], with `dst` and `src` 8-aligned.
#[inline(never)]
unsafe fn copy_words(dst: *mut u8, src: *const u8, n: usize) {
    let (d, s) = (dst as *mut u64, src as *const u64);
    let blocks = n / 64;
    // SAFETY: `blocks * 64 <= n` bytes of each, 8-aligned.
    unsafe {
        for b in 0..blocks {
            let (d, s) = (d.add(b * 8), s.add(b * 8));
            let w = [
                s.read_volatile(), s.add(1).read_volatile(), s.add(2).read_volatile(), s.add(3).read_volatile(),
                s.add(4).read_volatile(), s.add(5).read_volatile(), s.add(6).read_volatile(), s.add(7).read_volatile(),
            ];
            for (k, v) in w.into_iter().enumerate() {
                d.add(k).write_volatile(v);
            }
        }
        let done = blocks * 64;
        core::ptr::copy_nonoverlapping(src.add(done), dst.add(done), n - done);
    }
}

/// The index of the first NUL in the `n` bytes at `k`: a byte at a time to
/// the first 8-aligned byte, then a word at a time while no byte of the word
/// is the NUL (reading past the NUL stays inside the page the caller
/// validated), then bytes again. Scanning first and copying the found run
/// with [`copy_bytes`] after is what keeps a string near a byte an
/// instruction: copying word by word into an unaligned kernel buffer costs a
/// riscv64 without misaligned stores eight byte stores per word (vsbench
/// `uaccess-cstr-256`: the byte loop spent nine instructions a byte).
///
/// # Safety
///
/// `k` is valid for reads of `n` bytes, and of the whole aligned word around
/// any of them (the bytes are inside one page).
#[inline(always)]
unsafe fn nul_in(k: *const u8, n: usize) -> Option<usize> {
    let mut i = 0;
    // SAFETY: every read is inside `[k, k + n)` or the aligned word around a
    // byte of it, inside the page (the caller's contract).
    unsafe {
        while i < n && (k as usize + i) & 7 != 0 {
            if *k.add(i) == 0 {
                return Some(i);
            }
            i += 1;
        }
        while i + 8 <= n && !has_zero_byte((k.add(i) as *const u64).read_volatile()) {
            i += 8;
        }
        while i < n {
            if *k.add(i) == 0 {
                return Some(i);
            }
            i += 1;
        }
    }
    None
}

/// [`copy_bytes`]' run between addresses of different alignment: bytes up to
/// an 8-aligned destination, then each destination word built from two
/// aligned source words by shifts, then the tail by bytes. The kernel builds
/// for strict alignment (aarch64 `+strict-align`, riscv64 without
/// misaligned-access support), so `compiler_builtins`' `memcpy` assembles each
/// such word from eight byte loads: on aarch64 it spent 3.4 instructions a
/// byte on `uaccess-read-4k`. Every load is of an aligned word all of whose
/// bytes lie inside `[src, src + n)`: the first one is assembled from bytes.
///
/// # Safety
///
/// As [`copy_bytes`].
#[inline(never)]
unsafe fn copy_shifted(dst: *mut u8, src: *const u8, n: usize) {
    // SAFETY: every access is inside `[dst, dst + n)` / `[src, src + n)`,
    // the word loads 8-aligned (see the bounds below).
    unsafe {
        let head = (dst as usize).wrapping_neg() & 7;
        core::ptr::copy_nonoverlapping(src, dst, head);
        let (d, s, len) = (dst.add(head), src.add(head), n - head);
        let off = s as usize & 7;
        if off == 0 {
            return copy_words(d, s, len);
        }
        // The first source word's bytes from `s` up to the next 8-aligned
        // address, as the low end of an output word.
        let mut lo = 0u64;
        for j in 0..8 - off {
            lo |= (*s.add(j) as u64) << (8 * j);
        }
        let base = s.sub(off) as *const u64;
        let (rs, ls) = (8 * off as u32, 8 * (8 - off) as u32);
        let mut i = 0;
        // Word `i + 1` of `base` ends at `s - off + 8 * i + 16`, inside the run.
        while 8 * i + 16 - off <= len {
            let hi = base.add(i + 1).read_volatile();
            (d.add(8 * i) as *mut u64).write_volatile(lo | (hi << ls));
            lo = hi >> rs;
            i += 1;
        }
        core::ptr::copy_nonoverlapping(s.add(8 * i), d.add(8 * i), len - 8 * i);
    }
}

/// Does the word hold a zero byte? (The classic test: a byte borrows into
/// its top bit only when it was zero.)
#[inline(always)]
const fn has_zero_byte(w: u64) -> bool {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    w.wrapping_sub(LO) & !w & HI != 0
}

/// Largest access [`copy_small`] takes: two words, what an argument, a handle
/// or a futex word is.
const SMALL: usize = 16;

/// A copy of at most [`SMALL`] bytes inside one page: one section, one walk,
/// one scalar copy, in a function small enough to keep its state in a few
/// registers (the general loop saves thirteen). `None` on a miss, which the
/// caller hands to the general loop (it faults the page in and retries).
/// `to_user`: `user` is the destination (`k` the source), else the source.
#[inline(never)]
fn copy_small(pt: usize, user: usize, k: *mut u8, len: usize, to_user: bool) -> Option<()> {
    let _s = enter();
    let pa = resident(pt, user, to_user)?;
    #[cfg(not(target_os = "none"))]
    {
        let h = *HOOK.lock();
        if let Some(h) = h {
            h(pa);
        }
    }
    let _ua = ARCH.user_access();
    let u = crate::addr::phys_to_virt(pa) as *mut u8;
    // SAFETY: `pa` is a frame of `pt` resolved inside this section with the
    // permission the direction needs, `len` bytes fit in its page (the
    // caller checked), and `k` holds `len` bytes.
    unsafe {
        if to_user {
            copy_bytes(u, k, len);
        } else {
            copy_bytes(k, u, len);
        }
    }
    Some(())
}

/// Does `[va, va + len)` fit [`copy_small`]: short, and inside one page?
#[inline(always)]
fn small(va: usize, len: usize) -> bool {
    len != 0 && len <= SMALL && (va & (PAGE_SIZE - 1)) + len <= PAGE_SIZE
}

/// Copy `len` bytes from the kernel buffer `src` to user `va` of the address
/// space `pt`, a page per section. `false` on any page that is not (and
/// cannot be made) user-writable, or a range that wraps. Pages before a
/// failing one are written.
#[inline]
pub fn copy_out(pt: usize, va: usize, src: *const u8, len: usize) -> bool {
    if small(va, len) && copy_small(pt, va, src as *mut u8, len, true).is_some() {
        return true;
    }
    copy_out_pages(pt, va, src, len)
}

/// [`copy_out`]'s loop, out of line: its frame (thirteen saved registers on
/// riscv64) is not paid by the scalar path.
#[inline(never)]
fn copy_out_pages(pt: usize, va: usize, src: *const u8, len: usize) -> bool {
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
            copy_bytes(crate::addr::phys_to_virt(pa) as *mut u8, src.add(done), n);
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
#[inline]
pub fn copy_in(pt: usize, dst: *mut u8, va: usize, len: usize) -> bool {
    if small(va, len) && copy_small(pt, va, dst, len, false).is_some() {
        return true;
    }
    copy_in_pages(pt, dst, va, len)
}

/// [`copy_in`]'s loop, out of line (see [`copy_out_pages`]).
#[inline(never)]
fn copy_in_pages(pt: usize, dst: *mut u8, va: usize, len: usize) -> bool {
    if va.checked_add(len).is_none() {
        return false;
    }
    let mut done = 0;
    while done < len {
        let at = va + done;
        let n = chunk(at, len - done);
        // SAFETY: as `copy_out`, for a user-readable frame and `dst`.
        let ok = with_frame(pt, at, false, |pa| unsafe {
            copy_bytes(dst.add(done), crate::addr::phys_to_virt(pa) as *const u8, n);
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
        unsafe { copy_bytes(dst.add(done), crate::addr::phys_to_virt(pa) as *const u8, n) };
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
            // SAFETY: `n` bytes of the frame's page, validated by the walk.
            let nul = unsafe { nul_in(k, n) };
            let m = nul.map_or(n, |e| e + 1);
            // SAFETY: `m <= n` bytes of the page into `dst[start..start + m]`
            // (`n <= dst.len() - start`).
            unsafe { copy_bytes(dst[start..start + m].as_mut_ptr(), k, m) };
            nul.map(|e| start + e)
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

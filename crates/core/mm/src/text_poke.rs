// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The one controlled write path into kernel text (wave 15, TRACE: static
//! keys; Kconfig `KTRACE_STATIC_KEYS`). Linux's `text_poke`, for single
//! aligned 32-bit instructions.
//!
//! # W^X stays whole
//!
//! The kernel text is mapped read-execute and nothing here changes that
//! mapping. A word is written through an ALIAS: one page-sized slot of
//! kernel VA above the RAM map, mapped read-write and never executable to
//! the frame that holds the instruction, for the duration of one write, then
//! unmapped. Before every write the text page's own PTE is read and the write
//! is refused unless it is execute and not write, so the alias is provably
//! the only writable view of that frame the write used, and while no write is
//! in progress the alias is unmapped (`alias_mapped` reads it back). Every
//! CPU's TLB is shot down for the alias VA once a batch is done.
//!
//! # SMP: patched live, justified per ISA
//!
//! A site is one naturally aligned 32-bit instruction swapped for another
//! complete instruction (a nop and a branch); both are correct code at any
//! moment (the branch target re-tests the runtime mask), so a CPU that runs
//! the site while it changes only needs to see one word or the other.
//!
//! * aarch64: NOP and B are in the ARM ARM's list of instructions that may
//!   be modified while another PE executes them without synchronisation
//!   (B2.2.5, "Concurrent modification and execution of instructions").
//!   After the write: the alias line is cleaned to the point of
//!   unification, then `IC IALLUIS` + `DSB ISH` + `ISB`; another PE picks
//!   the new word up at its next context-synchronisation event.
//! * riscv64: the ISA gives no such list; the argument is the one Linux's
//!   riscv jump labels rely on (`arch/riscv/kernel/jump_label.c`, no
//!   stop_machine): an aligned 32-bit store of a whole instruction is seen by
//!   instruction fetch as the old or the new word, never a tear, and the
//!   sites are assembled 4-byte, 4-aligned and unrelaxed for exactly that.
//!   After the write: `fence rw,rw`, `fence.i`, and the SBI remote `fence.i`
//!   on every hart. (Linux takes stop_machine on riscv only for ftrace's
//!   two-instruction sequences.)
//!
//! Writes are serialised by one lock taken with interrupts masked, so the
//! alias is only ever one page at a time and only on the CPU that holds it.
//! It is waited for with interrupts as the waiter had them ([`lock_text`]):
//! on x86_64 the holder waits, interrupts masked, for every CPU to take its
//! serialising IPI, which a CPU spinning with interrupts masked never would.
//!
//! # Livepatch (Kconfig `LIVEPATCH`)
//!
//! The signed kernel livepatch (`kernel/src/boot/livepatch.rs`) writes through
//! the same alias, with two more doors: [`write_bytes`] for a replacement body
//! (several pages of code nothing runs yet, written page by page into the
//! pool) and [`write_bp5`] for x86_64, which has no instruction a CPU may
//! fetch while it changes. The format and the checks are in [`patch`].
//!
//! # x86_64: the `int3` sequence
//!
//! The five bytes at a function entry go from the one `nopl` to a `jmp
//! rel32` (or back) in three writes, each followed by the serialising IPI of
//! `icache_sync_all`: the first byte becomes `int3`, the other four are
//! written, the first byte is written. A CPU that fetches the site between
//! the first write and the last takes the breakpoint, and [`bp_resume`] (called
//! from the kernel `#BP` arm) hands it the address to continue at, as if the
//! new instruction were already there. The same discipline as Linux's
//! `text_poke_bp`, without its batching.

use crate::vmm;
use azos_arch::{ArchPlatform, ARCH};
use azos_arch_api::{Mmu, PagePerms, PAGE_SIZE};
use azos_sync::{IrqSaveGuard, SpinLock};
use core::sync::atomic::{AtomicUsize, Ordering};

// The blob format, the checks that admit it, the relocations and the entry
// redirects of each ISA: the half that touches no memory, which the host
// suite runs (tests/host/mm-tests/src/livepatch.rs).
#[path = "livepatch_fmt.rs"]
pub mod patch;

/// The alias VA (0: not set up, the patcher is unavailable).
static ALIAS: AtomicUsize = AtomicUsize::new(0);
/// The kernel text `[start, end)` a write may target.
static TEXT_START: AtomicUsize = AtomicUsize::new(0);
static TEXT_END: AtomicUsize = AtomicUsize::new(0);
static LOCK: SpinLock<()> = SpinLock::new(());

/// Why a write was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PokeError {
    /// [`init`] did not run or found no free alias slot.
    Unavailable,
    /// Not a 4-aligned address inside the kernel text.
    OutOfText,
    /// The text page is not mapped by a 4 KiB leaf.
    NotLeaf,
    /// The text page's mapping is not execute-only-readable: either not
    /// executable (not code) or WRITABLE (W^X is already broken; refuse).
    NotRx,
    /// The alias could not be mapped.
    Map,
    /// The word read back through the alias is not the word written.
    Readback,
    /// Kept for the error's users; no longer returned: a 2-byte-aligned
    /// instruction ([`write_insns_boot`]) that straddles a page is written
    /// through two adjacent alias pages mapped before either half.
    CrossesPage,
}

/// Take `l` with interrupts masked, as `lock_irqsave` does, but wait for it
/// with them as the caller had them: a failed try puts them back before the
/// next. The holder of a text-write lock (this module's, or a caller's around
/// a batch of writes, the static keys' `KEYS`) waits with interrupts masked
/// for every CPU's TLB shootdown and instruction-fetch IPIs on x86_64
/// ([`sync_all`]); a CPU spinning for the same lock with interrupts masked
/// would never take them, and the two would wait on each other. Held, it is
/// the ordinary irqsave guard.
pub fn lock_text<T>(l: &SpinLock<T>) -> IrqSaveGuard<'_, T> {
    loop {
        if let Some(g) = l.try_lock_irqsave() {
            return g;
        }
        core::hint::spin_loop();
    }
}

/// Candidate alias slots tried above the RAM map (2 MiB apart).
const ALIAS_TRIES: usize = 8;
const SLOT: usize = 2 << 20;

/// Set the patcher up: pick an unmapped kernel VA above the RAM map and
/// build its page-table path now, before any user page table copies the
/// kernel's upper levels (riscv64 shares them by reference from then on).
/// `text_*` bound what may be written. Returns the alias VA.
pub fn init(text_start: usize, text_end: usize) -> Option<usize> {
    let kpt = vmm::kernel_pagetable();
    let ram_end = vmm::ram_end();
    if kpt == 0 || ram_end == 0 || text_start >= text_end {
        return None;
    }
    let base = (crate::addr::phys_to_virt(ram_end) + SLOT - 1) & !(SLOT - 1);
    let probe_pa = crate::addr::virt_to_phys(text_start & !(PAGE_SIZE - 1));
    for i in 1..=ALIAS_TRIES {
        let va = base + i * SLOT;
        if vmm::translate(kpt, va).is_some() || vmm::va_is_kernel_mapped(va) {
            continue;
        }
        // Map once (allocating the tables), then unmap: the path stays.
        if vmm::map(kpt, va, probe_pa, PagePerms::KERNEL_RW).is_err() {
            continue;
        }
        vmm::unmap_kernel(kpt, va);
        ARCH.flush_tlb_page(va);
        TEXT_START.store(text_start, Ordering::Relaxed);
        TEXT_END.store(text_end, Ordering::Relaxed);
        ALIAS.store(va, Ordering::Release);
        return Some(va);
    }
    None
}

/// The alias VA, if the patcher is set up.
pub fn alias() -> Option<usize> {
    let a = ALIAS.load(Ordering::Acquire);
    (a != 0).then_some(a)
}

/// Is the alias mapped right now? (It must not be, outside [`write_words`].)
pub fn alias_mapped() -> bool {
    alias().is_some_and(|a| vmm::translate(vmm::kernel_pagetable(), a).is_some())
}

/// Is the kernel text page holding `va` mapped read-execute and not
/// writable? The precondition of every write, exported for the boot
/// readback.
pub fn text_is_rx(va: usize) -> Result<(), PokeError> {
    let kpt = vmm::kernel_pagetable();
    if vmm::leaf_level(kpt, va) != Some(0) {
        return Err(PokeError::NotLeaf);
    }
    let pte = vmm::walk(kpt, va, false).map_err(|_| PokeError::NotLeaf)?;
    // SAFETY: a valid leaf entry of the kernel's own table.
    let perms = ARCH.pte_perms(unsafe { core::ptr::read_volatile(pte) });
    if perms.exec && !perms.write { Ok(()) } else { Err(PokeError::NotRx) }
}

/// Write each `(text VA, word)` through the alias, then make every CPU's
/// instruction fetch see them. Stops at the first refusal; returns how many
/// were written. Rare and slow by design: a TLB shootdown and an icache
/// synchronisation of every CPU per call.
pub fn write_words(words: &[(usize, u32)]) -> Result<usize, PokeError> {
    write_impl(words, false)
}

/// [`write_words`] for boot-once sites (wave 15, N2b: the `SpinWait` probe
/// sites), which may also sit at 2 mod 4 on riscv64 (a 4-byte instruction
/// in compressed code, where the alignment padding a 4-aligned site needs
/// would cost a `c.nop` on every pass). Such a word is written as its two
/// halves, low then high, through one alias mapping, or through two adjacent
/// alias pages when it straddles a text page (both mapped before the first
/// half, so only the store sequence runs between the halves either way: a
/// layout that put a site at offset 0xffe used to refuse it and leave the
/// whole batch after it linked). Precondition: no other CPU runs the kernel text yet
/// (the boot CPU before `wake_secondaries`), and the caller is not itself
/// running the site; between the two halves only the store sequence runs.
pub fn write_insns_boot(words: &[(usize, u32)]) -> Result<usize, PokeError> {
    write_impl(words, true)
}

fn write_impl(words: &[(usize, u32)], halves: bool) -> Result<usize, PokeError> {
    let alias = alias().ok_or(PokeError::Unavailable)?;
    let (ts, te) = (TEXT_START.load(Ordering::Relaxed), TEXT_END.load(Ordering::Relaxed));
    let kpt = vmm::kernel_pagetable();
    let _g = lock_text(&LOCK);
    let mut done = 0;
    let mut res = Ok(());
    for &(va, w) in words {
        if va & if halves { 1 } else { 3 } != 0 || va < ts || va + 4 > te {
            res = Err(PokeError::OutOfText);
            break;
        }
        // Only a 2-aligned word (`halves`) can reach into the next page.
        let straddles = va & 3 != 0 && (va & (PAGE_SIZE - 1)) > PAGE_SIZE - 4;
        let next = (va & !(PAGE_SIZE - 1)) + PAGE_SIZE;
        if let Err(e) = text_is_rx(va).and_then(|()| if straddles { text_is_rx(next) } else { Ok(()) }) {
            res = Err(e);
            break;
        }
        let Some(pa) = vmm::translate(kpt, va & !(PAGE_SIZE - 1)) else {
            res = Err(PokeError::NotLeaf);
            break;
        };
        let pa_next = if straddles {
            let Some(pa) = vmm::translate(kpt, next) else {
                res = Err(PokeError::NotLeaf);
                break;
            };
            Some(pa)
        } else {
            None
        };
        if vmm::map(kpt, alias, pa & !(PAGE_SIZE - 1), PagePerms::KERNEL_RW).is_err() {
            res = Err(PokeError::Map);
            break;
        }
        // The straddling half: the next text page at the next alias page,
        // in the same leaf table `init` built (2 MiB-aligned slot).
        if let Some(pn) = pa_next {
            if vmm::map(kpt, alias + PAGE_SIZE, pn & !(PAGE_SIZE - 1), PagePerms::KERNEL_RW).is_err() {
                vmm::unmap_kernel(kpt, alias);
                ARCH.flush_tlb_page(alias);
                res = Err(PokeError::Map);
                break;
            }
            ARCH.flush_tlb_page(alias + PAGE_SIZE);
        }
        ARCH.flush_tlb_page(alias);
        let off = alias + (va & (PAGE_SIZE - 1));
        let back = if va & 3 == 0 {
            let p = off as *mut u32;
            // SAFETY: `p` is inside the alias page just mapped read-write.
            unsafe {
                core::ptr::write_volatile(p, w);
                core::ptr::read_volatile(p)
            }
        } else {
            let p = off as *mut u16;
            // SAFETY: `p` and `p + 1` are 2-aligned and mapped read-write:
            // inside the alias page, or (straddling) its last halfword and
            // the first of the next alias page, mapped above.
            unsafe {
                core::ptr::write_volatile(p, w as u16);
                core::ptr::write_volatile(p.add(1), (w >> 16) as u16);
                core::ptr::read_volatile(p) as u32 | (core::ptr::read_volatile(p.add(1)) as u32) << 16
            }
        };
        let p = off as *mut u32;
        // SAFETY: the alias line is mapped. A no-op where fetch is coherent
        // with data writes (riscv64).
        unsafe { ARCH.dcache_clean(p as usize, 4) };
        vmm::unmap_kernel(kpt, alias);
        ARCH.flush_tlb_page(alias);
        if straddles {
            vmm::unmap_kernel(kpt, alias + PAGE_SIZE);
            ARCH.flush_tlb_page(alias + PAGE_SIZE);
        }
        if back != w {
            res = Err(PokeError::Readback);
            break;
        }
        done += 1;
    }
    sync_all(alias);
    res.map(|()| done)
}

/// Write `bytes` into the kernel text at `va` (any alignment, any length,
/// across pages), one alias mapping per page, then make every CPU's
/// instruction fetch see them. For code nothing is running yet: unlike
/// [`write_words`] it gives no instruction-at-a-time guarantee, so it is for
/// a body in the livepatch pool and for the single bytes of [`write_bp5`].
/// Returns the bytes written; stops at the first refusal.
pub fn write_bytes(va: usize, bytes: &[u8]) -> Result<usize, PokeError> {
    let alias = alias().ok_or(PokeError::Unavailable)?;
    let (ts, te) = (TEXT_START.load(Ordering::Relaxed), TEXT_END.load(Ordering::Relaxed));
    if bytes.is_empty() || va < ts || va.checked_add(bytes.len()).is_none_or(|e| e > te) {
        return Err(PokeError::OutOfText);
    }
    let kpt = vmm::kernel_pagetable();
    let _g = lock_text(&LOCK);
    let mut done = 0;
    let mut res = Ok(());
    while done < bytes.len() {
        let cur = va + done;
        let page = cur & !(PAGE_SIZE - 1);
        let n = (PAGE_SIZE - (cur - page)).min(bytes.len() - done);
        if let Err(e) = text_is_rx(page) {
            res = Err(e);
            break;
        }
        let Some(pa) = vmm::translate(kpt, page) else {
            res = Err(PokeError::NotLeaf);
            break;
        };
        if vmm::map(kpt, alias, pa & !(PAGE_SIZE - 1), PagePerms::KERNEL_RW).is_err() {
            res = Err(PokeError::Map);
            break;
        }
        ARCH.flush_tlb_page(alias);
        let dst = (alias + (cur - page)) as *mut u8;
        let src = &bytes[done..done + n];
        // SAFETY: `dst..dst+n` is inside the alias page just mapped
        // read-write (`n` stops at the page end); `src` is a separate slice.
        let same = unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst, n);
            ARCH.dcache_clean(dst as usize, n);
            src.iter().enumerate().all(|(i, &b)| core::ptr::read_volatile(dst.add(i)) == b)
        };
        vmm::unmap_kernel(kpt, alias);
        ARCH.flush_tlb_page(alias);
        if !same {
            res = Err(PokeError::Readback);
            break;
        }
        done += n;
    }
    sync_all(alias);
    res.map(|()| done)
}

/// The site of the `int3` sequence in progress (0: none), where a CPU that
/// takes the breakpoint continues, and how many are inside [`bp_resume`].
static BP_SITE: AtomicUsize = AtomicUsize::new(0);
static BP_RESUME: AtomicUsize = AtomicUsize::new(0);
static BP_REFS: AtomicUsize = AtomicUsize::new(0);
/// One `int3` sequence at a time (taken before [`LOCK`], which each step
/// takes in turn).
static BP_LOCK: SpinLock<()> = SpinLock::new(());

/// x86_64: replace the five bytes `old` at `site` with `new` by the `int3`
/// sequence (module doc). `old` is what the caller read there and checked.
/// On a refusal the five bytes of `old` are put back whole (tail first, head
/// last) while the `int3` is still in place and [`BP_SITE`] still set, so a CPU
/// that fetches the site meanwhile takes the breakpoint and continues as the
/// old instruction, never on a new tail under the old first byte. If even that
/// is refused the site is left armed: the trap stays handled (as `old`) and
/// every later call is refused.
pub fn write_bp5(site: usize, old: &[u8; 5], new: &[u8; 5]) -> Result<(), PokeError> {
    let _g = lock_text(&BP_LOCK);
    if BP_SITE.load(Ordering::SeqCst) != 0 {
        // A previous sequence could not put its site back.
        return Err(PokeError::Unavailable);
    }
    BP_SITE.store(site, Ordering::SeqCst);
    let out = patch::x86_bp_sequence(
        site as u64,
        old,
        new,
        &mut |r| BP_RESUME.store(r as usize, Ordering::Relaxed),
        &mut |va, b| write_bytes(va as usize, b).map(|_| ()),
    );
    if let patch::BpOutcome::Stuck(e) = out {
        return Err(e);
    }
    // Every CPU is past the last step's serialising IPI; one still inside
    // `bp_resume` has not finished reading the two words above.
    BP_SITE.store(0, Ordering::SeqCst);
    while BP_REFS.load(Ordering::SeqCst) != 0 {
        core::hint::spin_loop();
    }
    match out {
        patch::BpOutcome::Done => Ok(()),
        patch::BpOutcome::Undone(e) | patch::BpOutcome::Stuck(e) => Err(e),
    }
}

/// The kernel `#BP` arm: `rip` is the address after the `int3`. Returns the
/// address to continue at if the breakpoint is the sequence of [`write_bp5`]
/// (the CPU then runs as if the new instruction were in place), `None` for
/// any other breakpoint.
pub fn bp_resume(rip: usize) -> Option<usize> {
    BP_REFS.fetch_add(1, Ordering::SeqCst);
    let site = BP_SITE.load(Ordering::SeqCst);
    let r = (site != 0 && rip == site + 1).then(|| BP_RESUME.load(Ordering::Relaxed));
    BP_REFS.fetch_sub(1, Ordering::SeqCst);
    r
}

/// The alias's TLB entries gone from every CPU, and every CPU's instruction
/// fetch synchronised with the text writes (module doc).
fn sync_all(alias: usize) {
    // riscv64: SBI `remote_sfence_vma` of the alias page to every hart (the
    // local `sfence.vma` too); aarch64: `TLBI VAAE1IS`, already broadcast.
    ARCH.flush_tlb_page_all(alias);
    // riscv64: local `fence rw, rw; fence.i`, then SBI remote fence.i;
    // aarch64: the broadcast I-cache invalidate.
    ARCH.icache_sync_all();
}

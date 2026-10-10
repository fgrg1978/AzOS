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

use crate::vmm;
use azos_arch::{ArchPlatform, ARCH};
use azos_arch_api::{Mmu, PagePerms, PAGE_SIZE};
use azos_sync::SpinLock;
use core::sync::atomic::{AtomicUsize, Ordering};

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
    /// A 2-byte-aligned instruction ([`write_insns_boot`]) that straddles a
    /// page: two alias mappings, with code running between the halves.
    CrossesPage,
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
/// halves through one alias mapping, low then high, and refused when it
/// straddles a page. Precondition: no other CPU runs the kernel text yet
/// (the boot CPU before `wake_secondaries`), and the caller is not itself
/// running the site; between the two halves only the store sequence runs.
pub fn write_insns_boot(words: &[(usize, u32)]) -> Result<usize, PokeError> {
    write_impl(words, true)
}

fn write_impl(words: &[(usize, u32)], halves: bool) -> Result<usize, PokeError> {
    let alias = alias().ok_or(PokeError::Unavailable)?;
    let (ts, te) = (TEXT_START.load(Ordering::Relaxed), TEXT_END.load(Ordering::Relaxed));
    let kpt = vmm::kernel_pagetable();
    let _g = LOCK.lock_irqsave();
    let mut done = 0;
    let mut res = Ok(());
    for &(va, w) in words {
        if va & if halves { 1 } else { 3 } != 0 || va < ts || va + 4 > te {
            res = Err(PokeError::OutOfText);
            break;
        }
        if va & 3 != 0 && (va & (PAGE_SIZE - 1)) > PAGE_SIZE - 4 {
            res = Err(PokeError::CrossesPage);
            break;
        }
        if let Err(e) = text_is_rx(va) {
            res = Err(e);
            break;
        }
        let Some(pa) = vmm::translate(kpt, va & !(PAGE_SIZE - 1)) else {
            res = Err(PokeError::NotLeaf);
            break;
        };
        if vmm::map(kpt, alias, pa & !(PAGE_SIZE - 1), PagePerms::KERNEL_RW).is_err() {
            res = Err(PokeError::Map);
            break;
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
            // SAFETY: `p` and `p + 1` are inside the alias page (the
            // straddling case is refused above), 2-aligned.
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
        if back != w {
            res = Err(PokeError::Readback);
            break;
        }
        done += 1;
    }
    sync_all(alias);
    res.map(|()| done)
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

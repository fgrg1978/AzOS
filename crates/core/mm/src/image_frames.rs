// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The frames of a verified image, kept for its next spawn (wave 14,
//! SPAWNCACHE).
//!
//! [`capture`] runs once, on the address space the loader has just built for
//! an image whose bytes were hashed and matched to a profile, before the task
//! that will own it runs a single instruction. It records every user page of
//! the image's range:
//!
//! * an **executable** page (never writable: W^X) is kept as it is: the
//!   record holds a reference on the frame (`cow_table`), so the frame
//!   outlives the task that loaded it;
//! * any other page (data, read-only data, the zero tail) is copied into a
//!   kernel-owned template frame.
//!
//! [`map_into`] builds the same pages in a new address space: the executable
//! frames are mapped again, read-execute, with one more reference each; every
//! other page gets a fresh frame filled from its template. A later spawn
//! therefore shares the text of the first and owns its data, and nothing it
//! maps is ever both shared and writable:
//!
//! * a shared frame is mapped with the permissions the loader gave it, which
//!   include EXEC and exclude WRITE;
//! * nothing adds WRITE to an executable leaf (`add_user_leaf_perms`,
//!   `protect_user_range`, `set_user_range_write` and `mprotect` all refuse
//!   it), and `handle_cow_fault` refuses an executable entry, so no task can
//!   turn its mapping of a shared frame into a writable one;
//! * every page is present when `map_into` returns: nothing is left to fault
//!   in, so a `mem = "locked"` row stays fully committed.
//!
//! [`release`] drops the records' references: a frame a running task still
//! maps survives until that task's teardown (`destroy_user_pagetable` and
//! every unmap path release leaves through `page_decref`), and was verified.
//!
//! The records live in one kernel frame: [`MAX_PAGES`] pages per image.

use azos_arch::ARCH;
use azos_arch_api::{Mmu, PagePerms, PAGE_SIZE};
use crate::addr::{phys_to_virt, PhysAddr};
use crate::{cow_table, pmm, vmm};

/// Pages one image may have to be kept (the records fill one frame).
pub const MAX_PAGES: usize = PAGE_SIZE / 16;

/// Record flag: the frame is shared (executable), mapped as is.
const SHARED: u64 = 1 << 11;
const R: u64 = 1 << 0;
const W: u64 = 1 << 1;
const X: u64 = 1 << 2;
const U: u64 = 1 << 3;
const C: u64 = 1 << 4;
const A: u64 = 1 << 5;
const D: u64 = 1 << 6;

fn encode(p: PagePerms) -> u64 {
    (p.read as u64) * R | (p.write as u64) * W | (p.exec as u64) * X | (p.user as u64) * U
        | (p.cache as u64) * C | (p.accessed as u64) * A | (p.dirty as u64) * D
}

fn decode(f: u64) -> PagePerms {
    PagePerms {
        read: f & R != 0, write: f & W != 0, exec: f & X != 0, user: f & U != 0,
        cache: f & C != 0, accessed: f & A != 0, dirty: f & D != 0,
    }
}

/// What a load of the image produced that its frames cannot tell again:
/// the entry point, the initial break and the five values of a Linux
/// auxiliary vector (`azos_linux_abi::ImageAux`: phdr, phent, phnum, entry,
/// pagesz), kept beside the frames by the cache.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeptImage {
    pub entry: u64,
    pub brk: u64,
    pub aux: [u64; 5],
}

/// A kept image: its record frame and how many pages it records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImagePages {
    meta: usize,
    n: u16,
    shared: u16,
}

impl ImagePages {
    /// Pages the image maps (what a task that maps it is charged).
    pub fn pages(&self) -> u32 { self.n as u32 }
    /// Of those, frames shared with every task that maps the image.
    pub fn shared(&self) -> u32 { self.shared as u32 }
    /// Frames these records keep allocated: the record frame, the templates
    /// and the shared frames (each of which a running task may also hold).
    pub fn frames_held(&self) -> u32 { 1 + self.n as u32 }

    fn records(&self) -> &[[u64; 2]] {
        // SAFETY: `meta` is a frame `capture` allocated and filled with `n`
        // records, reached through the kernel's mapping of RAM, and freed only
        // by `release`, which consumes the value.
        unsafe { core::slice::from_raw_parts(phys_to_virt(self.meta) as *const [u64; 2], self.n as usize) }
    }
}

/// The level-0 user leaf at `va`, if one is mapped.
fn user_leaf(user_pt: usize, va: usize) -> Option<u64> {
    let ptr = vmm::walk(user_pt, va, false).ok()?;
    // SAFETY: `walk` returned an aligned entry of a live table page.
    let pte = unsafe { core::ptr::read_volatile(ptr) };
    if !ARCH.pte_is_valid(pte) || !ARCH.pte_is_leaf(pte, 0) { return None; }
    Some(pte)
}

/// Keep the pages `[lo, hi)` of `user_pt`, an address space the loader has
/// just built and no task has run in. `None`, with nothing kept, when a page
/// is not an ordinary user frame, the image has more than [`MAX_PAGES`]
/// pages, the records would hold more than `max_frames` frames, or memory
/// runs out.
pub fn capture(user_pt: usize, lo: usize, hi: usize, max_frames: u32) -> Option<ImagePages> {
    if lo & (PAGE_SIZE - 1) != 0 || hi <= lo { return None; }
    let pages = (hi - lo) / PAGE_SIZE;
    if pages > MAX_PAGES || (pages as u32).saturating_add(1) > max_frames { return None; }
    let meta = pmm::alloc_page().ok()?.as_usize();
    let mut kept = ImagePages { meta, n: 0, shared: 0 };
    let recs = phys_to_virt(meta) as *mut [u64; 2];
    let mut va = lo;
    while va < hi {
        let Some(pte) = user_leaf(user_pt, va) else { va += PAGE_SIZE; continue };
        let perms = ARCH.pte_perms(pte);
        let phys = ARCH.pte_phys(pte);
        if !perms.user || ARCH.pte_is_cow(pte) || pmm::frame_index(phys).is_none() {
            release(kept);
            return None;
        }
        // Gate canary `image-share-all-canary`: data pages are shared too.
        let share = cfg!(feature = "image-share-all-canary") || (perms.exec && !perms.write);
        let rec = if share {
            if cow_table::page_addref(phys).is_err() { release(kept); return None; }
            kept.shared += 1;
            [va as u64 | encode(perms) | SHARED, phys as u64]
        } else {
            // SAFETY: every byte is written by the copy right below, before
            // the frame is recorded.
            let Ok(t) = (unsafe { pmm::alloc_page_uninit() }) else { release(kept); return None };
            let t = t.as_usize();
            // SAFETY: both are whole frames reached through the kernel's map.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    phys_to_virt(phys) as *const u8, phys_to_virt(t) as *mut u8, PAGE_SIZE,
                );
            }
            [va as u64 | encode(perms), t as u64]
        };
        // SAFETY: `kept.n < pages <= MAX_PAGES` records fit in the frame.
        unsafe { recs.add(kept.n as usize).write(rec) };
        kept.n += 1;
        va += PAGE_SIZE;
    }
    if kept.n == 0 { release(kept); return None; }
    Some(kept)
}

/// Map the kept image into `user_pt` (a fresh address space with nothing in
/// the image's range). `Some(pages)` when every page is mapped. On `None`
/// what was mapped stays in `user_pt` and the caller's teardown of it
/// (`destroy_user_pagetable`) releases it.
pub fn map_into(p: &ImagePages, user_pt: usize) -> Option<u32> {
    for &[w, phys] in p.records() {
        let va = (w & !(PAGE_SIZE as u64 - 1)) as usize;
        let perms = decode(w);
        let phys = phys as usize;
        if w & SHARED != 0 {
            cow_table::page_addref(phys).ok()?;
            if vmm::map(user_pt, va, phys, perms).is_err() {
                // The records still hold the frame: never the last decref.
                let _ = cow_table::page_decref(phys);
                return None;
            }
        } else {
            // SAFETY: overwritten whole by the copy below before it is mapped.
            let page = unsafe { pmm::alloc_page_uninit() }.ok()?;
            // SAFETY: two whole frames reached through the kernel's map.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    phys_to_virt(phys) as *const u8, phys_to_virt(page.as_usize()) as *mut u8, PAGE_SIZE,
                );
            }
            if vmm::map(user_pt, va, page.as_usize(), perms).is_err() {
                let _ = pmm::free_page(page);
                return None;
            }
        }
    }
    Some(p.n as u32)
}

/// Drop the records: each shared frame loses this reference (freed when no
/// task maps it any more), each template and the record frame are freed.
pub fn release(p: ImagePages) {
    for &[w, phys] in p.records() {
        let phys = phys as usize;
        if w & SHARED == 0 || cow_table::page_decref(phys) {
            let _ = pmm::free_page(PhysAddr::new(phys));
        }
    }
    let _ = pmm::free_page(PhysAddr::new(p.meta));
}

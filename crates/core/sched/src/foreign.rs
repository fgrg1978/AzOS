// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel half of the foreign-ABI family (`azos_abi::foreign`): per-thread
//! entry registration, trap reflect, resume, and the placement of the ring-3
//! runtime into the address space of a hosted process.
//!
//! The kernel knows nothing about the ABI it hosts. A thread that registered
//! an entry is in one of two modes (`scheduler::set_current_foreign_mode`):
//! in *runtime* mode its traps are native calls; in *foreign* mode the next
//! trap is reflected. Reflect and resume both finish at the thread's return
//! to user mode, where the architecture's trap return hook (the one the
//! Linux signal work already uses) turns the pending request into register
//! writes on the trap frame. Pending work is counted in
//! `scheduler::signal::WORK`, so a thread with none pays the one load that
//! hook already costs.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use azos_abi::foreign::{frame_base, ForeignFrame, FLAGS_USER_MASK, REG_RESULT, REG_SP};
use azos_arch::PAGE_SIZE;
use azos_arch_api::PagePerms;
use azos_mm::{pmm, vmm};

use crate::scheduler::{current_slot, signal::WORK};
use crate::task::MAX_TASKS;
use azos_abi::error::Errno;

/// The runtime's trap entry per slot (0: none registered).
static ENTRY: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];
/// Slots with an entry registered, machine-wide: the trap path asks this one
/// load before it looks at its own slot, so a Linux task of the in-kernel
/// personality (and a kernel in which nothing has registered) pays one load.
static LIVE: AtomicU32 = AtomicU32::new(0);
/// What waits for the slot's return to user mode ([`PEND_NONE`] ...).
static PEND: [AtomicU8; MAX_TASKS] = [const { AtomicU8::new(PEND_NONE) }; MAX_TASKS];
/// Reflect: the foreign call's number. Resume: the frame's address.
static PEND_A: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];
/// Reflect: the value the first argument register held at the trap (the
/// trap path overwrites it with the call's result).
static PEND_B: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];

const PEND_NONE: u8 = 0;
const PEND_REFLECT: u8 = 1;
const PEND_RESUME: u8 = 2;

/// What [`take_pending`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pending {
    /// A trap taken in foreign mode: its call number and the first
    /// argument register's value.
    Reflect { num: u64, arg0: u64 },
    /// A `SYS_FOREIGN_RESUME`: the user address of the frame to restore.
    Resume { frame: u64 },
}

/// Set slot `idx`'s entry, keeping [`LIVE`] the count of non-zero ones.
fn set_entry(idx: usize, new: u64) {
    let old = ENTRY[idx].swap(new, Ordering::Relaxed);
    match (old == 0, new == 0) {
        (true, false) => {
            LIVE.fetch_add(1, Ordering::Relaxed);
        }
        (false, true) => {
            LIVE.fetch_sub(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

/// Has any thread registered an entry? One relaxed load: what the trap path
/// of a task in foreign mode asks before [`request_reflect`].
#[inline(always)]
pub fn any_registered() -> bool {
    LIVE.load(Ordering::Relaxed) != 0
}

/// A new occupant of slot `idx` has registered nothing and has nothing
/// pending. Called where the slot's syscall word is published.
pub(crate) fn clear_slot(idx: usize) {
    set_entry(idx, 0);
    if PEND[idx].swap(PEND_NONE, Ordering::AcqRel) != PEND_NONE {
        WORK.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The entry the current thread registered; 0 if none.
#[inline]
pub fn current_entry() -> u64 {
    match current_slot() {
        Some(idx) => ENTRY[idx].load(Ordering::Relaxed),
        None => 0,
    }
}

/// `SYS_FOREIGN_ENTRY`: register (`entry != 0`) or withdraw the current
/// thread's trap entry. The thread is in runtime mode while it makes the
/// call, and stays in it.
pub fn register(entry: u64) -> i64 {
    let Some(idx) = current_slot() else { return Errno::EINVAL.to_syscall_ret() };
    if entry >= user_va_top() as u64 {
        return Errno::EINVAL.to_syscall_ret();
    }
    set_entry(idx, entry);
    0
}

/// The ceiling of the user address space: no entry or resumed program
/// counter may name an address at or above it.
fn user_va_top() -> usize {
    crate::process::USER_STACK_TOP
}

/// The current thread creates thread `child` (fork, fork-COW, thread
/// create): the child has its creator's entry. It starts in runtime mode,
/// as every hosted task does (its syscall word is published from its `abi`
/// at creation), and returns from the creating call into the runtime.
/// Before the child is runnable.
pub(crate) fn inherit_from_current(child: usize) {
    if child >= MAX_TASKS {
        return;
    }
    if let Some(parent) = current_slot() {
        set_entry(child, ENTRY[parent].load(Ordering::Relaxed));
    }
}

/// The current thread replaced its image: the registration belongs to the
/// old one. The thread is in runtime mode (it made the call).
pub fn on_exec() {
    if let Some(idx) = current_slot() {
        set_entry(idx, 0);
    }
}

fn set_pending(idx: usize, kind: u8, a: u64, b: u64) {
    PEND_A[idx].store(a, Ordering::Relaxed);
    PEND_B[idx].store(b, Ordering::Relaxed);
    if PEND[idx].swap(kind, Ordering::AcqRel) == PEND_NONE {
        WORK.fetch_add(1, Ordering::AcqRel);
    }
}

/// A trap in foreign mode: reflect it at the return to user mode. `num` is
/// the call number the thread put in the number register, `arg0` its first
/// argument register. `false` when the thread has no entry (the caller then
/// treats the trap as it always did).
pub fn request_reflect(num: u64, arg0: u64) -> bool {
    let Some(idx) = current_slot() else { return false };
    if ENTRY[idx].load(Ordering::Relaxed) == 0 {
        return false;
    }
    set_pending(idx, PEND_REFLECT, num, arg0);
    true
}

/// `SYS_FOREIGN_RESUME(frame)`: restore the frame at the return to user
/// mode. `0` is returned to the trap path, which the restore overwrites.
pub fn request_resume(frame: u64) -> i64 {
    let Some(idx) = current_slot() else { return Errno::EINVAL.to_syscall_ret() };
    if ENTRY[idx].load(Ordering::Relaxed) == 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    // The frame is read once, at the return to user mode. An unreadable one
    // ends the thread there, as a fault in the runtime would: the runtime owns
    // the memory, and a frame it cannot read is a bug in it, not a result.
    if frame == 0 || frame & 7 != 0 {
        return Errno::EFAULT.to_syscall_ret();
    }
    set_pending(idx, PEND_RESUME, frame, 0);
    0
}

/// Take the current thread's pending reflect or resume, if any.
pub fn take_pending() -> Option<Pending> {
    let idx = current_slot()?;
    let kind = PEND[idx].swap(PEND_NONE, Ordering::AcqRel);
    if kind == PEND_NONE {
        return None;
    }
    WORK.fetch_sub(1, Ordering::AcqRel);
    let a = PEND_A[idx].load(Ordering::Relaxed);
    let b = PEND_B[idx].load(Ordering::Relaxed);
    match kind {
        PEND_REFLECT => Some(Pending::Reflect { num: a, arg0: b }),
        _ => Some(Pending::Resume { frame: a }),
    }
}

/// Read the frame at user address `ptr`.
pub fn read_frame(ptr: u64) -> Option<ForeignFrame> {
    if ptr == 0 || ptr & 7 != 0 {
        return None;
    }
    crate::UserPtr::<ForeignFrame>::new(ptr).read().ok()
}

/// Reflect the current thread's trap: push `frame` below `frame.gpr[REG_SP]`
/// (and the ABI's red zone), enter runtime mode. The address the frame went
/// to and the entry to jump to; `None` if the stack cannot take the frame
/// (the caller ends the thread as a fault would).
pub fn reflect(frame: &ForeignFrame) -> Option<(u64, u64)> {
    let idx = current_slot()?;
    let entry = ENTRY[idx].load(Ordering::Relaxed);
    if entry == 0 {
        return None;
    }
    let base = frame_base(frame.gpr[REG_SP])?;
    crate::UserPtr::<ForeignFrame>::new(base).write(frame).ok()?;
    crate::scheduler::set_current_foreign_mode(false);
    Some((entry, base))
}

/// Resume the current thread into `frame`: foreign mode. Returns the frame
/// with its flags reduced to the bits a frame may set, or `None` for a
/// program counter outside user space.
pub fn resume(mut frame: ForeignFrame) -> Option<ForeignFrame> {
    if frame.pc >= user_va_top() as u64 {
        return None;
    }
    frame.flags &= FLAGS_USER_MASK;
    // Gate canary only (`foreign-regs-canary`): the frame's other registers
    // are not restored. A program that keeps a value in a register across a
    // trap (abitest's foreign probe) loses it.
    if cfg!(feature = "foreign-regs-canary") {
        let (sp, result) = (frame.gpr[REG_SP], frame.gpr[REG_RESULT]);
        frame.gpr = [0; 32];
        frame.gpr[REG_SP] = sp;
        frame.gpr[REG_RESULT] = result;
    }
    crate::scheduler::set_current_foreign_mode(true);
    Some(frame)
}

// ── The runtime image ───────────────────────────────────────────────────────

/// The runtime's ELF (the ring-3 half of a hosted ABI), embedded in the
/// kernel image by the boot code and so covered by the image's signature.
static RUNTIME_IMAGE: core::sync::atomic::AtomicPtr<u8> = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
static RUNTIME_LEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Install the runtime image. Called once at boot, by the code that embeds it.
pub fn set_runtime_image(image: &'static [u8]) {
    RUNTIME_LEN.store(image.len(), Ordering::Release);
    RUNTIME_IMAGE.store(image.as_ptr() as *mut u8, Ordering::Release);
}

fn runtime_image() -> Option<&'static [u8]> {
    let p = RUNTIME_IMAGE.load(Ordering::Acquire);
    if p.is_null() {
        return None;
    }
    // SAFETY: set from a `&'static [u8]` by `set_runtime_image`.
    Some(unsafe { core::slice::from_raw_parts(p, RUNTIME_LEN.load(Ordering::Acquire)) })
}

pub use azos_abi::foreign::{RUNTIME_BASE, RUNTIME_LIMIT};

/// What [`attach_runtime`] mapped.
#[derive(Clone, Copy, Debug)]
pub struct Attached {
    /// The runtime's entry point.
    pub entry: u64,
    /// Data frames it took (counted against the row's budget).
    pub frames: u32,
}

#[cfg(target_arch = "riscv64")]
const EXPECTED_MACHINE: u16 = 0xf3;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const EXPECTED_MACHINE: u16 = 0xb7;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const EXPECTED_MACHINE: u16 = 0x3e;
#[cfg(not(any(target_arch = "riscv64", all(any(target_arch = "aarch64", target_arch = "x86_64"), target_os = "none"))))]
const EXPECTED_MACHINE: u16 = 0xf3;

fn rd16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn rd32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn rd64(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

/// Map the runtime into the address space `user_pt`, which no task runs on
/// yet. Each `PT_LOAD` segment is mapped with exactly the permissions it
/// declares (read-write is never executable; an executable segment is never
/// writable), inside [`RUNTIME_BASE`]..[`RUNTIME_LIMIT`], on pages of their
/// own, in ascending order. The caller destroys `user_pt` when this fails.
pub fn attach_runtime(user_pt: usize) -> Option<Attached> {
    let img = runtime_image()?;
    if img.get(0..4)? != b"\x7fELF" || *img.get(4)? != 2 || *img.get(5)? != 1 {
        return None;
    }
    if rd16(img, 18)? != EXPECTED_MACHINE {
        return None;
    }
    let e_entry = rd64(img, 24)?;
    let e_phoff = rd64(img, 32)? as usize;
    let e_phentsize = rd16(img, 54)? as usize;
    let e_phnum = rd16(img, 56)? as usize;
    if e_phentsize < 56 || e_phnum == 0 {
        return None;
    }
    let mut frames = 0u32;
    let mut prev_end = RUNTIME_BASE;
    if RUNTIME_BASE & (PAGE_SIZE - 1) != 0 {
        return None;
    }
    let mut entry_ok = false;
    for i in 0..e_phnum {
        let ph = e_phoff.checked_add(i.checked_mul(e_phentsize)?)?;
        if rd32(img, ph)? != 1 {
            continue; // not PT_LOAD
        }
        let flags = rd32(img, ph + 4)?;
        let off = rd64(img, ph + 8)? as usize;
        let va = rd64(img, ph + 16)? as usize;
        let filesz = rd64(img, ph + 32)? as usize;
        let memsz = rd64(img, ph + 40)? as usize;
        if memsz == 0 {
            continue;
        }
        let end = va.checked_add(memsz)?;
        let end_page = end.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
        let first_page = va & !(PAGE_SIZE - 1);
        // A segment may start inside its first page (the linker keeps file
        // offset and address congruent) but never shares a page with another:
        // every page gets exactly one segment's permissions.
        if first_page < prev_end || end_page > RUNTIME_LIMIT || filesz > memsz {
            return None;
        }
        if off.checked_add(filesz)? > img.len() {
            return None;
        }
        let (w, x) = (flags & 2 != 0, flags & 1 != 0);
        if w && x {
            return None;
        }
        let perms = if w {
            PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW }
        } else if x {
            PagePerms { accessed: true, ..PagePerms::USER_RX }
        } else {
            PagePerms { accessed: true, ..PagePerms::USER_RO }
        };
        if x && e_entry as usize >= va && (e_entry as usize) < va + filesz {
            entry_ok = true;
        }
        let mut page = first_page;
        while page < end_page {
            let frame = pmm::alloc_page().ok()?;
            frames += 1;
            let pa = frame.as_usize();
            if vmm::map(user_pt, page, pa, perms).is_err() {
                let _ = pmm::free_page(frame);
                return None;
            }
            // The part of this page the segment's file bytes cover.
            let lo = page.max(va);
            let hi = (page + PAGE_SIZE).min(va + filesz);
            if lo < hi {
                // SAFETY: the page just allocated, reached through the
                // kernel's map; the source range was bounds-checked above.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        img.as_ptr().add(off + (lo - va)),
                        (azos_mm::addr::phys_to_virt(pa) + (lo - page)) as *mut u8,
                        hi - lo,
                    );
                }
            }
            page += PAGE_SIZE;
        }
        prev_end = end_page;
        if x {
            crate::process::sync_image_text(user_pt, first_page, end_page);
        }
    }
    if !entry_ok || e_entry & 1 != 0 {
        return None;
    }
    Some(Attached { entry: e_entry, frames })
}

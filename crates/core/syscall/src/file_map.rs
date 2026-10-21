// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Mapping a file into an address space (storage L11, part B): `NODE_MMAP`, the
//! first user of the page cache.
//!
//! A file `Cap<File>` is mapped through the cache object of the part of the
//! file it names, a `MemKind::Paged` MemObj (`azos_ipc::memobj`), and a fault
//! in the mapping is resolved from that object by the file pager
//! (`azos_mm::pager::resolve_file_fault`). This file is the half that knows
//! the object table, the file layer's seam and the task's address space:
//!
//! * **One object per window of a file.** An object holds at most
//!   [`MAX_MEMOBJ_PAGES`] pages, so a file is cached in aligned windows of that
//!   many pages, and a mapping is cut into one *piece* per window it touches.
//!   The registry ([`Entry`]) names the object of each (file, window): the file
//!   is the filesystem's own `InodeKey` under that filesystem's backing, the
//!   same on every open of it, so every mapper of the same file reaches the
//!   same object, and so the same frames.
//! * **`MAP_SHARED`** maps the cache's frames themselves (no second copy: a
//!   store by one mapper is seen by the others at once) into the task's shm/MMIO
//!   window, where the exit path and `munmap` never free a frame. The task
//!   books the mapping in the object (`memobj_note_mapping_ref`: from then on
//!   the cache can drop a page out of this address space, and a writable
//!   mapping makes the page dirty), and the pages go back to the file when the
//!   mapping is unmapped (`munmap`) or the file is synced (`NODE_FSYNC`, the
//!   `msync` of this tree: a file's mapped pages are part of its sync).
//!   A mapping reserves the window addresses from the start of the object's
//!   first page, so the booked address is the address of object page 0, as the
//!   object's mapping list needs; the pages before the piece are addresses and
//!   nothing else.
//! * **`MAP_PRIVATE`** is a region of the task's own, placed like an anonymous
//!   `mmap` and charged like one; each page it touches is a copy of the cache
//!   page taken at the first touch, so stores never reach the cache or the
//!   file. It books nothing in the object: its hold on the cache is the
//!   registry's count of regions.
//!
//! **The count of regions.** An entry stays while a region (of any task) uses
//! its object ([`FileFrames::addref`] / [`FileFrames::unref`], called by the
//! pager as regions are made, copied by a fork and removed). An entry nobody
//! uses is a cache: it stays, clean or dirty, until a call finds no room for
//! another window and reaps the unused ones (writes back what is dirty, then
//! closes the object). It cannot outlive the file it caches: the file layer
//! forgets the pages of a file that is unlinked, cut or replaced
//! ([`cache_forget`]).
//!
//! **A task that dies mapped** has its shared mappings written back by the exit
//! hook ([`exit_writeback`]) before its references go; its regions are then
//! forgotten with the address space and the entries nobody uses wait, clean, to
//! be used again or reaped.
//!
//! **The file layer's `read` and `write`** of a backend that takes the cache go
//! through these same objects ([`cache_read`] and the functions after it, the
//! kernel's `PageCacheHooks`), so a `write` is seen by the mapping and the
//! other way round, and the `fs-wb` flusher writes the pages back by age.
//! **Not here**: a page stored through a live mapping reaches the file at the
//! next `munmap`, sync or exit of the mapper, or at the flusher's pass over
//! the file; a window is mapped once per task; a mapping made of a file that
//! grew since its window was cached sees the size the file layer last attached
//! it at.

use azos_abi::cap::CapPerms;
use azos_abi::error::Errno;
use azos_common::error::{KResult, KernelError};
use azos_ipc::memobj::{
    self, MapAccess, MemObjError, MemPerms, PagedError, MAX_MEMOBJS, MAX_MEMOBJ_PAGES,
};
use azos_mm::addr::PhysAddr;
use azos_mm::pager::{self, FileFrames, FileRegion, PageBacking, PageKey, PAGE_KEY_LEN};
use azos_sync::SpinLock;

use crate::file_ops::{file_ops, FileMapSource};
use crate::handlers::{MMAP_PROT_READ, MMAP_PROT_WRITE};

/// `flags` of [`sys_file_mmap`]: the same values as Linux's `MAP_SHARED` and
/// `MAP_PRIVATE`, so the personality passes them through.
pub const MAP_SHARED: u64 = 1;
pub const MAP_PRIVATE: u64 = 2;

/// Pages of a cache object: the window of a file one object holds.
const WINDOW: usize = MAX_MEMOBJ_PAGES;

/// Pieces (windows) one call maps.
pub const MAX_PIECES: usize = 8;

/// File regions one `munmap` takes out at once (two full mappings): a range
/// holding more is refused, the caller unmaps them one by one. The list lives on
/// the kernel stack.
pub const MUNMAP_FILES: usize = 2 * MAX_PIECES;

// ── The registry: which object caches which window of which file ─────────────

/// One cached window of a file.
#[derive(Clone, Copy)]
struct Entry {
    used: bool,
    /// Being closed (written back and freed) outside the lock: not found.
    closing: bool,
    /// The filesystem's backing, by address.
    backing: usize,
    key: PageKey,
    /// The window: file pages `window * WINDOW ..`.
    window: u64,
    /// The packed reference of the cache object.
    obj: u32,
    /// Regions over the object, plus calls that are making one.
    users: u32,
    /// The file changed (or is gone) under the pages at or after this byte
    /// and a forget of them was refused ([`NOT_STALE`]: it was not). The
    /// object is neither served nor written back until the forget has gone
    /// through: see [`settle_stale`].
    stale_from: u64,
}

/// [`Entry::stale_from`] of an entry whose pages are all current.
const NOT_STALE: u64 = u64::MAX;

const NO_ENTRY: Entry = Entry {
    used: false,
    closing: false,
    backing: 0,
    key: PageKey([0; PAGE_KEY_LEN]),
    window: 0,
    obj: 0,
    users: 0,
    stale_from: NOT_STALE,
};

/// One slot per MemObj: the registry cannot hold more objects than exist.
static REG: SpinLock<[Entry; MAX_MEMOBJS]> = SpinLock::new([NO_ENTRY; MAX_MEMOBJS]);

fn backing_id(b: &'static dyn PageBacking) -> usize {
    b as *const dyn PageBacking as *const () as usize
}

fn entry_matches(e: &Entry, backing: usize, key: &PageKey, window: u64) -> bool {
    e.used && !e.closing && e.backing == backing && e.window == window && e.key == *key
}

/// The object of `window` of the file `src` names, made if it is not there; one
/// use of it is taken (the caller gives it back with [`FileFrames::unref`] once
/// its own region holds the object).
fn object_of(src: &FileMapSource, window: u64) -> Result<u32, i64> {
    let obj = object_for(src.backing, &src.key, src.size, window, MAX_MEMOBJS).or_else(|_| {
        // No room: the windows nobody uses give theirs back.
        reap_orphans();
        object_for(src.backing, &src.key, src.size, window, MAX_MEMOBJS)
    })?;
    // Pages the file changed under are not mapped: `EAGAIN`, the caller maps again.
    if !settle_stale(obj, false) {
        CACHE.unref(obj);
        return Err(Errno::EAGAIN.to_syscall_ret());
    }
    Ok(obj)
}

/// [`object_of`] by name: the file is `key` under `backing`, `size` bytes long
/// when the object is made, and the registry holds `limit` objects at most (a
/// window that is not there is refused with `ENOMEM` past it).
fn object_for(
    backing: &'static dyn PageBacking,
    key: &PageKey,
    size: u64,
    window: u64,
    limit: usize,
) -> Result<u32, i64> {
    let id = backing_id(backing);
    {
        let mut reg = REG.lock_irqsave();
        if let Some(e) = reg.iter_mut().find(|e| entry_matches(e, id, key, window)) {
            e.users += 1;
            return Ok(e.obj);
        }
        if reg.iter().filter(|e| e.used).count() >= limit {
            return Err(Errno::ENOMEM.to_syscall_ret());
        }
    }
    // Made outside the lock: a MemObj is a table slot and a lock of its own.
    let first = window * WINDOW as u64;
    let made = memobj::memobj_create_paged(backing, *key, first, WINDOW, size, MemPerms::ReadWrite)
        .map_err(|_| Errno::ENOMEM.to_syscall_ret())?;
    let mut reg = REG.lock_irqsave();
    // Another task may have made the same window meanwhile: its object stays
    // the one cache (two would hold two copies of a page), ours goes.
    if let Some(e) = reg.iter_mut().find(|e| entry_matches(e, id, key, window)) {
        e.users += 1;
        let obj = e.obj;
        drop(reg);
        let _ = memobj::memobj_paged_close_ref(made);
        return Ok(obj);
    }
    let room = reg.iter().filter(|e| e.used).count() < limit;
    match reg.iter_mut().find(|e| !e.used).filter(|_| room) {
        Some(e) => {
            *e = Entry { used: true, closing: false, backing: id, key: *key, window, obj: made, users: 1, stale_from: NOT_STALE };
            Ok(made)
        }
        None => {
            drop(reg);
            let _ = memobj::memobj_paged_close_ref(made);
            Err(Errno::ENOMEM.to_syscall_ret())
        }
    }
}

/// Write back and close every entry nobody uses: the room a window that has no
/// object needs. An object a task still holds (it is exiting and has not given
/// its references back yet) stays for a later pass.
fn reap_orphans() {
    for i in 0..MAX_MEMOBJS {
        close_idle(i);
    }
}

/// Write back and close the entry in slot `i` if nobody uses it.
fn close_idle(i: usize) {
    // Closing writes the dirty pages back: not the ones the file changed under.
    let stale = {
        let reg = REG.lock_irqsave();
        (reg[i].used && reg[i].stale_from != NOT_STALE && reg[i].users == 0).then_some(reg[i].obj)
    };
    if stale.is_some_and(|obj| !settle_stale(obj, false)) {
        return;
    }
    let obj = {
        let mut reg = REG.lock_irqsave();
        let e = &mut reg[i];
        if !e.used || e.closing || e.users != 0 {
            return;
        }
        e.closing = true;
        e.obj
    };
    let closed = memobj::memobj_paged_close_ref(obj).is_ok();
    let mut reg = REG.lock_irqsave();
    if closed {
        reg[i] = NO_ENTRY;
    } else {
        reg[i].closing = false;
    }
}

/// Note that a forget from byte `from` of the object was refused: it is not
/// served, mapped or written back until [`settle_stale`] has done it.
fn mark_stale(obj: u32, from: u64) {
    let mut reg = REG.lock_irqsave();
    if let Some(e) = reg.iter_mut().find(|e| e.used && e.obj == obj) {
        e.stale_from = e.stale_from.min(from);
    }
}

/// Carry out the forget an earlier refusal left ([`mark_stale`]). `true`: no
/// stale page remains and the object may be served and written back. `false`:
/// it is still refused (a page being written back, a pinned holder) and the
/// object must stay untouched; `wait` is whether to retry for a while (tasks)
/// or to try once (`munmap` and exit, which do not sleep).
fn settle_stale(obj: u32, wait: bool) -> bool {
    let from = {
        let reg = REG.lock_irqsave();
        reg.iter().find(|e| e.used && e.obj == obj).map_or(NOT_STALE, |e| e.stale_from)
    };
    if from == NOT_STALE {
        return true;
    }
    let r = if wait {
        retry_busy(|| memobj::memobj_paged_forget_ref(obj, from))
    } else {
        memobj::memobj_paged_forget_ref(obj, from)
    };
    if matches!(r, Err(PagedError::Obj(MemObjError::Busy))) {
        return false;
    }
    // Done, or the object is gone (nothing left of it to serve). A lower mark
    // set meanwhile is a later forget's and stays.
    let mut reg = REG.lock_irqsave();
    if let Some(e) = reg.iter_mut().find(|e| e.used && e.obj == obj && e.stale_from >= from) {
        e.stale_from = NOT_STALE;
    }
    true
}

/// Write the dirty pages of the object back, unless the file changed under
/// them and the forget that drops them has not gone through yet: those bytes
/// must not reach whatever has the file's name now. A refusal is not an error
/// of the write (the pages are the forget's), so it is `Ok`.
fn writeback_current(obj: u32, wait: bool) -> Result<usize, PagedError> {
    if !settle_stale(obj, wait) {
        return Ok(0);
    }
    memobj::memobj_paged_writeback_ref(obj)
}

// ── The page cache, as the file pager sees it ────────────────────────────────

struct Cache;

static CACHE: Cache = Cache;

fn kernel_err(e: PagedError) -> KernelError {
    match e {
        PagedError::Io(_) => KernelError::IoError,
        PagedError::Obj(MemObjError::NoMem | MemObjError::Busy) => KernelError::OutOfMemory,
        PagedError::Obj(_) => KernelError::NotMapped,
    }
}

impl FileFrames for Cache {
    fn frame(&self, obj: u32, page: usize, write: bool) -> KResult<PhysAddr> {
        memobj::memobj_paged_frame_ref(obj, page, write).map(PhysAddr::new).map_err(kernel_err)
    }

    fn resident(&self, obj: u32, page: usize) -> Option<PhysAddr> {
        memobj::memobj_page_phys_ref(obj, page).ok().flatten().map(PhysAddr::new)
    }

    fn read(&self, obj: u32, page: usize, dst: &mut [u8]) -> KResult<usize> {
        memobj::memobj_paged_read_ref(obj, page * azos_arch::PAGE_SIZE, dst).map_err(kernel_err)
    }

    fn addref(&self, obj: u32) {
        if let Some(e) = REG.lock_irqsave().iter_mut().find(|e| e.used && e.obj == obj) {
            e.users = e.users.saturating_add(1);
        }
    }

    fn unref(&self, obj: u32) {
        if let Some(e) = REG.lock_irqsave().iter_mut().find(|e| e.used && e.obj == obj) {
            e.users = e.users.saturating_sub(1);
        }
    }
}

// ── NODE_MMAP ────────────────────────────────────────────────────────────────

/// One piece of a mapping that is made.
#[derive(Clone, Copy)]
struct Piece {
    obj: u32,
    /// Address of object page 0 (the start of what a shared piece reserved).
    base: usize,
    /// Pages from `base` to the end of the piece.
    span: usize,
}

/// Give back what a shared piece took: its booking in the object, its
/// reference and its window addresses. The PTEs are the caller's (the sweep,
/// or nothing made them yet).
fn drop_shared(tid: u32, obj: u32, base: usize, span: usize) {
    let _ = memobj::memobj_take_mapping_ref(tid, obj);
    let _ = memobj::memobj_release_ref(tid, obj);
    let _ = azos_sched::process::release_user_window(base, span);
}

/// `NODE_MMAP`: map `len` bytes of the file the handle names, from byte `off`
/// (a multiple of the page), with `prot` (`PROT_READ`, `PROT_WRITE`; never
/// `PROT_EXEC`) and `flags` (exactly one of [`MAP_SHARED`], [`MAP_PRIVATE`]).
/// Returns the address.
///
/// `READ` on the handle maps it; a shared writable mapping needs `WRITE` too,
/// and a file opened for writing on a backend that takes the write-back.
/// `-ENODEV` for a file the cache cannot serve (a ramfs file, a backend that
/// does not stream), `-EINVAL` for bad arguments or an `off` past the end,
/// `-EBUSY` when the task already maps a window the call needs (shared),
/// `-ENOMEM` when no object, address or record is left.
pub fn sys_file_mmap(cap_raw: u64, len: u64, off: u64, prot: u64, flags: u64) -> i64 {
    let page = azos_arch::PAGE_SIZE;
    let einval = Errno::EINVAL.to_syscall_ret();
    let enomem = Errno::ENOMEM.to_syscall_ret();
    let shared = match flags {
        MAP_SHARED => true,
        MAP_PRIVATE => false,
        _ => return einval,
    };
    // Never executable (W^X), and a `PROT_NONE` file mapping is not one.
    if prot & !(MMAP_PROT_READ | MMAP_PROT_WRITE) != 0 || prot & (MMAP_PROT_READ | MMAP_PROT_WRITE) == 0 {
        return einval;
    }
    let write = prot & MMAP_PROT_WRITE != 0;
    if len == 0 || off as usize & (page - 1) != 0 {
        return einval;
    }
    let (Some(pages), Some(first_page)) = (
        (len as usize).checked_add(page - 1).map(|n| n / page),
        usize::try_from(off).ok().map(|o| o / page),
    ) else {
        return einval;
    };
    let in0 = first_page % WINDOW;
    let npieces = (in0 + pages).div_ceil(WINDOW);
    if npieces > MAX_PIECES {
        return enomem;
    }
    let root = azos_sched::current_user_pt();
    if root == 0 {
        return einval;
    }
    let _mm = azos_sched::group::mm_lock();
    let need = if shared && write { CapPerms::READ.union(CapPerms::WRITE) } else { CapPerms::READ };
    let fd = match crate::handlers::file_fd_for(cap_raw, need, azos_abi::invoke::NODE_MMAP) {
        Ok(fd) => fd as i32,
        Err(e) => return e,
    };
    let Some(src) = file_ops().and_then(|o| o.map_source(fd)) else {
        return Errno::ENODEV.to_syscall_ret();
    };
    if shared && write {
        if !src.writable {
            return Errno::EACCES.to_syscall_ret();
        }
        // A shared writable mapping is a write path to the file.
        if crate::handlers::untyped_write_contained() {
            return crate::handlers::E_CONTAINED;
        }
    }
    if off >= src.size {
        return einval;
    }
    pager::set_file_frames(&CACHE);

    let tid = azos_sched::current_proc_tid();
    let mut pieces = [Piece { obj: 0, base: 0, span: 0 }; MAX_PIECES];
    let mut done = 0usize;
    let first_window = (first_page / WINDOW) as u64;

    // Where a private mapping goes: the break, as an anonymous `mmap`.
    let (private_base, private_end) = if shared {
        (0, 0)
    } else {
        let base = azos_sched::update_user_brk(0) as usize;
        if base < azos_mm::vmm::USER_GUARD_LIMIT {
            return enomem;
        }
        let aligned = base.saturating_add(page - 1) & !(page - 1);
        let end = match pages.checked_mul(page).and_then(|s| aligned.checked_add(s)) {
            Some(e) if e <= azos_sched::user_shm_window().0 => e,
            _ => return enomem,
        };
        if !azos_sched::mm_charge(pages as u32) {
            return enomem;
        }
        (aligned, end)
    };

    let mut remaining = pages;
    let mut cursor = private_base;
    let mut failure = 0i64;
    for k in 0..npieces {
        let in_win = if k == 0 { in0 } else { 0 };
        let n = remaining.min(WINDOW - in_win);
        let obj = match object_of(&src, first_window + k as u64) {
            Ok(o) => o,
            Err(e) => {
                failure = e;
                break;
            }
        };
        let r = if shared {
            map_shared_piece(root, tid, obj, in_win, n, write, pieces[..done].last().copied())
        } else {
            let start = cursor;
            pager::reserve_file(root, start, start + n * page, write, false, obj, in_win)
                .map(|()| Piece { obj, base: start, span: n })
                .map_err(|_| enomem)
        };
        // The region (if any) has its own use of the object now.
        CACHE.unref(obj);
        match r {
            Ok(p) => {
                pieces[done] = p;
                done += 1;
                cursor += n * page;
                remaining -= n;
            }
            Err(e) => {
                failure = e;
                break;
            }
        }
    }
    if done < npieces {
        unwind(root, tid, shared, &pieces[..done], if shared { 0 } else { pages });
        return failure;
    }
    if shared {
        pieces[0].base as i64 + (in0 * page) as i64
    } else {
        azos_sched::update_user_brk(private_end as u64);
        private_base as i64
    }
}

/// Book and map one shared piece: `n` pages from page `in_win` of `obj`. The
/// piece's window addresses start at the address of the object's page 0, right
/// after the previous piece's when there is one (the mapping is contiguous).
fn map_shared_piece(
    root: usize,
    tid: u32,
    obj: u32,
    in_win: usize,
    n: usize,
    write: bool,
    prev: Option<Piece>,
) -> Result<Piece, i64> {
    let page = azos_arch::PAGE_SIZE;
    let span = in_win + n;
    match memobj::memobj_has_mapping_ref(tid, obj) {
        Ok(false) => {}
        Ok(true) => return Err(Errno::EBUSY.to_syscall_ret()),
        Err(_) => return Err(Errno::ENOMEM.to_syscall_ret()),
    }
    let (lo, hi) = match prev {
        // Exactly where the previous piece ends, or not at all.
        Some(p) => {
            let at = p.base + p.span * page;
            (at, at + span * page)
        }
        None => azos_sched::user_shm_window(),
    };
    let base = azos_sched::scheduler::reserve_current_user_window(lo, hi, span * page)
        .ok_or(Errno::ENOMEM.to_syscall_ret())?;
    if memobj::memobj_acquire_ref(tid, obj).is_err() {
        let _ = azos_sched::process::release_user_window(base, span);
        return Err(Errno::ENOMEM.to_syscall_ret());
    }
    let booked = matches!(
        memobj::memobj_note_mapping_ref(tid, obj, root, base, span, MapAccess { write, max_write: write }),
        Ok(true)
    );
    if !booked {
        let _ = memobj::memobj_release_ref(tid, obj);
        let _ = azos_sched::process::release_user_window(base, span);
        return Err(Errno::EBUSY.to_syscall_ret());
    }
    let start = base + in_win * page;
    if pager::reserve_file(root, start, start + n * page, write, true, obj, in_win).is_err() {
        drop_shared(tid, obj, base, span);
        return Err(Errno::ENOMEM.to_syscall_ret());
    }
    Ok(Piece { obj, base, span })
}

/// Undo the `done` pieces of a mapping that failed part-way: the regions go
/// (and their uses of the objects), then each shared piece's booking and window,
/// or a private mapping's charge. Nothing was committed: the call has not
/// returned an address.
fn unwind(root: usize, tid: u32, shared: bool, done: &[Piece], charged: usize) {
    let page = azos_arch::PAGE_SIZE;
    let (Some(first), Some(last)) = (done.first(), done.last()) else {
        if charged != 0 {
            azos_sched::mm_discharge(charged as u32);
        }
        return;
    };
    if shared {
        // Regions start `in_win` pages into the first piece's reservation.
        let _ = pager::release_range(root, first.base, last.base + last.span * page);
        for p in done {
            drop_shared(tid, p.obj, p.base, p.span);
        }
    } else {
        let _ = pager::release_range(root, first.base, last.base + last.span * page);
        azos_sched::mm_discharge(charged as u32);
    }
}

// ── munmap and fsync ─────────────────────────────────────────────────────────

/// The shared pieces `munmap` took out of the address space, once its sweep has
/// cleared their PTEs: the pages go back to the file, then the booking, the
/// reference and the window addresses go. `files` is what
/// `pager::file_regions_in` listed before the regions were removed.
pub(crate) fn unmap_finish(files: &[FileRegion]) {
    let page = azos_arch::PAGE_SIZE;
    let tid = azos_sched::current_proc_tid();
    for r in files.iter().filter(|r| r.shared) {
        // While the booking still makes every page of a writable mapping dirty.
        let _ = writeback_current(r.obj, false);
        let base = r.start - r.off * page;
        let span = r.off + (r.end - r.start) / page;
        drop_shared(tid, r.obj, base, span);
    }
}

/// Shared file regions an exiting task's write-back lists at once; a task with
/// more has every cached window written back instead (correct, only wider).
const EXIT_FILES: usize = 4 * MAX_PIECES;

/// The exit of the task `tid`: write back its shared file mappings, the way
/// `munmap` of each would. Called by the exit hook with the task still current,
/// its address space still whole, and BEFORE the hook gives its object
/// references back (`memobj_release_all`): that is what ends the booking that
/// makes every page of a writable mapping count as dirty (a store through a
/// page that is already mapped writable leaves no other mark), so once it is
/// gone a store made after the last sync could not be told from a clean page.
/// A task that only stores through a `MAP_SHARED` mapping and exits therefore
/// leaves the stores in the file, not in the cache.
///
/// A failed write is not reported (nobody is left to tell); the page stays
/// dirty in the cache and the next sync of the file or the reap tries again.
/// A thread-group member's exit does nothing: the mappings are the group's, and
/// its leader's exit is the last holder's.
pub fn exit_writeback(tid: u32) {
    if azos_sched::domain_shared(tid) {
        return;
    }
    let root = azos_sched::current_user_pt();
    if root == 0 {
        return;
    }
    let mut files = [FileRegion::NONE; EXIT_FILES];
    let Ok(n) = pager::file_regions_in(root, 0, usize::MAX, &mut files) else {
        // More mappings than the list holds: every cached window, whoever maps it.
        for i in 0..MAX_MEMOBJS {
            let obj = {
                let reg = REG.lock_irqsave();
                if !reg[i].used || reg[i].closing {
                    continue;
                }
                reg[i].obj
            };
            let _ = writeback_current(obj, false);
        }
        return;
    };
    for (i, r) in files[..n].iter().enumerate() {
        // Once per object: a window mapped twice has two regions.
        if r.shared && !files[..i].iter().any(|p| p.shared && p.obj == r.obj) {
            let _ = writeback_current(r.obj, false);
        }
    }
}

/// Write back the dirty pages of every cached window of the file open as `fd`:
/// the mapped half of a file's sync. `-EIO` when a page could not be written.
pub(crate) fn flush_fd(fd: i32) -> Result<(), i64> {
    let Some(src) = file_ops().and_then(|o| o.map_source(fd)) else { return Ok(()) };
    let id = backing_id(src.backing);
    let mut failed = false;
    for i in 0..MAX_MEMOBJS {
        let obj = {
            let reg = REG.lock_irqsave();
            let e = &reg[i];
            if !(e.used && !e.closing && e.backing == id && e.key == src.key) {
                continue;
            }
            e.obj
        };
        if settle(obj).is_err() {
            failed = true;
        }
    }
    if failed { Err(Errno::EIO.to_syscall_ret()) } else { Ok(()) }
}

// ── The file layer's reads and writes through the same cache ─────────────────
//
// `read`/`write` of a file whose backend takes the cache (`PageCacheHooks`,
// installed by `boot::pagecache`) go through the objects `mmap` maps: the same
// registry, so a store through a mapping and a `write` meet in one frame, and
// a file is held once. The file layer names a file by its backing and key and
// the length it has now; windows, their objects' sizes and their lifetime are
// this file's.

/// Bytes of a cache window.
const WINDOW_BYTES: u64 = (WINDOW * azos_arch::PAGE_SIZE) as u64;

/// Looks at a page that is being written back or dirtied before a call gives
/// up, a millisecond apart: the flusher is not a task a yield hands the hart to.
const BUSY_TRIES: usize = 50;

/// Objects the file layer's reads and writes may hold (with `mmap`'s): half of
/// the table, so that the cache cannot take the slots shared memory and pipes
/// need (the table is Kconfig `MAX_MEMOBJS`, shared with them).
pub const CACHE_OBJECTS: usize = if MAX_MEMOBJS / 2 > 1 { MAX_MEMOBJS / 2 } else { 1 };

/// Pages the cache can hold at most: [`CACHE_OBJECTS`] windows, full.
pub const CACHE_PAGES: usize = CACHE_OBJECTS * WINDOW;

/// Write back the dirty pages of the object and wait for the ones another
/// caller is writing, so that when it answers `Ok` the object's pages are on the file's
/// backing: a page whose write failed (here or by the other caller) is dirty
/// again and is the next pass's. `Err` when the file said no or the pages kept
/// being written. An object closed meanwhile has nothing left to write.
fn settle(obj: u32) -> Result<(), ()> {
    for _ in 0..BUSY_TRIES {
        if !settle_stale(obj, true) {
            return Err(());
        }
        match memobj::memobj_paged_writeback_ref(obj) {
            Ok(_) => {}
            Err(PagedError::Io(_)) => return Err(()),
            Err(PagedError::Obj(_)) => return Ok(()),
        }
        match memobj::memobj_paged_info_ref(obj) {
            Ok(i) if i.flushing != 0 => crate::sleep::sleep_ms(1),
            _ => return Ok(()),
        }
    }
    Err(())
}

/// Run `op` on the object until it is not `Busy`, a millisecond apart.
fn retry_busy<T>(mut op: impl FnMut() -> Result<T, PagedError>) -> Result<T, PagedError> {
    for _ in 0..BUSY_TRIES {
        match op() {
            Err(PagedError::Obj(MemObjError::Busy)) => crate::sleep::sleep_ms(1),
            other => return other,
        }
    }
    Err(PagedError::Obj(MemObjError::Busy))
}

/// The object of window `w` of the file, attached at `size`, with one use taken
/// (give it back with [`FileFrames::unref`]). A full cache gives back the
/// objects nobody uses and tries once more. `None`: no object.
fn use_window(backing: &'static dyn PageBacking, key: &PageKey, size: u64, w: u64) -> Option<u32> {
    let obj = match object_for(backing, key, size, w, CACHE_OBJECTS) {
        Ok(o) => o,
        Err(_) => {
            reap_orphans();
            object_for(backing, key, size, w, CACHE_OBJECTS).ok()?
        }
    };
    if !settle_stale(obj, true) || retry_busy(|| memobj::memobj_paged_set_size_ref(obj, size)).is_err() {
        CACHE.unref(obj);
        return None;
    }
    Some(obj)
}

/// The windows `[off, off + len)` of a file touches, in order: `(window, offset
/// in it, bytes in it)`.
fn windows(off: u64, len: usize) -> impl Iterator<Item = (u64, usize, usize)> {
    let mut done = 0usize;
    core::iter::from_fn(move || {
        if done >= len {
            return None;
        }
        let pos = off.checked_add(done as u64)?;
        let at = (pos % WINDOW_BYTES) as usize;
        let n = (len - done).min(WINDOW_BYTES as usize - at);
        done += n;
        Some((pos / WINDOW_BYTES, at, n))
    })
}

/// Up to `dst.len()` bytes of the file from byte `off`, through the cache: all
/// of what the file holds there (it serves nothing past `size`), or `None` when
/// the cache cannot serve it (no object, no frame, a file layer error) and the
/// caller reads the backing.
pub fn cache_read(backing: &'static dyn PageBacking, key: &PageKey, size: u64, off: u64, dst: &mut [u8]) -> Option<usize> {
    let want = dst.len().min(size.saturating_sub(off).min(usize::MAX as u64) as usize);
    let mut done = 0usize;
    for (w, at, n) in windows(off, want) {
        let obj = use_window(backing, key, size, w)?;
        let r = memobj::memobj_paged_read_ref(obj, at, &mut dst[done..done + n]);
        CACHE.unref(obj);
        match r {
            Ok(m) if m == n => done += n,
            _ => return None,
        }
    }
    Some(done)
}

/// Write `src` at `off`, all of it inside `size`, through the cache: the bytes
/// written and how many pages that made dirty that were clean. `None`: nothing
/// was written and the caller writes the backing. A failure after some windows
/// were written is a short count.
pub fn cache_write(backing: &'static dyn PageBacking, key: &PageKey, size: u64, off: u64, src: &[u8]) -> Option<(usize, usize)> {
    let (mut done, mut newly) = (0usize, 0usize);
    for (w, at, n) in windows(off, src.len()) {
        let Some(obj) = use_window(backing, key, size, w) else { break };
        let r = retry_busy(|| memobj::memobj_paged_write_ref(obj, at, &src[done..done + n]));
        CACHE.unref(obj);
        match r {
            Ok((m, nw)) => {
                done += m;
                newly += nw;
                if m < n {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    (done > 0).then_some((done, newly))
}

/// Does the entry cache a file of `backing` (the file `key`, or any when `None`)?
fn entry_of(e: &Entry, backing: usize, key: Option<&PageKey>) -> bool {
    e.used && !e.closing && e.backing == backing && key.map_or(true, |k| e.key == *k)
}

/// The object of the next entry at or after slot `from` for the file `key` (any
/// file of `backing` when `None`), and the slot after it.
fn next_entry(backing: usize, key: Option<&PageKey>, from: usize) -> Option<(u32, usize)> {
    let reg = REG.lock_irqsave();
    (from..MAX_MEMOBJS).find(|&i| entry_of(&reg[i], backing, key)).map(|i| (reg[i].obj, i + 1))
}

/// Write the dirty pages of the file back (`key: None`: of every file of
/// `backing`), a page under a writable mapping included, and wait for pages
/// another caller is writing. `Err`: a page could not be written; it stays
/// dirty.
pub fn cache_writeback(backing: &'static dyn PageBacking, key: Option<&PageKey>) -> Result<(), ()> {
    let id = backing_id(backing);
    let (mut from, mut failed) = (0, false);
    while let Some((obj, next)) = next_entry(id, key, from) {
        from = next;
        failed |= settle(obj).is_err();
    }
    if failed { Err(()) } else { Ok(()) }
}

/// Forget the pages of the file that hold a byte at or after `from` (`key:
/// None`: of every file of `backing`), dirty ones too: the file changed under
/// them or is gone. From byte 0 the objects nobody uses are closed. `false`:
/// a page could not be forgotten (it kept being written back, or a mapper is
/// pinned). Its object is marked stale and goes unserved (a read or write of
/// it is declined to the backend, a mapping refused) and unwritten until a
/// later call forgets it for good: nothing stale is ever read or written back.
pub fn cache_forget(backing: &'static dyn PageBacking, key: Option<&PageKey>, from: u64) -> bool {
    let id = backing_id(backing);
    let (mut next, mut all) = (0, true);
    while let Some((obj, after)) = next_entry(id, key, next) {
        next = after;
        match retry_busy(|| memobj::memobj_paged_forget_ref(obj, from)) {
            Ok(()) if from == 0 => close_idle(after - 1),
            Err(PagedError::Obj(MemObjError::Busy)) => {
                // Marked, so that the object is not served or written back
                // until the forget has gone through.
                mark_stale(obj, from);
                all = false;
            }
            // Closed since the walk: nothing left of it to serve.
            _ => {}
        }
    }
    all
}

/// Host tests: the packed reference of the cache object of window `window` of
/// the file, to pin or hold it the way a mapper does.
#[cfg(test)]
pub fn __object_for_tests(backing: &'static dyn PageBacking, key: &PageKey, window: u64) -> Option<u32> {
    let id = backing_id(backing);
    REG.lock_irqsave().iter().find(|e| entry_matches(e, id, key, window)).map(|e| e.obj)
}

/// Host tests: close every cache object and empty the registry, whatever
/// state a test left. Never built into the kernel.
#[cfg(test)]
pub fn __reset_for_tests() {
    let mut reg = REG.lock_irqsave();
    for e in reg.iter_mut().filter(|e| e.used) {
        let _ = memobj::memobj_paged_close_ref(e.obj);
        *e = NO_ENTRY;
    }
}

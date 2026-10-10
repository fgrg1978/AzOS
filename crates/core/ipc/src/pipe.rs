// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Pipe — port of kernel/core/pipe.c + kernel/include/pipe.h
///
/// # Reachability from ring 3 (audited 2026-08-22)
///
/// Only [`pipe_create`] is reachable from userspace, via `SYS_PIPE`
/// (`crates/core/syscall/src/dispatch.rs:139` → `sys_pipe`,
/// `crates/core/syscall/src/handlers.rs:550`). There is **no** `SYS_PIPE_READ` /
/// `SYS_PIPE_WRITE`, and `vfs_read` / `vfs_write`
/// (`crates/fs/fs/src/vfs.rs:974` and `:1016`) have no pipe branch — they
/// resolve an fd through the inode table and reject anything that is not
/// `INODE_FILE` or `INODE_DEVICE`. So the "fds" `sys_pipe` hands back are
/// pool indices that no `read()`/`write()` can act on. Every live call to
/// [`pipe_read`] / [`pipe_write`] comes from kernel context with kernel
/// buffers (`kernel/src/smokes/selftest.rs` and `domains/robot/bench/src/ipc.rs:87,88`).
///
/// That is why the raw-pointer signatures below are not, today, an arbitrary
/// kernel read/write primitive — but they are a **loaded gun on the table**:
/// the moment anyone wires a syscall to them, an unvalidated ring-3 pointer
/// becomes exactly that. Anything that reaches these from a syscall MUST go
/// through `azos_sched::copy_from_user` / `copy_to_user`
/// (`crates/core/sched/src/process.rs:452` / `:492`), which walk
/// `vmm::translate_user` and enforce VALID+USER+READ (+WRITE on the store
/// side) at every leaf. The safe [`pipe_read_buf`] / [`pipe_write_buf`]
/// wrappers below exist so that a future syscall never has to touch the raw
/// form at all.

use azos_sync::SpinLock;
pub use azos_limits::MAX_PIPES;

// ── Caller attribution ───────────────────────────────────────────────────────
//
// **WHY (Carril D / pipe ownership).** `pipe_read`, `pipe_write`,
// `pipe_close_read` and `pipe_close_write` took a raw pool index with no
// notion of who was calling. `pipe_create` returns `(idx, idx)` — both ends
// are the *same* slot — so an index is a full read+write right over the pipe,
// and `MAX_PIPES` is small enough to enumerate exhaustively. The moment a
// read/write syscall lands, an unowned index means any task drains or
// poisons any other task's pipe, and `pipe_close_*` is already a
// cross-task denial of service on its own.
//
// Same shape as `channel.rs`: the identity is read here instead of being
// passed in, so the arity of functions called from `domains/robot/bench` and
// `kernel/src/smokes/selftest.rs` (files outside this lane) does not change. Both of
// those callers are kernel tasks, so they take the privileged bypass.

/// Returns `(caller_tid, privileged)`; see `channel.rs` for the rationale.
#[cfg(not(test))]
#[inline(always)]
fn caller_ctx() -> (u32, bool) {
    (
        // Wave 15 (plan 4a): the process, so a thread's channel or pipe is
        // its process's, as a descriptor is, and outlives the thread.
        azos_sched::current_proc_tid(),
        azos_sched::current_user_pt() == 0,
    )
}

/// Host-test stand-in for [`caller_ctx`]; never compiled into the kernel.
#[cfg(test)]
pub mod test_ctx {
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    pub static TID: AtomicU32 = AtomicU32::new(0);
    pub static PRIVILEGED: AtomicBool = AtomicBool::new(true);

    pub fn set(tid: u32, privileged: bool) {
        TID.store(tid, Ordering::SeqCst);
        PRIVILEGED.store(privileged, Ordering::SeqCst);
    }
}

#[cfg(test)]
#[inline(always)]
fn caller_ctx() -> (u32, bool) {
    use core::sync::atomic::Ordering;
    (
        test_ctx::TID.load(Ordering::SeqCst),
        test_ctx::PRIVILEGED.load(Ordering::SeqCst),
    )
}

/// May the current caller touch pipe slot `idx`? Assumes the pool lock is
/// held by the caller (it takes no lock of its own).
#[inline(always)]
fn access_ok(pipe: &Pipe) -> bool {
    if pipe.typed {
        // RFC-0055: a capability pipe is reached through its handles only.
        return false;
    }
    let (caller, privileged) = caller_ctx();
    privileged || pipe.owner == caller
}

pub const PIPE_BUF_SIZE: usize = 4096;

#[derive(Copy, Clone, PartialEq)]
pub enum PipeState {
    Free         = 0,
    Active       = 1,
    ReadClosed   = 2,
    WriteClosed  = 3,
    Closed       = 4,
}

#[derive(Copy, Clone)]
pub struct Pipe {
    pub buffer:          [u8; PIPE_BUF_SIZE],
    pub read_pos:        u32,
    pub write_pos:       u32,
    pub state:           PipeState,
    pub readers:         u32,
    pub writers:         u32,
    pub waiting_readers: u32,
    pub waiting_writers: u32,
    pub id:              u32,
    /// TID of the task that called [`pipe_create`].
    ///
    /// `0` is the vacant marker — `current_task_tid()` returns 0 only when
    /// no task is running and `NEXT_TID` never issues it, so a free slot
    /// denies every ring-3 caller by construction. Rewritten on every
    /// `pipe_create`, so it also invalidates stale indices across slot
    /// reuse.
    pub owner:           u32,
    /// RFC-0055: a capability pipe (`SYS_PIPE_TYPED`). Its ends are
    /// `Cap<Pipe>` handles, it has no owner, and the untyped calls above
    /// refuse it.
    pub typed:           bool,
    /// RFC-0055 `PIPE_NONBLOCK`: a read of an empty typed pipe (a write to a
    /// full one) answers `-EAGAIN` instead of parking. Kept in the pipe, so it
    /// goes with it: the per-machine side table it lived in (16 entries) was
    /// cleared only by an explicit close, and the pipes of tasks that died
    /// holding them used it up until every later `PIPE_NONBLOCK` was silently
    /// ignored (plan item 7).
    pub nonblock:        bool,
    /// RFC-0055: bumped every time the slot is handed out, never 0, packed
    /// into the capability's resource so a handle to a freed pipe is stale.
    pub gen:             u16,
    /// RFC-0055: bytes queued in a typed pipe (its ring uses all
    /// `PIPE_BUF_SIZE` bytes; the untyped ring keeps one slot empty).
    pub count:           u32,
    /// RFC-0055: TID of a reader parked on an empty typed pipe, 0 = none.
    pub rd_waiter:       u32,
    /// RFC-0055: TID of a writer parked on a full typed pipe, 0 = none.
    pub wr_waiter:       u32,
    /// RFC-0055: the task that created a typed pipe, for its quota.
    pub creator:         u32,
}

impl Pipe {
    pub const fn zeroed() -> Self {
        Pipe {
            buffer:          [0u8; PIPE_BUF_SIZE],
            read_pos:        0,
            write_pos:       0,
            state:           PipeState::Free,
            readers:         0,
            writers:         0,
            waiting_readers: 0,
            waiting_writers: 0,
            id:              0,
            owner:           0,
            typed:           false,
            nonblock:        false,
            gen:             0,
            count:           0,
            rd_waiter:       0,
            wr_waiter:       0,
            creator:         0,
        }
    }

    pub fn is_empty(&self) -> bool { self.read_pos == self.write_pos }

    pub fn is_full(&self) -> bool {
        ((self.write_pos + 1) as usize % PIPE_BUF_SIZE) == self.read_pos as usize
    }

    pub fn available(&self) -> usize {
        let w = self.write_pos as usize;
        let r = self.read_pos as usize;
        if w >= r { w - r } else { PIPE_BUF_SIZE - r + w }
    }

    pub fn space(&self) -> usize {
        PIPE_BUF_SIZE - 1 - self.available()
    }
}

// ── Global pipe pool ──────────────────────────────────────────────────────────

struct PipePool {
    pipes:   [Pipe; MAX_PIPES],
    next_id: u32,
}

impl PipePool {
    const fn new() -> Self {
        PipePool {
            pipes:   [Pipe::zeroed(); MAX_PIPES],
            next_id: 1,
        }
    }

    fn alloc(&mut self) -> Option<usize> {
        for i in 0..MAX_PIPES {
            if self.pipes[i].state == PipeState::Free {
                // The generation survives the wipe: a typed handle to the
                // previous incarnation must never name this one.
                let gen = self.pipes[i].gen;
                self.pipes[i] = Pipe::zeroed();
                self.pipes[i].gen = gen;
                self.pipes[i].state = PipeState::Active;
                self.pipes[i].id    = self.next_id;
                self.next_id       += 1;
                return Some(i);
            }
        }
        None
    }
}

static PIPES: SpinLock<PipePool> = SpinLock::new(PipePool::new());

// ── Public API ────────────────────────────────────────────────────────────────

pub fn pipe_init() {
    let mut pool = PIPES.lock();
    for i in 0..MAX_PIPES {
        pool.pipes[i].state = PipeState::Free;
        pool.pipes[i].id    = 0;
    }
}

/// Create a pipe; returns (read_idx, write_idx) on success.
///
/// The calling task becomes the pipe's owner. Because both ends are the
/// same slot, that is the only model this data structure can express today:
/// there is nothing in the `Pipe` struct that distinguishes a read end from
/// a write end, so a "reader TID / writer TID" pair would be a lie. Handing
/// an end to another task requires splitting the slot in two first — an ABI
/// change, flagged in the report rather than improvised here.
pub fn pipe_create() -> Option<(usize, usize)> {
    let (owner, _privileged) = caller_ctx();
    let mut pool = PIPES.lock();
    let idx = pool.alloc()?;
    pool.pipes[idx].readers = 1;
    pool.pipes[idx].writers = 1;
    pool.pipes[idx].owner   = owner;
    Some((idx, idx))  // Same slot — read/write ends distinguished by caller
}

/// TID that owns pipe `idx`, or `None` for an out-of-range or free slot.
pub fn pipe_owner(idx: usize) -> Option<u32> {
    if idx >= MAX_PIPES { return None; }
    let pool = PIPES.lock();
    if pool.pipes[idx].state == PipeState::Free { None } else { Some(pool.pipes[idx].owner) }
}

/// Read up to `count` bytes.  Returns bytes read, 0 on EOF, -1 on error.
///
/// # Safety contract (not enforceable here)
///
/// `buf` must be a valid kernel-writable pointer for at least `count` bytes.
/// This function dereferences it directly; it has no page table to validate
/// against and no way to know whose address space `buf` belongs to. A ring-3
/// pointer must be translated by the *caller* — see the module header. The
/// null case is rejected below because it is the one invalid pointer that can
/// be recognised without an address space, and because `sys_pipe`-shaped
/// callers pass `0` for "no buffer"; everything else is the caller's contract.
/// Prefer [`pipe_read_buf`].
pub fn pipe_read(idx: usize, buf: *mut u8, count: usize) -> i32 {
    if idx >= MAX_PIPES { return -1; }
    if buf.is_null() { return -1; }
    let mut pool = PIPES.lock();
    let pipe = &mut pool.pipes[idx];

    if pipe.state == PipeState::Free { return -1; }
    if !access_ok(pipe) { return -1; }

    // No data available
    if pipe.is_empty() {
        return if pipe.state == PipeState::WriteClosed || pipe.state == PipeState::Closed {
            0   // EOF: write end closed, no more data coming
        } else {
            -2  // EAGAIN: would block, writer still alive
        };
    }

    let avail = pipe.available();
    let to_read = count.min(avail);
    // SAFETY: the caller's contract above (`buf` valid for `count` bytes,
    // and `to_read <= count`).
    let out = unsafe { core::slice::from_raw_parts_mut(buf, to_read) };
    // Block copies (`ring_take`, as the typed pipes), not a byte loop:
    // PIPES is one SpinLock for every pipe.
    pipe.read_pos = ring_take(&pipe.buffer, pipe.read_pos as usize, out) as u32;
    to_read as i32
}

/// Write up to `count` bytes.  Returns bytes written, -1 on error.
///
/// # Safety contract (not enforceable here)
///
/// Same as [`pipe_read`], mirrored: `buf` must be a valid kernel-readable
/// pointer for at least `count` bytes. Prefer [`pipe_write_buf`].
pub fn pipe_write(idx: usize, buf: *const u8, count: usize) -> i32 {
    if idx >= MAX_PIPES { return -1; }
    if buf.is_null() { return -1; }
    let mut pool = PIPES.lock();
    let pipe = &mut pool.pipes[idx];

    if pipe.state == PipeState::Free
        || pipe.state == PipeState::ReadClosed
        || pipe.state == PipeState::Closed
    {
        return -1;  // EPIPE
    }
    if !access_ok(pipe) { return -1; }

    let space = pipe.space();
    let to_write = count.min(space);
    // SAFETY: the caller's contract above (`buf` valid for `count` bytes,
    // and `to_write <= count`).
    let src = unsafe { core::slice::from_raw_parts(buf, to_write) };
    // Block copies, as in `pipe_read`.
    pipe.write_pos = ring_put(&mut pipe.buffer, pipe.write_pos as usize, src) as u32;
    to_write as i32
}

/// Safe wrapper over [`pipe_read`]. This is the form a syscall should use:
/// the kernel-side buffer is a real slice, so the pointer and the length can
/// never disagree, and the ring-3 copy-out stays in the syscall layer where
/// `copy_to_user` lives.
pub fn pipe_read_buf(idx: usize, buf: &mut [u8]) -> i32 {
    if buf.is_empty() { return 0; }
    pipe_read(idx, buf.as_mut_ptr(), buf.len())
}

/// Safe wrapper over [`pipe_write`]; see [`pipe_read_buf`].
pub fn pipe_write_buf(idx: usize, buf: &[u8]) -> i32 {
    if buf.is_empty() { return 0; }
    pipe_write(idx, buf.as_ptr(), buf.len())
}

/// Returns 0 on success, -1 if the index is out of range or the caller does
/// not own the pipe.
///
/// **WHY the check:** closing an end you do not own is a pure denial of
/// service — one call turns another task's live pipe into `ReadClosed`, and
/// every subsequent `pipe_write` on it returns EPIPE forever. Signature
/// changed from `()` to `i32` so a syscall can report `E_PERM`.
pub fn pipe_close_read(idx: usize) -> i32 {
    if idx >= MAX_PIPES { return -1; }
    let mut pool = PIPES.lock();
    let pipe = &mut pool.pipes[idx];
    if pipe.state == PipeState::Free { return -1; }
    if !access_ok(pipe) { return -1; }
    if pipe.readers > 0 { pipe.readers -= 1; }
    if pipe.readers == 0 {
        pipe.state = if pipe.writers == 0 { PipeState::Closed } else { PipeState::ReadClosed };
    }
    reclaim_if_closed(pipe);
    0
}

/// Counterpart of [`pipe_close_read`]; same authorization, same rationale.
pub fn pipe_close_write(idx: usize) -> i32 {
    if idx >= MAX_PIPES { return -1; }
    let mut pool = PIPES.lock();
    let pipe = &mut pool.pipes[idx];
    if pipe.state == PipeState::Free { return -1; }
    if !access_ok(pipe) { return -1; }
    if pipe.writers > 0 { pipe.writers -= 1; }
    if pipe.writers == 0 {
        pipe.state = if pipe.readers == 0 { PipeState::Closed } else { PipeState::WriteClosed };
    }
    reclaim_if_closed(pipe);
    0
}

/// Give a slot whose two ends are both closed back to the pool.
///
/// **WHY.** `PipePool::alloc` only takes `Free` slots, and closing used to stop
/// at `Closed`, so every pipe ever created held its slot until reboot: after
/// `MAX_PIPES` creations machine-wide `pipe_create` answered `None` forever.
/// `bench_pipe_create_destroy` alone creates hundreds, and a boot where it ran
/// before the IPC demo printed "Pipe create FAILED". Nothing can use a closed
/// slot any more: reads, writes and closes on `Free` answer -1. The next pipe
/// starts empty because `alloc` zeroes the slot it hands out, not because of
/// this.
fn reclaim_if_closed(pipe: &mut Pipe) {
    if pipe.state == PipeState::Closed {
        let gen = pipe.gen;
        *pipe = Pipe::zeroed();
        pipe.gen = gen;
    }
}

/// Free every pipe `tid` owns, when the task exits. Its ends die with it, and
/// without this its slots stay taken for the life of the board, which is the
/// same exhaustion as above reached one task lifetime at a time.
pub fn pipe_release_all(tid: u32) {
    if tid == 0 { return; }
    let mut pool = PIPES.lock();
    for pipe in pool.pipes.iter_mut() {
        if pipe.state != PipeState::Free && !pipe.typed && pipe.owner == tid {
            let gen = pipe.gen;
            *pipe = Pipe::zeroed();
            pipe.gen = gen;
        }
    }
}

/// Bytes currently queued. Returns 0 for an index the caller does not own —
/// occupancy is a side channel onto another task's traffic pattern, and 0 is
/// indistinguishable from "empty", so denial leaks nothing.
pub fn pipe_available(idx: usize) -> usize {
    if idx >= MAX_PIPES { return 0; }
    let pool = PIPES.lock();
    if !access_ok(&pool.pipes[idx]) { return 0; }
    pool.pipes[idx].available()
}

/// Free space. Denied callers get 0 ("full"), which is the fail-closed
/// answer: it discourages a write rather than inviting one.
pub fn pipe_space(idx: usize) -> usize {
    if idx >= MAX_PIPES { return 0; }
    let pool = PIPES.lock();
    if !access_ok(&pool.pipes[idx]) { return 0; }
    pool.pipes[idx].space()
}

// ── Capability pipes (RFC-0055, wave 11) ─────────────────────────────────────
//
// `SYS_PIPE_TYPED` mints two `Cap<Pipe>` handles naming one slot: the read end
// carries `READ`, the write end `WRITE`. The slot knows nothing of handles
// beyond two counts: `readers` and `writers` start at 1 and fall when an end's
// handle is closed or its holder exits (`crate::release_all` walks the dying
// task's table). Moving a handle to a child changes neither. When both reach
// 0 the slot is freed and its generation, packed into every handle's
// resource, makes the old handles stale.
//
// Nothing here blocks or wakes: a read of an empty pipe registers the caller
// as the slot's reader-waiter and answers `WouldBlock`, and every call returns
// the TID the caller must wake (the other side's waiter), because this crate's
// lock must not be held across a scheduler call. The syscall layer
// (`crates/core/syscall/src/ushell.rs`) parks and wakes.

/// What a typed read or write did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeIo {
    /// This many bytes moved.
    Done(usize),
    /// Read: empty and no write end left.
    Eof,
    /// Read: empty with a live writer; write: no room (all-or-nothing for a
    /// write of at most `PIPE_BUF_SIZE`). The caller is registered as the
    /// waiter.
    WouldBlock,
    /// Write: no read end left (`-EPIPE`).
    Broken,
    /// The handle names no live incarnation of the slot.
    Stale,
}

/// Why a typed pipe was not created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeCreateError {
    /// Every slot is taken.
    NoSpace,
    /// The creator already holds `MAX_PIPES / 2` live pipes it created.
    Quota,
}

/// Live typed pipes one task may have created at once (RFC-0003's
/// exhaustion corollary: no task takes the whole pool).
pub const PIPE_QUOTA: usize = if MAX_PIPES / 2 == 0 { 1 } else { MAX_PIPES / 2 };

/// Pack slot `idx` and generation `gen` into a capability resource.
pub const fn pipe_resource(idx: usize, gen: u16) -> u32 {
    ((gen as u32) << 16) | (idx as u32 & 0xffff)
}

const _: () = assert!(MAX_PIPES <= 0x1_0000, "a pipe index must fit 16 bits of the resource");

/// The live typed slot `resource` names, or `None`.
fn typed_slot(pool: &PipePool, resource: u32) -> Option<usize> {
    let idx = (resource & 0xffff) as usize;
    let gen = (resource >> 16) as u16;
    let p = pool.pipes.get(idx)?;
    (p.typed && p.state != PipeState::Free && p.gen == gen && gen != 0).then_some(idx)
}

/// Create a typed pipe for `creator`; returns its resource. Both counts start
/// at 1: the caller mints the two handles next, and must give the slot back
/// with [`pipe_typed_abandon`] if it cannot.
pub fn pipe_create_typed(creator: u32) -> Result<u32, PipeCreateError> {
    let mut pool = PIPES.lock();
    let held = pool.pipes.iter().filter(|p| p.typed && p.state != PipeState::Free && p.creator == creator).count();
    if held >= PIPE_QUOTA {
        return Err(PipeCreateError::Quota);
    }
    let idx = pool.alloc().ok_or(PipeCreateError::NoSpace)?;
    let p = &mut pool.pipes[idx];
    p.gen = p.gen.wrapping_add(1);
    if p.gen == 0 {
        p.gen = 1;
    }
    p.typed = true;
    p.readers = 1;
    p.writers = 1;
    p.creator = creator;
    Ok(pipe_resource(idx, p.gen))
}

/// Free a typed pipe whose handles were never minted.
pub fn pipe_typed_abandon(resource: u32) {
    let mut pool = PIPES.lock();
    if let Some(idx) = typed_slot(&pool, resource) {
        let gen = pool.pipes[idx].gen;
        pool.pipes[idx] = Pipe::zeroed();
        pool.pipes[idx].gen = gen;
    }
}

/// Copy `out.len()` bytes out of `ring` starting at `pos` (at most two
/// slices: up to the end, then from the start); the position after them.
/// Wave 13 (DEBTS): the typed pipe moved one byte per iteration with a
/// modulo, ~16 instructions a byte — 2,082 of the 4,157 instructions of a
/// 64-byte vsbench `pipe-rw` round (windowed per-function `-icount` count).
fn ring_take(ring: &[u8; PIPE_BUF_SIZE], pos: usize, out: &mut [u8]) -> usize {
    let first = out.len().min(PIPE_BUF_SIZE - pos);
    out[..first].copy_from_slice(&ring[pos..pos + first]);
    let rest = out.len() - first;
    out[first..].copy_from_slice(&ring[..rest]);
    (pos + out.len()) % PIPE_BUF_SIZE
}

/// Copy `data` into `ring` starting at `pos`, wrapping once; the position
/// after it. The caller has checked it fits.
fn ring_put(ring: &mut [u8; PIPE_BUF_SIZE], pos: usize, data: &[u8]) -> usize {
    let first = data.len().min(PIPE_BUF_SIZE - pos);
    ring[pos..pos + first].copy_from_slice(&data[..first]);
    let rest = data.len() - first;
    ring[..rest].copy_from_slice(&data[first..]);
    (pos + data.len()) % PIPE_BUF_SIZE
}

/// Read up to `out.len()` bytes. On `WouldBlock`, `me` is registered as the
/// reader to wake. The second value is a TID to wake (a writer waiting for
/// room), 0 for none.
pub fn pipe_typed_read(resource: u32, out: &mut [u8], me: u32) -> (PipeIo, u32) {
    let mut pool = PIPES.lock();
    let Some(idx) = typed_slot(&pool, resource) else { return (PipeIo::Stale, 0) };
    let p = &mut pool.pipes[idx];
    if p.count == 0 {
        if p.writers == 0 {
            return (PipeIo::Eof, 0);
        }
        p.rd_waiter = me;
        return (PipeIo::WouldBlock, 0);
    }
    let n = out.len().min(p.count as usize);
    p.read_pos = ring_take(&p.buffer, p.read_pos as usize, &mut out[..n]) as u32;
    p.count -= n as u32;
    if p.rd_waiter == me {
        p.rd_waiter = 0;
    }
    let wake = core::mem::take(&mut p.wr_waiter);
    (PipeIo::Done(n), wake)
}

/// Write `data`. A write of at most `PIPE_BUF_SIZE` bytes goes in whole or
/// not at all; a longer one writes what fits. On `WouldBlock`, `me` is
/// registered as the writer to wake. The second value is a TID to wake (a
/// reader waiting for data), 0 for none.
pub fn pipe_typed_write(resource: u32, data: &[u8], me: u32) -> (PipeIo, u32) {
    let mut pool = PIPES.lock();
    let Some(idx) = typed_slot(&pool, resource) else { return (PipeIo::Stale, 0) };
    let p = &mut pool.pipes[idx];
    if p.readers == 0 {
        return (PipeIo::Broken, 0);
    }
    if data.is_empty() {
        return (PipeIo::Done(0), 0);
    }
    let space = PIPE_BUF_SIZE - p.count as usize;
    let n = if data.len() <= PIPE_BUF_SIZE {
        if space < data.len() { 0 } else { data.len() }
    } else {
        space
    };
    if n == 0 {
        p.wr_waiter = me;
        return (PipeIo::WouldBlock, 0);
    }
    p.write_pos = ring_put(&mut p.buffer, p.write_pos as usize, &data[..n]) as u32;
    p.count += n as u32;
    if p.wr_waiter == me {
        p.wr_waiter = 0;
    }
    let wake = core::mem::take(&mut p.rd_waiter);
    (PipeIo::Done(n), wake)
}

/// A wait on `resource` ended without being served (timeout, stop request):
/// forget `me` as a waiter.
pub fn pipe_typed_unwait(resource: u32, me: u32) {
    let mut pool = PIPES.lock();
    if let Some(idx) = typed_slot(&pool, resource) {
        let p = &mut pool.pipes[idx];
        if p.rd_waiter == me {
            p.rd_waiter = 0;
        }
        if p.wr_waiter == me {
            p.wr_waiter = 0;
        }
    }
}

/// One end's handle is gone (closed, or its holder exited). Returns the TID
/// to wake: the other side's waiter, which now sees end-of-file or `-EPIPE`.
/// The slot is freed when no end is left.
pub fn pipe_typed_drop_end(resource: u32, write_end: bool) -> u32 {
    let mut pool = PIPES.lock();
    let Some(idx) = typed_slot(&pool, resource) else { return 0 };
    let p = &mut pool.pipes[idx];
    let wake = if write_end {
        p.writers = p.writers.saturating_sub(1);
        if p.writers == 0 { core::mem::take(&mut p.rd_waiter) } else { 0 }
    } else {
        p.readers = p.readers.saturating_sub(1);
        if p.readers == 0 { core::mem::take(&mut p.wr_waiter) } else { 0 }
    };
    if p.readers == 0 && p.writers == 0 {
        let gen = p.gen;
        *p = Pipe::zeroed();
        p.gen = gen;
    }
    wake
}

/// One more handle on an end of a live typed pipe (RFC-0047: a forked Linux
/// child inherits its parent's pipe descriptors as Linux does). `false` when
/// `resource` names no live typed pipe.
pub fn pipe_typed_add_end(resource: u32, write_end: bool) -> bool {
    let mut pool = PIPES.lock();
    let Some(idx) = typed_slot(&pool, resource) else { return false };
    let p = &mut pool.pipes[idx];
    if write_end {
        p.writers = p.writers.saturating_add(1);
    } else {
        p.readers = p.readers.saturating_add(1);
    }
    true
}

/// Live typed pipes `creator` made (its quota use).
pub fn pipe_typed_held_by(creator: u32) -> usize {
    let pool = PIPES.lock();
    pool.pipes.iter().filter(|p| p.typed && p.state != PipeState::Free && p.creator == creator).count()
}

/// `(readers, writers, bytes queued)` of a live typed pipe.
/// Set typed pipe `resource`'s `PIPE_NONBLOCK` flag. `false` for a stale
/// resource.
pub fn pipe_typed_set_nonblock(resource: u32, on: bool) -> bool {
    let mut pool = PIPES.lock();
    let Some(idx) = typed_slot(&pool, resource) else { return false };
    // The gate canary never records the flag.
    pool.pipes[idx].nonblock = on && !cfg!(feature = "pipe-nonblock-canary");
    true
}

/// Is typed pipe `resource` `PIPE_NONBLOCK`? `false` for a stale resource.
pub fn pipe_typed_nonblock(resource: u32) -> bool {
    let pool = PIPES.lock();
    typed_slot(&pool, resource).is_some_and(|idx| pool.pipes[idx].nonblock)
}

pub fn pipe_typed_state(resource: u32) -> Option<(u32, u32, usize)> {
    let pool = PIPES.lock();
    let idx = typed_slot(&pool, resource)?;
    let p = &pool.pipes[idx];
    Some((p.readers, p.writers, p.count as usize))
}

/// Wipe the whole pool. Host-test hygiene only — see the equivalent note in
/// `channel.rs`. Never built into the kernel.
#[cfg(test)]
pub fn __pipe_reset_for_tests() {
    let mut pool = PIPES.lock();
    for i in 0..MAX_PIPES {
        pool.pipes[i] = Pipe::zeroed();
    }
    pool.next_id = 1;
}

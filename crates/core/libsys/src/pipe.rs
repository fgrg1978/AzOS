// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The POSIX pipe of a process: the ends it holds over `azos_bytepipe`.
//!
//! A pipe is a `Cap<Shm>` region with a byte ring in it ([`azos_bytepipe`]),
//! mapped by every process that holds an end. This module is the process's
//! half: a table of the regions it has mapped, a **token** for each end it
//! holds, and the calls on a token (`read`, `write`, `close`), with the futex
//! as the doorbell. The kernel is entered only to create and map the region,
//! to sleep and to wake, and to give an end up: reading and writing a pipe is
//! a memory copy.
//!
//! # Tokens
//!
//! A token is a `u32` that is never a capability handle (its kind field is
//! zero, which no capability has), so it travels where a handle did: in a
//! `libsys` fd table, in a relibc `OpenFile`, in a Linux runtime's descriptor
//! entry. [`file_read_typed`](crate::file_read_typed),
//! [`file_write_typed`](crate::file_write_typed) and
//! [`close_typed`](crate::close_typed) answer for a token through this
//! module, so a program that reads a descriptor needs no pipe-specific code.
//!
//! # Ends across processes
//!
//! The region is one object and each process maps it. Who holds which end is
//! the **kernel's** record (`MEMOBJ_END_DROP`, `azos_bytepipe`'s docs): a
//! region handed over in a spawn's move list or by a fork arrives with its
//! ends already counted for the receiver, a process gives an end up here with
//! the last [`close`] of it, and a process that dies (a fault, a force-kill)
//! has whatever it still holds given up by the kernel, so a peer sees end of
//! file or `EPIPE` and a lock the dead process held is opened. This module
//! counts nothing itself. A received region is [`adopt`]ed into an end: the
//! sender made it.
//!
//! In a spawn's move list the read end goes to child fd 0 and the write end
//! to any other fd: a received region carries no role, the position says it
//! (the kernel counts the ends by the same rule).
//!
//! A forked process (the Linux runtime's `fork`) calls [`forked`] first thing
//! in the child: the process id the locks record is cached.

use crate::{
    futex_wait_addr, futex_wake_addr, getpid, invoke_abi::{SHM_END_READ, SHM_END_WRITE}, shm_acquire_typed, shm_create_typed, shm_end_drop_typed,
    shm_map_typed, shm_release_typed, E_BADF, E_INTR, E_INVAL, E_PIPE, FUTEX_ETIMEDOUT, PAGE_SIZE,
    RING_WAIT_NS, SHM_INFO_BYTES, SHM_RW,
};
pub use azos_bytepipe::End;
use azos_bytepipe::{BytePipe, PipeError, Slept, Sys, HEADER_BYTES};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

const E_AGAIN: isize = -11;
const E_MFILE: isize = -24;

/// Pipes (regions) a process holds at once: the shm mappings a task may have.
pub const MAX_PIPES: usize = 8;

/// Data bytes a new pipe aims at; the region is the pages that hold this and
/// the header, and the ring takes the largest power of two that fits.
const TARGET_DATA: usize = 16384;

const TOKEN_TAG: u32 = 0x0010_0000;
// A token is never a capability: its kind field is zero, which no minted
// capability has (kind 0 is the null capability).
const _: () = assert!(azos_abi::cap::CapHandle::from_raw(TOKEN_TAG | 0xF).kind() == 0);
const _: () = assert!(MAX_PIPES <= 8, "a token holds the table index in three bits");

/// Is `h` a pipe token (and not a capability handle)?
#[inline]
pub const fn is_token(h: u32) -> bool {
    h & !0xF == TOKEN_TAG
}

const fn token(idx: usize, end: End) -> u32 {
    TOKEN_TAG | (idx as u32) << 1 | matches!(end, End::Write) as u32
}

const fn parts(t: u32) -> (usize, End) {
    ((t >> 1) as usize & 7, if t & 1 == 1 { End::Write } else { End::Read })
}

const fn slot(end: End) -> usize {
    matches!(end, End::Write) as usize
}

/// The doorbell: the kernel futex on the region's words.
struct Bell;

impl Sys for Bell {
    fn wait(&self, addr: usize, expected: u32) -> Slept {
        // The backstop the rings use: a wake that never comes costs a second.
        match futex_wait_addr(addr, expected, RING_WAIT_NS) {
            E_INTR => Slept::Interrupted,
            FUTEX_ETIMEDOUT => Slept::Again,
            _ => Slept::Again,
        }
    }
    fn wake(&self, addr: usize) {
        let _ = futex_wake_addr(addr, u32::MAX);
    }
    fn me(&self) -> u32 {
        my_pid()
    }
}

/// This process's id, asked of the kernel once (a lock word records its owner,
/// so the kernel can open one a dying process held). 0: not asked yet.
static PID: AtomicU32 = AtomicU32::new(0);

fn my_pid() -> u32 {
    let p = PID.load(Ordering::Relaxed);
    if p != 0 {
        return p;
    }
    let p = getpid().max(0) as u32;
    PID.store(p, Ordering::Relaxed);
    p
}

/// This is the child of a fork: the process id cached is the parent's.
/// Called first thing after `fork` returns 0.
pub fn forked() {
    PID.store(0, Ordering::Relaxed);
}

#[derive(Clone, Copy)]
struct Rec {
    used: bool,
    /// The `Cap<Shm>` naming the region.
    cap: u32,
    pipe: Option<BytePipe>,
    /// Which ends this process holds (an end is held until its token closes).
    open: [bool; 2],
    /// `O_NONBLOCK` of each end's description.
    nonblock: [bool; 2],
}

const FREE: Rec = Rec { used: false, cap: 0, pipe: None, open: [false; 2], nonblock: [false; 2] };

struct Table {
    lock: AtomicBool,
    recs: core::cell::UnsafeCell<[Rec; MAX_PIPES]>,
}

// SAFETY: every access is under `lock`.
unsafe impl Sync for Table {}

static TABLE: Table = Table { lock: AtomicBool::new(false), recs: core::cell::UnsafeCell::new([FREE; MAX_PIPES]) };

fn with<R>(f: impl FnOnce(&mut [Rec; MAX_PIPES]) -> R) -> R {
    while TABLE.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    // SAFETY: the flag is held.
    let r = f(unsafe { &mut *TABLE.recs.get() });
    TABLE.lock.store(false, Ordering::Release);
    r
}

/// The region size of a new pipe, in pages.
fn region_pages() -> usize {
    (TARGET_DATA + HEADER_BYTES).div_ceil(PAGE_SIZE)
}

/// Make a pipe: a region, mapped and started, with this process holding both
/// ends. `[read, write]` tokens, or a negative errno.
pub fn create() -> Result<[u32; 2], isize> {
    let Some(i) = with(|t| t.iter().position(|r| !r.used).inspect(|&i| t[i].used = true)) else {
        return Err(E_MFILE);
    };
    let fail = |e: isize| {
        with(|t| t[i] = FREE);
        Err(e)
    };
    let pages = region_pages();
    let cap = shm_create_typed(pages as u64, SHM_RW);
    if cap < 0 {
        return fail(cap);
    }
    let cap = cap as u32;
    let va = shm_map_typed(cap);
    if va < 0 {
        let _ = shm_release_typed(cap);
        return fail(va);
    }
    let Some(ring) = BytePipe::cap_for(pages * PAGE_SIZE) else {
        let _ = shm_release_typed(cap);
        return fail(E_INVAL);
    };
    // SAFETY: a fresh region this process just mapped, `pages` pages long, at
    // an address the kernel aligned to a page; nobody else holds it yet.
    let Some(pipe) = (unsafe { BytePipe::init(va as usize, ring) }) else {
        let _ = shm_release_typed(cap);
        return fail(E_INVAL);
    };
    with(|t| t[i] = Rec { used: true, cap, pipe: Some(pipe), open: [true; 2], nonblock: [false; 2] });
    Ok([token(i, End::Read), token(i, End::Write)])
}

/// Take a received region (`handle`, a `Cap<Shm>` in this process's table) as
/// the `end` of a pipe: map it and read its header. The sender counted this
/// end; nothing is added. The same region and end again answer the same token.
/// `None` if the region is not a pipe or the process holds no room for it.
pub fn adopt(handle: u32, end: End) -> Option<u32> {
    if let Some(t) = with(|t| {
        t.iter().position(|r| r.used && r.cap == handle).map(|i| {
            t[i].open[slot(end)] = true;
            token(i, end)
        })
    }) {
        return Some(t);
    }
    let i = with(|t| t.iter().position(|r| !r.used).inspect(|&i| t[i].used = true))?;
    let mut info = [0u8; SHM_INFO_BYTES];
    let undo = |release: bool| {
        if release {
            let _ = shm_release_typed(handle);
        }
        with(|t| t[i] = FREE);
        None
    };
    if shm_acquire_typed(handle, &mut info) < 0 {
        return undo(false);
    }
    let pages = u32::from_le_bytes([info[0], info[1], info[2], info[3]]) as usize;
    let va = shm_map_typed(handle);
    if va < 0 {
        return undo(false);
    }
    // SAFETY: `va` is the start of this process's mapping of `pages` pages.
    let Some(pipe) = (unsafe { BytePipe::open(va as usize, pages * PAGE_SIZE) }) else {
        return undo(true);
    };
    let mut open = [false; 2];
    open[slot(end)] = true;
    with(|t| t[i] = Rec { used: true, cap: handle, pipe: Some(pipe), open, nonblock: [false; 2] });
    Some(token(i, end))
}

/// Turn the pipe ends of a startup block's fd list into tokens: a `Cap<Shm>`
/// at fd 0 is a read end, at any other fd a write end (two fds naming one
/// region and end share a token, as `2>&1` aliases a handle). A region that is
/// not a pipe closes the fd. Other entries are left as they are.
pub fn adopt_startup(fds: &mut [azos_abi::ushell::StartupFd; azos_abi::ushell::STARTUP_FDS]) {
    use azos_abi::{cap::{ty, CapHandle}, ushell::{FD_CLOSED, FD_HANDLE}};
    for (fd, f) in fds.iter_mut().enumerate() {
        if f.kind == FD_HANDLE && CapHandle::from_raw(f.handle).kind() == ty::SHM.raw() {
            match adopt(f.handle, if fd == 0 { End::Read } else { End::Write }) {
                Some(t) => f.handle = t,
                None => *f = azos_abi::ushell::StartupFd { kind: FD_CLOSED, handle: 0 },
            }
        }
    }
}

/// The pipe and flags behind `tok`, if this process holds that end.
fn lookup(tok: u32) -> Option<(BytePipe, End, bool)> {
    if !is_token(tok) {
        return None;
    }
    let (i, end) = parts(tok);
    with(|t| {
        let r = &t[i];
        (r.used && r.open[slot(end)]).then(|| (r.pipe, end, r.nonblock[slot(end)]))
    })
    .and_then(|(p, e, nb)| p.map(|p| (p, e, nb)))
}

fn errno(e: PipeError) -> isize {
    match e {
        PipeError::WouldBlock => E_AGAIN,
        PipeError::Broken => E_PIPE,
        PipeError::Interrupted => E_INTR,
    }
}

/// Read from the read end `tok`: bytes read, 0 at end of file, or a negative
/// errno (`-EAGAIN` for a non-blocking read of an empty pipe).
pub fn read(tok: u32, buf: &mut [u8]) -> isize {
    match lookup(tok) {
        Some((p, End::Read, nb)) => match p.read(&Bell, buf, nb) {
            Ok(n) => n as isize,
            Err(e) => errno(e),
        },
        _ => E_BADF,
    }
}

/// Write to the write end `tok`: bytes written, or a negative errno
/// (`-EPIPE` when no reader is left: the caller raises its alert).
pub fn write(tok: u32, buf: &[u8]) -> isize {
    match lookup(tok) {
        Some((p, End::Write, nb)) => match p.write(&Bell, buf, nb) {
            Ok(n) => n as isize,
            Err(e) => errno(e),
        },
        _ => E_BADF,
    }
}

/// Set `O_NONBLOCK` on the description `tok` names.
pub fn set_nonblock(tok: u32, on: bool) -> isize {
    if !is_token(tok) {
        return E_BADF;
    }
    let (i, end) = parts(tok);
    with(|t| {
        if t[i].used && t[i].open[slot(end)] {
            t[i].nonblock[slot(end)] = on;
            0
        } else {
            E_BADF
        }
    })
}

/// Which end `tok` is.
pub fn end_of(tok: u32) -> Option<End> {
    lookup(tok).map(|(_, e, _)| e)
}

/// The last close of the description `tok` names: the end is given up to the
/// kernel (the last writer's wakes the readers, the last reader's the
/// writers), and the region is released when the process holds neither end.
pub fn close(tok: u32) -> isize {
    if !is_token(tok) {
        return E_BADF;
    }
    let (i, end) = parts(tok);
    let got = with(|t| {
        let r = &mut t[i];
        if !(r.used && r.open[slot(end)]) {
            return None;
        }
        r.open[slot(end)] = false;
        r.nonblock[slot(end)] = false;
        let gone = !r.open[0] && !r.open[1];
        let cap = r.cap;
        if gone {
            *r = FREE;
        }
        Some((cap, gone))
    });
    let Some((cap, gone)) = got else { return E_BADF };
    // The kernel counts the ends: it drops this process's hold on `end` and
    // wakes the peers when it was the last.
    let _ = shm_end_drop_typed(cap, if end == End::Write { SHM_END_WRITE } else { SHM_END_READ });
    if gone {
        let _ = shm_release_typed(cap);
    }
    0
}

/// The region behind `tok` and the end it is, for a spawn's move list: the
/// capability goes in the list (the kernel derives a copy for the child and
/// counts the end its fd position names) and this process keeps its own end.
pub fn region_of(tok: u32) -> Result<(u32, End), isize> {
    let Some((_, end, _)) = lookup(tok) else { return Err(E_BADF) };
    let (i, _) = parts(tok);
    Ok((with(|t| t[i].cap), end))
}

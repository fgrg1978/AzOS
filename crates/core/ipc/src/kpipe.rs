// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's own calls on a POSIX byte pipe.
//!
//! A pipe is a `Cap<Shm>` region with a byte ring in it (`azos_bytepipe`); a
//! ring-3 program maps the region and runs the ring itself. A program under the
//! in-kernel Linux personality has no mapping of it: the personality's `pipe2`
//! creates the region ([`create`]) and its `read` and `write` run the same ring
//! from the kernel ([`KPipe`]), through the direct map, with the futex as the
//! doorbell. The region, the end counts, the lock words and the wakes are the
//! ones a ring-3 pipe has, so a ring-3 peer of the same region sleeps on and
//! is woken by the same `Key::Shared` words.
//!
//! There is no pipe table and no pipe object here: the region is the pipe, and
//! this module is the kernel's view of it.
//!
//! A region is `Anon`, one frame per page, whoever made it (the personality's
//! `pipe2` or a native `azos_libsys::pipe::create`): the kernel reaches each
//! page through the direct map and copies the data page by page
//! (`azos_bytepipe::BytePipe::open_scattered`), so a pipe a native parent made
//! and handed to a Linux child in a spawn's move list is read and written like
//! the child's own. The kernel mutates the ring, so [`KPipe::open`] needs a
//! read-write region and the callers hold the capability with both rights.

use crate::cap::{targets::Shm, Cap, CapPerms};
use crate::memobj::{
    memobj_create_cap, memobj_frames_pin, memobj_frames_unpin, memobj_release_cap, MemObjError, MemPerms, MemSpec,
};
use azos_bytepipe::{BytePipe, PipeError, Scatter, Slept, Sys, HEADER_BYTES, SCATTER_MAX};
use azos_sched::futex::{self, Key};
use core::sync::atomic::{AtomicU32, Ordering};

/// Data bytes a new pipe aims at (the region is the frames that hold this and
/// the header; the ring takes the largest power of two that fits).
const TARGET_DATA: usize = 16384;

/// How long a sleep on a ring word lasts at most: a wake that never comes costs
/// this much (the backstop the ring-3 pipes use).
const RING_WAIT_NS: u64 = 1_000_000_000;

/// Frames of a new pipe's region.
pub const PAGES: usize = (TARGET_DATA + HEADER_BYTES).div_ceil(azos_arch::PAGE_SIZE);

/// Make a pipe for process `tid`: a region, started with one reader and one
/// writer, both held by `tid`, and its capability.
pub fn create(tid: u32) -> Result<Cap<Shm>, MemObjError> {
    const { assert!(PAGES <= SCATTER_MAX) };
    let cap = memobj_create_cap(tid, PAGES, &MemSpec::anon(MemPerms::ReadWrite))?;
    let undo = |e: MemObjError| {
        let _ = crate::cap_store::with_table(tid, |t| memobj_release_cap(tid, t, cap));
        e
    };
    let r = crate::cap_store::get(tid, cap, CapPerms::RW).map_err(|e| undo(e.into()))?;
    let mut frames = [0usize; SCATTER_MAX];
    let n = memobj_frames_pin(r, &mut frames).map_err(undo)?;
    let started = BytePipe::cap_for(n * azos_arch::PAGE_SIZE)
        // SAFETY: the header page of a region created a moment ago, which no
        // other task holds yet; `init` writes the header only, and
        // `memobj_frames_pin` keeps the frames.
        .and_then(|ring| unsafe { BytePipe::init(frames[0], ring) });
    memobj_frames_unpin(r);
    if started.is_none() {
        return Err(undo(MemObjError::BadArg));
    }
    Ok(cap)
}

/// The doorbell: the kernel futex on the region's words.
struct Bell {
    /// The region's packed reference (the futex key's object).
    r: u32,
    /// The direct-map address of the region's first byte.
    base: usize,
}

impl Bell {
    fn key(&self, addr: usize) -> Key {
        Key::Shared { obj: self.r, offset: (addr - self.base) as u32 }
    }
}

impl Sys for Bell {
    fn wait(&self, addr: usize, expected: u32) -> Slept {
        // SAFETY: a word of the pinned region, 4-aligned (the header's words).
        let word = unsafe { &*(addr as *const AtomicU32) };
        let deadline = azos_drv_sys::timebase::now()
            .saturating_add(azos_abi::time::ns_to_ticks_ceil(RING_WAIT_NS, azos_drv_sys::timebase::TIMER_FREQ));
        let rc = futex::wait_key(self.key(addr), expected, Some(deadline), &|| Some(word.load(Ordering::Acquire)));
        if rc == -futex::EINTR { Slept::Interrupted } else { Slept::Again }
    }

    fn wake(&self, addr: usize) {
        let _ = futex::wake_key(self.key(addr), u32::MAX);
    }

    fn me(&self) -> u32 {
        azos_sched::current_proc_tid()
    }
}

/// The kernel's view of a pipe region while a call runs: the frames are pinned
/// for as long as it lives.
pub struct KPipe {
    bell: Bell,
    pipe: BytePipe,
}

impl KPipe {
    /// View the region `r` (a packed reference the caller resolved from a
    /// capability it holds with read and write rights). `BadArg` for a region
    /// that is no pipe, is read-only, is longer than [`SCATTER_MAX`] pages or
    /// is not in the direct map.
    pub fn open(r: u32) -> Result<KPipe, MemObjError> {
        let mut frames = [0usize; SCATTER_MAX];
        let n = memobj_frames_pin(r, &mut frames)?;
        // SAFETY: the frames are the direct-map pages of a live region, kept
        // by the pin until this view drops.
        let pipe = Scatter::new(azos_arch::PAGE_SIZE, &frames[..n]).and_then(|sc| unsafe { BytePipe::open_scattered(sc) });
        match pipe {
            Some(pipe) => Ok(KPipe { bell: Bell { r, base: frames[0] }, pipe }),
            None => {
                memobj_frames_unpin(r);
                Err(MemObjError::BadArg)
            }
        }
    }

    /// Read from the pipe (`azos_bytepipe::BytePipe::read`): bytes read, 0 at
    /// end of file.
    pub fn read(&self, buf: &mut [u8], nonblock: bool) -> Result<usize, PipeError> {
        self.pipe.read(&self.bell, buf, nonblock)
    }

    /// Write to the pipe (`azos_bytepipe::BytePipe::write`). Kconfig CHAOS,
    /// point `ipc-send`: refused as a pipe with no room is, before anything is
    /// written.
    pub fn write(&self, buf: &[u8], nonblock: bool) -> Result<usize, PipeError> {
        if azos_chaos::fire(azos_chaos::Point::IpcSend) {
            return Err(PipeError::WouldBlock);
        }
        self.pipe.write(&self.bell, buf, nonblock)
    }
}

impl Drop for KPipe {
    fn drop(&mut self) {
        memobj_frames_unpin(self.bell.r);
    }
}

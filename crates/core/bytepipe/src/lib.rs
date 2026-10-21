// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! The POSIX byte pipe, as a ring in a `Cap<Shm>` region.
//!
//! A pipe is a [`azos_rings::region::SpscStream`] (the byte form of the one
//! SPSC index protocol) in a shared-memory region both ends map, a header of
//! end counts and sleep events beside it, and the futex as the doorbell. Data
//! moves with no kernel entry unless a side has to sleep or the other side
//! said it may be asleep: the native ABI keeps syscalls for authority and for
//! sleeping, and a pipe is neither.
//!
//! What POSIX needs on top of a ring, and where it is emulated:
//!
//! * **EOF on the last writer's close.** The region counts its writer ends
//!   ([`BytePipe::writers`]); a read of an empty pipe with none left answers
//!   `Ok(0)` after one more look at the ring (the writer published before it
//!   left). [`Header::drop_end`] wakes a reader that was asleep.
//! * **EPIPE when no reader is left.** A write with no reader end answers
//!   [`PipeError::Broken`]: the caller raises its alert (the Linux runtime's
//!   `SIGPIPE`, a native program's `-EPIPE`). A writer asleep on a full ring
//!   is woken by the last reader's close and answers the same.
//! * **`O_NONBLOCK`.** A flag of the *open file description*, so it is an
//!   argument of each call and lives with the caller's description, not in
//!   the region: [`PipeError::WouldBlock`] where a blocking call would sleep.
//! * **`PIPE_BUF` atomic writes.** A write of at most [`PIPE_BUF`] bytes goes
//!   in whole or not at all, under the writer lock, never split around
//!   another writer's bytes; a larger one is written in pieces as room
//!   appears and may interleave with other writers, as POSIX allows.
//!
//! # Several ends, one ring
//!
//! POSIX lets a pipe end be held by many processes (a fork copies the table,
//! `2>&1` names one end twice). The ring is single-producer single-consumer,
//! so the writers take a lock word in the header (`Lock`) around the part
//! of a call that touches the head, and the readers one around the tail. The
//! lock is a futex mutex and is only contended between processes that write
//! (or read) the same pipe at the same moment.
//!
//! # End counts are the kernel's business
//!
//! Who holds which end of a pipe is kept by the kernel, per holding process
//! (a field of its record of the region), and the kernel is the only writer
//! of the two count words: a program that dies at any instruction (a fault,
//! a force-kill) cannot leave a count it had already given up, nor give one up
//! half way. The calls are [`Header`]'s, which the kernel runs on the region's
//! first page (it needs no mapping of the whole ring):
//!
//! * the creator starts the pipe with one reader and one writer
//!   ([`BytePipe::init`]); its record holds both;
//! * a spawn's move list and a fork hand a region over: the kernel counts the
//!   child's ends ([`Header::add_end`]) in the same step that gives it the
//!   capability, the fork giving it what the parent holds, the move list the
//!   end its fd position names (fd 0 reads, any other fd writes);
//! * a process gives an end up with `MEMOBJ_END_DROP`
//!   ([`Header::drop_end`]), once per end, when the last description naming
//!   it closes;
//! * the death of a process gives up whatever it still holds, and releases a
//!   lock word it died owning ([`Header::recover_locks`]).
//!
//! Programs only load the counts ([`BytePipe::writers`], [`BytePipe::readers`]).
//!
//! # The two lock words
//!
//! The writer lock and the reader lock hold the owner's process id above two
//! flag bits (locked, waiters), so the kernel can tell that a dying process
//! was the one holding it and open it for the others. That is safe because the
//! ring publishes an index only after the bytes are copied: a writer killed
//! mid-copy published nothing, a reader killed mid-copy consumed nothing.
//!
//! # Sleeping
//!
//! A reader loads the read event, looks, announces, looks again and sleeps on
//! the event word only if it is unchanged; whoever makes the reader's
//! condition true changes the state first and then bumps the event and wakes.
//! The event word is what the futex compares, so a wake that lands between the
//! reader's last look and its sleep still returns the sleep at once (a state
//! that is not a byte, such as the last writer leaving, changes no ring index
//! and would otherwise be lost). The writers' side is the mirror.

pub use azos_rings::region::{Scatter, SCATTER_MAX};
use azos_rings::region::{RingStep, SpscStream, RING_SLOTS};
use core::sync::atomic::{AtomicU32, Ordering};

/// A write of at most this many bytes is atomic (POSIX `PIPE_BUF` minimum
/// 512; Linux and the old kernel pipe: 4096).
pub const PIPE_BUF: usize = 4096;

/// Bytes of header before the data (the ring header of
/// [`azos_rings::region`], plus this crate's words in its spare space).
pub const HEADER_BYTES: usize = RING_SLOTS;

/// The header's word naming a pipe region (`"BPIP"`).
const MAGIC: u32 = u32::from_le_bytes(*b"BPIP");

// Words of the header past the four the ring protocol owns (RING_HEAD 0,
// RING_TAIL 64, RING_CONS_WAIT 128, RING_PROD_WAIT 192): each is a u32 at an
// offset no ring word uses.
const H_MAGIC: usize = 4;
const H_CAP: usize = 8;
const H_WRITERS: usize = 12;
const H_READERS: usize = 16;
/// Bumped before a wake of the readers; the word they sleep on.
const H_RD_EVENT: usize = 20;
/// Bumped before a wake of the writers; the word they sleep on.
const H_WR_EVENT: usize = 24;
const H_WLOCK: usize = 32;
const H_RLOCK: usize = 36;

// A lock word: 0 free, else the owner's id above two flag bits.
const LOCKED: u32 = 1;
/// Somebody sleeps on the word: the unlock wakes.
const WAITERS: u32 = 2;
const LOCK_OWNER_SHIFT: u32 = 2;

/// Which end of a pipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Read,
    Write,
}

/// Why a call did not move bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeError {
    /// `O_NONBLOCK`: a blocking call would have slept (`EAGAIN`).
    WouldBlock,
    /// A write with no reader end left (`EPIPE`, and the caller's alert).
    Broken,
    /// The sleep ended without the condition: a stop request (`EINTR`).
    Interrupted,
}

/// How a sleep ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slept {
    /// A wake, a changed word, or a backstop timeout: look again.
    Again,
    /// A stop request (the futex answered an interrupt).
    Interrupted,
}

/// The doorbell: the kernel's futex, keyed by region and offset (the address
/// is the caller's own mapping of the word). Implemented over `azos_libsys`
/// in the image, by a model in the host tests.
pub trait Sys {
    /// Sleep while the word at `addr` equals `expected`.
    fn wait(&self, addr: usize, expected: u32) -> Slept;
    /// Wake every sleeper on the word at `addr`.
    fn wake(&self, addr: usize);
    /// The calling process's id, the owner a lock word records (below
    /// [`MAX_OWNER`]; 0 names nobody, so the kernel never recovers it).
    fn me(&self) -> u32;
}

/// The largest process id a lock word can name: the owner sits above the two
/// flag bits.
pub const MAX_OWNER: u32 = u32::MAX >> LOCK_OWNER_SHIFT;

/// A view of one pipe at `base` (a mapping of at least
/// [`BytePipe::region_bytes`] bytes, 64-byte aligned).
#[derive(Clone, Copy, Debug)]
pub struct BytePipe {
    base: usize,
    ring: SpscStream,
    /// `Some`: the data pages are the frames of a region the kernel views
    /// through its direct map ([`BytePipe::open_scattered`]), not one run.
    scatter: Option<Scatter>,
}

fn word(base: usize, off: usize) -> &'static AtomicU32 {
    // SAFETY: `base` is a mapping at least HEADER_BYTES long, 4-byte aligned
    // (64 by the constructors' contract), shared only with holders that use
    // this layout; the words are atomics.
    unsafe { &*((base + off) as *const AtomicU32) }
}

/// The pipe's counts and locks, seen through the first words of the region:
/// all the kernel needs of a pipe it does not map (the end counts, the lock
/// words and the events a count reaching zero rings). `Copy`, like the view
/// of the whole pipe it belongs to ([`BytePipe::header`]).
#[derive(Clone, Copy, Debug)]
pub struct Header {
    base: usize,
}

impl Header {
    /// The header of the pipe at `base`, if the word at its magic offset names
    /// one. `base` is the start of a region's first page.
    ///
    /// # Safety
    /// `base` is the start of a mapping (or the kernel's view) of at least
    /// [`HEADER_BYTES`] bytes, 64-byte aligned, that stays valid for as long
    /// as the returned view is used.
    pub unsafe fn at(base: usize) -> Option<Header> {
        (base % 64 == 0 && word(base, H_MAGIC).load(Ordering::Acquire) == MAGIC).then_some(Header { base })
    }

    fn count(&self, end: End) -> &'static AtomicU32 {
        word(self.base, if end == End::Write { H_WRITERS } else { H_READERS })
    }

    /// One more holder process of `end` (the kernel, handing the end over).
    /// `false` if the count has no room left to grow.
    pub fn add_end(&self, end: End) -> bool {
        self.count(end)
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
            .is_ok()
    }

    /// One holder process of `end` is gone. When that was the last, the sleepers
    /// on the other side must look again (the last writer: the readers see end
    /// of file; the last reader: the writers see `EPIPE`): the event word they
    /// sleep on is bumped and `wake` is called with its offset in the region,
    /// for the caller to wake whatever sleeps there. A drop with no holder left
    /// to drop is ignored: a count never wraps.
    pub fn drop_end(&self, end: End, wake: impl FnOnce(usize)) {
        let left = match self.count(end).fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)) {
            Ok(was) => was - 1,
            Err(_) => return,
        };
        if left != 0 {
            return;
        }
        let event = if end == End::Write { H_RD_EVENT } else { H_WR_EVENT };
        word(self.base, event).fetch_add(1, Ordering::SeqCst);
        wake(event);
    }

    /// Open the writer and reader locks the process `owner` died holding, and
    /// call `wake` with the offset of each, for the sleepers on it. `owner` 0
    /// names nobody and opens nothing.
    pub fn recover_locks(&self, owner: u32, mut wake: impl FnMut(usize)) {
        if owner == 0 || owner > MAX_OWNER || cfg!(feature = "canary-no-lock-recovery") {
            return;
        }
        for off in [H_WLOCK, H_RLOCK] {
            let w = word(self.base, off);
            let mut v = w.load(Ordering::Acquire);
            while v & LOCKED != 0 && v >> LOCK_OWNER_SHIFT == owner {
                match w.compare_exchange(v, 0, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => {
                        wake(off);
                        break;
                    }
                    Err(now) => v = now,
                }
            }
        }
    }

    /// Writer ends alive (a snapshot).
    pub fn writers(&self) -> u32 {
        self.count(End::Write).load(Ordering::SeqCst)
    }

    /// Reader ends alive (a snapshot).
    pub fn readers(&self) -> u32 {
        self.count(End::Read).load(Ordering::SeqCst)
    }
}

impl BytePipe {
    /// Bytes of a region for a pipe of `cap` data bytes.
    pub const fn region_bytes(cap: u32) -> usize {
        SpscStream::bytes(cap)
    }

    /// The data capacity a region of `bytes` bytes holds: the largest power
    /// of two that fits after the header, `None` if it is below
    /// [`PIPE_BUF`].
    pub fn cap_for(bytes: usize) -> Option<u32> {
        let room = bytes.checked_sub(HEADER_BYTES)?;
        if room < PIPE_BUF {
            return None;
        }
        let cap = 1usize << (usize::BITS - 1 - room.leading_zeros());
        u32::try_from(cap.min(1 << 30)).ok()
    }

    /// Start a pipe in a fresh region: header zeroed, geometry written, one
    /// reader and one writer (the creator's own two ends, which the kernel's
    /// record of the creator holds). `None` if `cap` is not a power of two of
    /// at least [`PIPE_BUF`], or `base` is not 64-byte aligned.
    ///
    /// # Safety
    /// `base` is the start of a writable mapping of at least
    /// [`BytePipe::region_bytes`]`(cap)` bytes that no other holder uses yet.
    /// (`init` writes the header only, so a creator that reaches the region
    /// page by page may pass its first frame and drop the result.)
    pub unsafe fn init(base: usize, cap: u32) -> Option<BytePipe> {
        if base % 64 != 0 || !cap.is_power_of_two() || (cap as usize) < PIPE_BUF || cap > 1 << 30 {
            return None;
        }
        let ring = SpscStream { base, cap };
        ring.init();
        for off in [H_WRITERS, H_READERS, H_RD_EVENT, H_WR_EVENT, H_WLOCK, H_RLOCK] {
            word(base, off).store(0, Ordering::Relaxed);
        }
        word(base, H_WRITERS).store(1, Ordering::Relaxed);
        word(base, H_READERS).store(1, Ordering::Relaxed);
        word(base, H_CAP).store(cap, Ordering::Relaxed);
        word(base, H_MAGIC).store(MAGIC, Ordering::Release);
        Some(BytePipe { base, ring, scatter: None })
    }

    /// The pipe another holder created in the `mapped` bytes at `base`, if
    /// the header names a pipe whose geometry fits.
    ///
    /// # Safety
    /// `base` is the start of a mapping of `mapped` bytes, 64-byte aligned.
    pub unsafe fn open(base: usize, mapped: usize) -> Option<BytePipe> {
        if base % 64 != 0 || mapped < HEADER_BYTES || word(base, H_MAGIC).load(Ordering::Acquire) != MAGIC {
            return None;
        }
        let cap = word(base, H_CAP).load(Ordering::Relaxed);
        if !cap.is_power_of_two() || (cap as usize) < PIPE_BUF || Self::region_bytes(cap) > mapped {
            return None;
        }
        Some(BytePipe { base, ring: SpscStream { base, cap }, scatter: None })
    }

    /// The pipe another holder created in a region whose frames are `scatter`
    /// (the kernel's direct map of a ring-3 region, one frame per page); the
    /// header is in the first frame. The data is copied page by page.
    ///
    /// # Safety
    /// `scatter` names live frames of one region, valid for as long as the
    /// pipe is used.
    pub unsafe fn open_scattered(scatter: Scatter) -> Option<BytePipe> {
        // SAFETY: the first frame is the region's start; the contract.
        let mut p = unsafe { Self::open(scatter.first(), scatter.bytes()) }?;
        p.scatter = Some(scatter);
        Some(p)
    }

    /// The counts and locks of this pipe, as the kernel sees them.
    pub fn header(&self) -> Header {
        Header { base: self.base }
    }

    /// Bytes in the pipe now (a snapshot).
    pub fn len(&self) -> u32 {
        self.ring.len()
    }

    /// Writer ends alive (a snapshot).
    pub fn writers(&self) -> u32 {
        self.header().writers()
    }

    /// Reader ends alive (a snapshot).
    pub fn readers(&self) -> u32 {
        self.header().readers()
    }

    fn ring_bell<S: Sys>(&self, sys: &S, event: usize) {
        word(self.base, event).fetch_add(1, Ordering::SeqCst);
        sys.wake(self.base + event);
    }

    // ---- locks ------------------------------------------------------------

    fn lock<'a, S: Sys>(&self, sys: &'a S, off: usize) -> Lock<'a, S> {
        let w = word(self.base, off);
        // The owner is a process id; an id too wide to fit above the flag bits
        // is recorded as nobody (never recovered, still a lock).
        let me = sys.me();
        let mine = LOCKED | if me <= MAX_OWNER { me << LOCK_OWNER_SHIFT } else { 0 };
        loop {
            let v = w.load(Ordering::Relaxed);
            if v == 0 {
                if w.compare_exchange(0, mine, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    break;
                }
                continue;
            }
            // Held: say that somebody sleeps, so the unlock wakes, and sleep
            // while the word is as it was.
            let want = v | WAITERS;
            if v & WAITERS == 0 && w.compare_exchange(v, want, Ordering::Relaxed, Ordering::Relaxed).is_err() {
                continue;
            }
            let _ = sys.wait(self.base + off, want);
        }
        Lock { sys, addr: self.base + off, w }
    }

    // ---- read -------------------------------------------------------------

    /// Read up to `buf.len()` bytes. Blocks while the pipe is empty and a
    /// writer is left, unless `nonblock`. `Ok(0)` is end of file (empty, no
    /// writer left) — or an empty `buf`.
    pub fn read<S: Sys>(&self, sys: &S, buf: &mut [u8], nonblock: bool) -> Result<usize, PipeError> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let ev = word(self.base, H_RD_EVENT).load(Ordering::Acquire);
            // Writers before bytes: a writer publishes, then leaves, so
            // "none left" seen first means the bytes are already visible.
            let gone = self.writers() == 0;
            if let Some(n) = self.take(sys, buf) {
                return Ok(n);
            }
            if gone && !cfg!(feature = "canary-no-eof") {
                return Ok(0);
            }
            if nonblock && !cfg!(feature = "canary-block-nonblock") {
                return Err(PipeError::WouldBlock);
            }
            self.ring.announce_consumer();
            if !self.ring.is_empty() || self.writers() == 0 {
                continue;
            }
            if sys.wait(self.base + H_RD_EVENT, ev) == Slept::Interrupted {
                return Err(PipeError::Interrupted);
            }
        }
    }

    /// One locked read of what is there. `None` when the ring is empty.
    fn take<S: Sys>(&self, sys: &S, buf: &mut [u8]) -> Option<usize> {
        if self.ring.is_empty() {
            return None;
        }
        let g = self.lock(sys, H_RLOCK);
        let (n, step) = match &self.scatter {
            None => self.ring.read(buf),
            // SAFETY: `open_scattered`'s contract.
            Some(sc) => unsafe { self.ring.read_scattered(buf, sc) },
        };
        drop(g);
        if n == 0 {
            return None;
        }
        if matches!(step, RingStep::DoneWake { .. }) {
            self.ring_bell(sys, H_WR_EVENT);
        }
        Some(n)
    }

    // ---- write ------------------------------------------------------------

    /// Write `buf`. A write of at most [`PIPE_BUF`] bytes is atomic. Blocks
    /// while the pipe has no room, unless `nonblock`; a non-blocking write
    /// that moved some bytes answers their count, one that moved none
    /// [`PipeError::WouldBlock`]. [`PipeError::Broken`] when no reader end is
    /// left (with some bytes already written, their count first).
    pub fn write<S: Sys>(&self, sys: &S, buf: &[u8], nonblock: bool) -> Result<usize, PipeError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let atomic = buf.len() <= PIPE_BUF && !cfg!(feature = "canary-split-atomic");
        let mut done = 0usize;
        loop {
            if self.readers() == 0 && !cfg!(feature = "canary-no-epipe") {
                return if done > 0 { Ok(done) } else { Err(PipeError::Broken) };
            }
            let ev = word(self.base, H_WR_EVENT).load(Ordering::Acquire);
            let need = if atomic { buf.len() - done } else { 1 };
            if let Some(n) = self.put(sys, &buf[done..], need) {
                done += n;
                if done == buf.len() {
                    return Ok(done);
                }
                continue;
            }
            if nonblock && !cfg!(feature = "canary-block-nonblock") {
                return if done > 0 { Ok(done) } else { Err(PipeError::WouldBlock) };
            }
            self.ring.announce_producer();
            if self.ring.free() as usize >= need || self.readers() == 0 {
                continue;
            }
            if sys.wait(self.base + H_WR_EVENT, ev) == Slept::Interrupted {
                return if done > 0 { Ok(done) } else { Err(PipeError::Interrupted) };
            }
        }
    }

    /// One locked write of `src` if at least `need` bytes of room are there
    /// (all of `src` that fits, so an atomic write, whose `need` is its
    /// length, lands whole). `None` when there is not.
    fn put<S: Sys>(&self, sys: &S, src: &[u8], need: usize) -> Option<usize> {
        if (self.ring.free() as usize) < need {
            return None;
        }
        let g = self.lock(sys, H_WLOCK);
        // Under the lock the room can only have grown (readers free it,
        // other writers are shut out).
        if (self.ring.free() as usize) < need {
            return None;
        }
        let (n, step) = match &self.scatter {
            None => self.ring.write(src),
            // SAFETY: `open_scattered`'s contract.
            Some(sc) => unsafe { self.ring.write_scattered(src, sc) },
        };
        drop(g);
        if n == 0 {
            return None;
        }
        if matches!(step, RingStep::DoneWake { .. }) {
            self.ring_bell(sys, H_RD_EVENT);
        }
        Some(n)
    }
}

/// A held lock word; the drop is the unlock.
struct Lock<'a, S: Sys> {
    sys: &'a S,
    addr: usize,
    w: &'static AtomicU32,
}

impl<S: Sys> Drop for Lock<'_, S> {
    fn drop(&mut self) {
        if self.w.swap(0, Ordering::Release) & WAITERS != 0 {
            self.sys.wake(self.addr);
        }
    }
}

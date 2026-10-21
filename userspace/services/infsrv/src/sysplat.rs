// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The service's [`Platform`] on the real system calls.
//!
//! The only code of the image that maps a client's memory: a tensor arrives as
//! a memory object moved with the call, is mapped for the length of the run
//! and released after it (`SYS_MO_MAP`, `SYS_MO_UNMAP`: an unmap that also
//! revokes the moved capability, so nothing of the call outlives it).
//!
//! The other memory it owns is the blob arena, a volatile memory object
//! (`SHM_ATTR_VOLATILE`): marked droppable between calls through the kernel's
//! `memctl` endpoint and held while a call reads it, so the system can take it
//! back under pressure without writing it anywhere, and the service loads the
//! bundles again when it finds it gone (`Service::resume_blobs`).

use crate::bundles;
use azos_abi::syscall_nr::{SHM_ATTR_VOLATILE, SHM_CREATE_ATTR_SHIFT};
use azos_idl::Cap;
use azos_libsys as sys;
use infsrv::config::{BLOB_BYTES, CONTEXTS};
use infsrv::load::Arena;
use infsrv::broker::Broker;
use infsrv::service::{Blobs, LogObject, Platform, TensorError};
use infsrv::verdict;
use sys::dev::{MemCtlCall, MemCtlClient};

use crate::out::Line;

/// The blob arena's memory object and what the system may do with it.
struct BlobMem {
    /// The object, while there is one.
    cap: Option<u32>,
    /// Marked droppable (`set_volatile`) and not yet held again.
    droppable: bool,
}

pub struct SysPlatform {
    /// The memory object of each context's verdict log and its size.
    pub logs: [Option<(u32, u32)>; CONTEXTS],
    blobs: BlobMem,
    /// The kernel's `memctl` endpoint; none when the row grants none, and then
    /// the arena is never marked droppable (and never taken back).
    memctl: Option<u32>,
    /// The port the kernel reports this Domain's memory pressure on, and the
    /// last level it reported (0 normal, 1 warning, 2 critical). The port is
    /// made once and kept for the life of the program.
    pressure: Option<u32>,
    level: u8,
}

/// One mapped region: where, how long, whether writable.
struct Mapped {
    base: *mut u8,
    len: usize,
}

/// Map the memory object `cap`. `need_write`: refuse a read-only one.
fn map(cap: u32, need_write: bool) -> Result<Mapped, TensorError> {
    let mut info = [0u8; sys::SHM_INFO_BYTES];
    if sys::shm_acquire_typed(cap, &mut info) < 0 {
        return Err(TensorError::Unmappable);
    }
    let pages = u32::from_le_bytes([info[0], info[1], info[2], info[3]]) as usize;
    if need_write && info[4] == 0 {
        return Err(TensorError::ReadOnly);
    }
    let va = sys::shm_map_typed(cap);
    if va <= 0 {
        return Err(TensorError::Unmappable);
    }
    Ok(Mapped { base: va as *mut u8, len: pages * sys::PAGE_SIZE })
}

impl Platform for SysPlatform {
    fn now_ns(&self) -> u64 {
        sys::vdso_now_ns()
    }

    fn with_tensors(
        &mut self,
        input: u32,
        output: u32,
        f: &mut dyn FnMut(&[u8], &mut [u8], &dyn Fn() -> u64),
    ) -> Result<(), TensorError> {
        let i = map(input, false);
        let o = if i.is_ok() { map(output, true) } else { Err(TensorError::Unmappable) };
        let r = match (&i, &o) {
            (Ok(i), Ok(o)) => {
                // SAFETY: both regions are mapped until the releases below, and
                // are two different regions (the second map of one region
                // fails). A peer that still holds the memory may change it under
                // us; that corrupts its own tensor and nothing else.
                let (inp, outp) = unsafe {
                    (core::slice::from_raw_parts(i.base, i.len), core::slice::from_raw_parts_mut(o.base, o.len))
                };
                f(inp, outp, &sys::vdso_now_ns);
                Ok(())
            }
            (Err(e), _) | (_, Err(e)) => Err(*e),
        };
        // Release gives the mapping back and revokes the capability; the one
        // that was never mapped is closed all the same.
        let _ = sys::shm_release_typed(input);
        let _ = sys::shm_release_typed(output);
        r
    }

    fn drop_cap(&mut self, cap: u32) {
        let _ = sys::shm_release_typed(cap);
    }

    fn log_region(&mut self, slot: usize) -> Option<LogObject> {
        if let Some((cap, bytes)) = *self.logs.get(slot)? {
            return Some(LogObject { cap, bytes, fresh: None });
        }
        let pages = verdict::region_bytes().div_ceil(sys::PAGE_SIZE);
        let cap = sys::shm_create_typed(pages as u64, sys::SHM_RW);
        if cap < 0 {
            return None;
        }
        let va = sys::shm_map_typed(cap as u32);
        if va <= 0 {
            let _ = sys::shm_release_typed(cap as u32);
            return None;
        }
        let bytes = (pages * sys::PAGE_SIZE) as u32;
        self.logs[slot] = Some((cap as u32, bytes));
        // The mapping is ours alone (nothing else holds the capability yet),
        // writable, page-aligned, and stays for the life of the program.
        Some(LogObject { cap: cap as u32, bytes, fresh: Some(va as *mut u8) })
    }

    fn blobs_resume(&mut self) -> Blobs {
        let Some(cap) = self.blobs.cap else { return Blobs::Lost };
        if !self.blobs.droppable {
            return Blobs::Kept;
        }
        self.blobs.droppable = false;
        // `true`: purged while droppable. A failed call says nothing about the
        // contents, so it counts as lost: the object is let go and made again.
        if self.memctl_say(false) == Some(false) {
            return Blobs::Kept;
        }
        self.drop_blobs(cap);
        Blobs::Lost
    }

    fn pressure_rose(&mut self) -> bool {
        let Some(port) = self.pressure else { return false };
        let mut rose = false;
        let mut event = [0u8; sys::PORT_EVENT_BYTES];
        while sys::port_poll_typed(port, &mut event) == sys::PORT_EVENT_BYTES as isize {
            if let Some(level) = sys::pressure_level(&event) {
                rose |= level > self.level;
                self.level = level;
            }
        }
        rose
    }

    fn blobs_park(&mut self, give_back: bool) {
        let Some(cap) = self.blobs.cap else { return };
        if give_back {
            sys::println(b"[infsrv] memory pressure: blob arena given back, the next call loads it again");
            self.drop_blobs(cap);
            return;
        }
        if self.blobs.droppable {
            return;
        }
        match self.memctl_say(true) {
            Some(false) => self.blobs.droppable = true,
            // Purged already (a held object is not: the kernel contradicts
            // itself) or a call that failed: leave it held, and let it be made
            // again if it was lost.
            Some(true) => self.drop_blobs(cap),
            None => {}
        }
    }

    fn blobs_rebuild(&mut self, broker: &mut Broker, arena: &mut Arena<'_>) {
        match self.make_blobs() {
            Some(buf) => {
                arena.reset(buf);
                bundles::load_all(broker, arena);
                Line::new(b"[infsrv] blob arena rebuilt: ").num((BLOB_BYTES - arena.free()) as u64).push(b" of ")
                    .num(BLOB_BYTES as u64).push(b" bytes used").print();
            }
            None => sys::println(b"[infsrv] blob arena: no memory object, no model until one can be made"),
        }
    }
}

impl SysPlatform {
    /// Have the kernel tell this Domain when its frame budget runs short
    /// (`PORT_SRC_PRESSURE`). A build without reclaim has no pressure to
    /// report and refuses the bind: the service runs without the signal, and
    /// the arena is then given back only by the system's own purge.
    pub fn watch_pressure(&mut self) {
        let port = sys::port_create_typed();
        if port > 0 && sys::port_bind_pressure(port as u32, 0) == 0 {
            self.pressure = Some(port as u32);
        }
    }

    /// `MemCtl::set_volatile` (`volatile`) or `set_nonvolatile` on the arena's
    /// object, and the answer: whether the object was purged. `None`: no
    /// endpoint, no object, or the call failed.
    fn memctl_say(&self, volatile: bool) -> Option<bool> {
        let ep = self.memctl?;
        let mem = Cap::<sys::dev::memctl::VolatileMem>::from_raw(self.blobs.cap?);
        let mut c = MemCtlClient::new(sys::dev::Ep(ep));
        sys::dev::value(if volatile { c.set_volatile(mem) } else { c.set_nonvolatile(mem) }).ok()
    }

    /// Give the object back (its mapping with it) and have none.
    fn drop_blobs(&mut self, cap: u32) {
        let _ = sys::shm_release_typed(cap);
        self.blobs = BlobMem { cap: None, droppable: false };
    }

    /// A new, zeroed arena in a volatile memory object, mapped. `None`: the
    /// system gave no object (the row's frame budget) or no mapping. The
    /// service is held by `blobs_resume`/`blobs_park`: the object is made
    /// held, and marked droppable at the end of the first call.
    pub fn make_blobs(&mut self) -> Option<&'static mut [u8]> {
        let pages = BLOB_BYTES.div_ceil(sys::PAGE_SIZE);
        let cap = sys::shm_create_typed(pages as u64, sys::SHM_RW | SHM_ATTR_VOLATILE << SHM_CREATE_ATTR_SHIFT);
        if cap < 0 {
            return None;
        }
        let va = sys::shm_map_typed(cap as u32);
        if va <= 0 {
            let _ = sys::shm_release_typed(cap as u32);
            return None;
        }
        self.blobs = BlobMem { cap: Some(cap as u32), droppable: false };
        // SAFETY: `BLOB_BYTES <= pages * PAGE_SIZE` bytes at `va` are mapped
        // writable and are ours alone: nothing else holds the capability. The
        // mapping goes only when `drop_blobs` releases the object, which
        // `Service::resume_blobs` follows with `Arena::reset` before any read
        // of the arena, and a volatile object that reclaim took is unmapped
        // by the kernel the same way: `blobs_resume` finds it out (`true`)
        // before the next call reads the slice.
        Some(unsafe { core::slice::from_raw_parts_mut(va as *mut u8, BLOB_BYTES) })
    }
}

/// The platform, with no verdict log made yet (each is made on its context's
/// first `log` call, `Platform::log_region`).
pub fn platform() -> SysPlatform {
    SysPlatform {
        logs: [None; CONTEXTS],
        blobs: BlobMem { cap: None, droppable: false },
        memctl: sys::dev::lookup(sys::dev::key::MEMCTL, 0),
        pressure: None,
        level: 0,
    }
}

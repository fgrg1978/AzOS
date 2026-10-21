// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `AUDIOD.ELF`: the AzOS audio server.
//!
//! A ring-3 program whose topology row is its whole authority: `READ` on
//! `endpoint.audio` (it serves it) and `RW` on the kernel's `sound.0`, the one
//! device stream it holds. Clients open streams on `endpoint.audio` with the
//! same `Sound` interface the kernel serves on `sound.0` and hand it periods
//! of memory; the server mixes them into the device's one playback stream.
//! Capture is lent, never mixed, and decided on the client's microphone effect,
//! never the server's. The decisions are `server.rs`
//! (pure, tested on the host in `tests/host/audiod-tests`) and `mixer.rs`; this
//! file is the world they run in: the kernel calls behind [`Env`], and the two
//! threads.
//!
//! Two threads, because a call can arrive while a period is due: the main
//! thread accepts calls (the endpoint's `READ` grant is stamped with the main
//! thread, `SYS_IPC_ACCEPT_V2` waits for nothing but a call), the pump thread
//! calls [`Server::tick`] every few milliseconds while a stream runs and parks
//! on a futex word when none does. The server's state is behind one lock they
//! share, taken by yielding; the longest it is held is one mix pass or one
//! kernel control call, never a wait. The periods themselves move in queues in
//! shared memory, never in calls; the calls are the ones that change what a
//! stream may do.
//!
//! The pump runs under the topology row's deadline reservation (a period of
//! 10 ms), which is what keeps the device fed when a CPU-bound task runs.

#![no_std]
#![no_main]

mod mixer;
mod server;

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use azos_devif::sound::{self as snd, Info, Opened, Params, Status};
use azos_devif::{MsgDesc, SoundIdl};
use azos_libsys as sys;
use azos_rings::region::SpscSlots;
use server::{DevMem, Env, Limits, Mapped, Server};
use sys::dev::{Cap, Ep, SoundCall, SoundClient};

/// A memory object this task made, and where it is mapped.
#[derive(Clone, Copy)]
struct Region {
    cap: u32,
    va: usize,
}

/// A memory object of `pages` pages, read-write, mapped here. `kind` is the
/// creation word's kind field (`SHM_KIND_ANON` or `SHM_KIND_CONTIG`).
fn make(pages: usize, kind: u64) -> Option<Region> {
    let word = sys::SHM_RW | kind << azos_abi::syscall_nr::SHM_CREATE_KIND_SHIFT;
    let cap = sys::shm_create_typed(pages as u64, word);
    if cap <= 0 {
        return None;
    }
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 {
        let _ = sys::shm_release_typed(cap as u32);
        return None;
    }
    Some(Region { cap: cap as u32, va: va as usize })
}

/// The kernel, as the server sees it.
struct Kernel {
    snd: SoundClient<Ep>,
    /// The three objects of the device's playback stream while it is open.
    dev: Option<[Region; 3]>,
}

impl Kernel {
    fn code<T>(r: azos_idl::Result<azos_devif::Out<T>>) -> Result<T, u32> {
        sys::dev::value(r)
    }
}

impl Env for Kernel {
    fn now_ns(&mut self) -> u64 {
        sys::vdso_now_ns()
    }

    fn map(&mut self, cap: u32) -> Option<Mapped> {
        let mut info = [0u8; sys::SHM_INFO_BYTES];
        if sys::shm_acquire_typed(cap, &mut info) < 0 {
            return None;
        }
        let pages = u32::from_le_bytes([info[0], info[1], info[2], info[3]]) as usize;
        // `info[4]` is the object's access: 0 read-only, 1 read-write.
        let rw = info[4] == 1;
        let va = sys::shm_map_typed(cap);
        (va > 0).then_some(Mapped { va: va as usize, bytes: pages * sys::PAGE_SIZE, rw })
    }

    fn release(&mut self, cap: u32) {
        let _ = sys::shm_release_typed(cap);
    }

    fn wake(&mut self, addr: usize) {
        let _ = sys::futex_wake_addr(addr, 1);
    }

    fn log(&mut self, line: &[u8]) {
        let _ = sys::console_write(sys::STDOUT, line);
    }

    fn dev_info(&mut self) -> Result<Info, u32> {
        Self::code(self.snd.info())
    }

    fn dev_open(&mut self, params: Params) -> Result<DevMem, u32> {
        let geo = params.check()?;
        let slots = server::slots_for(sys::PAGE_SIZE).ok_or(azos_devif::outcome::FAULT)?;
        let arena_pages = (geo.arena_bytes as usize).div_ceil(sys::PAGE_SIZE);
        let (Some(ready), Some(done), Some(arena)) = (
            make(1, azos_abi::syscall_nr::SHM_KIND_ANON),
            make(1, azos_abi::syscall_nr::SHM_KIND_ANON),
            make(arena_pages, azos_abi::syscall_nr::SHM_KIND_CONTIG),
        ) else {
            return Err(azos_devif::outcome::NO_RESOURCE);
        };
        let (rq, dq) = (SpscSlots::<{ snd::SLOT_WORDS }> { base: ready.va, cap: slots }, SpscSlots::<{ snd::SLOT_WORDS }> { base: done.va, cap: slots });
        rq.init();
        dq.init();
        let opened = Self::code(self.snd.open(params, Cap::from_raw(ready.cap), Cap::from_raw(done.cap), Cap::from_raw(arena.cap), 0));
        match opened {
            Ok(o) if o.period_bytes == geo.period_bytes => {
                self.dev = Some([ready, done, arena]);
                Ok(DevMem { ready: rq, done: dq, arena: arena.va, geo })
            }
            other => {
                if other.is_ok() {
                    let _ = self.snd.close();
                }
                for r in [ready, done, arena] {
                    let _ = sys::shm_release_typed(r.cap);
                }
                Err(other.err().unwrap_or(azos_devif::outcome::FAULT))
            }
        }
    }

    fn dev_start(&mut self) -> Result<(), u32> {
        Self::code(self.snd.start())
    }

    fn dev_drain(&mut self) -> Result<(), u32> {
        Self::code(self.snd.drain())
    }

    fn dev_close(&mut self) {
        let _ = self.snd.close();
        if let Some(rs) = self.dev.take() {
            for r in rs {
                let _ = sys::shm_release_typed(r.cap);
            }
        }
    }

    fn lease_open(&mut self, params: Params, ready: u32, done: u32, arena: u32, on_behalf: u64) -> Result<Opened, u32> {
        Self::code(self.snd.open(params, Cap::from_raw(ready), Cap::from_raw(done), Cap::from_raw(arena), on_behalf))
    }

    fn lease_start(&mut self) -> Result<(), u32> {
        Self::code(self.snd.start())
    }

    fn lease_stop(&mut self) -> Result<(), u32> {
        Self::code(self.snd.stop())
    }

    fn lease_drain(&mut self) -> Result<(), u32> {
        Self::code(self.snd.drain())
    }

    fn lease_close(&mut self) -> Result<(), u32> {
        Self::code(self.snd.close())
    }

    fn lease_status(&mut self) -> Result<Status, u32> {
        Self::code(self.snd.status())
    }
}

struct Shared {
    lock: AtomicBool,
    state: UnsafeCell<Option<Server<Kernel>>>,
}
// SAFETY: `state` is touched only with `lock` held (`with`), and written once
// before the second thread exists.
unsafe impl Sync for Shared {}

static SHARED: Shared = Shared { lock: AtomicBool::new(false), state: UnsafeCell::new(None) };

/// Bumped by the main thread whenever a call may have changed a stream; the
/// pump thread's futex word.
static CHANGED: AtomicU32 = AtomicU32::new(0);

/// Run `f` on the server. Spins (yielding) while the other thread has it.
fn with<R>(f: impl FnOnce(&mut Server<Kernel>) -> R) -> R {
    while SHARED.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }
    // SAFETY: the lock is held.
    let r = unsafe { (*SHARED.state.get()).as_mut() }.map(f);
    SHARED.lock.store(false, Ordering::Release);
    r.expect("audiod: state used before it was set up")
}

/// Time between two passes of the pump while the device stream is open, ns.
const TICK_NS: u64 = 5_000_000;
/// Longest the pump parks with nothing to do, ns: a lost wake, and the time to
/// notice a client that stopped, are at most this.
const IDLE_PARK_NS: u64 = 500_000_000;

/// The pump thread's stack.
#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut PUMP_STACK: Stack = Stack([0; 16384]);

extern "C" fn pump_thread(_: u64, _: u64, _: u64) -> ! {
    loop {
        // Read the word BEFORE looking at the streams: a call that lands in
        // between changes it and the wait returns at once.
        let seen = CHANGED.load(Ordering::Acquire);
        let busy = with(|s| {
            s.tick();
            s.busy()
        });
        if busy {
            let _ = sys::sleep_until_ns(sys::vdso_now_ns() + TICK_NS);
        } else {
            let _ = sys::futex_wait(&CHANGED, seen, IDLE_PARK_NS);
        }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let Some(ep) = sys::dev::lookup(sys::dev::key::SOUND, snd::device_badge(0)) else {
        sys::println(b"[audiod] FAILED: the row grants no sound.0");
        sys::exit(1);
    };
    let limits = Limits {
        max_streams: azos_limits::AUDIO_MAX_STREAMS as usize,
        max_periods: azos_limits::AUDIO_MAX_PERIODS as u32,
        arena_bytes_max: azos_limits::AUDIO_ARENA_KB_MAX as u64 * 1024,
        capture: azos_limits::AUDIO_CAPTURE,
    };
    // SAFETY: no other thread exists yet.
    unsafe {
        *SHARED.state.get() = Some(Server::new(Kernel { snd: SoundClient::new(Ep(ep)), dev: None }, limits));
    }
    // The stack is the pump thread's alone, and its top is 16-aligned.
    let top = core::ptr::addr_of_mut!(PUMP_STACK) as usize + core::mem::size_of::<Stack>();
    if sys::thread_create(pump_thread, top, 0, core::ptr::null_mut()) < 0 {
        sys::println(b"[audiod] FAILED: no thread for the pump");
        sys::exit(1);
    }
    sys::println(b"[audiod] AzOS audio server (Sound on endpoint.audio, mixing into sound.0)");

    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // Nothing arrived (a spurious wake): wait again.
            sys::yield_now();
            continue;
        }
        // The badge of the capability the call came through, 0 when the call
        // was not badged: an unidentified caller, whom the server refuses.
        let badge = if req.flags & azos_abi::ipc_msg::MSG_BADGED != 0 { req.badge as u32 } else { 0 };
        let mut rep = MsgDesc::default();
        with(|s| {
            s.caller = badge;
            // The call's warrant is the client's authority for a capture open.
            s.call = call as u64;
            s.prepare();
            let _ = SoundIdl::dispatch(s, &req, &mut rep);
            s.caller = 0;
            s.call = 0;
        });
        // The pump re-reads its streams: a stream may have started.
        CHANGED.fetch_add(1, Ordering::Release);
        let _ = sys::futex_wake(&CHANGED, 1);
        let _ = sys::ipc_reply_v2(call as u64, &rep);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(70);
}

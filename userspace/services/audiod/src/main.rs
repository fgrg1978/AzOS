// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `AUDIOD.ELF`: the AzOS audio server.
//!
//! A ring-3 program whose topology row is its whole authority: `READ` on
//! `endpoint.audio` (it serves it), `RW` on the kernel's `sound.0`, the one
//! device stream it holds, and `WRITE` on `time`, the warrant its mixer
//! presents for a deadline reservation. Clients open streams on `endpoint.audio` with the
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
//! share, a futex word a thread that finds it held sleeps on (never spins: the
//! pump runs at a real-time level, so a spin would keep every task below it
//! off that CPU until its budget ran out); the longest it is held is one mix
//! pass or one kernel control call, never a wait. The periods themselves move
//! in queues in shared memory, never in calls; the calls are the ones that
//! change what a stream may do.
//!
//! **Who holds what time.** The topology row gives the process no profile, so
//! the main thread is a best-effort service: it sleeps in `accept` and its
//! work is the calls. The pump is the real-time work, and it asks for its own
//! deadline reservation first thing (`SYS_SCHEDCTL`, class DL, Kconfig
//! `AUDIOD_PUMP_RUNTIME_US` every `AUDIOD_PUMP_PERIOD_US` at band level
//! `AUDIOD_PUMP_LEVEL`, on the row's `time` warrant): a hard budget, so the
//! mixer is throttled past it and can never take more of a CPU than that. The
//! main thread waits for the answer before it serves a call. When admission
//! refuses (no room, the band cap, no warrant) the server says so on the
//! console and serves no playback stream (`UNSUPPORTED`): the pump then stays
//! a best-effort thread that sleeps, and capture, which the kernel moves, is
//! unaffected.

#![no_std]
#![no_main]

mod mixer;
mod server;

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

use azos_abi::cap::CapPerms;
use azos_devif::sound::{self as snd, Info, Opened, Params, Status};
use azos_devif::{Lent, MsgDesc, SoundIdl};
use azos_libsys as sys;
use azos_rings::region::SpscSlots;
use server::{DevMem, Env, Limits, Mapped, Server};
use sys::dev::{Ep, SoundCall, SoundClient};

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
        // `info[4]` is the object's access: 0 read-only, 1 read-write. The
        // mapping is bounded by the rights the client lent too, which `cap_info`
        // reads: a queue lent without `WRITE` maps read-only, and is refused.
        let lent_write = sys::cap_info(cap).is_ok_and(|i| i.rights & CapPerms::WRITE.bits() != 0);
        let rw = info[4] == 1 && lent_write;
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
        let opened = Self::code(self.snd.open(
            params,
            Lent::dup(ready.cap, snd::QUEUE_RIGHTS),
            Lent::dup(done.cap, snd::QUEUE_RIGHTS),
            Lent::dup(arena.cap, snd::arena_rights(params.dir)),
            0,
        ));
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
        // The client's own copies, lent on as the client lent them: the kernel
        // resolves them in this task's table.
        Self::code(self.snd.open(
            params,
            Lent::dup(ready, snd::QUEUE_RIGHTS),
            Lent::dup(done, snd::QUEUE_RIGHTS),
            Lent::dup(arena, snd::arena_rights(params.dir)),
            on_behalf,
        ))
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
    /// 0 free, 1 held, 2 held with a thread asleep on it.
    lock: AtomicU32,
    state: UnsafeCell<Option<Server<Kernel>>>,
}
// SAFETY: `state` is touched only with `lock` held (`with`), and written once
// before the second thread exists.
unsafe impl Sync for Shared {}

static SHARED: Shared = Shared { lock: AtomicU32::new(0), state: UnsafeCell::new(None) };

/// Bumped by the main thread whenever a call may have changed a stream; the
/// pump thread's futex word.
static CHANGED: AtomicU32 = AtomicU32::new(0);

/// Run `f` on the server. While the other thread has it, sleep on the lock
/// word until it lets go.
fn with<R>(f: impl FnOnce(&mut Server<Kernel>) -> R) -> R {
    if SHARED.lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        // Mark it contended and sleep while it stays so; the holder's release
        // wakes one sleeper.
        while SHARED.lock.swap(2, Ordering::Acquire) != 0 {
            let _ = sys::futex_wait(&SHARED.lock, 2, 0);
        }
    }
    // SAFETY: the lock is held.
    let r = unsafe { (*SHARED.state.get()).as_mut() }.map(f);
    if SHARED.lock.swap(0, Ordering::Release) == 2 {
        let _ = sys::futex_wake(&SHARED.lock, 1);
    }
    r.expect("audiod: state used before it was set up")
}

/// Time between two passes of the pump while the device stream is open, ns.
const TICK_NS: u64 = 5_000_000;
/// Longest the pump parks with nothing to do, ns: a lost wake, and the time to
/// notice a client that stopped, are at most this.
const IDLE_PARK_NS: u64 = 500_000_000;
/// How long the main thread sleeps when an accept comes back with no call
/// (its wakes ran out), ms: it blocks rather than spin.
const ACCEPT_RETRY_MS: u64 = 10;

/// What the pump learned of its reservation, for the main thread: 0 not yet,
/// 1 admitted, 2 refused. The main thread sleeps on it before it serves.
static MIXER_TIME: AtomicU32 = AtomicU32::new(0);

/// `v` in decimal, into `buf`; the digits.
fn decimal(mut v: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            return &buf[i..];
        }
    }
}

/// One console line from `parts`.
fn say(parts: &[&[u8]]) {
    let (mut line, mut n) = ([0u8; 128], 0);
    for p in parts {
        let k = p.len().min(line.len() - 1 - n);
        line[n..n + k].copy_from_slice(&p[..k]);
        n += k;
    }
    line[n] = b'\n';
    let _ = sys::console_write(sys::STDOUT, &line[..=n]);
}

/// Bind the calling thread (the pump) to its deadline reservation on the
/// row's `time` warrant: 0, or the kernel's refusal (a negative errno; -1
/// when the row grants no warrant).
fn reserve_mixer_time() -> i64 {
    let Some(warrant) = sys::dev::lookup(sys::dev::key::TIME, 0) else { return -1 };
    sys::schedctl(
        0,
        sys::SCHEDCTL_CLASS_DL,
        azos_limits::AUDIOD_PUMP_LEVEL as u32,
        azos_limits::AUDIOD_PUMP_RUNTIME_US as u64,
        azos_limits::AUDIOD_PUMP_PERIOD_US as u64,
        warrant,
    )
}

/// The pump thread's stack.
#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut PUMP_STACK: Stack = Stack([0; 16384]);

extern "C" fn pump_thread(_: u64, _: u64, _: u64) -> ! {
    let rc = reserve_mixer_time();
    let admitted = rc == 0;
    with(|s| s.set_playback(admitted));
    let (mut a, mut b, mut c) = ([0u8; 20], [0u8; 20], [0u8; 20]);
    if admitted {
        say(&[
            b"[audiod] mixer: deadline reservation of ",
            decimal(azos_limits::AUDIOD_PUMP_RUNTIME_US as u64, &mut a),
            b" us every ",
            decimal(azos_limits::AUDIOD_PUMP_PERIOD_US as u64, &mut b),
            b" us at band level ",
            decimal(azos_limits::AUDIOD_PUMP_LEVEL as u64, &mut c),
        ]);
    } else {
        say(&[b"[audiod] mixer: no deadline reservation (refused: -", decimal(rc.unsigned_abs(), &mut a), b"): no playback"]);
    }
    MIXER_TIME.store(if admitted { 1 } else { 2 }, Ordering::Release);
    let _ = sys::futex_wake(&MIXER_TIME, 1);
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
    // No call is served before the pump knows whether it may mix.
    while MIXER_TIME.load(Ordering::Acquire) == 0 {
        let _ = sys::futex_wait(&MIXER_TIME, 0, 0);
    }
    sys::println(b"[audiod] AzOS audio server (Sound on endpoint.audio, mixing into sound.0)");

    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // Nothing arrived (a spurious wake): wait a little rather than spin.
            sys::sleep(ACCEPT_RETRY_MS);
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

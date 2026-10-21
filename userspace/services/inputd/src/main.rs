// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `INPUTD.ELF`: the AzOS input server.
//!
//! A ring-3 program whose topology row is its whole authority: one grant of
//! `endpoint.input`, `READ` (it serves it) with the call right and `transfer`
//! (the source its warrants are derived from), and `MemObj
//! input.events` (the drivers' region, read-write: the server moves the tail
//! of the stream). It serves the `Input` object (`crates/core/devif/src/
//! input.rs`) and delivers the input drivers' stream only to the task that
//! holds the focus; the decisions are `focus.rs`'s, which the host suite
//! (`tests/host/inputd-tests`) drives.
//!
//! Two threads. **The main thread serves**: it accepts a call, dispatches it and
//! replies. The row's `READ` grant stamped the endpoint with the TID of the task
//! the program started as, and the kernel hands a call only to the thread
//! that has that TID (`ep_queue::take_locked`: `q.owner != server`; a created
//! thread has a TID of its own and accepts nothing on the endpoint, so a
//! caller waits for ever). The thread the main thread creates is the poller:
//! it reads the stream on a timer (`INPUTD_POLL_ACTIVE_MS` while a task holds
//! the focus, `INPUTD_POLL_IDLE_MS` otherwise) and hands the events to the
//! holder's ring. A single task cannot sleep on a timer and block in the
//! endpoint's accept, and nothing wakes a reader of the drivers' stream: the
//! producers nudge only the terminal server's console wait. Both threads meet
//! in one spin lock around the server's state; the server holds it for one
//! call, the poller for one batch.
//!
//! The terminal server keeps the console: this program never reads console
//! bytes, never claims console input, and touches the region's first ring not
//! at all. With no graphical client nothing it does is visible on the shell.

#![no_std]
#![no_main]

mod focus;

use azos_devif::input::{EventRing, InputIdl, TrustedPage, RING_PAGES, RING_SLOTS};
use azos_idl::MsgDesc;
use azos_input_wire::event::{REGION_TOTAL, STREAM_CAP, STREAM_DROPS_OFFSET, STREAM_OFFSET};
use azos_libsys as sys;
use azos_rings::region::{RingStep, SpscRing};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use focus::{Host, Ring, Service};

/// The rights of the capability the warrants are derived from: the call right
/// that can be lent (`DUP` and `TRANSFER`, which a row gets from
/// `transfer = true`).
const SOURCE_RIGHTS: u8 = azos_abi::cap::CapPerms::WRITE.union(azos_abi::cap::CapPerms::DELEGATE).bits();

/// The server's surroundings: the drivers' region, the trusted page, the
/// capability warrants come from.
struct Sys {
    /// Where the region of the drivers is mapped.
    region: usize,
    /// The trusted-path page: its capability and where it is mapped.
    page: u32,
    page_base: usize,
    /// The call right on this server's own endpoint, from which warrants are
    /// derived.
    source: u32,
}

impl Sys {
    fn stream(&self) -> SpscRing {
        SpscRing { base: self.region + STREAM_OFFSET, cap: STREAM_CAP }
    }
}

impl Host for Sys {
    fn pop(&mut self) -> Option<u64> {
        match self.stream().try_pop() {
            (RingStep::Blocked, _) => None,
            (_, w) => Some(w),
        }
    }

    fn stream_drops(&mut self) -> u32 {
        // SAFETY: `open_region` checked the mapping reaches the counter's line
        // (`STREAM_DROPS_OFFSET`); it stays mapped for the life of the program.
        unsafe { &*((self.region + STREAM_DROPS_OFFSET) as *const AtomicU32) }.load(Ordering::Acquire)
    }

    fn now_ns(&mut self) -> u64 {
        sys::vdso_now_ns()
    }

    fn make_ring(&mut self) -> Option<Ring> {
        let (handle, base) = make_region(RING_PAGES)?;
        SpscRing { base, cap: RING_SLOTS }.init();
        Some(Ring { handle, base })
    }

    fn push(&mut self, ring: &Ring, word: u64) -> bool {
        match (SpscRing { base: ring.base, cap: RING_SLOTS }).try_push(word) {
            RingStep::Blocked => {
                EventRing::drop_one(ring.base);
                false
            }
            // The holder polls; it never announces a sleep.
            _ => true,
        }
    }

    fn close_ring(&mut self, ring: &Ring) {
        EventRing::close(ring.base);
        // Unmaps it here and gives the handle back: what was lent from it goes
        // with it, and the holder's mapping of the page reads the close word.
        let _ = sys::shm_release_typed(ring.handle);
    }

    fn derive_warrant(&mut self, generation: u32) -> Option<u32> {
        let h = sys::endpoint_derive(self.source, SOURCE_RIGHTS, azos_devif::input::warrant_badge(generation), 0, &[]);
        (h > 0).then_some(h as u32)
    }

    fn revoke(&mut self, warrant: u32) {
        // Everything derived from it is gone (the holder's copy); the
        // replacement handle is not wanted either.
        let r = sys::cap_revoke(warrant);
        let _ = sys::close_typed(if r > 0 { r as u32 } else { warrant });
    }

    fn trusted_page(&mut self) -> Option<u32> {
        Some(self.page)
    }

    fn note_sak(&mut self, now_ns: u64) {
        TrustedPage::record(self.page_base, now_ns);
    }

    fn log(&mut self, line: &[u8]) {
        let _ = sys::console_write(sys::STDOUT, line);
    }
}

/// A fresh region of `pages` pages, mapped here: its capability and address.
fn make_region(pages: u64) -> Option<(u32, usize)> {
    let cap = sys::shm_create_typed(pages, sys::SHM_RW);
    if cap <= 0 {
        return None;
    }
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 {
        let _ = sys::shm_release_typed(cap as u32);
        return None;
    }
    Some((cap as u32, va as usize))
}

/// Map the drivers' region (`MemObj input.events`): its base, when the row
/// grants it and it is long enough to hold both rings.
fn open_region() -> Option<usize> {
    let cap = sys::cap_lookup(sys::ty::SHM.raw(), azos_abi::cap::SHM_INPUT_EVENTS);
    if cap < 0 {
        return None;
    }
    let mut info = [0u8; sys::SHM_INFO_BYTES];
    if sys::shm_acquire_typed(cap as u32, &mut info) < 0 {
        return None;
    }
    let pages = u32::from_le_bytes([info[0], info[1], info[2], info[3]]) as usize;
    let va = sys::shm_map_typed(cap as u32);
    (va > 0 && pages * sys::PAGE_SIZE >= REGION_TOTAL).then_some(va as usize)
}

/// The capability on this server's endpoint: the row's one grant, with `READ`
/// (the serving half), the call right and the right to lend it.
fn find_source() -> Option<u32> {
    use azos_abi::cap::CapPerms;
    let want = CapPerms::WRITE.union(CapPerms::DELEGATE).bits();
    // The only endpoint this row holds, whatever its pool index.
    (0..azos_limits::IPC_ENDPOINTS as u32).find_map(|i| {
        let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
        if h <= 0 {
            return None;
        }
        let info = sys::cap_info(h as u32).ok()?;
        (info.rights & want == want && info.badge == 0).then_some(h as u32)
    })
}

/// The server's state, shared by the two threads under [`LOCK`].
struct State(UnsafeCell<Option<Service<Sys>>>);

// SAFETY: every access is under `LOCK` (see `with`).
unsafe impl Sync for State {}

static STATE: State = State(UnsafeCell::new(None));
static LOCK: AtomicBool = AtomicBool::new(false);

/// Run `f` on the server with the lock held.
fn with<R>(f: impl FnOnce(&mut Service<Sys>) -> R) -> R {
    while LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }
    // SAFETY: the lock is held; `main` stored the server before the second
    // thread existed and nothing takes it out.
    let r = f(unsafe { (*STATE.0.get()).as_mut() }.expect("the server is installed before it is used"));
    LOCK.store(false, Ordering::Release);
    r
}

/// The stack of the poller thread.
const POLLER_STACK_BYTES: usize = 8192;

#[repr(C, align(16))]
struct Stack(UnsafeCell<[u8; POLLER_STACK_BYTES]>);

// SAFETY: the poller thread's alone.
unsafe impl Sync for Stack {}

static POLLER_STACK: Stack = Stack(UnsafeCell::new([0; POLLER_STACK_BYTES]));

/// The poller thread: read the drivers' stream on a timer and deliver it to the
/// holder of the focus, for ever.
extern "C" fn poller(_: u64, _: u64, _: u64) -> ! {
    loop {
        let (any, holding) = with(|svc| (svc.pump(), svc.holder() != 0));
        if any {
            sys::yield_now();
            continue;
        }
        sys::sleep(if holding { azos_limits::INPUTD_POLL_ACTIVE_MS } else { azos_limits::INPUTD_POLL_IDLE_MS } as u64);
    }
}

/// Accept a call on `endpoint.input`, dispatch it, reply, for ever: the main
/// thread's loop (the thread the endpoint is stamped with).
fn serve() -> ! {
    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // Nothing arrived (a spurious wake): wait a little rather than spin.
            sys::sleep(10);
            continue;
        }
        let mut rep = MsgDesc::default();
        with(|svc| {
            // The badge of the capability the call came through: the row's, or
            // a warrant's (0 when the call carried none).
            svc.caller = if req.flags & azos_abi::ipc_msg::MSG_BADGED != 0 { req.badge as u32 } else { 0 };
            let _ = InputIdl::dispatch(svc, &req, &mut rep);
        });
        let _ = sys::ipc_reply_v2(call as u64, &rep);
    }
}

fn log(line: &[u8]) {
    let _ = sys::console_write(sys::STDOUT, line);
}

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    let Some(region) = open_region() else {
        log(b"[inputd] no input event region in this row (no keyboard or mouse driver): nothing to serve\n");
        sys::exit(0);
    };
    let Some(source) = find_source() else {
        log(b"[inputd] the row grants no call right to lend on endpoint.input\n");
        sys::exit(1);
    };
    let Some((page, page_base)) = make_region(1) else {
        log(b"[inputd] no memory object for the trusted-path page\n");
        sys::exit(1);
    };
    let mut svc = Service::new(Sys { region, page, page_base, source }, azos_limits::COMPOSITOR);
    svc.attach();
    // SAFETY: no other thread exists yet.
    unsafe { *STATE.0.get() = Some(svc) };

    // The stack is the poller's alone; its top is 16-aligned.
    let top = POLLER_STACK.0.get() as usize + POLLER_STACK_BYTES;
    if sys::thread_create(poller, top, 0, core::ptr::null_mut()) < 0 {
        log(b"[inputd] no thread for the stream: nothing is delivered\n");
        sys::exit(1);
    }
    log(b"[inputd] AzOS input server (Input on endpoint.input)\n");
    serve()
}

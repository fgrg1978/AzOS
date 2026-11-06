// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `INPUTD.ELF`: the AzOS input server.
//!
//! A ring-3 program whose topology row is its whole authority: one grant of
//! `endpoint.input`, `READ` (it serves it) with the call right and `transfer`
//! (the source its warrants are derived from), `MemObj input.events` (the
//! drivers' region, read-write: the server moves the tail of the stream) and
//! `MemObj input.focus` (the focus word's page, read-write, this row's alone).
//! It serves the `Input` object (`crates/core/devif/src/
//! input.rs`) and delivers the input drivers' stream only to the task that
//! holds the focus; the decisions are `focus.rs`'s, which the host suite
//! (`tests/host/inputd-tests`) drives.
//!
//! One thread on one port (`azos_srv`): the calls on `endpoint.input` and the
//! doorbell of the drivers' stream wake the same wait. Before it waits the
//! server drains the stream into the holder's ring and, when the stream is
//! empty, announces a sleep on its consumer flag, as a futex waiter would; the
//! drivers' push that finds the announcement wakes the stream's head word
//! (the kernel's futex wake on the region, from the interrupt arm), and that
//! wake rings the port. An event is handed on as soon as the server runs, an
//! idle machine wakes it for nothing, and a batch of events and a batch of
//! calls take turns.
//!
//! **The keyboard is this server's to give.** While nobody holds the focus it
//! is the console's: the drivers type its keys into the console's input as
//! they always did, and the terminal server drains the region's first ring.
//! While a task holds it, the drivers give the console nothing of it (the focus
//! word, `focus.rs`): this program writes that word and never reads console
//! bytes, never claims console input, and touches the first ring not at all.
//! With no graphical client nothing it does is visible on the shell.

#![no_std]
#![no_main]

mod focus;

use azos_devif::input::{EventRing, InputIdl, TrustedPage, RING_PAGES, RING_SLOTS};
use azos_idl::MsgDesc;
use azos_input_wire::event::{FOCUS_BYTES, FOCUS_OFFSET, REGION_TOTAL, STREAM_CAP, STREAM_DROPS_OFFSET, STREAM_OFFSET};
use azos_libsys as sys;
use azos_rings::region::{RingSleep, RingStep, SpscRing, RING_HEAD};
use azos_srv::sys::Port;
use azos_srv::{Answer, Handler, Idle, Server, State};
use core::sync::atomic::{AtomicU32, Ordering};
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
    /// Where the focus word's page is mapped (this row's alone).
    focus: usize,
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

    /// The word at `off` of the mapping at `base`: the stream's drop counter of
    /// the drivers' region, or the focus word of its page.
    fn word(base: usize, off: usize) -> &'static AtomicU32 {
        // SAFETY: `open_region` checked each mapping reaches the words used in
        // it (`REGION_TOTAL`, `FOCUS_BYTES`); both stay mapped for the life of
        // the program.
        unsafe { &*((base + off) as *const AtomicU32) }
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
        Self::word(self.region, STREAM_DROPS_OFFSET).load(Ordering::Acquire)
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

    fn set_focus(&mut self, generation: u32) {
        Self::word(self.focus, FOCUS_OFFSET).store(generation, Ordering::Release);
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

/// Map the kernel-owned region the row grants under `key` (`MemObj
/// input.events`, `MemObj input.focus`): its capability and base, when it is
/// granted and at least `bytes` long.
fn open_region(key: u32, bytes: usize) -> Option<(u32, usize)> {
    let cap = sys::cap_lookup(sys::ty::SHM.raw(), key);
    if cap < 0 {
        return None;
    }
    let mut info = [0u8; sys::SHM_INFO_BYTES];
    if sys::shm_acquire_typed(cap as u32, &mut info) < 0 {
        return None;
    }
    let pages = u32::from_le_bytes([info[0], info[1], info[2], info[3]]) as usize;
    let va = sys::shm_map_typed(cap as u32);
    (va > 0 && pages * sys::PAGE_SIZE >= bytes).then_some((cap as u32, va as usize))
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

/// The port's sources: the calls on `endpoint.input`, the stream's doorbell.
const CALLS: u64 = 1;
const STREAM: u64 = 2;

/// The server on its port.
struct Input {
    svc: Service<Sys>,
    /// The drivers' stream, consumed here.
    stream: SpscRing,
}

impl Handler<Port> for Input {
    fn call(&mut self, _port: &mut Port, _handle: u64, req: &MsgDesc, rep: &mut MsgDesc) -> Answer {
        // The badge of the capability the call came through: the row's, or a
        // warrant's (0 when the call carried none).
        self.svc.caller = if req.flags & azos_abi::ipc_msg::MSG_BADGED != 0 { req.badge as u32 } else { 0 };
        let _ = InputIdl::dispatch(&mut self.svc, req, rep);
        Answer::Reply
    }

    /// Deliver what the stream holds; when it is empty, announce the sleep
    /// the doorbell ends (an event that came meanwhile is taken first). The
    /// ring library's backstop bounds a wake that went astray.
    fn idle(&mut self, _port: &mut Port) -> Idle {
        self.stream.consumer_woke();
        if self.svc.pump() {
            // A batch was taken, more may wait: let a call in, then look again.
            return Idle::Busy;
        }
        match self.stream.consumer_sleep() {
            RingSleep::Wait { .. } => Idle::Until(sys::vdso_now_ns().saturating_add(sys::RING_WAIT_NS)),
            RingSleep::Retry => Idle::Busy,
        }
    }
}

/// The server's state.
static INPUT: State<Input> = State::new();

fn log(line: &[u8]) {
    let _ = sys::console_write(sys::STDOUT, line);
}

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    let Some((events, region)) = open_region(azos_abi::cap::SHM_INPUT_EVENTS, REGION_TOTAL) else {
        log(b"[inputd] no input event region in this row (no keyboard or mouse driver): nothing to serve\n");
        sys::exit(0);
    };
    // Without the word the drivers cannot be told who holds the keyboard: the
    // console keeps it, and a grant would lend a ring nothing is routed to.
    let Some((_, focus)) = open_region(azos_abi::cap::SHM_INPUT_FOCUS, FOCUS_BYTES) else {
        log(b"[inputd] the row grants no focus word (MemObj input.focus): the console keeps the keyboard\n");
        sys::exit(1);
    };
    let Some(source) = find_source() else {
        log(b"[inputd] the row grants no call right to lend on endpoint.input\n");
        sys::exit(1);
    };
    let Some((page, page_base)) = make_region(1) else {
        log(b"[inputd] no memory object for the trusted-path page\n");
        sys::exit(1);
    };
    let mut svc = Service::new(Sys { region, focus, page, page_base, source }, azos_limits::COMPOSITOR);
    svc.attach();
    let Ok(port) = Port::create() else {
        log(b"[inputd] no event port\n");
        sys::exit(1);
    };
    if port.bind_calls(source, CALLS).is_err() {
        log(b"[inputd] the calls on endpoint.input reach no port\n");
        sys::exit(1);
    }
    if port.bind_doorbell(events, (STREAM_OFFSET + RING_HEAD) as u32, STREAM).is_err() {
        log(b"[inputd] the stream's doorbell reaches no port: nothing is delivered\n");
        sys::exit(1);
    }
    let stream = SpscRing { base: region + STREAM_OFFSET, cap: STREAM_CAP };
    // SAFETY: once, on the only thread.
    let input = unsafe { INPUT.install(Input { svc, stream }) };
    log(b"[inputd] AzOS input server (Input on endpoint.input)\n");
    Server::new(port).run(input)
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ring of input events no driver turned into a console byte.
//!
//! Mouse buttons and axes, the wheel, tablet positions, the modifier keys and
//! keys with no byte: packed with [`azos_input_wire::event::pack`] and
//! published here by whichever driver saw them (the PS/2 driver and
//! virtio-input, on every ISA, in the same word format).
//!
//! **The consumer is the ring-3 terminal server** (`userspace/services/termd`).
//! The ring lives in a kernel-owned memory object that `kernel/src/boot`
//! creates ([`install`]) and the server maps through its topology row
//! (`MemObj input.events`): the producers write the slots and the head through
//! the kernel's direct map, the server reads them and moves the tail. No
//! system call moves an event. The layout is `azos_rings::region::SpscRing`,
//! the contract both sides compile.
//!
//! **The stream.** The region holds a second ring after the first (Kconfig
//! `INPUTD`): every event of every input device, keys that became console
//! bytes included ([`observe`]), for the ring-3 input server
//! (`userspace/services/inputd`), which delivers them to the holder of the
//! focus. Its consumer is a different task from the terminal server, with a
//! wake of its own: it announces a sleep on the stream's consumer flag and
//! waits on the stream's head word (a futex keyed by the region), and the push
//! that finds the announcement calls the waker [`install`] was given (the
//! kernel's `notify_wake_kernel` on the region), after the lock is released.
//! So a key reaches the holder as soon as the server runs, with no timer.
//!
//! **The focus word** (`FOCUS_OFFSET`, after the stream's counter) is the input
//! server's decision of who the keyboard and the pointer belong to: 0 the
//! console, else the generation of the task that holds the focus. The producers
//! read it for each event ([`console_holds`]) and route by it
//! (`keymap::route`); every stream word of an event the console was given is
//! marked (`STREAM_CONSOLE`), so the server never hands it to a holder as well.
//! The Secure Attention chord resets it to the console here ([`attention`]),
//! before the server has seen the chord. Without `INPUTD` nothing reads it.
//! The terminal server maps the region read-write too (it moves the first
//! ring's tail), so it could write the word: the word arbitrates between the
//! console and the other tasks, and the terminal server is the console.
//!
//! The ring has one producer and two drivers (virtio-input's interrupt arm
//! and the PS/2 one) may run on different CPUs, so [`publish`] takes one lock
//! around the push. Producers run in interrupt context with interrupts off, so
//! the hold is a few instructions and never spans an enabled interrupt. A full
//! ring refuses the newest event ([`publish`] says so); the producer counts
//! the loss (`ring_drops`) and adds it to a counter in the region, after the
//! ring (`azos_input_wire::event::DROPS_OFFSET`): the consumer builds state
//! from the events (modifiers held, buttons down), and a dropped release would
//! leave it stuck, so it resynchronizes when the counter moves.
//!
//! **The wake.** The server has one task and waits for console bytes and for
//! these events in the same call (`LOG_CONSOLE_WAIT`), so it announces itself
//! on the ring's consumer flag before it sleeps there
//! (`SpscRing::consumer_sleep`) and withdraws it when the wait returns. The
//! first push after the announcement says so ([`Pushed::Wake`]); the driver
//! then nudges the console wait (`azos_drv_sys::uart::rx_nudge`) and wakes
//! the parked reader like it does for a console byte. A push while the server
//! is awake owes nothing, so an idle terminal is not woken by a timer.

use azos_input_wire::event::{
    DROPS_OFFSET, FOCUS_OFFSET, REGION_TOTAL, RING_CAP, STREAM_CAP, STREAM_CONSOLE, STREAM_DROPS_OFFSET, STREAM_OFFSET,
};
use azos_rings::region::{RingStep, SpscRing};
use azos_sync::SpinLock;
use core::sync::atomic::{AtomicU32, Ordering};

// The drop counter sits right after the ring: the wire crate names the offset
// without the rings crate. The stream ring follows it, with its own counter.
const _: () = assert!(DROPS_OFFSET == SpscRing::bytes(RING_CAP));
const _: () = assert!(STREAM_DROPS_OFFSET == STREAM_OFFSET + SpscRing::bytes(STREAM_CAP));
const _: () = assert!(STREAM_OFFSET % 64 == 0 && FOCUS_OFFSET % 64 == 0 && REGION_TOTAL <= 4096);

/// Bytes the region occupies: both rings, both drop counters, the focus word.
pub const RING_BYTES: usize = REGION_TOTAL;

/// Wakes up to `n` waiters on the word at `offset` of the region `obj`: the
/// kernel's `notify_wake_kernel`, which an interrupt handler may call.
pub type Waker = fn(obj: u32, offset: u32, n: u32) -> u32;

fn no_waker(_: u32, _: u32, _: u32) -> u32 {
    0
}

/// The installed region: its base in the kernel's direct map (0 until
/// [`install`]), its reference and the waker of the stream's consumer.
#[derive(Clone, Copy)]
struct Region {
    base: usize,
    obj: u32,
    wake: Waker,
}

static BASE: SpinLock<Region> = SpinLock::new(Region { base: 0, obj: 0, wake: no_waker });

/// Make `base` (at least [`RING_BYTES`] of zeroed, 64-byte aligned memory the
/// kernel owns for good) the event ring, and zero its header; `obj` is the
/// region's reference, which `wake` takes to wake the stream's consumer. Boot,
/// once, before the interrupt lines of the input devices are enabled.
///
/// # Safety
/// `base` must satisfy the above and stay valid and mapped for the life of the
/// kernel; the consumer's mapping of it is shared memory by design.
pub unsafe fn install(base: usize, obj: u32, wake: Waker) -> bool {
    if base == 0 || base % 64 != 0 {
        return false;
    }
    let mut g = BASE.lock();
    if g.base != 0 {
        return false;
    }
    SpscRing { base, cap: RING_CAP }.init();
    SpscRing { base: base + STREAM_OFFSET, cap: STREAM_CAP }.init();
    for off in [DROPS_OFFSET, STREAM_DROPS_OFFSET, FOCUS_OFFSET] {
        // SAFETY: the region is `RING_BYTES` long (the caller's contract).
        unsafe { &*((base + off) as *const AtomicU32) }.store(0, Ordering::Relaxed);
    }
    *g = Region { base, obj, wake };
    true
}

/// The word at `off` of the region at `base`.
fn word(base: usize, off: usize) -> &'static AtomicU32 {
    // SAFETY: `install` checked the base, the region is `RING_BYTES` long and
    // never freed; every offset used is inside it.
    unsafe { &*((base + off) as *const AtomicU32) }
}

/// Does the console hold the keyboard and the pointer (the focus word is 0)?
/// Always without Kconfig `INPUTD` (there is no one else to give them to) and
/// before the region exists.
pub fn console_holds() -> bool {
    if !azos_limits::INPUTD {
        return true;
    }
    let g = BASE.lock();
    g.base == 0 || word(g.base, FOCUS_OFFSET).load(Ordering::Acquire) == 0
}

/// The Secure Attention chord was pressed: the keyboard is the console's from
/// this event on, whoever held the focus. The input server, which sees the
/// chord in the stream, takes the focus from its holder and keeps the word at
/// 0; this is the half that does not depend on it.
pub fn attention() {
    if !azos_limits::INPUTD {
        return;
    }
    let g = BASE.lock();
    if g.base != 0 {
        word(g.base, FOCUS_OFFSET).store(0, Ordering::Release);
    }
}

/// What [`publish`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pushed {
    /// The ring is full, or there is none yet: the event is lost.
    Lost,
    /// In the ring; the consumer is awake or will look before it sleeps.
    Kept,
    /// In the ring, and the consumer had announced it was asleep: the caller
    /// wakes it.
    Wake,
}

impl Pushed {
    /// Is the event in the ring?
    pub const fn kept(self) -> bool {
        !matches!(self, Pushed::Lost)
    }

    /// Does the consumer need a wake?
    pub const fn wake(self) -> bool {
        matches!(self, Pushed::Wake)
    }
}

/// Put `word` into the stream ring of the region at `base`; a full ring drops
/// it and counts it. `Some(offset)`: the consumer had announced a sleep, wake
/// it on the word at that offset of the region. (Public for the host suite,
/// which drives it without the Kconfig switch.)
pub fn stream_push(base: usize, word: u64) -> Option<u32> {
    let ring = SpscRing { base: base + STREAM_OFFSET, cap: STREAM_CAP };
    match ring.try_push(word) {
        RingStep::Blocked => {
            let d = self::word(base, STREAM_DROPS_OFFSET);
            // Written under the lock by the one producer at a time.
            d.store(d.load(Ordering::Relaxed).wrapping_add(1), Ordering::Release);
            None
        }
        RingStep::Done => None,
        RingStep::DoneWake { addr } => Some((addr - base) as u32),
    }
}

/// The stream word of `word`: marked when the console was given the event.
const fn tagged(word: u64, console: bool) -> u64 {
    if console { word | STREAM_CONSOLE } else { word }
}

/// Offer one packed key event that is not for the first ring to the stream:
/// one the console took as a byte or swallowed (the release of a key that made
/// one; `console` true), or one withheld from the console because a task holds
/// the focus (`console` false). Only with Kconfig `INPUTD`.
pub fn observe(word: u64, console: bool) {
    if !azos_limits::INPUTD {
        return;
    }
    let g = BASE.lock();
    let r = *g;
    let wake = if r.base != 0 { stream_push(r.base, tagged(word, console)) } else { None };
    drop(g);
    if let Some(off) = wake {
        (r.wake)(r.obj, off, 1);
    }
}

/// Publish one packed event: into the ring the terminal server drains and, with
/// Kconfig `INPUTD`, into the stream (`console`: the console holds the focus,
/// so the stream's copy is marked as the console's).
pub fn publish(word: u64, console: bool) -> Pushed {
    let g = BASE.lock();
    let r = *g;
    if r.base == 0 {
        return Pushed::Lost;
    }
    let wake = if azos_limits::INPUTD { stream_push(r.base, tagged(word, console)) } else { None };
    let ring = SpscRing { base: r.base, cap: RING_CAP };
    let pushed = match ring.try_push(word) {
        RingStep::Blocked => {
            let d = self::word(r.base, DROPS_OFFSET);
            // Written under the lock by the one producer at a time.
            d.store(d.load(Ordering::Relaxed).wrapping_add(1), Ordering::Release);
            Pushed::Lost
        }
        RingStep::Done => Pushed::Kept,
        RingStep::DoneWake { .. } => Pushed::Wake,
    };
    drop(g);
    if let Some(off) = wake {
        (r.wake)(r.obj, off, 1);
    }
    pushed
}

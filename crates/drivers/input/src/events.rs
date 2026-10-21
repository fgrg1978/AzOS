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
//! `INPUTD`): every event the first ring gets, plus the key events that became
//! console bytes ([`observe`]), for the ring-3 input server
//! (`userspace/services/inputd`), which delivers them to the holder of the
//! focus. Its consumer is a different task from the terminal server and
//! polls: it never announces a sleep, so the stream never owes a wake and the
//! first ring's wake protocol is untouched.
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

use azos_input_wire::event::{DROPS_OFFSET, REGION_TOTAL, RING_CAP, STREAM_CAP, STREAM_DROPS_OFFSET, STREAM_OFFSET};
use azos_rings::region::{RingStep, SpscRing};
use azos_sync::SpinLock;
use core::sync::atomic::{AtomicU32, Ordering};

// The drop counter sits right after the ring: the wire crate names the offset
// without the rings crate. The stream ring follows it, with its own counter.
const _: () = assert!(DROPS_OFFSET == SpscRing::bytes(RING_CAP));
const _: () = assert!(STREAM_DROPS_OFFSET == STREAM_OFFSET + SpscRing::bytes(STREAM_CAP));
const _: () = assert!(STREAM_OFFSET % 64 == 0 && REGION_TOTAL <= 4096);

/// Bytes the region occupies: both rings and both drop counters.
pub const RING_BYTES: usize = REGION_TOTAL;

/// Base address of the ring in the kernel's direct map, 0 until [`install`].
static BASE: SpinLock<usize> = SpinLock::new(0);

/// Make `base` (at least [`RING_BYTES`] of zeroed, 64-byte aligned memory the
/// kernel owns for good) the event ring, and zero its header. Boot, once,
/// before the interrupt lines of the input devices are enabled.
///
/// # Safety
/// `base` must satisfy the above and stay valid and mapped for the life of the
/// kernel; the consumer's mapping of it is shared memory by design.
pub unsafe fn install(base: usize) -> bool {
    if base == 0 || base % 64 != 0 {
        return false;
    }
    let mut g = BASE.lock();
    if *g != 0 {
        return false;
    }
    SpscRing { base, cap: RING_CAP }.init();
    SpscRing { base: base + STREAM_OFFSET, cap: STREAM_CAP }.init();
    // SAFETY: the region is `RING_BYTES` long (the caller's contract).
    unsafe { &*((base + DROPS_OFFSET) as *const AtomicU32) }.store(0, Ordering::Relaxed);
    // SAFETY: as above.
    unsafe { &*((base + STREAM_DROPS_OFFSET) as *const AtomicU32) }.store(0, Ordering::Relaxed);
    *g = base;
    true
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
/// it and counts it. The stream has no wake: its consumer polls. (Public for
/// the host suite, which drives it without the Kconfig switch.)
pub fn stream_push(base: usize, word: u64) {
    let ring = SpscRing { base: base + STREAM_OFFSET, cap: STREAM_CAP };
    if let RingStep::Blocked = ring.try_push(word) {
        // SAFETY: `install` checked the base and the region is `RING_BYTES`
        // long: the counter's line is inside it.
        let d = unsafe { &*((base + STREAM_DROPS_OFFSET) as *const AtomicU32) };
        // Written under the lock by the one producer at a time.
        d.store(d.load(Ordering::Relaxed).wrapping_add(1), Ordering::Release);
    }
}

/// Offer one packed key event the console took as a byte (or swallowed, such as
/// the release of a key that made one) to the stream. The first ring does not
/// carry these; only the stream does, and only with Kconfig `INPUTD`.
pub fn observe(word: u64) {
    if !azos_limits::INPUTD {
        return;
    }
    let g = BASE.lock();
    if *g != 0 {
        stream_push(*g, word);
    }
}

/// Publish one packed event: into the ring the terminal server drains and, with
/// Kconfig `INPUTD`, into the stream.
pub fn publish(word: u64) -> Pushed {
    let g = BASE.lock();
    if *g == 0 {
        return Pushed::Lost;
    }
    if azos_limits::INPUTD {
        stream_push(*g, word);
    }
    let ring = SpscRing { base: *g, cap: RING_CAP };
    match ring.try_push(word) {
        RingStep::Blocked => {
            // SAFETY: `install` checked the base and the region is
            // `RING_BYTES` long: the counter's line is inside it.
            let d = unsafe { &*((*g + DROPS_OFFSET) as *const AtomicU32) };
            // Written under the lock by the one producer at a time.
            d.store(d.load(Ordering::Relaxed).wrapping_add(1), Ordering::Release);
            Pushed::Lost
        }
        RingStep::Done => Pushed::Kept,
        RingStep::DoneWake { .. } => Pushed::Wake,
    }
}

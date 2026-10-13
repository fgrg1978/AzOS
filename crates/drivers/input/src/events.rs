// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ring of input events no driver turned into a console byte.
//!
//! Mouse buttons and axes, tablet positions, keys with no byte: packed with
//! [`super::keymap::pack`] and published here by whichever driver saw them.
//! **That ring is the hook for the Phase 7 input server**: nothing drains it
//! today, so a full ring drops (the producer counts it).
//!
//! The ring is single-producer, and two drivers (virtio-input's interrupt
//! arm and the PS/2 one) may run on different CPUs, so [`publish`] takes one
//! lock around the push. Producers run in interrupt context with interrupts
//! off, so the hold is a few instructions and never spans an enabled
//! interrupt.

use core::sync::atomic::{AtomicBool, Ordering};
use azos_spsc::{RingStep, SpscRing};
use azos_sync::SpinLock;

/// Slots of [`event_ring`] (a power of two).
pub const RING_CAP: u32 = 64;

/// The ring's memory: header + slots, 64-byte aligned (the ring's contract).
#[repr(C, align(64))]
struct RingMem([u64; SpscRing::bytes(RING_CAP) / 8]);
static mut RING_MEM: RingMem = RingMem([0; SpscRing::bytes(RING_CAP) / 8]);

static PRODUCERS: SpinLock<()> = SpinLock::new(());
static INITED: AtomicBool = AtomicBool::new(false);

/// The ring of published events, for the input server: the consumer calls
/// `try_pop` and [`super::keymap::unpack`]s the word. One consumer.
pub fn event_ring() -> SpscRing {
    SpscRing { base: &raw const RING_MEM as usize, cap: RING_CAP }
}

/// Make the ring ready; the first driver to bring up a device calls it, the
/// rest find it done. Task context, before any producer's line is enabled:
/// it takes no lock, because a producer's interrupt on this CPU would spin on
/// it for good (the other driver's line may already be live when the second
/// driver gets here, and by then the ring is initialised and nothing is
/// touched).
pub fn init() {
    if !INITED.swap(true, Ordering::AcqRel) {
        event_ring().init();
    }
}

/// Publish one packed event. `false`: the ring is full and the event is lost.
pub fn publish(word: u64) -> bool {
    let _g = PRODUCERS.lock();
    !matches!(event_ring().try_push(word), RingStep::Blocked)
}

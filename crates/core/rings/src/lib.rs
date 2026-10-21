// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! The ring shapes, and the one SPSC protocol under them.
//!
//! * [`Queue`] — SPSC and backpressured: every item is consumed exactly once.
//!   When it is full the producer either gets the item back (`Backpressure`,
//!   the caller blocks or retries) or the item is dropped and counted
//!   (`DropNewest`); the choice is one flag, [`Full`]. It is the in-process
//!   instance of a [`region`] ring (same layout, same index and wake
//!   functions, called with its own address as the base), with a typed slot
//!   and a compile-time capacity; the shared-memory forms are the same
//!   protocol with a runtime capacity and a slot format both address spaces
//!   compile. The SPSC index protocol exists once, in [`region`].
//! * [`Log`] — one writer, sequence-numbered slots, overwrite-oldest, any
//!   number of readers each with a private cursor. A reader that falls behind
//!   is told how many items it lost and jumps to the oldest retained one.
//!   `Log<T, 1>` is a latest-value cell: the writer never blocks and a reader
//!   retries while the writer is mid-store (a seqlock). It is not an SPSC
//!   ring (no consumer index at all), so it shares nothing with [`region`]'s
//!   index protocol; [`region::trace`] is the other overwrite ring and differs
//!   on purpose (one consumer whose tail the producer must read, per-record
//!   stamps in shared memory, a hostile-reader trust boundary).
//! * [`region`] — the SPSC forms over a memory region two address spaces map
//!   (runtime capacity, a notify doorbell that rings only when the other side
//!   may be asleep): the rings ring 3 shares with the kernel and the kernel
//!   tracer's per-CPU record rings.
//!
//! [`Queue`] and [`Log`] ring a [`Doorbell`] after the head moves (a `Queue`
//! only when its consumer announced a sleep). The crate has no kernel
//! dependency: a caller that must mask preemption around a write (the
//! kernel's channels do) wraps the writer.
//!
//! # One writer is a property of the type
//!
//! [`Writer`], [`Producer`] and [`Consumer`] are handed out once per ring
//! (`Log::writer`, `Queue::producer`, `Queue::consumer` return `None` the
//! second time) and are neither `Clone` nor `Copy`; `publish`/`push`/`pop`
//! take `&mut self`. A second handle cannot be made; the compile-fail doctests
//! in `tests/host/rings-tests` prove it (they cannot live here: this crate
//! builds only for the bare-metal targets).

mod log;
mod queue;
pub mod region;

pub use log::{Log, Next, Reader, Writer};
pub use queue::{Consumer, Full, Producer, Push, Queue};

/// Called after every head advance, with the new head (items published so
/// far). The hook for "wake the other side"; it must not block.
pub trait Doorbell {
    fn ring(&self, head: u64);
}

/// No doorbell.
impl Doorbell for () {
    #[inline]
    fn ring(&self, _head: u64) {}
}

/// A plain function is a doorbell.
impl Doorbell for fn(u64) {
    #[inline]
    fn ring(&self, head: u64) {
        self(head)
    }
}

/// A cache line to itself, so the two sides never share one.
#[repr(C, align(64))]
pub struct Pad<T>(pub T);

pub(crate) const CLAIM_PRODUCER: u32 = 1;
pub(crate) const CLAIM_CONSUMER: u32 = 2;

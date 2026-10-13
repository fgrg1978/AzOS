// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! The two ring shapes.
//!
//! * [`Queue`] — SPSC and backpressured: every item is consumed exactly once.
//!   When it is full the producer either gets the item back (`Backpressure`,
//!   the caller blocks or retries) or the item is dropped and counted
//!   (`DropNewest`); the choice is one flag, [`Full`].
//! * [`Log`] — one writer, sequence-numbered slots, overwrite-oldest, any
//!   number of readers each with a private cursor. A reader that falls behind
//!   is told how many items it lost and jumps to the oldest retained one.
//!   `Log<T, 1>` is a latest-value cell: the writer never blocks and a reader
//!   retries while the writer is mid-store (a seqlock).
//!
//! Both embed the same [`Header`] and ring the same [`Doorbell`] after the
//! head moves. The crate has no kernel dependency: a caller that must mask
//! preemption around a write (the kernel's channels do) wraps the writer.
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

pub use log::{Log, Next, Reader, Writer};
pub use queue::{Consumer, Full, Producer, Push, Queue};

use core::sync::atomic::{AtomicU32, AtomicU64};

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

/// The header both shapes begin with.
///
/// `head` counts items published (the producer or the writer owns it), `tail`
/// counts items consumed (`Queue` only; a `Log` has no consumer and leaves it
/// 0 because its readers keep private cursors). `claims` records which
/// handles exist. `policy` is [`Full`] as a word (`Queue` only).
#[repr(C)]
pub struct Header {
    pub head: Pad<AtomicU64>,
    pub tail: Pad<AtomicU64>,
    pub claims: AtomicU32,
    pub policy: u32,
}

impl Header {
    pub(crate) const fn new(policy: u32) -> Self {
        Header {
            head: Pad(AtomicU64::new(0)),
            tail: Pad(AtomicU64::new(0)),
            claims: AtomicU32::new(0),
            policy,
        }
    }
}

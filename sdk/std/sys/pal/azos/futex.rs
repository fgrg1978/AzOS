// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The futex `std`'s locks are built on: `SYS_FUTEX_WAIT` and `SYS_FUTEX_WAKE`.

use crate::sync::atomic::Atomic;
use crate::time::Duration;

/// An atomic for use as a futex that is at least 32-bits but may be larger
pub type Futex = Atomic<Primitive>;
/// Must be the underlying type of Futex
pub type Primitive = u32;

/// An atomic for use as a futex that is at least 8-bits but may be larger.
pub type SmallFutex = Atomic<SmallPrimitive>;
/// Must be the underlying type of SmallFutex
pub type SmallPrimitive = u32;

/// Wait while `*futex == expected`; `false` only if `timeout` ran out.
pub fn futex_wait(futex: &Futex, expected: u32, timeout: Option<Duration>) -> bool {
    // An overflowing timeout is an infinite one.
    let ns = timeout.map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    azos_stdrt::futex::wait(futex, expected, ns)
}

/// Wake one waiter; whether there was one.
#[inline]
pub fn futex_wake(futex: &Futex) -> bool {
    azos_stdrt::futex::wake(futex, 1) > 0
}

/// Wake every waiter.
#[inline]
pub fn futex_wake_all(futex: &Futex) {
    azos_stdrt::futex::wake(futex, u32::MAX);
}

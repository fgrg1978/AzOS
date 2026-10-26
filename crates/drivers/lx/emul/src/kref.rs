// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! `refcount_t` and `struct kref`.
//!
//! A reference count bug is a use-after-free waiting to happen, so the
//! counter follows Linux's `refcount_t` hardening rather than a plain
//! integer: any operation that would wrap, resurrect a dead object or go
//! below zero instead *saturates* the counter at [`REFCOUNT_SATURATED`] and
//! records a warning. A saturated object is leaked (never released again),
//! which is the safe failure: a leak cannot be exploited, a double release
//! can.

use core::cell::Cell;

/// Value a misused counter is pinned at: far from both 0 and the wrap
/// point, so no number of further increments or decrements reaches either.
pub const REFCOUNT_SATURATED: i32 = i32::MIN / 2;

/// Kind of refcount misuse, as Linux classifies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefWarn {
    /// Increment of a counter at 0: the object is already released.
    AddOnZero,
    /// Increment past `i32::MAX`.
    Overflow,
    /// Decrement of a counter at 0.
    Underflow,
    /// Any operation on an already saturated counter.
    Saturated,
}

/// `refcount_t`. `Cell`-based so it can be shared by `&` like the Linux
/// field it stands for; single-threaded by construction.
#[derive(Debug, Default)]
pub struct Refcount {
    val: Cell<i32>,
    warnings: Cell<u32>,
    last: Cell<Option<RefWarn>>,
}

impl Refcount {
    /// `REFCOUNT_INIT(n)`.
    pub const fn new(n: i32) -> Self {
        Refcount { val: Cell::new(n), warnings: Cell::new(0), last: Cell::new(None) }
    }

    fn saturate(&self, w: RefWarn) {
        self.val.set(REFCOUNT_SATURATED);
        self.warnings.set(self.warnings.get() + 1);
        self.last.set(Some(w));
    }

    /// `refcount_read`.
    pub fn read(&self) -> i32 {
        self.val.get()
    }

    /// `refcount_set`.
    pub fn set(&self, n: i32) {
        self.val.set(n);
    }

    /// True once the counter has been saturated by a misuse.
    pub fn is_saturated(&self) -> bool {
        self.val.get() < 0
    }

    /// Misuses detected.
    pub fn warnings(&self) -> u32 {
        self.warnings.get()
    }

    /// Most recent misuse.
    pub fn last_warning(&self) -> Option<RefWarn> {
        self.last.get()
    }

    /// `refcount_inc`.
    pub fn inc(&self) {
        match self.val.get() {
            0 => self.saturate(RefWarn::AddOnZero),
            v if v < 0 => self.saturate(RefWarn::Saturated),
            i32::MAX => self.saturate(RefWarn::Overflow),
            v => self.val.set(v + 1),
        }
    }

    /// `refcount_inc_not_zero`: false (and no change) at 0. A saturated
    /// counter reports true: the object is pinned forever, so taking a
    /// reference is safe.
    pub fn inc_not_zero(&self) -> bool {
        match self.val.get() {
            0 => false,
            v if v < 0 => {
                self.saturate(RefWarn::Saturated);
                true
            }
            i32::MAX => {
                self.saturate(RefWarn::Overflow);
                true
            }
            v => {
                self.val.set(v + 1);
                true
            }
        }
    }

    /// `refcount_dec_and_test`: true exactly when this call took the count
    /// from 1 to 0 and the caller must release.
    pub fn dec_and_test(&self) -> bool {
        match self.val.get() {
            1 => {
                self.val.set(0);
                true
            }
            0 => {
                self.saturate(RefWarn::Underflow);
                false
            }
            v if v < 0 => {
                self.saturate(RefWarn::Saturated);
                false
            }
            v => {
                self.val.set(v - 1);
                false
            }
        }
    }
}

/// `struct kref`.
#[derive(Debug, Default)]
pub struct Kref {
    /// The underlying counter.
    pub refcount: Refcount,
}

impl Kref {
    /// `kref_init`: count 1.
    pub const fn new() -> Self {
        Kref { refcount: Refcount::new(1) }
    }

    /// `kref_init` on an existing kref.
    pub fn init(&self) {
        self.refcount.set(1);
    }

    /// `kref_get`.
    pub fn get(&self) {
        self.refcount.inc();
    }

    /// `kref_get_unless_zero`.
    pub fn get_unless_zero(&self) -> bool {
        self.refcount.inc_not_zero()
    }

    /// `kref_put`: calls `release` and returns true when the last reference
    /// is dropped. `release` runs at most once per `init`.
    pub fn put(&self, release: impl FnOnce()) -> bool {
        if self.refcount.dec_and_test() {
            release();
            true
        } else {
            false
        }
    }

    /// `kref_read`.
    pub fn read(&self) -> i32 {
        self.refcount.read()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_fires_exactly_once_on_the_last_put() {
        let k = Kref::new();
        let released = Cell::new(0);
        k.get();
        k.get();
        assert!(!k.put(|| released.set(released.get() + 1)));
        assert!(!k.put(|| released.set(released.get() + 1)));
        assert!(k.put(|| released.set(released.get() + 1)));
        assert_eq!(released.get(), 1);
        assert_eq!(k.read(), 0);
        assert_eq!(k.refcount.warnings(), 0);
    }

    #[test]
    fn put_after_release_is_an_underflow_and_never_releases_again() {
        let k = Kref::new();
        let released = Cell::new(0);
        assert!(k.put(|| released.set(released.get() + 1)));
        assert!(!k.put(|| released.set(released.get() + 1)));
        assert_eq!(released.get(), 1);
        assert_eq!(k.refcount.last_warning(), Some(RefWarn::Underflow));
        assert_eq!(k.read(), REFCOUNT_SATURATED);
    }

    #[test]
    fn get_on_zero_is_a_use_after_free_and_does_not_resurrect() {
        let k = Kref::new();
        assert!(k.put(|| {}));
        k.get();
        assert_eq!(k.refcount.last_warning(), Some(RefWarn::AddOnZero));
        assert!(k.refcount.is_saturated());
        // Canary: had the get resurrected the object (0 -> 1), this put
        // would release a second time.
        let released = Cell::new(false);
        assert!(!k.put(|| released.set(true)));
        assert!(!released.get());
    }

    #[test]
    fn get_unless_zero() {
        let k = Kref::new();
        assert!(k.get_unless_zero());
        assert_eq!(k.read(), 2);
        k.put(|| {});
        k.put(|| {});
        assert!(!k.get_unless_zero());
        assert_eq!(k.read(), 0);
        assert_eq!(k.refcount.warnings(), 0, "inc_not_zero at 0 is legal, not a warning");
    }

    #[test]
    fn overflow_saturates_instead_of_wrapping() {
        let r = Refcount::new(i32::MAX);
        r.inc();
        assert_eq!(r.read(), REFCOUNT_SATURATED);
        assert_eq!(r.last_warning(), Some(RefWarn::Overflow));
        let r2 = Refcount::new(i32::MAX);
        assert!(r2.inc_not_zero());
        assert_eq!(r2.read(), REFCOUNT_SATURATED);
    }

    #[test]
    fn saturated_counter_is_sticky() {
        let r = Refcount::new(REFCOUNT_SATURATED);
        for _ in 0..1000 {
            r.inc();
            assert!(!r.dec_and_test());
        }
        assert_eq!(r.read(), REFCOUNT_SATURATED);
        assert_eq!(r.warnings(), 2000);
        assert!(r.inc_not_zero());
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! Locks for a single-threaded, run-to-completion server.
//!
//! lxsrv runs every Linux context (kernel thread, work item, timer callback)
//! on one AzOS thread on one hart, one item at a time. Mutual exclusion is
//! therefore already guaranteed by construction, and a lock only has two jobs
//! left:
//!
//! * keep the *state* Linux code observes (`spin_is_locked`, the saved
//!   interrupt flag, the mutex owner) so drivers behave as on Linux;
//! * detect the cases that would hang or corrupt on Linux: re-taking a held
//!   spinlock (self-deadlock), unlocking what you do not hold, and any wait
//!   that would have to block.
//!
//! In stage L0 there is no stack switching, so an item cannot be suspended
//! in the middle of its function. A `mutex_lock` on a contended mutex, a
//! `down` on a zero semaphore or a `wait_for_completion` on an incomplete
//! completion therefore returns [`LockError::WouldBlock`]: inside a
//! run-to-completion item that is a bug to report, not a state to wait in.
//! Stage L1 adds stackful tasks and turns these into real waits.
//!
//! All types use `Cell` so they can be shared by `&` like their Linux
//! counterparts embedded in driver structures; they are `!Sync`, which is
//! the honest statement of the single-thread model.

use core::cell::Cell;

/// Identifier of the Linux-level task that holds a lock (see
/// [`crate::sched`]). 0 is the loop itself (softirq / timer context).
pub type TaskId = u32;

/// Lock misuse detected at run time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockError {
    /// The lock is already held by the caller: on Linux this spins or
    /// sleeps forever.
    Deadlock,
    /// Waiting is required, and an L0 run-to-completion item cannot wait.
    WouldBlock,
    /// Unlock of a lock that is not held.
    NotHeld,
    /// Mutex unlock by a task that does not own it.
    NotOwner,
    /// A sleeping primitive used from atomic context (timer callback or
    /// interrupts disabled): Linux's "sleeping function called from invalid
    /// context", reported even when the lock happens to be free.
    Atomic,
}

/// Saved interrupt state returned by `lock_irqsave`, consumed by
/// `unlock_irqrestore` (Linux's `unsigned long flags`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "the saved flags must be passed back to unlock_irqrestore"]
pub struct IrqFlags(bool);

/// The emulated local interrupt-enable flag. lxsrv never takes interrupts
/// in the middle of an item (IRQs are messages handled by the loop), so
/// this is pure bookkeeping that keeps `irqs_disabled()` truthful and lets
/// a missing restore be detected.
#[derive(Debug)]
pub struct IrqState {
    enabled: Cell<bool>,
}

impl Default for IrqState {
    fn default() -> Self {
        Self::new()
    }
}

impl IrqState {
    /// Interrupts start enabled, as in a Linux process context.
    pub const fn new() -> Self {
        IrqState { enabled: Cell::new(true) }
    }

    /// `local_irq_save`: disable and return the previous state.
    pub fn save(&self) -> IrqFlags {
        IrqFlags(self.enabled.replace(false))
    }

    /// `local_irq_restore`.
    pub fn restore(&self, flags: IrqFlags) {
        self.enabled.set(flags.0);
    }

    /// `local_irq_enable`.
    pub fn enable(&self) {
        self.enabled.set(true);
    }

    /// `local_irq_disable`.
    pub fn disable(&self) {
        self.enabled.set(false);
    }

    /// `irqs_disabled()`.
    pub fn disabled(&self) -> bool {
        !self.enabled.get()
    }
}

/// `spinlock_t` as a held flag plus a deadlock counter.
#[derive(Debug, Default)]
pub struct SpinLock {
    held: Cell<bool>,
    deadlocks: Cell<u32>,
}

impl SpinLock {
    /// `spin_lock_init`.
    pub const fn new() -> Self {
        SpinLock { held: Cell::new(false), deadlocks: Cell::new(0) }
    }

    fn take(&self) -> Result<(), LockError> {
        if self.held.replace(true) {
            self.deadlocks.set(self.deadlocks.get() + 1);
            return Err(LockError::Deadlock);
        }
        Ok(())
    }

    /// `spin_lock`. Re-locking a held lock is a self-deadlock (one hart, so
    /// the holder can only be the caller) and is reported, not spun on.
    pub fn lock(&self) -> Result<(), LockError> {
        self.take()
    }

    /// `spin_trylock`.
    pub fn try_lock(&self) -> bool {
        !self.held.replace(true)
    }

    /// `spin_unlock`.
    pub fn unlock(&self) -> Result<(), LockError> {
        if !self.held.replace(false) {
            return Err(LockError::NotHeld);
        }
        Ok(())
    }

    /// `spin_lock_irqsave`: saves and disables interrupts, then locks. On a
    /// deadlock report the interrupt state is left as it was.
    pub fn lock_irqsave(&self, irq: &IrqState) -> Result<IrqFlags, LockError> {
        self.take()?;
        Ok(irq.save())
    }

    /// `spin_unlock_irqrestore`.
    pub fn unlock_irqrestore(&self, irq: &IrqState, flags: IrqFlags) -> Result<(), LockError> {
        self.unlock()?;
        irq.restore(flags);
        Ok(())
    }

    /// `spin_is_locked`.
    pub fn is_locked(&self) -> bool {
        self.held.get()
    }

    /// Self-deadlocks detected on this lock.
    pub fn deadlocks(&self) -> u32 {
        self.deadlocks.get()
    }
}

/// `struct mutex` with an owner, so recursion, contention and foreign
/// unlocks are each distinguishable.
#[derive(Debug, Default)]
pub struct Mutex {
    owner: Cell<Option<TaskId>>,
}

impl Mutex {
    /// `mutex_init`.
    pub const fn new() -> Self {
        Mutex { owner: Cell::new(None) }
    }

    /// `mutex_lock` by task `me`. Contended → [`LockError::WouldBlock`]
    /// (L0 cannot sleep); already owned by `me` → [`LockError::Deadlock`].
    pub fn lock(&self, me: TaskId) -> Result<(), LockError> {
        match self.owner.get() {
            None => {
                self.owner.set(Some(me));
                Ok(())
            }
            Some(o) if o == me => Err(LockError::Deadlock),
            Some(_) => Err(LockError::WouldBlock),
        }
    }

    /// `mutex_trylock`: true if acquired (same polarity as Linux).
    pub fn try_lock(&self, me: TaskId) -> bool {
        if self.owner.get().is_some() {
            return false;
        }
        self.owner.set(Some(me));
        true
    }

    /// `mutex_unlock` by task `me`.
    pub fn unlock(&self, me: TaskId) -> Result<(), LockError> {
        match self.owner.get() {
            None => Err(LockError::NotHeld),
            Some(o) if o != me => Err(LockError::NotOwner),
            Some(_) => {
                self.owner.set(None);
                Ok(())
            }
        }
    }

    /// `mutex_is_locked`.
    pub fn is_locked(&self) -> bool {
        self.owner.get().is_some()
    }

    /// Current owner.
    pub fn owner(&self) -> Option<TaskId> {
        self.owner.get()
    }
}

/// `done` value set by `complete_all`: every later wait succeeds and
/// `complete` no longer changes it. Linux uses a large sentinel for the same
/// purpose; half of `u32::MAX` keeps it far from any real count.
pub const COMPLETION_ALL: u32 = u32::MAX / 2;

/// `struct completion`: a counted event.
#[derive(Debug, Default)]
pub struct Completion {
    done: Cell<u32>,
}

impl Completion {
    /// `init_completion`.
    pub const fn new() -> Self {
        Completion { done: Cell::new(0) }
    }

    /// `reinit_completion`.
    pub fn reinit(&self) {
        self.done.set(0);
    }

    /// `complete`: one waiter's worth. Saturates at [`COMPLETION_ALL`].
    pub fn complete(&self) {
        let d = self.done.get();
        if d < COMPLETION_ALL {
            self.done.set(d + 1);
        }
    }

    /// `complete_all`: release every present and future waiter until
    /// `reinit`.
    pub fn complete_all(&self) {
        self.done.set(COMPLETION_ALL);
    }

    /// `try_wait_for_completion`: consume one completion if available.
    /// After `complete_all` this always succeeds and consumes nothing.
    pub fn try_wait(&self) -> bool {
        match self.done.get() {
            0 => false,
            COMPLETION_ALL => true,
            d => {
                self.done.set(d - 1);
                true
            }
        }
    }

    /// `wait_for_completion`: [`LockError::WouldBlock`] if not done (L0
    /// cannot sleep; see the module documentation).
    pub fn wait(&self) -> Result<(), LockError> {
        if self.try_wait() {
            Ok(())
        } else {
            Err(LockError::WouldBlock)
        }
    }

    /// `completion_done`: true if a wait would not block.
    pub fn is_done(&self) -> bool {
        self.done.get() != 0
    }

    /// Raw `done` count.
    pub fn done(&self) -> u32 {
        self.done.get()
    }
}

/// `struct semaphore` (counting).
#[derive(Debug, Default)]
pub struct Semaphore {
    count: Cell<u32>,
}

impl Semaphore {
    /// `sema_init`.
    pub const fn new(count: u32) -> Self {
        Semaphore { count: Cell::new(count) }
    }

    /// `down_trylock`. NOTE the polarity: returns **true when acquired**,
    /// whereas Linux returns 0 on success. The C shim in L1 inverts it.
    pub fn down_trylock(&self) -> bool {
        let c = self.count.get();
        if c == 0 {
            return false;
        }
        self.count.set(c - 1);
        true
    }

    /// `down`: [`LockError::WouldBlock`] if the count is zero.
    pub fn down(&self) -> Result<(), LockError> {
        if self.down_trylock() {
            Ok(())
        } else {
            Err(LockError::WouldBlock)
        }
    }

    /// `up`. Saturates rather than wrapping.
    pub fn up(&self) {
        self.count.set(self.count.get().saturating_add(1));
    }

    /// Current count.
    pub fn count(&self) -> u32 {
        self.count.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn irqsave_restores_the_previous_state() {
        let irq = IrqState::new();
        let a = SpinLock::new();
        let b = SpinLock::new();
        let fa = a.lock_irqsave(&irq).unwrap();
        assert!(irq.disabled() && a.is_locked());
        let fb = b.lock_irqsave(&irq).unwrap();
        b.unlock_irqrestore(&irq, fb).unwrap();
        assert!(irq.disabled(), "inner restore must keep IRQs off");
        a.unlock_irqrestore(&irq, fa).unwrap();
        assert!(!irq.disabled());
        assert!(!a.is_locked());
    }

    #[test]
    fn relocking_a_held_spinlock_is_a_deadlock_report() {
        let irq = IrqState::new();
        let l = SpinLock::new();
        let f = l.lock_irqsave(&irq).unwrap();
        assert_eq!(l.lock_irqsave(&irq), Err(LockError::Deadlock));
        assert_eq!(l.lock(), Err(LockError::Deadlock));
        assert_eq!(l.deadlocks(), 2);
        assert!(!l.try_lock());
        l.unlock_irqrestore(&irq, f).unwrap();
        assert!(!irq.disabled(), "a failed relock must not have clobbered the saved state");
    }

    #[test]
    fn unlock_of_a_free_spinlock_is_reported() {
        let irq = IrqState::new();
        let l = SpinLock::new();
        assert_eq!(l.unlock(), Err(LockError::NotHeld));
        let f = irq.save();
        assert_eq!(l.unlock_irqrestore(&irq, f), Err(LockError::NotHeld));
        assert!(irq.disabled(), "a failed unlock does not restore");
    }

    #[test]
    fn mutex_owner_rules() {
        let m = Mutex::new();
        assert_eq!(m.unlock(1), Err(LockError::NotHeld));
        m.lock(1).unwrap();
        assert_eq!(m.owner(), Some(1));
        assert_eq!(m.lock(1), Err(LockError::Deadlock));
        assert_eq!(m.lock(2), Err(LockError::WouldBlock));
        assert!(!m.try_lock(2));
        assert_eq!(m.unlock(2), Err(LockError::NotOwner));
        assert!(m.is_locked());
        m.unlock(1).unwrap();
        assert!(m.try_lock(2));
        m.unlock(2).unwrap();
        assert!(!m.is_locked());
    }

    #[test]
    fn completion_counts_like_linux() {
        let c = Completion::new();
        assert_eq!(c.wait(), Err(LockError::WouldBlock));
        c.complete();
        c.complete();
        assert_eq!(c.done(), 2);
        assert!(c.try_wait());
        assert!(c.wait().is_ok());
        assert!(!c.try_wait());
        assert!(!c.is_done());
    }

    #[test]
    fn complete_all_releases_everyone_until_reinit() {
        let c = Completion::new();
        c.complete();
        c.complete_all();
        for _ in 0..1000 {
            assert!(c.try_wait());
        }
        c.complete();
        assert_eq!(c.done(), COMPLETION_ALL, "complete after complete_all saturates");
        c.reinit();
        assert!(!c.try_wait());
    }

    #[test]
    fn completion_count_saturates_below_the_all_sentinel() {
        let c = Completion::new();
        c.done.set(COMPLETION_ALL - 1);
        c.complete();
        c.complete();
        assert_eq!(c.done(), COMPLETION_ALL);
    }

    #[test]
    fn semaphore_counts() {
        let s = Semaphore::new(2);
        assert!(s.down_trylock());
        assert!(s.down().is_ok());
        assert_eq!(s.down(), Err(LockError::WouldBlock));
        assert!(!s.down_trylock());
        s.up();
        assert_eq!(s.count(), 1);
        let full = Semaphore::new(u32::MAX);
        full.up();
        assert_eq!(full.count(), u32::MAX);
    }
}

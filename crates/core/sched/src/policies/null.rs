// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Trivial always-empty policy — proof-of-extension for the
//! [`super::Backend`] enum-dispatch table (audit axis 9, task 2).
//!
//! Not used by [`super::default_table`]. It exists so
//! `sched-policy-tests` can add a "new" policy and wire it into one
//! table slot, demonstrating the count of files/sites a real policy
//! addition touches: this file, plus one variant and one arm per method
//! in `policies/mod.rs` — nothing in `aps_state.rs`, `scheduler.rs`,
//! `class.rs`, or `runtime/registry.rs`.

use super::{Policy, TaskMeta};

/// A policy that accepts nothing and holds nothing. `enqueue` always
/// refuses (mirrors a `CAPACITY = 0` runqueue), so a class assigned this
/// backend behaves as permanently empty to `Aps::pick_class`'s
/// `is_runnable` check — the class is skipped every time, exactly like
/// having no runnable tasks.
#[derive(Default)]
pub struct Null;

impl Null {
    pub const fn new() -> Self {
        Self
    }
}

impl Policy for Null {
    const CAPACITY: usize = 0;

    fn enqueue(&mut self, meta: TaskMeta) -> Result<(), TaskMeta> {
        Err(meta)
    }

    fn dequeue(&mut self, _tid: u32) -> Option<TaskMeta> {
        None
    }

    fn pick_next(&mut self, _now_us: u64) -> Option<TaskMeta> {
        None
    }

    fn len(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_empty_and_always_refuses() {
        let mut n = Null::new();
        assert!(n.is_empty());
        assert_eq!(n.len(), 0);
        assert!(n.pick_next(0).is_none());
        let meta = TaskMeta::new(1, crate::class::SchedClass::Idle, 0);
        assert_eq!(n.enqueue(meta), Err(meta));
    }
}

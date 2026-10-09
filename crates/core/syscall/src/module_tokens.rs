// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The live-token table behind `SYS_MODULE_VERIFY` / `SYS_MODULE_MAP_X`
//! (`module_ops.rs`): which task holds which one-shot token. Pure, with no
//! lock and no kernel call, so `tests/host/syscall-tests` pulls it in with
//! `#[path]`; `module_ops.rs` keeps it under its own spin lock.
//!
//! Sized by Kconfig `LX_MODULE_TOKENS`.

/// One live token: the task it is bound to, its nonce, and how many pages it
/// allows to become executable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub live: bool,
    pub tid: u32,
    pub nonce: u32,
    pub max_pages: usize,
}

pub const EMPTY: Slot = Slot { live: false, tid: 0, nonce: 0, max_pages: 0 };

/// `N` token slots.
pub struct Tokens<const N: usize> {
    slots: [Slot; N],
}

impl<const N: usize> Tokens<N> {
    pub const fn new() -> Self {
        Self { slots: [EMPTY; N] }
    }

    /// Grant `tid` a token. A task's previous unused token is replaced, not
    /// stacked; else the first free slot; else one is evicted, chosen by the
    /// nonce (its owner just gets `-EPERM` at MAP_X and verifies again).
    /// Returns the slot index (0-based).
    pub fn grant(&mut self, tid: u32, nonce: u32, max_pages: usize) -> usize {
        let i = self.slots.iter().position(|s| s.live && s.tid == tid)
            .or_else(|| self.slots.iter().position(|s| !s.live))
            // Rotates through the slots as the nonce advances.
            .unwrap_or((nonce >> 1) as usize % N);
        self.slots[i] = Slot { live: true, tid, nonce, max_pages };
        i
    }

    /// Consume the token in 1-based `slot` if it is live and bound to `tid`
    /// with `nonce`: one attempt per verification, whatever the caller does
    /// next. Returns the pages it allows.
    pub fn take(&mut self, slot: usize, tid: u32, nonce: u32) -> Option<usize> {
        if slot == 0 || slot > N {
            return None;
        }
        let s = &mut self.slots[slot - 1];
        if !s.live || s.tid != tid || s.nonce != nonce {
            return None;
        }
        s.live = false;
        Some(s.max_pages)
    }

    /// Task `tid` has exited: drop every token bound to it, so a dead task
    /// does not hold a slot until some later grant evicts it, and a reused
    /// TID never inherits a token. Returns how many were dropped.
    pub fn release_all(&mut self, tid: u32) -> usize {
        if cfg!(feature = "module-token-leak-canary") {
            return 0;
        }
        let mut n = 0;
        for s in self.slots.iter_mut() {
            if s.live && s.tid == tid {
                *s = EMPTY;
                n += 1;
            }
        }
        n
    }

    /// Live tokens bound to `tid`.
    pub fn live_of(&self, tid: u32) -> usize {
        self.slots.iter().filter(|s| s.live && s.tid == tid).count()
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! MSI identities waiting for a hart to come up (AIA).
//!
//! An IMSIC file's enable bits are reachable only from the hart that owns
//! the file (CSRs through `siselect`/`sireg`), so a driver that routes a
//! device's MSI-X vector to another CPU at boot, before that CPU runs, cannot
//! enable the identity itself. It asks here ([`MsiPending::request`]); the
//! target hart's own interrupt bring-up calls [`MsiPending::hart_init`] and
//! enables what was asked. A hart that has already run its bring-up cannot be
//! reached this way, and the request says so (`false`): the caller then does
//! without that vector, as it does without a route.
//!
//! The requests outlive the bring-up, so a hart that goes offline and comes
//! back (CPU hotplug) enables the same identities again.
//!
//! Pure bookkeeping over atomics, so the host tests run it as written; the
//! controller half is `irqchip::init` and `irqchip::enable_irq`.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Identities tracked: `irqchip::COUNTED_IDS`, the range QEMU's IMSIC
/// implements and the kernel counts.
pub const IDS: u32 = 256;
const WORDS: usize = (IDS / 64) as usize;

/// Requests for `HARTS` harts: one bit per identity, and whether the hart has
/// run its bring-up.
pub struct MsiPending<const HARTS: usize> {
    ids: [[AtomicU64; WORDS]; HARTS],
    up: [AtomicBool; HARTS],
}

impl<const HARTS: usize> MsiPending<HARTS> {
    pub const fn new() -> Self {
        MsiPending {
            ids: [const { [const { AtomicU64::new(0) }; WORDS] }; HARTS],
            up: [const { AtomicBool::new(false) }; HARTS],
        }
    }

    /// Ask for identity `id` to be enabled in `hart`'s file by that hart's
    /// bring-up. `true`: it will be (the hart has not run it yet, or is running
    /// it now). `false`: the request is not kept (no such hart or identity) or
    /// the hart is already up and nothing will enable it.
    pub fn request(&self, hart: u32, id: u32) -> bool {
        let Some(words) = self.ids.get(hart as usize) else { return false };
        if id == 0 || id >= IDS {
            return false;
        }
        words[(id / 64) as usize].fetch_or(1 << (id % 64), Ordering::AcqRel);
        // After the request is recorded: a hart that comes up from here on
        // sees it. One that came up before (`up`) was never going to.
        !self.up[hart as usize].load(Ordering::Acquire)
    }

    /// Withdraw a request. A hart already up keeps what it enabled (its file
    /// is its own).
    pub fn cancel(&self, hart: u32, id: u32) {
        if let Some(words) = self.ids.get(hart as usize) {
            if id != 0 && id < IDS {
                words[(id / 64) as usize].fetch_and(!(1 << (id % 64)), Ordering::AcqRel);
            }
        }
    }

    /// `hart` is bringing its file up: mark it up (later requests are refused)
    /// and call `enable` for every identity requested so far. Runs on `hart`.
    pub fn hart_init(&self, hart: u32, mut enable: impl FnMut(u32)) {
        let Some(words) = self.ids.get(hart as usize) else { return };
        // Up first: a request recorded after the sweep below answers `false`,
        // one recorded before it is swept. A request that races the flag may
        // answer `false` and still be enabled, never the reverse.
        self.up[hart as usize].store(true, Ordering::Release);
        for (w, word) in words.iter().enumerate() {
            let mut bits = word.load(Ordering::Acquire);
            while bits != 0 {
                let b = bits.trailing_zeros();
                enable(w as u32 * 64 + b);
                bits &= bits - 1;
            }
        }
    }
}

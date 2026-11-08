// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The behaviour layers' switches: which of L1 (avoid), L2 (the brain) and L3
//! (explore) the ring-3 engine may let drive. CONFIG.INI sets them at boot and
//! the operator's `behavior enable|disable` changes them; the engine reads the
//! mask through the `Behavior` interface. L0, the safety layer, is the
//! kernel's enforcer and has no switch.

use core::sync::atomic::{AtomicBool, Ordering};
use crate::types::NUM_LAYERS;

static LAYER_ENABLED: [AtomicBool; NUM_LAYERS] = [const { AtomicBool::new(true) }; NUM_LAYERS];

/// Enable or disable layer `layer`; layer 0 has no switch.
pub fn layer_set_enabled(layer: usize, enabled: bool) {
    if layer == 0 || layer >= NUM_LAYERS {
        return;
    }
    LAYER_ENABLED[layer].store(enabled, Ordering::Relaxed);
}

/// The enabled layers, bit `n` for layer `n` (layer 0 always set).
pub fn layer_mask() -> u64 {
    (0..NUM_LAYERS).filter(|&i| LAYER_ENABLED[i].load(Ordering::Relaxed)).fold(0, |m, i| m | 1 << i)
}

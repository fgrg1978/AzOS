// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Transport and ring feature bits (virtio 1.2, section 6), numbered as the
//! specification does: bit 32 is `1 << 32`, the lowest bit of the second
//! 32-bit word a transport exposes through `*FeaturesSel = 1`.

/// The indirect descriptor tables (bit 28).
pub const INDIRECT_DESC: u64 = 1 << 28;
/// `used_event` / `avail_event` in place of the NO_INTERRUPT / NO_NOTIFY flags (bit 29).
pub const EVENT_IDX: u64 = 1 << 29;
/// The modern interface (bit 32). A version-2 MMIO device grants `FEATURES_OK` only with it.
pub const VERSION_1: u64 = 1 << 32;
/// Addresses are the device's own (behind an IOMMU), not the guest-physical ones (bit 33).
pub const ACCESS_PLATFORM: u64 = 1 << 33;

/// The 32-bit word `sel` (0 or 1) of `bits`: what `*Features` reads when
/// `*FeaturesSel` is `sel`.
pub const fn word(bits: u64, sel: u32) -> u32 {
    (bits >> (32 * (sel & 1))) as u32
}

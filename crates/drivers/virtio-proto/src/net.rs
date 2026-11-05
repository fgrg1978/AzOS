// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! virtio-net on the wire (virtio 1.2, section 5.1): the per-buffer header,
//! the feature bits and the link status of the configuration space.

/// Bytes of the header in front of each frame on a legacy (version 1) transport.
pub const HDR_BYTES_LEGACY: usize = 10;
/// Bytes of the header on a modern transport (`num_buffers` included).
pub const HDR_BYTES: usize = 12;

/// The configuration space carries the MAC (bit 5).
pub const F_MAC: u64 = 1 << 5;
/// The configuration space carries the link `status` (bit 16).
pub const F_STATUS: u64 = 1 << 16;
/// `status` bit 0: the link is up.
pub const S_LINK_UP: u16 = 1;
